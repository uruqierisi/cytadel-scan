#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "auth_gate.h"
#include "banner.h"
#include "cli_args.h"
#include "report_cmd.h"
#include "scan_wiring.h"
#include "sync_cmd.h"
#include "cytadel/core/worker_pool.h"
#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel/kb/kb.h"
#include "cytadel/net/host_scan.h"
#include "cytadel/net/port_range.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/net/target.h"
#include "cytadel/net/target_list.h"
#include "cytadel/plugin/plugin.h"
#include "log.h"

/* plugin-api.md §0's canon severity scale, used only for display here --
 * the authoritative integer is what every cytadel_finding_t.severity
 * already holds (0-4); this is purely a human-readable label. */
static const char *cytadel_severity_name(int severity) {
    switch (severity) {
        case 0: return "Info";
        case 1: return "Low";
        case 2: return "Medium";
        case 3: return "High";
        case 4: return "Critical";
        default: return "Unknown";
    }
}

/* The frozen service-token vocabulary (docs/contracts/kb-schema.md §2),
 * duplicated here (as plain string literals, not shared code -- src/net's
 * copy in svc_token.c is private to that module) purely so this summary
 * printer can show which Services/<token>/<port> key(s), if any, were
 * written for a given port; kb-schema.md §7.3 keys `Services/<service>/
 * <port>` by service token first, port second, which is not a convenient
 * per-port lookup direction, so this just checks every known token. */
static const char *const CYTADEL_SVC_TOKENS[] = {
    "www", "https", "ssh", "ftp", "smb", "rdp", "telnet", "smtp",
    "pop3", "imap", "dns", "snmp", "mysql", "postgresql", "redis",
};

/* Milestone 4: prints whatever this port's KB entries (kb-schema.md
 * §7.3-§7.7) reveal -- detected service token(s), banner, HTTP server
 * header, CPE, and notable TLS facts (self-signed / expired certs are
 * exactly the kind of thing an operator wants to see at a glance). Every
 * lookup below is a plain kb-schema.md-key read -- absent keys are
 * skipped, never printed as blank/garbage. */
static void cytadel_print_port_kb_details(const cytadel_kb_t *kb, uint16_t port) {
    char key[64];

    for (size_t i = 0; i < sizeof(CYTADEL_SVC_TOKENS) / sizeof(CYTADEL_SVC_TOKENS[0]); i++) {
        snprintf(key, sizeof(key), "Services/%s/%u", CYTADEL_SVC_TOKENS[i], (unsigned)port);
        cytadel_kb_value_t svc;
        if (cytadel_kb_get(kb, key, &svc) == CYTADEL_KB_GET_FOUND) {
            printf("      service: %s\n", CYTADEL_SVC_TOKENS[i]);
        }
    }

    snprintf(key, sizeof(key), "Banner/%u", (unsigned)port);
    const char *banner = cytadel_kb_get_str(kb, key);
    if (banner != NULL) {
        printf("      banner: %s\n", banner);
    }

    snprintf(key, sizeof(key), "HTTP/%u/server", (unsigned)port);
    const char *http_server = cytadel_kb_get_str(kb, key);
    if (http_server != NULL) {
        snprintf(key, sizeof(key), "HTTP/%u/status", (unsigned)port);
        cytadel_kb_value_t status;
        if (cytadel_kb_get(kb, key, &status) == CYTADEL_KB_GET_FOUND) {
            printf("      http: %s (status %lld)\n", http_server, (long long)status.v.i64);
        } else {
            printf("      http: %s\n", http_server);
        }
    }

    snprintf(key, sizeof(key), "FTP/%u/banner", (unsigned)port);
    const char *ftp_banner = cytadel_kb_get_str(kb, key);
    if (ftp_banner != NULL) {
        printf("      ftp: %s\n", ftp_banner);
    }

    snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
    const char *cpe = cytadel_kb_get_str(kb, key);
    if (cpe != NULL) {
        printf("      cpe: %s\n", cpe);
    }

    snprintf(key, sizeof(key), "TLS/%u/enabled", (unsigned)port);
    cytadel_kb_value_t tls_enabled;
    bool has_tls = (cytadel_kb_get(kb, key, &tls_enabled) == CYTADEL_KB_GET_FOUND) &&
                   tls_enabled.type == CYTADEL_KB_TYPE_BOOL && tls_enabled.v.b;
    if (has_tls) {
        snprintf(key, sizeof(key), "TLS/%u/version", (unsigned)port);
        const char *tls_version = cytadel_kb_get_str(kb, key);
        printf("      tls: %s", (tls_version != NULL) ? tls_version : "enabled");

        snprintf(key, sizeof(key), "TLS/%u/self_signed", (unsigned)port);
        cytadel_kb_value_t self_signed;
        if (cytadel_kb_get(kb, key, &self_signed) == CYTADEL_KB_GET_FOUND &&
            self_signed.type == CYTADEL_KB_TYPE_BOOL && self_signed.v.b) {
            printf(" self-signed");
        }

        snprintf(key, sizeof(key), "TLS/%u/cert_expired", (unsigned)port);
        cytadel_kb_value_t expired;
        if (cytadel_kb_get(kb, key, &expired) == CYTADEL_KB_GET_FOUND &&
            expired.type == CYTADEL_KB_TYPE_BOOL && expired.v.b) {
            printf(" EXPIRED");
        }

        snprintf(key, sizeof(key), "TLS/%u/not_after", (unsigned)port);
        const char *not_after = cytadel_kb_get_str(kb, key);
        if (not_after != NULL) {
            printf(" not_after=%s", not_after);
        }
        printf("\n");
    }
}

/* Milestone 5: prints every finding this host's plugin schedule reported
 * (docs/contracts/plugin-api.md §2.9) -- severity, title, port, and
 * cve/cpe if the plugin supplied them. Persisted, structured reporting
 * (the DB row, branded HTML) is Milestone 7/8; this is the CLI's own
 * plain-text surface for a human operator in the meantime. */
static void cytadel_print_findings(const cytadel_finding_list_t *findings) {
    if (findings->count == 0) {
        return;
    }

    printf("Findings:\n");
    for (size_t i = 0; i < findings->count; i++) {
        const cytadel_finding_t *f = &findings->items[i];
        printf("  [%s] %s (port %lld)\n", cytadel_severity_name(f->severity), f->title,
               (long long)f->port);
        if (f->cve_count > 0) {
            printf("      cve:");
            for (size_t c = 0; c < f->cve_count; c++) {
                printf(" %s", f->cve[c]);
            }
            printf("\n");
        }
        if (f->cpe != NULL) {
            printf("      cpe: %s\n", f->cpe);
        }
        if (f->evidence != NULL) {
            printf("      evidence: %s\n", f->evidence);
        }
    }
}

/* Plain-text per-host scan summary. Machine-readable / branded reporting is
 * Milestone 8 (docs/build-plan.md's src/report); this is intentionally
 * minimal, but as of Milestone 4 does surface the detected
 * service/version/TLS facts recorded in this host's KB so the CLI is
 * useful for a human operator ahead of full report generation. */
static void cytadel_print_scan_summary(const cytadel_host_result_t *result) {
    printf("Target: %s (%s)\n", result->host, result->ip);

    if (result->state != CYTADEL_HOST_UP) {
        printf("Host state: down (no response)\n");
        return;
    }

    printf("Host state: up\n");

    size_t open_count = 0, closed_count = 0, filtered_count = 0;
    for (size_t i = 0; i < result->port_count; i++) {
        switch (result->ports[i].state) {
            case CYTADEL_PORT_OPEN:     open_count++;     break;
            case CYTADEL_PORT_CLOSED:   closed_count++;   break;
            case CYTADEL_PORT_FILTERED: filtered_count++; break;
        }
    }

    printf("Ports scanned: %zu (open=%zu closed=%zu filtered=%zu)\n",
           result->port_count, open_count, closed_count, filtered_count);

    if (open_count == 0) {
        printf("No open ports found.\n");
        return;
    }

    printf("Open ports:\n");
    for (size_t i = 0; i < result->port_count; i++) {
        if (result->ports[i].state == CYTADEL_PORT_OPEN) {
            printf("  %u/tcp open\n", (unsigned)result->ports[i].port);
            if (result->kb != NULL) {
                cytadel_print_port_kb_details(result->kb, result->ports[i].port);
            }
        }
    }

    cytadel_print_findings(&result->findings);
}

/* A short, human-readable description of what was authorized/scanned, for
 * log lines and error messages -- args.target_spec may be NULL when only
 * --targets-file was given (Milestone 3), so this picks whichever (or
 * both) were actually supplied rather than assuming target_spec exists. */
static const char *cytadel_describe_targets(const cytadel_cli_args_t *args, char *buf, size_t buf_len) {
    if (args->target_spec != NULL && args->targets_file != NULL) {
        snprintf(buf, buf_len, "%s + --targets-file %s", args->target_spec, args->targets_file);
    } else if (args->target_spec != NULL) {
        snprintf(buf, buf_len, "%s", args->target_spec);
    } else if (args->targets_file != NULL) {
        snprintf(buf, buf_len, "--targets-file %s", args->targets_file);
    } else {
        snprintf(buf, buf_len, "(none)");
    }
    return buf;
}

/* Ignores SIGPIPE for the whole process, once, before any worker thread
 * exists (src/core/worker_pool.c spawns its threads well after main()
 * reaches this point). A write to a peer that has already closed its end
 * (service_detect.c's HTTP probe, and Milestone 5's plugin socket/http_get
 * bindings, both send bytes to a target that may reset/close at any time)
 * raises SIGPIPE by default, whose disposition is process termination --
 * exactly the kind of thing this scanner must survive from a single
 * misbehaving target. Every write path in this codebase already checks its
 * return value (`n <= 0` -> treat as failure, never assumes success), so
 * turning SIGPIPE into a no-op is sufficient; the failing write then
 * surfaces as an ordinary EPIPE/SSL error return instead.
 *
 * This must happen exactly once, process-wide, before the worker pool
 * starts (docs/build-plan.md's fixed-size thread pool) -- signal
 * disposition is process-global state, so calling this from multiple
 * concurrently running worker threads would be a data race on that shared
 * state. sigaction() (not the simpler signal()) is used per POSIX
 * portability convention: its behavior is fully specified (unlike
 * signal(), whose semantics vary across historical UNIX/BSD/SysV), and a
 * zeroed struct sigaction with only sa_handler set is exactly the "set a
 * simple, non-restarting, no-mask disposition" idiom used throughout this
 * codebase's POSIX-facing code. */
static void cytadel_ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
}

/* M9 Phase 0: every early-return AFTER the mandatory-DB gate has already
 * created the durable `scans` row (cytadel_scan_wiring_open_gate() below)
 * must leave that row in an honest terminal state rather than stuck at
 * 'running' forever -- an operator/report reading this scan later must be
 * able to tell "this scan aborted before finishing" from "this scan is
 * still in progress". Best-effort: a finalize failure here is logged, never
 * fatal (the process is already on its way to a non-zero exit for the
 * original error). Always closes `db` -- callers must not touch it again
 * afterward. */
static void cytadel_scan_abort_and_close(cytadel_db_t *db, long long scan_id) {
    cytadel_scan_persist_status_t fin_rc = cytadel_scan_finalize(db, scan_id, CYTADEL_SCAN_FINALIZE_FAILED);
    if (fin_rc != CYTADEL_SCAN_PERSIST_OK) {
        cytadel_log_error("failed to finalize scans row (scan_id=%lld) as 'failed' (%s)", scan_id,
                           cytadel_scan_persist_status_to_string(fin_rc));
    }
    cytadel_db_close(db);
}

int main(int argc, char **argv) {
    cytadel_ignore_sigpipe();

    /* Milestone 8 slice 5: `cytadel-scan report ...` is dispatched here,
     * BEFORE cytadel_cli_parse_args() and BEFORE the mandatory startup
     * authorization gate below -- this subcommand only reads an
     * already-populated DB (CYTADEL_DB_PATH), it never scans (no packet
     * ever leaves the host), so the authorization gate does not apply to
     * it and must never be reached on this path. Every other invocation
     * shape (including a bare positional target spec that happens to be
     * the literal string "report" -- vanishingly unlikely for a real
     * host/CIDR spec, and the existing scan path already rejects anything
     * that isn't a valid target when it gets there) falls through to the
     * unmodified scan flow below. */
    if (argc > 1 && strcmp(argv[1], "report") == 0) {
        cytadel_report_cmd_args_t report_args;
        cytadel_report_cmd_parse_status_t report_status =
            cytadel_report_cmd_parse_args(argc - 1, argv + 1, &report_args);

        switch (report_status) {
            case CYTADEL_REPORT_CMD_PARSE_HELP:
                cytadel_report_cmd_print_usage(stdout, (argc > 0) ? argv[0] : NULL);
                return EXIT_SUCCESS;
            case CYTADEL_REPORT_CMD_PARSE_ERROR:
                cytadel_report_cmd_print_usage(stderr, (argc > 0) ? argv[0] : NULL);
                return EXIT_FAILURE;
            case CYTADEL_REPORT_CMD_PARSE_OK:
            default:
                break;
        }

        return cytadel_report_cmd_run(&report_args);
    }

    /* M9 Phase 4a: `cytadel-scan sync ...` is dispatched here, BEFORE
     * cytadel_cli_parse_args() and BEFORE the mandatory startup
     * authorization gate below -- same reasoning as `report` immediately
     * above: this subcommand's only network activity is this HOST updating
     * its OWN local vuln DB from the public NVD API, it never scans or
     * contacts any operator-specified target, so the authorization gate
     * does not apply to it and must never be reached on this path. */
    if (argc > 1 && strcmp(argv[1], "sync") == 0) {
        cytadel_sync_cmd_args_t sync_args;
        cytadel_sync_cmd_parse_status_t sync_status =
            cytadel_sync_cmd_parse_args(argc - 1, argv + 1, &sync_args);

        switch (sync_status) {
            case CYTADEL_SYNC_CMD_PARSE_HELP:
                cytadel_sync_cmd_print_usage(stdout, (argc > 0) ? argv[0] : NULL);
                return EXIT_SUCCESS;
            case CYTADEL_SYNC_CMD_PARSE_ERROR:
                cytadel_sync_cmd_print_usage(stderr, (argc > 0) ? argv[0] : NULL);
                return EXIT_FAILURE;
            case CYTADEL_SYNC_CMD_PARSE_OK:
            default:
                break;
        }

        return cytadel_sync_cmd_run(&sync_args);
    }

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    switch (status) {
        case CYTADEL_CLI_PARSE_HELP:
            cytadel_cli_print_usage(stdout, (argc > 0) ? argv[0] : NULL);
            return EXIT_SUCCESS;
        case CYTADEL_CLI_PARSE_VERSION:
            cytadel_cli_print_version(stdout);
            return EXIT_SUCCESS;
        case CYTADEL_CLI_PARSE_ERROR:
            cytadel_cli_print_usage(stderr, (argc > 0) ? argv[0] : NULL);
            return EXIT_FAILURE;
        case CYTADEL_CLI_PARSE_OK:
        default:
            break;
    }

    /* Cosmetic startup banner (src/cli/banner.h). Printed here -- right
     * after argument parsing succeeds (so --no-banner is already known) and
     * strictly BEFORE any scan work, logging, or the mandatory
     * authorization gate below -- stderr-only, TTY-gated, and purely
     * additive: it changes no decision this function makes. This call site
     * is reached ONLY by the live-scan path (the `report`/`sync`
     * subcommands both dispatch-and-return far above this point, long
     * before cytadel_cli_parse_args() is ever called), so those two
     * machine-output-producing paths never execute this code at all. */
    bool stderr_is_tty = (isatty(fileno(stderr)) != 0);
    if (cytadel_banner_should_print(args.no_banner, stderr_is_tty)) {
        cytadel_banner_print(stderr);
    }

    if (cytadel_log_init(args.log_level, args.log_file) != 0) {
        fprintf(stderr, "cytadel-scan: error: could not open log file '%s'\n",
                (args.log_file != NULL) ? args.log_file : "(null)");
        return EXIT_FAILURE;
    }

    char target_desc[512];
    cytadel_describe_targets(&args, target_desc, sizeof(target_desc));

    /* Mandatory startup authorization gate (the mandatory authorization-gate rule). This must
     * run before any scanning path -- and before target expansion, so the
     * gate covers the whole (unexpanded) target spec/file, not just
     * whatever a partial expansion happened to produce. */
    bool is_stdin_tty = (isatty(fileno(stdin)) != 0);
    cytadel_auth_decision_t decision =
        cytadel_auth_gate_decide(args.has_i_am_authorized, is_stdin_tty,
                                  cytadel_auth_gate_default_prompt);

    if (decision.result == CYTADEL_AUTH_RESULT_REFUSED) {
        /* W1: a refusal is just as much part of the mandatory authorization
         * record as a confirmation is -- audit-level so it is never
         * suppressed by --log-level. */
        cytadel_log_audit("authorization refused for target(s) '%s': %s",
                           target_desc, decision.reason);
        fprintf(stderr, "cytadel-scan: refused: %s\n", decision.reason);
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    char operator_buf[256];
    const char *operator_name = args.authorized_by;
    if (operator_name == NULL) {
        operator_name = cytadel_auth_default_operator(operator_buf, sizeof(operator_buf));
    }

    const char *method_str =
        (decision.method == CYTADEL_AUTH_METHOD_FLAG) ? "flag" : "interactive";

    /* W1: this is the mandatory authorization-confirmation LOG record
     * (the mandatory authorization-gate rule) -- it must never be suppressible by --log-level.
     * cytadel_log_audit() ignores the level filter entirely; target_desc/
     * operator_name are untrusted (argv / $USER) but cytadel_log_vwrite()
     * sanitizes them before they reach stderr/the log file (W2), so an
     * embedded newline can't forge an extra, unattributed line. */
    cytadel_log_audit("authorization confirmed: operator='%s' method=%s target='%s'",
                       operator_name, method_str, target_desc);

    /* M9 Phase 0, step 3/4: the DURABLE half of the authorization gate --
     * open+migrate the vuln DB (mandatory: the authorization-gate policy requires a
     * durable authorization record, and there is nowhere to put one without
     * a working DB), then create the `scans` row itself
     * (docs/contracts/db-schema.md §6/§9). This runs BEFORE target
     * expansion (below) and BEFORE the worker pool -- see
     * cytadel_scan_wiring_open_gate()'s own doc comment for why its
     * signature (no target list, no port range, no scan options) makes
     * that ordering structurally enforced, not just conventional. On any
     * failure here, NO target is ever expanded and NO packet ever leaves
     * this host. */
    const char *db_path = getenv("CYTADEL_DB_PATH");
    if (db_path == NULL || db_path[0] == '\0') {
        cytadel_log_error("CYTADEL_DB_PATH is not set -- a writable database is required to record "
                           "scan authorization (see .env.example); refusing to scan");
        fprintf(stderr,
                "cytadel-scan: error: CYTADEL_DB_PATH is not set -- a writable database is required "
                "to record scan authorization (see .env.example)\n");
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    cytadel_db_t *db = NULL;
    long long scan_id = 0;
    cytadel_scan_gate_status_t gate_status =
        cytadel_scan_wiring_open_gate(db_path, target_desc, operator_name, method_str, &db, &scan_id);
    if (gate_status != CYTADEL_SCAN_GATE_OK) {
        cytadel_log_error("mandatory-database gate failed (%s) -- a writable database is required to "
                           "record scan authorization; refusing to scan",
                           cytadel_scan_gate_status_to_string(gate_status));
        fprintf(stderr,
                "cytadel-scan: error: a writable database is required to record scan authorization "
                "(%s); see the log for details\n",
                cytadel_scan_gate_status_to_string(gate_status));
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    /* Milestone 3: multi-target expansion -- single host/hostname, IPv4
     * CIDR block, comma-separated list, and/or --targets-file, combined
     * and de-duplicated by resolved IPv4 address (target_list.h). */
    char err_buf[256];

    cytadel_target_list_t target_list;
    cytadel_target_list_status_t target_list_status =
        cytadel_target_list_parse(args.target_spec, args.targets_file, &target_list, err_buf,
                                   sizeof(err_buf));
    if (target_list_status != CYTADEL_TARGET_LIST_OK) {
        cytadel_log_error("target expansion failed for '%s': %s", target_desc, err_buf);
        fprintf(stderr, "cytadel-scan: error: %s\n", err_buf);
        cytadel_scan_abort_and_close(db, scan_id);
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    const char *port_spec =
        (args.port_spec != NULL) ? args.port_spec : CYTADEL_DEFAULT_PORT_SPEC;
    cytadel_port_list_t ports;
    cytadel_port_range_status_t port_status =
        cytadel_port_range_parse(port_spec, &ports, err_buf, sizeof(err_buf));
    if (port_status != CYTADEL_PORT_RANGE_OK) {
        cytadel_log_error("port range parsing failed for '%s': %s", port_spec, err_buf);
        fprintf(stderr, "cytadel-scan: error: %s\n", err_buf);
        cytadel_target_list_free(&target_list);
        cytadel_scan_abort_and_close(db, scan_id);
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    /* Milestone 5: load the plugin registry once, before the worker pool
     * starts (docs/contracts/plugin-api.md §4.1) -- shared read-only
     * across every worker thread (host_scan.h's opts->plugin_registry
     * comment). An explicitly-requested --plugins-dir that fails to load
     * is a hard CLI error; the compiled-in default ("plugins") is
     * best-effort -- a deployment/test invocation with no plugins/
     * directory still runs the Milestone 1-4 scan phases normally. */
    bool plugins_dir_explicit = (args.plugins_dir != NULL);
    const char *plugins_dir = plugins_dir_explicit ? args.plugins_dir : "plugins";

    cytadel_plugin_registry_t *plugin_registry = NULL;
    struct stat plugins_dir_stat;
    bool plugins_dir_present =
        (stat(plugins_dir, &plugins_dir_stat) == 0) && S_ISDIR(plugins_dir_stat.st_mode);

    if (plugins_dir_explicit || plugins_dir_present) {
        if (cytadel_plugin_registry_load(plugins_dir, &plugin_registry) != 0) {
            if (plugins_dir_explicit) {
                cytadel_log_error("failed to load plugins from '%s' (see prior errors)",
                                   plugins_dir);
                fprintf(stderr,
                        "cytadel-scan: error: failed to load plugins from '%s' (see log for "
                        "details)\n",
                        plugins_dir);
                cytadel_port_list_free(&ports);
                cytadel_target_list_free(&target_list);
                cytadel_scan_abort_and_close(db, scan_id);
                cytadel_log_close();
                return EXIT_FAILURE;
            }
            cytadel_log_warn("plugins directory '%s' exists but failed to load -- continuing "
                              "without any plugin phase",
                              plugins_dir);
            plugin_registry = NULL;
        }
    } else {
        cytadel_log_info("no plugins directory at '%s' -- scanning without a plugin phase",
                          plugins_dir);
    }
    if (plugin_registry != NULL) {
        cytadel_log_info("loaded %zu plugin(s) from '%s'",
                          cytadel_plugin_registry_count(plugin_registry), plugins_dir);
    }

    cytadel_host_scan_opts_t scan_opts;
    scan_opts.discovery_timeout_ms = args.discovery_timeout_ms;
    scan_opts.connect_timeout_ms = args.connect_timeout_ms;
    scan_opts.skip_discovery = args.skip_discovery;
    scan_opts.plugin_registry = plugin_registry;

    cytadel_worker_result_t *results = calloc(target_list.count, sizeof(cytadel_worker_result_t));
    if (results == NULL) {
        cytadel_log_error("out of memory allocating %zu result slot(s)", target_list.count);
        fprintf(stderr, "cytadel-scan: error: out of memory\n");
        cytadel_plugin_registry_free(plugin_registry);
        cytadel_port_list_free(&ports);
        cytadel_target_list_free(&target_list);
        cytadel_scan_abort_and_close(db, scan_id);
        cytadel_log_close();
        return EXIT_FAILURE;
    }

    cytadel_log_info("scanning %zu target(s) with up to %d worker(s)", target_list.count,
                      args.max_workers);
    int pool_rc = cytadel_worker_pool_run(target_list.targets, target_list.count, &ports,
                                           &scan_opts, args.max_workers, results);

    /* Milestone 4: each results[i].result.kb is already fully populated by
     * cytadel_host_scan() (Host/state, Host/ip, Ports/tcp/<port>, and every
     * service-detection/TLS-inspection fact for that host's open ports --
     * docs/contracts/kb-schema.md §7.1-§7.8) by the time the worker pool
     * returns; cytadel_print_scan_summary() above reads it directly.
     * Milestone 5: results[i].result.findings is likewise fully populated
     * by then (cytadel_host_scan() runs the plugin schedule strictly after
     * service detection -- host_scan.c), if a plugin_registry was
     * supplied. */
    size_t hosts_up = 0, hosts_down = 0, hosts_errored = 0, total_open_ports = 0;
    size_t total_findings = 0;
    /* M9 Phase 0, step 7 (PERSIST PHASE): per-host DB writes, aggregated
     * across every host this run scanned. `db_ok` latches false the moment
     * any cytadel_scan_wiring_persist_host() call reports a fatal DB error
     * (CYTADEL_SCAN_PERSIST_ERR_DB) -- a broken DB connection is not
     * expected to recover mid-scan, so no further host's results are handed
     * to the DB once that happens (this is a persistence-only decision:
     * the scan/print loop below still runs to completion for every host
     * regardless, so a DB failure never suppresses the operator's own
     * plain-text summary). */
    bool db_ok = true;
    cytadel_scan_wiring_host_counts_t scan_db_totals;
    memset(&scan_db_totals, 0, sizeof(scan_db_totals));

    for (size_t i = 0; i < target_list.count; i++) {
        cytadel_worker_result_t *r = &results[i];

        if (r->scan_rc != 0) {
            hosts_errored++;
            printf("Target: %s -- scan error\n", target_list.targets[i].host);
        } else if (r->result.host[0] == '\0') {
            /* Only reachable if cytadel_worker_pool_run() returned -1
             * because its very first pthread_create() call failed (see
             * worker_pool.h): zero worker threads ever ran, so this slot
             * is exactly as calloc() left it, not a "host is down" result.
             * Report it honestly instead of printing a blank "Target:  ()"
             * line as if it had been scanned. */
            hosts_errored++;
            printf("Target: %s -- not scanned (worker pool failed to start)\n",
                   target_list.targets[i].host);
        } else {
            cytadel_print_scan_summary(&r->result);
            if (r->result.state == CYTADEL_HOST_UP) {
                hosts_up++;
                for (size_t p = 0; p < r->result.port_count; p++) {
                    if (r->result.ports[p].state == CYTADEL_PORT_OPEN) {
                        total_open_ports++;
                    }
                }
                total_findings += r->result.findings.count;

                /* Persist BEFORE cytadel_host_result_free() below frees
                 * r->result.kb/findings -- this reads them, never mutates
                 * them, and issues no additional network probe (detection-
                 * only: the persist phase adds DB writes only). */
                if (db_ok) {
                    cytadel_scan_wiring_host_counts_t host_counts;
                    cytadel_scan_persist_status_t persist_rc =
                        cytadel_scan_wiring_persist_host(db, scan_id, &r->result, &host_counts);
                    if (persist_rc == CYTADEL_SCAN_PERSIST_ERR_DB) {
                        cytadel_log_error(
                            "scan_wiring: fatal DB error persisting host '%s' (scan_id=%lld) -- no "
                            "further hosts will be persisted this scan",
                            r->result.host, scan_id);
                        db_ok = false;
                    } else {
                        scan_db_totals.findings_persisted += host_counts.findings_persisted;
                        scan_db_totals.findings_skipped += host_counts.findings_skipped;
                        scan_db_totals.detections_attempted += host_counts.detections_attempted;
                        scan_db_totals.unresolvable_services += host_counts.unresolvable_services;
                        scan_db_totals.rows_inserted += host_counts.rows_inserted;
                        scan_db_totals.malformed_events += host_counts.malformed_events;
                    }
                }
            } else {
                hosts_down++;
            }
        }
        printf("\n");

        cytadel_host_result_free(&r->result);
    }
    free(results);

    /* M9 Phase 0, step 8 (FINALIZE): the scans row's status must reflect
     * the real outcome -- 'completed' only if both the worker pool itself
     * ran cleanly (pool_rc == 0) AND every host's persistence succeeded
     * (db_ok); 'failed' otherwise. Runs, and `db` is closed, before the
     * plain-text summary below so a failure here is logged ahead of the
     * final report-command hint. */
    cytadel_scan_finalize_status_t finalize_status =
        (pool_rc == 0 && db_ok) ? CYTADEL_SCAN_FINALIZE_COMPLETED : CYTADEL_SCAN_FINALIZE_FAILED;
    cytadel_scan_persist_status_t finalize_rc = cytadel_scan_finalize(db, scan_id, finalize_status);
    if (finalize_rc != CYTADEL_SCAN_PERSIST_OK) {
        cytadel_log_error("failed to finalize scans row (scan_id=%lld) as '%s' (%s)", scan_id,
                           cytadel_scan_finalize_status_to_string(finalize_status),
                           cytadel_scan_persist_status_to_string(finalize_rc));
    }
    cytadel_db_close(db);
    db = NULL;

    printf("=== Summary ===\n");
    printf("Targets scanned: %zu (up=%zu down=%zu errors=%zu)\n", target_list.count, hosts_up,
           hosts_down, hosts_errored);
    printf("Total open ports: %zu\n", total_open_ports);
    printf("Total findings: %zu\n", total_findings);
    printf("Persisted: %zu finding row(s), %zu CVE-match row(s) from %zu detection(s) "
           "(%zu malformed data-quality event(s), %zu open port(s) with an unresolvable service, "
           "%zu finding(s) skipped due to a per-row data/constraint error)\n",
           scan_db_totals.findings_persisted, scan_db_totals.rows_inserted,
           scan_db_totals.detections_attempted, scan_db_totals.malformed_events,
           scan_db_totals.unresolvable_services, scan_db_totals.findings_skipped);
    printf("Run `cytadel-scan report --latest` (scan_id=%lld) to view the full report.\n", scan_id);

    cytadel_log_info("scan complete: %zu target(s) (up=%zu down=%zu errors=%zu), "
                      "%zu total open port(s), %zu total finding(s)",
                      target_list.count, hosts_up, hosts_down, hosts_errored, total_open_ports,
                      total_findings);

    cytadel_plugin_registry_free(plugin_registry);
    cytadel_port_list_free(&ports);
    cytadel_target_list_free(&target_list);
    cytadel_log_close();

    /* pool_rc != 0 means a pool-level (pthread) infrastructure failure, and
     * db_ok == false means a fatal DB error stopped persistence partway
     * through -- both distinct from "some hosts were down" or "some hosts
     * errored", which are valid scan outcomes already reflected in the
     * summary above, not a process failure. */
    return (pool_rc == 0 && db_ok) ? EXIT_SUCCESS : EXIT_FAILURE;
}
