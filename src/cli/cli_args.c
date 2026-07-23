#include "cli_args.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/core/version.h"
#include "cytadel/net/port_range.h"
#include "cytadel/net/target_list.h"

/* If argv[*i] is a flag that requires a value, consumes and returns
 * argv[*i + 1] (advancing *i), or returns NULL and prints an error if no
 * value follows. */
static const char *cytadel_cli_arg_value(int argc, char *const argv[], int *i,
                                          const char *flag_name) {
    if (*i + 1 >= argc) {
        fprintf(stderr, "cytadel-scan: error: %s requires an argument\n", flag_name);
        return NULL;
    }
    (*i)++;
    return argv[*i];
}

/* Parses a strictly positive integer in (0, max_value], rejecting
 * non-numeric input, negative/zero values, and anything that would
 * overflow long. Shared by every "positive int" flag below
 * (--connect-timeout-ms, --discovery-timeout-ms, --max-workers) so the
 * overflow/format checks live in exactly one place. Returns 0 and writes
 * *out on success, -1 (with an error already printed to stderr, using
 * `unit` to phrase it, e.g. "milliseconds" or "worker threads") otherwise. */
static int cytadel_cli_parse_positive_int(const char *flag_name, const char *val, long max_value,
                                           const char *unit, int *out) {
    errno = 0;
    char *end = NULL;
    long parsed = strtol(val, &end, 10);
    if (end == val || *end != '\0' || errno == ERANGE || parsed <= 0 || parsed > max_value) {
        fprintf(stderr,
                "cytadel-scan: error: invalid %s '%s' (expected a positive integer "
                "number of %s, max %ld)\n", flag_name, val, unit, max_value);
        return -1;
    }
    *out = (int)parsed;
    return 0;
}

/* Thin wrapper kept for the two millisecond-timeout flags -- their upper
 * bound is INT_MAX (no domain-specific ceiling), unlike --max-workers. */
static int cytadel_cli_parse_timeout_ms(const char *flag_name, const char *val, int *out_ms) {
    return cytadel_cli_parse_positive_int(flag_name, val, INT_MAX, "milliseconds", out_ms);
}

void cytadel_cli_print_usage(FILE *stream, const char *prog_name) {
    const char *name = (prog_name != NULL) ? prog_name : "cytadel-scan";
    fprintf(stream,
        "Usage: %s [OPTIONS] [<target-spec>]\n"
        "\n"
        "Cytadel Scan -- detection-only vulnerability scanner.\n"
        "\n"
        "<target-spec> and/or --targets-file must supply at least one target.\n"
        "<target-spec> accepts:\n"
        "  - a single IPv4 literal or hostname:   \"10.0.0.1\", \"example.com\"\n"
        "  - an IPv4 CIDR block:                  \"10.0.0.0/24\"\n"
        "  - a comma-separated mix of the above:  \"10.0.0.1,10.0.0.0/30,example.com\"\n"
        "A CIDR block scans every address in the block, including the network and\n"
        "broadcast addresses (no addresses are excluded); /31 and /32 scan their\n"
        "2 and 1 address(es) respectively under the same rule. The total number of\n"
        "expanded hosts across --targets-file and <target-spec> combined is capped\n"
        "at %d (CYTADEL_MAX_TARGETS) -- an oversized block (e.g. a /8) is rejected\n"
        "up front rather than scanned.\n"
        "\n"
        "Options:\n"
        "  --i-am-authorized       Confirm you are authorized to scan the target(s).\n"
        "  --authorized-by <who>   Operator identity for the authorization record\n"
        "                          (defaults to the current OS user).\n"
        "  --log-level <lvl>       One of: debug, info, warn, error (default: info).\n"
        "  --log-file <path>       Also write log output to <path>.\n"
        "  --targets-file <path>   Read additional targets from <path>, one\n"
        "                          spec per line (same grammar as <target-spec>).\n"
        "                          '#' starts a comment; blank lines are skipped.\n"
        "  --ports <spec>          Ports to scan: \"22\", \"1-1024\", \"22,80,443\", or a\n"
        "                          mix like \"1-100,8080\" (default: %s).\n"
        "  --skip-discovery        Treat every target as up without probing it first\n"
        "                          (use when hosts are known to block discovery).\n"
        "  --connect-timeout-ms <ms>\n"
        "                          Per-port TCP connect timeout in milliseconds\n"
        "                          (default: %d).\n"
        "  --discovery-timeout-ms <ms>\n"
        "                          Per-host discovery-probe timeout in milliseconds\n"
        "                          (default: %d).\n"
        "  --max-workers <n>       Maximum number of concurrent worker threads\n"
        "                          scanning hosts in parallel (default: %d, max: %d).\n"
        "  --plugins-dir <path>    Directory of *.lua detection plugins to load\n"
        "                          (default: \"plugins\"; missing default directory is\n"
        "                          not an error -- the scan just runs without plugins).\n"
        "  --no-banner             Suppress the startup ASCII-art banner (it is also\n"
        "                          suppressed automatically whenever stderr is not a\n"
        "                          terminal, e.g. redirected/piped output or CI logs).\n"
        "  --help                  Show this help text and exit.\n"
        "  --version               Show version information and exit.\n"
        "\n"
        "Milestone 3: multi-target expansion (CIDR/lists/--targets-file) scanned\n"
        "concurrently by a fixed-size worker pool.\n",
        name, CYTADEL_MAX_TARGETS, CYTADEL_DEFAULT_PORT_SPEC, CYTADEL_CLI_DEFAULT_CONNECT_TIMEOUT_MS,
        CYTADEL_CLI_DEFAULT_DISCOVERY_TIMEOUT_MS, CYTADEL_CLI_DEFAULT_MAX_WORKERS,
        CYTADEL_WORKER_POOL_HARD_CAP_WORKERS);
}

void cytadel_cli_print_version(FILE *stream) {
    fprintf(stream, "cytadel-scan %s\n", CYTADEL_VERSION_STRING);
}

cytadel_cli_parse_status_t cytadel_cli_parse_args(int argc, char *const argv[],
                                                   cytadel_cli_args_t *out_args) {
    if (out_args == NULL) {
        return CYTADEL_CLI_PARSE_ERROR;
    }

    memset(out_args, 0, sizeof(*out_args));
    out_args->log_level = CYTADEL_LOG_INFO;
    out_args->connect_timeout_ms = CYTADEL_CLI_DEFAULT_CONNECT_TIMEOUT_MS;
    out_args->discovery_timeout_ms = CYTADEL_CLI_DEFAULT_DISCOVERY_TIMEOUT_MS;
    out_args->max_workers = CYTADEL_CLI_DEFAULT_MAX_WORKERS;

    bool have_positional = false;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "--help") == 0) {
            out_args->want_help = true;
            return CYTADEL_CLI_PARSE_HELP;
        }
        if (strcmp(arg, "--version") == 0) {
            out_args->want_version = true;
            return CYTADEL_CLI_PARSE_VERSION;
        }
        if (strcmp(arg, "--i-am-authorized") == 0) {
            out_args->has_i_am_authorized = true;
            continue;
        }
        if (strcmp(arg, "--authorized-by") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--authorized-by");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->authorized_by = val;
            continue;
        }
        if (strcmp(arg, "--log-level") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--log-level");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            cytadel_log_level_t lvl;
            if (cytadel_log_level_from_string(val, &lvl) != 0) {
                fprintf(stderr,
                        "cytadel-scan: error: invalid --log-level '%s' "
                        "(expected debug, info, warn, or error)\n", val);
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->log_level = lvl;
            out_args->has_log_level = true;
            continue;
        }
        if (strcmp(arg, "--log-file") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--log-file");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->log_file = val;
            continue;
        }
        if (strcmp(arg, "--targets-file") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--targets-file");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->targets_file = val;
            continue;
        }
        if (strcmp(arg, "--ports") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--ports");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->port_spec = val;
            continue;
        }
        if (strcmp(arg, "--skip-discovery") == 0) {
            out_args->skip_discovery = true;
            continue;
        }
        if (strcmp(arg, "--connect-timeout-ms") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--connect-timeout-ms");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            int ms;
            if (cytadel_cli_parse_timeout_ms("--connect-timeout-ms", val, &ms) != 0) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->connect_timeout_ms = ms;
            out_args->has_connect_timeout_ms = true;
            continue;
        }
        if (strcmp(arg, "--discovery-timeout-ms") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--discovery-timeout-ms");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            int ms;
            if (cytadel_cli_parse_timeout_ms("--discovery-timeout-ms", val, &ms) != 0) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->discovery_timeout_ms = ms;
            out_args->has_discovery_timeout_ms = true;
            continue;
        }
        if (strcmp(arg, "--no-banner") == 0) {
            out_args->no_banner = true;
            continue;
        }
        if (strcmp(arg, "--plugins-dir") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--plugins-dir");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->plugins_dir = val;
            continue;
        }
        if (strcmp(arg, "--max-workers") == 0) {
            const char *val = cytadel_cli_arg_value(argc, argv, &i, "--max-workers");
            if (val == NULL) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            int workers;
            if (cytadel_cli_parse_positive_int("--max-workers", val,
                                                CYTADEL_WORKER_POOL_HARD_CAP_WORKERS,
                                                "worker thread(s)", &workers) != 0) {
                return CYTADEL_CLI_PARSE_ERROR;
            }
            out_args->max_workers = workers;
            out_args->has_max_workers = true;
            continue;
        }
        if (arg[0] == '-') {
            fprintf(stderr, "cytadel-scan: error: unknown option '%s'\n", arg);
            return CYTADEL_CLI_PARSE_ERROR;
        }

        /* Positional argument: the (unexpanded) target spec. Only one is
         * accepted; the actual multi-target expansion (CIDR/lists/
         * --targets-file) happens later via cytadel_target_list_parse(). */
        if (have_positional) {
            fprintf(stderr,
                    "cytadel-scan: error: unexpected extra argument '%s' "
                    "(target spec was already given as '%s')\n",
                    arg, out_args->target_spec);
            return CYTADEL_CLI_PARSE_ERROR;
        }
        out_args->target_spec = arg;
        have_positional = true;
    }

    if (!have_positional && out_args->targets_file == NULL) {
        fprintf(stderr,
                "cytadel-scan: error: missing target specification "
                "(give <target-spec> and/or --targets-file)\n");
        return CYTADEL_CLI_PARSE_ERROR;
    }

    return CYTADEL_CLI_PARSE_OK;
}
