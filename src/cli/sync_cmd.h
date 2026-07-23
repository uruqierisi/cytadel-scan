#ifndef CYTADEL_CLI_SYNC_CMD_H
#define CYTADEL_CLI_SYNC_CMD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "cytadel/db/db.h"
#include "cytadel/db/nvd_catchup.h"
#include "cytadel/net/nvd_fetch.h"

/* M9 Phase 4a: the `cytadel-scan sync` CLI subcommand -- the first real
 * caller of the already-built NVD delta-sync driver
 * (include/cytadel/db/nvd_catchup.h). This wires that library up to a
 * command a scheduled timer (a later phase) can invoke; it does not add any
 * new sync logic of its own beyond resolving this one invocation's inputs
 * and reporting the result.
 *
 * DETECTION-ONLY NOTE (the detection-only rule): this subcommand's only network
 * activity is outbound HTTPS from this host to the public NVD CVE API, to
 * update this tool's OWN local vulnerability database -- it never sends a
 * single packet to, or inspects, any operator-specified target. That is why
 * it is dispatched (main.c) BEFORE the mandatory scan-authorization gate
 * (the mandatory authorization-gate rule), exactly like the read-only `report` subcommand
 * (report_cmd.h) is: the gate exists to authorize scanning a target, and
 * `sync` never does that.
 *
 * Split into small, independently-testable pieces, mirroring report_cmd.h's
 * own "parse is pure, the entry point does the I/O" split:
 *
 *   1. cytadel_sync_cmd_parse_args() -- pure argv parsing, no I/O.
 *   2. cytadel_sync_cmd_resolve_db_path() -- --db vs. the CYTADEL_DB_PATH
 *      environment variable, no filesystem access of its own.
 *   3. cytadel_sync_cmd_resolve_now() -- --now vs. the real wall-clock UTC
 *      "now" this invocation should catch up to. Unlike
 *      report_cmd_resolve_scan_id()/cytadel_report_cmd_render() (which
 *      genuinely need an already-open DB to query), building the fetch
 *      config and resolving `now` need no DB access at all, so neither this
 *      function nor cytadel_sync_cmd_build_fetch_config() below takes a
 *      cytadel_db_t* -- there is nothing for either to read from one.
 *   4. cytadel_sync_cmd_build_fetch_config() -- production defaults plus
 *      the one documented override this command honors (the API base URL).
 *      This never reads, logs, or otherwise touches the NVD API key itself
 *      -- that stays exactly where include/cytadel/net/nvd_fetch.h already
 *      puts it, read from its own environment variable strictly inside
 *      nvd_fetch.c, once per fetch attempt, and this command has no reason
 *      to duplicate or intercept that.
 *   5. cytadel_sync_cmd_run() -- the full entry point: resolves (2) and
 *      (3)/(4), opens+migrates the DB (mandatory -- same posture as
 *      `report`/the scan path: a writable DB is required, refusing cleanly
 *      otherwise), calls cytadel_nvd_catchup(), and prints a human summary.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    const char *db_path;      /* --db PATH; NULL -> resolve from CYTADEL_DB_PATH env.
                                * Aliases into argv, not owned. */
    const char *now_override; /* --now ISO8601; NULL -> real wall-clock UTC now.
                                * Aliases into argv, not owned. */
    bool want_help;
} cytadel_sync_cmd_args_t;

typedef enum {
    CYTADEL_SYNC_CMD_PARSE_OK = 0,
    CYTADEL_SYNC_CMD_PARSE_HELP,
    CYTADEL_SYNC_CMD_PARSE_ERROR
} cytadel_sync_cmd_parse_status_t;

/* Parses the `sync` subcommand's own arguments. Same argc/argv convention as
 * cytadel_report_cmd_parse_args() (report_cmd.h): argv[0] is this
 * subcommand's own program-name slot (never itself inspected as a flag);
 * parsing starts at argv[1]. A caller dispatching from the top-level argv
 * (where argv[1] == "sync") passes (argc - 1, argv + 1).
 *
 * Recognizes: --db <PATH>, --now <ISO8601>, -h/--help. On
 * CYTADEL_SYNC_CMD_PARSE_ERROR a human-readable message has already been
 * written to stderr (an unknown flag, or a flag missing its required
 * value). On CYTADEL_SYNC_CMD_PARSE_HELP, out_args->want_help is set and
 * the caller should print usage and exit 0 without inspecting the rest of
 * *out_args. Never allocates: every string field in *out_args aliases into
 * argv. Returns CYTADEL_SYNC_CMD_PARSE_ERROR (without dereferencing argv)
 * if out_args is NULL. */
cytadel_sync_cmd_parse_status_t cytadel_sync_cmd_parse_args(int argc, char *const argv[],
                                                             cytadel_sync_cmd_args_t *out_args);

void cytadel_sync_cmd_print_usage(FILE *stream, const char *prog_name);

/* Resolves which DB path this invocation should use: args->db_path if
 * non-NULL/non-empty, else the CYTADEL_DB_PATH environment variable if
 * non-empty, else neither is available. Returns true and writes
 * *out_db_path (a borrowed pointer -- into argv or into the environment
 * block, valid for the life of the process either way; never owned by the
 * caller) on success; returns false (leaving *out_db_path untouched, no
 * message printed -- that is cytadel_sync_cmd_run()'s job) when neither
 * source names a path, or when args/out_db_path is NULL. */
bool cytadel_sync_cmd_resolve_db_path(const cytadel_sync_cmd_args_t *args, const char **out_db_path);

/* Resolves the `now` timestamp this invocation's cytadel_nvd_catchup() call
 * will catch up to: args->now_override verbatim (borrowed -- *out_now then
 * aliases into argv, out_wallclock_buf is left untouched) when it is
 * non-NULL/non-empty, so a test (or an operator backfilling/replaying a
 * past window) can fully control it; otherwise the real current wall-clock
 * time, formatted as strict ISO-8601 UTC via
 * cytadel_log_format_timestamp_utc() (log.h) into out_wallclock_buf, with
 * *out_now then pointing at out_wallclock_buf. This is the one place this
 * command ever reads the system clock -- every other layer beneath it
 * (cytadel_nvd_catchup() and everything it calls) takes `now` purely as a
 * parameter, per that module's own "DETERMINISTIC now" contract.
 *
 * out_wallclock_buf must be non-NULL and at least CYTADEL_ISO8601_BUF_LEN
 * bytes (log.h) -- needed only on the wall-clock branch, but required
 * unconditionally so this function's own behavior does not silently change
 * shape based on whether --now happened to be given. Returns true on
 * success; false if args/out_now is NULL, out_wallclock_buf is too small,
 * or the wall-clock read itself fails. This function does not itself
 * validate args->now_override's ISO-8601 *shape* beyond non-empty --
 * cytadel_nvd_catchup() already performs that check and returns a clean,
 * typed error for a malformed value; duplicating it here would only be two
 * places that could disagree. */
bool cytadel_sync_cmd_resolve_now(const cytadel_sync_cmd_args_t *args, char *out_wallclock_buf,
                                   size_t out_wallclock_buf_len, const char **out_now);

/* Builds this invocation's cytadel_nvd_fetch_config_t: starts from
 * cytadel_nvd_fetch_config_init_default()'s production defaults (timeouts,
 * retry/backoff, result-page size, CA bundle path), then overrides
 * base_url from the CYTADEL_NVD_API_URL environment variable when it is
 * set and non-empty (.env.example's documented override point for mirroring
 * the feed internally) -- otherwise the compiled-in default
 * (CYTADEL_NVD_FETCH_DEFAULT_BASE_URL) stands. *out_cfg->base_url* then
 * borrows either the environment block's storage or the compiled-in string
 * literal -- never a copy this function owns. No-op if out_cfg is NULL. */
void cytadel_sync_cmd_build_fetch_config(cytadel_nvd_fetch_config_t *out_cfg);

/* Full `sync` subcommand entry point: resolves the DB path
 * (cytadel_sync_cmd_resolve_db_path()) -- a writable DB is MANDATORY, same
 * posture as `report`/the scan path, refusing cleanly with no DB access
 * attempted at all when neither --db nor CYTADEL_DB_PATH names one -- then
 * opens+migrates it, builds the fetch config
 * (cytadel_sync_cmd_build_fetch_config()), resolves `now`
 * (cytadel_sync_cmd_resolve_now()), and calls cytadel_nvd_catchup()
 * (nvd_catchup.h). Prints a human-readable summary (windows completed,
 * pages fetched, CVEs ingested/skipped) to stdout, and either a resulting
 * watermark line (also stdout, on success) or a specific error message
 * (stderr, non-zero exit) -- every failure path is distinguished: DB
 * open/migrate failure, a clock-read failure resolving `now`, and every
 * cytadel_nvd_catchup_status_t this call can return.
 *
 * Every failure path here happens strictly BEFORE any network I/O -- the
 * DB is opened/migrated first -- except for cytadel_nvd_catchup() failures
 * themselves, whose own network-facing behavior (retries, timeouts,
 * transport/auth/rate-limit/server-error handling) is entirely
 * nvd_fetch.c's/nvd_sync.c's responsibility, already covered by their own
 * test suites; this function does not re-implement or re-test any of that.
 *
 * Returns EXIT_SUCCESS/EXIT_FAILURE (<stdlib.h>). `args` must be non-NULL.
 * Never touches the scan authorization gate (auth_gate.h) -- see this
 * header's top-of-file "DETECTION-ONLY NOTE". */
int cytadel_sync_cmd_run(const cytadel_sync_cmd_args_t *args);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CLI_SYNC_CMD_H */
