#ifndef CYTADEL_CLI_REPORT_CMD_H
#define CYTADEL_CLI_REPORT_CMD_H

#include <stdbool.h>
#include <stdio.h>

#include "cytadel/db/db.h"
#include "cytadel/report/report.h"

/* Milestone 8 slice 5: the `cytadel-scan report` CLI subcommand. Reads an
 * already-populated vuln DB (CYTADEL_DB_PATH) and renders one scan's
 * findings as HTML or JSON -- it never scans (no packet ever leaves the
 * host), so the authorization gate does
 * NOT apply to this subcommand; main.c must route `report` to
 * cytadel_report_cmd_run() BEFORE reaching cytadel_cli_parse_args()/the
 * gate, never through them.
 *
 * Split into three independently-testable pieces (mirroring cli_args.c's
 * own "parse is pure, main.c does the I/O" split), from most to least
 * testable without a real DB/filesystem:
 *
 *   1. cytadel_report_cmd_parse_args() -- pure argv parsing, no I/O.
 *   2. cytadel_report_cmd_resolve_scan_id() / cytadel_report_cmd_render() --
 *      take an already-open cytadel_db_t*; testable against an in-memory
 *      DB exactly like tests/unit/test_report_html.c already does.
 *   3. cytadel_report_cmd_run() -- the full entry point: reads
 *      CYTADEL_DB_PATH from the environment, opens/migrates the DB, calls
 *      (1)/(2) in sequence, and writes the result to -o FILE or stdout.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_REPORT_CMD_FORMAT_HTML = 0,
    CYTADEL_REPORT_CMD_FORMAT_JSON = 1
} cytadel_report_cmd_format_t;

typedef struct {
    bool has_latest;  /* --latest */
    bool has_scan_id; /* --scan-id N */
    long long scan_id; /* only meaningful when has_scan_id is true */
    cytadel_report_cmd_format_t format; /* default: CYTADEL_REPORT_CMD_FORMAT_HTML */
    const char *output_path; /* -o FILE; NULL -> stdout. Aliases into argv, not owned. */
    bool want_help;
} cytadel_report_cmd_args_t;

typedef enum {
    CYTADEL_REPORT_CMD_PARSE_OK = 0,
    CYTADEL_REPORT_CMD_PARSE_HELP,
    CYTADEL_REPORT_CMD_PARSE_ERROR
} cytadel_report_cmd_parse_status_t;

/* Parses the `report` subcommand's own arguments. Same argc/argv convention
 * as cytadel_cli_parse_args() (cli_args.h): argv[0] is treated as this
 * subcommand's own program-name slot and is never itself inspected as a
 * flag; parsing starts at argv[1]. A caller dispatching from the top-level
 * argv (where argv[1] == "report") passes (argc - 1, argv + 1) so that,
 * from this function's point of view, argv[0] == "report" and argv[1..]
 * are the subcommand's own flags.
 *
 * On CYTADEL_REPORT_CMD_PARSE_ERROR a human-readable message has already
 * been written to stderr, covering: an unknown flag, a flag missing its
 * required value, a non-numeric/non-positive/overflowing --scan-id, an
 * unrecognized --format value, and giving both or neither of
 * --latest/--scan-id (exactly one is required). On
 * CYTADEL_REPORT_CMD_PARSE_HELP, out_args->want_help is set and the caller
 * should print usage and exit 0 without inspecting the rest of *out_args.
 * Never allocates: every string field in *out_args aliases into argv. */
cytadel_report_cmd_parse_status_t cytadel_report_cmd_parse_args(int argc, char *const argv[],
                                                                 cytadel_report_cmd_args_t *out_args);

void cytadel_report_cmd_print_usage(FILE *stream, const char *prog_name);

/* Resolves the scan_id this invocation should report on: `args->scan_id`
 * verbatim when `args->has_scan_id`, otherwise
 * cytadel_report_find_latest_scan_id(db, out_scan_id) (report.h) for
 * `--latest` (`ORDER BY started_at DESC LIMIT 1`, idx_scans_started_at).
 * A successfully-parsed *args (cytadel_report_cmd_parse_args()'s own
 * CYTADEL_REPORT_CMD_PARSE_OK contract) guarantees exactly one of
 * has_latest/has_scan_id is true -- this function does not re-validate
 * that invariant itself.
 *
 * Shares cytadel_report_status_t (report.h) with
 * cytadel_report_html()/cytadel_report_json() -- CYTADEL_REPORT_OK,
 * CYTADEL_REPORT_ERR_NOT_FOUND (only reachable via --latest against a DB
 * with zero `scans` rows; an explicit --scan-id is returned verbatim here
 * without checking existence -- that check happens naturally when
 * cytadel_report_cmd_render() below queries it), CYTADEL_REPORT_ERR_DB, or
 * CYTADEL_REPORT_ERR_INVALID_ARG for a NULL db/args/out_scan_id. `db` must
 * already be open (and migrated, for --latest to see any real rows). */
cytadel_report_status_t cytadel_report_cmd_resolve_scan_id(cytadel_db_t *db, const cytadel_report_cmd_args_t *args,
                                                            long long *out_scan_id);

/* The one-line "which renderer for which --format" dispatch, factored out
 * so it is unit-testable independent of any argv/env-var/filesystem I/O:
 * CYTADEL_REPORT_CMD_FORMAT_HTML -> cytadel_report_html(); JSON ->
 * cytadel_report_json(). Appends to `*out` (already
 * cytadel_report_buf_init()'d), same append-only contract as both of those
 * functions. */
cytadel_report_status_t cytadel_report_cmd_render(cytadel_db_t *db, long long scan_id,
                                                   cytadel_report_cmd_format_t format, cytadel_report_buf_t *out);

/* Full `report` subcommand entry point: reads CYTADEL_DB_PATH from the
 * environment (.env.example), opens+migrates that DB, resolves the scan_id
 * (cytadel_report_cmd_resolve_scan_id()), renders per `args->format`
 * (cytadel_report_cmd_render()), and writes the result to
 * `args->output_path` (or stdout when NULL). Every failure path prints a
 * clear, specific message to stderr before returning -- a missing
 * CYTADEL_DB_PATH, a DB that fails to open/migrate, a --scan-id that names
 * no row, a --latest against a DB with zero scans, and a failed output
 * write are all distinguished. Returns EXIT_SUCCESS/EXIT_FAILURE
 * (<stdlib.h>). `args` must be non-NULL. Never touches the scan
 * authorization gate (auth_gate.h) -- this subcommand only reads an
 * existing DB; no packet ever leaves the host, so the mandatory authorization-gate rule does
 * not apply here. */
int cytadel_report_cmd_run(const cytadel_report_cmd_args_t *args);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CLI_REPORT_CMD_H */
