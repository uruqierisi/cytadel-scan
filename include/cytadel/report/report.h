#ifndef CYTADEL_REPORT_REPORT_H
#define CYTADEL_REPORT_REPORT_H

#include "cytadel/db/db.h"
#include "cytadel/report/escape.h"

/* Milestone 8 slice 3: the branded HTML report generator -- the FIRST
 * caller of the four context-specific escapers (include/cytadel/report/
 * escape.h, M8 slice 1) against real `scans`/`scan_results` data. Built
 * strictly against:
 *
 *   - docs/contracts/db-schema.md SS6 (scans, incl. malformed_data_count),
 *     SS7 (scan_results incl. match_status), SS9's "Report: findings for a
 *     scan" SELECT (augmented here with `match_status` -- an additive
 *     column, same allowed shape of augmentation src/db/scan_persist.c's
 *     candidate lookup already used for `ORDER BY cve_id, id`), and SS10
 *     assumption 6 (severity/kev_flag/epss_score/match_status are
 *     POINT-IN-TIME SNAPSHOTS read straight from scan_results -- this
 *     module NEVER joins cves/kev/epss to "freshen" a value).
 *   - docs/contracts/cpe-matching.md SS3.1/SS3.3/SS6 item 4: a scan_results
 *     row whose match_status is 'undetermined' MUST render as its own
 *     distinct, operator-visible "could not determine -- manual review
 *     needed" state, and a host with any undetermined row must NEVER be
 *     described as "no vulnerabilities found".
 *
 * THREAT MODEL: every string column this module reads out of
 * `scans`/`scan_results` (host, service, evidence, remediation, cve_id,
 * target_spec, authorized_by, ...) is either fully attacker-controlled (a
 * scan target can put anything it wants in a banner the plugin layer copies
 * into `evidence`) or untrusted third-party data, and is stored RAW by
 * design (db-schema.md SS7's own `evidence` column comment: "never
 * escaped... escaping is the reporter's job"). This module is that job: NOT
 * ONE of those string fields is ever written into the output HTML without
 * going through exactly one of cytadel_escape_html_body() /
 * cytadel_escape_html_attr() / cytadel_escape_url() (belt-and-suspenders
 * with cytadel_escape_html_attr()), chosen to match the exact context the
 * value lands in -- see escape.h's own "RENDERER CONTRACT" block. Numbers
 * (port, severity, counts, epss_score) are formatted with bounded snprintf
 * and never treated as strings needing escaping, but are also never
 * produced by printf-ing a raw DB string field.
 *
 * Output is ONE self-contained HTML document (inline CSS, inline SVG
 * wordmark, no external assets) -- portable by email or by Print -> Save as
 * PDF. Every color is a CSS custom property (`--cytadel-*` / `--sev-*`) so
 * the shipped placeholder palette can be swapped for the real cytadel.eu
 * brand colors without touching any structural markup.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_REPORT_OK = 0,
    /* NULL db/out, or scan_id <= 0 -- caller bug, no DB access attempted. */
    CYTADEL_REPORT_ERR_INVALID_ARG = 1,
    /* scan_id does not name any row in `scans`. */
    CYTADEL_REPORT_ERR_NOT_FOUND = 2,
    /* A fatal (non-recoverable) sqlite3 error occurred while querying. */
    CYTADEL_REPORT_ERR_DB = 3,
    /* Allocation failure while assembling the output buffer. */
    CYTADEL_REPORT_ERR_OOM = 4
} cytadel_report_status_t;

/* Returns a static, human-readable name for `status`. Never returns NULL. */
const char *cytadel_report_status_to_string(cytadel_report_status_t status);

/* Renders the full branded HTML report for `scan_id` and APPENDS it to
 * `*out` (which must already be cytadel_report_buf_init()'d -- this
 * function never clears/reinitializes it first, mirroring every escape.h
 * function's own append-only contract; a caller rendering exactly one
 * report normally just inits an empty buf immediately before calling this).
 *
 * Queries, in order:
 *   1. The `scans` row for `scan_id` (db-schema.md SS6) -- cover-page
 *      metadata (target_spec, started_at, finished_at, authorized_by,
 *      authorization_confirmed_at, authorization_method, status) and
 *      malformed_data_count (the Gate-2 data-quality banner trigger).
 *      CYTADEL_REPORT_ERR_NOT_FOUND if no such row exists.
 *   2. Aggregate counts over `scan_results WHERE scan_id = ?`: confirmed
 *      findings by severity (0..4), confirmed+KEV, undetermined, and
 *      not_affected -- rendered in the Summary section BEFORE the
 *      per-finding detail (which is why these are separate GROUP BY/COUNT
 *      queries rather than being derived while streaming the detail query
 *      below: the summary section is emitted first in document order).
 *   3. The SS9 "findings for a scan" SELECT, augmented with the
 *      `match_status` column, `ORDER BY host, port, severity DESC` exactly
 *      as SS9 specifies -- streamed and grouped by host (rows for one host
 *      are contiguous by construction of that ORDER BY), rendering:
 *        - every 'confirmed' row as a full finding card (evidence, CVE,
 *          severity, KEV, EPSS), grouped by port within the host;
 *        - every 'undetermined' row as its own visible
 *          "could not determine -- manual review needed" record (cve_id +
 *          detected context), NEVER folded into or omitted alongside a
 *          not_affected/confirmed row for the same host;
 *        - 'not_affected' rows folded into a per-host COUNT only (audit
 *          trail), never listed individually.
 *      A host renders "no vulnerabilities found" only when BOTH its
 *      confirmed and undetermined counts are zero (cpe-matching.md SS6
 *      item 4 / SS3.3) -- a host with zero confirmed but a nonzero
 *      undetermined count instead states the confirmed=0 fact alongside
 *      the undetermined count and the manual-review call to action.
 *
 * Returns CYTADEL_REPORT_ERR_OOM if assembling the output ever fails an
 * allocation (matching escape.h's own "false only on OOM" convention) --
 * `*out` is left in whatever partial-but-valid state cytadel_report_buf_t's
 * own append functions guarantee (never a half-written escape sequence),
 * but the caller should treat a non-OK return as "discard this buffer", not
 * "salvage a partial report".
 *
 * `db` and `out` must be non-NULL; `scan_id` must be > 0. This function
 * opens no transaction of its own (read-only queries; SQLite's own default
 * read-uncommitted-within-a-connection semantics are sufficient for a
 * point-in-time report read) and does not close `db`. */
cytadel_report_status_t cytadel_report_html(cytadel_db_t *db, long long scan_id, cytadel_report_buf_t *out);

/* Milestone 8 slice 4: the JSON report generator (src/report/report_json.c)
 * -- the SAME data layer as cytadel_report_html() above (identical `scans`
 * metadata read, identical SS9 findings SELECT augmented with
 * `match_status`, identical snapshot-only discipline: severity/kev_flag/
 * epss_score/match_status are read straight from `scan_results`, this
 * module NEVER joins cves/kev/epss to "freshen" a value), rendered as ONE
 * valid JSON document instead of an HTML page:
 *
 *   {
 *     "scan": {scan_id, started_at, finished_at, target_spec, authorized_by,
 *              authorization_confirmed_at, authorization_method, status,
 *              malformed_data_count},
 *     "summary": {severity_counts (an object keyed "0".."4"), kev_count,
 *                 undetermined_count, not_affected_count, confirmed_count},
 *     "findings": [{host, port, service, plugin_id, cve_id, severity,
 *                   evidence, remediation, kev_flag, epss_score, detected_at,
 *                   match_status}, ...]
 *   }
 *
 * THREAT MODEL: identical to cytadel_report_html()'s own -- every string
 * column this module reads out of `scans`/`scan_results` is either fully
 * attacker-controlled or untrusted third-party data, stored RAW by design.
 * NOT ONE of those string fields is ever written into the output without
 * going through cytadel_escape_json() first (escape.h's Context 4). Numbers
 * (port, severity, kev_flag, malformed_data_count, every summary count) are
 * formatted with bounded snprintf as bare JSON numbers, never quoted,
 * never printf'd from a raw DB string field; epss_score is a JSON number
 * when present, JSON `null` when the column is SQL NULL. A NULL nullable
 * string column (finished_at, service, cve_id, remediation) is rendered as
 * JSON `null`, never an empty string or an omitted key -- a JSON consumer
 * must be able to tell "absent" from "empty" for every one of these.
 *
 * `match_status` is included VERBATIM per finding, exactly as stored
 * ('confirmed' / 'undetermined' / 'not_affected') -- cpe-matching.md
 * SS3.1/SS3.3/SS6 item 4's "never coerce an unclear verdict" rule applies
 * here exactly as it does to cytadel_report_html(): an 'undetermined' row
 * is never folded into or omitted alongside a not_affected/confirmed
 * finding for the same host.
 *
 * RENDERER OBLIGATION (escape.h's own json() comment, repeated here because
 * this is the ONE call site that matters): this function's output is safe
 * ONLY as a standalone JSON response/file -- exactly how `--format json`
 * (Milestone 8 slice 5) delivers it. It MUST NOT be inlined into an HTML
 * `<script>` block by any future caller without that caller additionally
 * escaping `<` first; this function itself does not do that (json()
 * deliberately leaves `<` untouched per RFC 8259, and this module never
 * second-guesses that contract).
 *
 * Same OOM/DB/NOT_FOUND/INVALID_ARG contract as cytadel_report_html():
 * `db` and `out` must be non-NULL, `scan_id` must be > 0, `*out` is only
 * ever appended to (never cleared first), and a non-OK return means
 * "discard this buffer", not "salvage a partial document". This function
 * opens no transaction of its own and does not close `db`. */
cytadel_report_status_t cytadel_report_json(cytadel_db_t *db, long long scan_id, cytadel_report_buf_t *out);

/* Milestone 8 slice 5 (the `cytadel-scan report --latest` CLI path):
 * resolves the most recently STARTED scan's scan_id via db-schema.md SS6's
 * own `idx_scans_started_at` index (`SELECT scan_id FROM scans ORDER BY
 * started_at DESC LIMIT 1`) -- the exact query db-schema.md SS6's own
 * rationale for that index names as its purpose. Kept in src/report (not
 * src/cli) so no translation unit outside src/db and src/report ever needs
 * to `#include <sqlite3.h>` directly or hand-write a query against this
 * schema -- src/cli's report subcommand only ever calls typed entry points.
 *
 * CYTADEL_REPORT_ERR_NOT_FOUND iff the `scans` table has zero rows (there is
 * no "most recent scan" to report on yet) -- distinct from
 * cytadel_report_html()/cytadel_report_json()'s own NOT_FOUND (which means
 * "this specific scan_id does not exist"); both share the same enum value
 * because both mean exactly "nothing to render", never a DB-level failure.
 *
 * `db` and `out_scan_id` must be non-NULL (CYTADEL_REPORT_ERR_INVALID_ARG
 * otherwise, *out_scan_id left unset). On any non-OK return, *out_scan_id is
 * left unset -- callers must not read it. */
cytadel_report_status_t cytadel_report_find_latest_scan_id(cytadel_db_t *db, long long *out_scan_id);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_REPORT_REPORT_H */
