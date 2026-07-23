#include "cytadel/report/report.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "log.h"

/* Milestone 8 slice 4: see include/cytadel/report/report.h's own
 * cytadel_report_json() comment for the full design/contract. This comment
 * covers implementation details only -- it deliberately mirrors
 * report_html.c's own data layer (identical `scans` metadata read,
 * identical SS9 findings SELECT, identical snapshot-only discipline: no
 * live join to cves/kev/epss) while rendering JSON instead of HTML.
 *
 * ESCAPER CALL-SITE INVENTORY (every place a scan_results/scans string field
 * is written into the output; grep `cytadel_escape_json` in this file for
 * the exhaustive, literal list this comment summarizes):
 *
 *   scans.started_at, .finished_at, .target_spec, .authorized_by,
 *   .authorization_confirmed_at, .authorization_method, .status
 *   (render_scan_object(), all via append_json_string_col());
 *   scan_results.host, .service, .plugin_id, .cve_id, .evidence,
 *   .remediation, .detected_at, .match_status (render_findings_array(), all
 *   via append_json_string_col()).
 *
 *   NEVER escaped / not a scan_results-or-scans string field: scan_id, port,
 *   severity, kev_flag, epss_score, malformed_data_count, and every summary
 *   count are formatted with bounded snprintf (append_int_lit()/
 *   append_double_lit()) or emitted as a JSON boolean literal
 *   (append_json_bool_field()) -- never a printf of a raw string field.
 *   JSON object KEY names ("scan", "started_at", "port", ...) are this
 *   module's OWN fixed C-string literals, appended verbatim via
 *   cytadel_report_buf_append_lit() -- never derived from DB data.
 *
 * NO STREAMING BUFFER OF ROWS is needed here (unlike report_html.c's
 * finding_row_t array, which exists solely to support that module's
 * "decide the whole host's clean/undetermined-only banner before rendering
 * any of its findings" logic): a JSON findings array has no such
 * whole-group decision to make, so each `scan_results` row is read,
 * escaped, and appended to *out in full before the next sqlite3_step() call
 * -- sqlite3_column_text()/_bytes()'s "valid only until the next step()"
 * lifetime rule is satisfied by construction, with no need to copy any
 * column out to a caller-owned buffer first. */

/* --------------------------------------------------------------------- */
/* Small formatting helpers -- numbers/booleans only, never a raw string   */
/* field. Mirrors report_html.c's own append_int_lit()/append_epss_lit(),  */
/* duplicated here (not shared) so this module has no compile-time         */
/* dependency on report_html.c's internals.                                */
/* --------------------------------------------------------------------- */

static bool append_int_lit(cytadel_report_buf_t *out, long long v) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lld", v);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return false;
    }
    return cytadel_report_buf_append_lit(out, buf);
}

static bool append_double_lit(cytadel_report_buf_t *out, double v) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%.4f", v);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return false;
    }
    return cytadel_report_buf_append_lit(out, buf);
}

/* --------------------------------------------------------------------- */
/* JSON field helpers. Every one of these appends `"key":value` and,       */
/* iff `comma` is true, a trailing `,` -- callers pass `comma = false` for */
/* the last field of an object exactly once per object below, mirroring   */
/* report_html.c's own append_meta_row()-style "one call per field, fixed  */
/* order" convention.                                                     */
/* --------------------------------------------------------------------- */

static bool append_json_key(cytadel_report_buf_t *out, const char *key) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "\"");
    ok = ok && cytadel_report_buf_append_lit(out, key); /* trusted literal key name, never DB data */
    ok = ok && cytadel_report_buf_append_lit(out, "\":");
    return ok;
}

static bool append_json_int_field(cytadel_report_buf_t *out, const char *key, long long value, bool comma) {
    bool ok = append_json_key(out, key);
    ok = ok && append_int_lit(out, value);
    if (comma) {
        ok = ok && cytadel_report_buf_append_lit(out, ",");
    }
    return ok;
}

static bool append_json_bool_field(cytadel_report_buf_t *out, const char *key, bool value, bool comma) {
    bool ok = append_json_key(out, key);
    ok = ok && cytadel_report_buf_append_lit(out, value ? "true" : "false");
    if (comma) {
        ok = ok && cytadel_report_buf_append_lit(out, ",");
    }
    return ok;
}

/* Reads column `col` of the CURRENT row of `stmt` and appends `"key":null`
 * (column is SQL NULL) or `"key":"<escaped>"` (via cytadel_escape_json(),
 * reading sqlite3_column_bytes() -- never strlen(), never assuming the
 * value is NUL-clean). Used for every `scans`/`scan_results` TEXT column
 * this module emits, nullable or not -- a non-nullable column simply never
 * takes the NULL branch. */
static bool append_json_string_col(cytadel_report_buf_t *out, const char *key, sqlite3_stmt *stmt, int col,
                                     bool comma) {
    bool ok = append_json_key(out, key);
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        ok = ok && cytadel_report_buf_append_lit(out, "null");
    } else {
        const unsigned char *text = sqlite3_column_text(stmt, col);
        int bytes = sqlite3_column_bytes(stmt, col);
        size_t len = (bytes > 0) ? (size_t)bytes : 0;
        ok = ok && cytadel_report_buf_append_lit(out, "\"");
        ok = ok && cytadel_escape_json(out, (const char *)text, len);
        ok = ok && cytadel_report_buf_append_lit(out, "\"");
    }
    if (comma) {
        ok = ok && cytadel_report_buf_append_lit(out, ",");
    }
    return ok;
}

/* Same NULL-aware shape as append_json_string_col(), for `epss_score`
 * (the one nullable REAL column this module emits): `"key":null` or a
 * bounded-snprintf JSON number. */
static bool append_json_double_or_null_col(cytadel_report_buf_t *out, const char *key, sqlite3_stmt *stmt, int col,
                                             bool comma) {
    bool ok = append_json_key(out, key);
    if (sqlite3_column_type(stmt, col) == SQLITE_NULL) {
        ok = ok && cytadel_report_buf_append_lit(out, "null");
    } else {
        ok = ok && append_double_lit(out, sqlite3_column_double(stmt, col));
    }
    if (comma) {
        ok = ok && cytadel_report_buf_append_lit(out, ",");
    }
    return ok;
}

/* cpe-matching.md SS3.1/SS3.3/SS6 item 4: match_status is emitted VERBATIM
 * (append_json_string_col() above), never coerced/omitted. This is purely
 * a data-quality WARN for an operator if the schema's own three-value CHECK
 * constraint were ever somehow bypassed -- it never changes what gets
 * emitted, unlike report_html.c's classify_match_status() (which HAS to
 * pick a rendering bucket; this module has no such bucketing to do). */
static void warn_if_unrecognized_match_status(const char *text, size_t len) {
    static const char *const known[] = {"confirmed", "undetermined", "not_affected"};
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        size_t known_len = strlen(known[i]);
        if (len == known_len && (len == 0 || memcmp(text, known[i], known_len) == 0)) {
            return;
        }
    }
    cytadel_log_warn(
        "report: scan_results.match_status has an unrecognized value '%.*s' in the JSON report -- "
        "emitted verbatim regardless (never coerced/omitted)",
        (int)len, text);
}

/* --------------------------------------------------------------------- */
/* "scan" object: scans row (cover metadata + the Gate-2 malformed count). */
/* --------------------------------------------------------------------- */

static cytadel_report_status_t render_scan_object(sqlite3 *handle, long long scan_id, cytadel_report_buf_t *out) {
    static const char *const sql =
        "SELECT started_at, finished_at, target_spec, authorized_by, authorization_confirmed_at, "
        "authorization_method, status, malformed_data_count FROM scans WHERE scan_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing JSON scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_REPORT_ERR_DB;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding JSON scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        cytadel_log_warn("report: no scans row found for scan_id=%lld (JSON report)", scan_id);
        return CYTADEL_REPORT_ERR_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        cytadel_log_error("report: stepping JSON scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "\"scan\":{");
    ok = ok && append_json_int_field(out, "scan_id", scan_id, true);
    ok = ok && append_json_string_col(out, "started_at", stmt, 0, true);
    ok = ok && append_json_string_col(out, "finished_at", stmt, 1, true);
    ok = ok && append_json_string_col(out, "target_spec", stmt, 2, true);
    ok = ok && append_json_string_col(out, "authorized_by", stmt, 3, true);
    ok = ok && append_json_string_col(out, "authorization_confirmed_at", stmt, 4, true);
    ok = ok && append_json_string_col(out, "authorization_method", stmt, 5, true);
    ok = ok && append_json_string_col(out, "status", stmt, 6, true);
    long long malformed = sqlite3_column_int64(stmt, 7);
    ok = ok && append_json_int_field(out, "malformed_data_count", malformed, false);
    ok = ok && cytadel_report_buf_append_lit(out, "}");

    sqlite3_finalize(stmt);
    return ok ? CYTADEL_REPORT_OK : CYTADEL_REPORT_ERR_OOM;
}

/* --------------------------------------------------------------------- */
/* "summary" object: aggregate counts (own queries, same shape as          */
/* report_html.c's report_counts_t, plus confirmed_count -- the JSON        */
/* shape's own explicit total, derived here as the sum of severity_counts   */
/* rather than a 5th query since it is the exact same population).         */
/* --------------------------------------------------------------------- */

typedef struct {
    long long severity_counts[5]; /* confirmed findings only, index 0..4 */
    long long kev_count;          /* confirmed findings with kev_flag = 1 */
    long long undetermined_count;
    long long not_affected_count;
    long long confirmed_count; /* sum of severity_counts[0..4] */
} json_report_counts_t;

static bool count_where(sqlite3 *handle, const char *sql, long long scan_id, long long *out_count) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing a JSON summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return false;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding a JSON summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return false;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cytadel_log_error("report: stepping a JSON summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return false;
    }
    *out_count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return true;
}

static bool load_counts(sqlite3 *handle, long long scan_id, json_report_counts_t *counts) {
    for (int i = 0; i < 5; i++) {
        counts->severity_counts[i] = 0;
    }

    static const char *const severity_sql =
        "SELECT severity, COUNT(*) FROM scan_results WHERE scan_id = ? AND match_status = 'confirmed' "
        "GROUP BY severity;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, severity_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing JSON severity-count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return false;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding JSON severity-count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return false;
    }
    for (;;) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            cytadel_log_error("report: stepping JSON severity-count query failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            sqlite3_finalize(stmt);
            return false;
        }
        int severity = sqlite3_column_int(stmt, 0);
        long long count = sqlite3_column_int64(stmt, 1);
        if (severity >= 0 && severity <= 4) {
            counts->severity_counts[severity] = count;
        } else {
            cytadel_log_warn(
                "report: scan_results.severity %d is out of [0,4] while summarizing the JSON report -- ignored",
                severity);
        }
    }
    sqlite3_finalize(stmt);

    counts->confirmed_count = 0;
    for (int i = 0; i < 5; i++) {
        counts->confirmed_count += counts->severity_counts[i];
    }

    if (!count_where(handle,
                      "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND match_status = 'confirmed' "
                      "AND kev_flag = 1;",
                      scan_id, &counts->kev_count)) {
        return false;
    }
    if (!count_where(handle, "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND match_status = 'undetermined';",
                      scan_id, &counts->undetermined_count)) {
        return false;
    }
    if (!count_where(handle, "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND match_status = 'not_affected';",
                      scan_id, &counts->not_affected_count)) {
        return false;
    }
    return true;
}

static bool render_summary_object(cytadel_report_buf_t *out, const json_report_counts_t *counts) {
    static const char *const sev_keys[5] = {"0", "1", "2", "3", "4"};

    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "\"summary\":{\"severity_counts\":{");
    for (int s = 0; s < 5 && ok; s++) {
        ok = ok && append_json_int_field(out, sev_keys[s], counts->severity_counts[s], s < 4);
    }
    ok = ok && cytadel_report_buf_append_lit(out, "},");
    ok = ok && append_json_int_field(out, "kev_count", counts->kev_count, true);
    ok = ok && append_json_int_field(out, "undetermined_count", counts->undetermined_count, true);
    ok = ok && append_json_int_field(out, "not_affected_count", counts->not_affected_count, true);
    ok = ok && append_json_int_field(out, "confirmed_count", counts->confirmed_count, false);
    ok = ok && cytadel_report_buf_append_lit(out, "}");
    return ok;
}

/* --------------------------------------------------------------------- */
/* "findings" array: the SS9 SELECT, augmented with match_status, streamed */
/* row-by-row -- no whole-array buffering needed (see this file's top       */
/* comment for why report_html.c's finding_row_t buffering does not apply   */
/* here).                                                                   */
/* --------------------------------------------------------------------- */

static cytadel_report_status_t render_findings_array(sqlite3 *handle, long long scan_id, cytadel_report_buf_t *out) {
    static const char *const sql =
        "SELECT host, port, service, plugin_id, cve_id, severity, evidence, remediation, kev_flag, "
        "epss_score, detected_at, match_status "
        "FROM scan_results WHERE scan_id = ? ORDER BY host, port, severity DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing JSON findings query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_REPORT_ERR_DB;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding JSON findings query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    bool ok = cytadel_report_buf_append_lit(out, "\"findings\":[");
    bool first = true;
    cytadel_report_status_t status = CYTADEL_REPORT_OK;

    for (;;) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            cytadel_log_error("report: stepping JSON findings query failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            status = CYTADEL_REPORT_ERR_DB;
            break;
        }

        if (!first) {
            ok = ok && cytadel_report_buf_append_lit(out, ",");
        }
        first = false;

        ok = ok && cytadel_report_buf_append_lit(out, "{");
        ok = ok && append_json_string_col(out, "host", stmt, 0, true);
        ok = ok && append_json_int_field(out, "port", sqlite3_column_int(stmt, 1), true);
        ok = ok && append_json_string_col(out, "service", stmt, 2, true);
        ok = ok && append_json_string_col(out, "plugin_id", stmt, 3, true);
        ok = ok && append_json_string_col(out, "cve_id", stmt, 4, true);
        ok = ok && append_json_int_field(out, "severity", sqlite3_column_int(stmt, 5), true);
        ok = ok && append_json_string_col(out, "evidence", stmt, 6, true);
        ok = ok && append_json_string_col(out, "remediation", stmt, 7, true);
        ok = ok && append_json_bool_field(out, "kev_flag", sqlite3_column_int(stmt, 8) != 0, true);
        ok = ok && append_json_double_or_null_col(out, "epss_score", stmt, 9, true);
        ok = ok && append_json_string_col(out, "detected_at", stmt, 10, true);

        {
            const unsigned char *ms_text = sqlite3_column_text(stmt, 11);
            int ms_bytes = sqlite3_column_bytes(stmt, 11);
            size_t ms_len = (ms_bytes > 0) ? (size_t)ms_bytes : 0;
            warn_if_unrecognized_match_status((const char *)ms_text, ms_len);
        }
        /* match_status: VERBATIM, never coerced/omitted -- see this file's
         * top comment and warn_if_unrecognized_match_status()'s own
         * comment. Last field of the object -> no trailing comma. */
        ok = ok && append_json_string_col(out, "match_status", stmt, 11, false);
        ok = ok && cytadel_report_buf_append_lit(out, "}");

        if (!ok) {
            status = CYTADEL_REPORT_ERR_OOM;
            break;
        }
    }

    sqlite3_finalize(stmt);

    if (status != CYTADEL_REPORT_OK) {
        return status;
    }
    if (!ok) {
        return CYTADEL_REPORT_ERR_OOM;
    }
    if (!cytadel_report_buf_append_lit(out, "]")) {
        return CYTADEL_REPORT_ERR_OOM;
    }
    return CYTADEL_REPORT_OK;
}

/* --------------------------------------------------------------------- */
/* Public entry point.                                                     */
/* --------------------------------------------------------------------- */

cytadel_report_status_t cytadel_report_json(cytadel_db_t *db, long long scan_id, cytadel_report_buf_t *out) {
    if (db == NULL || out == NULL || scan_id <= 0) {
        cytadel_log_error(
            "report: cytadel_report_json() called with a NULL db/out or a non-positive scan_id (%lld)", scan_id);
        return CYTADEL_REPORT_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    if (!cytadel_report_buf_append_lit(out, "{")) {
        return CYTADEL_REPORT_ERR_OOM;
    }

    cytadel_report_status_t status = render_scan_object(handle, scan_id, out);
    if (status != CYTADEL_REPORT_OK) {
        return status;
    }
    if (!cytadel_report_buf_append_lit(out, ",")) {
        return CYTADEL_REPORT_ERR_OOM;
    }

    json_report_counts_t counts;
    memset(&counts, 0, sizeof(counts));
    if (!load_counts(handle, scan_id, &counts)) {
        return CYTADEL_REPORT_ERR_DB;
    }
    if (!render_summary_object(out, &counts)) {
        return CYTADEL_REPORT_ERR_OOM;
    }
    if (!cytadel_report_buf_append_lit(out, ",")) {
        return CYTADEL_REPORT_ERR_OOM;
    }

    status = render_findings_array(handle, scan_id, out);
    if (status != CYTADEL_REPORT_OK) {
        return status;
    }

    if (!cytadel_report_buf_append_lit(out, "}")) {
        return CYTADEL_REPORT_ERR_OOM;
    }
    return CYTADEL_REPORT_OK;
}
