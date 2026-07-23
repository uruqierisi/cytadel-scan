#include "cytadel/report/report.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "logo_data_uri.h" /* CYTADEL_LOGO_DATA_URI -- generated, see assets/brand/make-logo-datauri.py */

/* Milestone 8 slice 3: see include/cytadel/report/report.h for the full
 * design/contract this file implements. This comment covers implementation
 * details only.
 *
 * ESCAPER CALL-SITE INVENTORY (every place a scan_results/scans string field
 * is written into the output; grep `cytadel_escape_` in this file for the
 * exhaustive, literal list this comment summarizes):
 *
 *   BODY  (cytadel_escape_html_body): scans.target_spec, .authorized_by,
 *     .authorization_confirmed_at, .authorization_method, .status,
 *     .started_at, .finished_at (cover table); scan_results.host (host
 *     heading), .service (port heading / undetermined port line),
 *     .evidence (finding body), .remediation, .detected_at, .plugin_id,
 *     .cve_id (as the NVD link's visible text, and as the undetermined
 *     card's heading text).
 *   ATTR  (cytadel_escape_html_attr): scan_results.host (the host-block's
 *     data-host="..." attribute -- a SECOND, attribute-context use of the
 *     same field already rendered via BODY above), .evidence (the finding
 *     card's title="..." tooltip -- a second, attribute-context use of the
 *     same field already rendered via BODY), .plugin_id (data-plugin-id=
 *     "..."), .cve_id (the NVD link's title="..." attribute).
 *   URL+ATTR (cytadel_escape_url() then cytadel_escape_html_attr(), per
 *     escape.h's belt-and-suspenders rule): scan_results.cve_id as the NVD
 *     detail link's href="..." value (append_nvd_href_attr() below).
 *   NEVER escaped / not a scan_results-or-scans string field: severity,
 *   port, kev_flag, epss_score, malformed_data_count, and every summary
 *   count are formatted with bounded snprintf (append_int_lit()/
 *   append_epss_lit()) and appended as plain digit/'.'/'-' text -- never a
 *   printf of a raw string field. severity_label()/match-status labels are
 *   this module's OWN fixed C-string literals (never the raw DB text),
 *   appended verbatim as trusted template text, same as every literal HTML
 *   tag/class name in this file.
 *
 * NOT ONE scan_results/scans TEXT column is ever appended via
 * cytadel_report_buf_append_lit() (the "trusted literal only" function) --
 * every dynamic string value above goes through html_body or html_attr (or
 * both, url() first for the one href).
 */

/* --------------------------------------------------------------------- */
/* Small formatting helpers -- numbers only, never a raw string field.    */
/* --------------------------------------------------------------------- */

static bool append_int_lit(cytadel_report_buf_t *out, long long v) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%lld", v);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return false;
    }
    return cytadel_report_buf_append_lit(out, buf);
}

static bool append_epss_lit(cytadel_report_buf_t *out, double v) {
    char buf[32];
    int n = snprintf(buf, sizeof(buf), "%.4f", v);
    if (n < 0 || (size_t)n >= sizeof(buf)) {
        return false;
    }
    return cytadel_report_buf_append_lit(out, buf);
}

/* Trusted, fixed literals -- never derived from a DB text column. */
static const char *severity_label(int severity) {
    switch (severity) {
        case 0: return "Info";
        case 1: return "Low";
        case 2: return "Medium";
        case 3: return "High";
        case 4: return "Critical";
        default: return "Unknown";
    }
}

/* --------------------------------------------------------------------- */
/* Per-CVE match_status classification (db-schema.md SS7 / cpe-matching.md */
/* SS3.1). Classified defensively: an unrecognized value (should be        */
/* impossible given the schema's own CHECK constraint) is NEVER coerced to */
/* confirmed or not_affected -- cpe-matching.md SS3.2's prohibition on     */
/* ever silently resolving an unclear verdict either way -- it is treated  */
/* as needing manual review, the same as a genuine 'undetermined' row.    */
/* --------------------------------------------------------------------- */

typedef enum {
    FINDING_CONFIRMED,
    FINDING_UNDETERMINED,
    FINDING_NOT_AFFECTED
} finding_status_t;

static bool text_eq_lit(const char *text, size_t len, const char *lit) {
    size_t lit_len = strlen(lit);
    return len == lit_len && (len == 0 || memcmp(text, lit, lit_len) == 0);
}

static finding_status_t classify_match_status(const char *text, size_t len) {
    if (text_eq_lit(text, len, "confirmed")) {
        return FINDING_CONFIRMED;
    }
    if (text_eq_lit(text, len, "not_affected")) {
        return FINDING_NOT_AFFECTED;
    }
    if (text_eq_lit(text, len, "undetermined")) {
        return FINDING_UNDETERMINED;
    }
    cytadel_log_warn(
        "report: scan_results.match_status has an unrecognized value '%.*s' -- treating as "
        "undetermined (manual review needed), never confirmed/not_affected",
        (int)len, text);
    return FINDING_UNDETERMINED;
}

/* --------------------------------------------------------------------- */
/* Column-copy helper: sqlite3_column_text()/_bytes() pointers are only    */
/* valid until the NEXT sqlite3_step() on the same statement, but this     */
/* module buffers every row of a host group before rendering any of it    */
/* (so the "clean host" / "confirmed vs undetermined" decision can be made */
/* with the whole group in hand) -- every text column must therefore be   */
/* copied out immediately, not read lazily later. Copies EXACTLY the      */
/* column's byte length (sqlite3_column_bytes()), never strlen() -- a      */
/* value is never assumed NUL-clean. Always allocates (even a 0-length    */
/* value gets a 1-byte "\0" buffer) so free() is always safe to call      */
/* unconditionally on every field this touches. Returns false ONLY on     */
/* allocation failure, in which case *out_ptr is left UNTOUCHED (caller    */
/* must not free it -- mirrors escape.h's own "never write half a result" */
/* convention). */
static bool dup_column(sqlite3_stmt *stmt, int col, char **out_ptr, size_t *out_len, bool *out_has) {
    bool has = sqlite3_column_type(stmt, col) != SQLITE_NULL;
    const unsigned char *text = NULL;
    size_t len = 0;
    if (has) {
        text = sqlite3_column_text(stmt, col);
        int bytes = sqlite3_column_bytes(stmt, col);
        len = (bytes > 0) ? (size_t)bytes : 0;
    }
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        return false;
    }
    if (len > 0) {
        memcpy(copy, text, len);
    }
    copy[len] = '\0';
    *out_ptr = copy;
    *out_len = len;
    if (out_has != NULL) {
        *out_has = has;
    }
    return true;
}

/* --------------------------------------------------------------------- */
/* scans row (cover-page metadata + the Gate-2 malformed_data_count).      */
/* --------------------------------------------------------------------- */

typedef struct {
    char *started_at;
    size_t started_at_len;
    char *finished_at;
    size_t finished_at_len;
    bool has_finished_at;
    char *target_spec;
    size_t target_spec_len;
    char *authorized_by;
    size_t authorized_by_len;
    char *authorization_confirmed_at;
    size_t authorization_confirmed_at_len;
    char *authorization_method;
    size_t authorization_method_len;
    char *status;
    size_t status_len;
    long long malformed_data_count;
} scan_meta_t;

static void free_scan_meta(scan_meta_t *meta) {
    free(meta->started_at);
    meta->started_at = NULL;
    free(meta->finished_at);
    meta->finished_at = NULL;
    free(meta->target_spec);
    meta->target_spec = NULL;
    free(meta->authorized_by);
    meta->authorized_by = NULL;
    free(meta->authorization_confirmed_at);
    meta->authorization_confirmed_at = NULL;
    free(meta->authorization_method);
    meta->authorization_method = NULL;
    free(meta->status);
    meta->status = NULL;
}

/* db-schema.md SS6: the `scans` row for scan_id. NOT a live join to any
 * other table -- this is the durable authorization-gate record and the
 * Gate-2 malformed_data_count, both read verbatim. */
static cytadel_report_status_t load_scan_meta(sqlite3 *handle, long long scan_id, scan_meta_t *meta) {
    static const char *const sql =
        "SELECT started_at, finished_at, target_spec, authorized_by, authorization_confirmed_at, "
        "authorization_method, status, malformed_data_count FROM scans WHERE scan_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_REPORT_ERR_DB;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        cytadel_log_warn("report: no scans row found for scan_id=%lld", scan_id);
        return CYTADEL_REPORT_ERR_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        cytadel_log_error("report: stepping scans metadata query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    bool ok = dup_column(stmt, 0, &meta->started_at, &meta->started_at_len, NULL);
    ok = ok && dup_column(stmt, 1, &meta->finished_at, &meta->finished_at_len, &meta->has_finished_at);
    ok = ok && dup_column(stmt, 2, &meta->target_spec, &meta->target_spec_len, NULL);
    ok = ok && dup_column(stmt, 3, &meta->authorized_by, &meta->authorized_by_len, NULL);
    ok = ok && dup_column(stmt, 4, &meta->authorization_confirmed_at, &meta->authorization_confirmed_at_len, NULL);
    ok = ok && dup_column(stmt, 5, &meta->authorization_method, &meta->authorization_method_len, NULL);
    ok = ok && dup_column(stmt, 6, &meta->status, &meta->status_len, NULL);
    long long malformed = sqlite3_column_int64(stmt, 7);

    sqlite3_finalize(stmt);

    if (!ok) {
        return CYTADEL_REPORT_ERR_OOM;
    }
    meta->malformed_data_count = malformed;
    return CYTADEL_REPORT_OK;
}

/* --------------------------------------------------------------------- */
/* Aggregate summary counts -- computed BEFORE the finding-detail stream   */
/* since the Summary section is emitted first in document order.          */
/* --------------------------------------------------------------------- */

typedef struct {
    long long severity_counts[5]; /* confirmed findings only, index 0..4 */
    long long kev_count;          /* confirmed findings with kev_flag = 1 */
    long long undetermined_count;
    long long not_affected_count;
} report_counts_t;

static bool count_where(sqlite3 *handle, const char *sql, long long scan_id, long long *out_count) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing a summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return false;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding a summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return false;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cytadel_log_error("report: stepping a summary count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return false;
    }
    *out_count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return true;
}

static bool load_report_counts(sqlite3 *handle, long long scan_id, report_counts_t *counts) {
    for (int i = 0; i < 5; i++) {
        counts->severity_counts[i] = 0;
    }

    static const char *const severity_sql =
        "SELECT severity, COUNT(*) FROM scan_results WHERE scan_id = ? AND match_status = 'confirmed' "
        "GROUP BY severity;";
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, severity_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing severity-count query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return false;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding severity-count query failed (sqlite rc=%d): %s", rc,
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
            cytadel_log_error("report: stepping severity-count query failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            sqlite3_finalize(stmt);
            return false;
        }
        int severity = sqlite3_column_int(stmt, 0);
        long long count = sqlite3_column_int64(stmt, 1);
        if (severity >= 0 && severity <= 4) {
            counts->severity_counts[severity] = count;
        } else {
            cytadel_log_warn("report: scan_results.severity %d is out of [0,4] while summarizing -- ignored",
                              severity);
        }
    }
    sqlite3_finalize(stmt);

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

/* --------------------------------------------------------------------- */
/* One buffered scan_results row (host is tracked by the caller, not here) */
/* --------------------------------------------------------------------- */

typedef struct {
    int port;
    int severity;
    int kev_flag;
    bool has_epss;
    double epss_score;
    finding_status_t status;

    char *service;
    size_t service_len;
    bool has_service;

    char *plugin_id;
    size_t plugin_id_len;

    char *cve_id;
    size_t cve_id_len;
    bool has_cve_id;

    char *evidence;
    size_t evidence_len;

    char *remediation;
    size_t remediation_len;
    bool has_remediation;

    char *detected_at;
    size_t detected_at_len;
} finding_row_t;

static void free_row(finding_row_t *row) {
    free(row->service);
    row->service = NULL;
    free(row->plugin_id);
    row->plugin_id = NULL;
    free(row->cve_id);
    row->cve_id = NULL;
    free(row->evidence);
    row->evidence = NULL;
    free(row->remediation);
    row->remediation = NULL;
    free(row->detected_at);
    row->detected_at = NULL;
}

static void free_rows_contents(finding_row_t *rows, size_t count) {
    for (size_t i = 0; i < count; i++) {
        free_row(&rows[i]);
    }
}

/* Doubling growth, overflow-checked -- mirrors escape.c's own buf_reserve()
 * pattern applied to an array of finding_row_t instead of raw bytes. */
static bool rows_grow(finding_row_t **rows, size_t *cap, size_t need) {
    if (need <= *cap) {
        return true;
    }
    size_t new_cap = (*cap == 0) ? 8 : *cap;
    while (new_cap < need) {
        if (new_cap > (size_t)-1 / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }
    if (new_cap > (size_t)-1 / sizeof(finding_row_t)) {
        return false;
    }
    finding_row_t *grown = realloc(*rows, new_cap * sizeof(finding_row_t));
    if (grown == NULL) {
        return false;
    }
    *rows = grown;
    *cap = new_cap;
    return true;
}

/* --------------------------------------------------------------------- */
/* NVD href: fixed trusted prefix + cytadel_escape_url()'d dynamic suffix. */
/* --------------------------------------------------------------------- */

/* URL-context site. "https://nvd.nist.gov/vuln/detail/" is a fixed literal
 * this module itself wrote, never influenced by scan data; only the
 * dynamic cve_id suffix is run through cytadel_escape_url(). A hostile
 * suffix like "javascript:alert(1)" is recognized by url()'s own
 * scheme-grammar scan as an (disallowed) scheme and rejected to "#" --
 * concatenated after the trusted prefix that becomes
 * ".../vuln/detail/#", never leaking the scheme. A "//evil.com" suffix is
 * likewise rejected (S1, protocol-relative). A well-formed CVE id
 * (letters/digits/hyphens, no ':') has no scheme grammar to trip and is
 * treated as "clearly relative", round-tripping unchanged. The whole
 * assembled value (prefix + escaped suffix) is then run through
 * cytadel_escape_html_attr() before this function's caller places it in
 * href="..." -- escape.h's belt-and-suspenders rule -- even though url()'s
 * own percent-encoding already makes a raw '"' impossible here. */
static bool append_nvd_href_attr(cytadel_report_buf_t *out, const char *cve_id, size_t cve_id_len) {
    cytadel_report_buf_t url_buf;
    cytadel_report_buf_init(&url_buf);

    bool ok = cytadel_report_buf_append_lit(&url_buf, "https://nvd.nist.gov/vuln/detail/") &&
              cytadel_escape_url(&url_buf, cve_id, cve_id_len);
    if (ok) {
        ok = cytadel_escape_html_attr(out, url_buf.data, url_buf.len);
    }
    cytadel_report_buf_free(&url_buf);
    return ok;
}

/* --------------------------------------------------------------------- */
/* Finding-card rendering.                                                */
/* --------------------------------------------------------------------- */

static bool render_confirmed_card(cytadel_report_buf_t *out, const finding_row_t *row) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "<div class=\"finding sev-");
    ok = ok && append_int_lit(out, row->severity);
    ok = ok && cytadel_report_buf_append_lit(out, "\" title=\"");
    /* ATTR site: evidence, as a hover tooltip. */
    ok = ok && cytadel_escape_html_attr(out, row->evidence, row->evidence_len);
    ok = ok && cytadel_report_buf_append_lit(out, "\" data-plugin-id=\"");
    /* ATTR site: plugin_id. */
    ok = ok && cytadel_escape_html_attr(out, row->plugin_id, row->plugin_id_len);
    ok = ok && cytadel_report_buf_append_lit(out, "\">\n<h5>");

    if (row->has_cve_id && row->cve_id_len > 0) {
        ok = ok && cytadel_report_buf_append_lit(out, "<a href=\"");
        /* URL+ATTR site: cve_id, as the NVD link target. */
        ok = ok && append_nvd_href_attr(out, row->cve_id, row->cve_id_len);
        ok = ok && cytadel_report_buf_append_lit(out, "\" title=\"");
        /* ATTR site: cve_id, in the link's own title attribute. */
        ok = ok && cytadel_escape_html_attr(out, row->cve_id, row->cve_id_len);
        ok = ok && cytadel_report_buf_append_lit(out, "\">");
        /* BODY site: cve_id, as the link's visible text. */
        ok = ok && cytadel_escape_html_body(out, row->cve_id, row->cve_id_len);
        ok = ok && cytadel_report_buf_append_lit(out, "</a>");
    } else {
        ok = ok && cytadel_report_buf_append_lit(out, "Configuration finding (no CVE)");
    }

    ok = ok && cytadel_report_buf_append_lit(out, " <span class=\"badge sev-badge\">");
    ok = ok && cytadel_report_buf_append_lit(out, severity_label(row->severity));
    ok = ok && cytadel_report_buf_append_lit(out, "</span>");
    if (row->kev_flag) {
        ok = ok && cytadel_report_buf_append_lit(out, " <span class=\"badge kev-badge\">KEV</span>");
    }
    ok = ok && cytadel_report_buf_append_lit(out, "</h5>\n<p class=\"evidence\">Evidence: ");
    /* BODY site: evidence, as visible text. */
    ok = ok && cytadel_escape_html_body(out, row->evidence, row->evidence_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n");

    if (row->has_remediation && row->remediation_len > 0) {
        ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"remediation\">Remediation: ");
        /* BODY site: remediation. */
        ok = ok && cytadel_escape_html_body(out, row->remediation, row->remediation_len);
        ok = ok && cytadel_report_buf_append_lit(out, "</p>\n");
    }

    if (row->has_epss) {
        ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"epss\">EPSS: ");
        ok = ok && append_epss_lit(out, row->epss_score);
        ok = ok && cytadel_report_buf_append_lit(out, "</p>\n");
    }

    ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"detected-at\">Detected: ");
    /* BODY site: detected_at. */
    ok = ok && cytadel_escape_html_body(out, row->detected_at, row->detected_at_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n<p class=\"plugin\">Detected by: ");
    /* BODY site: plugin_id. */
    ok = ok && cytadel_escape_html_body(out, row->plugin_id, row->plugin_id_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n</div>\n");
    return ok;
}

/* cpe-matching.md SS3.1: a distinct, always-visible "could not determine"
 * record naming the cve_id and the detected context -- never folded into a
 * not-affected label, never omitted. */
static bool render_undetermined_card(cytadel_report_buf_t *out, const finding_row_t *row) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "<div class=\"finding undetermined-finding\" title=\"");
    /* ATTR site: evidence. */
    ok = ok && cytadel_escape_html_attr(out, row->evidence, row->evidence_len);
    ok = ok && cytadel_report_buf_append_lit(out, "\">\n<h5>");
    if (row->has_cve_id && row->cve_id_len > 0) {
        /* BODY site: cve_id. */
        ok = ok && cytadel_escape_html_body(out, row->cve_id, row->cve_id_len);
    } else {
        ok = ok && cytadel_report_buf_append_lit(out, "Unknown CVE");
    }
    ok = ok && cytadel_report_buf_append_lit(
                   out, " <span class=\"badge undetermined-badge\">Could not determine -- manual review "
                        "needed</span></h5>\n<p class=\"port-line\">Port: ");
    ok = ok && append_int_lit(out, row->port);
    if (row->has_service && row->service_len > 0) {
        ok = ok && cytadel_report_buf_append_lit(out, " (");
        /* BODY site: service. */
        ok = ok && cytadel_escape_html_body(out, row->service, row->service_len);
        ok = ok && cytadel_report_buf_append_lit(out, ")");
    }
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n<p class=\"evidence\">Evidence: ");
    /* BODY site: evidence. */
    ok = ok && cytadel_escape_html_body(out, row->evidence, row->evidence_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n<p class=\"detected-at\">Detected: ");
    /* BODY site: detected_at. */
    ok = ok && cytadel_escape_html_body(out, row->detected_at, row->detected_at_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n</div>\n");
    return ok;
}

/* --------------------------------------------------------------------- */
/* One host section: clean-host logic (cpe-matching.md SS3.3 / SS6 item 4) */
/* --------------------------------------------------------------------- */

static bool render_host_section(cytadel_report_buf_t *out, const char *host, size_t host_len,
                                  const finding_row_t *rows, size_t row_count) {
    long long confirmed = 0;
    long long undetermined = 0;
    long long not_affected = 0;
    for (size_t i = 0; i < row_count; i++) {
        switch (rows[i].status) {
            case FINDING_CONFIRMED:    confirmed++; break;
            case FINDING_UNDETERMINED: undetermined++; break;
            case FINDING_NOT_AFFECTED: not_affected++; break;
        }
    }

    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "<section class=\"host-block\" data-host=\"");
    /* ATTR site: host. */
    ok = ok && cytadel_escape_html_attr(out, host, host_len);
    ok = ok && cytadel_report_buf_append_lit(out, "\">\n<h3>Host: ");
    /* BODY site: host. */
    ok = ok && cytadel_escape_html_body(out, host, host_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</h3>\n");

    if (confirmed == 0 && undetermined == 0) {
        /* cpe-matching.md SS6 item 4: "no vulnerabilities found" is only
         * ever emitted when BOTH counts are zero. */
        ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"host-clean\">No vulnerabilities found.</p>\n");
    } else {
        if (confirmed == 0 && undetermined > 0) {
            ok = ok && cytadel_report_buf_append_lit(
                           out, "<p class=\"host-undetermined-only\">No confirmed vulnerabilities; ");
            ok = ok && append_int_lit(out, undetermined);
            ok = ok && cytadel_report_buf_append_lit(out, " check(s) undetermined -- manual review needed.</p>\n");
        }

        if (confirmed > 0) {
            bool port_open = false;
            int cur_port = -1;
            for (size_t i = 0; i < row_count && ok; i++) {
                if (rows[i].status != FINDING_CONFIRMED) {
                    continue;
                }
                if (!port_open || rows[i].port != cur_port) {
                    if (port_open) {
                        ok = ok && cytadel_report_buf_append_lit(out, "</div>\n");
                    }
                    cur_port = rows[i].port;
                    port_open = true;
                    ok = ok && cytadel_report_buf_append_lit(out, "<div class=\"port-block\">\n<h4>");
                    if (cur_port == 0) {
                        ok = ok && cytadel_report_buf_append_lit(out, "Host-level finding");
                    } else {
                        ok = ok && cytadel_report_buf_append_lit(out, "Port ");
                        ok = ok && append_int_lit(out, cur_port);
                    }
                    if (rows[i].has_service && rows[i].service_len > 0) {
                        ok = ok && cytadel_report_buf_append_lit(out, " (");
                        /* BODY site: service. */
                        ok = ok && cytadel_escape_html_body(out, rows[i].service, rows[i].service_len);
                        ok = ok && cytadel_report_buf_append_lit(out, ")");
                    }
                    ok = ok && cytadel_report_buf_append_lit(out, "</h4>\n");
                }
                ok = ok && render_confirmed_card(out, &rows[i]);
            }
            if (port_open) {
                ok = ok && cytadel_report_buf_append_lit(out, "</div>\n");
            }
        }

        if (undetermined > 0) {
            ok = ok && cytadel_report_buf_append_lit(
                           out, "<div class=\"undetermined-block\">\n<h4>Undetermined -- Manual Review "
                                "Needed</h4>\n");
            for (size_t i = 0; i < row_count && ok; i++) {
                if (rows[i].status != FINDING_UNDETERMINED) {
                    continue;
                }
                ok = ok && render_undetermined_card(out, &rows[i]);
            }
            ok = ok && cytadel_report_buf_append_lit(out, "</div>\n");
        }
    }

    /* not_affected is a per-host audit-trail COUNT only (never individual
     * findings) -- rendered unconditionally whenever nonzero, independent
     * of the clean/undetermined-only branching above: a host can be
     * "clean" (zero confirmed, zero undetermined) and STILL have ruled-out
     * checks worth showing for audit purposes. */
    if (not_affected > 0) {
        ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"not-affected-count\">");
        ok = ok && append_int_lit(out, not_affected);
        ok = ok && cytadel_report_buf_append_lit(out, " check(s) ruled not affected (audit trail).</p>\n");
    }

    ok = ok && cytadel_report_buf_append_lit(out, "</section>\n");
    return ok;
}

/* --------------------------------------------------------------------- */
/* Streams the SS9 "findings for a scan" SELECT (augmented with            */
/* match_status), grouped by host.                                        */
/* --------------------------------------------------------------------- */

static cytadel_report_status_t render_findings(sqlite3 *handle, long long scan_id, cytadel_report_buf_t *out) {
    /* db-schema.md SS9's own "Report: findings for a scan" SELECT, with
     * `match_status` appended -- an additive column, not a change to the
     * WHERE clause or ORDER BY, mirroring src/db/scan_persist.c's own
     * `ORDER BY cve_id, id` augmentation of the SS9 candidate lookup. */
    static const char *const sql =
        "SELECT host, port, service, plugin_id, cve_id, severity, evidence, remediation, kev_flag, "
        "epss_score, detected_at, match_status "
        "FROM scan_results WHERE scan_id = ? ORDER BY host, port, severity DESC;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing findings query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_REPORT_ERR_DB;
    }
    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: binding findings query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    cytadel_report_status_t status = CYTADEL_REPORT_OK;
    char *cur_host = NULL;
    size_t cur_host_len = 0;
    bool have_group = false;
    bool any_host_rendered = false;
    finding_row_t *rows = NULL;
    size_t row_count = 0;
    size_t row_cap = 0;

    for (;;) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            cytadel_log_error("report: stepping findings query failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            status = CYTADEL_REPORT_ERR_DB;
            break;
        }

        char *row_host = NULL;
        size_t row_host_len = 0;
        if (!dup_column(stmt, 0, &row_host, &row_host_len, NULL)) {
            status = CYTADEL_REPORT_ERR_OOM;
            break;
        }

        bool same_host =
            have_group && row_host_len == cur_host_len && memcmp(row_host, cur_host, cur_host_len) == 0;

        if (have_group && !same_host) {
            if (!render_host_section(out, cur_host, cur_host_len, rows, row_count)) {
                status = CYTADEL_REPORT_ERR_OOM;
                free(row_host);
                break;
            }
            any_host_rendered = true;
            free_rows_contents(rows, row_count);
            row_count = 0;
        }

        if (!same_host) {
            free(cur_host);
            cur_host = row_host; /* ownership transferred */
            cur_host_len = row_host_len;
            have_group = true;
        } else {
            free(row_host);
        }

        finding_row_t row;
        memset(&row, 0, sizeof(row));
        row.port = sqlite3_column_int(stmt, 1);
        bool row_ok = dup_column(stmt, 2, &row.service, &row.service_len, &row.has_service);
        row_ok = row_ok && dup_column(stmt, 3, &row.plugin_id, &row.plugin_id_len, NULL);
        row_ok = row_ok && dup_column(stmt, 4, &row.cve_id, &row.cve_id_len, &row.has_cve_id);
        row.severity = sqlite3_column_int(stmt, 5);
        row_ok = row_ok && dup_column(stmt, 6, &row.evidence, &row.evidence_len, NULL);
        row_ok = row_ok && dup_column(stmt, 7, &row.remediation, &row.remediation_len, &row.has_remediation);
        row.kev_flag = sqlite3_column_int(stmt, 8);
        row.has_epss = sqlite3_column_type(stmt, 9) != SQLITE_NULL;
        row.epss_score = row.has_epss ? sqlite3_column_double(stmt, 9) : 0.0;
        row_ok = row_ok && dup_column(stmt, 10, &row.detected_at, &row.detected_at_len, NULL);

        if (!row_ok) {
            free_row(&row);
            status = CYTADEL_REPORT_ERR_OOM;
            break;
        }

        const unsigned char *ms_text = sqlite3_column_text(stmt, 11);
        int ms_bytes = sqlite3_column_bytes(stmt, 11);
        row.status = classify_match_status((const char *)ms_text, (ms_bytes > 0) ? (size_t)ms_bytes : 0);

        if (!rows_grow(&rows, &row_cap, row_count + 1)) {
            free_row(&row);
            status = CYTADEL_REPORT_ERR_OOM;
            break;
        }
        rows[row_count++] = row;
    }

    if (status == CYTADEL_REPORT_OK && have_group) {
        if (render_host_section(out, cur_host, cur_host_len, rows, row_count)) {
            any_host_rendered = true;
        } else {
            status = CYTADEL_REPORT_ERR_OOM;
        }
    }

    free_rows_contents(rows, row_count);
    free(rows);
    free(cur_host);
    sqlite3_finalize(stmt);

    if (status != CYTADEL_REPORT_OK) {
        return status;
    }

    if (!any_host_rendered) {
        if (!cytadel_report_buf_append_lit(out, "<p class=\"no-findings\">No scan_results recorded for this "
                                                 "scan.</p>\n")) {
            return CYTADEL_REPORT_ERR_OOM;
        }
    }
    return CYTADEL_REPORT_OK;
}

/* --------------------------------------------------------------------- */
/* Cover page + Summary section.                                          */
/* --------------------------------------------------------------------- */

static bool append_meta_row(cytadel_report_buf_t *out, const char *label, const char *value, size_t value_len) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "<tr><th>");
    ok = ok && cytadel_report_buf_append_lit(out, label); /* trusted literal, not DB data */
    ok = ok && cytadel_report_buf_append_lit(out, "</th><td>");
    /* BODY site: every `scans` text column shown on the cover page. */
    ok = ok && cytadel_escape_html_body(out, value, value_len);
    ok = ok && cytadel_report_buf_append_lit(out, "</td></tr>\n");
    return ok;
}

static bool render_cover(cytadel_report_buf_t *out, long long scan_id, const scan_meta_t *meta) {
    bool ok = true;
    /* Cover: the brand logo (self-contained base64 data: URI -- no external
     * asset, survives email + print-to-PDF) on the black cover panel that
     * matches the logo's own solid-black background, plus the CYTADEL
     * wordmark. The data URI is a generated header (assets/brand/
     * make-logo-datauri.py); swapping the logo is re-running that script. */
    ok = ok && cytadel_report_buf_append_lit(
                   out,
                   "<section class=\"cover\">\n<div class=\"brand\">\n"
                   "<img class=\"logo\" width=\"120\" height=\"120\" alt=\"Cytadel\" src=\"");
    /* The data URI is a static, engine-generated constant (not scan data), so
     * it is appended verbatim -- no escaping needed. Chunked to stay under the
     * C99 string-literal limit; see assets/brand/make-logo-datauri.py. */
    for (size_t i = 0; ok && i < CYTADEL_LOGO_DATA_URI_CHUNK_COUNT; i++) {
        ok = ok && cytadel_report_buf_append_lit(out, CYTADEL_LOGO_DATA_URI_CHUNKS[i]);
    }
    ok = ok && cytadel_report_buf_append_lit(
                   out,
                   "\">\n<div class=\"wordmark\">CYTADEL</div>\n"
                   "</div>\n<h1>SCAN REPORT #");
    ok = ok && append_int_lit(out, scan_id);
    ok = ok && cytadel_report_buf_append_lit(out, "</h1>\n<table class=\"meta\">\n");

    ok = ok && append_meta_row(out, "Target", meta->target_spec, meta->target_spec_len);
    ok = ok && append_meta_row(out, "Status", meta->status, meta->status_len);
    ok = ok && append_meta_row(out, "Started", meta->started_at, meta->started_at_len);
    if (meta->has_finished_at && meta->finished_at_len > 0) {
        ok = ok && append_meta_row(out, "Finished", meta->finished_at, meta->finished_at_len);
    } else {
        static const char *const in_progress = "In progress";
        ok = ok && append_meta_row(out, "Finished", in_progress, strlen(in_progress));
    }
    ok = ok && append_meta_row(out, "Authorized By", meta->authorized_by, meta->authorized_by_len);
    ok = ok && append_meta_row(out, "Authorization Confirmed At", meta->authorization_confirmed_at,
                                meta->authorization_confirmed_at_len);
    ok = ok && append_meta_row(out, "Authorization Method", meta->authorization_method,
                                meta->authorization_method_len);

    ok = ok && cytadel_report_buf_append_lit(out, "</table>\n</section>\n");
    return ok;
}

static bool render_summary(cytadel_report_buf_t *out, const scan_meta_t *meta, const report_counts_t *counts) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(out, "<section class=\"summary\">\n<h2>Summary</h2>\n");

    if (meta->malformed_data_count > 0) {
        /* Gate 2: docs/contracts/db-schema.md SS6's malformed_data_count. */
        ok = ok && cytadel_report_buf_append_lit(out, "<div class=\"data-quality-banner\">");
        ok = ok && append_int_lit(out, meta->malformed_data_count);
        ok = ok &&
             cytadel_report_buf_append_lit(out, " record(s) had malformed data -- results may be incomplete.</div>\n");
    }

    static const char *const sev_classes[5] = {"sev-count-info", "sev-count-low", "sev-count-medium",
                                                "sev-count-high", "sev-count-critical"};
    ok = ok && cytadel_report_buf_append_lit(out, "<ul class=\"severity-counts\">\n");
    for (int s = 4; s >= 0 && ok; s--) {
        ok = ok && cytadel_report_buf_append_lit(out, "<li class=\"");
        ok = ok && cytadel_report_buf_append_lit(out, sev_classes[s]);
        ok = ok && cytadel_report_buf_append_lit(out, "\">");
        ok = ok && cytadel_report_buf_append_lit(out, severity_label(s));
        ok = ok && cytadel_report_buf_append_lit(out, ": ");
        ok = ok && append_int_lit(out, counts->severity_counts[s]);
        ok = ok && cytadel_report_buf_append_lit(out, "</li>\n");
    }
    ok = ok && cytadel_report_buf_append_lit(out, "</ul>\n");

    ok = ok && cytadel_report_buf_append_lit(out, "<p class=\"kev-count\">Known Exploited Vulnerabilities (KEV): ");
    ok = ok && append_int_lit(out, counts->kev_count);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n");

    /* Gate 3 / cpe-matching.md SS3.3: the undetermined count is ALWAYS
     * stated in the summary, never omitted or demoted to a debug line. */
    ok = ok && cytadel_report_buf_append_lit(out,
                                              "<p class=\"undetermined-count-line\">Undetermined (manual review "
                                              "needed): ");
    ok = ok && append_int_lit(out, counts->undetermined_count);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n");

    ok = ok && cytadel_report_buf_append_lit(out,
                                              "<p class=\"not-affected-count\">Not affected (ruled out, audit "
                                              "trail): ");
    ok = ok && append_int_lit(out, counts->not_affected_count);
    ok = ok && cytadel_report_buf_append_lit(out, "</p>\n</section>\n");
    return ok;
}

/* --------------------------------------------------------------------- */
/* Document head: inline CSS. Every color is a custom property so the      */
/* placeholder palette below can be swapped for the real cytadel.eu brand */
/* colors without touching any structural markup. Split into several      */
/* literals (db_migrations.c's own CYTADEL_DB_MIGRATION_1_STATEMENTS       */
/* precedent) so no single string literal risks exceeding the 4095-byte    */
/* length ISO C99 compilers are only required to support                  */
/* (-Wpedantic/-Werror). Pure static template text -- no DB data, no       */
/* escaping needed. */
/* --------------------------------------------------------------------- */

static const char *const CYTADEL_REPORT_CSS_CHUNKS[] = {
    ":root {\n"
    "  /* BRAND: Cytadel palette. --cytadel-primary/accent are derived from the\n"
    "     brand logo (assets/brand/cytadelredllogo.jpg -- red on black); swap in\n"
    "     official cytadel.eu hex here if it differs. */\n"
    "  --cytadel-primary: #0b0e14;\n"
    "  --cytadel-accent: #fb0202;\n"
    "  --cytadel-bg: #f5f7fa;\n"
    "  --cytadel-surface: #ffffff;\n"
    "  --cytadel-text: #1a1a1a;\n"
    "  --cytadel-muted: #5a6472;\n"
    "  --sev-critical: #b3001b;\n"
    "  --sev-high: #d9534f;\n"
    "  --sev-medium: #e0a100;\n"
    "  --sev-low: #4a90d9;\n"
    "  --sev-info: #7a7a7a;\n"
    "  --undetermined-color: #6a3fb5;\n"
    "  --warning-color: #c47f00;\n"
    "  /* END BRAND */\n"
    "}\n"
    "* { box-sizing: border-box; }\n"
    "body { font-family: 'Segoe UI', Arial, sans-serif; background: var(--cytadel-bg); "
    "color: var(--cytadel-text); margin: 0; padding: 0; }\n"
    ".cover { background: var(--cytadel-primary); color: #fff; padding: 4rem 2rem; text-align: center; }\n"
    ".cover .brand { display: flex; flex-direction: column; align-items: center; gap: 0.75rem; }\n"
    /* Circular badge: the logo is a red sphere on a solid-black JPG background.
     * border-radius:50% clips it to a circle so its black background never
     * shows as a square -- seamless on the dark screen cover AND on the white
     * ink-friendly print cover (reads as a red-sphere-in-black-circle mark). */
    ".cover .logo { width: 120px; height: 120px; border-radius: 50%; display: block; }\n"
    ".cover .wordmark { font-size: 2.5rem; font-weight: 700; letter-spacing: 0.35em; "
    "padding-left: 0.35em; color: var(--cytadel-accent); }\n"
    ".cover h1 { font-size: 1.5rem; letter-spacing: 0.2em; margin-top: 1rem; }\n"
    "table.meta { margin: 2rem auto; border-collapse: collapse; color: #fff; }\n"
    "table.meta th { text-align: right; padding: 0.25rem 1rem; color: var(--cytadel-accent); "
    "font-weight: 600; }\n"
    "table.meta td { text-align: left; padding: 0.25rem 1rem; }\n",

    "section.summary, section.findings { max-width: 960px; margin: 2rem auto; "
    "background: var(--cytadel-surface); padding: 1.5rem 2rem; border-radius: 8px; }\n"
    ".data-quality-banner { background: var(--warning-color); color: #fff; padding: 0.75rem 1rem; "
    "border-radius: 4px; margin-bottom: 1rem; font-weight: 600; }\n"
    "ul.severity-counts { list-style: none; display: flex; gap: 1rem; padding: 0; flex-wrap: wrap; }\n"
    "ul.severity-counts li { padding: 0.5rem 1rem; border-radius: 4px; color: #fff; font-weight: 600; }\n"
    ".sev-count-critical { background: var(--sev-critical); }\n"
    ".sev-count-high { background: var(--sev-high); }\n"
    ".sev-count-medium { background: var(--sev-medium); }\n"
    ".sev-count-low { background: var(--sev-low); }\n"
    ".sev-count-info { background: var(--sev-info); }\n"
    ".undetermined-count-line { color: var(--undetermined-color); font-weight: 600; }\n"
    ".host-block { border-top: 2px solid var(--cytadel-primary); padding-top: 1rem; margin-top: 1.5rem; }\n"
    ".host-clean { color: #2a7a2a; font-weight: 600; }\n"
    ".host-undetermined-only { color: var(--undetermined-color); font-weight: 600; }\n"
    ".port-block { margin: 1rem 0; padding-left: 1rem; border-left: 3px solid var(--cytadel-accent); }\n",

    ".finding { border: 1px solid #ddd; border-radius: 6px; padding: 0.75rem 1rem; margin: 0.5rem 0; }\n"
    ".finding.sev-4 { border-left: 6px solid var(--sev-critical); }\n"
    ".finding.sev-3 { border-left: 6px solid var(--sev-high); }\n"
    ".finding.sev-2 { border-left: 6px solid var(--sev-medium); }\n"
    ".finding.sev-1 { border-left: 6px solid var(--sev-low); }\n"
    ".finding.sev-0 { border-left: 6px solid var(--sev-info); }\n"
    ".finding.undetermined-finding { border-left: 6px solid var(--undetermined-color); background: #f8f5ff; }\n"
    ".badge { display: inline-block; padding: 0.1rem 0.5rem; border-radius: 3px; font-size: 0.8rem; "
    "color: #fff; margin-left: 0.4rem; }\n"
    ".sev-badge { background: var(--cytadel-muted); }\n"
    ".kev-badge { background: var(--sev-critical); }\n"
    ".undetermined-badge { background: var(--undetermined-color); }\n"
    ".not-affected-count { color: var(--cytadel-muted); font-style: italic; }\n"
    "@media print {\n"
    "  body { background: #fff; }\n"
    "  .cover { page-break-after: always; background: #fff; color: var(--cytadel-primary); "
    "border-bottom: 4px solid var(--cytadel-primary); }\n"
    "  table.meta th, table.meta td { color: var(--cytadel-primary); }\n"
    "  .finding, .host-block { page-break-inside: avoid; }\n"
    "  section.summary, section.findings { box-shadow: none; }\n"
    "}\n",
};
#define CYTADEL_REPORT_CSS_CHUNK_COUNT (sizeof(CYTADEL_REPORT_CSS_CHUNKS) / sizeof(CYTADEL_REPORT_CSS_CHUNKS[0]))

static bool render_document_head(cytadel_report_buf_t *out, long long scan_id) {
    bool ok = true;
    ok = ok && cytadel_report_buf_append_lit(
                   out, "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
                        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                        "<title>Cytadel Scan Report #");
    ok = ok && append_int_lit(out, scan_id);
    ok = ok && cytadel_report_buf_append_lit(out, "</title>\n<style>\n");
    for (size_t i = 0; i < CYTADEL_REPORT_CSS_CHUNK_COUNT && ok; i++) {
        ok = ok && cytadel_report_buf_append_lit(out, CYTADEL_REPORT_CSS_CHUNKS[i]);
    }
    ok = ok && cytadel_report_buf_append_lit(out, "</style>\n</head>\n<body>\n");
    return ok;
}

/* --------------------------------------------------------------------- */
/* Public entry point.                                                     */
/* --------------------------------------------------------------------- */

const char *cytadel_report_status_to_string(cytadel_report_status_t status) {
    switch (status) {
        case CYTADEL_REPORT_OK:              return "OK";
        case CYTADEL_REPORT_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_REPORT_ERR_NOT_FOUND:   return "NOT_FOUND";
        case CYTADEL_REPORT_ERR_DB:          return "DB";
        case CYTADEL_REPORT_ERR_OOM:         return "OOM";
    }
    return "UNKNOWN";
}

cytadel_report_status_t cytadel_report_html(cytadel_db_t *db, long long scan_id, cytadel_report_buf_t *out) {
    if (db == NULL || out == NULL || scan_id <= 0) {
        cytadel_log_error(
            "report: cytadel_report_html() called with a NULL db/out or a non-positive scan_id (%lld)", scan_id);
        return CYTADEL_REPORT_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    scan_meta_t meta;
    memset(&meta, 0, sizeof(meta));
    cytadel_report_status_t status = load_scan_meta(handle, scan_id, &meta);
    if (status != CYTADEL_REPORT_OK) {
        free_scan_meta(&meta);
        return status;
    }

    report_counts_t counts;
    memset(&counts, 0, sizeof(counts));
    if (!load_report_counts(handle, scan_id, &counts)) {
        free_scan_meta(&meta);
        return CYTADEL_REPORT_ERR_DB;
    }

    bool ok = render_document_head(out, scan_id);
    ok = ok && render_cover(out, scan_id, &meta);
    ok = ok && render_summary(out, &meta, &counts);
    free_scan_meta(&meta);

    if (!ok) {
        return CYTADEL_REPORT_ERR_OOM;
    }

    if (!cytadel_report_buf_append_lit(out, "<section class=\"findings\">\n<h2>Findings</h2>\n")) {
        return CYTADEL_REPORT_ERR_OOM;
    }

    status = render_findings(handle, scan_id, out);
    if (status != CYTADEL_REPORT_OK) {
        return status;
    }

    ok = cytadel_report_buf_append_lit(out, "</section>\n</body>\n</html>\n");
    return ok ? CYTADEL_REPORT_OK : CYTADEL_REPORT_ERR_OOM;
}
