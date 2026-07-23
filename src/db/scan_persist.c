#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/db/nvd_ingest.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

#include "cytadel/db/scan_persist.h"

#include <ctype.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <string.h>

#include "cve_id_valid.h"
#include "log.h"

/* Milestone 7 (CPE-matching-caller slice): see
 * include/cytadel/db/scan_persist.h for the full design/contract this file
 * implements -- especially its top comment on the per-CVE three-valued,
 * order-independent aggregation (docs/contracts/cpe-matching.md SS3.2.3)
 * and the audit-trail row model. This comment covers implementation
 * details only.
 *
 * Two independent entry points share ONE accumulator (accumulate_outcome()
 * + finalize_verdict() below), by construction, so there is exactly one
 * place in this file that encodes the Kleene fold CPE-MATCH-CALLER-1
 * SS3.2.3 requires:
 *
 *   - cytadel_scan_aggregate_cve_verdict() (public, PURE, no DB): walks a
 *     caller-supplied array of cytadel_cpe_match_row_t belonging to one
 *     cve_id. Used directly by tests/unit/test_scan_persist.c to prove
 *     order-independence without any SQL machinery.
 *   - cytadel_scan_detect_and_persist()'s internal streaming loop: walks
 *     `cve_cpe_matches` rows returned by one SQL query (`ORDER BY cve_id,
 *     id` so each cve_id's rows are contiguous), accumulating the SAME
 *     any_match/any_undecidable/any_no_match/malformed_count state
 *     incrementally per row (no rows array is ever materialized -- O(1)
 *     extra memory regardless of how many candidate rows a query returns),
 *     and flushes (finalize_verdict() + a scan_results insert) whenever
 *     the cve_id changes or the result set ends.
 *
 * Neither path calls the other; both call the same two static helpers, so
 * they cannot silently diverge in behavior.
 */

#define CYTADEL_SCAN_CVE_ID_MAX_LEN 64
#define CYTADEL_SCAN_CVE_ID_BUF_LEN (CYTADEL_SCAN_CVE_ID_MAX_LEN + 1)
#define CYTADEL_SCAN_VENDOR_PRODUCT_BUF_LEN (CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN + 1)

const char *cytadel_scan_persist_status_to_string(cytadel_scan_persist_status_t status) {
    switch (status) {
        case CYTADEL_SCAN_PERSIST_OK:                 return "OK";
        case CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG:    return "INVALID_ARG";
        case CYTADEL_SCAN_PERSIST_ERR_DB:             return "DB";
        case CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED:    return "ROW_SKIPPED";
    }
    return "UNKNOWN";
}

const char *cytadel_scan_match_status_to_string(cytadel_scan_match_status_t status) {
    switch (status) {
        case CYTADEL_SCAN_MATCH_CONFIRMED:    return "confirmed";
        case CYTADEL_SCAN_MATCH_UNDETERMINED: return "undetermined";
        case CYTADEL_SCAN_MATCH_NOT_AFFECTED: return "not_affected";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* THE shared Kleene accumulator (cpe-matching.md SS3.2.3).            */
/* ------------------------------------------------------------------ */

/* CPE-MATCH-CALLER-1 SS3.2.2: exhaustive switch over EVERY
 * cytadel_cpe_match_t enumerator, NO `default:` label. Under this
 * project's -Wall -Werror, a no-default: switch that omits an enumerator
 * is a -Wswitch build error -- so a future 5th outcome (cpe-matching.md
 * SS5) forces a deliberate decision here rather than silently falling
 * through a default: branch. CYTADEL_CPE_MALFORMED_ROW touches ONLY
 * *malformed_count -- it must never set any_match/any_undecidable/
 * any_no_match, and nothing here ever coerces it into one of those three
 * (no `!=`, no `else`, no boolean cast of the enum -- SS3.2 prohibitions). */
static void accumulate_outcome(cytadel_cpe_match_t outcome, bool *any_match, bool *any_undecidable,
                                bool *any_no_match, size_t *malformed_count) {
    switch (outcome) {
    case CYTADEL_CPE_MATCH:
        *any_match = true;
        return;
    case CYTADEL_CPE_NO_MATCH:
        *any_no_match = true;
        return;
    case CYTADEL_CPE_UNDECIDABLE:
        *any_undecidable = true;
        return;
    case CYTADEL_CPE_MALFORMED_ROW:
        (*malformed_count)++;
        return;
    }
}

/* Decides the final three-valued verdict from the accumulated booleans.
 * any_match/any_undecidable/any_no_match are the result of folding EVERY
 * row's outcome via accumulate_outcome() above, in ANY order -- this
 * function itself only ever reads the three final booleans, never an
 * ordered sequence, which is precisely what makes the overall aggregation
 * order-independent (SS3.2.3): swapping the order two rows were folded in
 * cannot change which of the three booleans end up true. A NO_MATCH row
 * can only ever set any_no_match; it can never un-set any_match or
 * any_undecidable, wherever it appears in the fold -- so "NO_MATCH
 * overwriting a previously-seen UNDECIDABLE" (the defect SS3.2's
 * prohibition 3 names explicitly) is structurally impossible here. */
static cytadel_scan_cve_verdict_t finalize_verdict(bool any_match, bool any_undecidable, bool any_no_match,
                                                     size_t malformed_count) {
    cytadel_scan_cve_verdict_t verdict;
    verdict.malformed_count = malformed_count;
    if (any_match) {
        verdict.has_verdict = true;
        verdict.status = CYTADEL_SCAN_MATCH_CONFIRMED;
    } else if (any_undecidable) {
        verdict.has_verdict = true;
        verdict.status = CYTADEL_SCAN_MATCH_UNDETERMINED;
    } else if (any_no_match) {
        verdict.has_verdict = true;
        verdict.status = CYTADEL_SCAN_MATCH_NOT_AFFECTED;
    } else {
        /* Either row_count == 0 (no candidate rows -- nothing to persist,
         * not a data-quality event) or every row was MALFORMED_ROW (a
         * data-quality event only, per cve_id -- no host verdict exists to
         * report). `status` is unspecified/unused in this case; callers
         * must check has_verdict before ever reading it. */
        verdict.has_verdict = false;
        verdict.status = CYTADEL_SCAN_MATCH_NOT_AFFECTED;
    }
    return verdict;
}

cytadel_scan_cve_verdict_t cytadel_scan_aggregate_cve_verdict(const cytadel_cpe_match_row_t *rows,
                                                                size_t row_count,
                                                                const char *detected_version,
                                                                size_t detected_version_len) {
    bool any_match = false;
    bool any_undecidable = false;
    bool any_no_match = false;
    size_t malformed_count = 0;

    for (size_t i = 0; i < row_count; i++) {
        cytadel_cpe_match_t outcome =
            cytadel_cpe_match_evaluate(&rows[i], detected_version, detected_version_len);
        accumulate_outcome(outcome, &any_match, &any_undecidable, &any_no_match, &malformed_count);
    }

    return finalize_verdict(any_match, any_undecidable, any_no_match, malformed_count);
}

/* ------------------------------------------------------------------ */
/* Small helpers.                                                      */
/* ------------------------------------------------------------------ */

/* Lower-cases `src` into `dst` (db-schema.md SS10 assumption 2: vendor/
 * product are stored lowercase). Rejects an empty or oversized `src`
 * rather than silently truncating -- a truncated vendor/product would
 * silently query the wrong candidate set instead of failing loudly. */
static bool lowercase_copy(char *dst, size_t dst_cap, const char *src) {
    size_t len = strnlen(src, dst_cap);
    if (len == 0 || len >= dst_cap) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        dst[i] = (char)tolower((unsigned char)src[i]);
    }
    dst[len] = '\0';
    return true;
}

static int exec_sql(sqlite3 *handle, const char *sql, const char *context) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: %s failed (sqlite rc=%d): %s", context, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

/* db-schema.md SS6/SS9 (migration v3, M8 report slice 2): bumps the durable
 * `scans.malformed_data_count` running total by `malformed_events` for
 * `scan_id` -- a single parameterized UPDATE, never string-concatenated.
 * Called from inside cytadel_scan_detect_and_persist()'s own BEGIN...COMMIT
 * transaction, after every scan_results row this call produces has already
 * been flushed and BEFORE that transaction's COMMIT -- so this durable count
 * update is atomic with the row writes it describes: a fatal error anywhere
 * in this call rolls back both together, never just one. Always runs (even
 * when malformed_events is 0) so a scan with no data-quality events reads
 * back the column's own honest DEFAULT 0, never a stale/mismatched value. */
static cytadel_scan_persist_status_t update_malformed_data_count(sqlite3 *handle, long long scan_id,
                                                                   size_t malformed_events) {
    static const char *const sql =
        "UPDATE scans SET malformed_data_count = malformed_data_count + ? WHERE scan_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing scans.malformed_data_count update failed (sqlite "
                           "rc=%d): %s",
                           rc, sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_bind_int64(stmt, 1, (sqlite3_int64)malformed_events);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(stmt, 2, scan_id);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding scans.malformed_data_count update failed (sqlite "
                           "rc=%d): %s",
                           rc, sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cytadel_log_error("scan_persist: updating scans.malformed_data_count failed (sqlite rc=%d): %s",
                           rc, sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }
    return CYTADEL_SCAN_PERSIST_OK;
}

/* ------------------------------------------------------------------ */
/* cytadel_scan_create().                                              */
/* ------------------------------------------------------------------ */

cytadel_scan_persist_status_t cytadel_scan_create(cytadel_db_t *db, const char *target_spec,
                                                    const char *authorized_by,
                                                    const char *authorization_method,
                                                    long long *out_scan_id) {
    if (db == NULL || target_spec == NULL || authorized_by == NULL || authorization_method == NULL ||
        out_scan_id == NULL) {
        cytadel_log_error("scan_persist: cytadel_scan_create() called with a NULL argument");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    /* db-schema.md SS9 "Scan authorization + creation" -- reproduced
     * verbatim (FROZEN CONTRACT text, unmodified by this slice). This row
     * IS the durable record of the mandatory authorization-gate
     * confirmation (the mandatory authorization-gate rule). */
    static const char *const sql =
        "INSERT INTO scans (started_at, target_spec, authorized_by, authorization_confirmed_at, "
        "authorization_method, status) "
        "VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, "
        "'running');";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing scans insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_bind_text(stmt, 1, target_spec, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, authorized_by, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 3, authorization_method, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding scans insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cytadel_log_error("scan_persist: inserting scans row failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    *out_scan_id = (long long)sqlite3_last_insert_rowid(handle);
    return CYTADEL_SCAN_PERSIST_OK;
}

/* ------------------------------------------------------------------ */
/* cytadel_scan_detect_and_persist().                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    sqlite3_stmt *severity_stmt;
    sqlite3_stmt *kev_stmt;
    sqlite3_stmt *epss_stmt;
    sqlite3_stmt *insert_stmt;
} scan_persist_stmts_t;

static int prepare_group_statements(sqlite3 *handle, scan_persist_stmts_t *stmts) {
    static const char *const severity_sql = "SELECT severity FROM cves WHERE cve_id = ?;";
    static const char *const kev_sql = "SELECT 1 FROM kev WHERE cve_id = ?;";
    static const char *const epss_sql = "SELECT epss_score FROM epss WHERE cve_id = ?;";
    /* db-schema.md SS9's new scan_results insert pattern (this slice --
     * see that section's own "added migration v2" note on match_status). */
    static const char *const insert_sql =
        "INSERT INTO scan_results (scan_id, host, port, service, plugin_id, cve_id, match_status, "
        "severity, evidence, remediation, kev_flag, epss_score, detected_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));";

    int rc = sqlite3_prepare_v2(handle, severity_sql, -1, &stmts->severity_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing severity snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, kev_sql, -1, &stmts->kev_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing kev snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, epss_sql, -1, &stmts->epss_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing epss snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, insert_sql, -1, &stmts->insert_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing scan_results insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    return SQLITE_OK;
}

/* sqlite3_finalize(NULL) is a documented no-op -- safe to call on any
 * member that never got prepared (e.g. a prepare failure partway through
 * prepare_group_statements() above). */
static void finalize_group_statements(scan_persist_stmts_t *stmts) {
    sqlite3_finalize(stmts->severity_stmt);
    sqlite3_finalize(stmts->kev_stmt);
    sqlite3_finalize(stmts->epss_stmt);
    sqlite3_finalize(stmts->insert_stmt);
}

/* Flushes one already-aggregated cve_id group: logs+counts every malformed
 * occurrence (independent of has_verdict -- SS3.2's prohibition 4: an
 * UNDECIDABLE/MALFORMED_ROW record must never be suppressed because
 * another outcome for the same CVE already settled a verdict), and, only
 * when has_verdict is true, looks up the severity/kev/epss snapshots and
 * inserts exactly one scan_results row. */
static cytadel_scan_persist_status_t flush_group(sqlite3 *handle, scan_persist_stmts_t *stmts,
                                                   long long scan_id,
                                                   const cytadel_scan_detection_t *detection,
                                                   const char *cve_id, size_t cve_id_len, bool any_match,
                                                   bool any_undecidable, bool any_no_match,
                                                   size_t malformed_count,
                                                   cytadel_scan_persist_counts_t *out_counts) {
    cytadel_scan_cve_verdict_t verdict =
        finalize_verdict(any_match, any_undecidable, any_no_match, malformed_count);

    if (verdict.malformed_count > 0) {
        /* cpe-matching.md SS3.1: a distinct, operator-visible data-quality
         * record naming the CVE id -- this is that record's log-line half.
         * SS6 item 2 ("a log_debug(), a counter, a comment, or a TODO does
         * NOT count as surfaced") is about REPLACING a rendered artifact
         * with only a log line; this project's actual rendered artifact
         * (the report, a later milestone) is expected to read
         * out_counts->malformed_events / a future dedicated data-quality
         * table, not this log line alone -- the log line supplements that,
         * it does not substitute for it. */
        cytadel_log_warn(
            "scan_persist: cve_id='%.*s': %zu malformed cve_cpe_matches row(s) -- data-quality "
            "event, contributes no verdict",
            (int)cve_id_len, cve_id, verdict.malformed_count);
        out_counts->malformed_events += verdict.malformed_count;
    }

    if (!verdict.has_verdict) {
        /* Every row for this cve_id was malformed -- no scan_results row. */
        return CYTADEL_SCAN_PERSIST_OK;
    }

    int severity = 0;
    sqlite3_reset(stmts->severity_stmt);
    sqlite3_clear_bindings(stmts->severity_stmt);
    int rc = sqlite3_bind_text(stmts->severity_stmt, 1, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmts->severity_stmt);
        if (rc == SQLITE_ROW) {
            severity = sqlite3_column_int(stmts->severity_stmt, 0);
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            /* Should not happen in a consistent DB (cve_cpe_matches.cve_id
             * is a hard FK into cves), but never trust that at this
             * boundary -- default to 0 (Info) rather than fail the whole
             * detection over one missing snapshot row. */
            cytadel_log_warn(
                "scan_persist: cve_id='%.*s': no cves row found for the severity snapshot -- using "
                "0 (Info)",
                (int)cve_id_len, cve_id);
            rc = SQLITE_OK;
        } else {
            cytadel_log_error("scan_persist: cve_id='%.*s': severity snapshot lookup failed (sqlite "
                               "rc=%d): %s",
                               (int)cve_id_len, cve_id, rc, sqlite3_errmsg(handle));
            return CYTADEL_SCAN_PERSIST_ERR_DB;
        }
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding severity snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    int kev_flag = 0;
    sqlite3_reset(stmts->kev_stmt);
    sqlite3_clear_bindings(stmts->kev_stmt);
    rc = sqlite3_bind_text(stmts->kev_stmt, 1, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmts->kev_stmt);
        if (rc == SQLITE_ROW) {
            kev_flag = 1;
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            rc = SQLITE_OK;
        }
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: cve_id='%.*s': kev snapshot lookup failed (sqlite rc=%d): %s",
                           (int)cve_id_len, cve_id, rc, sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    bool has_epss = false;
    double epss_score = 0.0;
    sqlite3_reset(stmts->epss_stmt);
    sqlite3_clear_bindings(stmts->epss_stmt);
    rc = sqlite3_bind_text(stmts->epss_stmt, 1, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmts->epss_stmt);
        if (rc == SQLITE_ROW) {
            has_epss = true;
            epss_score = sqlite3_column_double(stmts->epss_stmt, 0);
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            rc = SQLITE_OK;
        }
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: cve_id='%.*s': epss snapshot lookup failed (sqlite rc=%d): %s",
                           (int)cve_id_len, cve_id, rc, sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    sqlite3_reset(stmts->insert_stmt);
    sqlite3_clear_bindings(stmts->insert_stmt);
    rc = sqlite3_bind_int64(stmts->insert_stmt, 1, scan_id);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmts->insert_stmt, 2, detection->host, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmts->insert_stmt, 3, detection->port);
    }
    if (rc == SQLITE_OK) {
        rc = (detection->service != NULL)
                 ? sqlite3_bind_text(stmts->insert_stmt, 4, detection->service, -1, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(stmts->insert_stmt, 4);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmts->insert_stmt, 5, detection->plugin_id, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmts->insert_stmt, 6, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmts->insert_stmt, 7, cytadel_scan_match_status_to_string(verdict.status),
                                -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmts->insert_stmt, 8, severity);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmts->insert_stmt, 9, detection->evidence, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = (detection->remediation != NULL)
                 ? sqlite3_bind_text(stmts->insert_stmt, 10, detection->remediation, -1, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(stmts->insert_stmt, 10);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmts->insert_stmt, 11, kev_flag);
    }
    if (rc == SQLITE_OK) {
        rc = has_epss ? sqlite3_bind_double(stmts->insert_stmt, 12, epss_score)
                       : sqlite3_bind_null(stmts->insert_stmt, 12);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding scan_results insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_step(stmts->insert_stmt);
    if (rc != SQLITE_DONE) {
        cytadel_log_error(
            "scan_persist: cve_id='%.*s': inserting scan_results row failed (sqlite rc=%d): %s",
            (int)cve_id_len, cve_id, rc, sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    out_counts->rows_inserted++;
    return CYTADEL_SCAN_PERSIST_OK;
}

cytadel_scan_persist_status_t cytadel_scan_detect_and_persist(cytadel_db_t *db, long long scan_id,
                                                                const char *vendor, const char *product,
                                                                const cytadel_scan_detection_t *detection,
                                                                cytadel_scan_persist_counts_t *out_counts) {
    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
    }
    if (db == NULL || vendor == NULL || product == NULL || detection == NULL || out_counts == NULL) {
        cytadel_log_error("scan_persist: cytadel_scan_detect_and_persist() called with a NULL argument");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (scan_id <= 0) {
        cytadel_log_error(
            "scan_persist: cytadel_scan_detect_and_persist() called with a non-positive scan_id %lld",
            scan_id);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (detection->host == NULL || detection->host[0] == '\0' || detection->plugin_id == NULL ||
        detection->plugin_id[0] == '\0' || detection->evidence == NULL) {
        cytadel_log_error(
            "scan_persist: detection context is missing a required field (host/plugin_id/evidence)");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (detection->port < 0 || detection->port > 65535) {
        cytadel_log_error("scan_persist: detection->port %d is out of range [0, 65535]", detection->port);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (detection->detected_version == NULL && detection->detected_version_len != 0) {
        cytadel_log_error(
            "scan_persist: detection->detected_version is NULL paired with a nonzero length");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    char vendor_lc[CYTADEL_SCAN_VENDOR_PRODUCT_BUF_LEN];
    char product_lc[CYTADEL_SCAN_VENDOR_PRODUCT_BUF_LEN];
    if (!lowercase_copy(vendor_lc, sizeof(vendor_lc), vendor) ||
        !lowercase_copy(product_lc, sizeof(product_lc), product)) {
        cytadel_log_error("scan_persist: vendor/product is empty or exceeds %d bytes",
                           CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    if (exec_sql(handle, "BEGIN;", "starting scan_persist transaction") != SQLITE_OK) {
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    scan_persist_stmts_t stmts = {NULL, NULL, NULL, NULL};
    if (prepare_group_statements(handle, &stmts) != SQLITE_OK) {
        finalize_group_statements(&stmts);
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a prepare failure");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    /* db-schema.md SS9's candidate lookup, augmented with `ORDER BY cve_id,
     * id` -- see scan_persist.h's own doc comment on
     * cytadel_scan_detect_and_persist() for why this is not a change to
     * the WHERE clause or returned columns, only to result ordering, so
     * this module can group each cve_id's rows by simple adjacency while
     * streaming. */
    static const char *const candidate_sql =
        "SELECT cve_id, version, version_start_including, version_start_excluding, "
        "version_end_including, version_end_excluding, vulnerable "
        "FROM cve_cpe_matches WHERE vendor = ? AND product = ? ORDER BY cve_id, id;";

    sqlite3_stmt *cand_stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, candidate_sql, -1, &cand_stmt, NULL);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(cand_stmt, 1, vendor_lc, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(cand_stmt, 2, product_lc, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing/binding candidate lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(cand_stmt);
        finalize_group_statements(&stmts);
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a candidate-lookup prepare failure");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    cytadel_scan_persist_status_t status = CYTADEL_SCAN_PERSIST_OK;
    char cur_cve_id[CYTADEL_SCAN_CVE_ID_BUF_LEN];
    size_t cur_cve_id_len = 0;
    bool have_group = false;
    bool any_match = false;
    bool any_undecidable = false;
    bool any_no_match = false;
    size_t malformed_count = 0;

    for (;;) {
        rc = sqlite3_step(cand_stmt);
        if (rc == SQLITE_DONE) {
            break;
        }
        if (rc != SQLITE_ROW) {
            cytadel_log_error("scan_persist: stepping candidate lookup failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            status = CYTADEL_SCAN_PERSIST_ERR_DB;
            break;
        }

        const unsigned char *row_cve_id = sqlite3_column_text(cand_stmt, 0);
        int row_cve_id_bytes = sqlite3_column_bytes(cand_stmt, 0);
        if (row_cve_id == NULL || row_cve_id_bytes <= 0 ||
            (size_t)row_cve_id_bytes > CYTADEL_SCAN_CVE_ID_MAX_LEN) {
            /* cve_cpe_matches.cve_id is NOT NULL in the frozen schema, and
             * every writer that has ever inserted a cve_id validated its
             * grammar (cve_id_valid.h) -- this should be unreachable
             * against a DB this project's own ingest wrote. Never trusted
             * at this boundary anyway: skip this one row rather than
             * dereference/copy a NULL or oversized value. */
            cytadel_log_warn(
                "scan_persist: candidate row has a NULL/empty/oversized cve_id -- skipping this row");
            continue;
        }
        size_t row_cve_id_len = (size_t)row_cve_id_bytes;

        bool same_group = have_group && row_cve_id_len == cur_cve_id_len &&
                           memcmp(row_cve_id, cur_cve_id, cur_cve_id_len) == 0;

        if (have_group && !same_group) {
            status = flush_group(handle, &stmts, scan_id, detection, cur_cve_id, cur_cve_id_len, any_match,
                                  any_undecidable, any_no_match, malformed_count, out_counts);
            if (status != CYTADEL_SCAN_PERSIST_OK) {
                break;
            }
            any_match = false;
            any_undecidable = false;
            any_no_match = false;
            malformed_count = 0;
        }

        if (!same_group) {
            memcpy(cur_cve_id, row_cve_id, row_cve_id_len);
            cur_cve_id[row_cve_id_len] = '\0';
            cur_cve_id_len = row_cve_id_len;
            have_group = true;
        }

        cytadel_cpe_match_row_t row;
        row.version = (const char *)sqlite3_column_text(cand_stmt, 1);
        row.version_len = (size_t)sqlite3_column_bytes(cand_stmt, 1);
        row.version_start_including = (const char *)sqlite3_column_text(cand_stmt, 2);
        row.version_start_including_len = (size_t)sqlite3_column_bytes(cand_stmt, 2);
        row.version_start_excluding = (const char *)sqlite3_column_text(cand_stmt, 3);
        row.version_start_excluding_len = (size_t)sqlite3_column_bytes(cand_stmt, 3);
        row.version_end_including = (const char *)sqlite3_column_text(cand_stmt, 4);
        row.version_end_including_len = (size_t)sqlite3_column_bytes(cand_stmt, 4);
        row.version_end_excluding = (const char *)sqlite3_column_text(cand_stmt, 5);
        row.version_end_excluding_len = (size_t)sqlite3_column_bytes(cand_stmt, 5);
        row.vulnerable = sqlite3_column_int(cand_stmt, 6);

        cytadel_cpe_match_t outcome =
            cytadel_cpe_match_evaluate(&row, detection->detected_version, detection->detected_version_len);
        accumulate_outcome(outcome, &any_match, &any_undecidable, &any_no_match, &malformed_count);
    }

    if (have_group && status == CYTADEL_SCAN_PERSIST_OK) {
        status = flush_group(handle, &stmts, scan_id, detection, cur_cve_id, cur_cve_id_len, any_match,
                              any_undecidable, any_no_match, malformed_count, out_counts);
    }

    sqlite3_finalize(cand_stmt);
    finalize_group_statements(&stmts);

    if (status == CYTADEL_SCAN_PERSIST_OK) {
        /* Same transaction as every scan_results row just flushed above --
         * see update_malformed_data_count()'s own doc comment. Must run
         * (and be checked) BEFORE COMMIT so a failure here rolls back the
         * scan_results rows too, never leaving a durable count without the
         * rows it describes or vice versa. */
        status = update_malformed_data_count(handle, scan_id, out_counts->malformed_events);
    }

    if (status != CYTADEL_SCAN_PERSIST_OK) {
        (void)exec_sql(handle, "ROLLBACK;", "rolling back scan_persist after a fatal DB error");
        return status;
    }

    if (exec_sql(handle, "COMMIT;", "committing scan_persist") != SQLITE_OK) {
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    return CYTADEL_SCAN_PERSIST_OK;
}

/* ------------------------------------------------------------------ */
/* M9 Phase 0: cytadel_scan_persist_finding() -- direct plugin findings. */
/* ------------------------------------------------------------------ */

/* db-schema.md SS9's "KEV/EPSS reconciliation upsert", cves half --
 * reproduced verbatim (FROZEN CONTRACT text), byte-for-byte identical to
 * src/db/kev_ingest.c's/epss_ingest.c's own CYTADEL_KEV_CVE_PLACEHOLDER_SQL/
 * CYTADEL_EPSS_CVE_PLACEHOLDER_SQL. Kept as its own static copy in this
 * translation unit rather than shared, matching this project's existing
 * per-TU-copy convention for fixed SQL text (epss_ingest.c's own comment on
 * its copy explains the precedent this follows: nvd_ingest.c/db_migrations.c
 * each keep their own exec helper rather than sharing one). M9 Gap #3 fix:
 * this is the SAME placeholder-FK dance KEV/EPSS already rely on, applied
 * here so a plugin-supplied cve_id not yet in `cves` (NVD sync lag, the
 * NORMAL case) satisfies scan_results.cve_id's hard FK instead of failing
 * the whole row. */
static const char *const CYTADEL_SCAN_CVE_PLACEHOLDER_SQL =
    "INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at) "
    "VALUES (?, ?, ?, '', 0, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO NOTHING;";

/* db-schema.md SS9's "Is this CVE in KEV?" query, standalone (not sharing
 * cytadel_scan_detect_and_persist()'s own cached scan_persist_stmts_t --
 * this is called at most once per cytadel_scan_persist_finding() call, so
 * the prepare-per-call cost this incurs is not worth sharing statement
 * lifetime/caching machinery across the two, independent call sites). */
static cytadel_scan_persist_status_t lookup_kev_flag(sqlite3 *handle, const char *cve_id, size_t cve_id_len,
                                                       int *out_kev_flag) {
    *out_kev_flag = 0;
    static const char *const sql = "SELECT 1 FROM kev WHERE cve_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing kev snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }
    rc = sqlite3_bind_text(stmt, 1, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            *out_kev_flag = 1;
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            rc = SQLITE_OK;
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: kev snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }
    return CYTADEL_SCAN_PERSIST_OK;
}

/* db-schema.md SS9's "What's its EPSS?" query, standalone -- see
 * lookup_kev_flag()'s own comment for why this does not share
 * cytadel_scan_detect_and_persist()'s cached statements. */
static cytadel_scan_persist_status_t lookup_epss_score(sqlite3 *handle, const char *cve_id, size_t cve_id_len,
                                                          bool *out_has_epss, double *out_epss_score) {
    *out_has_epss = false;
    *out_epss_score = 0.0;
    static const char *const sql = "SELECT epss_score FROM epss WHERE cve_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing epss snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }
    rc = sqlite3_bind_text(stmt, 1, cve_id, (int)cve_id_len, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = sqlite3_step(stmt);
        if (rc == SQLITE_ROW) {
            *out_has_epss = true;
            *out_epss_score = sqlite3_column_double(stmt, 0);
            rc = SQLITE_OK;
        } else if (rc == SQLITE_DONE) {
            rc = SQLITE_OK;
        }
    }
    sqlite3_finalize(stmt);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: epss snapshot lookup failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }
    return CYTADEL_SCAN_PERSIST_OK;
}

cytadel_scan_persist_status_t cytadel_scan_persist_finding(cytadel_db_t *db, long long scan_id,
                                                             const cytadel_scan_finding_persist_t *finding) {
    if (db == NULL || finding == NULL) {
        cytadel_log_error("scan_persist: cytadel_scan_persist_finding() called with a NULL db/finding");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (scan_id <= 0) {
        cytadel_log_error(
            "scan_persist: cytadel_scan_persist_finding() called with a non-positive scan_id %lld", scan_id);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (finding->host == NULL || finding->host[0] == '\0' || finding->plugin_id == NULL ||
        finding->plugin_id[0] == '\0' || finding->evidence == NULL) {
        cytadel_log_error(
            "scan_persist: finding is missing a required field (host/plugin_id/evidence)");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (finding->port < 0 || finding->port > 65535) {
        cytadel_log_error("scan_persist: finding->port %d is out of range [0, 65535]", finding->port);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (finding->severity < 0 || finding->severity > 4) {
        cytadel_log_error("scan_persist: finding->severity %d is out of range [0, 4]", finding->severity);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (finding->cve_id != NULL && finding->cve_id[0] == '\0') {
        cytadel_log_error("scan_persist: finding->cve_id is an empty string (use NULL for \"no CVE\")");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    /* M9 Gap #3 fix, defense 1/2 (grammar validation) -- see this function's
     * own header comment in scan_persist.h. `finding->cve_id` is untrusted
     * plugin input; a value that does not fully match the shared CVE-ID
     * grammar is NEVER used as a PK/FK -- this finding is persisted with
     * cve_id=NULL instead (kev_flag=0, epss_score=NULL below), not rejected
     * outright. */
    const char *effective_cve_id = NULL;
    size_t effective_cve_id_len = 0;
    if (finding->cve_id != NULL) {
        if (cytadel_is_valid_cve_id(finding->cve_id)) {
            effective_cve_id = finding->cve_id;
            effective_cve_id_len = strlen(finding->cve_id);
        } else {
            cytadel_log_warn(
                "scan_persist: host=%s plugin_id=%s: plugin-supplied cve_id '%s' does not fully match "
                "the CVE-ID grammar -- persisting this finding with cve_id=NULL (a bad key must never "
                "become a PK/FK)",
                finding->host, finding->plugin_id, finding->cve_id);
        }
    }

    int kev_flag = 0;
    bool has_epss = false;
    double epss_score = 0.0;
    if (effective_cve_id != NULL) {
        cytadel_scan_persist_status_t st =
            lookup_kev_flag(handle, effective_cve_id, effective_cve_id_len, &kev_flag);
        if (st != CYTADEL_SCAN_PERSIST_OK) {
            return st;
        }
        st = lookup_epss_score(handle, effective_cve_id, effective_cve_id_len, &has_epss, &epss_score);
        if (st != CYTADEL_SCAN_PERSIST_OK) {
            return st;
        }
    }

    if (exec_sql(handle, "BEGIN;", "starting cytadel_scan_persist_finding transaction") != SQLITE_OK) {
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    /* M9 Gap #3 fix, defense 2/2 (placeholder-FK dance) -- for a well-formed
     * cve_id not yet present in `cves` (NVD sync lag, the NORMAL case), run
     * the SAME placeholder upsert KEV/EPSS already use, in the SAME
     * transaction as the scan_results insert below (atomic: either both rows
     * land, or neither does). See this function's own scan_persist.h doc
     * comment for the full fatal-vs-per-row rc classification. */
    if (effective_cve_id != NULL) {
        char now_ts[CYTADEL_ISO8601_BUF_LEN];
        if (cytadel_log_format_timestamp_utc(now_ts, sizeof(now_ts)) != 0) {
            cytadel_log_error(
                "scan_persist: cve_id=%s: formatting cves placeholder timestamp failed -- treating as a "
                "fatal error",
                effective_cve_id);
            (void)exec_sql(handle, "ROLLBACK;", "rolling back after a placeholder timestamp failure");
            return CYTADEL_SCAN_PERSIST_ERR_DB;
        }

        sqlite3_stmt *placeholder_stmt = NULL;
        int rc = sqlite3_prepare_v2(handle, CYTADEL_SCAN_CVE_PLACEHOLDER_SQL, -1, &placeholder_stmt, NULL);
        if (rc != SQLITE_OK) {
            cytadel_log_error("scan_persist: preparing cves placeholder upsert failed (sqlite rc=%d): %s",
                               rc, sqlite3_errmsg(handle));
            (void)exec_sql(handle, "ROLLBACK;", "rolling back after a placeholder prepare failure");
            return CYTADEL_SCAN_PERSIST_ERR_DB;
        }
        rc = sqlite3_bind_text(placeholder_stmt, 1, effective_cve_id, (int)effective_cve_id_len,
                                SQLITE_TRANSIENT);
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(placeholder_stmt, 2, now_ts, -1, SQLITE_TRANSIENT);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_bind_text(placeholder_stmt, 3, now_ts, -1, SQLITE_TRANSIENT);
        }
        if (rc != SQLITE_OK) {
            cytadel_log_error("scan_persist: binding cves placeholder upsert failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            sqlite3_finalize(placeholder_stmt);
            (void)exec_sql(handle, "ROLLBACK;", "rolling back after a placeholder bind failure");
            return CYTADEL_SCAN_PERSIST_ERR_DB;
        }

        rc = sqlite3_step(placeholder_stmt);
        sqlite3_finalize(placeholder_stmt);
        if (rc != SQLITE_DONE) {
            if (rc == SQLITE_CONSTRAINT) {
                /* Per-row, NOT fatal (see this function's own scan_persist.h
                 * "M9 Gap #3 fix" comment for the classification rule) --
                 * skip only this finding; the connection is still usable. */
                cytadel_log_warn(
                    "scan_persist: host=%s plugin_id=%s cve_id=%s: cves placeholder upsert rejected by a "
                    "constraint -- skipping this finding (per-row, does not abort the rest of this host/scan)",
                    finding->host, finding->plugin_id, effective_cve_id);
                (void)exec_sql(handle, "ROLLBACK;", "rolling back after a placeholder constraint rejection");
                return CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED;
            }
            cytadel_log_error(
                "scan_persist: cve_id=%s: fatal sqlite error upserting cves placeholder row (sqlite "
                "rc=%d): %s",
                effective_cve_id, rc, sqlite3_errmsg(handle));
            (void)exec_sql(handle, "ROLLBACK;", "rolling back after a fatal placeholder step failure");
            return CYTADEL_SCAN_PERSIST_ERR_DB;
        }
    }

    /* db-schema.md SS9's scan_results insert pattern -- match_status is
     * always the fixed literal 'confirmed' here (never bound from any
     * caller-controlled value): a direct plugin finding is not a
     * candidate-CVE-range verdict, so cpe-matching.md's three-valued
     * aggregation has no role in this call site at all. */
    static const char *const sql =
        "INSERT INTO scan_results (scan_id, host, port, service, plugin_id, cve_id, match_status, "
        "severity, evidence, remediation, kev_flag, epss_score, detected_at) "
        "VALUES (?, ?, ?, ?, ?, ?, 'confirmed', ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing finding insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a finding-insert prepare failure");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_bind_int64(stmt, 1, scan_id);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, finding->host, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 3, finding->port);
    }
    if (rc == SQLITE_OK) {
        rc = (finding->service != NULL) ? sqlite3_bind_text(stmt, 4, finding->service, -1, SQLITE_TRANSIENT)
                                          : sqlite3_bind_null(stmt, 4);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 5, finding->plugin_id, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = (effective_cve_id != NULL)
                 ? sqlite3_bind_text(stmt, 6, effective_cve_id, (int)effective_cve_id_len, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(stmt, 6);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 7, finding->severity);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 8, finding->evidence, -1, SQLITE_TRANSIENT);
    }
    if (rc == SQLITE_OK) {
        rc = (finding->remediation != NULL)
                 ? sqlite3_bind_text(stmt, 9, finding->remediation, -1, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(stmt, 9);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int(stmt, 10, kev_flag);
    }
    if (rc == SQLITE_OK) {
        rc = has_epss ? sqlite3_bind_double(stmt, 11, epss_score) : sqlite3_bind_null(stmt, 11);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding finding insert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a finding-insert bind failure");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            /* Per-row, NOT fatal -- this is exactly the M9 Gap #3 regression
             * scenario (a bad/rejected scan_results row) but now correctly
             * scoped to just this one finding: the transaction (including
             * any placeholder cves row just upserted above) rolls back
             * together, so no orphaned placeholder is ever left behind, and
             * the connection remains fully usable for the very next call. */
            cytadel_log_warn(
                "scan_persist: host=%s plugin_id=%s: scan_results insert rejected by a constraint -- "
                "skipping this finding (per-row, does not abort the rest of this host/scan)",
                finding->host, finding->plugin_id);
            (void)exec_sql(handle, "ROLLBACK;", "rolling back after a finding-insert constraint rejection");
            return CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED;
        }
        cytadel_log_error("scan_persist: inserting finding row failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a fatal finding-insert step failure");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    if (exec_sql(handle, "COMMIT;", "committing cytadel_scan_persist_finding") != SQLITE_OK) {
        (void)exec_sql(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    return CYTADEL_SCAN_PERSIST_OK;
}

/* ------------------------------------------------------------------ */
/* M9 Phase 0: cytadel_scan_finalize().                                */
/* ------------------------------------------------------------------ */

const char *cytadel_scan_finalize_status_to_string(cytadel_scan_finalize_status_t status) {
    switch (status) {
        case CYTADEL_SCAN_FINALIZE_COMPLETED: return "completed";
        case CYTADEL_SCAN_FINALIZE_ABORTED:   return "aborted";
        case CYTADEL_SCAN_FINALIZE_FAILED:    return "failed";
    }
    return "UNKNOWN";
}

cytadel_scan_persist_status_t cytadel_scan_finalize(cytadel_db_t *db, long long scan_id,
                                                      cytadel_scan_finalize_status_t status) {
    if (db == NULL) {
        cytadel_log_error("scan_persist: cytadel_scan_finalize() called with a NULL db");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (scan_id <= 0) {
        cytadel_log_error("scan_persist: cytadel_scan_finalize() called with a non-positive scan_id %lld",
                           scan_id);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    static const char *const sql =
        "UPDATE scans SET status = ?, finished_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') "
        "WHERE scan_id = ?;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: preparing scans finalize update failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    /* status_str is always one of this module's own fixed literals
     * (cytadel_scan_finalize_status_to_string() never returns NULL and
     * never returns a caller-supplied string) -- SQLITE_STATIC is safe
     * since the referenced storage is a static string literal, not a
     * stack/heap buffer whose lifetime could end before sqlite3_step(). */
    const char *status_str = cytadel_scan_finalize_status_to_string(status);
    rc = sqlite3_bind_text(stmt, 1, status_str, -1, SQLITE_STATIC);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_int64(stmt, 2, scan_id);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("scan_persist: binding scans finalize update failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cytadel_log_error("scan_persist: updating scans row for finalize failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    if (sqlite3_changes(handle) == 0) {
        /* UPDATE ... WHERE matched zero rows -- not a sqlite3-level error,
         * but this call chain believes scan_id names a real scans row (it
         * came from a prior cytadel_scan_create() call), so zero rows
         * changed means that belief was wrong -- surface it rather than
         * silently reporting success for a finalize that finalized nothing. */
        cytadel_log_error("scan_persist: cytadel_scan_finalize() found no scans row for scan_id=%lld",
                           scan_id);
        return CYTADEL_SCAN_PERSIST_ERR_DB;
    }

    return CYTADEL_SCAN_PERSIST_OK;
}
