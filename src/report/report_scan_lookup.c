#include "cytadel/report/report.h"

#include <sqlite3.h>

#include "log.h"

/* Milestone 8 slice 5: see include/cytadel/report/report.h's own
 * cytadel_report_find_latest_scan_id() comment for the full contract. This
 * file holds ONLY that one query -- kept separate from report_html.c/
 * report_json.c (which both read a scan_id the CALLER already knows) so
 * neither of those files needs to also own the very different "which
 * scan_id are we even reporting on" question. */

cytadel_report_status_t cytadel_report_find_latest_scan_id(cytadel_db_t *db, long long *out_scan_id) {
    if (db == NULL || out_scan_id == NULL) {
        cytadel_log_error(
            "report: cytadel_report_find_latest_scan_id() called with a NULL db/out_scan_id");
        return CYTADEL_REPORT_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    /* db-schema.md SS6: idx_scans_started_at (started_at DESC) serves this
     * exact query without a sort. */
    static const char *const sql = "SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT 1;";

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("report: preparing latest-scan query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_REPORT_ERR_DB;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        sqlite3_finalize(stmt);
        cytadel_log_warn("report: no scans rows exist yet -- nothing to report on");
        return CYTADEL_REPORT_ERR_NOT_FOUND;
    }
    if (rc != SQLITE_ROW) {
        cytadel_log_error("report: stepping latest-scan query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_REPORT_ERR_DB;
    }

    *out_scan_id = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return CYTADEL_REPORT_OK;
}
