#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/db/nvd_ingest.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

#include "cytadel/db/kev_ingest.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <string.h>

#include "cve_id_valid.h"
#include "log.h"

/* KEV/EPSS ingest slice: see include/cytadel/db/kev_ingest.h for the full
 * design/contract this file implements. This module mirrors
 * src/db/nvd_ingest.c's architecture exactly -- see that file's own
 * top-of-file comment for the fully-documented hostile-input defenses this
 * file relies on throughout (every cJSON_Is*()/GetObjectItemCaseSensitive()
 * check happens before any deref, both are NULL-safe on a wrong-typed/
 * missing ancestor; every sqlite3_step() outcome is classified into exactly
 * one of SQLITE_DONE (success)/SQLITE_CONSTRAINT (skip-and-log, never
 * fatal)/anything else (fatal, aborts via ROLLBACK); every TEXT bind is
 * clipped to a fixed cap rather than rejected for size).
 *
 * Deviations from the NVD pattern, and why:
 *
 *   - No pagination/window concept from the remote feed's own side -- the
 *     CISA KEV catalog is always fetched as one whole file (db-schema.md
 *     SS4: "refreshed daily (full-file re-pull)"). `full_pull_complete`
 *     still exists (mirroring nvd_ingest.h's `window_complete`) purely as a
 *     safety valve for a *future* fetch driver that might choose to hand
 *     this module the file in more than one call; this module itself makes
 *     no assumption about how many calls constitute "the whole file".
 *   - No `lastmod_end_date` parameter: KEV/EPSS have no remote delta cursor
 *     (db-schema.md SS8's `sync_state.last_mod_watermark` doc comment: "the
 *     local ingestion date of the last successful pull"). The watermark
 *     value itself is therefore computed by SQLite (`strftime('%Y-%m-%d',
 *     'now')`) inside the sync_state UPDATE, not threaded through from a
 *     caller-supplied argument the way NVD's window cursor is.
 *   - The placeholder-FK dance (db-schema.md SS9/SS10 assumption 5) runs
 *     before every kev upsert -- nvd_ingest.c never needs this (it only
 *     ever writes source='nvd' rows and is itself the table that
 *     `kev`/`epss` reference).
 *   - cve_id validation calls the ONE shared cytadel_is_valid_cve_id()
 *     (src/db/cve_id_valid.h) rather than a second, independently
 *     hand-rolled grammar check -- see that header's own comment.
 */

/* Pre-parse sanity cap on the raw byte length of the KEV JSON buffer,
 * checked BEFORE cJSON_ParseWithLength() is ever called -- same rationale as
 * nvd_ingest.c's CYTADEL_NVD_PAGE_MAX_BYTES: fail fast against a hostile/
 * corrupted `len` instead of relying on the allocator's own back-pressure.
 * The real KEV catalog (a few thousand records) is far smaller than this in
 * practice. */
#define CYTADEL_KEV_MAX_BYTES (64 * 1024 * 1024)

#define CYTADEL_KEV_CVE_ID_MAX_LEN 64
#define CYTADEL_KEV_CVE_ID_BUF_LEN (CYTADEL_KEV_CVE_ID_MAX_LEN + 1)

/* 'YYYY-MM-DD' is 10 bytes; generous headroom for a slightly-longer-than-
 * expected but still plausible date string, while still bounding a hostile
 * one. */
#define CYTADEL_KEV_DATE_MAX_LEN 32
#define CYTADEL_KEV_DATE_BUF_LEN (CYTADEL_KEV_DATE_MAX_LEN + 1)

#define CYTADEL_KEV_VENDOR_PRODUCT_MAX_LEN 256
#define CYTADEL_KEV_VENDOR_PRODUCT_BUF_LEN (CYTADEL_KEV_VENDOR_PRODUCT_MAX_LEN + 1)

/* CISA's "vulnerabilityName" is a short descriptive title, but not as short
 * as a vendor/product token -- generous headroom for a real one. */
#define CYTADEL_KEV_NAME_MAX_LEN 512
#define CYTADEL_KEV_NAME_BUF_LEN (CYTADEL_KEV_NAME_MAX_LEN + 1)

/* "requiredAction" is often a full sentence or two. */
#define CYTADEL_KEV_ACTION_MAX_LEN 2048
#define CYTADEL_KEV_ACTION_BUF_LEN (CYTADEL_KEV_ACTION_MAX_LEN + 1)

#define CYTADEL_KEV_NOTES_BUF_LEN (CYTADEL_KEV_NOTES_MAX_LEN + 1)

const char *cytadel_kev_ingest_status_to_string(cytadel_kev_ingest_status_t status) {
    switch (status) {
        case CYTADEL_KEV_INGEST_OK:              return "OK";
        case CYTADEL_KEV_INGEST_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_KEV_INGEST_ERR_PARSE:       return "PARSE";
        case CYTADEL_KEV_INGEST_ERR_DB:          return "DB";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* Small bounded-copy / cJSON-field-extraction helpers (same shapes as     */
/* nvd_ingest.c's own file-static copies -- kept as separate per-TU        */
/* copies rather than shared, matching that file's own cytadel_nvd_exec()  */
/* vs db_migrations.c's cytadel_db_exec() precedent: neither helper is     */
/* part of either module's public surface).                                */
/* ------------------------------------------------------------------ */

static void clip_into(char *dst, size_t dst_cap, const char *src) {
    size_t n = strnlen(src, dst_cap - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

static bool json_get_string(const cJSON *obj, const char *key, const char **out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return false;
    }
    *out = item->valuestring;
    return true;
}

/* ------------------------------------------------------------------ */
/* Prepared-statement plumbing.                                       */
/* ------------------------------------------------------------------ */

/* db-schema.md SS9's "KEV/EPSS reconciliation upsert", cves half --
 * reproduced verbatim (FROZEN CONTRACT text, do not edit without a
 * stop-and-ask). `published`/`last_modified` are bound to this record's own
 * ingestion timestamp -- a placeholder row's job is only to satisfy the FK
 * until the NVD sync (if it ever reaches this CVE) unconditionally
 * overwrites every column via its own upsert's ON CONFLICT branch. */
static const char *const CYTADEL_KEV_CVE_PLACEHOLDER_SQL =
    "INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at) "
    "VALUES (?, ?, ?, '', 0, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO NOTHING;";

/* db-schema.md SS9's "KEV/EPSS reconciliation upsert", kev half --
 * reproduced verbatim (FROZEN CONTRACT text, do not edit without a
 * stop-and-ask). Note the ON CONFLICT clause deliberately does NOT
 * re-assign vendor_project/product/vulnerability_name on an update -- this
 * is the contract's own literal text, not an oversight to "fix" here. */
static const char *const CYTADEL_KEV_UPSERT_SQL =
    "INSERT INTO kev (cve_id, date_added, vendor_project, product, vulnerability_name, "
    "required_action, due_date, known_ransomware, notes, synced_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO UPDATE SET "
    "date_added = excluded.date_added, due_date = excluded.due_date, "
    "required_action = excluded.required_action, known_ransomware = excluded.known_ransomware, "
    "notes = excluded.notes, synced_at = excluded.synced_at;";

/* Not part of db-schema.md SS9's illustrative query list (sync_state's own
 * update is only described procedurally) -- this module's own parameterized
 * statements implementing that documented procedure for feed='kev', only
 * ever reached inside the same transaction as this call's own data (see
 * cytadel_kev_ingest()). Mirrors nvd_ingest.c's COMPLETE/PARTIAL split
 * (W2-style): selected by `full_pull_complete`, exactly one of the two is
 * ever prepared/used per call. Unlike NVD, the watermark value itself
 * (`strftime('%Y-%m-%d','now')`) needs no bound parameter -- there is no
 * caller-supplied cursor for this feed (see this file's top-of-file
 * comment). */
static const char *const CYTADEL_KEV_SYNC_STATE_COMPLETE_SQL =
    "UPDATE sync_state SET "
    "last_mod_watermark = strftime('%Y-%m-%d','now'), "
    "last_sync_completed = strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
    "total_records = total_records + ?, "
    "status = 'success', "
    "last_error = NULL "
    "WHERE feed = 'kev';";

static const char *const CYTADEL_KEV_SYNC_STATE_PARTIAL_SQL =
    "UPDATE sync_state SET "
    "total_records = total_records + ?, "
    "status = 'running', "
    "last_error = NULL "
    "WHERE feed = 'kev';";

static int cytadel_kev_exec(sqlite3 *handle, const char *sql, const char *context) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: %s failed (sqlite rc=%d): %s", context, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

static int prepare_statements(sqlite3 *handle, bool full_pull_complete, sqlite3_stmt **placeholder_stmt,
                               sqlite3_stmt **kev_stmt, sqlite3_stmt **sync_stmt) {
    int rc = sqlite3_prepare_v2(handle, CYTADEL_KEV_CVE_PLACEHOLDER_SQL, -1, placeholder_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: preparing cves placeholder upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, CYTADEL_KEV_UPSERT_SQL, -1, kev_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: preparing kev upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    const char *sync_sql =
        full_pull_complete ? CYTADEL_KEV_SYNC_STATE_COMPLETE_SQL : CYTADEL_KEV_SYNC_STATE_PARTIAL_SQL;
    rc = sqlite3_prepare_v2(handle, sync_sql, -1, sync_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: preparing sync_state update failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    return SQLITE_OK;
}

static void finalize_all(sqlite3_stmt *placeholder_stmt, sqlite3_stmt *kev_stmt, sqlite3_stmt *sync_stmt) {
    sqlite3_finalize(placeholder_stmt);
    sqlite3_finalize(kev_stmt);
    sqlite3_finalize(sync_stmt);
}

/* ------------------------------------------------------------------ */
/* Per-record processing.                                              */
/* ------------------------------------------------------------------ */

static void process_one_kev(sqlite3_stmt *placeholder_stmt, sqlite3_stmt *kev_stmt, const cJSON *elem,
                             cytadel_kev_ingest_counts_t *counts, bool *fatal_db_error) {
    const char *cve_id_raw = NULL;
    if (!json_get_string(elem, "cveID", &cve_id_raw) || cve_id_raw[0] == '\0' ||
        strnlen(cve_id_raw, CYTADEL_KEV_CVE_ID_MAX_LEN + 1) > CYTADEL_KEV_CVE_ID_MAX_LEN ||
        !cytadel_is_valid_cve_id(cve_id_raw)) {
        /* Same W3-class defense as nvd_ingest.c: a bad/malformed/oversized/
         * embedded-NUL-truncated id is never allowed to reach
         * sqlite3_bind_text() as either a PK or (here) an FK-satisfying
         * placeholder-row key. */
        cytadel_log_warn(
            "kev_ingest: <no id>: 'cveID' is missing/empty/non-string/oversized/malformed (does not fully "
            "match the CVE-ID grammar) -- skipping this record");
        counts->kev_skipped++;
        return;
    }
    char cve_id[CYTADEL_KEV_CVE_ID_BUF_LEN];
    clip_into(cve_id, sizeof(cve_id), cve_id_raw);

    const char *date_added_raw = NULL;
    if (!json_get_string(elem, "dateAdded", &date_added_raw) || date_added_raw[0] == '\0') {
        cytadel_log_warn("kev_ingest: %s: 'dateAdded' is missing/empty/non-string -- skipping this record",
                          cve_id);
        counts->kev_skipped++;
        return;
    }
    char date_added[CYTADEL_KEV_DATE_BUF_LEN];
    clip_into(date_added, sizeof(date_added), date_added_raw);

    const char *vendor_project_raw = NULL;
    if (!json_get_string(elem, "vendorProject", &vendor_project_raw) || vendor_project_raw[0] == '\0') {
        cytadel_log_warn(
            "kev_ingest: %s: 'vendorProject' is missing/empty/non-string -- skipping this record", cve_id);
        counts->kev_skipped++;
        return;
    }
    char vendor_project[CYTADEL_KEV_VENDOR_PRODUCT_BUF_LEN];
    clip_into(vendor_project, sizeof(vendor_project), vendor_project_raw);

    const char *product_raw = NULL;
    if (!json_get_string(elem, "product", &product_raw) || product_raw[0] == '\0') {
        cytadel_log_warn("kev_ingest: %s: 'product' is missing/empty/non-string -- skipping this record",
                          cve_id);
        counts->kev_skipped++;
        return;
    }
    char product[CYTADEL_KEV_VENDOR_PRODUCT_BUF_LEN];
    clip_into(product, sizeof(product), product_raw);

    const char *vuln_name_raw = NULL;
    if (!json_get_string(elem, "vulnerabilityName", &vuln_name_raw) || vuln_name_raw[0] == '\0') {
        cytadel_log_warn(
            "kev_ingest: %s: 'vulnerabilityName' is missing/empty/non-string -- skipping this record", cve_id);
        counts->kev_skipped++;
        return;
    }
    char vulnerability_name[CYTADEL_KEV_NAME_BUF_LEN];
    clip_into(vulnerability_name, sizeof(vulnerability_name), vuln_name_raw);

    /* Nullable per db-schema.md SS4: requiredAction, dueDate, notes. Absent,
     * wrong-typed, or empty all bind SQL NULL -- an empty string is treated
     * identically to "field not present", matching nvd_ingest.c's own
     * extract_first_cvss() convention for its optional string fields
     * (vector/severity only counted "present" when non-empty). Only a
     * present, non-empty string is clipped and stored. */
    const char *tmp = NULL;
    bool has_required_action = json_get_string(elem, "requiredAction", &tmp) && tmp[0] != '\0';
    char required_action[CYTADEL_KEV_ACTION_BUF_LEN];
    if (has_required_action) {
        clip_into(required_action, sizeof(required_action), tmp);
    }

    tmp = NULL;
    bool has_due_date = json_get_string(elem, "dueDate", &tmp) && tmp[0] != '\0';
    char due_date[CYTADEL_KEV_DATE_BUF_LEN];
    if (has_due_date) {
        clip_into(due_date, sizeof(due_date), tmp);
    }

    tmp = NULL;
    bool has_notes = json_get_string(elem, "notes", &tmp) && tmp[0] != '\0';
    char notes[CYTADEL_KEV_NOTES_BUF_LEN];
    if (has_notes) {
        clip_into(notes, sizeof(notes), tmp);
    }

    /* "knownRansomwareCampaignUse": 'Known' -> 1, anything else (absent,
     * wrong-typed, 'Unknown', or any other string) -> 0. */
    tmp = NULL;
    bool known_ransomware = json_get_string(elem, "knownRansomwareCampaignUse", &tmp) && strcmp(tmp, "Known") == 0;

    /* Placeholder-FK dance FIRST (db-schema.md SS9/SS10 assumption 5) --
     * kev.cve_id is a hard FK into cves(cve_id), and the KEV feed can name a
     * CVE the NVD sync has not reached yet. Both published/last_modified
     * are bound to this record's own ingestion timestamp. */
    char now_ts[CYTADEL_ISO8601_BUF_LEN];
    if (cytadel_log_format_timestamp_utc(now_ts, sizeof(now_ts)) != 0) {
        cytadel_log_error("kev_ingest: %s: formatting placeholder timestamp failed -- treating as a fatal error",
                           cve_id);
        *fatal_db_error = true;
        return;
    }

    sqlite3_reset(placeholder_stmt);
    sqlite3_clear_bindings(placeholder_stmt);
    int rc = sqlite3_bind_text(placeholder_stmt, 1, cve_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(placeholder_stmt, 2, now_ts, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(placeholder_stmt, 3, now_ts, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: %s: binding cves placeholder upsert failed (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(placeholder_stmt)));
        counts->kev_skipped++;
        return;
    }
    rc = sqlite3_step(placeholder_stmt);
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            cytadel_log_warn(
                "kev_ingest: %s: cves placeholder upsert rejected by a constraint -- skipping this record",
                cve_id);
            counts->kev_skipped++;
            return;
        }
        cytadel_log_error("kev_ingest: %s: fatal sqlite error upserting cves placeholder row (sqlite rc=%d): %s",
                           cve_id, rc, sqlite3_errmsg(sqlite3_db_handle(placeholder_stmt)));
        *fatal_db_error = true;
        return;
    }

    sqlite3_reset(kev_stmt);
    sqlite3_clear_bindings(kev_stmt);
    rc = sqlite3_bind_text(kev_stmt, 1, cve_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(kev_stmt, 2, date_added, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(kev_stmt, 3, vendor_project, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(kev_stmt, 4, product, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(kev_stmt, 5, vulnerability_name, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = has_required_action ? sqlite3_bind_text(kev_stmt, 6, required_action, -1, SQLITE_TRANSIENT)
                                  : sqlite3_bind_null(kev_stmt, 6);
    }
    if (rc == SQLITE_OK) {
        rc = has_due_date ? sqlite3_bind_text(kev_stmt, 7, due_date, -1, SQLITE_TRANSIENT)
                           : sqlite3_bind_null(kev_stmt, 7);
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(kev_stmt, 8, known_ransomware ? 1 : 0);
    if (rc == SQLITE_OK) {
        rc = has_notes ? sqlite3_bind_text(kev_stmt, 9, notes, -1, SQLITE_TRANSIENT) : sqlite3_bind_null(kev_stmt, 9);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("kev_ingest: %s: binding kev upsert failed (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(kev_stmt)));
        counts->kev_skipped++;
        return;
    }

    rc = sqlite3_step(kev_stmt);
    if (rc == SQLITE_DONE) {
        counts->kev_ingested++;
    } else if (rc == SQLITE_CONSTRAINT) {
        cytadel_log_warn("kev_ingest: %s: kev upsert rejected by a CHECK/constraint -- skipping this record",
                          cve_id);
        counts->kev_skipped++;
    } else {
        cytadel_log_error("kev_ingest: %s: fatal sqlite error upserting kev row (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(kev_stmt)));
        *fatal_db_error = true;
    }
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

cytadel_kev_ingest_status_t cytadel_kev_ingest(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                bool full_pull_complete,
                                                cytadel_kev_ingest_counts_t *out_counts) {
    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
    }
    if (db == NULL || json_bytes == NULL || out_counts == NULL) {
        cytadel_log_error("kev_ingest: cytadel_kev_ingest() called with a NULL db/json_bytes/out_counts");
        return CYTADEL_KEV_INGEST_ERR_INVALID_ARG;
    }

    if (len > CYTADEL_KEV_MAX_BYTES) {
        cytadel_log_error(
            "kev_ingest: buffer length %zu exceeds the %d-byte sanity cap -- rejecting without parsing; no "
            "data was written and sync_state is unchanged",
            len, CYTADEL_KEV_MAX_BYTES);
        return CYTADEL_KEV_INGEST_ERR_PARSE;
    }

    /* Parsed BEFORE any transaction is opened -- a truncated/malformed
     * document never touches the DB at all, so sync_state cannot possibly
     * be perturbed by this call in that case. */
    cJSON *root = cJSON_ParseWithLength(json_bytes, len);
    if (root == NULL) {
        cytadel_log_error(
            "kev_ingest: cJSON_ParseWithLength() failed to parse this buffer (truncated or invalid JSON) -- "
            "rejecting the whole ingest; no data was written and sync_state is unchanged");
        return CYTADEL_KEV_INGEST_ERR_PARSE;
    }
    if (!cJSON_IsObject(root)) {
        cytadel_log_error(
            "kev_ingest: top-level KEV document is not a JSON object -- rejecting the whole ingest; no data "
            "was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_PARSE;
    }

    /* Only a present JSON ARRAY value for "vulnerabilities" is a valid
     * buffer -- an empty array (`[]`) IS valid (0 records, still OK). A
     * missing/wrong-typed "vulnerabilities" is treated as a corrupted/
     * tampered file and rejected outright, exactly like malformed JSON
     * (mirrors nvd_ingest.c's W1 fix). */
    const cJSON *vulnerabilities = cJSON_GetObjectItemCaseSensitive(root, "vulnerabilities");
    if (!cJSON_IsArray(vulnerabilities)) {
        cytadel_log_error(
            "kev_ingest: top-level 'vulnerabilities' is missing or not an array -- rejecting the whole "
            "ingest; no data was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_PARSE;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    if (cytadel_kev_exec(handle, "BEGIN;", "starting kev_ingest transaction") != SQLITE_OK) {
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_DB;
    }

    sqlite3_stmt *placeholder_stmt = NULL;
    sqlite3_stmt *kev_stmt = NULL;
    sqlite3_stmt *sync_stmt = NULL;
    if (prepare_statements(handle, full_pull_complete, &placeholder_stmt, &kev_stmt, &sync_stmt) != SQLITE_OK) {
        finalize_all(placeholder_stmt, kev_stmt, sync_stmt);
        (void)cytadel_kev_exec(handle, "ROLLBACK;", "rolling back after a prepare failure");
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_DB;
    }

    bool fatal_db_error = false;

    {
        size_t processed = 0;
        const cJSON *elem = vulnerabilities->child;
        for (; elem != NULL && processed < CYTADEL_KEV_MAX_RECORDS; elem = elem->next, processed++) {
            if (!cJSON_IsObject(elem)) {
                out_counts->kev_skipped++;
                continue;
            }
            process_one_kev(placeholder_stmt, kev_stmt, elem, out_counts, &fatal_db_error);
            if (fatal_db_error) {
                break;
            }
        }
        if (!fatal_db_error && processed >= CYTADEL_KEV_MAX_RECORDS && elem != NULL) {
            cytadel_log_warn(
                "kev_ingest: buffer exceeds %d entries -- remaining entries were not processed (hostile/"
                "oversized input)",
                CYTADEL_KEV_MAX_RECORDS);
            for (; elem != NULL; elem = elem->next) {
                out_counts->kev_skipped++;
            }
        }
    }

    if (!fatal_db_error) {
        sqlite3_int64 records_seen = (sqlite3_int64)(out_counts->kev_ingested + out_counts->kev_skipped);
        int rc = sqlite3_bind_int64(sync_stmt, 1, records_seen);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(sync_stmt);
        }
        if (rc != SQLITE_OK && rc != SQLITE_DONE) {
            cytadel_log_error("kev_ingest: updating sync_state failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            fatal_db_error = true;
        }
    }

    finalize_all(placeholder_stmt, kev_stmt, sync_stmt);

    if (fatal_db_error) {
        (void)cytadel_kev_exec(handle, "ROLLBACK;", "rolling back kev_ingest after a fatal DB error");
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_DB;
    }

    if (cytadel_kev_exec(handle, "COMMIT;", "committing kev_ingest") != SQLITE_OK) {
        (void)cytadel_kev_exec(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
        cJSON_Delete(root);
        return CYTADEL_KEV_INGEST_ERR_DB;
    }

    cJSON_Delete(root);
    return CYTADEL_KEV_INGEST_OK;
}
