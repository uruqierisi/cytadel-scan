#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/db/nvd_ingest.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

#include "cytadel/db/epss_ingest.h"

#include <cJSON.h>
#include <errno.h>
#include <math.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cve_id_valid.h"
#include "log.h"

/* KEV/EPSS ingest slice: see include/cytadel/db/epss_ingest.h for the full
 * design/contract this file implements. This module is the near-twin of
 * src/db/kev_ingest.c in this same slice, itself mirroring
 * src/db/nvd_ingest.c's architecture -- see those two files' own
 * top-of-file comments for the fully-documented hostile-input defenses
 * relied on throughout (every cJSON_Is*()/GetObjectItemCaseSensitive()
 * check happens before any deref; every sqlite3_step() outcome is
 * classified into exactly one of SQLITE_DONE (success)/SQLITE_CONSTRAINT
 * (skip-and-log, never fatal)/anything else (fatal, aborts via ROLLBACK);
 * every TEXT bind is clipped to a fixed cap rather than rejected for size).
 *
 * Deviations from kev_ingest.c, and why:
 *
 *   - Top-level array key is "data", not "vulnerabilities" (first.org's own
 *     API response shape: {"status":"OK", ..., "data": [...]}).
 *   - `epss`/`percentile` arrive as JSON STRINGS (e.g. "0.00042"), not
 *     numbers -- parse_probability_string() below defensively parses each
 *     via strtod(), rejecting anything that is not a fully-consumed,
 *     finite, in-[0.0,1.0] value BEFORE this module ever attempts to bind
 *     or insert it (the schema's own CHECK constraint would also reject an
 *     out-of-range value via SQLITE_CONSTRAINT, but validating first avoids
 *     depending on that being the only guard, per this milestone's task
 *     brief).
 *   - The per-record date field is looked up as "date" first (first.org's
 *     actual field name), falling back to "score_date" if "date" is absent
 *     -- this milestone's task brief describes the field ambiguously
 *     ("a date/score_date field"); supporting both names is the more
 *     defensive choice and costs nothing.
 */

/* Pre-parse sanity cap on the raw byte length of the EPSS JSON buffer,
 * checked BEFORE cJSON_ParseWithLength() is ever called -- same rationale as
 * nvd_ingest.c's CYTADEL_NVD_PAGE_MAX_BYTES. Larger than kev_ingest.c's own
 * cap: a full EPSS pull (~250k+ records) is a meaningfully bigger JSON
 * document than the KEV catalog. */
#define CYTADEL_EPSS_MAX_BYTES (128 * 1024 * 1024)

#define CYTADEL_EPSS_CVE_ID_MAX_LEN 64
#define CYTADEL_EPSS_CVE_ID_BUF_LEN (CYTADEL_EPSS_CVE_ID_MAX_LEN + 1)

#define CYTADEL_EPSS_DATE_BUF_LEN (CYTADEL_EPSS_DATE_MAX_LEN + 1)

/* Real EPSS score/percentile strings look like "0.00042" or "1.00000" --
 * comfortably under 32 bytes. This bounds the amount of text
 * parse_probability_string() will ever hand to strtod(), purely as a
 * hostile-input safety valve (a value claiming to be a huge digit run is
 * rejected outright rather than handed to the C library's float parser). */
#define CYTADEL_EPSS_PROB_STR_MAX_LEN 31

const char *cytadel_epss_ingest_status_to_string(cytadel_epss_ingest_status_t status) {
    switch (status) {
        case CYTADEL_EPSS_INGEST_OK:              return "OK";
        case CYTADEL_EPSS_INGEST_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_EPSS_INGEST_ERR_PARSE:       return "PARSE";
        case CYTADEL_EPSS_INGEST_ERR_DB:          return "DB";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* Small bounded-copy / cJSON-field-extraction / numeric-string helpers.  */
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

/* Defensively parses `s` (a NUL-terminated string, e.g. "0.00042") into a
 * finite double in [0.0, 1.0]. Rejects: NULL/empty, longer than
 * CYTADEL_EPSS_PROB_STR_MAX_LEN bytes, anything strtod() cannot fully
 * consume (trailing garbage such as "1.5abc", or nothing parseable at all
 * such as "abc"), an ERANGE overflow/underflow, a non-finite result (NaN/
 * inf -- a hostile "1e400"-style literal that overflows double parsing),
 * or a value outside [0.0, 1.0] (catches "1.5", "-0.1", and every other
 * out-of-range string this milestone's task brief calls out). Returns true
 * and writes *out only when every one of those checks passes. */
static bool parse_probability_string(const char *s, double *out) {
    if (s == NULL) {
        return false;
    }
    size_t len = strnlen(s, CYTADEL_EPSS_PROB_STR_MAX_LEN + 1);
    if (len == 0 || len > CYTADEL_EPSS_PROB_STR_MAX_LEN) {
        return false;
    }
    /* strtod() requires NUL-termination at some point within a bounded
     * distance -- `s` here is always a cJSON valuestring (already
     * NUL-terminated by cJSON's own parser), and the length check above
     * already bounds how far this could possibly read even if that were
     * somehow not true. */
    char buf[CYTADEL_EPSS_PROB_STR_MAX_LEN + 1];
    memcpy(buf, s, len);
    buf[len] = '\0';

    errno = 0;
    char *endptr = NULL;
    double v = strtod(buf, &endptr);
    if (endptr == buf || *endptr != '\0') {
        return false; /* no conversion at all, or unconsumed trailing text */
    }
    if (errno == ERANGE) {
        return false; /* overflow/underflow */
    }
    if (!isfinite(v)) {
        return false; /* NaN or +/-inf */
    }
    if (v < 0.0 || v > 1.0) {
        return false; /* out of the schema's own [0.0, 1.0] CHECK range */
    }
    *out = v;
    return true;
}

/* ------------------------------------------------------------------ */
/* Prepared-statement plumbing.                                       */
/* ------------------------------------------------------------------ */

/* db-schema.md SS9's "KEV/EPSS reconciliation upsert", cves half --
 * identical text to kev_ingest.c's own copy (FROZEN CONTRACT text, do not
 * edit without a stop-and-ask). Kept as a separate static copy in this
 * translation unit rather than shared, matching this project's existing
 * per-TU-copy convention for fixed SQL text (nvd_ingest.c/db_migrations.c
 * each keep their own cytadel_*_exec() helper rather than sharing one). */
static const char *const CYTADEL_EPSS_CVE_PLACEHOLDER_SQL =
    "INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at) "
    "VALUES (?, ?, ?, '', 0, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO NOTHING;";

/* epss upsert -- not spelled out verbatim in db-schema.md SS9 (only the kev
 * half is), so this is this module's own parameterized statement following
 * the same idiom against the SS5 schema (cve_id PK, epss_score, percentile,
 * score_date, synced_at) and SS5's own "refreshed daily (full replace ...
 * via upsert)" description. */
static const char *const CYTADEL_EPSS_UPSERT_SQL =
    "INSERT INTO epss (cve_id, epss_score, percentile, score_date, synced_at) "
    "VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO UPDATE SET "
    "epss_score = excluded.epss_score, "
    "percentile = excluded.percentile, "
    "score_date = excluded.score_date, "
    "synced_at = excluded.synced_at;";

/* Mirrors kev_ingest.c's own COMPLETE/PARTIAL sync_state split, for
 * feed='epss'. */
static const char *const CYTADEL_EPSS_SYNC_STATE_COMPLETE_SQL =
    "UPDATE sync_state SET "
    "last_mod_watermark = strftime('%Y-%m-%d','now'), "
    "last_sync_completed = strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
    "total_records = total_records + ?, "
    "status = 'success', "
    "last_error = NULL "
    "WHERE feed = 'epss';";

static const char *const CYTADEL_EPSS_SYNC_STATE_PARTIAL_SQL =
    "UPDATE sync_state SET "
    "total_records = total_records + ?, "
    "status = 'running', "
    "last_error = NULL "
    "WHERE feed = 'epss';";

static int cytadel_epss_exec(sqlite3 *handle, const char *sql, const char *context) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("epss_ingest: %s failed (sqlite rc=%d): %s", context, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

static int prepare_statements(sqlite3 *handle, bool full_pull_complete, sqlite3_stmt **placeholder_stmt,
                               sqlite3_stmt **epss_stmt, sqlite3_stmt **sync_stmt) {
    int rc = sqlite3_prepare_v2(handle, CYTADEL_EPSS_CVE_PLACEHOLDER_SQL, -1, placeholder_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("epss_ingest: preparing cves placeholder upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, CYTADEL_EPSS_UPSERT_SQL, -1, epss_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("epss_ingest: preparing epss upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    const char *sync_sql =
        full_pull_complete ? CYTADEL_EPSS_SYNC_STATE_COMPLETE_SQL : CYTADEL_EPSS_SYNC_STATE_PARTIAL_SQL;
    rc = sqlite3_prepare_v2(handle, sync_sql, -1, sync_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("epss_ingest: preparing sync_state update failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    return SQLITE_OK;
}

static void finalize_all(sqlite3_stmt *placeholder_stmt, sqlite3_stmt *epss_stmt, sqlite3_stmt *sync_stmt) {
    sqlite3_finalize(placeholder_stmt);
    sqlite3_finalize(epss_stmt);
    sqlite3_finalize(sync_stmt);
}

/* ------------------------------------------------------------------ */
/* Per-record processing.                                              */
/* ------------------------------------------------------------------ */

static void process_one_epss(sqlite3_stmt *placeholder_stmt, sqlite3_stmt *epss_stmt, const cJSON *elem,
                              cytadel_epss_ingest_counts_t *counts, bool *fatal_db_error) {
    const char *cve_id_raw = NULL;
    if (!json_get_string(elem, "cve", &cve_id_raw) || cve_id_raw[0] == '\0' ||
        strnlen(cve_id_raw, CYTADEL_EPSS_CVE_ID_MAX_LEN + 1) > CYTADEL_EPSS_CVE_ID_MAX_LEN ||
        !cytadel_is_valid_cve_id(cve_id_raw)) {
        cytadel_log_warn(
            "epss_ingest: <no id>: 'cve' is missing/empty/non-string/oversized/malformed (does not fully "
            "match the CVE-ID grammar) -- skipping this record");
        counts->epss_skipped++;
        return;
    }
    char cve_id[CYTADEL_EPSS_CVE_ID_BUF_LEN];
    clip_into(cve_id, sizeof(cve_id), cve_id_raw);

    const char *epss_raw = NULL;
    double epss_score = 0.0;
    if (!json_get_string(elem, "epss", &epss_raw) || !parse_probability_string(epss_raw, &epss_score)) {
        cytadel_log_warn(
            "epss_ingest: %s: 'epss' is missing/non-string/non-numeric/out-of-[0,1]-range -- skipping this "
            "record",
            cve_id);
        counts->epss_skipped++;
        return;
    }

    const char *percentile_raw = NULL;
    double percentile = 0.0;
    if (!json_get_string(elem, "percentile", &percentile_raw) ||
        !parse_probability_string(percentile_raw, &percentile)) {
        cytadel_log_warn(
            "epss_ingest: %s: 'percentile' is missing/non-string/non-numeric/out-of-[0,1]-range -- skipping "
            "this record",
            cve_id);
        counts->epss_skipped++;
        return;
    }

    /* first.org's actual field name is "date"; "score_date" is accepted as
     * a fallback (this milestone's task brief describes the field
     * ambiguously) -- see this file's top-of-file comment. */
    const char *date_raw = NULL;
    if (!json_get_string(elem, "date", &date_raw) || date_raw[0] == '\0') {
        if (!json_get_string(elem, "score_date", &date_raw) || date_raw[0] == '\0') {
            cytadel_log_warn(
                "epss_ingest: %s: neither 'date' nor 'score_date' is present as a non-empty string -- "
                "skipping this record",
                cve_id);
            counts->epss_skipped++;
            return;
        }
    }
    char score_date[CYTADEL_EPSS_DATE_BUF_LEN];
    clip_into(score_date, sizeof(score_date), date_raw);

    /* Placeholder-FK dance FIRST (db-schema.md SS9/SS10 assumption 5) --
     * epss.cve_id is a hard FK into cves(cve_id), and the EPSS feed scores
     * essentially every known CVE, including ones the NVD sync has not
     * reached yet. */
    char now_ts[CYTADEL_ISO8601_BUF_LEN];
    if (cytadel_log_format_timestamp_utc(now_ts, sizeof(now_ts)) != 0) {
        cytadel_log_error("epss_ingest: %s: formatting placeholder timestamp failed -- treating as a fatal error",
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
        cytadel_log_error("epss_ingest: %s: binding cves placeholder upsert failed (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(placeholder_stmt)));
        counts->epss_skipped++;
        return;
    }
    rc = sqlite3_step(placeholder_stmt);
    if (rc != SQLITE_DONE) {
        if (rc == SQLITE_CONSTRAINT) {
            cytadel_log_warn(
                "epss_ingest: %s: cves placeholder upsert rejected by a constraint -- skipping this record",
                cve_id);
            counts->epss_skipped++;
            return;
        }
        cytadel_log_error("epss_ingest: %s: fatal sqlite error upserting cves placeholder row (sqlite rc=%d): %s",
                           cve_id, rc, sqlite3_errmsg(sqlite3_db_handle(placeholder_stmt)));
        *fatal_db_error = true;
        return;
    }

    sqlite3_reset(epss_stmt);
    sqlite3_clear_bindings(epss_stmt);
    rc = sqlite3_bind_text(epss_stmt, 1, cve_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_double(epss_stmt, 2, epss_score);
    if (rc == SQLITE_OK) rc = sqlite3_bind_double(epss_stmt, 3, percentile);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(epss_stmt, 4, score_date, -1, SQLITE_TRANSIENT);
    if (rc != SQLITE_OK) {
        cytadel_log_error("epss_ingest: %s: binding epss upsert failed (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(epss_stmt)));
        counts->epss_skipped++;
        return;
    }

    rc = sqlite3_step(epss_stmt);
    if (rc == SQLITE_DONE) {
        counts->epss_ingested++;
    } else if (rc == SQLITE_CONSTRAINT) {
        cytadel_log_warn("epss_ingest: %s: epss upsert rejected by a CHECK/constraint -- skipping this record",
                          cve_id);
        counts->epss_skipped++;
    } else {
        cytadel_log_error("epss_ingest: %s: fatal sqlite error upserting epss row (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(epss_stmt)));
        *fatal_db_error = true;
    }
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

cytadel_epss_ingest_status_t cytadel_epss_ingest(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                  bool full_pull_complete,
                                                  cytadel_epss_ingest_counts_t *out_counts) {
    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
    }
    if (db == NULL || json_bytes == NULL || out_counts == NULL) {
        cytadel_log_error("epss_ingest: cytadel_epss_ingest() called with a NULL db/json_bytes/out_counts");
        return CYTADEL_EPSS_INGEST_ERR_INVALID_ARG;
    }

    if (len > CYTADEL_EPSS_MAX_BYTES) {
        cytadel_log_error(
            "epss_ingest: buffer length %zu exceeds the %d-byte sanity cap -- rejecting without parsing; no "
            "data was written and sync_state is unchanged",
            len, CYTADEL_EPSS_MAX_BYTES);
        return CYTADEL_EPSS_INGEST_ERR_PARSE;
    }

    cJSON *root = cJSON_ParseWithLength(json_bytes, len);
    if (root == NULL) {
        cytadel_log_error(
            "epss_ingest: cJSON_ParseWithLength() failed to parse this buffer (truncated or invalid JSON) -- "
            "rejecting the whole ingest; no data was written and sync_state is unchanged");
        return CYTADEL_EPSS_INGEST_ERR_PARSE;
    }
    if (!cJSON_IsObject(root)) {
        cytadel_log_error(
            "epss_ingest: top-level EPSS document is not a JSON object -- rejecting the whole ingest; no "
            "data was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_PARSE;
    }

    /* Only a present JSON ARRAY value for "data" is a valid buffer -- an
     * empty array (`[]`) IS valid. A missing/wrong-typed "data" is treated
     * as a corrupted/tampered response and rejected outright (mirrors
     * nvd_ingest.c's W1 fix / kev_ingest.c's own "vulnerabilities" check). */
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (!cJSON_IsArray(data)) {
        cytadel_log_error(
            "epss_ingest: top-level 'data' is missing or not an array -- rejecting the whole ingest; no "
            "data was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_PARSE;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    if (cytadel_epss_exec(handle, "BEGIN;", "starting epss_ingest transaction") != SQLITE_OK) {
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_DB;
    }

    sqlite3_stmt *placeholder_stmt = NULL;
    sqlite3_stmt *epss_stmt = NULL;
    sqlite3_stmt *sync_stmt = NULL;
    if (prepare_statements(handle, full_pull_complete, &placeholder_stmt, &epss_stmt, &sync_stmt) != SQLITE_OK) {
        finalize_all(placeholder_stmt, epss_stmt, sync_stmt);
        (void)cytadel_epss_exec(handle, "ROLLBACK;", "rolling back after a prepare failure");
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_DB;
    }

    bool fatal_db_error = false;

    {
        size_t processed = 0;
        const cJSON *elem = data->child;
        for (; elem != NULL && processed < CYTADEL_EPSS_MAX_RECORDS; elem = elem->next, processed++) {
            if (!cJSON_IsObject(elem)) {
                out_counts->epss_skipped++;
                continue;
            }
            process_one_epss(placeholder_stmt, epss_stmt, elem, out_counts, &fatal_db_error);
            if (fatal_db_error) {
                break;
            }
        }
        if (!fatal_db_error && processed >= CYTADEL_EPSS_MAX_RECORDS && elem != NULL) {
            cytadel_log_warn(
                "epss_ingest: buffer exceeds %d entries -- remaining entries were not processed (hostile/"
                "oversized input)",
                CYTADEL_EPSS_MAX_RECORDS);
            for (; elem != NULL; elem = elem->next) {
                out_counts->epss_skipped++;
            }
        }
    }

    if (!fatal_db_error) {
        sqlite3_int64 records_seen = (sqlite3_int64)(out_counts->epss_ingested + out_counts->epss_skipped);
        int rc = sqlite3_bind_int64(sync_stmt, 1, records_seen);
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(sync_stmt);
        }
        if (rc != SQLITE_OK && rc != SQLITE_DONE) {
            cytadel_log_error("epss_ingest: updating sync_state failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            fatal_db_error = true;
        }
    }

    finalize_all(placeholder_stmt, epss_stmt, sync_stmt);

    if (fatal_db_error) {
        (void)cytadel_epss_exec(handle, "ROLLBACK;", "rolling back epss_ingest after a fatal DB error");
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_DB;
    }

    if (cytadel_epss_exec(handle, "COMMIT;", "committing epss_ingest") != SQLITE_OK) {
        (void)cytadel_epss_exec(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
        cJSON_Delete(root);
        return CYTADEL_EPSS_INGEST_ERR_DB;
    }

    cJSON_Delete(root);
    return CYTADEL_EPSS_INGEST_OK;
}
