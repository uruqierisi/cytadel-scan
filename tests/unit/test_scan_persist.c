#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/db/nvd_ingest.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

#include "cytadel/db/scan_persist.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel/db/nvd_ingest.h"
#include "cytadel_test.h"

/* CPE-matching-caller slice: the FIRST PRODUCTION CALLER of
 * cytadel_cpe_match_evaluate() (docs/contracts/cpe-matching.md, FROZEN
 * CONTRACT). This test proves, through the REAL DB boundary (not just by
 * reading source), that:
 *
 *   1. An UNDECIDABLE per-CVE aggregation round-trips as 'undetermined' --
 *      NOT 'confirmed', NOT 'not_affected' (the headline gate).
 *   2. All three match_status values round-trip correctly (MATCH ->
 *      'confirmed', NO_MATCH -> 'not_affected', UNDECIDABLE ->
 *      'undetermined'), using real OpenSSL Heartbleed (CVE-2014-0160)
 *      bounds for the MATCH/NO_MATCH pair.
 *   3. Per-CVE aggregation is order-independent -- both as a PURE,
 *      no-DB check directly against cytadel_scan_aggregate_cve_verdict(),
 *      AND as a real DB round trip with cve_cpe_matches rows inserted in
 *      both orders.
 *   4. A cve_id whose only candidate row is CYTADEL_CPE_MALFORMED_ROW
 *      produces a data-quality event (counted), never a scan_results row.
 *   5. kev_flag/epss_score persist as point-in-time snapshots, present and
 *      absent.
 *   6. Migration v2 (scan_results.match_status) itself is covered by
 *      tests/unit/test_db.c's test_match_status_column_migration_v2().
 */

#define LIT(s) (s), (sizeof(s) - 1)
#define EMPTY NULL, (size_t)0

/* ------------------------------------------------------------------ */
/* Fixture helpers -- direct, parameterized inserts mirroring db-schema.md */
/* SS9's own patterns (never string-concatenated), matching test_db.c's    */
/* style.                                                                  */
/* ------------------------------------------------------------------ */

static cytadel_db_t *open_migrated_memory_db(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    return db;
}

static void insert_cve(sqlite3 *handle, const char *cve_id, int severity) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cves (cve_id, published, last_modified, description, "
                            "severity, source, ingested_at) VALUES (?, '2020-01-01T00:00:00.000Z', "
                            "'2020-01-01T00:00:00.000Z', '', ?, 'nvd', '2020-01-01T00:00:00.000Z');",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 2, severity), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void insert_cpe_row(sqlite3 *handle, const char *cve_id, const char *vendor,
                            const char *product, const char *version, const char *start_inc,
                            const char *start_exc, const char *end_inc, const char *end_exc,
                            int vulnerable) {
    /* cve_cpe_matches's UNIQUE constraint is (cve_id, cpe23_uri,
     * version_start_including, version_start_excluding,
     * version_end_including, version_end_excluding, vulnerable) --
     * `version` is deliberately NOT part of that key (db-schema.md SS3),
     * so two rows for the same cve_id with identical (often all-empty)
     * bounds but a different `version` collide unless their cpe23_uri
     * differs too. A real NVD cpe23_uri always embeds the version, making
     * this a non-issue in production; this fixture mirrors that by giving
     * every inserted row its own unique cpe23_uri via a monotonic counter
     * (the exact text is never read by the evaluator -- kept verbatim
     * purely for audit/debug per that column's own schema comment). */
    static int uri_counter = 0;
    char cpe23_uri[64];
    int written = snprintf(cpe23_uri, sizeof(cpe23_uri), "cpe:2.3:a:x:y:fixture-row-%d:*:*:*:*:*:*:*",
                            uri_counter++);
    CYTADEL_ASSERT(written > 0 && (size_t)written < sizeof(cpe23_uri));

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, "
                            "version, version_start_including, version_start_excluding, "
                            "version_end_including, version_end_excluding, vulnerable) VALUES "
                            "(?, ?, 'a', ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, cpe23_uri, -1, SQLITE_TRANSIENT), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, vendor, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 4, product, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 5, version, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 6, start_inc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 7, start_exc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 8, end_inc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 9, end_exc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 10, vulnerable), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void insert_kev(sqlite3 *handle, const char *cve_id) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO kev (cve_id, date_added, vendor_project, product, "
                            "vulnerability_name, synced_at) VALUES (?, '2020-01-01', 'v', 'p', "
                            "'name', '2020-01-01T00:00:00.000Z');",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void insert_epss(sqlite3 *handle, const char *cve_id, double score) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO epss (cve_id, epss_score, percentile, score_date, "
                            "synced_at) VALUES (?, ?, 0.5, '2020-01-01', '2020-01-01T00:00:00.000Z');",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_double(stmt, 2, score), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

typedef struct {
    bool found;
    char match_status[32];
    int kev_flag;
    bool epss_is_null;
    double epss_score;
} scan_result_row_t;

static scan_result_row_t select_scan_result(sqlite3 *handle, long long scan_id, const char *host,
                                             const char *cve_id) {
    scan_result_row_t out;
    memset(&out, 0, sizeof(out));

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT match_status, kev_flag, epss_score FROM "
                                         "scan_results WHERE scan_id = ? AND host = ? AND cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, host, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, cve_id, -1, SQLITE_STATIC), SQLITE_OK);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.found = true;
        const char *ms = (const char *)sqlite3_column_text(stmt, 0);
        CYTADEL_ASSERT(ms != NULL);
        size_t n = strnlen(ms, sizeof(out.match_status) - 1);
        memcpy(out.match_status, ms, n);
        out.match_status[n] = '\0';
        out.kev_flag = sqlite3_column_int(stmt, 1);
        out.epss_is_null = (sqlite3_column_type(stmt, 2) == SQLITE_NULL);
        if (!out.epss_is_null) {
            out.epss_score = sqlite3_column_double(stmt, 2);
        }
    }
    /* Every row this module writes must be alone for (scan_id, host,
     * cve_id) in these tests -- assert there is never a second row, so a
     * silent double-insert defect can never hide behind "found the first
     * one and stopped looking". */
    CYTADEL_ASSERT(sqlite3_step(stmt) != SQLITE_ROW);
    sqlite3_finalize(stmt);
    return out;
}

/* M8 report slice 2: reads the durable scans.malformed_data_count column
 * back through the real DB boundary -- see this file's own gate-6 tests
 * below. */
static long long select_malformed_data_count(sqlite3 *handle, long long scan_id) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT malformed_data_count FROM scans WHERE scan_id = ?;", -1, &stmt,
                            NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    long long count = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

static int count_scan_results_for_cve(sqlite3 *handle, long long scan_id, const char *cve_id) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND cve_id = ?;",
                           -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static int count_scan_results_for_host(sqlite3 *handle, long long scan_id, const char *host) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND host = ?;", -1,
                           &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, host, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

/* M9 Gap #3 fix: counts `cves` rows for `cve_id`, independent of source --
 * used to prove "no garbage cves row was ever created" for a malformed
 * plugin cve_id, and "the placeholder row did not survive a rolled-back
 * transaction" for the atomicity proof. */
static long long count_cves_for_id(sqlite3 *handle, const char *cve_id) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    long long n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static long long create_scan(cytadel_db_t *db) {
    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(
        cytadel_scan_create(db, "10.0.0.0/24", "operator@example.com", "flag", &scan_id),
        CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);
    return scan_id;
}

/* ------------------------------------------------------------------ */
/* Gate 3 (part A): PURE, no-DB order-independence proof directly       */
/* against cytadel_scan_aggregate_cve_verdict(). Mirrors test_cpe_match.c's */
/* own reversed-order oracle idea, one layer up.                        */
/* ------------------------------------------------------------------ */

static void test_pure_aggregate_order_independence(void) {
    /* "1.0.0-cr1" vs a bound of "1.0.0" is UNDECIDABLE (unrecognized
     * detached alpha residual "cr1" -- tests/unit/test_version_compare.c's
     * own truth table, reused verbatim per this task's suggested
     * construction). "1.0.0-cr1" vs the far-away exact version "9.9.9" is
     * fully decidable (the leading numeric component "1" vs "9" already
     * settles it) -- NO_MATCH. */
    const char *detected = "1.0.0-cr1";
    size_t detected_len = strlen(detected);

    cytadel_cpe_match_row_t no_match_row = {LIT("9.9.9"), EMPTY, EMPTY, EMPTY, EMPTY, 1};
    cytadel_cpe_match_row_t undecidable_row = {LIT("*"), EMPTY, EMPTY, EMPTY, LIT("1.0.0"), 1};
    /* Exact-match row whose text is byte-identical to `detected` -- MATCH
     * (verified: identical alpha residuals compare EQUAL, not UNDECIDABLE;
     * see src/match/version_compare.c's "both sides ALPHA at the same
     * shared position" branch). */
    cytadel_cpe_match_row_t match_row = {LIT("1.0.0-cr1"), EMPTY, EMPTY, EMPTY, EMPTY, 1};

    /* [NO_MATCH, UNDECIDABLE] and reversed -- must BOTH be 'undetermined'. */
    {
        cytadel_cpe_match_row_t forward[2] = {no_match_row, undecidable_row};
        cytadel_cpe_match_row_t reversed[2] = {undecidable_row, no_match_row};

        cytadel_scan_cve_verdict_t v_fwd =
            cytadel_scan_aggregate_cve_verdict(forward, 2, detected, detected_len);
        cytadel_scan_cve_verdict_t v_rev =
            cytadel_scan_aggregate_cve_verdict(reversed, 2, detected, detected_len);

        CYTADEL_ASSERT(v_fwd.has_verdict);
        CYTADEL_ASSERT_EQ(v_fwd.status, CYTADEL_SCAN_MATCH_UNDETERMINED);
        CYTADEL_ASSERT_EQ(v_fwd.malformed_count, 0);

        CYTADEL_ASSERT(v_rev.has_verdict);
        CYTADEL_ASSERT_EQ(v_rev.status, CYTADEL_SCAN_MATCH_UNDETERMINED);
        CYTADEL_ASSERT_EQ(v_rev.malformed_count, 0);
    }

    /* [MATCH, UNDECIDABLE] and reversed -- must BOTH be 'confirmed' (a
     * MATCH anywhere in the set always wins, order notwithstanding). */
    {
        cytadel_cpe_match_row_t forward[2] = {match_row, undecidable_row};
        cytadel_cpe_match_row_t reversed[2] = {undecidable_row, match_row};

        cytadel_scan_cve_verdict_t v_fwd =
            cytadel_scan_aggregate_cve_verdict(forward, 2, detected, detected_len);
        cytadel_scan_cve_verdict_t v_rev =
            cytadel_scan_aggregate_cve_verdict(reversed, 2, detected, detected_len);

        CYTADEL_ASSERT(v_fwd.has_verdict);
        CYTADEL_ASSERT_EQ(v_fwd.status, CYTADEL_SCAN_MATCH_CONFIRMED);
        CYTADEL_ASSERT(v_rev.has_verdict);
        CYTADEL_ASSERT_EQ(v_rev.status, CYTADEL_SCAN_MATCH_CONFIRMED);
    }

    /* Zero rows: nothing to persist, no data-quality event. */
    {
        cytadel_scan_cve_verdict_t v = cytadel_scan_aggregate_cve_verdict(NULL, 0, detected, detected_len);
        CYTADEL_ASSERT(!v.has_verdict);
        CYTADEL_ASSERT_EQ(v.malformed_count, 0);
    }
}

/* ------------------------------------------------------------------ */
/* Gate 3 (part B): the SAME order-independence property proved at the */
/* real DB boundary -- cve_cpe_matches rows inserted in both orders,   */
/* read back through cytadel_scan_detect_and_persist().                */
/* ------------------------------------------------------------------ */

static void test_db_round_trip_order_independence(void) {
    /* Order 1: NO_MATCH row inserted first, UNDECIDABLE row second. */
    {
        cytadel_db_t *db = open_migrated_memory_db();
        sqlite3 *handle = cytadel_db_handle(db);
        insert_cve(handle, "CVE-2099-00001", 2);
        insert_cpe_row(handle, "CVE-2099-00001", "acme", "gadget", "9.9.9", "", "", "", "", 1);
        insert_cpe_row(handle, "CVE-2099-00001", "acme", "gadget", "*", "", "", "", "1.0.0", 1);

        long long scan_id = create_scan(db);
        cytadel_scan_detection_t det = {0};
        det.host = "order1-host";
        det.port = 443;
        det.plugin_id = "test_plugin";
        det.evidence = "banner";
        det.detected_version = "1.0.0-cr1";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "acme", "gadget", &det, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);
        CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

        scan_result_row_t row = select_scan_result(handle, scan_id, "order1-host", "CVE-2099-00001");
        CYTADEL_ASSERT(row.found);
        CYTADEL_ASSERT_STREQ(row.match_status, "undetermined");

        cytadel_db_close(db);
    }

    /* Order 2: the SAME two rows, inserted in the OPPOSITE order --
     * UNDECIDABLE first, NO_MATCH second. Must still be 'undetermined'. */
    {
        cytadel_db_t *db = open_migrated_memory_db();
        sqlite3 *handle = cytadel_db_handle(db);
        insert_cve(handle, "CVE-2099-00001", 2);
        insert_cpe_row(handle, "CVE-2099-00001", "acme", "gadget", "*", "", "", "", "1.0.0", 1);
        insert_cpe_row(handle, "CVE-2099-00001", "acme", "gadget", "9.9.9", "", "", "", "", 1);

        long long scan_id = create_scan(db);
        cytadel_scan_detection_t det = {0};
        det.host = "order2-host";
        det.port = 443;
        det.plugin_id = "test_plugin";
        det.evidence = "banner";
        det.detected_version = "1.0.0-cr1";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "acme", "gadget", &det, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);
        CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

        scan_result_row_t row = select_scan_result(handle, scan_id, "order2-host", "CVE-2099-00001");
        CYTADEL_ASSERT(row.found);
        CYTADEL_ASSERT_STREQ(row.match_status, "undetermined");

        cytadel_db_close(db);
    }
}

/* ------------------------------------------------------------------ */
/* Gate 1 (the headline gate): standalone UNDECIDABLE round trip.       */
/* ------------------------------------------------------------------ */

static void test_headline_undecidable_round_trip(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00010", 3);
    /* detected "1.0.0-cr1" against versionEndExcluding="1.0.0" -- exactly
     * this task's own suggested UNDECIDABLE construction. */
    insert_cpe_row(handle, "CVE-2099-00010", "acme", "widget", "*", "", "", "", "1.0.0", 1);

    long long scan_id = create_scan(db);
    cytadel_scan_detection_t det = {0};
    det.host = "10.0.0.5";
    det.port = 8080;
    det.plugin_id = "cpe_match_test";
    det.evidence = "widget/1.0.0-cr1";
    det.detected_version = "1.0.0-cr1";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    /* Mixed-case vendor/product on purpose: db-schema.md SS10 assumption 2
     * requires the caller to lowercase before the candidate lookup --
     * this proves cytadel_scan_detect_and_persist() does that itself. */
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "ACME", "Widget", &det, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

    scan_result_row_t row = select_scan_result(handle, scan_id, "10.0.0.5", "CVE-2099-00010");
    CYTADEL_ASSERT(row.found);
    /* THE assertion: must read back 'undetermined', not 'confirmed' and
     * not 'not_affected'. */
    CYTADEL_ASSERT_STREQ(row.match_status, "undetermined");
    CYTADEL_ASSERT(strcmp(row.match_status, "confirmed") != 0);
    CYTADEL_ASSERT(strcmp(row.match_status, "not_affected") != 0);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 2: all three verdicts round-trip, using real OpenSSL Heartbleed */
/* (CVE-2014-0160) bounds for MATCH/NO_MATCH.                          */
/* ------------------------------------------------------------------ */

static void test_all_three_verdicts_round_trip(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* REAL advisory: OpenSSL CVE-2014-0160 (Heartbleed). Affected 1.0.1
     * through 1.0.1f inclusive; fixed in 1.0.1g. */
    insert_cve(handle, "CVE-2014-0160", 4);
    insert_cpe_row(handle, "CVE-2014-0160", "openssl", "openssl", "*", "1.0.1", "", "1.0.1f", "", 1);

    /* Separate synthetic CVE with only an UNDECIDABLE-producing bound. */
    insert_cve(handle, "CVE-2099-00020", 2);
    insert_cpe_row(handle, "CVE-2099-00020", "openssl", "openssl", "*", "", "", "", "1.0.0", 1);

    long long scan_id = create_scan(db);

    /* MATCH: 1.0.1f is inside the affected range. */
    {
        cytadel_scan_detection_t det = {0};
        det.host = "host-match";
        det.port = 443;
        det.plugin_id = "cpe_match_test";
        det.evidence = "OpenSSL/1.0.1f";
        det.detected_version = "1.0.1f";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(
            cytadel_scan_detect_and_persist(db, scan_id, "openssl", "openssl", &det, &counts),
            CYTADEL_SCAN_PERSIST_OK);
        /* Two candidate CVEs share (vendor, product) here: Heartbleed
         * MATCHes, the synthetic CVE-2099-00020 bound ("1.0.0" excluded)
         * decidably FAILs against "1.0.1f" (definitely NOT_AFFECTED) --
         * both produce rows. */
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 2);
        CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

        scan_result_row_t heartbleed = select_scan_result(handle, scan_id, "host-match", "CVE-2014-0160");
        CYTADEL_ASSERT(heartbleed.found);
        CYTADEL_ASSERT_STREQ(heartbleed.match_status, "confirmed");
    }

    /* NO_MATCH: 1.0.1g is the fix, just past the inclusive upper bound. */
    {
        cytadel_scan_detection_t det = {0};
        det.host = "host-no-match";
        det.port = 443;
        det.plugin_id = "cpe_match_test";
        det.evidence = "OpenSSL/1.0.1g";
        det.detected_version = "1.0.1g";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(
            cytadel_scan_detect_and_persist(db, scan_id, "openssl", "openssl", &det, &counts),
            CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 2);
        CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

        scan_result_row_t heartbleed =
            select_scan_result(handle, scan_id, "host-no-match", "CVE-2014-0160");
        CYTADEL_ASSERT(heartbleed.found);
        CYTADEL_ASSERT_STREQ(heartbleed.match_status, "not_affected");
    }

    /* UNDECIDABLE: 1.0.0-cr1 against the synthetic CVE's bound. Also
     * exercises Heartbleed's OWN bound with the same hostile version:
     * "1.0.0-cr1" vs versionStartIncluding="1.0.1" -- the leading numeric
     * component (1.0.0 < 1.0.1) already decides GREATER-than-nothing... in
     * fact LESS, a decidable FAIL, so Heartbleed settles NOT_AFFECTED here
     * too, independently. */
    {
        cytadel_scan_detection_t det = {0};
        det.host = "host-undecidable";
        det.port = 443;
        det.plugin_id = "cpe_match_test";
        det.evidence = "OpenSSL/1.0.0-cr1";
        det.detected_version = "1.0.0-cr1";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(
            cytadel_scan_detect_and_persist(db, scan_id, "openssl", "openssl", &det, &counts),
            CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 2);
        CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

        scan_result_row_t synthetic =
            select_scan_result(handle, scan_id, "host-undecidable", "CVE-2099-00020");
        CYTADEL_ASSERT(synthetic.found);
        CYTADEL_ASSERT_STREQ(synthetic.match_status, "undetermined");
    }

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 4: MALFORMED_ROW -- data-quality event, never a fabricated row. */
/* ------------------------------------------------------------------ */

static void test_malformed_row_produces_no_verdict_row(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00030", 1);
    /* Range row, version='*', ALL FOUR bounds empty -- MALFORMED_ROW per
     * cpe-matching.md SS2 / db-schema.md SS3. */
    insert_cpe_row(handle, "CVE-2099-00030", "malf", "thing", "*", "", "", "", "", 1);

    long long scan_id = create_scan(db);
    cytadel_scan_detection_t det = {0};
    det.host = "malf-host";
    det.port = 1234;
    det.plugin_id = "cpe_match_test";
    det.evidence = "thing/9.9.9";
    det.detected_version = "9.9.9";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "malf", "thing", &det, &counts),
                      CYTADEL_SCAN_PERSIST_OK);

    /* The counter: a data-quality event WAS recorded... */
    CYTADEL_ASSERT_EQ(counts.malformed_events, 1);
    /* ...but NO scan_results row -- neither 'confirmed' nor 'not_affected'
     * nor any other bogus verdict -- was ever written for this cve_id. */
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 0);
    CYTADEL_ASSERT_EQ(count_scan_results_for_cve(handle, scan_id, "CVE-2099-00030"), 0);

    cytadel_db_close(db);
}

/* A cve_id with BOTH a malformed row and a decidable row: the malformed
 * row must still surface as its own data-quality event even though the
 * decidable row DOES produce a verdict row -- prohibitions 3.2/4 (an
 * UNDECIDABLE/MALFORMED_ROW record must never be suppressed just because
 * another outcome for the same CVE settled a verdict). */
static void test_malformed_row_alongside_a_decidable_row(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00031", 1);
    insert_cpe_row(handle, "CVE-2099-00031", "mix", "thing", "*", "", "", "", "", 1); /* malformed */
    insert_cpe_row(handle, "CVE-2099-00031", "mix", "thing", "5.0.0", "", "", "", "", 1); /* exact MATCH */

    long long scan_id = create_scan(db);
    cytadel_scan_detection_t det = {0};
    det.host = "mix-host";
    det.port = 1234;
    det.plugin_id = "cpe_match_test";
    det.evidence = "thing/5.0.0";
    det.detected_version = "5.0.0";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "mix", "thing", &det, &counts),
                      CYTADEL_SCAN_PERSIST_OK);

    CYTADEL_ASSERT_EQ(counts.malformed_events, 1);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);

    scan_result_row_t row = select_scan_result(handle, scan_id, "mix-host", "CVE-2099-00031");
    CYTADEL_ASSERT(row.found);
    CYTADEL_ASSERT_STREQ(row.match_status, "confirmed");

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 5: kev_flag/epss_score snapshots, present and absent.          */
/* ------------------------------------------------------------------ */

static void test_kev_epss_snapshot(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00040", 3);
    insert_cpe_row(handle, "CVE-2099-00040", "snap", "shot", "1.2.3", "", "", "", "", 1);
    insert_kev(handle, "CVE-2099-00040");
    insert_epss(handle, "CVE-2099-00040", 0.42);

    insert_cve(handle, "CVE-2099-00041", 3);
    insert_cpe_row(handle, "CVE-2099-00041", "snap", "shot2", "1.2.3", "", "", "", "", 1);
    /* no kev/epss rows for this one */

    long long scan_id = create_scan(db);

    {
        cytadel_scan_detection_t det = {0};
        det.host = "snap-host";
        det.port = 80;
        det.plugin_id = "cpe_match_test";
        det.evidence = "shot/1.2.3";
        det.detected_version = "1.2.3";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "snap", "shot", &det, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);

        scan_result_row_t row = select_scan_result(handle, scan_id, "snap-host", "CVE-2099-00040");
        CYTADEL_ASSERT(row.found);
        CYTADEL_ASSERT_STREQ(row.match_status, "confirmed");
        CYTADEL_ASSERT_EQ(row.kev_flag, 1);
        CYTADEL_ASSERT(!row.epss_is_null);
        CYTADEL_ASSERT(row.epss_score > 0.41 && row.epss_score < 0.43);
    }

    {
        cytadel_scan_detection_t det = {0};
        det.host = "snap-host2";
        det.port = 80;
        det.plugin_id = "cpe_match_test";
        det.evidence = "shot2/1.2.3";
        det.detected_version = "1.2.3";
        det.detected_version_len = strlen(det.detected_version);

        cytadel_scan_persist_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "snap", "shot2", &det, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);

        scan_result_row_t row = select_scan_result(handle, scan_id, "snap-host2", "CVE-2099-00041");
        CYTADEL_ASSERT(row.found);
        CYTADEL_ASSERT_STREQ(row.match_status, "confirmed");
        CYTADEL_ASSERT_EQ(row.kev_flag, 0);
        CYTADEL_ASSERT(row.epss_is_null);
    }

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* cytadel_scan_create(): round trip + invalid args.                    */
/* ------------------------------------------------------------------ */

static void test_scan_create_round_trip(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(
        cytadel_scan_create(db, "192.168.1.0/24", "alice", "interactive", &scan_id),
        CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT target_spec, authorized_by, authorization_method, "
                                         "status FROM scans WHERE scan_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "192.168.1.0/24");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "alice");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "interactive");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3), "running");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_scan_create_rejects_invalid_args(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    long long scan_id = -1;

    CYTADEL_ASSERT_EQ(cytadel_scan_create(NULL, "x", "y", "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, NULL, "y", "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "x", NULL, "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "x", "y", NULL, &scan_id),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "x", "y", "flag", NULL),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);

    /* An authorization_method outside the CHECK constraint is a DB-level
     * rejection (SQLITE_CONSTRAINT), not something this function
     * pre-validates -- see scan_persist.h's own doc comment. */
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "x", "y", "bogus", &scan_id),
                      CYTADEL_SCAN_PERSIST_ERR_DB);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* cytadel_scan_detect_and_persist(): invalid args + no-candidates case. */
/* ------------------------------------------------------------------ */

static void test_detect_and_persist_rejects_invalid_args(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    long long scan_id = create_scan(db);

    cytadel_scan_detection_t det = {0};
    det.host = "h";
    det.port = 80;
    det.plugin_id = "p";
    det.evidence = "e";

    cytadel_scan_persist_counts_t counts;

    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(NULL, scan_id, "v", "p", &det, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, 0, "v", "p", &det, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, NULL, "p", &det, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", NULL, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &det, NULL),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);

    /* Empty vendor/product. */
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "", "p", &det, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);

    /* Out-of-range port. */
    {
        cytadel_scan_detection_t bad_port = det;
        bad_port.port = 70000;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &bad_port, &counts),
                          CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    }

    /* Missing required detection fields. */
    {
        cytadel_scan_detection_t bad_det = det;
        bad_det.host = NULL;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &bad_det, &counts),
                          CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    }
    {
        cytadel_scan_detection_t bad_det = det;
        bad_det.plugin_id = NULL;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &bad_det, &counts),
                          CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    }
    {
        cytadel_scan_detection_t bad_det = det;
        bad_det.evidence = NULL;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &bad_det, &counts),
                          CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    }

    /* NULL detected_version paired with a nonzero length -- caller bug,
     * handled defensively rather than dereferenced. */
    {
        cytadel_scan_detection_t bad_det = det;
        bad_det.detected_version = NULL;
        bad_det.detected_version_len = 5;
        CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "v", "p", &bad_det, &counts),
                          CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG);
    }

    cytadel_db_close(db);
}

static void test_detect_and_persist_no_candidates_is_a_clean_noop(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    long long scan_id = create_scan(db);

    cytadel_scan_detection_t det = {0};
    det.host = "nobody-home";
    det.port = 80;
    det.plugin_id = "p";
    det.evidence = "e";
    det.detected_version = "1.0.0";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    counts.rows_inserted = 999; /* poison -- must be reset to 0 */
    counts.malformed_events = 999;
    CYTADEL_ASSERT_EQ(
        cytadel_scan_detect_and_persist(db, scan_id, "nonexistent", "vendor", &det, &counts),
        CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 0);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 6 (M8 report slice 2): scans.malformed_data_count DURABLE round     */
/* trip -- report Gate 2's data source, migration v3.                       */
/* ------------------------------------------------------------------ */

/* A scan whose only candidate row is malformed: the DURABLE column (read
 * back through a fresh SELECT against the real DB, not the ephemeral
 * out_counts struct) must show the incremented count. */
static void test_malformed_data_count_durable_round_trip(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00050", 1);
    /* Range row, version='*', ALL FOUR bounds empty -- MALFORMED_ROW. */
    insert_cpe_row(handle, "CVE-2099-00050", "durable", "thing", "*", "", "", "", "", 1);

    long long scan_id = create_scan(db);
    /* Baseline: a freshly created scan reads back 0, not a stale/uninitialized
     * value -- the column's own honest DEFAULT 0. */
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 0);

    cytadel_scan_detection_t det = {0};
    det.host = "durable-host";
    det.port = 1234;
    det.plugin_id = "cpe_match_test";
    det.evidence = "thing/9.9.9";
    det.detected_version = "9.9.9";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "durable", "thing", &det, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 1);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 0);

    /* THE assertion: the DURABLE column, read back through a brand-new
     * SELECT against the real DB (not the in-memory counts struct this
     * call happened to return), shows the increment. */
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 1);

    cytadel_db_close(db);
}

/* A scan with NO malformed events at all reads back 0 -- no false count. */
static void test_malformed_data_count_zero_when_no_malformed_events(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00051", 1);
    insert_cpe_row(handle, "CVE-2099-00051", "clean", "thing", "1.2.3", "", "", "", "", 1);

    long long scan_id = create_scan(db);
    cytadel_scan_detection_t det = {0};
    det.host = "clean-host";
    det.port = 1234;
    det.plugin_id = "cpe_match_test";
    det.evidence = "thing/1.2.3";
    det.detected_version = "1.2.3";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "clean", "thing", &det, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 0);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);

    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 0);

    cytadel_db_close(db);
}

/* The durable count is a RUNNING SUM across every detect_and_persist() call
 * for the same scan_id -- two separate calls (different vendor/product, each
 * with its own malformed row) must accumulate, not overwrite. */
static void test_malformed_data_count_accumulates_across_calls(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    insert_cve(handle, "CVE-2099-00052", 1);
    insert_cpe_row(handle, "CVE-2099-00052", "sumv1", "thing", "*", "", "", "", "", 1); /* malformed */
    insert_cve(handle, "CVE-2099-00053", 1);
    insert_cpe_row(handle, "CVE-2099-00053", "sumv2", "thing", "*", "", "", "", "", 1); /* malformed */

    long long scan_id = create_scan(db);

    cytadel_scan_detection_t det1 = {0};
    det1.host = "sum-host-1";
    det1.port = 1234;
    det1.plugin_id = "cpe_match_test";
    det1.evidence = "thing/9.9.9";
    det1.detected_version = "9.9.9";
    det1.detected_version_len = strlen(det1.detected_version);

    cytadel_scan_persist_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "sumv1", "thing", &det1, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 1);
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 1);

    cytadel_scan_detection_t det2 = {0};
    det2.host = "sum-host-2";
    det2.port = 1234;
    det2.plugin_id = "cpe_match_test";
    det2.evidence = "thing/9.9.9";
    det2.detected_version = "9.9.9";
    det2.detected_version_len = strlen(det2.detected_version);

    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "sumv2", "thing", &det2, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 1);
    /* Running sum: 1 (first call) + 1 (this call) = 2, not overwritten to 1. */
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 2);

    cytadel_db_close(db);
}

/* Atomicity: the durable count update happens inside the SAME transaction as
 * the scan_results rows it describes. A malformed row is seen and counted
 * mid-call, but a LATER row in the same call forces a fatal DB error (a
 * BEFORE INSERT trigger that RAISEs on a specific host, engineered by this
 * test -- not something production code ever does) -- the whole call must
 * roll back, and scans.malformed_data_count must NOT have been bumped by the
 * malformed row this failed call saw. */
static void test_malformed_data_count_rolls_back_with_its_transaction(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* Forces the scan_results INSERT for host='atomic-fail-host' to fail
     * with SQLITE_CONSTRAINT -- simulates "some later fatal DB error occurs
     * after a malformed row was already counted in this same call". */
    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "CREATE TEMP TRIGGER force_fail BEFORE INSERT ON scan_results "
                     "WHEN NEW.host = 'atomic-fail-host' "
                     "BEGIN SELECT RAISE(ABORT, 'test-forced failure'); END;",
                     NULL, NULL, NULL),
        SQLITE_OK);

    /* CVE-2099-00060 (malformed, sorts first) and CVE-2099-00061 (a
     * decidable MATCH, sorts second) share (vendor, product) so ONE
     * detect_and_persist() call streams both: the malformed group flushes
     * (and counts) first, then the MATCH group's scan_results insert hits
     * the trigger above and fails. */
    insert_cve(handle, "CVE-2099-00060", 1);
    insert_cpe_row(handle, "CVE-2099-00060", "atomic", "thing", "*", "", "", "", "", 1); /* malformed */
    insert_cve(handle, "CVE-2099-00061", 1);
    insert_cpe_row(handle, "CVE-2099-00061", "atomic", "thing", "5.0.0", "", "", "", "", 1); /* MATCH */

    long long scan_id = create_scan(db);
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 0);

    cytadel_scan_detection_t det = {0};
    det.host = "atomic-fail-host";
    det.port = 1234;
    det.plugin_id = "cpe_match_test";
    det.evidence = "thing/5.0.0";
    det.detected_version = "5.0.0";
    det.detected_version_len = strlen(det.detected_version);

    cytadel_scan_persist_counts_t counts;
    /* The whole call must fail -- the forced constraint violation is a fatal
     * DB error, not something detect_and_persist() can recover from. */
    CYTADEL_ASSERT_EQ(cytadel_scan_detect_and_persist(db, scan_id, "atomic", "thing", &det, &counts),
                      CYTADEL_SCAN_PERSIST_ERR_DB);

    /* THE atomicity assertion: the malformed row this failed call saw (and
     * locally counted, mid-call, before the later fatal error) must NOT have
     * been durably committed -- the whole BEGIN..COMMIT rolled back
     * together, count included. */
    CYTADEL_ASSERT_EQ(select_malformed_data_count(handle, scan_id), 0);
    /* And, consistently, no scan_results row was left behind either. */
    CYTADEL_ASSERT_EQ(count_scan_results_for_cve(handle, scan_id, "CVE-2099-00061"), 0);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* M9 Gap #3 fix: cytadel_scan_persist_finding()'s placeholder-FK dance +   */
/* per-row resilience, proven at the real DB boundary.                     */
/* ------------------------------------------------------------------ */

/* Part A: a plugin-supplied, well-formed cve_id NOT already in `cves` (NVD
 * sync lag, the NORMAL case) must still succeed -- (a) a placeholder cves
 * row is created, (b) the scan_results row lands referencing that cve_id,
 * (c) a later NVD sync promotes the placeholder to source='nvd', mirroring
 * test_kev_ingest.c's own test_placeholder_promoted_by_later_nvd_ingest().
 *
 * REVERT-PROOF (executed manually during this milestone's verification):
 * temporarily delete the `if (effective_cve_id != NULL) { ... }` placeholder
 * block from cytadel_scan_persist_finding() (src/db/scan_persist.c),
 * rebuild, and rerun this test. It MUST fail with
 * CYTADEL_SCAN_PERSIST_ERR_DB (a bare FOREIGN KEY constraint violation on
 * the scan_results insert) instead of CYTADEL_SCAN_PERSIST_OK -- if it does
 * not fail, this test is not exercising the real fix and must be corrected.
 * Revert the edit afterward. */
static void test_persist_finding_placeholder_dance_for_missing_cve(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db);

    CYTADEL_ASSERT_EQ(count_cves_for_id(handle, "CVE-2030-00001"), 0);

    cytadel_scan_finding_persist_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.host = "placeholder-host";
    finding.port = 443;
    finding.plugin_id = "ssh_known_vulnerable_openssh";
    finding.evidence = "OpenSSH 8.9p1";
    finding.cve_id = "CVE-2030-00001";
    finding.severity = 3;

    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &finding), CYTADEL_SCAN_PERSIST_OK);

    /* (a) a placeholder cves row now exists. */
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source, severity FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2030-00001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "placeholder");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 1), 0);
    sqlite3_finalize(stmt);

    /* (b) the scan_results row was inserted, referencing that cve_id. */
    scan_result_row_t row = select_scan_result(handle, scan_id, "placeholder-host", "CVE-2030-00001");
    CYTADEL_ASSERT(row.found);
    CYTADEL_ASSERT_STREQ(row.match_status, "confirmed");
    CYTADEL_ASSERT_EQ(row.kev_flag, 0);
    CYTADEL_ASSERT(row.epss_is_null);

    /* (c) a later NVD sync of the same id promotes the placeholder. */
    static const char *const njson =
        "{\"vulnerabilities\":[{\"cve\":{\"id\":\"CVE-2030-00001\","
        "\"published\":\"2023-01-01T00:00:00.000Z\","
        "\"lastModified\":\"2023-06-01T00:00:00.000Z\"}}]}";
    cytadel_nvd_ingest_counts_t ncounts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, njson, strlen(njson), "2023-06-01T00:00:00.000Z", true, &ncounts),
        CYTADEL_NVD_INGEST_OK);

    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source FROM cves WHERE cve_id = ?;", -1, &stmt, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2030-00001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "nvd");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* Part A: a malformed plugin-supplied cve_id (does not match the shared
 * CVE-ID grammar) must NEVER become a PK/FK -- the finding is persisted with
 * cve_id=NULL instead, and NO cves row (garbage or otherwise) is created for
 * it.
 *
 * REVERT-PROOF: temporarily remove the `cytadel_is_valid_cve_id()` grammar
 * gate in cytadel_scan_persist_finding() (treat `finding->cve_id` as
 * unconditionally valid), rebuild, and rerun this test. It MUST fail with
 * CYTADEL_SCAN_PERSIST_ERR_DB (this garbage id also fails the FK, and with
 * the gate removed the placeholder dance would try -- and fail some other
 * way -- rather than short-circuiting to cve_id=NULL) or, at minimum, the
 * `count_cves_for_id(handle, "CVE-BAD-ID") == 0` assertion below would no
 * longer hold once a placeholder for it existed. Revert the edit afterward. */
static void test_persist_finding_malformed_cve_id_persists_as_null(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db);

    cytadel_scan_finding_persist_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.host = "malformed-host";
    finding.port = 22;
    finding.plugin_id = "some_plugin";
    finding.evidence = "heuristic match";
    finding.cve_id = "CVE-BAD-ID"; /* "BAD" is not a 4-digit year -- fails the grammar */
    finding.severity = 2;

    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &finding), CYTADEL_SCAN_PERSIST_OK);

    /* No garbage cves row was ever created for the malformed id. */
    CYTADEL_ASSERT_EQ(count_cves_for_id(handle, "CVE-BAD-ID"), 0);

    /* The finding itself still landed, with cve_id/kev_flag/epss_score all
     * reflecting "no CVE", not a rejected row. */
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                           "SELECT match_status, cve_id, kev_flag, epss_score FROM scan_results WHERE "
                           "scan_id = ? AND host = ?;",
                           -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, "malformed-host", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "confirmed");
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 1) == SQLITE_NULL);
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 2), 0);
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 3) == SQLITE_NULL);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* Part B: a genuine per-row SQLITE_CONSTRAINT on the scan_results insert
 * itself (forced here via a TEMP trigger -- the same proven technique
 * test_malformed_data_count_rolls_back_with_its_transaction() above already
 * uses) must be classified CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED, not
 * CYTADEL_SCAN_PERSIST_ERR_DB -- AND the placeholder cves row this same call
 * already upserted for its cve_id must NOT survive (both statements are in
 * ONE transaction, rolled back together: never an orphaned placeholder
 * without its finding, or vice versa). The connection must remain fully
 * usable for the very next call. */
static void test_persist_finding_row_skip_is_atomic_and_non_fatal(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "CREATE TEMP TRIGGER force_finding_fail BEFORE INSERT ON scan_results "
                     "WHEN NEW.host = 'force-fail-finding-host' "
                     "BEGIN SELECT RAISE(ABORT, 'test-forced failure'); END;",
                     NULL, NULL, NULL),
        SQLITE_OK);

    long long scan_id = create_scan(db);

    cytadel_scan_finding_persist_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.host = "force-fail-finding-host";
    finding.port = 443;
    finding.plugin_id = "some_plugin";
    finding.evidence = "heuristic match";
    finding.cve_id = "CVE-2030-00099"; /* well-formed, not yet in cves */
    finding.severity = 3;

    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &finding),
                      CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED);

    /* THE atomicity assertion. */
    CYTADEL_ASSERT_EQ(count_cves_for_id(handle, "CVE-2030-00099"), 0);
    CYTADEL_ASSERT_EQ(count_scan_results_for_cve(handle, scan_id, "CVE-2030-00099"), 0);

    /* The connection remains fully usable for the very next call -- proves
     * ERR_ROW_SKIPPED is NOT the same class of failure as ERR_DB. */
    cytadel_scan_finding_persist_t finding2;
    memset(&finding2, 0, sizeof(finding2));
    finding2.host = "still-usable-host";
    finding2.port = 8080;
    finding2.plugin_id = "some_plugin";
    finding2.evidence = "clean";
    finding2.severity = 1;
    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &finding2), CYTADEL_SCAN_PERSIST_OK);

    cytadel_db_close(db);
}

/* Part B (THE headline no-poisoning regression test): [good, BAD, good] must
 * land BOTH good findings; the bad one is skipped (ERR_ROW_SKIPPED), and the
 * scan can still reach 'completed' -- directly disproving the original bug
 * ("detecting one CVE-referencing finding poisons the whole scan").
 *
 * REVERT-PROOF (executed manually during this milestone's verification):
 * temporarily change the scan_results-insert SQLITE_CONSTRAINT branch in
 * cytadel_scan_persist_finding() back to the OLD fatal-abort behavior (make
 * it fall through to the generic fatal branch instead of returning
 * CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED), rebuild, and rerun this test. It
 * MUST fail: the middle call returns CYTADEL_SCAN_PERSIST_ERR_DB instead of
 * CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED, and a real caller
 * (src/cli/scan_wiring.c) would stop calling cytadel_scan_persist_finding()
 * altogether at that point -- so the THIRD ("good2") finding would never
 * even be attempted, exactly reproducing "one bad finding poisons the rest
 * of the scan". Revert the edit afterward. */
static void test_persist_finding_sequence_bad_middle_does_not_poison(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "CREATE TEMP TRIGGER force_seq_fail BEFORE INSERT ON scan_results "
                     "WHEN NEW.plugin_id = 'seq_bad_plugin' "
                     "BEGIN SELECT RAISE(ABORT, 'test-forced failure'); END;",
                     NULL, NULL, NULL),
        SQLITE_OK);

    long long scan_id = create_scan(db);

    cytadel_scan_finding_persist_t good1;
    memset(&good1, 0, sizeof(good1));
    good1.host = "seq-host";
    good1.port = 80;
    good1.plugin_id = "seq_good_plugin_1";
    good1.evidence = "finding one";
    good1.severity = 1;
    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &good1), CYTADEL_SCAN_PERSIST_OK);

    cytadel_scan_finding_persist_t bad;
    memset(&bad, 0, sizeof(bad));
    bad.host = "seq-host";
    bad.port = 81;
    bad.plugin_id = "seq_bad_plugin";
    bad.evidence = "finding two (forced to fail)";
    bad.severity = 1;
    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &bad), CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED);

    cytadel_scan_finding_persist_t good2;
    memset(&good2, 0, sizeof(good2));
    good2.host = "seq-host";
    good2.port = 82;
    good2.plugin_id = "seq_good_plugin_2";
    good2.evidence = "finding three";
    good2.severity = 1;
    CYTADEL_ASSERT_EQ(cytadel_scan_persist_finding(db, scan_id, &good2), CYTADEL_SCAN_PERSIST_OK);

    /* Exactly the two good findings landed -- the bad one left no row. */
    CYTADEL_ASSERT_EQ(count_scan_results_for_host(handle, scan_id, "seq-host"), 2);

    /* The scan itself can still reach 'completed' -- this is the exact
     * db_ok-latch-level property the original M9 Gap #3 bug broke. */
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_OK);

    cytadel_db_close(db);
}

int main(void) {
    test_pure_aggregate_order_independence();
    test_db_round_trip_order_independence();
    test_headline_undecidable_round_trip();
    test_all_three_verdicts_round_trip();
    test_malformed_row_produces_no_verdict_row();
    test_malformed_row_alongside_a_decidable_row();
    test_kev_epss_snapshot();
    test_scan_create_round_trip();
    test_scan_create_rejects_invalid_args();
    test_detect_and_persist_rejects_invalid_args();
    test_detect_and_persist_no_candidates_is_a_clean_noop();
    test_malformed_data_count_durable_round_trip();
    test_malformed_data_count_zero_when_no_malformed_events();
    test_malformed_data_count_accumulates_across_calls();
    test_malformed_data_count_rolls_back_with_its_transaction();
    test_persist_finding_placeholder_dance_for_missing_cve();
    test_persist_finding_malformed_cve_id_persists_as_null();
    test_persist_finding_row_skip_is_atomic_and_non_fatal();
    test_persist_finding_sequence_bad_middle_does_not_poison();

    CYTADEL_TEST_PASS();
}
