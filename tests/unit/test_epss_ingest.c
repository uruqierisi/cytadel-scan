#include "cytadel/db/epss_ingest.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel_test.h"

/* KEV/EPSS ingest slice: src/db/epss_ingest.c (docs/contracts/db-schema.md
 * SS5/SS8/SS9/SS10 assumption 5, FROZEN CONTRACT). Near-twin of
 * test_kev_ingest.c in this same slice -- see that file's own header
 * comment for the general fixture-building convention this file follows. */

static cytadel_db_t *open_migrated_memory_db(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    return db;
}

/* ------------------------------------------------------------------ */
/* Fixture builders (cJSON tree -> serialized bytes).                  */
/* ------------------------------------------------------------------ */

static cJSON *new_root(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "status", cJSON_CreateString("OK"));
    cJSON_AddItemToObject(root, "data", cJSON_CreateArray());
    return root;
}

static void add_element(cJSON *root, cJSON *elem) {
    cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON_AddItemToArray(data, elem);
}

/* Builds one EPSS entry. Passing NULL for cve/epss/percentile/date omits
 * that key entirely (simulating "field absent"). `date_key` selects which
 * key name the date value is stored under ("date" or "score_date"), or NULL
 * to omit the date field entirely. All four value fields are stored as
 * JSON STRINGS, matching first.org's real API shape. */
static cJSON *new_epss_entry(const char *cve, const char *epss, const char *percentile, const char *date_key,
                             const char *date_value) {
    cJSON *e = cJSON_CreateObject();
    if (cve != NULL) cJSON_AddItemToObject(e, "cve", cJSON_CreateString(cve));
    if (epss != NULL) cJSON_AddItemToObject(e, "epss", cJSON_CreateString(epss));
    if (percentile != NULL) cJSON_AddItemToObject(e, "percentile", cJSON_CreateString(percentile));
    if (date_key != NULL && date_value != NULL) cJSON_AddItemToObject(e, date_key, cJSON_CreateString(date_value));
    return e;
}

static void set_string_field(cJSON *e, const char *key, const char *value) {
    cJSON_DeleteItemFromObject(e, key);
    cJSON_AddItemToObject(e, key, cJSON_CreateString(value));
}

static char *print_and_delete(cJSON *root) {
    char *json = cJSON_PrintUnformatted(root);
    CYTADEL_ASSERT(json != NULL);
    cJSON_Delete(root);
    return json;
}

/* ------------------------------------------------------------------ */
/* DB query helpers.                                                   */
/* ------------------------------------------------------------------ */

static long long count_where_cve_id(sqlite3 *handle, const char *table, const char *cve_id) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s WHERE cve_id = ?;", table);
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    long long n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static long long count_all(sqlite3 *handle, const char *table) {
    char sql[128];
    snprintf(sql, sizeof(sql), "SELECT COUNT(*) FROM %s;", table);
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, sql, -1, &stmt, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    long long n = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static void get_sync_state(sqlite3 *handle, const char *feed, char *watermark, size_t watermark_cap, char *status,
                            size_t status_cap, long long *total_records) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT last_mod_watermark, status, total_records FROM "
                                         "sync_state WHERE feed = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, feed, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const unsigned char *wm = sqlite3_column_text(stmt, 0);
    snprintf(watermark, watermark_cap, "%s", wm ? (const char *)wm : "");
    const unsigned char *st = sqlite3_column_text(stmt, 1);
    snprintf(status, status_cap, "%s", st ? (const char *)st : "");
    *total_records = sqlite3_column_int64(stmt, 2);
    sqlite3_finalize(stmt);
}

/* ------------------------------------------------------------------ */
/* Tests.                                                              */
/* ------------------------------------------------------------------ */

static void test_invalid_args(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    cytadel_epss_ingest_counts_t counts;

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(NULL, "{}", 2, true, &counts), CYTADEL_EPSS_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, NULL, 0, true, &counts), CYTADEL_EPSS_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);

    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, "{}", 2, true, NULL), CYTADEL_EPSS_INGEST_ERR_INVALID_ARG);

    cytadel_db_close(db);
}

static void test_happy_path_two_records(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2021-44228", "0.97432", "0.99991", "date", "2024-01-01"));
    /* Uses "score_date" instead of "date" -- both key names must be
     * accepted (this milestone's task brief describes the field
     * ambiguously). */
    add_element(root, new_epss_entry("CVE-2022-00001", "0.00042", "0.31000", "score_date", "2024-01-02"));

    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "SELECT epss_score, percentile, score_date FROM epss WHERE "
                                                 "cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT(sqlite3_column_double(stmt, 0) > 0.974 && sqlite3_column_double(stmt, 0) < 0.975);
    CYTADEL_ASSERT(sqlite3_column_double(stmt, 1) > 0.999 && sqlite3_column_double(stmt, 1) < 1.0001);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "2024-01-01");
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "SELECT score_date FROM epss WHERE cve_id = ?;", -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2022-00001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "2024-01-02"); /* from "score_date" fallback */
    sqlite3_finalize(stmt);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state(handle, "epss", watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT(watermark[0] != '\0');
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 2);

    cytadel_db_close(db);
}

/* Proves the placeholder-FK dance for EPSS: an entry naming a CVE not
 * already in `cves` still succeeds. */
static void test_placeholder_fk_dance_creates_cves_row(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2023-22222"), 0);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2023-22222", "0.5", "0.5", "date", "2023-06-01"));
    char *json = print_and_delete(root);

    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2023-22222"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2023-22222"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source, severity FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2023-22222", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "placeholder");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 1), 0);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* Proves skip-and-log does NOT abort the whole ingest: [good, BAD, good]
 * must land BOTH good records and skip only the bad one (missing required
 * field). */
static void test_missing_required_field_skipped_others_ingested(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2024-10001", "0.1", "0.1", "date", "2024-01-01"));
    /* BAD: no "percentile" key at all. */
    add_element(root, new_epss_entry("CVE-2024-10002", "0.2", NULL, "date", "2024-01-01"));
    add_element(root, new_epss_entry("CVE-2024-10003", "0.3", "0.3", "date", "2024-01-01"));

    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 1);
    CYTADEL_ASSERT_EQ(count_all(handle, "epss"), 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-10001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-10003"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-10002"), 0);

    cytadel_db_close(db);
}

/* out-of-[0,1]-range and non-numeric epss/percentile strings must each be
 * skipped, without aborting the other, good records in the same buffer. */
static void test_out_of_range_and_non_numeric_probability_strings_skipped(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2024-20001", "0.5", "0.5", "date", "2024-01-01")); /* GOOD */
    add_element(root, new_epss_entry("CVE-2024-20002", "1.5", "0.5", "date", "2024-01-01")); /* BAD: epss > 1.0 */
    add_element(root,
                new_epss_entry("CVE-2024-20003", "0.5", "-0.1", "date", "2024-01-01")); /* BAD: percentile < 0.0 */
    add_element(root, new_epss_entry("CVE-2024-20004", "abc", "0.5", "date", "2024-01-01")); /* BAD: non-numeric */
    add_element(root, new_epss_entry("CVE-2024-20005", "0.5", "0.5", "date", "2024-01-01")); /* GOOD, after bad ones */

    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 3);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-20001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-20005"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-20002"), 0);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-20003"), 0);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-20004"), 0);

    cytadel_db_close(db);
}

/* Security-review W3-class regression, same as test_kev_ingest.c's own copy
 * -- proves this module also calls the ONE shared cytadel_is_valid_cve_id()
 * (src/db/cve_id_valid.h), not a second, independently hand-rolled check. */
static void test_embedded_nul_cve_id_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    const char *page_json =
        "{\"data\":["
        "{\"cve\":\"CVE-X\\u0000A\",\"epss\":\"0.5\",\"percentile\":\"0.5\",\"date\":\"2024-01-01\"},"
        "{\"cve\":\"CVE-2024-80001\",\"epss\":\"0.5\",\"percentile\":\"0.5\",\"date\":\"2024-01-01\"}"
        "]}";

    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, page_json, strlen(page_json), true, &counts),
                      CYTADEL_EPSS_INGEST_OK);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-80001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-X"), 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "epss"), 1);

    cytadel_db_close(db);
}

static void test_oversized_date_clipped_not_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    size_t huge_len = CYTADEL_EPSS_DATE_MAX_LEN + 1000;
    char *huge = malloc(huge_len + 1);
    CYTADEL_ASSERT(huge != NULL);
    memset(huge, '9', huge_len);
    huge[huge_len] = '\0';

    cJSON *root = new_root();
    cJSON *e = new_epss_entry("CVE-2024-30001", "0.5", "0.5", "date", "2024-01-01");
    set_string_field(e, "date", huge);
    add_element(root, e);
    free(huge);

    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT LENGTH(score_date) FROM epss WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-30001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int64(stmt, 0), CYTADEL_EPSS_DATE_MAX_LEN);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_duplicate_cve_id_upsert_idempotent(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2024-70001", "0.1", "0.1", "date", "2024-01-01"));
    add_element(root, new_epss_entry("CVE-2024-70001", "0.9", "0.9", "date", "2024-02-02")); /* should win */

    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.epss_ingested, 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-70001"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT epss_score, score_date FROM epss WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-70001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT(sqlite3_column_double(stmt, 0) > 0.899 && sqlite3_column_double(stmt, 0) < 0.901);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "2024-02-02");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_missing_data_key_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    const char *page_json = "{\"status\":\"OK\"}";
    cytadel_epss_ingest_counts_t counts;
    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, page_json, strlen(page_json), true, &counts),
                      CYTADEL_EPSS_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    cytadel_db_close(db);
}

static void test_non_array_data_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *seed_root = new_root();
    add_element(seed_root, new_epss_entry("CVE-2024-90001", "0.1", "0.1", "date", "2024-01-01"));
    char *seed_json = print_and_delete(seed_root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, seed_json, strlen(seed_json), true, &counts),
                      CYTADEL_EPSS_INGEST_OK);
    cJSON_free(seed_json);

    char seed_watermark[64];
    char seed_status[32];
    long long seed_total_records = -1;
    get_sync_state(handle, "epss", seed_watermark, sizeof(seed_watermark), seed_status, sizeof(seed_status),
                    &seed_total_records);
    CYTADEL_ASSERT_STREQ(seed_status, "success");

    const char *page_json = "{\"data\":\"x\"}";
    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, page_json, strlen(page_json), true, &counts),
                      CYTADEL_EPSS_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state(handle, "epss", watermark_after, sizeof(watermark_after), status_after, sizeof(status_after),
                    &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, seed_watermark);
    CYTADEL_ASSERT_STREQ(status_after, seed_status);
    CYTADEL_ASSERT_EQ(total_records_after, seed_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "epss"), 1);

    cytadel_db_close(db);
}

static void test_empty_data_array_is_valid_empty_buffer(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    char *json = print_and_delete(root);

    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state(handle, "epss", watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT(watermark[0] != '\0');
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "epss"), 0);

    cytadel_db_close(db);
}

/* Revert-proof-shaped regression: proves the watermark advances ONLY when a
 * call parses+commits cleanly, mirroring test_kev_ingest.c's own copy. */
static void test_truncated_json_returns_parse_error_watermark_unchanged(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_epss_entry("CVE-2024-60001", "0.1", "0.1", "date", "2024-01-01"));
    char *json = print_and_delete(root);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json, strlen(json), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json);

    char baseline_watermark[64];
    char baseline_status[32];
    long long baseline_total_records = -1;
    get_sync_state(handle, "epss", baseline_watermark, sizeof(baseline_watermark), baseline_status,
                    sizeof(baseline_status), &baseline_total_records);
    long long baseline_epss_count = count_all(handle, "epss");
    CYTADEL_ASSERT_STREQ(baseline_status, "success");
    CYTADEL_ASSERT_EQ(baseline_epss_count, 1);

    root = new_root();
    add_element(root, new_epss_entry("CVE-2024-60002", "0.2", "0.2", "date", "2024-02-01"));
    json = print_and_delete(root);
    size_t full_len = strlen(json);
    size_t truncated_len = full_len / 2;

    memset(&counts, 0xAA, sizeof(counts));
    cytadel_epss_ingest_status_t status = cytadel_epss_ingest(db, json, truncated_len, true, &counts);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(status, CYTADEL_EPSS_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.epss_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state(handle, "epss", watermark_after, sizeof(watermark_after), status_after, sizeof(status_after),
                    &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, baseline_watermark);
    CYTADEL_ASSERT_STREQ(status_after, baseline_status);
    CYTADEL_ASSERT_EQ(total_records_after, baseline_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "epss"), baseline_epss_count);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-60002"), 0);

    cytadel_db_close(db);
}

static void test_full_pull_complete_false_then_true(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    char initial_watermark[64];
    char initial_status[32];
    long long initial_total_records = -1;
    get_sync_state(handle, "epss", initial_watermark, sizeof(initial_watermark), initial_status,
                    sizeof(initial_status), &initial_total_records);
    CYTADEL_ASSERT_STREQ(initial_watermark, "");
    CYTADEL_ASSERT_STREQ(initial_status, "idle");
    CYTADEL_ASSERT_EQ(initial_total_records, 0);

    cJSON *root1 = new_root();
    add_element(root1, new_epss_entry("CVE-2024-95001", "0.1", "0.1", "date", "2024-01-01"));
    char *json1 = print_and_delete(root1);
    cytadel_epss_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json1, strlen(json1), false, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json1);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "epss", "CVE-2024-95001"), 1);

    char watermark_mid[64];
    char status_mid[32];
    long long total_records_mid = -1;
    get_sync_state(handle, "epss", watermark_mid, sizeof(watermark_mid), status_mid, sizeof(status_mid),
                    &total_records_mid);
    CYTADEL_ASSERT_STREQ(watermark_mid, initial_watermark);
    CYTADEL_ASSERT_STREQ(status_mid, "running");
    CYTADEL_ASSERT_EQ(total_records_mid, 1);

    cJSON *root2 = new_root();
    add_element(root2, new_epss_entry("CVE-2024-95002", "0.2", "0.2", "date", "2024-01-02"));
    char *json2 = print_and_delete(root2);
    CYTADEL_ASSERT_EQ(cytadel_epss_ingest(db, json2, strlen(json2), true, &counts), CYTADEL_EPSS_INGEST_OK);
    cJSON_free(json2);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 1);

    char watermark_final[64];
    char status_final[32];
    long long total_records_final = -1;
    get_sync_state(handle, "epss", watermark_final, sizeof(watermark_final), status_final, sizeof(status_final),
                    &total_records_final);
    CYTADEL_ASSERT(watermark_final[0] != '\0');
    CYTADEL_ASSERT_STREQ(status_final, "success");
    CYTADEL_ASSERT_EQ(total_records_final, 2);

    cytadel_db_close(db);
}

static void test_status_to_string_never_null(void) {
    CYTADEL_ASSERT(cytadel_epss_ingest_status_to_string(CYTADEL_EPSS_INGEST_OK) != NULL);
    CYTADEL_ASSERT(cytadel_epss_ingest_status_to_string(CYTADEL_EPSS_INGEST_ERR_INVALID_ARG) != NULL);
    CYTADEL_ASSERT(cytadel_epss_ingest_status_to_string(CYTADEL_EPSS_INGEST_ERR_PARSE) != NULL);
    CYTADEL_ASSERT(cytadel_epss_ingest_status_to_string(CYTADEL_EPSS_INGEST_ERR_DB) != NULL);
    CYTADEL_ASSERT(cytadel_epss_ingest_status_to_string((cytadel_epss_ingest_status_t)999) != NULL);
}

int main(void) {
    test_invalid_args();
    test_happy_path_two_records();
    test_placeholder_fk_dance_creates_cves_row();
    test_missing_required_field_skipped_others_ingested();
    test_out_of_range_and_non_numeric_probability_strings_skipped();
    test_embedded_nul_cve_id_rejected();
    test_oversized_date_clipped_not_rejected();
    test_duplicate_cve_id_upsert_idempotent();
    test_missing_data_key_returns_parse_error();
    test_non_array_data_returns_parse_error();
    test_empty_data_array_is_valid_empty_buffer();
    test_truncated_json_returns_parse_error_watermark_unchanged();
    test_full_pull_complete_false_then_true();
    test_status_to_string_never_null();

    CYTADEL_TEST_PASS();
}
