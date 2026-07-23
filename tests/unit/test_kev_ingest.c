#include "cytadel/db/kev_ingest.h"

#include "cytadel/db/nvd_ingest.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel_test.h"

/* KEV/EPSS ingest slice: src/db/kev_ingest.c (docs/contracts/db-schema.md
 * SS4/SS8/SS9/SS10 assumption 5, FROZEN CONTRACT). Fixtures are built with
 * cJSON's own C API, same convention as test_nvd_ingest.c, so a fixture's
 * *shape* is unambiguous. Links cytadel_sqlite3 (own prepare/bind/step
 * assertions against cytadel_db_handle()) and cytadel_cjson (fixtures)
 * directly, same "the module that needs it links it" policy. */

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
    cJSON_AddItemToObject(root, "vulnerabilities", cJSON_CreateArray());
    return root;
}

static void add_element(cJSON *root, cJSON *elem) {
    cJSON *vulnerabilities = cJSON_GetObjectItemCaseSensitive(root, "vulnerabilities");
    cJSON_AddItemToArray(vulnerabilities, elem);
}

/* Builds one KEV entry with only the required fields set. Passing NULL for
 * any of the five omits that key entirely (simulating "field absent"). */
static cJSON *new_kev_entry(const char *cve_id, const char *date_added, const char *vendor_project,
                            const char *product, const char *vulnerability_name) {
    cJSON *e = cJSON_CreateObject();
    if (cve_id != NULL) cJSON_AddItemToObject(e, "cveID", cJSON_CreateString(cve_id));
    if (date_added != NULL) cJSON_AddItemToObject(e, "dateAdded", cJSON_CreateString(date_added));
    if (vendor_project != NULL) cJSON_AddItemToObject(e, "vendorProject", cJSON_CreateString(vendor_project));
    if (product != NULL) cJSON_AddItemToObject(e, "product", cJSON_CreateString(product));
    if (vulnerability_name != NULL)
        cJSON_AddItemToObject(e, "vulnerabilityName", cJSON_CreateString(vulnerability_name));
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
    cytadel_kev_ingest_counts_t counts;

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(NULL, "{}", 2, true, &counts), CYTADEL_KEV_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, NULL, 0, true, &counts), CYTADEL_KEV_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);

    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, "{}", 2, true, NULL), CYTADEL_KEV_INGEST_ERR_INVALID_ARG);

    cytadel_db_close(db);
}

static void test_happy_path_ransomware_variants(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();

    cJSON *e1 = new_kev_entry("CVE-2021-44228", "2021-12-10", "Apache", "Log4j", "Apache Log4j RCE");
    set_string_field(e1, "requiredAction", "Apply updates.");
    set_string_field(e1, "dueDate", "2022-01-01");
    set_string_field(e1, "notes", "https://example.com/advisory");
    set_string_field(e1, "knownRansomwareCampaignUse", "Known");
    add_element(root, e1);

    cJSON *e2 = new_kev_entry("CVE-2021-99991", "2021-12-11", "Vendor", "Product", "Some issue");
    set_string_field(e2, "knownRansomwareCampaignUse", "Unknown");
    add_element(root, e2);

    /* No knownRansomwareCampaignUse key at all -- must also default to 0. */
    cJSON *e3 = new_kev_entry("CVE-2021-99992", "2021-12-12", "Vendor2", "Product2", "Another issue");
    add_element(root, e3);

    char *json = print_and_delete(root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 3);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT date_added, vendor_project, product, vulnerability_name, "
                                         "required_action, due_date, notes, known_ransomware FROM kev WHERE "
                                         "cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "2021-12-10");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "Apache");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "Log4j");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3), "Apache Log4j RCE");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 4), "Apply updates.");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 5), "2022-01-01");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 6), "https://example.com/advisory");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 7), 1); /* "Known" -> 1 */
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT known_ransomware FROM kev WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-99991", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 0), 0); /* "Unknown" -> 0 */
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                           "SELECT known_ransomware, required_action, due_date, notes FROM kev WHERE cve_id = ?;",
                           -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-99992", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 0), 0); /* absent -> 0 */
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 1) == SQLITE_NULL);
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 2) == SQLITE_NULL);
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 3) == SQLITE_NULL);
    sqlite3_finalize(stmt);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state(handle, "kev", watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT(watermark[0] != '\0'); /* strftime('%Y-%m-%d','now') -- non-empty */
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 3);

    cytadel_db_close(db);
}

/* Proves the placeholder-FK dance: a KEV entry naming a CVE NOT already in
 * `cves` still succeeds -- a placeholder row is created (source =
 * 'placeholder') rather than the whole record failing on `FOREIGN KEY
 * constraint failed`. */
static void test_placeholder_fk_dance_creates_cves_row(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2023-11111"), 0);

    cJSON *root = new_root();
    add_element(root, new_kev_entry("CVE-2023-11111", "2023-01-01", "Acme", "Widget", "Widget RCE"));
    char *json = print_and_delete(root);

    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2023-11111"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2023-11111"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source, severity FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2023-11111", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "placeholder");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 1), 0);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* W1 (security review): closes the untested SECOND half of the placeholder-FK
 * property. A KEV entry creates a placeholder cves row (source='placeholder');
 * a later NVD ingest of the SAME cve_id must PROMOTE it to source='nvd' while
 * the kev row survives. The promotion code path was correct but had no shipped
 * test -- exactly the "green over an unexercised path" risk this project keeps
 * getting bitten by. Revert-proof: weaken the NVD upsert's
 * `source='nvd'` reassignment and this test fails. */
static void test_placeholder_promoted_by_later_nvd_ingest(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* 1. KEV names a CVE not yet in cves -> placeholder row. */
    cJSON *kroot = new_root();
    add_element(kroot, new_kev_entry("CVE-2023-22222", "2023-01-01", "Acme", "Widget", "Widget RCE"));
    char *kjson = print_and_delete(kroot);
    cytadel_kev_ingest_counts_t kcounts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, kjson, strlen(kjson), true, &kcounts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(kjson);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2023-22222", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "placeholder");
    sqlite3_finalize(stmt);

    /* 2. NVD ingest of the same id -> promoted to source='nvd'. */
    cJSON *nroot = cJSON_CreateObject();
    cJSON *vulns = cJSON_AddArrayToObject(nroot, "vulnerabilities");
    cJSON *elem = cJSON_CreateObject();
    cJSON *cve = cJSON_CreateObject();
    cJSON_AddItemToObject(cve, "id", cJSON_CreateString("CVE-2023-22222"));
    cJSON_AddItemToObject(cve, "published", cJSON_CreateString("2023-01-01T00:00:00.000Z"));
    cJSON_AddItemToObject(cve, "lastModified", cJSON_CreateString("2023-06-01T00:00:00.000Z"));
    cJSON_AddItemToObject(elem, "cve", cve);
    cJSON_AddItemToArray(vulns, elem);
    char *njson = cJSON_PrintUnformatted(nroot);
    cJSON_Delete(nroot);

    cytadel_nvd_ingest_counts_t ncounts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, njson, strlen(njson), "2023-06-01T00:00:00.000Z", true, &ncounts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(njson);

    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT source FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2023-22222", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "nvd");
    sqlite3_finalize(stmt);

    /* 3. The kev row survives the promotion. */
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2023-22222"), 1);

    cytadel_db_close(db);
}

/* Proves skip-and-log does NOT abort the whole ingest: [good, BAD, good]
 * must land BOTH good records and skip only the bad one (missing required
 * field). */
static void test_missing_required_field_skipped_others_ingested(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_kev_entry("CVE-2024-10001", "2024-01-01", "Vendor", "Product", "Issue A"));
    /* BAD: no "vendorProject" key at all. */
    add_element(root, new_kev_entry("CVE-2024-10002", "2024-01-02", NULL, "Product", "Issue B"));
    add_element(root, new_kev_entry("CVE-2024-10003", "2024-01-03", "Vendor", "Product", "Issue C"));

    char *json = print_and_delete(root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 1);
    CYTADEL_ASSERT_EQ(count_all(handle, "kev"), 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-10001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-10003"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-10002"), 0);

    cytadel_db_close(db);
}

/* Security-review W3-class regression: cJSON decodes a JSON string's
 * null-character escape sequence into a genuine embedded NUL byte. A
 * crafted cveID whose visible prefix is not itself a complete CVE id must
 * be skipped -- proving the shared cytadel_is_valid_cve_id() guard (src/db/
 * cve_id_valid.h) is actually being called from this module, not just
 * nvd_ingest.c. */
static void test_embedded_nul_cve_id_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    const char *page_json =
        "{\"vulnerabilities\":["
        "{\"cveID\":\"CVE-X\\u0000A\",\"dateAdded\":\"2024-01-01\",\"vendorProject\":\"V\","
        "\"product\":\"P\",\"vulnerabilityName\":\"N\"},"
        "{\"cveID\":\"CVE-2024-80001\",\"dateAdded\":\"2024-01-01\",\"vendorProject\":\"V\","
        "\"product\":\"P\",\"vulnerabilityName\":\"N\"}"
        "]}";

    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, page_json, strlen(page_json), true, &counts), CYTADEL_KEV_INGEST_OK);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-80001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-X"), 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "kev"), 1);

    cytadel_db_close(db);
}

static void test_oversized_notes_clipped_not_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    size_t huge_len = CYTADEL_KEV_NOTES_MAX_LEN + 1000;
    char *huge = malloc(huge_len + 1);
    CYTADEL_ASSERT(huge != NULL);
    memset(huge, 'A', huge_len);
    huge[huge_len] = '\0';

    cJSON *root = new_root();
    cJSON *e = new_kev_entry("CVE-2024-30001", "2024-01-01", "Vendor", "Product", "Issue");
    set_string_field(e, "notes", huge);
    add_element(root, e);
    free(huge);

    char *json = print_and_delete(root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "SELECT LENGTH(notes) FROM kev WHERE cve_id = ?;", -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-30001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int64(stmt, 0), CYTADEL_KEV_NOTES_MAX_LEN);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* Duplicate cve_id within one buffer: both attempts succeed at the DB layer
 * (upsert, never a crash); only one distinct row exists afterward, with the
 * later upsert's fields winning. */
static void test_duplicate_cve_id_upsert_idempotent(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    cJSON *first = new_kev_entry("CVE-2024-70001", "2024-01-01", "VendorA", "ProductA", "First name");
    add_element(root, first);
    cJSON *second = new_kev_entry("CVE-2024-70001", "2024-02-02", "VendorB", "ProductB", "Second name (should win)");
    add_element(root, second);

    char *json = print_and_delete(root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.kev_ingested, 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-70001"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT date_added, vulnerability_name FROM kev WHERE cve_id = ?;", -1, &stmt,
                           NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-70001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "2024-02-02");
    /* Per the frozen contract's own upsert text, vulnerability_name is only
     * ever set on the INITIAL insert -- it is NOT in the ON CONFLICT DO
     * UPDATE SET clause, so the FIRST record's name survives. */
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "First name");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_missing_vulnerabilities_key_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    const char *page_json = "{\"foo\":\"bar\"}";
    cytadel_kev_ingest_counts_t counts;
    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, page_json, strlen(page_json), true, &counts),
                      CYTADEL_KEV_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    cytadel_db_close(db);
}

static void test_non_array_vulnerabilities_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* Seed a known watermark via one real, successful ingest first. */
    cJSON *seed_root = new_root();
    add_element(seed_root, new_kev_entry("CVE-2024-90001", "2024-01-01", "Vendor", "Product", "Issue"));
    char *seed_json = print_and_delete(seed_root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, seed_json, strlen(seed_json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(seed_json);

    char seed_watermark[64];
    char seed_status[32];
    long long seed_total_records = -1;
    get_sync_state(handle, "kev", seed_watermark, sizeof(seed_watermark), seed_status, sizeof(seed_status),
                    &seed_total_records);
    CYTADEL_ASSERT_STREQ(seed_status, "success");

    const char *page_json = "{\"vulnerabilities\":\"x\"}";
    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, page_json, strlen(page_json), true, &counts),
                      CYTADEL_KEV_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state(handle, "kev", watermark_after, sizeof(watermark_after), status_after, sizeof(status_after),
                    &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, seed_watermark);
    CYTADEL_ASSERT_STREQ(status_after, seed_status);
    CYTADEL_ASSERT_EQ(total_records_after, seed_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "kev"), 1);

    cytadel_db_close(db);
}

static void test_empty_vulnerabilities_array_is_valid_empty_buffer(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    char *json = print_and_delete(root);

    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state(handle, "kev", watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT(watermark[0] != '\0');
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "kev"), 0);

    cytadel_db_close(db);
}

/* Revert-proof-shaped regression: proves the watermark advances ONLY when a
 * chunk is truncated/malformed. Establishes a baseline via a real
 * successful ingest, then hands a truncated (never-valid) JSON buffer to a
 * SECOND call and asserts sync_state is byte-for-byte unchanged from the
 * baseline (no transaction was ever opened for the failed call). */
static void test_truncated_json_returns_parse_error_watermark_unchanged(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    add_element(root, new_kev_entry("CVE-2024-60001", "2024-01-01", "Vendor", "Product", "Issue"));
    char *json = print_and_delete(root);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json, strlen(json), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json);

    char baseline_watermark[64];
    char baseline_status[32];
    long long baseline_total_records = -1;
    get_sync_state(handle, "kev", baseline_watermark, sizeof(baseline_watermark), baseline_status,
                    sizeof(baseline_status), &baseline_total_records);
    long long baseline_kev_count = count_all(handle, "kev");
    CYTADEL_ASSERT_STREQ(baseline_status, "success");
    CYTADEL_ASSERT_EQ(baseline_kev_count, 1);

    /* A second, otherwise-valid buffer, truncated mid-document before ever
     * reaching the parser -- simulates a connection that died mid-fetch. */
    root = new_root();
    add_element(root, new_kev_entry("CVE-2024-60002", "2024-02-01", "Vendor2", "Product2", "Issue2"));
    json = print_and_delete(root);
    size_t full_len = strlen(json);
    size_t truncated_len = full_len / 2;

    memset(&counts, 0xAA, sizeof(counts));
    cytadel_kev_ingest_status_t status = cytadel_kev_ingest(db, json, truncated_len, true, &counts);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(status, CYTADEL_KEV_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state(handle, "kev", watermark_after, sizeof(watermark_after), status_after, sizeof(status_after),
                    &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, baseline_watermark);
    CYTADEL_ASSERT_STREQ(status_after, baseline_status);
    CYTADEL_ASSERT_EQ(total_records_after, baseline_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "kev"), baseline_kev_count);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-60002"), 0);

    cytadel_db_close(db);
}

/* full_pull_complete = false must commit this chunk's data but leave the
 * watermark/status untouched ('running', not 'success'); a later
 * full_pull_complete = true call then advances the watermark. */
static void test_full_pull_complete_false_then_true(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    char initial_watermark[64];
    char initial_status[32];
    long long initial_total_records = -1;
    get_sync_state(handle, "kev", initial_watermark, sizeof(initial_watermark), initial_status,
                    sizeof(initial_status), &initial_total_records);
    CYTADEL_ASSERT_STREQ(initial_watermark, "");
    CYTADEL_ASSERT_STREQ(initial_status, "idle");
    CYTADEL_ASSERT_EQ(initial_total_records, 0);

    cJSON *root1 = new_root();
    add_element(root1, new_kev_entry("CVE-2024-95001", "2024-01-01", "Vendor", "Product", "Issue"));
    char *json1 = print_and_delete(root1);
    cytadel_kev_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json1, strlen(json1), false, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json1);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "kev", "CVE-2024-95001"), 1);

    char watermark_mid[64];
    char status_mid[32];
    long long total_records_mid = -1;
    get_sync_state(handle, "kev", watermark_mid, sizeof(watermark_mid), status_mid, sizeof(status_mid),
                    &total_records_mid);
    CYTADEL_ASSERT_STREQ(watermark_mid, initial_watermark);
    CYTADEL_ASSERT_STREQ(status_mid, "running");
    CYTADEL_ASSERT_EQ(total_records_mid, 1);

    cJSON *root2 = new_root();
    add_element(root2, new_kev_entry("CVE-2024-95002", "2024-01-02", "Vendor2", "Product2", "Issue2"));
    char *json2 = print_and_delete(root2);
    CYTADEL_ASSERT_EQ(cytadel_kev_ingest(db, json2, strlen(json2), true, &counts), CYTADEL_KEV_INGEST_OK);
    cJSON_free(json2);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 1);

    char watermark_final[64];
    char status_final[32];
    long long total_records_final = -1;
    get_sync_state(handle, "kev", watermark_final, sizeof(watermark_final), status_final, sizeof(status_final),
                    &total_records_final);
    CYTADEL_ASSERT(watermark_final[0] != '\0');
    CYTADEL_ASSERT_STREQ(status_final, "success");
    CYTADEL_ASSERT_EQ(total_records_final, 2);

    cytadel_db_close(db);
}

static void test_status_to_string_never_null(void) {
    CYTADEL_ASSERT(cytadel_kev_ingest_status_to_string(CYTADEL_KEV_INGEST_OK) != NULL);
    CYTADEL_ASSERT(cytadel_kev_ingest_status_to_string(CYTADEL_KEV_INGEST_ERR_INVALID_ARG) != NULL);
    CYTADEL_ASSERT(cytadel_kev_ingest_status_to_string(CYTADEL_KEV_INGEST_ERR_PARSE) != NULL);
    CYTADEL_ASSERT(cytadel_kev_ingest_status_to_string(CYTADEL_KEV_INGEST_ERR_DB) != NULL);
    CYTADEL_ASSERT(cytadel_kev_ingest_status_to_string((cytadel_kev_ingest_status_t)999) != NULL);
}

int main(void) {
    test_invalid_args();
    test_happy_path_ransomware_variants();
    test_placeholder_fk_dance_creates_cves_row();
    test_placeholder_promoted_by_later_nvd_ingest();
    test_missing_required_field_skipped_others_ingested();
    test_embedded_nul_cve_id_rejected();
    test_oversized_notes_clipped_not_rejected();
    test_duplicate_cve_id_upsert_idempotent();
    test_missing_vulnerabilities_key_returns_parse_error();
    test_non_array_vulnerabilities_returns_parse_error();
    test_empty_vulnerabilities_array_is_valid_empty_buffer();
    test_truncated_json_returns_parse_error_watermark_unchanged();
    test_full_pull_complete_false_then_true();
    test_status_to_string_never_null();

    CYTADEL_TEST_PASS();
}
