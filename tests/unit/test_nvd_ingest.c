#include "cytadel/db/nvd_ingest.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel_test.h"

/* Milestone 7 slice 2: src/db/nvd_ingest.c (docs/contracts/db-schema.md,
 * FROZEN CONTRACT). Every hostile-input fixture below is built with cJSON's
 * own C API (rather than hand-escaped string literals) so a fixture's
 * *shape* -- e.g. "metrics is a JSON string, not an object" -- is
 * unambiguous and cannot be misread the way a giant raw JSON literal could
 * be. Links cytadel_sqlite3 (own sqlite3_prepare_v2()/bind/step assertions
 * against cytadel_db_handle(), same convention as test_db.c) and
 * cytadel_cjson (building fixtures) directly, per build-plan.md §2's "the
 * module that needs it links it" policy applied to this test binary
 * itself. */

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

/* Builds a bare "cve" object with just id/published/lastModified set.
 * Passing NULL for any of the three omits that key entirely (simulating
 * "field absent"). */
static cJSON *new_cve_shell(const char *id, const char *published, const char *last_modified) {
    cJSON *cve = cJSON_CreateObject();
    if (id != NULL) {
        cJSON_AddItemToObject(cve, "id", cJSON_CreateString(id));
    }
    if (published != NULL) {
        cJSON_AddItemToObject(cve, "published", cJSON_CreateString(published));
    }
    if (last_modified != NULL) {
        cJSON_AddItemToObject(cve, "lastModified", cJSON_CreateString(last_modified));
    }
    return cve;
}

/* Wraps a "cve" object into a "vulnerabilities[]" element:
 * {"cve": {...}}. */
static cJSON *wrap_element(cJSON *cve) {
    cJSON *elem = cJSON_CreateObject();
    cJSON_AddItemToObject(elem, "cve", cve);
    return elem;
}

static void add_description(cJSON *cve, const char *lang, const char *value) {
    cJSON *descriptions = cJSON_GetObjectItemCaseSensitive(cve, "descriptions");
    if (descriptions == NULL) {
        descriptions = cJSON_CreateArray();
        cJSON_AddItemToObject(cve, "descriptions", descriptions);
    }
    cJSON *entry = cJSON_CreateObject();
    cJSON_AddItemToObject(entry, "lang", cJSON_CreateString(lang));
    cJSON_AddItemToObject(entry, "value", cJSON_CreateString(value));
    cJSON_AddItemToArray(descriptions, entry);
}

static void add_cvss_v31(cJSON *cve, const char *vector, double score, const char *severity) {
    cJSON *metrics = cJSON_GetObjectItemCaseSensitive(cve, "metrics");
    if (metrics == NULL) {
        metrics = cJSON_CreateObject();
        cJSON_AddItemToObject(cve, "metrics", metrics);
    }
    cJSON *arr = cJSON_CreateArray();
    cJSON_AddItemToObject(metrics, "cvssMetricV31", arr);

    cJSON *cvss_data = cJSON_CreateObject();
    cJSON_AddItemToObject(cvss_data, "vectorString", cJSON_CreateString(vector));
    cJSON_AddItemToObject(cvss_data, "baseScore", cJSON_CreateNumber(score));
    cJSON_AddItemToObject(cvss_data, "baseSeverity", cJSON_CreateString(severity));

    cJSON *metric = cJSON_CreateObject();
    cJSON_AddItemToObject(metric, "cvssData", cvss_data);
    cJSON_AddItemToArray(arr, metric);
}

/* Ensures cve.configurations[0].nodes[0] exists and returns that node
 * object, creating the configurations/nodes scaffolding on first call. */
static cJSON *get_or_create_first_node(cJSON *cve) {
    cJSON *configurations = cJSON_GetObjectItemCaseSensitive(cve, "configurations");
    if (configurations == NULL) {
        configurations = cJSON_CreateArray();
        cJSON_AddItemToObject(cve, "configurations", configurations);
        cJSON *config = cJSON_CreateObject();
        cJSON *nodes = cJSON_CreateArray();
        cJSON_AddItemToObject(config, "nodes", nodes);
        cJSON_AddItemToArray(configurations, config);
        cJSON *node = cJSON_CreateObject();
        cJSON_AddItemToArray(nodes, node);
        return node;
    }
    cJSON *config = configurations->child;
    cJSON *nodes = cJSON_GetObjectItemCaseSensitive(config, "nodes");
    return nodes->child;
}

static void add_cpe_match_full(cJSON *cve, const char *criteria, int vulnerable, const char *vsi,
                                const char *vse, const char *vei, const char *vee) {
    cJSON *node = get_or_create_first_node(cve);
    cJSON *matches = cJSON_GetObjectItemCaseSensitive(node, "cpeMatch");
    if (matches == NULL) {
        matches = cJSON_CreateArray();
        cJSON_AddItemToObject(node, "cpeMatch", matches);
    }
    cJSON *m = cJSON_CreateObject();
    cJSON_AddItemToObject(m, "criteria", cJSON_CreateString(criteria));
    cJSON_AddItemToObject(m, "vulnerable", cJSON_CreateBool(vulnerable));
    if (vsi != NULL) cJSON_AddItemToObject(m, "versionStartIncluding", cJSON_CreateString(vsi));
    if (vse != NULL) cJSON_AddItemToObject(m, "versionStartExcluding", cJSON_CreateString(vse));
    if (vei != NULL) cJSON_AddItemToObject(m, "versionEndIncluding", cJSON_CreateString(vei));
    if (vee != NULL) cJSON_AddItemToObject(m, "versionEndExcluding", cJSON_CreateString(vee));
    cJSON_AddItemToArray(matches, m);
}

static void add_cpe_match(cJSON *cve, const char *criteria, const char *vei) {
    add_cpe_match_full(cve, criteria, 1, NULL, NULL, vei, NULL);
}

static cJSON *new_root(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "format", cJSON_CreateString("NVD_CVE"));
    cJSON_AddItemToObject(root, "vulnerabilities", cJSON_CreateArray());
    return root;
}

static void add_element(cJSON *root, cJSON *elem) {
    cJSON *vulnerabilities = cJSON_GetObjectItemCaseSensitive(root, "vulnerabilities");
    cJSON_AddItemToArray(vulnerabilities, elem);
}

/* Serializes `root` to a heap buffer and deletes the tree -- the returned
 * pointer must be freed with cJSON_free(). */
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

static void get_sync_state_nvd(sqlite3 *handle, char *watermark, size_t watermark_cap, char *status,
                                size_t status_cap, long long *total_records) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT last_mod_watermark, status, total_records FROM "
                                         "sync_state WHERE feed = 'nvd';",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
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
    cytadel_nvd_ingest_counts_t counts;

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(NULL, "{}", 2, "2024-01-01T00:00:00.000Z", true, &counts),
                      CYTADEL_NVD_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, NULL, 0, "2024-01-01T00:00:00.000Z", true, &counts),
                      CYTADEL_NVD_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, "{}", 2, NULL, true, &counts),
                      CYTADEL_NVD_INGEST_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);

    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, "{}", 2, "", true, &counts),
                      CYTADEL_NVD_INGEST_ERR_INVALID_ARG);

    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, "{}", 2, "2024-01-01T00:00:00.000Z", true, NULL),
                      CYTADEL_NVD_INGEST_ERR_INVALID_ARG);

    cytadel_db_close(db);
}

static void test_happy_path_two_cves_with_cvss_and_cpe(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();

    cJSON *cve1 = new_cve_shell("CVE-2021-44228", "2021-12-10T10:15:09.143", "2021-12-14T00:00:00.000");
    add_description(cve1, "en", "Log4Shell");
    add_cvss_v31(cve1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0, "CRITICAL");
    add_cpe_match(cve1, "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", "2.15.0");
    add_element(root, wrap_element(cve1));

    cJSON *cve2 = new_cve_shell("CVE-2022-00001", "2022-01-01T00:00:00.000Z", "2022-01-02T00:00:00.000Z");
    add_description(cve2, "en", "A medium severity issue");
    add_cvss_v31(cve2, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", 5.0, "MEDIUM");
    add_element(root, wrap_element(cve2));

    char *json = print_and_delete(root);
    size_t len = strlen(json);

    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, json, len, "2022-02-01T00:00:00.000Z", true, &counts),
                      CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.cve_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);
    CYTADEL_ASSERT_EQ(counts.cpe_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.cpe_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT published, last_modified, description, cvss_v3_vector, "
                                         "cvss_v3_base_score, cvss_v3_severity, severity, source FROM cves "
                                         "WHERE cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    /* NVD's own timestamp lacked a trailing 'Z' -- db-schema.md's binding
     * convention requires the sync writer append one. */
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "2021-12-10T10:15:09.143Z");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "2021-12-14T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "Log4Shell");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3),
                          "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    CYTADEL_ASSERT(sqlite3_column_double(stmt, 4) == 10.0);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 5), "CRITICAL");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 6), 4); /* severity ordinal: score 10.0 -> Critical (4) */
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 7), "nvd");
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "SELECT severity FROM cves WHERE cve_id = ?;", -1, &stmt,
                                         NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2022-00001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 0), 2); /* score 5.0 -> Medium (2) */
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT part, vendor, product, version, version_end_including, "
                                         "vulnerable FROM cve_cpe_matches WHERE cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "a");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "apache");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "log4j");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3), "2.14.1");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 4), "2.15.0");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 5), 1);
    sqlite3_finalize(stmt);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state_nvd(handle, watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT_STREQ(watermark, "2022-02-01T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 2);

    cytadel_db_close(db);
}

static void test_missing_id_skipped_others_ingested(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    /* BAD: no "id" key at all. */
    add_element(root, wrap_element(new_cve_shell(NULL, "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z")));
    /* GOOD, before and after the bad one -- proves ordering-independence. */
    add_element(root, wrap_element(new_cve_shell("CVE-2024-10001", "2024-01-01T00:00:00.000Z",
                                                  "2024-01-02T00:00:00.000Z")));
    /* BAD: empty "id". */
    add_element(root,
                wrap_element(new_cve_shell("", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z")));
    add_element(root, wrap_element(new_cve_shell("CVE-2024-10002", "2024-01-01T00:00:00.000Z",
                                                  "2024-01-02T00:00:00.000Z")));

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.cve_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-10001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-10002"), 1);
    CYTADEL_ASSERT_EQ(count_all(handle, "cves"), 2);

    cytadel_db_close(db);
}

/* Proves that "cve is not an object" / "metrics is a string" / "descriptions
 * is a number" never abort the page and never take down a good neighboring
 * record. Per this module's own documented DESIGN CHOICE (see
 * nvd_ingest.c's top-of-file comment): "cve is not an object" IS a
 * whole-record skip (no id is recoverable at all); a wrong-typed
 * "metrics"/"descriptions" on an otherwise-valid record (valid id/
 * published/lastModified) instead degrades gracefully -- the record IS
 * ingested, with no CVSS data / an empty description respectively -- matching
 * this milestone's own field-by-field fallback spec ("descriptions ...
 * else ''"; "metrics ... preferred, else ..."). */
static void test_cve_not_object_and_wrong_type_fields(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();

    add_element(root, wrap_element(new_cve_shell("CVE-2024-20001", "2024-01-01T00:00:00.000Z",
                                                  "2024-01-02T00:00:00.000Z")));

    /* BAD: "cve" is a JSON string, not an object -- no id recoverable, must
     * be skipped whole. */
    {
        cJSON *elem = cJSON_CreateObject();
        cJSON_AddItemToObject(elem, "cve", cJSON_CreateString("not-an-object"));
        add_element(root, elem);
    }

    /* Record with a valid id/published/lastModified, but "metrics" is a
     * JSON string -- degrades to no CVSS data (severity 0), still
     * ingested. */
    {
        cJSON *cve = new_cve_shell("CVE-2024-20002", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
        cJSON_AddItemToObject(cve, "metrics", cJSON_CreateString("bogus"));
        add_element(root, wrap_element(cve));
    }

    /* Record with a valid id/published/lastModified, but "descriptions" is
     * a JSON number -- degrades to description = "", still ingested. */
    {
        cJSON *cve = new_cve_shell("CVE-2024-20003", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
        cJSON_AddItemToObject(cve, "descriptions", cJSON_CreateNumber(42));
        add_element(root, wrap_element(cve));
    }

    add_element(root, wrap_element(new_cve_shell("CVE-2024-20004", "2024-01-01T00:00:00.000Z",
                                                  "2024-01-02T00:00:00.000Z")));

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    /* Only the "cve not object" element lacked a recoverable id. */
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 1);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 4);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-20001"), 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-20004"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT description, cvss_v3_vector, severity FROM cves WHERE "
                                         "cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-20002", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "");
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 1) == SQLITE_NULL);
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 2), 0);
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "SELECT description FROM cves WHERE cve_id = ?;", -1, &stmt,
                                         NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-20003", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_oversized_description_clipped_not_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    size_t huge_len = CYTADEL_NVD_DESC_MAX_LEN + 1000;
    char *huge = malloc(huge_len + 1);
    CYTADEL_ASSERT(huge != NULL);
    memset(huge, 'A', huge_len);
    huge[huge_len] = '\0';

    cJSON *root = new_root();
    cJSON *cve = new_cve_shell("CVE-2024-30001", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
    add_description(cve, "en", huge);
    add_element(root, wrap_element(cve));
    free(huge);

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT LENGTH(description) FROM cves WHERE cve_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-30001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_EQ(sqlite3_column_int64(stmt, 0), CYTADEL_NVD_DESC_MAX_LEN);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_huge_cpe_match_array_capped(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    const size_t total_matches = CYTADEL_NVD_MAX_CPE_PER_CVE + 904;

    cJSON *root = new_root();
    cJSON *cve = new_cve_shell("CVE-2024-40001", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
    for (size_t i = 0; i < total_matches; i++) {
        char criteria[128];
        /* Distinct version per entry so no two rows collide on the
         * cve_cpe_matches UNIQUE index -- every entry that is actually
         * attempted (within the cap) must land as its own physical row. */
        snprintf(criteria, sizeof(criteria), "cpe:2.3:a:acme:widget:9.9.%zu:*:*:*:*:*:*:*", i);
        add_cpe_match(cve, criteria, NULL);
    }
    add_element(root, wrap_element(cve));

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1); /* the CVE itself is still ingested */
    CYTADEL_ASSERT_EQ(counts.cpe_ingested, CYTADEL_NVD_MAX_CPE_PER_CVE);
    CYTADEL_ASSERT_EQ(counts.cpe_skipped, total_matches - CYTADEL_NVD_MAX_CPE_PER_CVE);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cve_cpe_matches", "CVE-2024-40001"),
                      CYTADEL_NVD_MAX_CPE_PER_CVE);

    cytadel_db_close(db);
}

static void test_malformed_cpe_criteria_skipped_others_ingested(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    cJSON *cve = new_cve_shell("CVE-2024-50001", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
    /* GOOD: fully valid criteria. */
    add_cpe_match(cve, "cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", NULL);
    /* BAD: too few colon-delimited fields (missing product/version/...). */
    add_cpe_match(cve, "cpe:2.3:a:acme", NULL);
    /* BAD: invalid 'part' component ('z' is not a/o/h). */
    add_cpe_match(cve, "cpe:2.3:z:acme:widget:2.0:*:*:*:*:*:*:*", NULL);
    /* BAD: version='*' range row with no bound set at all (db-schema.md SS3). */
    add_cpe_match_full(cve, "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*", 1, NULL, NULL, NULL, NULL);
    /* GOOD: another fully valid criteria, after all the bad ones. */
    add_cpe_match(cve, "cpe:2.3:a:acme:gadget:3.0:*:*:*:*:*:*:*", NULL);
    add_element(root, wrap_element(cve));

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.cpe_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.cpe_skipped, 3);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cve_cpe_matches", "CVE-2024-50001"), 2);

    cytadel_db_close(db);
}

static void test_truncated_json_returns_parse_error_watermark_unchanged(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* Establish a known-good baseline via one real successful ingest. */
    cJSON *root = new_root();
    add_element(root, wrap_element(new_cve_shell("CVE-2024-60001", "2024-01-01T00:00:00.000Z",
                                                  "2024-01-02T00:00:00.000Z")));
    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-01-15T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    char baseline_watermark[64];
    char baseline_status[32];
    long long baseline_total_records = -1;
    get_sync_state_nvd(handle, baseline_watermark, sizeof(baseline_watermark), baseline_status,
                        sizeof(baseline_status), &baseline_total_records);
    long long baseline_cve_count = count_all(handle, "cves");
    CYTADEL_ASSERT_STREQ(baseline_watermark, "2024-01-15T00:00:00.000Z");
    CYTADEL_ASSERT_EQ(baseline_cve_count, 1);

    /* Now build a second, otherwise-valid page and truncate it mid-document
     * before handing it to the parser -- simulates a connection that died
     * mid-page-fetch. */
    root = new_root();
    add_element(root, wrap_element(new_cve_shell("CVE-2024-60002", "2024-02-01T00:00:00.000Z",
                                                  "2024-02-02T00:00:00.000Z")));
    json = print_and_delete(root);
    size_t full_len = strlen(json);
    size_t truncated_len = full_len / 2; /* cuts mid-structure -- never valid JSON */

    memset(&counts, 0xAA, sizeof(counts));
    cytadel_nvd_ingest_status_t status =
        cytadel_nvd_ingest_page(db, json, truncated_len, "2024-03-01T00:00:00.000Z", true, &counts);
    cJSON_free(json);

    CYTADEL_ASSERT_EQ(status, CYTADEL_NVD_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state_nvd(handle, watermark_after, sizeof(watermark_after), status_after,
                        sizeof(status_after), &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, baseline_watermark);
    CYTADEL_ASSERT_STREQ(status_after, baseline_status);
    CYTADEL_ASSERT_EQ(total_records_after, baseline_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "cves"), baseline_cve_count);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-60002"), 0);

    cytadel_db_close(db);
}

static void test_duplicate_cve_id_in_one_page(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root();
    cJSON *first = new_cve_shell("CVE-2024-70001", "2024-01-01T00:00:00.000Z", "2024-01-02T00:00:00.000Z");
    add_description(first, "en", "first description");
    add_element(root, wrap_element(first));

    cJSON *second = new_cve_shell("CVE-2024-70001", "2024-01-01T00:00:00.000Z", "2024-01-03T00:00:00.000Z");
    add_description(second, "en", "second description (should win)");
    add_element(root, wrap_element(second));

    char *json = print_and_delete(root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-02-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);

    /* Both attempts succeed at the DB layer (no crash); only one distinct
     * row exists afterward, with the second (later) upsert's fields
     * winning -- per the frozen ON CONFLICT DO UPDATE clause. */
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-70001"), 1);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT description, last_modified FROM cves WHERE cve_id = ?;", -1,
                                         &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2024-70001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "second description (should win)");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "2024-01-03T00:00:00.000Z");
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

/* Security-review W1 regression: a top-level "vulnerabilities" key that is
 * entirely MISSING must be rejected as ERR_PARSE (not silently treated as
 * an empty page) -- no transaction opened, sync_state untouched. */
static void test_missing_vulnerabilities_key_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    cJSON *root = cJSON_CreateObject();
    cJSON_AddItemToObject(root, "format", cJSON_CreateString("NVD_CVE"));
    char *json = print_and_delete(root);

    cytadel_nvd_ingest_counts_t counts;
    memset(&counts, 0xAA, sizeof(counts));
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-01-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_ERR_PARSE);
    cJSON_free(json);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);

    cytadel_db_close(db);
}

/* Security-review W1 regression (the exact case called out in the review):
 * {"vulnerabilities":"x"} -- valid JSON, but "vulnerabilities" is a string,
 * not an array -- must return ERR_PARSE, out_counts all zero, and
 * sync_state.last_mod_watermark must be UNCHANGED from a known seed value
 * (proving no transaction was opened and no window's real CVEs were
 * silently skipped). */
static void test_w1_present_non_array_vulnerabilities_returns_parse_error(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* Seed a known watermark via one real, successful, complete-window
     * ingest first. */
    cJSON *seed_root = new_root();
    add_element(seed_root, wrap_element(new_cve_shell("CVE-2024-90001", "2024-01-01T00:00:00.000Z",
                                                       "2024-01-02T00:00:00.000Z")));
    char *seed_json = print_and_delete(seed_root);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, seed_json, strlen(seed_json), "2024-01-15T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(seed_json);

    char seed_watermark[64];
    char seed_status[32];
    long long seed_total_records = -1;
    get_sync_state_nvd(handle, seed_watermark, sizeof(seed_watermark), seed_status, sizeof(seed_status),
                        &seed_total_records);
    CYTADEL_ASSERT_STREQ(seed_watermark, "2024-01-15T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(seed_status, "success");

    const char *page_json = "{\"vulnerabilities\":\"x\"}";
    memset(&counts, 0xAA, sizeof(counts));
    cytadel_nvd_ingest_status_t status = cytadel_nvd_ingest_page(
        db, page_json, strlen(page_json), "2024-03-01T00:00:00.000Z", true, &counts);

    CYTADEL_ASSERT_EQ(status, CYTADEL_NVD_INGEST_ERR_PARSE);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);
    CYTADEL_ASSERT_EQ(counts.cpe_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cpe_skipped, 0);

    char watermark_after[64];
    char status_after[32];
    long long total_records_after = -1;
    get_sync_state_nvd(handle, watermark_after, sizeof(watermark_after), status_after, sizeof(status_after),
                        &total_records_after);
    CYTADEL_ASSERT_STREQ(watermark_after, seed_watermark);
    CYTADEL_ASSERT_STREQ(status_after, seed_status);
    CYTADEL_ASSERT_EQ(total_records_after, seed_total_records);
    CYTADEL_ASSERT_EQ(count_all(handle, "cves"), 1); /* only the seed CVE -- nothing else was ever written */

    cytadel_db_close(db);
}

/* A present, actually-empty array ("vulnerabilities": []) must remain a
 * valid, legitimately-empty page (CYTADEL_NVD_INGEST_OK) -- proves the W1
 * fix did not overreach into rejecting the one genuinely valid "0 records"
 * shape. */
static void test_empty_vulnerabilities_array_is_valid_empty_page(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    cJSON *root = new_root(); /* "vulnerabilities": [] by default -- nothing added to it */
    char *json = print_and_delete(root);

    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json, strlen(json), "2024-01-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 0);

    char watermark[64];
    char status[32];
    long long total_records = -1;
    get_sync_state_nvd(handle, watermark, sizeof(watermark), status, sizeof(status), &total_records);
    CYTADEL_ASSERT_STREQ(watermark, "2024-01-01T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(status, "success");
    CYTADEL_ASSERT_EQ(total_records, 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "cves"), 0);

    cytadel_db_close(db);
}

/* Security-review W2 regression: a simulated 2-page window. Page 1 is
 * ingested with window_complete=false -- its CVE data must be present, but
 * the watermark must NOT have advanced and status must not be 'success'
 * (proving a crash right after this call, before the window's final page,
 * never advances the watermark past data that hasn't fully landed). Page 2
 * (window_complete=true) then advances the watermark and sets
 * status='success'. */
static void test_w2_window_complete_false_then_true(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    char initial_watermark[64];
    char initial_status[32];
    long long initial_total_records = -1;
    get_sync_state_nvd(handle, initial_watermark, sizeof(initial_watermark), initial_status,
                        sizeof(initial_status), &initial_total_records);
    CYTADEL_ASSERT_STREQ(initial_watermark, ""); /* NULL watermark on a freshly migrated DB */
    CYTADEL_ASSERT_STREQ(initial_status, "idle");
    CYTADEL_ASSERT_EQ(initial_total_records, 0);

    /* Page 1 of 2: window_complete = false. */
    cJSON *root1 = new_root();
    add_element(root1, wrap_element(new_cve_shell("CVE-2024-95001", "2024-01-01T00:00:00.000Z",
                                                   "2024-01-02T00:00:00.000Z")));
    char *json1 = print_and_delete(root1);
    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json1, strlen(json1), "2024-05-01T00:00:00.000Z", false, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json1);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);

    /* Page 1's CVE data IS present ... */
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-95001"), 1);

    /* ... but the watermark must be exactly where it was before the window
     * started, and status must not be 'success' yet -- this is the
     * "simulated mid-window crash" assertion: if the process died right
     * here, the next run's watermark read would still correctly say "this
     * window never completed". */
    char watermark_mid[64];
    char status_mid[32];
    long long total_records_mid = -1;
    get_sync_state_nvd(handle, watermark_mid, sizeof(watermark_mid), status_mid, sizeof(status_mid),
                        &total_records_mid);
    CYTADEL_ASSERT_STREQ(watermark_mid, initial_watermark);
    CYTADEL_ASSERT(strcmp(status_mid, "success") != 0);
    CYTADEL_ASSERT_STREQ(status_mid, "running");
    CYTADEL_ASSERT_EQ(total_records_mid, 1); /* still accumulated -- this file's documented choice */

    /* Page 2 of 2 (the final page): window_complete = true. */
    cJSON *root2 = new_root();
    add_element(root2, wrap_element(new_cve_shell("CVE-2024-95002", "2024-01-01T00:00:00.000Z",
                                                   "2024-01-02T00:00:00.000Z")));
    char *json2 = print_and_delete(root2);
    CYTADEL_ASSERT_EQ(
        cytadel_nvd_ingest_page(db, json2, strlen(json2), "2024-05-01T00:00:00.000Z", true, &counts),
        CYTADEL_NVD_INGEST_OK);
    cJSON_free(json2);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-95002"), 1);

    char watermark_final[64];
    char status_final[32];
    long long total_records_final = -1;
    get_sync_state_nvd(handle, watermark_final, sizeof(watermark_final), status_final, sizeof(status_final),
                        &total_records_final);
    CYTADEL_ASSERT_STREQ(watermark_final, "2024-05-01T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(status_final, "success");
    CYTADEL_ASSERT_EQ(total_records_final, 2);

    cytadel_db_close(db);
}

/* Security-review W3 regression: cJSON decodes a JSON string's
 * null-character escape sequence (the standard JSON way of encoding code
 * point U+0000 inside a string) into a genuine embedded NUL byte inside
 * valuestring. Two crafted ids share the identical VISIBLE prefix "CVE-X"
 * (strlen()==5) but differ in the bytes hidden after their own embedded
 * NUL -- proving neither one is ever stored (so they can never collide on
 * the cves.cve_id PRIMARY KEY), while a genuinely valid CVE placed between
 * them is still ingested (ordering-independence, same as every other
 * skip-and-log test in this file). Built as a raw JSON string literal (not
 * the cJSON fixture builders above) so that escape sequence reaches
 * cJSON_ParseWithLength() literally, exactly as it would over the wire.
 *
 * Source-code note: the six-character escape sequence (backslash, the
 * letter u, then four zero digits) appears in the C string literal below
 * with its leading backslash doubled. That doubling is required: an
 * UNDOUBLED backslash immediately followed by u and four hex digits is
 * itself a C11 universal-character-name escape, and one that spells out
 * code point zero is a constraint violation this project's -Wpedantic
 * -Werror build would reject at compile time. Doubling the backslash
 * makes the C compiler treat it as an ordinary escaped backslash followed
 * by five ordinary characters, so the six bytes reach the *runtime*
 * string unchanged -- which is what must appear in the wire-format JSON
 * text for cJSON's own parser to decode at ingest time, not compile
 * time. */
static void test_w3_embedded_nul_cve_id_rejected(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    const char *page_json =
        "{\"format\":\"NVD_CVE\",\"vulnerabilities\":["
        "{\"cve\":{\"id\":\"CVE-X\\u0000A\",\"published\":\"2024-01-01T00:00:00.000Z\","
        "\"lastModified\":\"2024-01-02T00:00:00.000Z\"}},"
        "{\"cve\":{\"id\":\"CVE-2024-80001\",\"published\":\"2024-01-01T00:00:00.000Z\","
        "\"lastModified\":\"2024-01-02T00:00:00.000Z\"}},"
        "{\"cve\":{\"id\":\"CVE-X\\u0000B\",\"published\":\"2024-01-01T00:00:00.000Z\","
        "\"lastModified\":\"2024-01-02T00:00:00.000Z\"}}"
        "]}";

    cytadel_nvd_ingest_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_nvd_ingest_page(db, page_json, strlen(page_json), "2024-02-01T00:00:00.000Z",
                                               true, &counts),
                      CYTADEL_NVD_INGEST_OK);

    /* Both embedded-NUL ids are skipped; only the genuinely valid CVE
     * between them is ingested. */
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);
    CYTADEL_ASSERT_EQ(counts.cve_skipped, 2);
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-2024-80001"), 1);
    /* Neither crafted id, nor a merged row keyed by their shared visible
     * prefix, was ever stored -- proving the PK-collision hole is closed. */
    CYTADEL_ASSERT_EQ(count_where_cve_id(handle, "cves", "CVE-X"), 0);
    CYTADEL_ASSERT_EQ(count_all(handle, "cves"), 1);

    cytadel_db_close(db);
}

static void test_status_to_string_never_null(void) {
    CYTADEL_ASSERT(cytadel_nvd_ingest_status_to_string(CYTADEL_NVD_INGEST_OK) != NULL);
    CYTADEL_ASSERT(cytadel_nvd_ingest_status_to_string(CYTADEL_NVD_INGEST_ERR_INVALID_ARG) != NULL);
    CYTADEL_ASSERT(cytadel_nvd_ingest_status_to_string(CYTADEL_NVD_INGEST_ERR_PARSE) != NULL);
    CYTADEL_ASSERT(cytadel_nvd_ingest_status_to_string(CYTADEL_NVD_INGEST_ERR_DB) != NULL);
    CYTADEL_ASSERT(cytadel_nvd_ingest_status_to_string((cytadel_nvd_ingest_status_t)999) != NULL);
}

int main(void) {
    test_invalid_args();
    test_happy_path_two_cves_with_cvss_and_cpe();
    test_missing_id_skipped_others_ingested();
    test_cve_not_object_and_wrong_type_fields();
    test_oversized_description_clipped_not_rejected();
    test_huge_cpe_match_array_capped();
    test_malformed_cpe_criteria_skipped_others_ingested();
    test_truncated_json_returns_parse_error_watermark_unchanged();
    test_duplicate_cve_id_in_one_page();
    test_missing_vulnerabilities_key_returns_parse_error();
    test_w1_present_non_array_vulnerabilities_returns_parse_error();
    test_empty_vulnerabilities_array_is_valid_empty_page();
    test_w2_window_complete_false_then_true();
    test_w3_embedded_nul_cve_id_rejected();
    test_status_to_string_never_null();

    CYTADEL_TEST_PASS();
}
