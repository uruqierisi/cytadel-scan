#include "cytadel/db/db.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "cytadel_test.h"

/* Milestone 7 slice 1: docs/contracts/db-schema.md (FROZEN CONTRACT), the
 * vertical DB foundation. This test links cytadel_sqlite3 directly (in
 * addition to `cytadel`) so it can drive its own sqlite3_prepare_v2()/bind/
 * step calls against cytadel_db_handle()'s raw connection -- exactly the
 * pattern later milestones' own query code (db-schema.md SS9) will follow,
 * matching test_tls_inspect.c/test_plugin_lua_embed.c's convention of
 * linking a third-party dependency explicitly when the test itself calls
 * into that library's C API directly rather than only through this
 * project's own wrapper. */

static cytadel_db_t *open_migrated_memory_db(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    return db;
}

static void test_migrate_reaches_latest_version(void) {
    /* M8 report slice 2: migration 3 (scans.malformed_data_count, db-schema.md
     * SS6 amendment authorized 2026-07-22) was added after v2 -- cytadel_db_
     * migrate() on a brand-new connection now runs ALL THREE migrations and
     * lands at version 3, not 2. */
    cytadel_db_t *db = open_migrated_memory_db();

    int version = -1;
    CYTADEL_ASSERT_EQ(cytadel_db_schema_version(db, &version), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(version, 3);

    cytadel_db_close(db);
}

static void test_schema_version_before_any_migration_is_zero(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);

    int version = -1;
    CYTADEL_ASSERT_EQ(cytadel_db_schema_version(db, &version), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(version, 0);

    cytadel_db_close(db);
}

/* Counts sqlite_master rows of a given `type` ('table' or 'index') whose
 * `name` matches exactly -- a small helper so every existence assertion
 * below reads as a single line. */
static int count_sqlite_master(sqlite3 *handle, const char *type, const char *name) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM sqlite_master WHERE type = ? AND name = ?;",
                                 -1, &stmt, NULL);
    CYTADEL_ASSERT_EQ(rc, SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, type, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, name, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    int count = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return count;
}

static void test_all_eight_tables_exist(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    CYTADEL_ASSERT(handle != NULL);

    static const char *const tables[] = {
        "schema_migrations", "cves", "cve_cpe_matches", "kev",
        "epss",              "scans", "scan_results",    "sync_state",
    };
    for (size_t i = 0; i < sizeof(tables) / sizeof(tables[0]); i++) {
        CYTADEL_ASSERT_EQ(count_sqlite_master(handle, "table", tables[i]), 1);
    }

    cytadel_db_close(db);
}

static void test_representative_indexes_exist(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* One representative named index per indexed table (db-schema.md
     * SS2/SS3/SS6/SS7) -- not exhaustive, but covers every table that has
     * any named index at all (kev/epss/sync_state are WITHOUT ROWID,
     * PK-only access, and have none by design). */
    static const char *const indexes[] = {
        "idx_cves_last_modified",   "idx_cves_severity",       "idx_cpe_vendor_product",
        "idx_cpe_product",          "idx_cpe_cve_id",          "idx_scans_started_at",
        "idx_scan_results_scan_id", "idx_scan_results_host_port",
        "idx_scan_results_severity", "idx_scan_results_cve_id",
    };
    for (size_t i = 0; i < sizeof(indexes) / sizeof(indexes[0]); i++) {
        CYTADEL_ASSERT_EQ(count_sqlite_master(handle, "index", indexes[i]), 1);
    }

    cytadel_db_close(db);
}

static void test_migrate_is_idempotent(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    int rows_before = -1;
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM schema_migrations;", -1, &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        rows_before = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
    }

    /* Second run: must apply nothing and leave the version (and the
     * schema_migrations row count) exactly as it was. */
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);

    int version_after = -1;
    CYTADEL_ASSERT_EQ(cytadel_db_schema_version(db, &version_after), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(version_after, 3);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM schema_migrations;", -1, &stmt, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    int rows_after = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(rows_after, rows_before);
    CYTADEL_ASSERT_EQ(rows_after, 3); /* migrations 1, 2, AND 3, each its own row */

    cytadel_db_close(db);
}

/* CPE-matching-caller slice: migration 2 (docs/contracts/db-schema.md SS7
 * amendment, authorized 2026-07-22) adds scan_results.match_status. This
 * proves, against a real migrated connection, all three of: (a) the column
 * exists and is readable via PRAGMA table_info, (b) its CHECK constraint
 * rejects a 4th value, and (c) an INSERT that omits match_status entirely
 * gets the documented 'confirmed' default -- exactly the v1->2 assertion
 * this slice's task brief asked for, alongside the still-passing v0->1/
 * 8-table assertions above (unchanged by this migration). */
static void test_match_status_column_migration_v2(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* (a) column exists. */
    bool found_match_status = false;
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "PRAGMA table_info(scan_results);", -1, &stmt, NULL),
                          SQLITE_OK);
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *col_name = (const char *)sqlite3_column_text(stmt, 1);
            if (col_name != NULL && strcmp(col_name, "match_status") == 0) {
                found_match_status = true;
            }
        }
        CYTADEL_ASSERT_EQ(rc, SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    CYTADEL_ASSERT(found_match_status);

    /* Common insert prefix, minus match_status, used by both (b) and (c)
     * below. Needs a real scans/cves row first to satisfy the FKs. */
    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "INSERT INTO scans (started_at, target_spec, authorized_by, "
                     "authorization_confirmed_at, authorization_method, status) VALUES "
                     "('2026-01-01T00:00:00.000Z', 'x', 'op', '2026-01-01T00:00:00.000Z', 'flag', "
                     "'running');",
                     NULL, NULL, NULL),
        SQLITE_OK);

    /* (b) CHECK rejects a 4th value. */
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle,
                                "INSERT INTO scan_results (scan_id, host, port, plugin_id, severity, "
                                "evidence, detected_at, match_status) VALUES "
                                "(1, 'h', 80, 'p', 0, 'e', '2026-01-01T00:00:00.000Z', ?);",
                                -1, &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "bogus_status", -1, SQLITE_STATIC), SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_CONSTRAINT);
        sqlite3_finalize(stmt);
    }

    /* (c) omitting match_status entirely defaults to 'confirmed'. */
    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "INSERT INTO scan_results (scan_id, host, port, plugin_id, severity, evidence, "
                     "detected_at) VALUES (1, 'h', 80, 'p', 0, 'e', '2026-01-01T00:00:00.000Z');",
                     NULL, NULL, NULL),
        SQLITE_OK);
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle, "SELECT match_status FROM scan_results WHERE scan_id = 1;", -1,
                                &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "confirmed");
        sqlite3_finalize(stmt);
    }

    cytadel_db_close(db);
}

/* M8 report slice 2: migration 3 (docs/contracts/db-schema.md SS6 amendment,
 * authorized 2026-07-22) adds scans.malformed_data_count. This proves,
 * against a real migrated connection, all of: (a) the column exists and is
 * readable via PRAGMA table_info, (b) it defaults to 0 for a brand-new scans
 * row inserted WITHOUT naming the column at all (the exact SS9 "Scan
 * authorization + creation" INSERT shape, unmodified by this migration), and
 * (c) it round-trips a non-default value through a direct UPDATE. */
static void test_malformed_data_count_column_migration_v3(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* (a) column exists. */
    bool found_malformed_data_count = false;
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "PRAGMA table_info(scans);", -1, &stmt, NULL),
                          SQLITE_OK);
        int rc;
        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
            const char *col_name = (const char *)sqlite3_column_text(stmt, 1);
            if (col_name != NULL && strcmp(col_name, "malformed_data_count") == 0) {
                found_malformed_data_count = true;
            }
        }
        CYTADEL_ASSERT_EQ(rc, SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    CYTADEL_ASSERT(found_malformed_data_count);

    /* (b) SS9's own "Scan authorization + creation" INSERT shape, naming
     * every OTHER column but never malformed_data_count -- must default to
     * 0, exactly as db-schema.md's own amended §9 note says this migration
     * leaves that INSERT unchanged. */
    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "INSERT INTO scans (started_at, target_spec, authorized_by, "
                     "authorization_confirmed_at, authorization_method, status) VALUES "
                     "('2026-01-01T00:00:00.000Z', 'x', 'op', '2026-01-01T00:00:00.000Z', 'flag', "
                     "'running');",
                     NULL, NULL, NULL),
        SQLITE_OK);
    long long scan_id = sqlite3_last_insert_rowid(handle);
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle, "SELECT malformed_data_count FROM scans WHERE scan_id = ?;", -1,
                                &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 0), 0);
        sqlite3_finalize(stmt);
    }

    /* (c) round-trips a non-default value. */
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle, "UPDATE scans SET malformed_data_count = ? WHERE scan_id = ?;", -1,
                                &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 1, 7), SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 2, scan_id), SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
    }
    {
        sqlite3_stmt *stmt = NULL;
        CYTADEL_ASSERT_EQ(
            sqlite3_prepare_v2(handle, "SELECT malformed_data_count FROM scans WHERE scan_id = ?;", -1,
                                &stmt, NULL),
            SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
        CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
        CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 0), 7);
        sqlite3_finalize(stmt);
    }

    cytadel_db_close(db);
}

static void test_foreign_keys_are_enforced(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* kev.cve_id REFERENCES cves(cve_id) ON DELETE CASCADE -- inserting a
     * kev row for a CVE ID that does not exist in `cves` must fail with
     * SQLITE_CONSTRAINT (foreign key), proving PRAGMA foreign_keys=ON is
     * actually in effect for this connection (it silently no-ops the FK
     * entirely when off, which would let this exact insert succeed). */
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO kev (cve_id, date_added, vendor_project, product, "
                            "vulnerability_name, synced_at) VALUES (?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2099-00001", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, "2026-01-01", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, "acme", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 4, "widget", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 5, "Widget RCE", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 6, "2026-01-01T00:00:00.000Z", -1, SQLITE_STATIC),
                      SQLITE_OK);

    int rc = sqlite3_step(stmt);
    CYTADEL_ASSERT_EQ(rc, SQLITE_CONSTRAINT);
    sqlite3_finalize(stmt);

    /* And the same for epss.cve_id, same FK reasoning. */
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "INSERT INTO epss (cve_id, epss_score, percentile, score_date, "
                                         "synced_at) VALUES (?, ?, ?, ?, ?);",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2099-00002", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_double(stmt, 2, 0.5), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_double(stmt, 3, 0.9), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 4, "2026-01-01", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 5, "2026-01-01T00:00:00.000Z", -1, SQLITE_STATIC),
                      SQLITE_OK);
    rc = sqlite3_step(stmt);
    CYTADEL_ASSERT_EQ(rc, SQLITE_CONSTRAINT);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_cves_parameterized_insert_round_trip(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* db-schema.md SS9's "CVE upsert" pattern, minus the ON CONFLICT clause
     * (a plain first insert here) -- every value bound, nothing string-
     * concatenated. */
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cves (cve_id, published, last_modified, description, "
                            "cvss_v3_vector, cvss_v3_base_score, cvss_v3_severity, severity, source, "
                            "ingested_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, "2021-12-10T10:15:09.143Z", -1, SQLITE_STATIC),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, "2021-12-14T00:00:00.000Z", -1, SQLITE_STATIC),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 4, "Log4Shell", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(
        sqlite3_bind_text(stmt, 5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", -1, SQLITE_STATIC),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_double(stmt, 6, 10.0), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 7, "CRITICAL", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 8, 4), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 9, "nvd", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 10, "2026-01-01T00:00:00.000Z", -1, SQLITE_STATIC),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);

    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "SELECT published, description, cvss_v3_base_score, cvss_v3_severity, "
                            "severity, source FROM cves WHERE cve_id = ?;",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, "CVE-2021-44228", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);

    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "2021-12-10T10:15:09.143Z");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 1), "Log4Shell");
    CYTADEL_ASSERT(sqlite3_column_double(stmt, 2) == 10.0);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3), "CRITICAL");
    CYTADEL_ASSERT_EQ(sqlite3_column_int(stmt, 4), 4);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 5), "nvd");

    sqlite3_finalize(stmt);
    cytadel_db_close(db);
}

static void test_open_rejects_invalid_args(void) {
    cytadel_db_t *db = (cytadel_db_t *)0x1; /* poison to ensure open() resets it on rejection */
    CYTADEL_ASSERT_EQ(cytadel_db_open(NULL, &db), CYTADEL_DB_ERR_INVALID_ARG);
    CYTADEL_ASSERT(db == NULL);

    db = (cytadel_db_t *)0x1;
    CYTADEL_ASSERT_EQ(cytadel_db_open("", &db), CYTADEL_DB_ERR_INVALID_ARG);
    CYTADEL_ASSERT(db == NULL);

    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", NULL), CYTADEL_DB_ERR_INVALID_ARG);
}

static void test_close_null_is_safe(void) {
    cytadel_db_close(NULL); /* must not crash */
}

int main(void) {
    test_migrate_reaches_latest_version();
    test_schema_version_before_any_migration_is_zero();
    test_all_eight_tables_exist();
    test_representative_indexes_exist();
    test_migrate_is_idempotent();
    test_foreign_keys_are_enforced();
    test_cves_parameterized_insert_round_trip();
    test_match_status_column_migration_v2();
    test_malformed_data_count_column_migration_v3();
    test_open_rejects_invalid_args();
    test_close_null_is_safe();

    CYTADEL_TEST_PASS();
}
