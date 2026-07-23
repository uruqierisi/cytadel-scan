#include "db_migrations.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "log.h"

/* Migration version 1: the full frozen schema, docs/contracts/db-schema.md
 * SS1-SS8 reproduced verbatim (every CHECK constraint, FK, UNIQUE, and
 * named index) -- this is the FROZEN CONTRACT; do not edit this string to
 * "fix" or "improve" anything here without a stop-and-ask per project policy.
 *
 * schema_migrations itself is deliberately NOT created by this script --
 * see cytadel_db_migrations_current_version() below, which creates it
 * unconditionally (CREATE TABLE IF NOT EXISTS) before any version can even
 * be checked. This script only creates the 7 tables db-schema.md SS2-SS8
 * describe plus their indexes and sync_state's 3 seed rows; the migration
 * runner records THIS script having been applied via its own parameterized
 * INSERT INTO schema_migrations, identical in shape for every future
 * migration version (see cytadel_db_migrations_run() below).
 *
 * Expressed as an array of separate per-table statement-group strings (one
 * array element per table, each element itself a semicolon-separated
 * "CREATE TABLE ... ; CREATE INDEX ...;" batch executed via one
 * sqlite3_exec() call) rather than one single giant concatenated string
 * literal: adjacent-string-literal concatenation still produces one string
 * *object*, and the full schema comfortably exceeds the 4095-byte string
 * length ISO C99 compilers are only required to support
 * (-Wpedantic/-Werror correctly rejects a longer single literal). Splitting
 * per table keeps every individual literal small while changing nothing
 * about *what* SQL runs -- none of this batch embeds any external or
 * user-controlled value, so this is not the "string-concatenation of
 * untrusted values" this project's parameterized-queries rule forbids; it
 * is fixed schema text, identical to a migration file in any other
 * migration tool. */
static const char *const CYTADEL_DB_MIGRATION_1_STATEMENTS[] = {
    /* db-schema.md SS2: cves */
    "CREATE TABLE cves ("
    "    cve_id             TEXT    NOT NULL PRIMARY KEY,"
    "    published          TEXT    NOT NULL,"
    "    last_modified      TEXT    NOT NULL,"
    "    description        TEXT    NOT NULL DEFAULT '',"
    "    cvss_v3_vector     TEXT,"
    "    cvss_v3_base_score REAL    CHECK (cvss_v3_base_score IS NULL"
    "                                      OR (cvss_v3_base_score >= 0.0 AND cvss_v3_base_score <= 10.0)),"
    "    cvss_v3_severity   TEXT    CHECK (cvss_v3_severity IS NULL"
    "                                      OR cvss_v3_severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),"
    "    cvss_v2_vector     TEXT,"
    "    cvss_v2_base_score REAL    CHECK (cvss_v2_base_score IS NULL"
    "                                      OR (cvss_v2_base_score >= 0.0 AND cvss_v2_base_score <= 10.0)),"
    "    cvss_v2_severity   TEXT    CHECK (cvss_v2_severity IS NULL"
    "                                      OR cvss_v2_severity IN ('LOW','MEDIUM','HIGH')),"
    "    severity           INTEGER NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 4),"
    "    source             TEXT    NOT NULL DEFAULT 'nvd',"
    "    ingested_at        TEXT    NOT NULL"
    ");"
    "CREATE INDEX idx_cves_last_modified ON cves (last_modified);"
    "CREATE INDEX idx_cves_severity      ON cves (severity);",

    /* db-schema.md SS3: cve_cpe_matches */
    "CREATE TABLE cve_cpe_matches ("
    "    id                      INTEGER NOT NULL PRIMARY KEY,"
    "    cve_id                  TEXT    NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,"
    "    cpe23_uri                TEXT    NOT NULL,"
    "    part                     TEXT    NOT NULL DEFAULT 'a' CHECK (part IN ('a','o','h')),"
    "    vendor                   TEXT    NOT NULL,"
    "    product                  TEXT    NOT NULL,"
    "    version                  TEXT    NOT NULL DEFAULT '*',"
    "    version_start_including   TEXT    NOT NULL DEFAULT '',"
    "    version_start_excluding   TEXT    NOT NULL DEFAULT '',"
    "    version_end_including     TEXT    NOT NULL DEFAULT '',"
    "    version_end_excluding     TEXT    NOT NULL DEFAULT '',"
    "    vulnerable                INTEGER NOT NULL DEFAULT 1 CHECK (vulnerable IN (0,1)),"
    "    UNIQUE (cve_id, cpe23_uri, version_start_including, version_start_excluding,"
    "            version_end_including, version_end_excluding, vulnerable)"
    ");"
    "CREATE INDEX idx_cpe_vendor_product ON cve_cpe_matches (vendor, product);"
    "CREATE INDEX idx_cpe_product        ON cve_cpe_matches (product);"
    "CREATE INDEX idx_cpe_cve_id         ON cve_cpe_matches (cve_id);",

    /* db-schema.md SS4: kev */
    "CREATE TABLE kev ("
    "    cve_id            TEXT    NOT NULL PRIMARY KEY REFERENCES cves (cve_id) ON DELETE CASCADE,"
    "    date_added         TEXT    NOT NULL,"
    "    vendor_project      TEXT    NOT NULL,"
    "    product             TEXT    NOT NULL,"
    "    vulnerability_name   TEXT    NOT NULL,"
    "    required_action      TEXT,"
    "    due_date             TEXT,"
    "    known_ransomware     INTEGER NOT NULL DEFAULT 0 CHECK (known_ransomware IN (0,1)),"
    "    notes                TEXT,"
    "    synced_at            TEXT    NOT NULL"
    ") WITHOUT ROWID;",

    /* db-schema.md SS5: epss */
    "CREATE TABLE epss ("
    "    cve_id     TEXT    NOT NULL PRIMARY KEY REFERENCES cves (cve_id) ON DELETE CASCADE,"
    "    epss_score REAL    NOT NULL CHECK (epss_score  >= 0.0 AND epss_score  <= 1.0),"
    "    percentile REAL    NOT NULL CHECK (percentile  >= 0.0 AND percentile  <= 1.0),"
    "    score_date TEXT    NOT NULL,"
    "    synced_at  TEXT    NOT NULL"
    ") WITHOUT ROWID;",

    /* db-schema.md SS6: scans */
    "CREATE TABLE scans ("
    "    scan_id                     INTEGER NOT NULL PRIMARY KEY,"
    "    started_at                   TEXT    NOT NULL,"
    "    finished_at                  TEXT,"
    "    target_spec                  TEXT    NOT NULL,"
    "    authorized_by                 TEXT    NOT NULL,"
    "    authorization_confirmed_at     TEXT    NOT NULL,"
    "    authorization_method           TEXT    NOT NULL"
    "                                   CHECK (authorization_method IN ('interactive','flag')),"
    "    status                       TEXT    NOT NULL DEFAULT 'running'"
    "                                   CHECK (status IN ('running','completed','aborted','failed')),"
    "    notes                        TEXT"
    ");"
    "CREATE INDEX idx_scans_started_at ON scans (started_at DESC);",

    /* db-schema.md SS7: scan_results */
    "CREATE TABLE scan_results ("
    "    id             INTEGER NOT NULL PRIMARY KEY,"
    "    scan_id         INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,"
    "    host            TEXT    NOT NULL,"
    "    port            INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),"
    "    service         TEXT,"
    "    plugin_id       TEXT    NOT NULL,"
    "    cve_id          TEXT    REFERENCES cves (cve_id) ON DELETE SET NULL,"
    "    severity        INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 4),"
    "    evidence        TEXT    NOT NULL,"
    "    remediation     TEXT,"
    "    kev_flag        INTEGER NOT NULL DEFAULT 0 CHECK (kev_flag IN (0,1)),"
    "    epss_score      REAL    CHECK (epss_score IS NULL OR (epss_score >= 0.0 AND epss_score <= 1.0)),"
    "    detected_at     TEXT    NOT NULL"
    ");"
    "CREATE INDEX idx_scan_results_scan_id   ON scan_results (scan_id);"
    "CREATE INDEX idx_scan_results_host_port ON scan_results (scan_id, host, port);"
    "CREATE INDEX idx_scan_results_severity  ON scan_results (scan_id, severity DESC);"
    "CREATE INDEX idx_scan_results_cve_id    ON scan_results (cve_id) WHERE cve_id IS NOT NULL;",

    /* db-schema.md SS8: sync_state (+ its 3 seed rows) */
    "CREATE TABLE sync_state ("
    "    feed                 TEXT    NOT NULL PRIMARY KEY CHECK (feed IN ('nvd','kev','epss')),"
    "    last_sync_started      TEXT,"
    "    last_sync_completed     TEXT,"
    "    last_mod_watermark      TEXT,"
    "    total_records          INTEGER NOT NULL DEFAULT 0,"
    "    status                 TEXT    NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','running','success','error')),"
    "    last_error             TEXT"
    ") WITHOUT ROWID;"
    "INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('nvd', 'idle', 0);"
    "INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('kev', 'idle', 0);"
    "INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('epss', 'idle', 0);",
};
#define CYTADEL_DB_MIGRATION_1_STATEMENT_COUNT \
    (sizeof(CYTADEL_DB_MIGRATION_1_STATEMENTS) / sizeof(CYTADEL_DB_MIGRATION_1_STATEMENTS[0]))

typedef struct {
    int version;
    const char *description; /* stored verbatim in schema_migrations.description */
    const char *const *statements; /* array of independent, non-parameterized DDL/DML
                                     * statements (see CYTADEL_DB_MIGRATION_1_STATEMENTS's
                                     * header comment for why this is an array of strings
                                     * rather than one concatenated literal), each run via
                                     * its own sqlite3_exec() call. */
    size_t statement_count;
} cytadel_db_migration_t;

/* db-schema.md SS1's own illustrative INSERT uses this exact description
 * string for version 1 -- reproduced verbatim here so the recorded
 * schema_migrations row matches the contract byte-for-byte. */
/* Migration version 2: scan_results gains a match-verdict column
 * (docs/contracts/db-schema.md SS7, amended -- authorized 2026-07-22, the
 * M7 CPE-matching-caller slice; see that section's own "added migration v2"
 * note). Append-only: v1 above stays byte-for-byte the frozen M0 schema; this
 * is a SEPARATE migration step, never an edit to CYTADEL_DB_MIGRATION_1_STATEMENTS.
 *
 * ALTER TABLE ... ADD COLUMN is used rather than a rebuild-the-table dance
 * (SQLite has no native "ALTER COLUMN") because this is a pure column
 * addition: a NOT NULL column with a constant DEFAULT and a CHECK that only
 * references the new column itself -- exactly the shape SQLite's ADD COLUMN
 * supports directly (no PRIMARY KEY/UNIQUE, no non-constant default, no
 * cross-column CHECK). Every pre-existing scan_results row backfills to
 * 'confirmed' (SQLite's row-store-time / lazy-materialization is irrelevant
 * here; there ARE no pre-existing rows in freshly-migrated v1 tables at the
 * moment this ever runs, since scan_results was never written to by any
 * caller prior to this slice). */
static const char *const CYTADEL_DB_MIGRATION_2_STATEMENTS[] = {
    "ALTER TABLE scan_results ADD COLUMN match_status TEXT NOT NULL DEFAULT 'confirmed' "
    "CHECK (match_status IN ('confirmed','undetermined','not_affected'));",
};
#define CYTADEL_DB_MIGRATION_2_STATEMENT_COUNT \
    (sizeof(CYTADEL_DB_MIGRATION_2_STATEMENTS) / sizeof(CYTADEL_DB_MIGRATION_2_STATEMENTS[0]))

/* Migration version 3: scans gains a durable malformed-data-quality counter
 * (docs/contracts/db-schema.md SS6, amended -- authorized 2026-07-22, the M8
 * report-slice-2 "durable MALFORMED-data surface" work; see that section's
 * own "added migration v3" note). Append-only, exactly like v2 above: v1 and
 * v2 stay byte-for-byte unchanged; this is a SEPARATE migration step, never
 * an edit to either CYTADEL_DB_MIGRATION_1_STATEMENTS or
 * CYTADEL_DB_MIGRATION_2_STATEMENTS.
 *
 * `DEFAULT 0` is honest here (unlike match_status, which deliberately has no
 * default because every real match_status value must be an explicit
 * caller decision) -- this is a plain COUNT column, and 0 genuinely means "no
 * malformed cve_cpe_matches row was ever seen for this scan", which is the
 * correct value for every scan that predates this column (backfilled by
 * SQLite's ADD COLUMN ... DEFAULT) and for any brand-new scan that simply
 * never triggers a data-quality event. */
static const char *const CYTADEL_DB_MIGRATION_3_STATEMENTS[] = {
    "ALTER TABLE scans ADD COLUMN malformed_data_count INTEGER NOT NULL DEFAULT 0;",
};
#define CYTADEL_DB_MIGRATION_3_STATEMENT_COUNT \
    (sizeof(CYTADEL_DB_MIGRATION_3_STATEMENTS) / sizeof(CYTADEL_DB_MIGRATION_3_STATEMENTS[0]))

static const cytadel_db_migration_t CYTADEL_DB_MIGRATIONS[] = {
    {1,
     "Initial frozen schema: cves, cve_cpe_matches, kev, epss, scans, scan_results, sync_state",
     CYTADEL_DB_MIGRATION_1_STATEMENTS, CYTADEL_DB_MIGRATION_1_STATEMENT_COUNT},
    {2,
     "Add scan_results.match_status (CPE-match caller verdict: confirmed/undetermined/not_affected)",
     CYTADEL_DB_MIGRATION_2_STATEMENTS, CYTADEL_DB_MIGRATION_2_STATEMENT_COUNT},
    {3,
     "Add scans.malformed_data_count (durable MALFORMED_ROW data-quality counter, M8 report slice 2)",
     CYTADEL_DB_MIGRATION_3_STATEMENTS, CYTADEL_DB_MIGRATION_3_STATEMENT_COUNT},
};
#define CYTADEL_DB_MIGRATION_COUNT (sizeof(CYTADEL_DB_MIGRATIONS) / sizeof(CYTADEL_DB_MIGRATIONS[0]))

/* db-schema.md SS1's own DDL for this bookkeeping table, run unconditionally
 * (IF NOT EXISTS) every time the current version needs to be known -- this
 * is what lets cytadel_db_schema_version()/cytadel_db_migrate() both be
 * called safely against a brand-new, never-migrated connection. */
static const char CYTADEL_DB_SCHEMA_MIGRATIONS_DDL[] =
    "CREATE TABLE IF NOT EXISTS schema_migrations ("
    "    version     INTEGER NOT NULL PRIMARY KEY,"
    "    description TEXT    NOT NULL,"
    "    applied_at  TEXT    NOT NULL"
    ") WITHOUT ROWID;";

/* Runs `sql` (a fixed, non-parameterized DDL/DML batch -- never a value
 * built from external input) via sqlite3_exec(). On failure, logs the
 * sqlite3 error text and frees the error-message buffer sqlite3_exec()
 * allocates for it (sqlite3_exec() only ever writes into *errmsg on
 * failure, and the caller must sqlite3_free() it -- never plain free()). */
static int cytadel_db_exec(sqlite3 *handle, const char *sql, const char *context) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: %s failed (sqlite rc=%d): %s", context, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

cytadel_db_status_t cytadel_db_migrations_current_version(sqlite3 *handle, int *out_version) {
    if (handle == NULL || out_version == NULL) {
        cytadel_log_error("db: migrations_current_version() called with a NULL handle or out_version");
        return CYTADEL_DB_ERR_INVALID_ARG;
    }

    if (cytadel_db_exec(handle, CYTADEL_DB_SCHEMA_MIGRATIONS_DDL, "ensuring schema_migrations exists") !=
        SQLITE_OK) {
        return CYTADEL_DB_ERR_QUERY;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, "SELECT COALESCE(MAX(version), 0) FROM schema_migrations;", -1,
                                 &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: preparing schema_migrations version query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_DB_ERR_QUERY;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cytadel_log_error("db: stepping schema_migrations version query failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_DB_ERR_QUERY;
    }

    *out_version = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return CYTADEL_DB_OK;
}

/* Records that `m` has been applied: a parameterized INSERT (bound
 * version/description/applied_at -- never string-concatenated, per this
 * project's parameterized-queries rule, even though every value here
 * happens to be a compile-time constant or a freshly-formatted
 * timestamp). Must be called inside the same transaction as `m`'s own DDL
 * so a crash between the two can never record a migration whose DDL never
 * actually ran (or vice versa). */
static int cytadel_db_record_migration(sqlite3 *handle, const cytadel_db_migration_t *m) {
    char applied_at[CYTADEL_ISO8601_BUF_LEN];
    if (cytadel_log_format_timestamp_utc(applied_at, sizeof(applied_at)) != 0) {
        cytadel_log_error("db: formatting applied_at timestamp for migration %d failed", m->version);
        return SQLITE_ERROR;
    }

    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(
        handle, "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?);", -1,
        &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: preparing schema_migrations insert for version %d failed (sqlite rc=%d): %s",
                           m->version, rc, sqlite3_errmsg(handle));
        return rc;
    }

    /* SQLITE_STATIC/SQLITE_TRANSIENT: m->description is a static string
     * literal (safe to bind SQLITE_STATIC -- outlives the statement),
     * applied_at is a stack buffer sqlite3 must copy (SQLITE_TRANSIENT). */
    rc = sqlite3_bind_int(stmt, 1, m->version);
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 2, m->description, -1, SQLITE_STATIC);
    }
    if (rc == SQLITE_OK) {
        rc = sqlite3_bind_text(stmt, 3, applied_at, -1, SQLITE_TRANSIENT);
    }
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: binding schema_migrations insert for version %d failed (sqlite rc=%d): %s",
                           m->version, rc, sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return rc;
    }

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    if (rc != SQLITE_DONE) {
        cytadel_log_error("db: recording schema_migrations version %d failed (sqlite rc=%d): %s",
                           m->version, rc, sqlite3_errmsg(handle));
        return rc;
    }
    return SQLITE_OK;
}

cytadel_db_status_t cytadel_db_migrations_run(sqlite3 *handle) {
    if (handle == NULL) {
        cytadel_log_error("db: migrations_run() called with a NULL handle");
        return CYTADEL_DB_ERR_INVALID_ARG;
    }

    int current_version = 0;
    cytadel_db_status_t status = cytadel_db_migrations_current_version(handle, &current_version);
    if (status != CYTADEL_DB_OK) {
        return status;
    }

    for (size_t i = 0; i < CYTADEL_DB_MIGRATION_COUNT; i++) {
        const cytadel_db_migration_t *m = &CYTADEL_DB_MIGRATIONS[i];
        if (m->version <= current_version) {
            continue; /* already applied -- this is what makes re-running a no-op */
        }

        if (cytadel_db_exec(handle, "BEGIN;", "starting migration transaction") != SQLITE_OK) {
            return CYTADEL_DB_ERR_MIGRATION;
        }

        bool statement_failed = false;
        for (size_t j = 0; j < m->statement_count; j++) {
            if (cytadel_db_exec(handle, m->statements[j], "applying migration DDL") != SQLITE_OK) {
                statement_failed = true;
                break;
            }
        }

        if (statement_failed || cytadel_db_record_migration(handle, m) != SQLITE_OK) {
            /* Best-effort rollback -- if even this fails there is nothing more
             * this function can safely do; the ROLLBACK failure is logged by
             * cytadel_db_exec() itself and the caller already gets an error
             * status either way. */
            (void)cytadel_db_exec(handle, "ROLLBACK;", "rolling back failed migration");
            cytadel_log_error("db: migration %d ('%s') failed and was rolled back", m->version,
                               m->description);
            return CYTADEL_DB_ERR_MIGRATION;
        }

        if (cytadel_db_exec(handle, "COMMIT;", "committing migration transaction") != SQLITE_OK) {
            /* Security-review suggestion (Milestone 7 slice 2 round):
             * a failed COMMIT previously returned immediately, leaving the
             * BEGIN...COMMIT transaction still open on `handle` -- any
             * later caller reusing this same connection (e.g. a retry, or
             * cytadel_db_migrate() called again) would then silently run
             * its own statements inside that stale, already-broken
             * transaction instead of a fresh one. Roll it back first, same
             * as the statement_failed/record_migration failure path just
             * above and nvd_ingest.c's own failed-COMMIT handling --
             * best-effort: if the ROLLBACK itself fails there is nothing
             * more this function can safely do, and the caller already
             * gets CYTADEL_DB_ERR_MIGRATION either way. */
            (void)cytadel_db_exec(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
            return CYTADEL_DB_ERR_MIGRATION;
        }

        cytadel_log_info("db: applied migration %d ('%s')", m->version, m->description);
    }

    return CYTADEL_DB_OK;
}
