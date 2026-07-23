#include "cytadel/db/db.h"

#include <sqlite3.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "db_migrations.h"
#include "log.h"

/* See include/cytadel/db/db.h's top-of-file comment for the design this
 * implementation follows: one connection per cytadel_db_open() call, the
 * full mandatory connection-setup PRAGMA sequence applied every time (never
 * cached/skipped -- db-schema.md is explicit that PRAGMA foreign_keys is
 * not a persistent DB property), and no pooling/sharing across threads in
 * this slice. */

struct cytadel_db {
    sqlite3 *handle;
};

const char *cytadel_db_status_to_string(cytadel_db_status_t status) {
    switch (status) {
        case CYTADEL_DB_OK:              return "OK";
        case CYTADEL_DB_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_DB_ERR_OOM:         return "OOM";
        case CYTADEL_DB_ERR_OPEN:        return "OPEN";
        case CYTADEL_DB_ERR_PRAGMA:      return "PRAGMA";
        case CYTADEL_DB_ERR_MIGRATION:   return "MIGRATION";
        case CYTADEL_DB_ERR_QUERY:       return "QUERY";
    }
    return "UNKNOWN";
}

/* Runs one fixed (no bound parameters -- these are static PRAGMA strings,
 * never built from external input) PRAGMA via sqlite3_exec(), logging
 * sqlite3's error text on failure. Used for the three PRAGMAs whose result
 * value this module never needs to inspect (foreign_keys, synchronous,
 * busy_timeout) -- see cytadel_db_apply_connection_setup() below for why
 * journal_mode is handled separately. */
static int cytadel_db_pragma_exec(sqlite3 *handle, const char *pragma_sql, const char *name) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, pragma_sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: PRAGMA %s failed (sqlite rc=%d): %s", name, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

/* PRAGMA journal_mode=WAL is the one connection-setup PRAGMA whose result
 * SQLite always reports back as a result row, even in its "setter" form --
 * because a requested WAL switch can silently fail to actually take effect
 * (most notably: ":memory:"/temporary databases can never use WAL and
 * SQLite reports back "memory" instead; db-schema.md also flags a
 * CIFS/NFS-mounted DB file as a real-world case where the switch can fail).
 * This function reads that result back so a failure to actually reach WAL
 * mode on a REAL on-disk path can be logged -- the ":memory:" case is
 * expected and intentionally not logged as a warning. */
static int cytadel_db_set_journal_mode_wal(sqlite3 *handle, const char *path) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, "PRAGMA journal_mode = WAL;", -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("db: preparing PRAGMA journal_mode=WAL failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cytadel_log_error("db: PRAGMA journal_mode=WAL produced no result (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return rc;
    }

    const unsigned char *mode = sqlite3_column_text(stmt, 0);
    bool is_wal = (mode != NULL) && (strcmp((const char *)mode, "wal") == 0);
    bool is_memory_path = (strcmp(path, ":memory:") == 0);
    if (!is_wal && !is_memory_path) {
        cytadel_log_warn(
            "db: PRAGMA journal_mode=WAL did not take effect on '%s' (got '%s') -- WAL requires a "
            "local filesystem (db-schema.md: no CIFS/NFS-mounted DB path); continuing with whatever "
            "journal mode SQLite fell back to",
            path, mode ? (const char *)mode : "(null)");
    }

    sqlite3_finalize(stmt);
    return SQLITE_OK;
}

/* Applies db-schema.md's mandatory per-connection setup, in the exact
 * documented order. Returns SQLITE_OK on success; on any failure the
 * specific PRAGMA's own helper has already logged context. */
static int cytadel_db_apply_connection_setup(sqlite3 *handle, const char *path) {
    int rc = cytadel_db_pragma_exec(handle, "PRAGMA foreign_keys = ON;", "foreign_keys");
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = cytadel_db_set_journal_mode_wal(handle, path);
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = cytadel_db_pragma_exec(handle, "PRAGMA synchronous = NORMAL;", "synchronous");
    if (rc != SQLITE_OK) {
        return rc;
    }

    rc = cytadel_db_pragma_exec(handle, "PRAGMA busy_timeout = 5000;", "busy_timeout");
    if (rc != SQLITE_OK) {
        return rc;
    }

    return SQLITE_OK;
}

cytadel_db_status_t cytadel_db_open(const char *path, cytadel_db_t **out_db) {
    if (out_db != NULL) {
        *out_db = NULL;
    }
    if (path == NULL || path[0] == '\0' || out_db == NULL) {
        cytadel_log_error("db: open() called with a NULL/empty path or a NULL out_db");
        return CYTADEL_DB_ERR_INVALID_ARG;
    }

    sqlite3 *handle = NULL;
    int rc = sqlite3_open_v2(path, &handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if (rc != SQLITE_OK) {
        /* sqlite3_open_v2() may still have allocated a handle purely to hold
         * the error message -- must be closed either way (sqlite3 docs: "Whether
         * or not an error occurs when it is opened, resources associated with
         * the database connection handle should be released by passing it to
         * sqlite3_close()"). */
        cytadel_log_error("db: opening '%s' failed (sqlite rc=%d): %s", path, rc,
                           handle ? sqlite3_errmsg(handle) : sqlite3_errstr(rc));
        sqlite3_close(handle);
        return CYTADEL_DB_ERR_OPEN;
    }

    if (cytadel_db_apply_connection_setup(handle, path) != SQLITE_OK) {
        sqlite3_close(handle);
        return CYTADEL_DB_ERR_PRAGMA;
    }

    cytadel_db_t *db = malloc(sizeof(*db));
    if (db == NULL) {
        cytadel_log_error("db: out of memory allocating connection wrapper for '%s'", path);
        sqlite3_close(handle);
        return CYTADEL_DB_ERR_OOM;
    }
    db->handle = handle;

    *out_db = db;
    return CYTADEL_DB_OK;
}

cytadel_db_status_t cytadel_db_migrate(cytadel_db_t *db) {
    if (db == NULL) {
        cytadel_log_error("db: migrate() called with a NULL db");
        return CYTADEL_DB_ERR_INVALID_ARG;
    }
    return cytadel_db_migrations_run(db->handle);
}

cytadel_db_status_t cytadel_db_schema_version(cytadel_db_t *db, int *out_version) {
    if (db == NULL || out_version == NULL) {
        cytadel_log_error("db: schema_version() called with a NULL db or out_version");
        return CYTADEL_DB_ERR_INVALID_ARG;
    }
    return cytadel_db_migrations_current_version(db->handle, out_version);
}

sqlite3 *cytadel_db_handle(cytadel_db_t *db) {
    return (db != NULL) ? db->handle : NULL;
}

void cytadel_db_close(cytadel_db_t *db) {
    if (db == NULL) {
        return;
    }
    sqlite3_close(db->handle);
    db->handle = NULL;
    free(db);
}
