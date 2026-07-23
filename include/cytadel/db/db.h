#ifndef CYTADEL_DB_DB_H
#define CYTADEL_DB_DB_H

#include <stddef.h>

/* Milestone 7 slice 1: the vertical DB foundation. First code realization
 * of docs/contracts/db-schema.md (FROZEN CONTRACT) -- open/create the
 * single-file SQLite vuln DB, apply the frozen DDL via an idempotent
 * migration runner, and hand back a correctly-configured connection. Every
 * constant, PRAGMA, and constraint below is taken directly from that
 * contract; where a comment cites a section ("db-schema.md's connection
 * setup block", "db-schema.md SS6"), that document is authoritative and
 * this is just the C encoding of it.
 *
 * Explicitly OUT of scope for this slice (later Milestone 7 work):
 * CVE/CPE/KEV/EPSS ingest, the NVD sync writer, and scan/scan_results
 * persistence. This module's job here is only: open a connection, run the
 * frozen schema (docs/contracts/db-schema.md SS1-SS8) into it, and expose
 * the raw sqlite3 handle (cytadel_db_handle() below) for later milestones'
 * own prepared statements -- see db-schema.md SS9 for the parameterized
 * query patterns those milestones must follow (never string-concatenate a
 * bound value into SQL text).
 *
 * `sqlite3` is forward-declared, not `#include <sqlite3.h>`'d, so this
 * public header carries no dependency on the vendored third_party/sqlite
 * amalgamation's own header. Any translation unit that needs to run its own
 * prepared statements against the handle cytadel_db_handle() returns must
 * separately `#include <sqlite3.h>` itself (reachable via the
 * cytadel_sqlite3 target's public include directory -- see
 * third_party/sqlite/CMakeLists.txt) -- exactly the same split
 * db-schema.md SS9 already assumes for the engine work/the plugin work's own query code.
 *
 * Concurrency / ownership model: this module opens exactly one connection
 * per cytadel_db_open() call and does not pool or share connections across
 * threads. db-schema.md's connection-setup block ("PRAGMA foreign_keys =
 * ON ... not a persistent DB property ... must be set every time a
 * connection is opened") is applied fully, in the documented order, on
 * every single cytadel_db_open() call -- callers on separate worker threads
 * that each need their own connection to the same DB file must each call
 * cytadel_db_open() themselves; this module does not do that fan-out for
 * them. journal_mode=WAL IS a persistent, one-time DB-file property (once
 * any connection sets it, it sticks for every future connection to that
 * file) -- see cytadel_db_open()'s doc comment below for exactly how a
 * ":memory:" path's inherently different journal-mode behavior is handled.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declaration matching sqlite3.h's own "typedef struct sqlite3
 * sqlite3;" -- this header never needs the full struct definition, only
 * later translation units that call sqlite3_* functions directly against
 * cytadel_db_handle()'s return value do, and they get it from <sqlite3.h>
 * themselves. */
typedef struct sqlite3 sqlite3;

typedef struct cytadel_db cytadel_db_t;

/* Typed status for every cytadel_db_* entry point below. Every failure path
 * also logs context (via this module's own cytadel_log_error() calls,
 * including the underlying sqlite3_errmsg()/sqlite3_errstr() text) before
 * returning one of these -- callers do not need a separate "get last error
 * string" accessor to get a meaningful diagnostic out of a failure; this
 * mirrors src/kb/kb.c's "log immediately at the failure site, return a
 * simple typed result" convention. */
typedef enum {
    CYTADEL_DB_OK              = 0,
    CYTADEL_DB_ERR_INVALID_ARG = 1, /* NULL out-param, empty path, etc. -- caller bug */
    CYTADEL_DB_ERR_OOM         = 2, /* malloc/calloc failure allocating the wrapper struct */
    CYTADEL_DB_ERR_OPEN        = 3, /* sqlite3_open_v2() itself failed */
    CYTADEL_DB_ERR_PRAGMA      = 4, /* one of the mandatory connection-setup PRAGMAs failed */
    CYTADEL_DB_ERR_MIGRATION   = 5, /* a pending migration's DDL/bookkeeping insert failed
                                      * (transaction rolled back, DB left at its prior version) */
    CYTADEL_DB_ERR_QUERY       = 6  /* a schema_version-style bookkeeping query failed */
} cytadel_db_status_t;

/* Returns a static, human-readable name for `status` ("OK", "INVALID_ARG",
 * ...). Never returns NULL -- an unrecognized value maps to "UNKNOWN",
 * mirroring cytadel_log_level_to_string()'s convention (src/log/log.h). */
const char *cytadel_db_status_to_string(cytadel_db_status_t status);

/* Opens (creating the file if it does not exist) the SQLite database at
 * `path` and applies db-schema.md's mandatory per-connection setup, in this
 * exact order:
 *
 *   1. PRAGMA foreign_keys = ON;      -- every table below relies on this
 *                                        for ON DELETE CASCADE / SET NULL.
 *   2. PRAGMA journal_mode = WAL;     -- one-time (persists in the DB file
 *                                        once any connection sets it); lets
 *                                        a future scan engine (reader) run
 *                                        concurrently with a future sync
 *                                        job (writer). For the special
 *                                        ":memory:" path (or any other
 *                                        temporary/in-memory database)
 *                                        SQLite cannot use WAL at all and
 *                                        silently reports back "memory"
 *                                        instead -- this is expected and
 *                                        NOT treated as a failure; only a
 *                                        real on-disk path that fails to
 *                                        report back "wal" logs a WARN
 *                                        (db-schema.md flags exactly this
 *                                        case for the ops work: no
 *                                        CIFS/NFS-mounted DB path).
 *   3. PRAGMA synchronous = NORMAL;   -- the documented safe durability/
 *                                        perf tradeoff under WAL.
 *   4. PRAGMA busy_timeout = 5000;    -- avoids SQLITE_BUSY races between a
 *                                        future reader/writer pair instead
 *                                        of an ad-hoc retry loop.
 *
 * `path` may be ":memory:" (a private, temporary in-memory database -- used
 * throughout this module's own unit tests) or a real filesystem path (the
 * containing directory must already exist; this function does not create
 * directories). Passing NULL or an empty string for `path`, or NULL for
 * `out_db`, returns CYTADEL_DB_ERR_INVALID_ARG without touching *out_db.
 *
 * On any failure *out_db is left unset (callers must not read it) and no
 * sqlite3 connection is leaked -- every failure path inside this function
 * closes whatever partially-opened handle sqlite3_open_v2() may have
 * returned before returning an error status. On success, *out_db is a
 * heap-allocated handle that must be released exactly once via
 * cytadel_db_close(). */
cytadel_db_status_t cytadel_db_open(const char *path, cytadel_db_t **out_db);

/* Runs every migration with a version greater than the DB's current
 * schema_migrations version, in ascending version order, each inside its
 * own transaction (BEGIN ... COMMIT, or ROLLBACK on any failure -- a failed
 * migration never leaves the DB at a half-applied version). Version 1 is
 * the full frozen schema (docs/contracts/db-schema.md SS1-SS8 verbatim --
 * all 8 tables, every CHECK/FK/UNIQUE constraint, and every named index).
 * Version 2 (docs/contracts/db-schema.md SS7, amended -- authorized
 * 2026-07-22, the M7 CPE-matching-caller slice) adds
 * scan_results.match_status via ALTER TABLE ... ADD COLUMN. Version 3
 * (docs/contracts/db-schema.md SS6, amended -- authorized 2026-07-22, the M8
 * report-slice-2 durable MALFORMED-data surface) adds
 * scans.malformed_data_count, also via ALTER TABLE ... ADD COLUMN; see
 * src/db/db_migrations.c's own migration table for the exact DDL. All three
 * run, in ascending order, from a brand-new connection.
 *
 * Idempotent: if the DB is already at the latest defined version, this is a
 * complete no-op (not even an empty transaction is opened) -- safe to call
 * on every process startup regardless of whether this is the first run
 * ever or the ten-thousandth. `db` must be non-NULL (returns
 * CYTADEL_DB_ERR_INVALID_ARG otherwise). */
cytadel_db_status_t cytadel_db_migrate(cytadel_db_t *db);

/* Writes the DB's current schema_migrations version (0 if the
 * schema_migrations table has no rows yet, e.g. cytadel_db_migrate() has
 * never been called against this DB) into *out_version. Safe to call before
 * cytadel_db_migrate() -- ensures the schema_migrations bookkeeping table
 * itself exists (harmless CREATE TABLE IF NOT EXISTS) before querying it,
 * so this never fails with a bare "no such table" error on a brand-new
 * connection. `db` and `out_version` must both be non-NULL (returns
 * CYTADEL_DB_ERR_INVALID_ARG, *out_version left unset, otherwise). */
cytadel_db_status_t cytadel_db_schema_version(cytadel_db_t *db, int *out_version);

/* Returns the raw sqlite3 connection handle owned by `db`, for later
 * milestones' own prepared statements (db-schema.md SS9's query patterns).
 * The returned pointer is borrowed -- valid until cytadel_db_close(db) is
 * called, never owned by the caller. Returns NULL if db is NULL. */
sqlite3 *cytadel_db_handle(cytadel_db_t *db);

/* Closes the underlying sqlite3 connection and frees `db`. Safe to call
 * with db == NULL (no-op), matching cytadel_kb_free()'s free-function
 * idiom. Not safe to call twice on the same non-NULL pointer. */
void cytadel_db_close(cytadel_db_t *db);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_DB_H */
