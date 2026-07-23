#ifndef CYTADEL_DB_MIGRATIONS_H
#define CYTADEL_DB_MIGRATIONS_H

#include <sqlite3.h>

#include "cytadel/db/db.h"

/* Private to src/db/ -- not under include/cytadel/db/ -- matching the
 * icmp_probe.h/tcp_ping.h (src/net) and kb_validate.h (src/kb) convention:
 * only db.c in this same module includes this. The migration table/runner
 * is an implementation detail of cytadel_db_migrate()/
 * cytadel_db_schema_version(); callers only ever see the public db.h API.
 *
 * This header (unlike db.h) does include <sqlite3.h> directly: it works on
 * a raw sqlite3* handle, not the opaque cytadel_db_t wrapper, and is only
 * ever compiled inside this module where linking cytadel_sqlite3 (see
 * src/db/CMakeLists.txt) is already required. */

#ifdef __cplusplus
extern "C" {
#endif

/* Ensures the schema_migrations bookkeeping table exists (CREATE TABLE IF
 * NOT EXISTS db-schema.md SS1's exact DDL -- safe to call unconditionally,
 * even against a brand-new connection that has never been migrated) and
 * writes the current MAX(version) (0 if the table has no rows) into
 * *out_version. `handle`/`out_version` must both be non-NULL. */
cytadel_db_status_t cytadel_db_migrations_current_version(sqlite3 *handle, int *out_version);

/* Runs every migration with version > the DB's current schema_migrations
 * version, in ascending order, each inside its own transaction. See db.h's
 * cytadel_db_migrate() doc comment for the full contract (idempotency,
 * rollback-on-failure, etc.) -- this is that function's implementation,
 * operating on the raw handle rather than the cytadel_db_t wrapper. */
cytadel_db_status_t cytadel_db_migrations_run(sqlite3 *handle);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_MIGRATIONS_H */
