#ifndef CYTADEL_DB_KEV_INGEST_H
#define CYTADEL_DB_KEV_INGEST_H

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/db/db.h"

/* KEV/EPSS ingest slice: defensive ingest of one CISA Known Exploited
 * Vulnerabilities (KEV) catalog JSON buffer (docs/contracts/db-schema.md SS4/
 * SS8/SS9/SS10 assumption 5, FROZEN CONTRACT -- this module persists into
 * that schema exactly, it does not alter it) into the kev / cves (placeholder
 * rows only) / sync_state tables.
 *
 * This mirrors src/db/nvd_ingest.c's architecture exactly -- see that file
 * and include/cytadel/db/nvd_ingest.h for the fully-documented pattern this
 * module follows: defensive cJSON parse via cJSON_ParseWithLength() (bounded,
 * never assumes NUL-termination), every field type-checked before use,
 * skip-and-log per bad record (one bad KEV entry NEVER aborts the whole
 * ingest), per-field length caps (clip, never reject-for-size), the whole
 * buffer ingested inside ONE BEGIN..COMMIT transaction, and the sync_state
 * watermark update happens INSIDE that same transaction so it only ever
 * advances together with durably committed data.
 *
 * PRIME DIRECTIVE (the project policy, this milestone's task brief): the input is
 * hostile. CISA's KEV JSON is untrusted -- every field may be absent, null,
 * the wrong type, empty, oversized, or duplicated; the document may be
 * truncated mid-file. ONE bad KEV record must never abort the whole ingest --
 * it is skipped and logged, and the loop continues. Only a genuinely fatal,
 * non-constraint sqlite error aborts the whole ingest, and even then via a
 * full ROLLBACK, never a partial write.
 *
 * Scope: parse + persist only, from an in-memory buffer. NO network I/O, NO
 * libcurl -- this function is handed already-fetched file bytes by a later
 * slice's fetch loop; it has no opinion about how those bytes arrived.
 *
 * Placeholder-FK dance (db-schema.md SS9/SS10 assumption 5): `kev.cve_id` is
 * a hard FOREIGN KEY into `cves(cve_id)`, and the KEV feed can (and
 * routinely does) name a CVE the NVD sync has not ingested yet. For every
 * valid KEV record, this module FIRST runs the placeholder-row upsert
 * (`INSERT INTO cves (...) VALUES (..., 'placeholder', ...) ON CONFLICT
 * (cve_id) DO NOTHING`) and only then upserts the `kev` row itself -- both
 * inside the same page transaction. A KEV entry naming a CVE not already in
 * `cves` therefore always succeeds (a placeholder row is created), never
 * fails on `FOREIGN KEY constraint failed`.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on the number of "vulnerabilities" array elements this module
 * will walk for a single call -- the real CISA KEV catalog currently holds a
 * few thousand entries and grows slowly; this is purely a hostile-input
 * safety valve (a buffer claiming far more entries than any real KEV catalog
 * ever would). Exceeding this cap is logged and the excess entries are
 * counted as skipped; every entry processed before the cap was hit is still
 * ingested. Exposed here (not just an internal #define) so tests can assert
 * against it by name. */
#define CYTADEL_KEV_MAX_RECORDS 100000

/* Hard cap on the length (bytes) of the `notes` column value this module
 * will ever store for one KEV record -- an oversized `notes` value is
 * clipped to this many bytes, never rejected outright (matching
 * nvd_ingest.h's CYTADEL_NVD_DESC_MAX_LEN convention). Exposed here so tests
 * can assert against it by name instead of a duplicated magic number. */
#define CYTADEL_KEV_NOTES_MAX_LEN 4096

typedef enum {
    CYTADEL_KEV_INGEST_OK = 0,
    /* NULL db/json_bytes/out_counts -- caller bug, no DB access and no parse
     * was ever attempted. */
    CYTADEL_KEV_INGEST_ERR_INVALID_ARG = 1,
    /* Any of: `len` exceeds this module's own pre-parse sanity cap; cJSON
     * failed to parse the buffer (truncated/malformed JSON); the top-level
     * document parsed but was not a JSON object; or the top-level
     * "vulnerabilities" key is either ABSENT or present but NOT a JSON array
     * (only a present JSON array -- including an empty one, `[]` -- is a
     * valid, legitimately-empty buffer). In every one of these cases, no DB
     * transaction was ever opened -- sync_state is byte-for-byte unchanged. */
    CYTADEL_KEV_INGEST_ERR_PARSE = 2,
    /* A fatal (non-CONSTRAINT) sqlite3 error occurred while the transaction
     * was open. The whole transaction was rolled back -- no partial write,
     * and sync_state is unchanged from before this call. */
    CYTADEL_KEV_INGEST_ERR_DB = 3
} cytadel_kev_ingest_status_t;

/* Per-call outcome counters -- every element present in the "vulnerabilities"
 * array lands in exactly one bucket: a record this module never even got to
 * inspect because CYTADEL_KEV_MAX_RECORDS was already exhausted still counts
 * as "skipped", not silently uncounted. */
typedef struct {
    size_t kev_ingested;
    size_t kev_skipped;
} cytadel_kev_ingest_counts_t;

/* Returns a static, human-readable name for `status`. Never returns NULL. */
const char *cytadel_kev_ingest_status_to_string(cytadel_kev_ingest_status_t status);

/* Ingests one CISA KEV catalog JSON buffer (`json_bytes`, exactly `len`
 * bytes -- never assumed NUL-terminated; parsed via
 * cJSON_ParseWithLength()) into `db`.
 *
 * `full_pull_complete` mirrors nvd_ingest.h's `window_complete` parameter,
 * generalized to a possible future multi-chunk fetch driver for this feed
 * (the KEV catalog is currently small enough to always be ingested in one
 * call, but this module makes no such assumption itself):
 *
 *   full_pull_complete == true (the final/only chunk of this pull):
 *     `sync_state` for feed='kev' is updated, IN THE SAME TRANSACTION as
 *     this chunk's own kev/cves upserts, to:
 *       last_mod_watermark  = strftime('%Y-%m-%d','now')  -- local
 *         ingestion date (db-schema.md SS8: KEV/EPSS have no remote delta
 *         cursor, this column just records "we already have today's file")
 *       last_sync_completed = now()
 *       total_records       = total_records + (kev_ingested + kev_skipped
 *                              this call)
 *       status              = 'success'
 *       last_error          = NULL
 *
 *   full_pull_complete == false (an earlier, non-final chunk): this chunk's
 *     own kev/cves data is still committed, but last_mod_watermark is left
 *     UNTOUCHED and status is set to 'running' instead of 'success', with
 *     total_records still accumulated -- so a crash after this chunk (but
 *     before the pull's final chunk) leaves the watermark exactly where it
 *     was, and the next run safely re-fetches and re-ingests the WHOLE file
 *     (idempotent via this module's own ON CONFLICT upserts).
 *
 * `db` must already be migrated (cytadel_db_migrate()) -- this function
 * assumes `sync_state` already has its seeded 'kev' row and does not create
 * it.
 *
 * `*out_counts` is always reset to all-zero at entry (even on an early
 * INVALID_ARG/PARSE return). `out_counts` must be non-NULL.
 *
 * Never partially commits: either every upsert this call performs is durably
 * committed together with its sync_state update (CYTADEL_KEV_INGEST_OK), or
 * none of it is (ERR_PARSE / ERR_DB, full ROLLBACK or no transaction ever
 * opened). */
cytadel_kev_ingest_status_t cytadel_kev_ingest(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                bool full_pull_complete,
                                                cytadel_kev_ingest_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_KEV_INGEST_H */
