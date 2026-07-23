#ifndef CYTADEL_DB_EPSS_INGEST_H
#define CYTADEL_DB_EPSS_INGEST_H

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/db/db.h"

/* KEV/EPSS ingest slice: defensive ingest of one first.org EPSS
 * (Exploit Prediction Scoring System) JSON buffer (docs/contracts/
 * db-schema.md SS5/SS8/SS9/SS10 assumption 5, FROZEN CONTRACT -- this module
 * persists into that schema exactly, it does not alter it) into the epss /
 * cves (placeholder rows only) / sync_state tables.
 *
 * This mirrors src/db/nvd_ingest.c's architecture exactly, and is the
 * near-twin of src/db/kev_ingest.c in this same slice -- see both files'
 * own top-of-file comments for the fully-documented hostile-input defenses
 * this file relies on throughout (defensive cJSON parse via
 * cJSON_ParseWithLength(), every field type-checked before use,
 * skip-and-log per bad record, per-field length caps, one BEGIN..COMMIT per
 * call, sync_state watermark update inside that same transaction).
 *
 * PRIME DIRECTIVE (the project policy, this milestone's task brief): the input is
 * hostile. first.org's EPSS JSON is untrusted -- every field may be absent,
 * null, the wrong type, empty, oversized, or duplicated; `epss`/`percentile`
 * arrive as STRINGS (e.g. "0.00042") that must be defensively parsed to a
 * double and range-checked ([0.0, 1.0]) BEFORE insert, not left to a CHECK
 * constraint to reject (a CHECK failure is still handled -- via
 * SQLITE_CONSTRAINT, skip-and-log, never fatal -- but validating first
 * avoids relying on that as the only guard). ONE bad EPSS record must never
 * abort the whole ingest.
 *
 * Scope: parse + persist only, from an in-memory buffer. NO network I/O, NO
 * libcurl -- this function is handed already-fetched response bytes by a
 * later slice's fetch loop.
 *
 * Placeholder-FK dance (db-schema.md SS9/SS10 assumption 5): `epss.cve_id`
 * is a hard FOREIGN KEY into `cves(cve_id)`, and the EPSS feed can (and
 * routinely does, since it scores essentially every known CVE) name a CVE
 * the NVD sync has not ingested yet. For every valid EPSS record, this
 * module FIRST runs the placeholder-row upsert and only then upserts the
 * `epss` row itself -- both inside the same call's transaction.
 *
 * ~250k+ records in a full pull: the single-transaction-per-call design is
 * still correct here (SQLite handles a quarter-million-row transaction
 * without issue) -- see CYTADEL_EPSS_MAX_RECORDS below for the hostile-input
 * safety valve bounding how many this module will ever attempt in one call.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on the number of "data" array elements this module will walk for
 * a single call -- the real EPSS feed currently scores roughly 250k+ CVEs;
 * this generous cap is purely a hostile-input safety valve (a buffer
 * claiming far more entries than any real EPSS response ever would).
 * Exceeding this cap is logged and the excess entries are counted as
 * skipped; every entry processed before the cap was hit is still ingested.
 * Exposed here so tests can assert against it by name. */
#define CYTADEL_EPSS_MAX_RECORDS 500000

/* Hard cap on the length (bytes) of the `score_date` column value this
 * module will ever store -- an oversized date string is clipped, never
 * rejected outright (matching nvd_ingest.h's CYTADEL_NVD_DESC_MAX_LEN
 * convention). Exposed here so tests can assert against it by name. */
#define CYTADEL_EPSS_DATE_MAX_LEN 32

typedef enum {
    CYTADEL_EPSS_INGEST_OK = 0,
    /* NULL db/json_bytes/out_counts -- caller bug, no DB access and no parse
     * was ever attempted. */
    CYTADEL_EPSS_INGEST_ERR_INVALID_ARG = 1,
    /* Any of: `len` exceeds this module's own pre-parse sanity cap; cJSON
     * failed to parse the buffer; the top-level document parsed but was not
     * a JSON object; or the top-level "data" key is either ABSENT or
     * present but NOT a JSON array (only a present JSON array -- including
     * an empty one, `[]` -- is a valid, legitimately-empty buffer). In every
     * one of these cases, no DB transaction was ever opened -- sync_state is
     * byte-for-byte unchanged. */
    CYTADEL_EPSS_INGEST_ERR_PARSE = 2,
    /* A fatal (non-CONSTRAINT) sqlite3 error occurred while the transaction
     * was open. The whole transaction was rolled back -- no partial write,
     * and sync_state is unchanged from before this call. */
    CYTADEL_EPSS_INGEST_ERR_DB = 3
} cytadel_epss_ingest_status_t;

/* Per-call outcome counters -- every element present in the "data" array
 * lands in exactly one bucket: a record this module never even got to
 * inspect because CYTADEL_EPSS_MAX_RECORDS was already exhausted still
 * counts as "skipped", not silently uncounted. */
typedef struct {
    size_t epss_ingested;
    size_t epss_skipped;
} cytadel_epss_ingest_counts_t;

/* Returns a static, human-readable name for `status`. Never returns NULL. */
const char *cytadel_epss_ingest_status_to_string(cytadel_epss_ingest_status_t status);

/* Ingests one first.org EPSS JSON buffer (`json_bytes`, exactly `len` bytes
 * -- never assumed NUL-terminated; parsed via cJSON_ParseWithLength()) into
 * `db`.
 *
 * `full_pull_complete` mirrors kev_ingest.h's own parameter of the same
 * name (itself mirroring nvd_ingest.h's `window_complete`) -- see that
 * header's doc comment for the full contract, applied here to feed='epss':
 *
 *   full_pull_complete == true (the final/only chunk of this pull):
 *     sync_state.last_mod_watermark advances to strftime('%Y-%m-%d','now'),
 *     status='success', IN THE SAME TRANSACTION as this chunk's own
 *     epss/cves upserts.
 *
 *   full_pull_complete == false (an earlier, non-final chunk): this chunk's
 *     data is still committed, but last_mod_watermark is left UNTOUCHED and
 *     status is set to 'running' instead -- so a crash before the pull's
 *     final chunk never advances the watermark past data that has not
 *     fully landed, and the next run safely re-fetches/re-ingests the whole
 *     feed (idempotent via this module's own ON CONFLICT upserts).
 *
 * `db` must already be migrated (cytadel_db_migrate()) -- this function
 * assumes `sync_state` already has its seeded 'epss' row and does not
 * create it.
 *
 * `*out_counts` is always reset to all-zero at entry (even on an early
 * INVALID_ARG/PARSE return). `out_counts` must be non-NULL.
 *
 * Never partially commits: either every upsert this call performs is
 * durably committed together with its sync_state update
 * (CYTADEL_EPSS_INGEST_OK), or none of it is (ERR_PARSE / ERR_DB, full
 * ROLLBACK or no transaction ever opened). */
cytadel_epss_ingest_status_t cytadel_epss_ingest(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                  bool full_pull_complete,
                                                  cytadel_epss_ingest_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_EPSS_INGEST_H */
