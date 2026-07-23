#ifndef CYTADEL_DB_NVD_INGEST_H
#define CYTADEL_DB_NVD_INGEST_H

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/db/db.h"

/* Milestone 7 slice 2: defensive ingest of one NVD 2.0 CVE JSON page
 * (docs/contracts/db-schema.md SS2/SS3/SS8/SS9, FROZEN CONTRACT -- this
 * module persists into that schema exactly, it does not alter it) into the
 * cves / cve_cpe_matches / sync_state tables.
 *
 * PRIME DIRECTIVE (the project policy, this milestone's task brief): the input is
 * hostile. NVD 2.0 JSON is untrusted -- every field may be absent, null,
 * the wrong type, empty, oversized, or duplicated; arrays may be huge or
 * truncated mid-element; the document may be truncated mid-page. ONE bad
 * CVE record must NEVER abort the whole page's ingest -- it is skipped and
 * logged (debug/warn, with the offending cve_id or "<no id>" when no id
 * could be recovered at all), and the loop continues. Only a genuinely
 * fatal, non-constraint sqlite error (I/O, corruption, out-of-memory, a
 * prepare failure against this module's own fixed SQL text) aborts the
 * whole page -- and even then, via a full ROLLBACK, never a partial write.
 *
 * Scope: parse + persist only. NO network I/O, NO libcurl, NO NVD API key
 * -- this function is handed already-fetched page bytes by a later slice's
 * fetch loop; it has no opinion about how those bytes arrived. Pagination
 * (startIndex/resultsPerPage) and the multi-window catch-up loop
 * (db-schema.md SS8's "NVD delta-sync procedure") are also a later slice's
 * concern -- this function ingests exactly one page per call.
 *
 * Explicitly OUT of scope (a later slice, per db-schema.md SS9's own
 * "KEV/EPSS reconciliation upsert" note): the kev/epss placeholder-row FK
 * dance. This module only ever writes source='nvd' rows.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on the number of cve_cpe_matches rows this module will attempt
 * to persist for a single CVE record's "configurations" block, regardless
 * of how many cpeMatch entries the (untrusted) input actually contains.
 * Real NVD CVEs rarely carry more than a few dozen CPE match rows even for
 * heavily-affected products; this is purely a hostile-input safety valve
 * (the project policy: "never trust a length or count from the input to size an
 * allocation without bounding it" -- generalized here to "without bounding
 * the work done", since this module never allocates proportionally to an
 * untrusted count in the first place, walking cJSON's own already-parsed
 * child/next chain instead). Exceeding this cap is logged and the excess
 * cpeMatch entries for that CVE are skipped; the CVE row itself is still
 * ingested with whatever CPE rows were processed before the cap was hit.
 * Exposed here (not just an internal #define in nvd_ingest.c) so tests can
 * assert against it by name instead of a duplicated magic number. */
#define CYTADEL_NVD_MAX_CPE_PER_CVE 4096

/* Hard cap on the length (bytes) of the `description` column value this
 * module will ever store for one CVE -- an oversized NVD description is
 * clipped to this many bytes, never rejected outright (the project policy: "clip any
 * string bound into a TEXT column to a sane max"). Exposed for the same
 * test-assertion reason as CYTADEL_NVD_MAX_CPE_PER_CVE above. */
#define CYTADEL_NVD_DESC_MAX_LEN 4096

typedef enum {
    CYTADEL_NVD_INGEST_OK = 0,
    /* NULL db/json_bytes/out_counts, or a NULL/empty lastmod_end_date --
     * caller bug, no DB access and no parse was ever attempted. */
    CYTADEL_NVD_INGEST_ERR_INVALID_ARG = 1,
    /* Any of: `len` exceeds this module's own pre-parse sanity cap (a page
     * claiming to be absurdly large is rejected before cJSON ever touches
     * it); cJSON_ParseWithLength() returned NULL (truncated/malformed
     * JSON); the top-level document parsed but was not a JSON object; or
     * (security-review W1 fix) the top-level "vulnerabilities" key is
     * either ABSENT or present but NOT a JSON array. Only a present JSON
     * ARRAY value for "vulnerabilities" is a valid page -- an empty array
     * (`[]`) IS valid (a legitimately empty page, 0 records, still
     * CYTADEL_NVD_INGEST_OK). A missing/wrong-typed "vulnerabilities" is
     * instead treated as a corrupted/tampered page (e.g. a MITM'd or
     * truncated-at-the-top-level response) and rejected outright, exactly
     * like malformed JSON -- silently treating it as "0 records, all
     * good" would let a corrupted page skip a whole window's worth of
     * real CVE data with no error ever surfaced.
     * In every one of these cases, no DB transaction was ever opened --
     * sync_state is byte-for-byte unchanged, guaranteeing the caller's
     * next attempt re-fetches/re-ingests the same window instead of
     * silently skipping whatever this page would have contained. */
    CYTADEL_NVD_INGEST_ERR_PARSE = 2,
    /* A fatal (non-CONSTRAINT) sqlite3 error occurred while this page's
     * transaction was open (a prepare failure against this module's own
     * fixed SQL, an I/O/corruption/OOM error mid-page, or a failure
     * updating the sync_state watermark itself). The whole page's
     * transaction was rolled back -- no partial write, and sync_state is
     * unchanged from before this call. */
    CYTADEL_NVD_INGEST_ERR_DB = 3
} cytadel_nvd_ingest_status_t;

/* Per-page outcome counters -- every CVE element present in the page's
 * "vulnerabilities" array, and every cpeMatch element present in an
 * ingested CVE's "configurations", lands in exactly one of these four
 * buckets (never both ingested and skipped for the same logical row, and
 * never neither): a row this module never even got to inspect because a
 * hostile-input cap (CYTADEL_NVD_MAX_CPE_PER_CVE, or this file's own
 * internal per-page CVE cap) was already exhausted still counts as
 * "skipped", not silently uncounted. A duplicate cve_id appearing more
 * than once within the same page counts every occurrence as an ingest
 * attempt (each one is a real upsert against the frozen ON CONFLICT DO
 * UPDATE clause, and the last one processed wins the stored row) -- these
 * counters report attempts, not distinct entities; querying the DB itself
 * is how a caller/test learns the distinct row count. */
typedef struct {
    size_t cve_ingested;
    size_t cve_skipped;
    size_t cpe_ingested;
    size_t cpe_skipped;
} cytadel_nvd_ingest_counts_t;

/* Returns a static, human-readable name for `status`. Never returns NULL --
 * mirrors cytadel_db_status_to_string()'s convention. */
const char *cytadel_nvd_ingest_status_to_string(cytadel_nvd_ingest_status_t status);

/* Ingests one NVD 2.0 API page (`json_bytes`, exactly `len` bytes -- never
 * assumed NUL-terminated; parsed via cJSON_ParseWithLength()) into `db`.
 *
 * `lastmod_end_date` is the caller-supplied watermark value for the WINDOW
 * this page belongs to (db-schema.md SS8: the window's `lastModEndDate`
 * cursor). A single NVD delta-sync window is typically paged across
 * multiple calls to this function (`startIndex`/`resultsPerPage`, per
 * db-schema.md SS8 step 3) -- `window_complete` tells this call whether it
 * is the LAST page of that window:
 *
 *   window_complete == true  (the final page of the window): `sync_state`
 *     for feed='nvd' is updated, IN THE SAME TRANSACTION as this page's own
 *     cves/cve_cpe_matches upserts, to:
 *       last_mod_watermark  = lastmod_end_date
 *       last_sync_completed = now() (this module's own write time)
 *       total_records       = total_records + (cve_ingested + cve_skipped this page)
 *       status              = 'success'
 *       last_error          = NULL
 *
 *   window_complete == false (an earlier, non-final page of the window):
 *     this page's own cves/cve_cpe_matches data is still committed, but
 *     `last_mod_watermark` is deliberately left UNTOUCHED (not even
 *     included in the UPDATE's SET clause) and `status` is set to
 *     'running' (not 'success') instead, with `last_error` cleared and
 *     `total_records` still accumulated by this page's own attempt count
 *     (documented choice: total_records tracks cumulative records SEEN
 *     across the whole sync run, independent of whether the window they
 *     belonged to has fully landed yet, so it grows monotonically page by
 *     page instead of jumping only at each window's last page).
 *
 * This is what makes "advance the watermark only after the window's data
 * is durably committed, never before" (db-schema.md SS8 step 5) correct for
 * a REAL multi-page window, not just a single-page one: if the process
 * crashes after page 3 of a 5-page window (each called with
 * window_complete=false), `last_mod_watermark` is still exactly where it
 * was before page 1 started, so the caller's next run safely re-fetches
 * and re-ingests the WHOLE window from scratch (this module's own ON
 * CONFLICT upserts make that idempotent) instead of the watermark having
 * skipped ahead of data that never fully landed.
 *
 * Updating sync_state inside the very same BEGIN/COMMIT as the page's own
 * data (rather than as a separate statement/transaction issued after
 * COMMIT), for EITHER value of window_complete, is what guarantees this
 * atomicity: a crash or fatal error at any point before COMMIT rolls back
 * BOTH the page's data and its sync_state update together.
 *
 * `db` must already be migrated (cytadel_db_migrate()) -- this function
 * assumes `sync_state` already has its seeded 'nvd' row (db-schema.md SS8's
 * `INSERT OR IGNORE` seed) and does not create it.
 *
 * `*out_counts` is always reset to all-zero at entry (even on an early
 * INVALID_ARG/PARSE return) before anything else happens, so a caller that
 * only checks the return status still sees zeroed counts on failure rather
 * than stale/uninitialized values. `out_counts` must be non-NULL.
 *
 * Never partially commits: either every upsert this call performs for a
 * page is durably committed together with its sync_state update
 * (CYTADEL_NVD_INGEST_OK), or none of it is (ERR_PARSE / ERR_DB, full
 * ROLLBACK or no transaction ever opened). */
cytadel_nvd_ingest_status_t cytadel_nvd_ingest_page(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                     const char *lastmod_end_date, bool window_complete,
                                                     cytadel_nvd_ingest_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_NVD_INGEST_H */
