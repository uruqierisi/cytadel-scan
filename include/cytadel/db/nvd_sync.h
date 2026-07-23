#ifndef CYTADEL_DB_NVD_SYNC_H
#define CYTADEL_DB_NVD_SYNC_H

#include <stddef.h>

#include "cytadel/db/db.h"
#include "cytadel/net/nvd_fetch.h"

/* Milestone 7 (live NVD fetch slice): the pagination / delta-sync DRIVER that
 * sits between the libcurl transport (src/net/nvd_fetch.c) and the frozen
 * slice-2 ingest (src/db/nvd_ingest.c). It owns the db-schema.md §8 "NVD
 * delta-sync procedure" paging loop: for one lastMod window it fetches page
 * after page (startIndex += resultsPerPage) until the window is exhausted,
 * handing each page's bounded body to cytadel_nvd_ingest_page().
 *
 * WATERMARK / CRASH-SAFETY INVARIANT (the whole point of this module): the
 * sync_state 'nvd' watermark is advanced by the ingest layer ONLY when it is
 * called with window_complete=true, and this driver passes window_complete=
 * true ONLY on the final page of a window in which EVERY prior page fetched
 * and committed cleanly. Any fetch failure, protocol violation, or ingest
 * error at any page returns immediately WITHOUT ever making that final-page
 * call, so the watermark stays exactly where it was and the caller's next run
 * re-fetches the whole window from the same cursor -- never skipping data.
 *
 * Scope, deliberately one window per call: computing the window bounds
 * themselves (reading the current watermark, the min(now, watermark+120d)
 * arithmetic, and the multi-window catch-up loop of §8 step 6) is the
 * caller's concern; this driver is handed an explicit [start_date, end_date]
 * and drives exactly that window. start_date == NULL means the initial bulk
 * load (no lastModStartDate/lastModEndDate filter is sent). CPE version-range
 * matching is a separate later slice and is not touched here.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Hostile-input safety valve: an upper bound on the number of pages this
 * driver will fetch for a single window regardless of a (possibly hostile)
 * totalResults. At the NVD max of 2000 results/page this covers 200M CVEs --
 * far beyond the real corpus -- so a legitimate window never hits it; a
 * response advertising an absurd totalResults just aborts the window
 * (ERR_PROTOCOL, watermark unchanged) instead of looping unboundedly. This is
 * the DEFAULT used when cytadel_nvd_sync_window()'s own `max_pages` argument
 * is 0 -- see that function's doc comment; a test injects a small override so
 * the valve itself can be exercised without a 100000-page fixture. */
#define CYTADEL_NVD_SYNC_MAX_PAGES 100000

typedef enum {
    CYTADEL_NVD_SYNC_OK = 0,
    CYTADEL_NVD_SYNC_ERR_INVALID_ARG = 1,
    /* A page fetch failed (transport error, auth failure, rate-limit
     * exhaustion, 5xx give-up, size-cap abort, ...). The window is abandoned
     * and the watermark is unchanged. */
    CYTADEL_NVD_SYNC_ERR_FETCH = 2,
    /* A page was fetched but the ingest layer reported a fatal (ERR_DB) or
     * parse (ERR_PARSE) failure -- the page's transaction was rolled back and
     * the watermark is unchanged. */
    CYTADEL_NVD_SYNC_ERR_INGEST = 3,
    /* The fetched page did not carry a usable, non-negative totalResults (so
     * the driver cannot tell where the window ends), or the per-window page
     * cap was exceeded. Watermark unchanged. */
    CYTADEL_NVD_SYNC_ERR_PROTOCOL = 4
} cytadel_nvd_sync_status_t;

typedef struct {
    size_t pages_fetched;
    size_t cve_ingested; /* summed across the window's pages */
    size_t cve_skipped;
} cytadel_nvd_sync_counts_t;

/* Never returns NULL. */
const char *cytadel_nvd_sync_status_to_string(cytadel_nvd_sync_status_t status);

/* Drives one delta-sync window. `db` must already be migrated. `cfg` is the
 * transport config (base_url is injectable so tests can point at a loopback
 * fixture server). `start_date` is the window's lastModStartDate (NULL for
 * the initial bulk load); `end_date` is BOTH the lastModEndDate query bound
 * AND the watermark value that will be stored when the window completes, and
 * must be non-NULL. `max_pages` overrides this window's per-call page-cap
 * valve: 0 means "use the default CYTADEL_NVD_SYNC_MAX_PAGES", a positive
 * value is used as-is instead. Production callers should pass 0; this exists
 * so a test can inject a small cap and exercise the "hostile totalResults
 * pages the window all the way to the cap" valve directly, without a fixture
 * that would otherwise need to serve 100000 pages. `*out_counts` is zeroed on
 * entry and is always safe to read after the call. Returns CYTADEL_NVD_SYNC_OK
 * only when the entire window was fetched and committed (and the watermark
 * therefore advanced). */
cytadel_nvd_sync_status_t cytadel_nvd_sync_window(cytadel_db_t *db,
                                                  const cytadel_nvd_fetch_config_t *cfg,
                                                  const char *start_date, const char *end_date,
                                                  long max_pages,
                                                  cytadel_nvd_sync_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_NVD_SYNC_H */
