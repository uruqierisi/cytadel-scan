#ifndef CYTADEL_DB_EPSS_SYNC_H
#define CYTADEL_DB_EPSS_SYNC_H

#include <stddef.h>

#include "cytadel/db/db.h"
#include "cytadel/net/nvd_fetch.h"

/* EPSS live-fetch driver: the transport half that feeds the already-tested
 * cytadel_epss_ingest() (src/db/epss_ingest.c). Unlike the single-document KEV
 * catalog, the first.org EPSS API is PAGINATED (~250k CVEs), so this drives a
 * limit/offset loop, ingesting each page and advancing the feed='epss'
 * watermark only on the FINAL page (full_pull_complete=true) -- exactly the
 * per-page-commit / advance-only-when-done discipline the NVD pagination
 * driver uses. Termination is decided from the envelope's own `total` field
 * (authoritative even if the server caps `limit` below what we ask for), and
 * the cursor advances by the number of records ACTUALLY returned, so a
 * server-side limit cap never skips records.
 *
 * Same discipline as the NVD path: each GET rides cytadel_nvd_fetch_get()
 * (bounded response body, TLS verification always on, retry-with-backoff on
 * transport errors / 429 / 5xx, and the NVD apiKey NEVER sent to first.org).
 * Per-record skip-and-log, placeholder-FK handling, and watermark atomicity
 * live in cytadel_epss_ingest(). A fetch/parse/ingest failure at ANY page
 * returns immediately WITHOUT the final-page watermark advance, so the
 * feed='epss' watermark stays put and the next run safely re-pulls the whole
 * feed (idempotent via the ingest layer's ON CONFLICT upserts). */

#ifdef __cplusplus
extern "C" {
#endif

/* Official first.org EPSS API base URL (matches .env.example's CYTADEL_EPSS_URL
 * default). Used as the default when the caller passes NULL/empty. This driver
 * appends "?limit=<N>&offset=<M>" -- the URL must therefore NOT already carry a
 * query string of its own. */
#define CYTADEL_EPSS_DEFAULT_URL "https://api.first.org/data/v1/epss"

/* Default page size (limit=) when the caller passes 0. The first.org API may
 * cap this lower; the cursor advances by records actually returned, so a cap
 * costs extra pages but never skips data. */
#define CYTADEL_EPSS_SYNC_DEFAULT_PAGE_SIZE 2000

/* Hostile-input safety valve: the most pages a single sync will ever drive.
 * At even a 100-record server cap this covers 20M CVEs -- far beyond the real
 * feed -- so a legitimate pull never hits it; a response advertising an absurd
 * `total` just aborts the pull (ERR_PROTOCOL, watermark unchanged) rather than
 * looping unboundedly. */
#define CYTADEL_EPSS_SYNC_MAX_PAGES 200000

/* Ceiling enforced on the envelope's `total` before it is trusted (matches
 * nvd_sync's own CYTADEL_NVD_SYNC_MAX_TOTAL_RESULTS reasoning). */
#define CYTADEL_EPSS_SYNC_MAX_TOTAL 100000000L

typedef enum {
    CYTADEL_EPSS_SYNC_OK = 0,
    /* NULL db/cfg/out_counts -- caller bug, no I/O attempted. */
    CYTADEL_EPSS_SYNC_ERR_INVALID_ARG = 1,
    /* A page GET failed (transport after retries, 429/5xx exhaustion, auth/HTTP
     * status, size-cap abort). Watermark unchanged. */
    CYTADEL_EPSS_SYNC_ERR_FETCH = 2,
    /* A page was fetched but ingest reported a fatal/parse failure -- rolled
     * back, watermark unchanged. */
    CYTADEL_EPSS_SYNC_ERR_INGEST = 3,
    /* A page carried no usable `total`/`data` envelope, an empty page appeared
     * before `total` was reached, or the per-pull page cap was exceeded. The
     * driver cannot safely tell where the feed ends -- watermark unchanged. */
    CYTADEL_EPSS_SYNC_ERR_PROTOCOL = 4
} cytadel_epss_sync_status_t;

typedef struct {
    size_t pages_fetched;
    size_t epss_ingested; /* summed across pages */
    size_t epss_skipped;
} cytadel_epss_sync_counts_t;

/* Never returns NULL. */
const char *cytadel_epss_sync_status_to_string(cytadel_epss_sync_status_t status);

/* Pages the first.org EPSS feed from `epss_url` (NULL/empty ->
 * CYTADEL_EPSS_DEFAULT_URL) and ingests every page into `db` (already
 * migrated), advancing the feed='epss' watermark only once the final page has
 * committed. `page_size` <= 0 uses CYTADEL_EPSS_SYNC_DEFAULT_PAGE_SIZE. `cfg`
 * supplies transport tunables (its `base_url` is ignored). `*out_counts` is
 * zeroed on entry and always safe to read after the call. Returns
 * CYTADEL_EPSS_SYNC_OK only when the entire feed was fetched and committed. */
cytadel_epss_sync_status_t cytadel_epss_sync(cytadel_db_t *db, const cytadel_nvd_fetch_config_t *cfg,
                                             const char *epss_url, long page_size,
                                             cytadel_epss_sync_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_EPSS_SYNC_H */
