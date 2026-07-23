#ifndef CYTADEL_DB_KEV_SYNC_H
#define CYTADEL_DB_KEV_SYNC_H

#include <stddef.h>

#include "cytadel/db/db.h"
#include "cytadel/net/nvd_fetch.h"

/* KEV live-fetch driver: the transport half that feeds the already-tested
 * cytadel_kev_ingest() (src/db/kev_ingest.c). The CISA Known Exploited
 * Vulnerabilities catalog is a single JSON document (a few thousand entries),
 * so -- unlike the NVD delta sync -- this is ONE bounded GET, handed straight
 * to the ingest layer as one full pull (full_pull_complete=true), which
 * advances the feed='kev' watermark inside its own transaction.
 *
 * Same discipline as the NVD path: the GET rides cytadel_nvd_fetch_get()
 * (bounded response body, TLS verification always on, retry-with-backoff on
 * transport errors / 429 / 5xx, and the NVD apiKey NEVER sent to cisa.gov).
 * Per-record skip-and-log, placeholder-FK handling, and watermark atomicity
 * all live in cytadel_kev_ingest() and are unchanged here. A fetch or ingest
 * failure leaves the feed='kev' watermark exactly where it was -- no partial
 * state -- and the next run safely re-fetches the whole catalog (idempotent
 * via the ingest layer's ON CONFLICT upserts). */

#ifdef __cplusplus
extern "C" {
#endif

/* Official CISA KEV catalog JSON feed (matches .env.example's CYTADEL_KEV_URL
 * default). Only used as the default when the caller passes NULL/empty. */
#define CYTADEL_KEV_DEFAULT_URL \
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

typedef enum {
    CYTADEL_KEV_SYNC_OK = 0,
    /* NULL db/cfg/out_counts -- caller bug, no network or DB I/O attempted. */
    CYTADEL_KEV_SYNC_ERR_INVALID_ARG = 1,
    /* The HTTP GET failed (transport error after retries, 429/5xx exhaustion,
     * auth/HTTP status, or the size-cap abort). Nothing was ingested; the
     * watermark is unchanged. */
    CYTADEL_KEV_SYNC_ERR_FETCH = 2,
    /* The catalog was fetched but the ingest layer reported a fatal (ERR_DB)
     * or parse (ERR_PARSE) failure -- rolled back, watermark unchanged. */
    CYTADEL_KEV_SYNC_ERR_INGEST = 3
} cytadel_kev_sync_status_t;

typedef struct {
    size_t kev_ingested;
    size_t kev_skipped;
} cytadel_kev_sync_counts_t;

/* Never returns NULL. */
const char *cytadel_kev_sync_status_to_string(cytadel_kev_sync_status_t status);

/* Fetches the CISA KEV catalog from `kev_url` (NULL/empty ->
 * CYTADEL_KEV_DEFAULT_URL) and ingests it into `db` (already migrated) as one
 * full pull. `cfg` supplies the transport tunables (timeouts, retry/backoff,
 * response-size cap, CA bundle); its `base_url` field is ignored -- the URL is
 * passed to cytadel_nvd_fetch_get() verbatim. `*out_counts` is zeroed on entry
 * and always safe to read after the call. Returns CYTADEL_KEV_SYNC_OK only when
 * the catalog was fetched AND ingested (advancing the feed='kev' watermark). */
cytadel_kev_sync_status_t cytadel_kev_sync(cytadel_db_t *db, const cytadel_nvd_fetch_config_t *cfg,
                                           const char *kev_url, cytadel_kev_sync_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_KEV_SYNC_H */
