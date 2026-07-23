/* KEV live-fetch driver -- see include/cytadel/db/kev_sync.h for the contract.
 * One bounded GET of the CISA KEV catalog, handed to the frozen, already-tested
 * cytadel_kev_ingest() as a single full pull. */

#include "cytadel/db/kev_sync.h"

#include <stdlib.h>

#include "cytadel/db/kev_ingest.h"
#include "log.h"

const char *cytadel_kev_sync_status_to_string(cytadel_kev_sync_status_t status) {
    switch (status) {
        case CYTADEL_KEV_SYNC_OK:              return "OK";
        case CYTADEL_KEV_SYNC_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_KEV_SYNC_ERR_FETCH:       return "FETCH";
        case CYTADEL_KEV_SYNC_ERR_INGEST:      return "INGEST";
    }
    return "UNKNOWN";
}

cytadel_kev_sync_status_t cytadel_kev_sync(cytadel_db_t *db, const cytadel_nvd_fetch_config_t *cfg,
                                           const char *kev_url, cytadel_kev_sync_counts_t *out_counts) {
    if (out_counts != NULL) {
        out_counts->kev_ingested = 0;
        out_counts->kev_skipped = 0;
    }
    if (db == NULL || cfg == NULL || out_counts == NULL) {
        cytadel_log_error("kev_sync: called with a NULL db/cfg/out_counts");
        return CYTADEL_KEV_SYNC_ERR_INVALID_ARG;
    }

    const char *url = (kev_url != NULL && kev_url[0] != '\0') ? kev_url : CYTADEL_KEV_DEFAULT_URL;

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t fetch_status = cytadel_nvd_fetch_get(cfg, url, &body, &len);
    if (fetch_status != CYTADEL_NVD_FETCH_OK) {
        cytadel_log_warn("kev_sync: KEV catalog fetch failed (%s) -- watermark left unchanged",
                         cytadel_nvd_fetch_status_to_string(fetch_status));
        return CYTADEL_KEV_SYNC_ERR_FETCH;
    }

    cytadel_log_info("kev_sync: fetched CISA KEV catalog (%zu bytes) -- ingesting", len);

    /* The KEV catalog is a single document: one full pull, so full_pull_complete
     * = true (advances the feed='kev' watermark inside the ingest transaction). */
    cytadel_kev_ingest_counts_t ic;
    cytadel_kev_ingest_status_t ingest_status = cytadel_kev_ingest(db, body, len, true, &ic);
    free(body);
    if (ingest_status != CYTADEL_KEV_INGEST_OK) {
        cytadel_log_warn("kev_sync: KEV ingest failed (%s) -- watermark left unchanged",
                         cytadel_kev_ingest_status_to_string(ingest_status));
        return CYTADEL_KEV_SYNC_ERR_INGEST;
    }

    out_counts->kev_ingested = ic.kev_ingested;
    out_counts->kev_skipped = ic.kev_skipped;
    cytadel_log_info("kev_sync: complete -- %zu ingested, %zu skipped; watermark advanced",
                     ic.kev_ingested, ic.kev_skipped);
    return CYTADEL_KEV_SYNC_OK;
}
