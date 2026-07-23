/* EPSS live-fetch driver -- see include/cytadel/db/epss_sync.h for the
 * contract. Paginated limit/offset loop over the first.org EPSS API, each page
 * handed to the frozen, already-tested cytadel_epss_ingest(); the feed='epss'
 * watermark advances only on the final page. */

#include "cytadel/db/epss_sync.h"

#include <cJSON.h>
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "cytadel/db/epss_ingest.h"
#include "log.h"

/* Generous headroom for "<base_url>?limit=<int>&offset=<long>"; real URLs are
 * well under this, and build_page_url() below fails closed rather than ever
 * truncating silently. */
#define CYTADEL_EPSS_SYNC_URL_BUF_LEN 1024

const char *cytadel_epss_sync_status_to_string(cytadel_epss_sync_status_t status) {
    switch (status) {
        case CYTADEL_EPSS_SYNC_OK:              return "OK";
        case CYTADEL_EPSS_SYNC_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_EPSS_SYNC_ERR_FETCH:       return "FETCH";
        case CYTADEL_EPSS_SYNC_ERR_INGEST:      return "INGEST";
        case CYTADEL_EPSS_SYNC_ERR_PROTOCOL:    return "PROTOCOL";
    }
    return "UNKNOWN";
}

/* Reads the envelope's top-level `total` (number) and the length of its `data`
 * array. Both are required: without `total` the driver cannot tell where the
 * feed ends. The finite/in-range check runs BEFORE the double->long cast (same
 * defensive reasoning as nvd_sync's parse_total_results). Returns false if the
 * body does not parse, is not an object, `total` is absent/non-numeric/out of
 * range, or `data` is absent/not an array. */
static bool parse_envelope(const char *body, size_t len, long *out_total, long *out_data_count) {
    cJSON *root = cJSON_ParseWithLength(body, len);
    if (root == NULL) {
        return false;
    }
    bool ok = false;
    const cJSON *total = cJSON_GetObjectItemCaseSensitive(root, "total");
    const cJSON *data = cJSON_GetObjectItemCaseSensitive(root, "data");
    if (cJSON_IsNumber(total) && cJSON_IsArray(data)) {
        const double tv = total->valuedouble;
        if (isfinite(tv) && tv >= 0.0 && tv <= (double)CYTADEL_EPSS_SYNC_MAX_TOTAL) {
            *out_total = (long)tv;
            *out_data_count = (long)cJSON_GetArraySize(data);
            ok = true;
        }
    }
    cJSON_Delete(root);
    return ok;
}

static bool build_page_url(const char *base_url, long limit, long offset, char *out, size_t out_cap) {
    int n = snprintf(out, out_cap, "%s?limit=%ld&offset=%ld", base_url, limit, offset);
    return n > 0 && (size_t)n < out_cap;
}

cytadel_epss_sync_status_t cytadel_epss_sync(cytadel_db_t *db, const cytadel_nvd_fetch_config_t *cfg,
                                             const char *epss_url, long page_size,
                                             cytadel_epss_sync_counts_t *out_counts) {
    if (out_counts != NULL) {
        out_counts->pages_fetched = 0;
        out_counts->epss_ingested = 0;
        out_counts->epss_skipped = 0;
    }
    if (db == NULL || cfg == NULL || out_counts == NULL) {
        cytadel_log_error("epss_sync: called with a NULL db/cfg/out_counts");
        return CYTADEL_EPSS_SYNC_ERR_INVALID_ARG;
    }

    const char *base_url =
        (epss_url != NULL && epss_url[0] != '\0') ? epss_url : CYTADEL_EPSS_DEFAULT_URL;
    long limit = (page_size > 0) ? page_size : CYTADEL_EPSS_SYNC_DEFAULT_PAGE_SIZE;

    long offset = 0;
    for (long page = 0; page < CYTADEL_EPSS_SYNC_MAX_PAGES; page++) {
        char url[CYTADEL_EPSS_SYNC_URL_BUF_LEN];
        if (!build_page_url(base_url, limit, offset, url, sizeof(url))) {
            cytadel_log_error("epss_sync: request URL too long at offset=%ld -- aborting", offset);
            return CYTADEL_EPSS_SYNC_ERR_PROTOCOL;
        }

        char *body = NULL;
        size_t len = 0;
        cytadel_nvd_fetch_status_t fetch_status = cytadel_nvd_fetch_get(cfg, url, &body, &len);
        if (fetch_status != CYTADEL_NVD_FETCH_OK) {
            cytadel_log_warn("epss_sync: page fetch failed at offset=%ld (%s) -- watermark unchanged",
                             offset, cytadel_nvd_fetch_status_to_string(fetch_status));
            return CYTADEL_EPSS_SYNC_ERR_FETCH;
        }

        long total = 0, data_count = 0;
        if (!parse_envelope(body, len, &total, &data_count)) {
            free(body);
            cytadel_log_warn("epss_sync: page at offset=%ld carried no usable total/data envelope -- "
                             "watermark unchanged",
                             offset);
            return CYTADEL_EPSS_SYNC_ERR_PROTOCOL;
        }

        /* The feed is exhausted once this page reaches `total`. An empty page
         * BEFORE `total` is reached (offset>0) is a truncated/anomalous pull:
         * refuse to advance the watermark on it. */
        const bool is_last = (offset + data_count >= total);
        if (data_count == 0 && !is_last) {
            free(body);
            cytadel_log_warn("epss_sync: empty page at offset=%ld but total=%ld not reached -- "
                             "abandoning pull, watermark unchanged",
                             offset, total);
            return CYTADEL_EPSS_SYNC_ERR_PROTOCOL;
        }

        cytadel_epss_ingest_counts_t ic;
        cytadel_epss_ingest_status_t ingest_status = cytadel_epss_ingest(db, body, len, is_last, &ic);
        free(body);
        if (ingest_status != CYTADEL_EPSS_INGEST_OK) {
            cytadel_log_warn("epss_sync: ingest failed at offset=%ld (%s) -- watermark unchanged",
                             offset, cytadel_epss_ingest_status_to_string(ingest_status));
            return CYTADEL_EPSS_SYNC_ERR_INGEST;
        }

        out_counts->pages_fetched++;
        out_counts->epss_ingested += ic.epss_ingested;
        out_counts->epss_skipped += ic.epss_skipped;

        cytadel_log_info("epss_sync: page %zu (offset=%ld): +%zu ingested, +%zu skipped "
                         "(%zu / %ld total)",
                         out_counts->pages_fetched, offset, ic.epss_ingested, ic.epss_skipped,
                         out_counts->epss_ingested, total);

        if (is_last) {
            cytadel_log_info("epss_sync: complete -- %zu page(s), %zu ingested, %zu skipped; "
                             "watermark advanced",
                             out_counts->pages_fetched, out_counts->epss_ingested,
                             out_counts->epss_skipped);
            return CYTADEL_EPSS_SYNC_OK;
        }

        /* Advance by records ACTUALLY returned, so a server-side limit cap
         * (fewer than `limit`) never skips records. data_count > 0 here (the
         * data_count==0 && !is_last case returned above), so the offset always
         * advances and the loop cannot spin. */
        offset += data_count;
    }

    cytadel_log_warn("epss_sync: exceeded the %d-page safety cap without reaching total -- "
                     "watermark unchanged",
                     CYTADEL_EPSS_SYNC_MAX_PAGES);
    return CYTADEL_EPSS_SYNC_ERR_PROTOCOL;
}
