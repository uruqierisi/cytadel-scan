/* Milestone 7 (live NVD fetch slice): the delta-sync pagination driver.
 * See include/cytadel/db/nvd_sync.h for the module contract and the
 * watermark / crash-safety invariant this file exists to uphold. */

#include "cytadel/db/nvd_sync.h"

#include <cJSON.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/db/nvd_ingest.h"
#include "log.h"

/* Ceiling `parse_total_results()` enforces on a page's "totalResults" BEFORE
 * ever converting it from cJSON's double storage to a long (see that
 * function's doc comment for why the check must happen before the cast, not
 * after). 10^8 is already an order of magnitude above the real NVD CVE
 * corpus size, so no legitimate response is ever rejected by it; a hostile or
 * MITM'd response advertising anything above this (or a non-finite value) is
 * treated as a protocol error, identically to a negative or missing value. */
#define CYTADEL_NVD_SYNC_MAX_TOTAL_RESULTS 100000000L

const char *cytadel_nvd_sync_status_to_string(cytadel_nvd_sync_status_t status) {
    switch (status) {
        case CYTADEL_NVD_SYNC_OK:              return "OK";
        case CYTADEL_NVD_SYNC_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_NVD_SYNC_ERR_FETCH:       return "FETCH";
        case CYTADEL_NVD_SYNC_ERR_INGEST:      return "INGEST";
        case CYTADEL_NVD_SYNC_ERR_PROTOCOL:    return "PROTOCOL";
    }
    return "UNKNOWN";
}

/* Reads the top-level "totalResults" integer from one NVD 2.0 page body so
 * the driver can tell when a window is exhausted. The body is untrusted but
 * already size-bounded by the fetch layer; this is an independent, defensive
 * cJSON read (type-checked, no assumption the field exists) that does NOT
 * touch the DB -- the authoritative full parse/persist is the ingest layer's
 * job. Returns the count in [0, CYTADEL_NVD_SYNC_MAX_TOTAL_RESULTS], or -1 if
 * the field is absent, not a number, not finite (NaN/+-Inf), negative, above
 * that ceiling, or the document does not parse.
 *
 * The finite-and-in-range check below runs BEFORE `total->valuedouble` is
 * ever cast to `long`, and is the whole point of this function's shape: cJSON
 * stores a "totalResults" value as a plain double (it only clamps/truncates
 * into `valueint`, which this code never reads), so a hostile or MITM'd peer
 * can return a syntactically valid "totalResults":1e30. Casting an
 * out-of-range double to long is undefined behaviour in C, not just
 * "implementation-defined" -- on x86-64 `cvttsd2si` happens to produce
 * LONG_MIN for such an overflow (which a post-cast `< 0` check would still
 * catch), but AArch64's `FCVTZS` saturates to LONG_MAX instead, which would
 * silently look like a huge-but-"valid" totalResults and defeat the
 * pagination valve. Range-checking the double itself first makes the
 * eventual cast well-defined on every target this project builds for. */
static long parse_total_results(const char *body, size_t len) {
    cJSON *root = cJSON_ParseWithLength(body, len);
    if (root == NULL) {
        return -1;
    }
    long result = -1;
    const cJSON *total = cJSON_GetObjectItemCaseSensitive(root, "totalResults");
    if (cJSON_IsNumber(total)) {
        const double value = total->valuedouble;
        if (isfinite(value) && value >= 0.0 &&
            value <= (double)CYTADEL_NVD_SYNC_MAX_TOTAL_RESULTS) {
            result = (long)value;
        }
    }
    cJSON_Delete(root);
    return result;
}

cytadel_nvd_sync_status_t cytadel_nvd_sync_window(cytadel_db_t *db,
                                                  const cytadel_nvd_fetch_config_t *cfg,
                                                  const char *start_date, const char *end_date,
                                                  long max_pages,
                                                  cytadel_nvd_sync_counts_t *out_counts) {
    if (db == NULL || cfg == NULL || end_date == NULL || end_date[0] == '\0' ||
        out_counts == NULL) {
        cytadel_log_error("nvd_sync: window() called with a NULL/empty argument");
        return CYTADEL_NVD_SYNC_ERR_INVALID_ARG;
    }
    memset(out_counts, 0, sizeof(*out_counts));

    /* results_per_page is NOT clamped by the fetch layer -- nvd_fetch.h's own
     * CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE is never enforced anywhere in
     * that module, it is documentation of NVD's own ceiling only. This
     * driver therefore clamps it on both ends itself: a config of <= 0 is
     * floored to 1 (the startIndex stepping below must never advance by
     * <= 0, or the loop would never terminate), and a config above
     * CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE is capped down to it. The upper
     * clamp is not just cosmetic: an uncapped results_per_page (e.g. a
     * misconfigured 2000000000) combined with a large network-supplied
     * totalResults is exactly what drove `start_index += per_page` into
     * signed integer overflow (UB) below before this clamp existed. */
    int per_page = cfg->results_per_page;
    if (per_page < 1) {
        per_page = 1;
    } else if (per_page > CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE) {
        per_page = CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE;
    }

    const long effective_max_pages = max_pages > 0 ? max_pages : CYTADEL_NVD_SYNC_MAX_PAGES;

    /* Kept as a `long` accumulator (rather than stepping the `int` passed to
     * cytadel_nvd_fetch_page() directly) with an explicit bound check before
     * every use/increment, so this loop cannot reach a signed-int overflow on
     * `start_index += per_page` regardless of `per_page`'s clamp above or of
     * how large `effective_max_pages` is configured. */
    long start_index_l = 0;
    for (long page = 0; page < effective_max_pages; page++) {
        if (start_index_l > INT_MAX) {
            cytadel_log_warn("nvd_sync: startIndex accumulator exceeded INT_MAX -- abandoning "
                             "window, watermark left unchanged");
            return CYTADEL_NVD_SYNC_ERR_PROTOCOL;
        }
        const int start_index = (int)start_index_l;

        /* Bug fix (found while building the nvd_catchup.c multi-window
         * driver, which is the first caller to actually exercise the
         * start_date == NULL bulk-load path end-to-end): this header's own
         * doc comment for `start_date` is explicit -- "start_date == NULL
         * means the initial bulk load (no lastModStartDate/lastModEndDate
         * filter is sent)" -- i.e. NEITHER date is sent to the transport
         * layer for a bulk load, not just lastModStartDate. But
         * cytadel_nvd_fetch_page() requires BOTH last_mod_start_date/
         * last_mod_end_date to be set or BOTH unset (nvd_fetch.h: "passing
         * only one of the two is a caller bug, CYTADEL_NVD_FETCH_ERR_
         * INVALID_ARG"). Forwarding `end_date` unconditionally (as this
         * line used to) while `start_date` is NULL therefore violated that
         * contract and made every bulk-load call fail closed as
         * ERR_INVALID_ARG -- silently, since no earlier test ever drove
         * cytadel_nvd_sync_window() with start_date == NULL all the way
         * through to a real fetch_page() call. `end_date` itself is still
         * used, unconditionally, a few lines below as the watermark value
         * handed to cytadel_nvd_ingest_page() -- that part of the contract
         * (db-schema.md SS8 step 1: the bulk load still ends at, and
         * advances the watermark to, `end_date`) is unaffected; only the
         * outgoing HTTP query's date filter is suppressed for a bulk load. */
        const char *fetch_start_date = start_date;
        const char *fetch_end_date = (start_date != NULL) ? end_date : NULL;

        char *body = NULL;
        size_t len = 0;
        cytadel_nvd_fetch_status_t fetch_status =
            cytadel_nvd_fetch_page(cfg, start_index, fetch_start_date, fetch_end_date, &body, &len);
        if (fetch_status != CYTADEL_NVD_FETCH_OK) {
            cytadel_log_warn("nvd_sync: page fetch failed at startIndex=%d (%s) -- abandoning "
                             "window, watermark left unchanged",
                             start_index, cytadel_nvd_fetch_status_to_string(fetch_status));
            return CYTADEL_NVD_SYNC_ERR_FETCH;
        }

        const long total_results = parse_total_results(body, len);
        if (total_results < 0) {
            free(body);
            cytadel_log_warn("nvd_sync: page at startIndex=%d carried no usable totalResults -- "
                             "abandoning window, watermark left unchanged",
                             start_index);
            return CYTADEL_NVD_SYNC_ERR_PROTOCOL;
        }

        /* This is the final page of the window iff there are no more results
         * beyond the ones this page covers (or the corpus is empty). Only on
         * the final page does the ingest layer advance the watermark. */
        const bool is_last = (total_results == 0) ||
                             (start_index_l + per_page >= total_results);

        cytadel_nvd_ingest_counts_t page_counts;
        cytadel_nvd_ingest_status_t ingest_status =
            cytadel_nvd_ingest_page(db, body, len, end_date, is_last, &page_counts);
        free(body);
        if (ingest_status != CYTADEL_NVD_INGEST_OK) {
            cytadel_log_warn("nvd_sync: ingest failed at startIndex=%d (%s) -- watermark left "
                             "unchanged",
                             start_index, cytadel_nvd_ingest_status_to_string(ingest_status));
            return CYTADEL_NVD_SYNC_ERR_INGEST;
        }

        out_counts->pages_fetched++;
        out_counts->cve_ingested += page_counts.cve_ingested;
        out_counts->cve_skipped += page_counts.cve_skipped;

        /* Per-page progress so an operator watching a multi-hour sync can see
         * it is alive and how far along it is: which window, which page, what
         * this page ingested, and the running total for this window (measured
         * against the window's own advertised totalResults). Replaces the old
         * once-per-page "API key is set" line, which carried no progress. */
        cytadel_log_info(
            "nvd_sync: window [%s..%s] page %zu: +%zu ingested, +%zu skipped "
            "(%zu ingested / %ld total this window)",
            (start_date != NULL) ? start_date : "(bulk)", end_date, out_counts->pages_fetched,
            page_counts.cve_ingested, page_counts.cve_skipped, out_counts->cve_ingested, total_results);

        if (is_last) {
            cytadel_log_info("nvd_sync: window [%s..%s] complete -- %zu page(s), %zu ingested, "
                             "%zu skipped; watermark advanced to %s",
                             (start_date != NULL) ? start_date : "(bulk)", end_date,
                             out_counts->pages_fetched, out_counts->cve_ingested,
                             out_counts->cve_skipped, end_date);
            return CYTADEL_NVD_SYNC_OK;
        }
        start_index_l += per_page;
    }

    cytadel_log_warn("nvd_sync: window exceeded the %ld-page safety cap without reaching the end "
                     "(hostile totalResults?) -- watermark left unchanged",
                     effective_max_pages);
    return CYTADEL_NVD_SYNC_ERR_PROTOCOL;
}
