#define _POSIX_C_SOURCE 200809L /* strnlen(), nanosleep() -- see src/net/target.c for the same
                                 * project-wide convention. Must be defined before any header is
                                 * included. */

#include "cytadel/net/nvd_fetch.h"

#include <curl/curl.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h> /* strncasecmp() -- see src/net/http_probe.c for the same convention */
#include <time.h>

#include "log.h"

/* Milestone 7 slice 3: see include/cytadel/net/nvd_fetch.h for the full
 * design/contract this file implements, including the "hostile-response
 * discipline" list and the secret-hygiene contract for NVD_API_KEY. This is
 * the ONLY translation unit in this codebase that #includes <curl/curl.h> --
 * see that header's top-of-file "Scope" note for why. */

#define CYTADEL_NVD_FETCH_USER_AGENT "cytadel-scan-nvd-sync/1.0"

/* Generous headroom for "https://services.nvd.nist.gov/rest/json/cves/2.0"
 * plus resultsPerPage/startIndex/lastModStartDate/lastModEndDate query
 * params (each a percent-encoded ISO-8601 timestamp, ~30 bytes raw or up to
 * ~90 escaped in the worst case) -- real URLs built here are well under
 * 512 bytes; this leaves ample margin without ever being unbounded. */
#define CYTADEL_NVD_FETCH_URL_BUF_LEN 4096

/* "apiKey: " (8) + a key of at most CYTADEL_NVD_FETCH_APIKEY_MAX_LEN bytes +
 * NUL. A key longer than CYTADEL_NVD_FETCH_APIKEY_MAX_LEN is refused
 * outright (see append_api_key_header()) rather than ever being truncated
 * and sent as a silently-wrong value. */
#define CYTADEL_NVD_FETCH_APIKEY_MAX_LEN 256
#define CYTADEL_NVD_FETCH_APIKEY_HEADER_BUF_LEN (8 + CYTADEL_NVD_FETCH_APIKEY_MAX_LEN + 1)

const char *cytadel_nvd_fetch_status_to_string(cytadel_nvd_fetch_status_t status) {
    switch (status) {
        case CYTADEL_NVD_FETCH_OK:              return "OK";
        case CYTADEL_NVD_FETCH_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_NVD_FETCH_ERR_TRANSPORT:   return "TRANSPORT";
        case CYTADEL_NVD_FETCH_ERR_AUTH:        return "AUTH";
        case CYTADEL_NVD_FETCH_ERR_RATE_LIMITED: return "RATE_LIMITED";
        case CYTADEL_NVD_FETCH_ERR_SERVER:      return "SERVER";
        case CYTADEL_NVD_FETCH_ERR_HTTP:        return "HTTP";
    }
    return "UNKNOWN";
}

void cytadel_nvd_fetch_config_init_default(cytadel_nvd_fetch_config_t *cfg) {
    if (cfg == NULL) {
        return;
    }
    memset(cfg, 0, sizeof(*cfg));
    cfg->base_url = CYTADEL_NVD_FETCH_DEFAULT_BASE_URL;
    cfg->results_per_page = CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE;
    cfg->connect_timeout_sec = 10;
    cfg->total_timeout_sec = 60;
    cfg->low_speed_limit_bytes = 256;
    cfg->low_speed_time_sec = 30;
    cfg->max_response_bytes = CYTADEL_NVD_FETCH_DEFAULT_MAX_BODY_BYTES;
    cfg->max_retries = 5;
    cfg->backoff_initial_ms = 1000;
    cfg->backoff_max_ms = 30000;
    cfg->retry_after_max_sec = 60;
    cfg->ca_info_path = "/etc/ssl/certs/ca-certificates.crt";
}

/* curl_global_init() is documented as NOT thread-safe and must run before
 * any other libcurl call from any thread -- pthread_once() gives exactly
 * the "exactly once, safe under concurrent first callers" guarantee this
 * needs, matching src/log's own statically-initialized-mutex convention
 * (see log.c) for "no separate init/destroy call required". */
static pthread_once_t g_curl_global_init_once = PTHREAD_ONCE_INIT;
static void curl_global_init_once(void) {
    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        /* Not fatal here by itself -- a real failure to initialize libcurl
         * surfaces immediately afterward as curl_easy_init() returning NULL,
         * which IS handled/logged at every call site below. This is purely
         * an earlier, more specific diagnostic for that same condition. */
        cytadel_log_error("nvd_fetch: curl_global_init() failed (curl rc=%d): %s", (int)rc,
                           curl_easy_strerror(rc));
    }
}

/* ------------------------------------------------------------------ */
/* Bounded write callback -- hostile-response discipline item 1.       */
/* ------------------------------------------------------------------ */

typedef struct {
    char *buf;
    size_t len;
    size_t alloc_cap; /* current allocation size, including the trailing NUL slot */
    size_t hard_cap;  /* cfg->max_response_bytes for this attempt */
    bool aborted;     /* true iff this callback forced curl to abort the transfer */
} fetch_write_ctx_t;

static size_t fetch_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    fetch_write_ctx_t *ctx = userdata;
    if (size != 0 && nmemb > (size_t)-1 / size) {
        /* size*nmemb would overflow size_t. curl never actually does this
         * in practice, but a hostile/misbehaving transfer is exactly the
         * class of input this project's own posture requires guarding
         * against regardless of how the bytes reached this callback. */
        ctx->aborted = true;
        return 0;
    }
    size_t add = size * nmemb;
    if (add == 0) {
        return 0; /* trivially "consumed all 0 bytes" -- not an error */
    }
    if (add > ctx->hard_cap - ctx->len) {
        /* Accepting `add` more bytes would exceed the hard cap -- abort
         * NOW, before any of these bytes are copied in. A short return
         * (anything other than `add`) makes curl_easy_perform() fail with
         * CURLE_WRITE_ERROR; see do_one_attempt() below. */
        ctx->aborted = true;
        return 0;
    }
    if (ctx->len + add + 1 > ctx->alloc_cap) {
        size_t new_cap = (ctx->alloc_cap == 0) ? 8192 : ctx->alloc_cap;
        while (new_cap < ctx->len + add + 1) {
            if (new_cap > ((size_t)-1) / 2) {
                new_cap = ctx->len + add + 1;
                break;
            }
            new_cap *= 2;
        }
        if (new_cap > ctx->hard_cap + 1) {
            new_cap = ctx->hard_cap + 1;
        }
        char *nb = realloc(ctx->buf, new_cap);
        if (nb == NULL) {
            ctx->aborted = true;
            return 0;
        }
        ctx->buf = nb;
        ctx->alloc_cap = new_cap;
    }
    memcpy(ctx->buf + ctx->len, ptr, add);
    ctx->len += add;
    ctx->buf[ctx->len] = '\0';
    return add;
}

/* ------------------------------------------------------------------ */
/* NVD_API_KEY secret hygiene -- see nvd_fetch.h's top-of-file comment. */
/* ------------------------------------------------------------------ */

/* Returns true iff `url` begins with the "https://" scheme (case-insensitive
 * -- RFC 3986 3.1: scheme names are case-insensitive). NULL is treated as
 * not-https; defensive only (callers here already validate cfg->base_url is
 * non-NULL/non-empty before it ever reaches this function). */
static bool url_is_https(const char *url) {
    return url != NULL && strncasecmp(url, "https://", 8) == 0;
}

/* Best-effort defense-in-depth: overwrites `len` bytes of `buf` with zero in
 * a way the compiler cannot optimize away as a dead store (unlike a plain
 * memset(), which is legitimately eligible for dead-store elimination here
 * since nothing reads `buf` again before it goes out of scope). Writing
 * through a volatile pointer forces every store to actually happen -- this
 * avoids depending on glibc's explicit_bzero(), which needs _DEFAULT_SOURCE
 * (a feature-test macro this file does not otherwise need; see
 * src/net/icmp_probe.c's own top-of-file comment for why this codebase does
 * not define it in every translation unit). Not a substitute for disabling
 * core dumps -- see this function's call site's own comment. */
static void secure_zero(void *buf, size_t len) {
    volatile unsigned char *p = buf;
    while (len-- > 0) {
        *p++ = 0;
    }
}

/* Reads CYTADEL_NVD_API_KEY (CYTADEL_NVD_API_KEY_ENV_VAR) via getenv() --
 * and ONLY here, exactly once per fetch attempt -- and, iff it is set to a
 * non-empty value AND `base_url` is https://, appends an "apiKey: <value>"
 * entry to `headers` (curl_slist_append() copies the string internally into
 * memory libcurl owns; this function's own stack buffer is scrubbed via
 * secure_zero() before returning regardless of outcome). Every log line on
 * every path below names the environment variable and describes what
 * HAPPENED, never the value itself. Returns the (possibly unchanged) head of
 * `headers`. */
static struct curl_slist *append_api_key_header(struct curl_slist *headers, const char *base_url) {
    const char *key = getenv(CYTADEL_NVD_API_KEY_ENV_VAR);
    if (key == NULL || key[0] == '\0') {
        /* Per-attempt info logging is deliberately suppressed here: this runs
         * once per page and used to emit an identical "key is/ isn't set" line
         * on every page, drowning out real progress. The key's status is
         * instead logged exactly once per sync run by
         * cytadel_nvd_fetch_log_api_key_status(). */
        return headers;
    }

    if (!url_is_https(base_url)) {
        cytadel_log_warn(
            "nvd_fetch: %s is set but base_url is not https:// -- withholding the apiKey header "
            "to avoid ever sending it over cleartext (proceeding unauthenticated for this attempt; "
            "the value itself is never logged)",
            CYTADEL_NVD_API_KEY_ENV_VAR);
        return headers;
    }

    size_t key_len = strnlen(key, CYTADEL_NVD_FETCH_APIKEY_MAX_LEN + 1);
    if (key_len > CYTADEL_NVD_FETCH_APIKEY_MAX_LEN) {
        cytadel_log_error(
            "nvd_fetch: %s is set but implausibly long (> %d bytes) -- refusing to send a "
            "truncated (and therefore wrong) key; fix or unset %s to proceed (the value itself is "
            "never logged)",
            CYTADEL_NVD_API_KEY_ENV_VAR, CYTADEL_NVD_FETCH_APIKEY_MAX_LEN, CYTADEL_NVD_API_KEY_ENV_VAR);
        return headers;
    }

    char header_line[CYTADEL_NVD_FETCH_APIKEY_HEADER_BUF_LEN];
    struct curl_slist *result = headers;
    int n = snprintf(header_line, sizeof(header_line), "apiKey: %.*s", (int)key_len, key);
    if (n < 0 || (size_t)n >= sizeof(header_line)) {
        cytadel_log_error("nvd_fetch: internal error formatting the %s header -- proceeding "
                           "unauthenticated for this attempt",
                           CYTADEL_NVD_API_KEY_ENV_VAR);
    } else {
        struct curl_slist *updated = curl_slist_append(headers, header_line);
        if (updated == NULL) {
            cytadel_log_error("nvd_fetch: curl_slist_append() failed (out of memory) building the "
                               "%s header -- proceeding unauthenticated for this attempt",
                               CYTADEL_NVD_API_KEY_ENV_VAR);
        } else {
            /* Success path: no per-attempt log (see the not-set branch above);
             * the one-shot status line is cytadel_nvd_fetch_log_api_key_status(). */
            result = updated;
        }
    }

    secure_zero(header_line, sizeof(header_line));
    return result;
}

/* One-shot, human-facing API-key status line for the start of a sync run --
 * see nvd_fetch.h. Reads CYTADEL_NVD_API_KEY once (via getenv) but, exactly
 * like append_api_key_header(), NEVER logs the value itself, only whether it
 * is set and whether it will actually be sent (an https endpoint). Intended to
 * be called exactly once per sync run by the catch-up driver, replacing the
 * old once-per-page logging. */
void cytadel_nvd_fetch_log_api_key_status(const char *base_url) {
    const char *key = getenv(CYTADEL_NVD_API_KEY_ENV_VAR);
    if (key == NULL || key[0] == '\0') {
        cytadel_log_info(
            "nvd sync: %s is not set -- using NVD's unauthenticated rate limit (~5 requests/30s). "
            "Setting an API key raises this to ~50/30s and makes the initial bulk load far faster.",
            CYTADEL_NVD_API_KEY_ENV_VAR);
        return;
    }
    if (base_url != NULL && !url_is_https(base_url)) {
        cytadel_log_warn(
            "nvd sync: %s is set but the endpoint is not https:// -- the key will be withheld and "
            "requests proceed unauthenticated (the value itself is never logged)",
            CYTADEL_NVD_API_KEY_ENV_VAR);
        return;
    }
    cytadel_log_info(
        "nvd sync: %s is set -- sending authenticated requests (the value itself is never logged)",
        CYTADEL_NVD_API_KEY_ENV_VAR);
}

/* ------------------------------------------------------------------ */
/* URL construction.                                                   */
/* ------------------------------------------------------------------ */

/* Builds "{cfg->base_url}?resultsPerPage=N&startIndex=M[&lastModStartDate=
 * <escaped>&lastModEndDate=<escaped>]" into out_url (bounded, never
 * truncated silently -- returns false if it would not fit). `easy` is only
 * used for curl_easy_escape(); it may be (and, from
 * cytadel_nvd_fetch_page(), is) a short-lived handle distinct from the one
 * that later performs the actual request. */
static bool build_url(const cytadel_nvd_fetch_config_t *cfg, CURL *easy, int start_index,
                       const char *last_mod_start_date, const char *last_mod_end_date, char *out_url,
                       size_t out_url_cap) {
    int n = snprintf(out_url, out_url_cap, "%s?resultsPerPage=%d&startIndex=%d", cfg->base_url,
                      cfg->results_per_page, start_index);
    if (n < 0 || (size_t)n >= out_url_cap) {
        return false;
    }
    if (last_mod_start_date == NULL) {
        return true; /* initial bulk load -- no date filter, per db-schema.md SS8 step 1 */
    }

    char *esc_start = curl_easy_escape(easy, last_mod_start_date, 0);
    char *esc_end = curl_easy_escape(easy, last_mod_end_date, 0);
    bool ok = false;
    if (esc_start != NULL && esc_end != NULL) {
        size_t used = (size_t)n;
        int m = snprintf(out_url + used, out_url_cap - used, "&lastModStartDate=%s&lastModEndDate=%s",
                          esc_start, esc_end);
        ok = (m >= 0 && (size_t)m < out_url_cap - used);
    }
    curl_free(esc_start);
    curl_free(esc_end);
    return ok;
}

/* ------------------------------------------------------------------ */
/* One HTTP attempt (no retry logic here -- that lives in the public   */
/* entry point below, which drives this in a bounded loop).            */
/* ------------------------------------------------------------------ */

typedef enum {
    ATTEMPT_OK,
    ATTEMPT_RETRY_429,
    ATTEMPT_RETRY_5XX,
    /* A retryable transport failure: curl_easy_perform() returned a network-
     * level error (timeout, connection reset/refused, DNS failure, a peer that
     * closed with nothing sent, a truncated transfer). NVD times these out
     * routinely, so -- unlike ATTEMPT_TRANSPORT_FAIL below -- one of these does
     * NOT abandon the window on its own; it is retried with the same bounded
     * exponential backoff as a 5xx. */
    ATTEMPT_RETRY_TRANSPORT,
    ATTEMPT_AUTH_FAIL,
    ATTEMPT_HTTP_FAIL,
    /* A NON-retryable transport failure: our own defensive abort (the response
     * exceeded the size cap, or a local allocation failed) or a fail-closed
     * setopt/init error. Retrying cannot help and would only re-pull a hostile/
     * oversized body, so this abandons the window immediately. */
    ATTEMPT_TRANSPORT_FAIL
} attempt_result_t;

/* Performs exactly one GET against `url`. CURL* and curl_slist are freed on
 * EVERY path below -- there is no early return that skips either cleanup
 * call. On ATTEMPT_OK, `*out_body`/`*out_len` are the caller's to free();
 * every other outcome leaves them NULL/0 (the local write-ctx buffer, if
 * any was allocated, is freed here instead). */
static attempt_result_t do_one_attempt(const cytadel_nvd_fetch_config_t *cfg, const char *url,
                                        char **out_body, size_t *out_len, long *out_retry_after_sec) {
    *out_body = NULL;
    *out_len = 0;
    *out_retry_after_sec = 0;

    pthread_once(&g_curl_global_init_once, curl_global_init_once);

    CURL *easy = curl_easy_init();
    if (easy == NULL) {
        cytadel_log_error("nvd_fetch: curl_easy_init() failed");
        return ATTEMPT_TRANSPORT_FAIL;
    }

    struct curl_slist *headers = append_api_key_header(NULL, cfg->base_url);

    fetch_write_ctx_t ctx = {0};
    ctx.hard_cap = cfg->max_response_bytes;

    attempt_result_t result;

    /* Security-relevant options are set through this macro, which FAILS CLOSED:
     * if libcurl rejects one (CURLE_UNKNOWN_OPTION / CURLE_NOT_BUILT_IN -- e.g.
     * this module rebuilt against a libcurl older than 7.85, which predates
     * CURLOPT_PROTOCOLS_STR, or one compiled without TLS), we abandon the
     * attempt rather than perform a request with the protection silently
     * absent. Checking the return is the whole point: an unchecked setopt for
     * SSL_VERIFYPEER/VERIFYHOST turns "verification is always on" from an
     * enforced property into an unverified claim about the source text. */
#define CYTADEL_SETOPT_CRITICAL(opt, val)                                                          \
    do {                                                                                           \
        CURLcode setopt_rc_ = curl_easy_setopt(easy, (opt), (val));                                \
        if (setopt_rc_ != CURLE_OK) {                                                              \
            cytadel_log_error("nvd_fetch: curl_easy_setopt(%s) failed (curl rc=%d: %s) -- "         \
                               "refusing to proceed without this protection",                      \
                               #opt, (int)setopt_rc_, curl_easy_strerror(setopt_rc_));             \
            result = ATTEMPT_TRANSPORT_FAIL;                                                       \
            goto cleanup;                                                                          \
        }                                                                                          \
    } while (0)

    curl_easy_setopt(easy, CURLOPT_URL, url);
    curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(easy, CURLOPT_USERAGENT, CYTADEL_NVD_FETCH_USER_AGENT);
    curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT, cfg->connect_timeout_sec);
    curl_easy_setopt(easy, CURLOPT_TIMEOUT, cfg->total_timeout_sec);
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_LIMIT, cfg->low_speed_limit_bytes);
    curl_easy_setopt(easy, CURLOPT_LOW_SPEED_TIME, cfg->low_speed_time_sec);

    /* Redirect/protocol confinement: this module only ever speaks http(s), and
     * never follows a redirect, so a hostile or MITM'd endpoint cannot walk us
     * to file://, scp://, or an unintended host. */
    CYTADEL_SETOPT_CRITICAL(CURLOPT_FOLLOWLOCATION, 0L);
    CYTADEL_SETOPT_CRITICAL(CURLOPT_PROTOCOLS_STR, "http,https");
    CYTADEL_SETOPT_CRITICAL(CURLOPT_REDIR_PROTOCOLS_STR, "http,https");

    /* TLS verification is ALWAYS on -- hostile-response discipline item 3. No
     * configuration path in this module can turn either of these off, and
     * because both are set through CYTADEL_SETOPT_CRITICAL, a libcurl that
     * cannot honour them aborts the attempt instead of downgrading it. */
    CYTADEL_SETOPT_CRITICAL(CURLOPT_SSL_VERIFYPEER, 1L);
    CYTADEL_SETOPT_CRITICAL(CURLOPT_SSL_VERIFYHOST, 2L);
    if (cfg->ca_info_path != NULL && cfg->ca_info_path[0] != '\0') {
        CYTADEL_SETOPT_CRITICAL(CURLOPT_CAINFO, cfg->ca_info_path);
    }

#undef CYTADEL_SETOPT_CRITICAL

    curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, fetch_write_cb);
    curl_easy_setopt(easy, CURLOPT_WRITEDATA, &ctx);

    CURLcode rc = curl_easy_perform(easy);

    if (rc != CURLE_OK) {
        free(ctx.buf);
        if (ctx.aborted) {
            /* Our own size-cap / allocation abort -- NOT retryable (retrying
             * would just re-pull the same oversized/hostile body). */
            cytadel_log_warn(
                "nvd_fetch: response body aborted (exceeded the %zu-byte cap, or a local allocation "
                "failure) -- treating this page as a failed fetch (not retried)",
                cfg->max_response_bytes);
            result = ATTEMPT_TRANSPORT_FAIL;
        } else {
            /* A genuine network-level error (timeout, reset, DNS, short/empty
             * transfer) -- retryable with bounded backoff. */
            cytadel_log_warn("nvd_fetch: transport error (curl rc=%d): %s -- will retry if attempts remain",
                              (int)rc, curl_easy_strerror(rc));
            result = ATTEMPT_RETRY_TRANSPORT;
        }
    } else {
        long http_status = 0;
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &http_status);

        if (http_status == 200) {
            *out_body = ctx.buf; /* ownership transferred to the caller */
            *out_len = ctx.len;
            result = ATTEMPT_OK;
        } else if (http_status == 429) {
            struct curl_header *h = NULL;
            if (curl_easy_header(easy, "Retry-After", 0, CURLH_HEADER, -1, &h) == CURLHE_OK && h != NULL &&
                h->value != NULL) {
                errno = 0;
                char *endptr = NULL;
                long v = strtol(h->value, &endptr, 10);
                if (errno == 0 && endptr != h->value && v >= 0) {
                    *out_retry_after_sec = v;
                }
            }
            cytadel_log_warn("nvd_fetch: HTTP 429 (rate limited)%s",
                              (*out_retry_after_sec > 0) ? " with a Retry-After hint" : "");
            free(ctx.buf);
            result = ATTEMPT_RETRY_429;
        } else if (http_status >= 500 && http_status <= 599) {
            cytadel_log_warn("nvd_fetch: HTTP %ld (server error)", http_status);
            free(ctx.buf);
            result = ATTEMPT_RETRY_5XX;
        } else if (http_status == 401 || http_status == 403) {
            cytadel_log_error(
                "nvd_fetch: HTTP %ld -- authentication failed (bad/missing %s); never retried",
                http_status, CYTADEL_NVD_API_KEY_ENV_VAR);
            free(ctx.buf);
            result = ATTEMPT_AUTH_FAIL;
        } else {
            cytadel_log_error("nvd_fetch: unexpected HTTP status %ld", http_status);
            free(ctx.buf);
            result = ATTEMPT_HTTP_FAIL;
        }
    }

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(easy);
    return result;
}

/* ------------------------------------------------------------------ */
/* Retry/backoff scheduling (429 Retry-After / 5xx exponential+jitter). */
/* ------------------------------------------------------------------ */

/* xorshift32 -- a fast, tiny, NON-cryptographic PRNG used only to jitter
 * retry delays (spread out otherwise-synchronized retries after a shared
 * outage; never a security control). Avoids any dependency on rand_r()'s
 * feature-test-macro visibility or on mutating the process-wide rand()
 * state other threads might rely on. */
static unsigned int fetch_prng_next(unsigned int *state) {
    unsigned int x = *state;
    if (x == 0) {
        x = 0x9e3779b9u; /* never let a zero seed produce an all-zero stream */
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

/* delay_ms = min(backoff_max_ms, backoff_initial_ms * 2^(attempt-1)), plus
 * up to +/-25% jitter. `attempt` is 1-based (the first retry is attempt 1).
 * Never returns a negative delay. */
static long compute_backoff_ms(const cytadel_nvd_fetch_config_t *cfg, int attempt) {
    long delay = cfg->backoff_initial_ms;
    if (delay < 0) {
        delay = 0;
    }
    for (int i = 1; i < attempt; i++) {
        if (delay >= cfg->backoff_max_ms - delay) {
            delay = cfg->backoff_max_ms;
            break;
        }
        delay *= 2;
    }
    if (delay > cfg->backoff_max_ms) {
        delay = cfg->backoff_max_ms;
    }

    unsigned int seed = (unsigned int)time(NULL) ^ (unsigned int)(uintptr_t)&seed ^ (unsigned int)attempt;
    long jitter_span = delay / 4;
    long jitter = 0;
    if (jitter_span > 0) {
        unsigned int span2 = (unsigned int)(jitter_span * 2 + 1);
        jitter = (long)(fetch_prng_next(&seed) % span2) - jitter_span;
    }
    delay += jitter;
    return (delay < 0) ? 0 : delay;
}

static void fetch_sleep_ms(long ms) {
    if (ms <= 0) {
        return;
    }
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * 1000000L;
    nanosleep(&ts, NULL); /* best-effort: an EINTR-shortened sleep just makes the next retry fire a
                           * little sooner, never a correctness issue for this bounded retry loop. */
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

cytadel_nvd_fetch_status_t cytadel_nvd_fetch_page(const cytadel_nvd_fetch_config_t *cfg, int start_index,
                                                   const char *last_mod_start_date,
                                                   const char *last_mod_end_date, char **out_body,
                                                   size_t *out_len) {
    if (out_body != NULL) {
        *out_body = NULL;
    }
    if (out_len != NULL) {
        *out_len = 0;
    }
    if (cfg == NULL || cfg->base_url == NULL || cfg->base_url[0] == '\0' || out_body == NULL ||
        out_len == NULL || start_index < 0) {
        cytadel_log_error("nvd_fetch: fetch_page() called with a NULL cfg/out_body/out_len, an empty "
                           "cfg->base_url, or a negative start_index");
        return CYTADEL_NVD_FETCH_ERR_INVALID_ARG;
    }
    bool has_start = (last_mod_start_date != NULL && last_mod_start_date[0] != '\0');
    bool has_end = (last_mod_end_date != NULL && last_mod_end_date[0] != '\0');
    if (has_start != has_end) {
        cytadel_log_error("nvd_fetch: fetch_page() called with exactly one of "
                           "last_mod_start_date/last_mod_end_date set -- both or neither is required");
        return CYTADEL_NVD_FETCH_ERR_INVALID_ARG;
    }

    pthread_once(&g_curl_global_init_once, curl_global_init_once);

    /* A short-lived easy handle purely so curl_easy_escape() has a `CURL *`
     * to hang off of -- unrelated to (and cleaned up well before) the easy
     * handle each retry attempt below creates for the actual request. */
    CURL *url_helper = curl_easy_init();
    if (url_helper == NULL) {
        cytadel_log_error("nvd_fetch: curl_easy_init() failed while building the request URL");
        return CYTADEL_NVD_FETCH_ERR_TRANSPORT;
    }
    char url[CYTADEL_NVD_FETCH_URL_BUF_LEN];
    bool built = build_url(cfg, url_helper, start_index, has_start ? last_mod_start_date : NULL,
                            has_end ? last_mod_end_date : NULL, url, sizeof(url));
    curl_easy_cleanup(url_helper);
    if (!built) {
        cytadel_log_error("nvd_fetch: failed to build the request URL (unexpectedly long inputs)");
        return CYTADEL_NVD_FETCH_ERR_INVALID_ARG;
    }

    int attempt = 0;
    for (;;) {
        char *body = NULL;
        size_t len = 0;
        long retry_after_sec = 0;
        attempt_result_t r = do_one_attempt(cfg, url, &body, &len, &retry_after_sec);

        if (r == ATTEMPT_OK) {
            *out_body = body;
            *out_len = len;
            return CYTADEL_NVD_FETCH_OK;
        }
        if (r == ATTEMPT_TRANSPORT_FAIL) {
            return CYTADEL_NVD_FETCH_ERR_TRANSPORT; /* non-retryable (our abort / setopt failure) */
        }
        if (r == ATTEMPT_AUTH_FAIL) {
            return CYTADEL_NVD_FETCH_ERR_AUTH;
        }
        if (r == ATTEMPT_HTTP_FAIL) {
            return CYTADEL_NVD_FETCH_ERR_HTTP;
        }

        /* Only the retryable classes remain -- ATTEMPT_RETRY_429 /
         * ATTEMPT_RETRY_5XX / ATTEMPT_RETRY_TRANSPORT -- all bounded by
         * cfg->max_retries, never an unbounded loop. */
        attempt++;
        if (attempt > cfg->max_retries) {
            const char *why = (r == ATTEMPT_RETRY_429)   ? "rate limited"
                              : (r == ATTEMPT_RETRY_5XX) ? "server error"
                                                         : "transport error";
            cytadel_log_error("nvd_fetch: giving up after %d retr%s (%s)", cfg->max_retries,
                               (cfg->max_retries == 1) ? "y" : "ies", why);
            if (r == ATTEMPT_RETRY_429) {
                return CYTADEL_NVD_FETCH_ERR_RATE_LIMITED;
            }
            if (r == ATTEMPT_RETRY_5XX) {
                return CYTADEL_NVD_FETCH_ERR_SERVER;
            }
            return CYTADEL_NVD_FETCH_ERR_TRANSPORT;
        }

        long delay_ms;
        if (r == ATTEMPT_RETRY_429 && retry_after_sec > 0) {
            long capped = (retry_after_sec > cfg->retry_after_max_sec) ? cfg->retry_after_max_sec
                                                                        : retry_after_sec;
            delay_ms = capped * 1000;
        } else {
            delay_ms = compute_backoff_ms(cfg, attempt);
        }
        cytadel_log_info("nvd_fetch: retrying in %ld ms (attempt %d/%d)", delay_ms, attempt, cfg->max_retries);
        fetch_sleep_ms(delay_ms);
    }
}
