#ifndef CYTADEL_NET_NVD_FETCH_H
#define CYTADEL_NET_NVD_FETCH_H

#include <stddef.h>

/* Milestone 7 slice 3 ("live NVD fetch"): a single-page HTTPS client for
 * NVD's 2.0 CVE API (docs/contracts/db-schema.md SS8's "NVD delta-sync
 * procedure" -- this module is the fetch half of that procedure; the
 * window/pagination driver that decides WHAT to fetch and WHEN a window is
 * complete lives in src/db/nvd_sync.c, one layer up, and calls
 * cytadel_nvd_fetch_page() below once per page).
 *
 * Scope, deliberately narrow: HTTP(S) transport only. This is the ONLY
 * translation unit in this codebase that #includes <curl/curl.h> --
 * everything in nvd_fetch.c is libcurl-specific plumbing (CURL* easy-handle
 * lifecycle, CURLOPT_* configuration, retry/backoff for 429/5xx, the
 * bounded write-callback). It has NO knowledge of NVD's JSON shape, does NOT
 * parse "totalResults" or "vulnerabilities", and NEVER touches the DB --
 * those are src/db/nvd_sync.c's job (the pagination driver) and
 * src/db/nvd_ingest.c's job (the frozen slice-2 ingest), respectively. This
 * mirrors db-schema.md's own module boundary: "the engine (C) ... stay
 * cleanly separated" applied one level deeper, to transport-vs-orchestration
 * within the engine itself.
 *
 * HOSTILE-RESPONSE DISCIPLINE (this milestone's task brief, same posture as
 * nvd_ingest.h's own "the input is hostile" framing -- here the "input" is
 * an untrusted HTTP response from a network peer, not just untrusted JSON):
 *
 *   1. Every response body is accumulated into a buffer with a HARD byte
 *      cap (`cytadel_nvd_fetch_config_t.max_response_bytes`, defaulting to
 *      CYTADEL_NVD_FETCH_DEFAULT_MAX_BODY_BYTES -- the same 64 MiB slice-2's
 *      own CYTADEL_NVD_PAGE_MAX_BYTES uses, kept as a separately-named
 *      constant here since nvd_ingest.h does not expose its own). Exceeding
 *      it aborts the transfer via a short return from the write callback
 *      (forces CURLE_WRITE_ERROR out of curl_easy_perform()) -- this is
 *      never "buffer everything, check the length afterward": the abort
 *      happens mid-transfer, before any more of a hostile/oversized body is
 *      ever accepted into memory.
 *   2. CURLOPT_CONNECTTIMEOUT, CURLOPT_TIMEOUT (total), and
 *      CURLOPT_LOW_SPEED_LIMIT/CURLOPT_LOW_SPEED_TIME (a stalled-but-still-
 *      open connection, trickling bytes too slowly to ever hit the total
 *      timeout, is aborted too) are always set from the config -- a hung or
 *      malicious server can never block this call forever.
 *   3. TLS verification is always requested (CURLOPT_SSL_VERIFYPEER=1,
 *      CURLOPT_SSL_VERIFYHOST=2) and this module contains NO option that
 *      could ever ask curl to disable it -- there is no "insecure" flag
 *      anywhere in cytadel_nvd_fetch_config_t. `ca_info_path` only ever
 *      narrows *which* trust store curl consults (CURLOPT_CAINFO), it can
 *      never widen trust or skip verification. This is runtime-enforced, not
 *      just source-level: the curl_easy_setopt() calls for
 *      CURLOPT_SSL_VERIFYPEER, CURLOPT_SSL_VERIFYHOST, CURLOPT_PROTOCOLS_STR,
 *      and (when set) CURLOPT_CAINFO each have their CURLcode checked, and
 *      ANY of them returning anything other than CURLE_OK (e.g. a rebuild
 *      against an older/differently-configured libcurl that does not support
 *      one of these options) fails the attempt closed as
 *      CYTADEL_NVD_FETCH_ERR_TRANSPORT rather than silently performing the
 *      request with that control possibly unset.
 *   4. HTTP status handling (nvd_fetch.c's own do_one_attempt()/
 *      cytadel_nvd_fetch_page()): 200 succeeds; 429 reads Retry-After
 *      (capped at `retry_after_max_sec`) and retries; 5xx retries with
 *      exponential backoff + jitter; 401/403 fail immediately as
 *      CYTADEL_NVD_FETCH_ERR_AUTH (never retried -- a bad/missing key does
 *      not get "fixed" by trying again); any other unexpected status fails
 *      immediately as CYTADEL_NVD_FETCH_ERR_HTTP. Every retry path is bounded
 *      by `max_retries` -- there is no unbounded retry loop.
 *   5. A network-level transport failure (connect refused, TLS handshake
 *      failure, timeout, a peer that closes having sent nothing, or a
 *      truncated/short transfer where curl detects fewer bytes arrived than
 *      Content-Length promised) IS retried, bounded by `max_retries`, with the
 *      same exponential-backoff-plus-jitter schedule as a 5xx -- NVD times out
 *      routinely and a single such hiccup must not abandon a whole window.
 *      Only once every retry is exhausted does it surface as
 *      CYTADEL_NVD_FETCH_ERR_TRANSPORT. The ONE transport outcome that is
 *      never retried is this module's OWN defensive abort -- the write-callback
 *      size-cap (item 1) tripping, or a local allocation failure -- since
 *      retrying that would merely re-pull the same oversized/hostile body; it
 *      returns CYTADEL_NVD_FETCH_ERR_TRANSPORT immediately.
 *
 * SECRET HYGIENE (project rule 4, this milestone's task brief): the NVD
 * API key is read via getenv(CYTADEL_NVD_API_KEY_ENV_VAR) ONLY inside
 * nvd_fetch.c's own request-building helper, exactly once per attempt, and
 * is bound directly into a `curl_slist` HTTP header ("apiKey: <value>") that
 * libcurl owns for the lifetime of that one curl_easy_perform() call. The
 * key value is NEVER formatted into any cytadel_log_*() call, any returned
 * status/string, or the request URL (NVD 2.0 takes the key as a header,
 * never a query param -- this module never places it in the URL). Missing/
 * empty CYTADEL_NVD_API_KEY is logged (that the var is unset, never a value)
 * and the request simply proceeds with no apiKey header -- NVD's own
 * documented unauthenticated rate limit applies, this module does not treat
 * that as an error.
 *
 * The apiKey header is additionally only ever attached when `base_url`'s
 * scheme is https:// -- an implausibly long key (> 256 bytes) is refused
 * outright (never clipped and sent as a silently-wrong value) rather than
 * truncated, and a non-https `base_url` (e.g. a misconfigured/tampered
 * CYTADEL_NVD_API_URL override, should a future slice ever wire one) causes
 * the key to be withheld and a warning logged (again, naming the fact, never
 * the value) instead of ever letting the key go out over cleartext HTTP.
 * `http://` remains an accepted URL scheme purely so this module's own test
 * suite can point `base_url` at a loopback fixture server -- see
 * tests/unit/test_nvd_sync.c. */

#ifdef __cplusplus
extern "C" {
#endif

/* The name of the environment variable this module reads the NVD API key
 * from. Matches .env.example's CYTADEL_NVD_API_KEY -- keeping the
 * CYTADEL_ prefix consistent with every other variable that file ships
 * (CYTADEL_DB_PATH, CYTADEL_NVD_API_URL, etc.) so an operator who copies
 * .env.example to .env and fills it in gets a working key, rather than one
 * silently read by nothing. Secret-hygiene policy / this milestone's task brief:
 * optional, never hardcoded, never logged. Exposed as a named constant
 * (rather than a string literal repeated at every call site) so a test can
 * assert against it and so there is exactly one place in this header
 * documenting the contract. */
#define CYTADEL_NVD_API_KEY_ENV_VAR "CYTADEL_NVD_API_KEY"

/* Logs a single, human-facing line describing whether the NVD API key is set
 * (and, when set, whether it will actually be sent -- i.e. the endpoint is
 * https://). Reads CYTADEL_NVD_API_KEY via getenv() but, exactly like the
 * per-request header builder, NEVER logs the value itself. This exists so a
 * sync run reports the key's status EXACTLY ONCE at startup, instead of the
 * per-page fetch layer repeating an identical line for every page of a
 * multi-hour bulk load. `base_url` may be NULL (treated as "not https"). */
void cytadel_nvd_fetch_log_api_key_status(const char *base_url);

/* Official NVD 2.0 CVE API base URL (docs/build-plan.md's own dependency
 * table; matches .env.example's CYTADEL_NVD_API_URL default). Only ever
 * used as `cytadel_nvd_fetch_config_t.base_url`'s default -- tests
 * deliberately override `base_url` to point at a loopback fixture server
 * instead (see this header's own top-of-file "Scope" note and
 * tests/unit/test_nvd_fetch.c), which is what makes every hostile-response
 * class below fully unit-testable without ever touching the real network. */
#define CYTADEL_NVD_FETCH_DEFAULT_BASE_URL "https://services.nvd.nist.gov/rest/json/cves/2.0"

/* Hard cap on a single page's response body, enforced BEFORE the body is
 * ever handed to anything else (checked inside the libcurl write callback
 * itself, aborting the transfer the instant it would be exceeded -- see
 * this header's top-of-file "hostile-response discipline" item 1). Matches
 * nvd_ingest.h's own CYTADEL_NVD_PAGE_MAX_BYTES (64 MiB) -- kept as a
 * separate constant here since that header does not expose its own value
 * for other translation units to depend on. */
#define CYTADEL_NVD_FETCH_DEFAULT_MAX_BODY_BYTES ((size_t)64 * 1024 * 1024)

/* NVD 2.0's own documented ceiling on resultsPerPage. */
#define CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE 2000

typedef enum {
    CYTADEL_NVD_FETCH_OK = 0,
    /* NULL cfg/out_body/out_len, an empty/NULL cfg->base_url, or a
     * start_index < 0 -- caller bug, no network I/O was ever attempted. */
    CYTADEL_NVD_FETCH_ERR_INVALID_ARG = 1,
    /* A transport-level failure: connection refused/timed out, TLS
     * handshake failure, the bounded write-callback aborting an oversized
     * transfer, or curl detecting a truncated/short transfer (fewer bytes
     * arrived than the response's own Content-Length promised). NEVER
     * retried by this module -- see this header's top-of-file item 5. */
    CYTADEL_NVD_FETCH_ERR_TRANSPORT = 2,
    /* HTTP 401 or 403 -- a missing/bad/rejected API key. Logged loudly
     * (status code + the fact that authentication failed), but the key
     * VALUE itself is never included anywhere in that log line. Never
     * retried: an auth failure does not resolve itself by trying again. */
    CYTADEL_NVD_FETCH_ERR_AUTH = 3,
    /* HTTP 429 (rate limited), and every retry attempt (bounded by
     * cfg->max_retries, honoring Retry-After when NVD sends one, capped at
     * cfg->retry_after_max_sec) was also rate-limited. */
    CYTADEL_NVD_FETCH_ERR_RATE_LIMITED = 4,
    /* HTTP 5xx, and every retry attempt (bounded by cfg->max_retries,
     * exponential backoff + jitter) also returned a 5xx. */
    CYTADEL_NVD_FETCH_ERR_SERVER = 5,
    /* Any other unexpected HTTP status (a 3xx this module does not follow --
     * CURLOPT_FOLLOWLOCATION is never enabled -- or an unanticipated 4xx
     * other than 401/403/429). Never retried. */
    CYTADEL_NVD_FETCH_ERR_HTTP = 6
} cytadel_nvd_fetch_status_t;

/* Returns a static, human-readable name for `status`. Never returns NULL --
 * mirrors cytadel_db_status_to_string()/cytadel_nvd_ingest_status_to_string()'s
 * convention. */
const char *cytadel_nvd_fetch_status_to_string(cytadel_nvd_fetch_status_t status);

/* Every tunable this module needs, all injectable so tests can point at a
 * loopback fixture server and shrink every timeout/backoff/retry-count down
 * to milliseconds instead of the real, production-sized values below --
 * this is what keeps tests/unit/test_nvd_fetch.c fully deterministic and
 * fast with NO live network access (this header's own top-of-file "Scope"
 * note). A real HTTPS call to services.nvd.nist.gov is a manual smoke test
 * only, never part of the automated suite. */
typedef struct {
    /* Base URL for the CVE 2.0 endpoint, no trailing slash and no query
     * string of its own (this module appends "?startIndex=...&...").
     * Production default: CYTADEL_NVD_FETCH_DEFAULT_BASE_URL. Tests set
     * this to "http://127.0.0.1:<port>" (a loopback fixture -- see
     * cytadel_nvd_fetch_config_init_default() below for why plain HTTP
     * against a fixture is fine: curl only enforces TLS verification for an
     * https:// URL in the first place). Must be non-NULL/non-empty. NOTE:
     * when CYTADEL_NVD_API_KEY is set, the apiKey header is attached ONLY if
     * this scheme is https:// -- a non-https base_url proceeds unauthenticated
     * rather than ever sending the key in cleartext (see this header's
     * top-of-file "SECRET HYGIENE" note). */
    const char *base_url;

    /* Results-per-page NVD query parameter (<=
     * CYTADEL_NVD_FETCH_MAX_RESULTS_PER_PAGE). Production default: the max,
     * 2000. Tests shrink this to force a multi-page window with only a
     * handful of fixture CVEs. */
    int results_per_page;

    /* curl connect-phase timeout (CURLOPT_CONNECTTIMEOUT). */
    long connect_timeout_sec;
    /* curl whole-transfer timeout (CURLOPT_TIMEOUT). */
    long total_timeout_sec;
    /* CURLOPT_LOW_SPEED_LIMIT: abort if the transfer runs slower than this
     * many bytes/sec for low_speed_time_sec seconds straight -- catches a
     * connection that stays open and trickles data too slowly to ever hit
     * total_timeout_sec. */
    long low_speed_limit_bytes;
    long low_speed_time_sec;

    /* Hard cap on the accumulated response body -- see this header's
     * CYTADEL_NVD_FETCH_DEFAULT_MAX_BODY_BYTES doc comment. */
    size_t max_response_bytes;

    /* Bounds the number of retry attempts across BOTH the 429 and 5xx retry
     * classes (a shared counter -- see nvd_fetch.c). Production default: a
     * handful of attempts. Tests set this small (e.g. 2-3) so a "retries
     * exhausted" test does not take long to run. */
    int max_retries;
    /* Exponential-backoff base/ceiling for 5xx retries (and for a 429 whose
     * Retry-After is absent/malformed) -- delay_ms = min(backoff_max_ms,
     * backoff_initial_ms * 2^attempt) plus a small non-cryptographic random
     * jitter (this is scheduling jitter to avoid a retry stampede, not a
     * security control -- see nvd_fetch.c's compute_backoff_ms()). */
    long backoff_initial_ms;
    long backoff_max_ms;
    /* Upper bound on how long a server-supplied Retry-After (seconds) is
     * ever honored for -- a hostile/misconfigured peer sending
     * "Retry-After: 999999999" cannot stall this module beyond this cap. */
    long retry_after_max_sec;

    /* Optional explicit CA bundle path for CURLOPT_CAINFO. NULL/empty
     * leaves curl's own compiled-in default trust store in effect.
     * Production default: "/etc/ssl/certs/ca-certificates.crt" (this
     * milestone's verified-working CA bundle location) -- explicitly
     * setting it, rather than relying on the vendored libcurl build's own
     * compiled-in default, is the conservative choice this milestone's task
     * brief calls out ("or set CURLOPT_CAINFO ... explicitly"). Ignored
     * entirely for a plain http:// base_url (loopback fixture tests). */
    const char *ca_info_path;
} cytadel_nvd_fetch_config_t;

/* Fills `cfg` with this module's production defaults (see each field's own
 * doc comment above for the exact value/rationale). Safe starting point for
 * a real sync run; tests take the result and override base_url plus
 * whichever timeout/retry/backoff fields need to shrink for a fast,
 * deterministic run against a loopback fixture. `cfg` must be non-NULL. */
void cytadel_nvd_fetch_config_init_default(cytadel_nvd_fetch_config_t *cfg);

/* Fetches exactly one page of NVD 2.0 CVE results:
 *   GET {base_url}?resultsPerPage={cfg->results_per_page}&startIndex={start_index}
 *       [&lastModStartDate={last_mod_start_date}&lastModEndDate={last_mod_end_date}]
 * (the lastMod* pair is included iff BOTH last_mod_start_date and
 * last_mod_end_date are non-NULL/non-empty -- this is the "NULL watermark =
 * initial bulk load, page the whole corpus with no date filter" case from
 * db-schema.md SS8 step 1; passing only one of the two is a caller bug,
 * CYTADEL_NVD_FETCH_ERR_INVALID_ARG). Both date strings, when present, are
 * percent-encoded by this function before being placed in the URL (they are
 * expected to already be in NVD's own ISO-8601 form, e.g.
 * "2024-01-01T00:00:00.000"; this function does not itself validate that
 * shape beyond non-empty -- db-schema.md's timestamp convention is the
 * caller's, i.e. nvd_sync.c's, responsibility to uphold).
 *
 * On CYTADEL_NVD_FETCH_OK, `*out_body` is a heap buffer the caller now owns
 * (must free() it -- ordinary malloc/realloc-backed memory, not anything
 * curl-specific) containing exactly `*out_len` bytes (NUL-terminated as a
 * convenience, but callers must use `*out_len`, never strlen(), since a JSON
 * body could in principle contain an embedded NUL byte -- same
 * never-assume-NUL-terminated posture as cytadel_nvd_ingest_page()). On any
 * non-OK status, `*out_body`/`*out_len` are left unset (NULL/0) -- there is
 * nothing for the caller to free.
 *
 * This function's own retry loop (429/5xx, see this header's top-of-file
 * item 4) blocks the calling thread for the duration of any backoff sleep
 * (nanosleep()) -- callers on a latency-sensitive thread should run this
 * from a dedicated sync thread/process, not inline on a hot path; this
 * matches how the rest of this codebase's own blocking network calls
 * (tcp_connect_probe(), http_probe.c) are documented as blocking-by-design. */
cytadel_nvd_fetch_status_t cytadel_nvd_fetch_page(const cytadel_nvd_fetch_config_t *cfg, int start_index,
                                                   const char *last_mod_start_date,
                                                   const char *last_mod_end_date, char **out_body,
                                                   size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_NVD_FETCH_H */
