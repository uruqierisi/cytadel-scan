/* Milestone 7 live NVD fetch slice: tests for the fetch-driver / multi-window
 * catch-up wrapper (src/db/nvd_catchup.c), built on top of the already-tested
 * single-window driver (src/db/nvd_sync.c, see test_nvd_sync.c). Every test is
 * deterministic and hits a loopback fixture HTTP server (same bind-ephemeral +
 * background-accept-thread pattern as test_nvd_sync.c) -- NO live network, and
 * NO wall-clock dependence: `now` is always an explicit, hand-picked literal
 * passed into cytadel_nvd_catchup(), never read from the system clock.
 *
 * Every multi-window date boundary asserted below (the 120/300/60-day window
 * lengths, the exact 120-vs-121-day tie-break, the leap-year Feb 29 2024
 * crossing) was independently computed by hand via ordinal-day-of-year
 * arithmetic (see this file's own per-test comments) -- NOT derived by
 * running the code under test and copying its output. That is what makes
 * these assertions a real check of nvd_catchup.c's date arithmetic rather
 * than a tautology. */

#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <sqlite3.h>

#include "cytadel/db/db.h"
#include "cytadel/db/nvd_catchup.h"
#include "cytadel/net/nvd_fetch.h"

/* ----- loopback fixture server -------------------------------------------- */

static int bind_ephemeral(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 8) == 0);
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &blen) == 0);
    *out_port = ntohs(bound.sin_port);
    return fd;
}

/* A scripted sequence of raw HTTP responses, one served per accepted
 * connection (every response carries "Connection: close"). Unlike
 * test_nvd_sync.c's fixture, this one ALSO captures each accepted
 * connection's HTTP request line (up to the first "\r\n") into
 * `captured_requests[i]`, malloc'd -- this is what lets each test below
 * independently verify the exact lastModStartDate/lastModEndDate query
 * parameters cytadel_nvd_catchup() drove for window i, not just the
 * resulting DB state. */
#define FIXTURE_MAX_REQUESTS 8
typedef struct {
    int listen_fd;
    char *responses[FIXTURE_MAX_REQUESTS];
    size_t response_lens[FIXTURE_MAX_REQUESTS];
    size_t count;
    char *captured_requests[FIXTURE_MAX_REQUESTS];
} fixture_t;

static void *fixture_main(void *arg) {
    fixture_t *fx = arg;
    for (size_t i = 0; i < fx->count; i++) {
        int fd = accept(fx->listen_fd, NULL, NULL);
        if (fd < 0) {
            return NULL;
        }
        char req[4096];
        ssize_t n = recv(fd, req, sizeof(req) - 1, 0);
        if (n < 0) {
            n = 0;
        }
        req[n] = '\0';
        const char *eol = strstr(req, "\r\n");
        size_t line_len = (eol != NULL) ? (size_t)(eol - req) : (size_t)n;
        char *line = malloc(line_len + 1);
        CYTADEL_ASSERT(line != NULL);
        memcpy(line, req, line_len);
        line[line_len] = '\0';
        fx->captured_requests[i] = line;

        (void)send(fd, fx->responses[i], fx->response_lens[i], 0);
        close(fd);
    }
    return NULL;
}

static void fixture_free_requests(fixture_t *fx) {
    for (size_t i = 0; i < fx->count; i++) {
        free(fx->captured_requests[i]);
        fx->captured_requests[i] = NULL;
    }
}

static char *http_response(const char *status_line, const char *body, size_t *out_len) {
    char *buf = malloc(1024 + strlen(body));
    CYTADEL_ASSERT(buf != NULL);
    int n = snprintf(buf, 1024 + strlen(body),
                     "%s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %zu\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "%s",
                     status_line, strlen(body), body);
    CYTADEL_ASSERT(n > 0);
    *out_len = (size_t)n;
    return buf;
}

/* An NVD 2.0 page body reporting totalResults=0 and an empty
 * "vulnerabilities" array -- cytadel_nvd_sync_window() treats this as the
 * (only, trivially "last") page of the window: 0 CVEs ingested, and the
 * window's watermark advance still fires normally. Using this for every
 * fixture response in this file means every window this suite drives is
 * exactly ONE HTTP request -- so "N windows" and "N accepted connections"
 * are the same number throughout, which is what makes the request-capture
 * boundary assertions below straightforward. */
static const char *const EMPTY_PAGE_BODY =
    "{\"format\":\"NVD_CVE\",\"version\":\"2.0\",\"totalResults\":0,\"vulnerabilities\":[]}";

static void fixture_fill_empty_pages(fixture_t *fx, size_t count) {
    CYTADEL_ASSERT(count <= FIXTURE_MAX_REQUESTS);
    fx->count = count;
    for (size_t i = 0; i < count; i++) {
        fx->responses[i] = http_response("HTTP/1.1 200 OK", EMPTY_PAGE_BODY, &fx->response_lens[i]);
    }
}

static void fixture_free_responses(fixture_t *fx) {
    for (size_t i = 0; i < fx->count; i++) {
        free(fx->responses[i]);
        fx->responses[i] = NULL;
    }
}

/* Percent-encodes ONLY ':' as "%3A" (curl_easy_escape()'s RFC 3986 unreserved
 * set -- A-Za-z0-9-._~ -- covers every other byte an ISO-8601 instant this
 * suite ever emits can contain: digits, '-', 'T', '.', 'Z'). Bounded,
 * asserts rather than silently truncating. */
static void percent_encode_colon(const char *in, char *out, size_t out_cap) {
    size_t oi = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        if (in[i] == ':') {
            CYTADEL_ASSERT(oi + 3 < out_cap);
            out[oi++] = '%';
            out[oi++] = '3';
            out[oi++] = 'A';
        } else {
            CYTADEL_ASSERT(oi + 1 < out_cap);
            out[oi++] = in[i];
        }
    }
    out[oi] = '\0';
}

/* Asserts that captured request line `req_line` carries
 * "lastModStartDate=<percent-encoded start_date>" (or, if start_date is
 * NULL, that it carries NO lastModStartDate/lastModEndDate at all -- the
 * initial-bulk-load shape) and "lastModEndDate=<percent-encoded end_date>". */
static void assert_request_window(const char *req_line, const char *start_date, const char *end_date) {
    if (start_date == NULL) {
        CYTADEL_ASSERT(strstr(req_line, "lastModStartDate=") == NULL);
        CYTADEL_ASSERT(strstr(req_line, "lastModEndDate=") == NULL);
        return;
    }
    char enc_start[80];
    percent_encode_colon(start_date, enc_start, sizeof(enc_start));
    char needle_start[128];
    snprintf(needle_start, sizeof(needle_start), "lastModStartDate=%s", enc_start);
    CYTADEL_ASSERT(strstr(req_line, needle_start) != NULL);

    char enc_end[80];
    percent_encode_colon(end_date, enc_end, sizeof(enc_end));
    char needle_end[128];
    snprintf(needle_end, sizeof(needle_end), "lastModEndDate=%s", enc_end);
    CYTADEL_ASSERT(strstr(req_line, needle_end) != NULL);
}

/* ----- DB helpers --------------------------------------------------------- */

static cytadel_db_t *fresh_migrated_db(sqlite3 **out_handle) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    *out_handle = cytadel_db_handle(db);
    return db;
}

static void read_nvd_watermark(sqlite3 *h, char *out, size_t out_cap) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(h, "SELECT COALESCE(last_mod_watermark, '') FROM sync_state WHERE feed = 'nvd';",
                           -1, &st, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    snprintf(out, out_cap, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
}

/* Directly seeds sync_state.last_mod_watermark for feed='nvd' -- test-only
 * back door (production code only ever advances this via
 * cytadel_nvd_sync_window()'s own commit) so each test can start from a
 * specific, hand-picked watermark without first driving a real sync.
 * `len < 0` means "NUL-terminated, use strlen()"; a non-negative `len`
 * binds exactly that many bytes (used by the embedded-control-byte
 * malformed-watermark test, which cannot be expressed as a plain C string
 * literal beyond its first embedded NUL). */
static void set_nvd_watermark(sqlite3 *h, const char *data, int len) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(h, "UPDATE sync_state SET last_mod_watermark = ? WHERE feed = 'nvd';", -1, &st,
                           NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(st, 1, data, len, SQLITE_TRANSIENT), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_DONE);
    sqlite3_finalize(st);
}

static void make_cfg(cytadel_nvd_fetch_config_t *cfg, char *url_buf, size_t url_cap, uint16_t port) {
    cytadel_nvd_fetch_config_init_default(cfg);
    snprintf(url_buf, url_cap, "http://127.0.0.1:%u", (unsigned)port);
    cfg->base_url = url_buf;
    cfg->results_per_page = 2000;
    cfg->max_retries = 0; /* keep every failure-path test fast and deterministic */
    cfg->backoff_initial_ms = 1;
    cfg->backoff_max_ms = 2;
    cfg->connect_timeout_sec = 5;
    cfg->total_timeout_sec = 10;
    cfg->ca_info_path = NULL; /* plain http fixture, no TLS trust store needed */
}

/* ----- Test 1: no watermark -> single bulk-load window -------------------- */

static void test_no_watermark_single_bulk_load_window(void) {
    static const char *const NOW = "2024-05-01T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 1);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char wm0[64];
    read_nvd_watermark(h, wm0, sizeof(wm0));
    CYTADEL_ASSERT_STREQ(wm0, ""); /* seeded NULL, per db-schema.md SS8 */

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 1);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 1);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);

    pthread_join(th, NULL);
    /* Bulk load: start_date=NULL, end_date=now -- no lastModStartDate/
     * lastModEndDate query params at all (db-schema.md SS8 step 1). */
    assert_request_window(fx.captured_requests[0], NULL, NOW);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Test 2: watermark < 120 days before now -> exactly ONE window ----- */

static void test_watermark_under_120_days_one_window(void) {
    /* 2024-04-01 -> 2024-06-01 is 61 days (April 29 + May 31 + June 1 = 61;
     * ordinal(2024-04-01)=31(Jan)+29(Feb)+31(Mar)+1=92, ordinal(2024-06-01)=
     * 31+29+31+30+31+1=153; 153-92=61), comfortably under 120. */
    static const char *const WATERMARK = "2024-04-01T00:00:00.000Z";
    static const char *const NOW = "2024-06-01T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 1);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 1);

    pthread_join(th, NULL);
    assert_request_window(fx.captured_requests[0], WATERMARK, NOW);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Test 3: watermark ~300 days before now -> THREE windows ----------- */

/* Hand-computed (ordinal-day-of-year arithmetic, 2024 is a leap year):
 *   ordinal(2024-03-07) = 31(Jan) + 29(Feb) + 7          = 67
 *   ordinal(2024-07-05) = 31+29+31+30+31+30+5             = 187  (187-67=120)
 *   ordinal(2024-11-02) = 31+29+31+30+31+30+31+31+30+31+2 = 307  (307-187=120)
 *   2025-01-01 is 60 days after 2024-11-02 (366-307=59 remaining in 2024,
 *   +1 to reach 2025-01-01) -- 2025 is not a leap year, irrelevant here since
 *   we never cross past Jan 1, 2025.
 *   Total span 2024-03-07 -> 2025-01-01 = 120+120+60 = 300 days.
 * This is exactly the "120 + 120 + ~60" three-window case the task brief
 * calls for, and independently pins that add_days()/min() never drifts
 * across month or leap-year boundaries. */
static void test_watermark_300_days_three_windows(void) {
    static const char *const WATERMARK = "2024-03-07T00:00:00.000Z";
    static const char *const NOW = "2025-01-01T00:00:00.000Z";
    static const char *const W1_END = "2024-07-05T00:00:00.000Z";
    static const char *const W2_END = "2024-11-02T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 3);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 3);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 3);

    pthread_join(th, NULL);
    assert_request_window(fx.captured_requests[0], WATERMARK, W1_END);
    assert_request_window(fx.captured_requests[1], W1_END, W2_END);
    assert_request_window(fx.captured_requests[2], W2_END, NOW);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Test 4: mid-catch-up FAILURE leaves the watermark at window 1 ----- */

/* Same window boundaries as test 3 above (verified there) -- window 2's
 * fetch is made to fail (HTTP 500, max_retries=0 so it fails at once, no
 * retry delay). The claim under test: the catch-up loop stops immediately,
 * reports exactly 1 completed window, and the DURABLE watermark (read back
 * from sync_state) sits at window 1's end -- NOT at "now", and NOT at window
 * 2's end (which never committed at all). Window 3 must never even be
 * attempted -- this test's fixture only scripts 2 responses, so a driver
 * that kept going after the failure would starve on accept() and this test
 * would hang (a real, first-class regression signal) rather than pass
 * quietly.
 *
 * REVERT-PROOF (recorded in the task's final report, not re-executed by this
 * suite each run): temporarily editing nvd_catchup.c so `cursor` advances to
 * `window_end` unconditionally (i.e. even when cytadel_nvd_sync_window()
 * returns a non-OK status), rebuilding, and re-running this exact test
 * changes the outcome from PASS to a FAILED assertion on the watermark
 * check below (it reads back window 2's end, "2024-11-02T00:00:00.000Z",
 * instead of window 1's end) -- see the task report for the exact command
 * and captured failing output. */
static void test_midcatchup_failure_leaves_watermark_at_last_good_window(void) {
    static const char *const WATERMARK = "2024-03-07T00:00:00.000Z";
    static const char *const NOW = "2025-01-01T00:00:00.000Z";
    static const char *const W1_END = "2024-07-05T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fx.count = 2;
    fx.responses[0] = http_response("HTTP/1.1 200 OK", EMPTY_PAGE_BODY, &fx.response_lens[0]);
    fx.responses[1] = http_response("HTTP/1.1 500 Internal Server Error", "", &fx.response_lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_ERR_SYNC);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 1);

    pthread_join(th, NULL);
    assert_request_window(fx.captured_requests[0], WATERMARK, W1_END);
    assert_request_window(fx.captured_requests[1], W1_END, "2024-11-02T00:00:00.000Z");

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, W1_END); /* NOT now, NOT window 2's end */

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Test 5: watermark already == now -> ZERO windows ------------------ */

static void test_watermark_equals_now_zero_windows(void) {
    static const char *const NOW = "2024-06-01T00:00:00.000Z";

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, NOW, -1);

    /* Deliberately NOT bound to any accept()-ing fixture: port 1 is a
     * privileged, essentially-never-listening port, so any (buggy) fetch
     * attempt fails fast with ECONNREFUSED rather than hanging this test. A
     * correct implementation issues no fetch at all, so this is never
     * exercised. */
    cytadel_nvd_fetch_config_t cfg;
    cytadel_nvd_fetch_config_init_default(&cfg);
    cfg.base_url = "http://127.0.0.1:1";
    cfg.connect_timeout_sec = 2;
    cfg.total_timeout_sec = 3;
    cfg.max_retries = 0;
    cfg.ca_info_path = NULL;

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 0);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 0);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW); /* untouched */

    cytadel_db_close(db);
}

/* ----- Test 6: malformed watermark -> clean error, no crash, no loop ----- */

static void run_malformed_watermark_case(const char *data, int len) {
    static const char *const NOW = "2024-06-01T00:00:00.000Z";

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, data, len);

    cytadel_nvd_fetch_config_t cfg;
    cytadel_nvd_fetch_config_init_default(&cfg);
    cfg.base_url = "http://127.0.0.1:1"; /* never actually dialed -- parse fails first */
    cfg.connect_timeout_sec = 2;
    cfg.total_timeout_sec = 3;
    cfg.max_retries = 0;
    cfg.ca_info_path = NULL;

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 0);

    cytadel_db_close(db);
}

static void test_malformed_watermark_garbage_text(void) {
    run_malformed_watermark_case("not-a-real-date-at-all", -1);
}

static void test_malformed_watermark_embedded_control_bytes(void) {
    /* "2024\x00\x01\x02-01-01" -- an embedded NUL followed by more control
     * bytes, bound with an EXPLICIT byte length (not -1/strlen) so the bytes
     * after the NUL genuinely reach sqlite3/this module rather than being
     * truncated by C-string semantics before ever leaving this test file. */
    static const char raw[] = {'2', '0', '2', '4', '\x00', '\x01', '\x02', '-', '0', '1', '-', '0', '1'};
    run_malformed_watermark_case(raw, (int)sizeof(raw));
}

static void test_malformed_watermark_absurd_length(void) {
    /* Well beyond CYTADEL_NVD_CATCHUP_TS_MAX_LEN (40) -- must be rejected by
     * the length check before any digit is even inspected, not merely
     * truncated-then-misparsed. */
    char buf[256];
    memset(buf, 'A', sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    run_malformed_watermark_case(buf, -1);
}

static void test_malformed_watermark_invalid_calendar_date(void) {
    /* 2023 is not a leap year -- Feb 29 does not exist. Must be rejected by
     * the days_from_civil()/civil_from_days() round-trip check, not silently
     * normalized to some nearby real date. */
    run_malformed_watermark_case("2023-02-29T00:00:00.000Z", -1);
}

/* ----- Test 7: the 120-vs-121-day boundary (pins the off-by-one) --------- */

/* Hand-computed (2024 is a leap year -- this crosses the Feb 29 boundary),
 * kept as line-by-line ordinal-day-of-year arithmetic so it is checkable
 * independently of this suite's own pass/fail result:
 *     ordinal(2024-05-01) = 31 + 29 + 31 + 30 + 1 = 122
 *     ordinal(2024-01-02) = 2                          -> 122 - 2   = 120
 *     ordinal(2024-01-01) = 1                          -> 122 - 1   = 121
 *     ordinal(2024-04-30) = 31 + 29 + 31 + 30           = 121
 * So:
 *   watermark 2024-01-02 is EXACTLY 120 days before 2024-05-01 -> 1 window.
 *   watermark 2024-01-01 is EXACTLY 121 days before 2024-05-01 -> 2 windows,
 *     the first ending 2024-04-30 (121 - 120 = 1 -> 120 days from 2024-01-01
 *     lands on ordinal 1+120=121 = 2024-04-30), the second covering the
 *     final 1 day up to 2024-05-01.
 * Both cases cross the 2024 Feb 29 leap day, so this test simultaneously
 * pins the exact 120/121-day tie-break AND a leap-year crossing. */
static void test_boundary_exactly_120_days_one_window(void) {
    static const char *const WATERMARK = "2024-01-02T00:00:00.000Z";
    static const char *const NOW = "2024-05-01T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 1);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 1);

    pthread_join(th, NULL);
    assert_request_window(fx.captured_requests[0], WATERMARK, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

static void test_boundary_exactly_121_days_two_windows(void) {
    static const char *const WATERMARK = "2024-01-01T00:00:00.000Z";
    static const char *const NOW = "2024-05-01T00:00:00.000Z";
    static const char *const W1_END = "2024-04-30T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 2);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 2);

    pthread_join(th, NULL);
    assert_request_window(fx.captured_requests[0], WATERMARK, W1_END);
    assert_request_window(fx.captured_requests[1], W1_END, NOW);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Bare-date watermark (liberal-in / strict-out) ---------------------- */

/* db-schema.md's own sync_state column doc + this module's header both call
 * out accepting a bare "YYYY-MM-DD" cursor (e.g. a hand-edited or
 * legacy-written value) in addition to a full instant. Confirms that shape
 * is accepted (midnight UTC) and that the window this module drives, and the
 * new watermark it stores, are both emitted in the full canonical
 * "...T00:00:00.000Z" shape (strict-out). */
static void test_bare_date_watermark_is_accepted(void) {
    static const char *const WATERMARK_BARE = "2024-04-01";
    static const char *const WATERMARK_CANON = "2024-04-01T00:00:00.000Z";
    static const char *const NOW = "2024-06-01T00:00:00.000Z";

    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd};
    fixture_fill_empty_pages(&fx, 1);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    set_nvd_watermark(h, WATERMARK_BARE, -1);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_nvd_catchup_counts_t counts;
    cytadel_nvd_catchup_status_t st = cytadel_nvd_catchup(db, &cfg, NOW, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_CATCHUP_OK);
    CYTADEL_ASSERT_EQ(counts.windows_completed, 1);

    pthread_join(th, NULL);
    /* The window handed to cytadel_nvd_sync_window() (and therefore sent
     * over the wire) uses the CANONICAL form, not the bare input. */
    assert_request_window(fx.captured_requests[0], WATERMARK_CANON, NOW);

    char wm1[64];
    read_nvd_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT_STREQ(wm1, NOW);

    cytadel_db_close(db);
    fixture_free_requests(&fx);
    fixture_free_responses(&fx);
    close(listen_fd);
}

/* ----- Invalid-argument surface ------------------------------------------- */

static void test_invalid_args(void) {
    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);
    cytadel_nvd_fetch_config_t cfg;
    cytadel_nvd_fetch_config_init_default(&cfg);
    cfg.base_url = "http://127.0.0.1:1";

    cytadel_nvd_catchup_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(NULL, &cfg, "2024-01-01T00:00:00.000Z", &counts),
                      CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(db, NULL, "2024-01-01T00:00:00.000Z", &counts),
                      CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(db, &cfg, NULL, &counts), CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(db, &cfg, "", &counts), CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(db, &cfg, "garbage", &counts),
                      CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_nvd_catchup(db, &cfg, "2024-01-01T00:00:00.000Z", NULL),
                      CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG);

    cytadel_db_close(db);
}

int main(void) {
    /* libcurl's send() can raise SIGPIPE when a fixture closes early; ignore
     * it process-wide (matches test_nvd_sync.c). */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_no_watermark_single_bulk_load_window();
    test_watermark_under_120_days_one_window();
    test_watermark_300_days_three_windows();
    test_midcatchup_failure_leaves_watermark_at_last_good_window();
    test_watermark_equals_now_zero_windows();
    test_malformed_watermark_garbage_text();
    test_malformed_watermark_embedded_control_bytes();
    test_malformed_watermark_absurd_length();
    test_malformed_watermark_invalid_calendar_date();
    test_boundary_exactly_120_days_one_window();
    test_boundary_exactly_121_days_two_windows();
    test_bare_date_watermark_is_accepted();
    test_invalid_args();
    CYTADEL_TEST_PASS();
}
