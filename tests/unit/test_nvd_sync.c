/* Milestone 7 live NVD fetch slice: tests for the libcurl transport
 * (src/net/nvd_fetch.c) and the pagination/watermark driver
 * (src/db/nvd_sync.c). Every test is deterministic and hits a loopback
 * fixture HTTP server (the same bind-ephemeral + background-accept pattern as
 * test_plugins_stock_network.c) -- NO live network. The client's base_url and
 * backoff/timeout knobs are injectable, so the size-cap / retry / truncation /
 * watermark logic is exercised over plain http to 127.0.0.1. A real HTTPS call
 * to NVD is a manual smoke test, not part of this suite. */

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
#include "cytadel/db/nvd_sync.h"
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
 * connection (every response carries "Connection: close", so the client opens
 * a fresh connection per request and the i-th request gets responses[i]). */
typedef struct {
    int listen_fd;
    char *responses[8];
    size_t response_lens[8];
    size_t count;
} fixture_t;

static void *fixture_main(void *arg) {
    fixture_t *fx = arg;
    for (size_t i = 0; i < fx->count; i++) {
        int fd = accept(fx->listen_fd, NULL, NULL);
        if (fd < 0) {
            return NULL;
        }
        char req[4096];
        (void)recv(fd, req, sizeof(req), 0); /* best-effort drain */
        (void)send(fd, fx->responses[i], fx->response_lens[i], 0);
        close(fd);
    }
    return NULL;
}

/* Assembles one HTTP/1.1 response into a freshly malloc'd buffer. When
 * content_length_override >= 0 it is used verbatim as the Content-Length
 * header value (pass a value LARGER than strlen(body) to simulate a truncated
 * transfer: the client waits for bytes that never arrive before the
 * Connection: close hangup). Otherwise strlen(body) is used. */
static char *http_response(const char *status_line, const char *body,
                            long content_length_override, size_t *out_len) {
    long clen = content_length_override >= 0 ? content_length_override : (long)strlen(body);
    char *buf = malloc(1024 + strlen(body));
    CYTADEL_ASSERT(buf != NULL);
    int n = snprintf(buf, 1024 + strlen(body),
                     "%s\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %ld\r\n"
                     "Connection: close\r\n"
                     "\r\n"
                     "%s",
                     status_line, clen, body);
    CYTADEL_ASSERT(n > 0);
    *out_len = (size_t)n;
    return buf;
}

/* Like http_response but adds a Retry-After header (for the 429 case). */
static char *http_response_retry_after(const char *status_line, int retry_after_sec,
                                        size_t *out_len) {
    char *buf = malloc(512);
    CYTADEL_ASSERT(buf != NULL);
    int n = snprintf(buf, 512,
                     "%s\r\n"
                     "Retry-After: %d\r\n"
                     "Content-Length: 0\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     status_line, retry_after_sec);
    CYTADEL_ASSERT(n > 0);
    *out_len = (size_t)n;
    return buf;
}

/* One minimal-but-valid NVD 2.0 page body: `total` totalResults and `n_ids`
 * vulnerability records with the given ids. */
static char *nvd_page_body(long total, const char *const *ids, size_t n_ids) {
    char *buf = malloc(4096);
    CYTADEL_ASSERT(buf != NULL);
    size_t off = 0;
    off += (size_t)snprintf(buf + off, 4096 - off,
                            "{\"format\":\"NVD_CVE\",\"version\":\"2.0\",\"totalResults\":%ld,"
                            "\"vulnerabilities\":[",
                            total);
    for (size_t i = 0; i < n_ids; i++) {
        off += (size_t)snprintf(buf + off, 4096 - off,
                                "%s{\"cve\":{\"id\":\"%s\",\"published\":\"2024-01-01T00:00:00.000\","
                                "\"lastModified\":\"2024-01-02T00:00:00.000\","
                                "\"descriptions\":[{\"lang\":\"en\",\"value\":\"x\"}]}}",
                                i == 0 ? "" : ",", ids[i]);
    }
    off += (size_t)snprintf(buf + off, 4096 - off, "]}");
    CYTADEL_ASSERT(off < 4096);
    return buf;
}

/* ----- DB helpers --------------------------------------------------------- */

static void read_nvd_sync_state(sqlite3 *h, char *watermark, size_t wcap, char *status,
                                 size_t scap) {
    sqlite3_stmt *st = NULL;
    int rc = sqlite3_prepare_v2(
        h, "SELECT COALESCE(last_mod_watermark, ''), status FROM sync_state WHERE feed = 'nvd';", -1,
        &st, NULL);
    CYTADEL_ASSERT_EQ(rc, SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    snprintf(watermark, wcap, "%s", (const char *)sqlite3_column_text(st, 0));
    snprintf(status, scap, "%s", (const char *)sqlite3_column_text(st, 1));
    sqlite3_finalize(st);
}

static int count_cve(sqlite3 *h, const char *id) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(h, "SELECT COUNT(*) FROM cves WHERE cve_id = ?;", -1, &st,
                                          NULL),
                      SQLITE_OK);
    sqlite3_bind_text(st, 1, id, -1, SQLITE_TRANSIENT);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    int c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

static void make_cfg(cytadel_nvd_fetch_config_t *cfg, char *url_buf, size_t url_cap, uint16_t port,
                      int max_retries) {
    cytadel_nvd_fetch_config_init_default(cfg);
    snprintf(url_buf, url_cap, "http://127.0.0.1:%u", (unsigned)port);
    cfg->base_url = url_buf;
    cfg->results_per_page = 2;
    cfg->max_retries = max_retries;
    cfg->backoff_initial_ms = 1; /* keep retries instant so tests stay fast */
    cfg->backoff_max_ms = 2;
    cfg->connect_timeout_sec = 5;
    cfg->total_timeout_sec = 10;
    cfg->ca_info_path = NULL; /* plain http fixture, no TLS trust store needed */
}

static cytadel_db_t *fresh_migrated_db(sqlite3 **out_handle) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    *out_handle = cytadel_db_handle(db);
    return db;
}

/* ----- transport tests (cytadel_nvd_fetch_page) --------------------------- */

/* A response body larger than max_response_bytes must abort the transfer and
 * surface as a transport error -- never buffered unboundedly. */
static void test_fetch_size_cap_aborts(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 1};
    static const char *ids[] = {"CVE-2024-90001"};
    char *big = nvd_page_body(1, ids, 1); /* a few hundred bytes */
    fx.responses[0] = http_response("HTTP/1.1 200 OK", big, -1, &fx.response_lens[0]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);
    cfg.max_response_bytes = 64; /* smaller than the body -> abort */

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t st =
        cytadel_nvd_fetch_page(&cfg, 0, NULL, NULL, &body, &len);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_FETCH_ERR_TRANSPORT);
    CYTADEL_ASSERT(body == NULL);

    pthread_join(th, NULL);
    free(big);
    free(fx.responses[0]);
    close(listen_fd);
}

/* 429 with Retry-After, then 200 -> the client backs off (bounded) and
 * ultimately succeeds. */
static void test_fetch_429_retry_then_success(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 2};
    fx.responses[0] = http_response_retry_after("HTTP/1.1 429 Too Many Requests", 0,
                                                 &fx.response_lens[0]);
    static const char *ids[] = {"CVE-2024-90001"};
    char *page = nvd_page_body(1, ids, 1);
    fx.responses[1] = http_response("HTTP/1.1 200 OK", page, -1, &fx.response_lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 3);

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t st = cytadel_nvd_fetch_page(&cfg, 0, NULL, NULL, &body, &len);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_FETCH_OK);
    CYTADEL_ASSERT(body != NULL && len > 0);

    pthread_join(th, NULL);
    free(body);
    free(page);
    free(fx.responses[0]);
    free(fx.responses[1]);
    close(listen_fd);
}

/* Persistent 5xx -> retried max_retries times, then given up as a server
 * error (never an unbounded loop). */
static void test_fetch_5xx_gives_up(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 2}; /* attempt0 + 1 retry */
    fx.responses[0] = http_response("HTTP/1.1 500 Internal Server Error", "", 0,
                                     &fx.response_lens[0]);
    fx.responses[1] = http_response("HTTP/1.1 500 Internal Server Error", "", 0,
                                     &fx.response_lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 1); /* one retry, then give up */

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t st = cytadel_nvd_fetch_page(&cfg, 0, NULL, NULL, &body, &len);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_FETCH_ERR_SERVER);
    CYTADEL_ASSERT(body == NULL);

    pthread_join(th, NULL);
    free(fx.responses[0]);
    free(fx.responses[1]);
    close(listen_fd);
}

/* Body shorter than the advertised Content-Length (peer hangs up mid-body)
 * -> a truncated transfer, surfaced as a transport error, not a short "OK". */
static void test_fetch_truncated_body_is_transport_error(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 1};
    /* Claim 5000 bytes, send a 1-byte body, then close. */
    fx.responses[0] = http_response("HTTP/1.1 200 OK", "{", 5000, &fx.response_lens[0]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t st = cytadel_nvd_fetch_page(&cfg, 0, NULL, NULL, &body, &len);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_FETCH_ERR_TRANSPORT);
    CYTADEL_ASSERT(body == NULL);

    pthread_join(th, NULL);
    free(fx.responses[0]);
    close(listen_fd);
}

/* An unset NVD_API_KEY must not crash or block -- the client proceeds
 * unauthenticated (the key value never appears anywhere; that hygiene is
 * additionally grep-verified against the source). */
static void test_fetch_missing_api_key_proceeds(void) {
    unsetenv("NVD_API_KEY");
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 1};
    static const char *ids[] = {"CVE-2024-90001"};
    char *page = nvd_page_body(1, ids, 1);
    fx.responses[0] = http_response("HTTP/1.1 200 OK", page, -1, &fx.response_lens[0]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    char *body = NULL;
    size_t len = 0;
    cytadel_nvd_fetch_status_t st = cytadel_nvd_fetch_page(&cfg, 0, NULL, NULL, &body, &len);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_FETCH_OK);

    pthread_join(th, NULL);
    free(body);
    free(page);
    free(fx.responses[0]);
    close(listen_fd);
}

/* Assembles a minimal NVD-2.0-shaped page body where the "totalResults"
 * value is `total_raw` verbatim (unquoted -- pass a quoted string literal
 * like "\"bogus\"" for the non-numeric case), or omitted entirely when
 * `total_raw` is NULL. `vulnerabilities` is always an empty array -- these
 * fixtures exist only to exercise parse_total_results()'s rejection paths,
 * never the ingest layer's per-CVE handling. */
static char *hostile_total_results_body(const char *total_raw) {
    char *buf = malloc(256);
    CYTADEL_ASSERT(buf != NULL);
    int n;
    if (total_raw == NULL) {
        n = snprintf(buf, 256,
                     "{\"format\":\"NVD_CVE\",\"version\":\"2.0\",\"vulnerabilities\":[]}");
    } else {
        n = snprintf(buf, 256,
                     "{\"format\":\"NVD_CVE\",\"version\":\"2.0\",\"totalResults\":%s,"
                     "\"vulnerabilities\":[]}",
                     total_raw);
    }
    CYTADEL_ASSERT(n > 0 && n < 256);
    return buf;
}

/* ----- sync driver tests (cytadel_nvd_sync_window) ------------------------ */

/* A clean two-page window: both pages ingest, and the watermark advances
 * exactly once, after the FINAL page commits. */
static void test_sync_two_page_window_advances_watermark(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 2};
    static const char *page0_ids[] = {"CVE-2024-90001", "CVE-2024-90002"};
    static const char *page1_ids[] = {"CVE-2024-90003"};
    char *p0 = nvd_page_body(3, page0_ids, 2);
    char *p1 = nvd_page_body(3, page1_ids, 1);
    fx.responses[0] = http_response("HTTP/1.1 200 OK", p0, -1, &fx.response_lens[0]);
    fx.responses[1] = http_response("HTTP/1.1 200 OK", p1, -1, &fx.response_lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char wm0[64], stt0[32];
    read_nvd_sync_state(h, wm0, sizeof(wm0), stt0, sizeof(stt0));
    CYTADEL_ASSERT_STREQ(wm0, "");

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    cytadel_nvd_sync_counts_t counts;
    cytadel_nvd_sync_status_t st = cytadel_nvd_sync_window(
        db, &cfg, "2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z", 0, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_SYNC_OK);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 2);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 3);

    CYTADEL_ASSERT_EQ(count_cve(h, "CVE-2024-90001"), 1);
    CYTADEL_ASSERT_EQ(count_cve(h, "CVE-2024-90003"), 1);

    char wm1[64], stt1[32];
    read_nvd_sync_state(h, wm1, sizeof(wm1), stt1, sizeof(stt1));
    CYTADEL_ASSERT_STREQ(wm1, "2024-02-01T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(stt1, "success");

    pthread_join(th, NULL);
    cytadel_db_close(db);
    free(p0);
    free(p1);
    free(fx.responses[0]);
    free(fx.responses[1]);
    close(listen_fd);
}

/* The crash-safety assertion: page 1 commits (window_complete=false, so the
 * watermark is NOT advanced), then page 2's fetch fails. The window is
 * abandoned and the watermark stays exactly where it started -- the next run
 * re-fetches the whole window rather than skipping page 2's data. */
static void test_sync_midwindow_failure_leaves_watermark_unchanged(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 2};
    static const char *page0_ids[] = {"CVE-2024-90001", "CVE-2024-90002"};
    char *p0 = nvd_page_body(3, page0_ids, 2); /* totalResults=3 -> not the last page */
    fx.responses[0] = http_response("HTTP/1.1 200 OK", p0, -1, &fx.response_lens[0]);
    fx.responses[1] = http_response("HTTP/1.1 500 Internal Server Error", "", 0,
                                     &fx.response_lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0); /* no retry -> page 2's 500 fails at once */

    cytadel_nvd_sync_counts_t counts;
    cytadel_nvd_sync_status_t st = cytadel_nvd_sync_window(
        db, &cfg, "2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z", 0, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_SYNC_ERR_FETCH);

    /* Page 1's data WAS committed... */
    CYTADEL_ASSERT_EQ(count_cve(h, "CVE-2024-90001"), 1);
    /* ...but the watermark did NOT advance (still the seed NULL/''), and
     * status was never promoted to 'success'. */
    char wm[64], stt[32];
    read_nvd_sync_state(h, wm, sizeof(wm), stt, sizeof(stt));
    CYTADEL_ASSERT_STREQ(wm, "");
    CYTADEL_ASSERT(strcmp(stt, "success") != 0);

    pthread_join(th, NULL);
    cytadel_db_close(db);
    free(p0);
    free(fx.responses[0]);
    free(fx.responses[1]);
    close(listen_fd);
}

/* W8(a): a single page whose "totalResults" is absent, non-numeric, negative,
 * or hostilely huge (1e30, the exact value the security audit called out --
 * cJSON stores it raw in `valuedouble` and only saturates `valueint`, so this
 * is a syntactically valid JSON number, not a parse failure) must all be
 * rejected identically: CYTADEL_NVD_SYNC_ERR_PROTOCOL, zero pages counted,
 * the watermark left exactly at its seed value, and no partial commit (the
 * one page served is never handed to the ingest layer at all, since
 * parse_total_results() rejects it before cytadel_nvd_ingest_page() is ever
 * called). `total_raw` is the literal JSON fixture text for "totalResults"
 * (NULL omits the field entirely); `case_name` is only used in assertion
 * failure context via the surrounding CYTADEL_ASSERT_EQ line numbers. */
static void run_hostile_total_results_case(const char *total_raw) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = 1};
    char *body = hostile_total_results_body(total_raw);
    fx.responses[0] = http_response("HTTP/1.1 200 OK", body, -1, &fx.response_lens[0]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char wm0[64], stt0[32];
    read_nvd_sync_state(h, wm0, sizeof(wm0), stt0, sizeof(stt0));
    CYTADEL_ASSERT_STREQ(wm0, "");

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    cytadel_nvd_sync_counts_t counts;
    cytadel_nvd_sync_status_t st = cytadel_nvd_sync_window(
        db, &cfg, "2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z", 0, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_SYNC_ERR_PROTOCOL);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 0);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 0);

    char wm1[64], stt1[32];
    read_nvd_sync_state(h, wm1, sizeof(wm1), stt1, sizeof(stt1));
    CYTADEL_ASSERT_STREQ(wm1, "");
    CYTADEL_ASSERT(strcmp(stt1, "success") != 0);

    pthread_join(th, NULL);
    cytadel_db_close(db);
    free(body);
    free(fx.responses[0]);
    close(listen_fd);
}

static void test_sync_total_results_absent_is_protocol_error(void) {
    run_hostile_total_results_case(NULL);
}

static void test_sync_total_results_non_numeric_is_protocol_error(void) {
    run_hostile_total_results_case("\"bogus\"");
}

static void test_sync_total_results_negative_is_protocol_error(void) {
    run_hostile_total_results_case("-5");
}

/* The exact value the security audit called out: cJSON stores 1e30 raw in
 * `valuedouble` (only `valueint` saturates), so a naive `(long)valuedouble`
 * cast is an out-of-range double->long conversion -- undefined behaviour in
 * C, and NOT reliably "just a huge value" across architectures (AArch64's
 * FCVTZS saturates to LONG_MAX rather than x86-64's cvttsd2si-produced
 * LONG_MIN). This test is also this fix's empirical proof: run under the
 * float-cast-overflow-strengthened ASan+UBSan build (CYTADEL_SANITIZE=ON,
 * see cmake/Sanitizers.cmake) and the sanitizer stays silent while this test
 * still asserts the rejection -- i.e. the range check now runs strictly
 * before the cast, not just "the cast happens to still work out". */
static void test_sync_total_results_huge_is_protocol_error(void) {
    run_hostile_total_results_case("1e30");
}

/* W8(b): the MAX_PAGES safety valve itself, exercised via the newly
 * injectable `max_pages` argument rather than a 100000-page fixture. Every
 * page reports a huge-but-in-range totalResults (1000000, comfortably under
 * CYTADEL_NVD_SYNC_MAX_TOTAL_RESULTS) and zero vulnerabilities, so the window
 * never reaches its "last page" condition; once `injected_max_pages` pages
 * have been fetched the driver must give up as ERR_PROTOCOL with
 * pages_fetched exactly at the injected cap, and the watermark must still be
 * untouched -- pinning the exact auditor-verified valve behaviour (PROTOCOL,
 * pages_fetched==cap, watermark empty) without needing a fixture that serves
 * anywhere near the real 100000-page default. */
static void test_sync_max_pages_valve_is_injectable(void) {
    const long injected_max_pages = 5;
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = listen_fd, .count = (size_t)injected_max_pages};
    char *page = nvd_page_body(1000000, NULL, 0);
    for (size_t i = 0; i < fx.count; i++) {
        fx.responses[i] = http_response("HTTP/1.1 200 OK", page, -1, &fx.response_lens[i]);
    }

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    cytadel_nvd_sync_counts_t counts;
    cytadel_nvd_sync_status_t st =
        cytadel_nvd_sync_window(db, &cfg, "2024-01-01T00:00:00.000Z", "2024-02-01T00:00:00.000Z",
                                 injected_max_pages, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_SYNC_ERR_PROTOCOL);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, (size_t)injected_max_pages);

    char wm[64], stt[32];
    read_nvd_sync_state(h, wm, sizeof(wm), stt, sizeof(stt));
    CYTADEL_ASSERT_STREQ(wm, "");
    CYTADEL_ASSERT(strcmp(stt, "success") != 0);

    pthread_join(th, NULL);
    cytadel_db_close(db);
    free(page);
    for (size_t i = 0; i < fx.count; i++) {
        free(fx.responses[i]);
    }
    close(listen_fd);
}

/* ----- bulk-load ("start_date == NULL") regression ------------------------ */

/* Minimal single-request fixture, local to this one test: captures the
 * accepted connection's HTTP request line (up to the first "\r\n") so the
 * test can assert on the exact query string sent, not just the driver's
 * return status. Kept separate from `fixture_t`/`fixture_main` above (which
 * every other test in this file uses) rather than adding capture there,
 * since every other test's fixture_t would then need to free a
 * captured_request it never asked for. */
typedef struct {
    int listen_fd;
    char *response;
    size_t response_len;
    char *captured_request;
} bulk_load_fixture_t;

static void *bulk_load_fixture_main(void *arg) {
    bulk_load_fixture_t *fx = arg;
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
    fx->captured_request = line;

    (void)send(fd, fx->response, fx->response_len, 0);
    close(fd);
    return NULL;
}

/* Regression for a bug caught while building src/db/nvd_catchup.c (the
 * multi-window catch-up wrapper, the first caller to ever drive
 * cytadel_nvd_sync_window() with start_date == NULL all the way through to a
 * real cytadel_nvd_fetch_page() call): this header's own doc comment says a
 * bulk load ("start_date == NULL") sends NO lastModStartDate/lastModEndDate
 * filter at all -- but the driver used to forward `end_date` unconditionally
 * to the transport layer regardless of `start_date`, which
 * cytadel_nvd_fetch_page() rejects (it requires both dates set or neither).
 * Every bulk-load call therefore failed closed as CYTADEL_NVD_SYNC_ERR_FETCH
 * before this fix -- silently, since no test exercised this path end-to-end.
 * Proves both halves of the contract at once: no date-filter query params
 * are sent on the wire, AND `end_date` still becomes the stored watermark on
 * success (db-schema.md SS8 step 1's "the bulk load still ends at, and
 * advances the watermark to, end_date" -- only the outgoing HTTP filter is
 * suppressed, not the watermark write). */
static void test_sync_bulk_load_sends_no_date_filter(void) {
    uint16_t port = 0;
    int listen_fd = bind_ephemeral(&port);
    bulk_load_fixture_t fx = {.listen_fd = listen_fd};
    static const char *ids[] = {"CVE-2024-90001"};
    char *page = nvd_page_body(1, ids, 1);
    fx.response = http_response("HTTP/1.1 200 OK", page, -1, &fx.response_len);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, bulk_load_fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_migrated_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port, 0);

    cytadel_nvd_sync_counts_t counts;
    cytadel_nvd_sync_status_t st =
        cytadel_nvd_sync_window(db, &cfg, NULL, "2024-02-01T00:00:00.000Z", 0, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_NVD_SYNC_OK);
    CYTADEL_ASSERT_EQ(counts.cve_ingested, 1);

    pthread_join(th, NULL);
    CYTADEL_ASSERT(fx.captured_request != NULL);
    CYTADEL_ASSERT(strstr(fx.captured_request, "lastModStartDate=") == NULL);
    CYTADEL_ASSERT(strstr(fx.captured_request, "lastModEndDate=") == NULL);

    char wm[64], stt[32];
    read_nvd_sync_state(h, wm, sizeof(wm), stt, sizeof(stt));
    CYTADEL_ASSERT_STREQ(wm, "2024-02-01T00:00:00.000Z");
    CYTADEL_ASSERT_STREQ(stt, "success");

    free(fx.captured_request);
    cytadel_db_close(db);
    free(page);
    free(fx.response);
    close(listen_fd);
}

int main(void) {
    /* libcurl's send() can raise SIGPIPE when a fixture closes early; ignore
     * it process-wide (this binary never runs src/cli/main.c's startup). */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_fetch_size_cap_aborts();
    test_fetch_429_retry_then_success();
    test_fetch_5xx_gives_up();
    test_fetch_truncated_body_is_transport_error();
    test_fetch_missing_api_key_proceeds();
    test_sync_two_page_window_advances_watermark();
    test_sync_midwindow_failure_leaves_watermark_unchanged();
    test_sync_total_results_absent_is_protocol_error();
    test_sync_total_results_non_numeric_is_protocol_error();
    test_sync_total_results_negative_is_protocol_error();
    test_sync_total_results_huge_is_protocol_error();
    test_sync_max_pages_valve_is_injectable();
    test_sync_bulk_load_sends_no_date_filter();
    CYTADEL_TEST_PASS();
}
