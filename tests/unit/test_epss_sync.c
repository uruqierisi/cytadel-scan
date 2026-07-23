/* EPSS live-fetch driver tests (src/db/epss_sync.c). Deterministic loopback
 * fixture (one scripted response per accepted connection, in order) -- NO live
 * network. Proves: the limit/offset loop paginates using the envelope's own
 * `total`, ingests every page, advances the feed='epss' watermark only on the
 * FINAL page, and a mid-pull fetch failure leaves earlier pages' data committed
 * but the watermark un-advanced (idempotent re-pull next run). */

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
#include "cytadel/db/epss_sync.h"
#include "cytadel/net/nvd_fetch.h"

#define FIXTURE_MAX 4
typedef struct {
    int listen_fd;
    char *responses[FIXTURE_MAX]; /* NULL entry => send 0 bytes (transport fail) */
    size_t lens[FIXTURE_MAX];
    size_t count;
} fixture_t;

static int bind_ephemeral(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&a, sizeof(a)) == 0);
    CYTADEL_ASSERT(listen(fd, 4) == 0);
    struct sockaddr_in b;
    socklen_t bl = sizeof(b);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&b, &bl) == 0);
    *out_port = ntohs(b.sin_port);
    return fd;
}

static void *fixture_main(void *arg) {
    fixture_t *fx = arg;
    for (size_t i = 0; i < fx->count; i++) {
        int fd = accept(fx->listen_fd, NULL, NULL);
        if (fd < 0) {
            return NULL;
        }
        char req[2048];
        (void)recv(fd, req, sizeof(req), 0);
        if (fx->responses[i] != NULL) {
            (void)send(fd, fx->responses[i], fx->lens[i], 0);
        }
        close(fd);
    }
    return NULL;
}

static char *http_ok(const char *json, size_t *out_len) {
    char *buf = malloc(512 + strlen(json));
    CYTADEL_ASSERT(buf != NULL);
    int n = snprintf(buf, 512 + strlen(json),
                     "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %zu\r\n"
                     "Connection: close\r\n\r\n%s",
                     strlen(json), json);
    CYTADEL_ASSERT(n > 0);
    *out_len = (size_t)n;
    return buf;
}

static void make_cfg(cytadel_nvd_fetch_config_t *cfg, char *url_buf, size_t cap, uint16_t port) {
    cytadel_nvd_fetch_config_init_default(cfg);
    snprintf(url_buf, cap, "http://127.0.0.1:%u", (unsigned)port);
    cfg->base_url = url_buf;
    cfg->max_retries = 0;
    cfg->backoff_initial_ms = 1;
    cfg->backoff_max_ms = 2;
    cfg->connect_timeout_sec = 5;
    cfg->total_timeout_sec = 10;
    cfg->ca_info_path = NULL;
}

static cytadel_db_t *fresh_db(sqlite3 **h) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    *h = cytadel_db_handle(db);
    return db;
}

static int count_rows(sqlite3 *h, const char *sql) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(h, sql, -1, &st, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    int c = sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
    return c;
}

static void epss_watermark(sqlite3 *h, char *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(
                          h, "SELECT COALESCE(last_mod_watermark,'') FROM sync_state WHERE feed='epss';",
                          -1, &st, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    snprintf(out, cap, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
}

/* total=3 across two pages at limit=2: page 1 has 2 records, page 2 has 1. */
static const char *const PAGE1 =
    "{\"status\":\"OK\",\"total\":3,\"offset\":0,\"limit\":2,\"data\":["
    "{\"cve\":\"CVE-2021-44228\",\"epss\":\"0.97400\",\"percentile\":\"0.99999\",\"date\":\"2026-07-23\"},"
    "{\"cve\":\"CVE-2023-23397\",\"epss\":\"0.00123\",\"percentile\":\"0.42000\",\"date\":\"2026-07-23\"}]}";
static const char *const PAGE2 =
    "{\"status\":\"OK\",\"total\":3,\"offset\":2,\"limit\":2,\"data\":["
    "{\"cve\":\"CVE-2020-1472\",\"epss\":\"0.94000\",\"percentile\":\"0.98000\",\"date\":\"2026-07-23\"}]}";

static void test_epss_sync_paginates_and_ingests(void) {
    uint16_t port = 0;
    int lfd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = lfd, .count = 2};
    fx.responses[0] = http_ok(PAGE1, &fx.lens[0]);
    fx.responses[1] = http_ok(PAGE2, &fx.lens[1]);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_epss_sync_counts_t counts;
    cytadel_epss_sync_status_t st = cytadel_epss_sync(db, &cfg, url, 2, &counts); /* page_size=2 */
    CYTADEL_ASSERT_EQ(st, CYTADEL_EPSS_SYNC_OK);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 2);
    CYTADEL_ASSERT_EQ(counts.epss_ingested, 3);

    pthread_join(th, NULL);

    CYTADEL_ASSERT_EQ(count_rows(h, "SELECT COUNT(*) FROM epss;"), 3);
    char wm[64];
    epss_watermark(h, wm, sizeof(wm));
    CYTADEL_ASSERT(wm[0] != '\0'); /* advanced only after the final page */

    cytadel_db_close(db);
    free(fx.responses[0]);
    free(fx.responses[1]);
    close(lfd);
}

/* Page 1 OK (non-final: data committed, watermark untouched), page 2 transport
 * failure -> ERR_FETCH. Page 1's rows persist, but the watermark did NOT
 * advance -- so the next run safely re-pulls the whole feed from offset 0. */
static void test_epss_sync_midpull_failure_leaves_watermark_unadvanced(void) {
    uint16_t port = 0;
    int lfd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = lfd, .count = 2};
    fx.responses[0] = http_ok(PAGE1, &fx.lens[0]);
    fx.responses[1] = NULL; /* 0 bytes -> curl CURLE_GOT_NOTHING (transport) */
    fx.lens[1] = 0;

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port); /* max_retries=0 */

    cytadel_epss_sync_counts_t counts;
    cytadel_epss_sync_status_t st = cytadel_epss_sync(db, &cfg, url, 2, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_EPSS_SYNC_ERR_FETCH);
    CYTADEL_ASSERT_EQ(counts.pages_fetched, 1); /* only page 1 committed */

    pthread_join(th, NULL);

    CYTADEL_ASSERT_EQ(count_rows(h, "SELECT COUNT(*) FROM epss;"), 2); /* page 1 data persisted */
    char wm[64];
    epss_watermark(h, wm, sizeof(wm));
    CYTADEL_ASSERT_STREQ(wm, ""); /* NOT advanced -- re-pull whole feed next run */

    cytadel_db_close(db);
    free(fx.responses[0]);
    close(lfd);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_epss_sync_paginates_and_ingests();
    test_epss_sync_midpull_failure_leaves_watermark_unadvanced();
    CYTADEL_TEST_PASS();
}
