/* KEV live-fetch driver tests (src/db/kev_sync.c). Deterministic, loopback
 * fixture HTTP server (same bind-ephemeral + accept-thread pattern as
 * test_nvd_sync.c / test_nvd_catchup.c) -- NO live network. Proves the
 * transport wiring: a fetched CISA KEV catalog is ingested (kev table + cves
 * placeholder rows populate, feed='kev' watermark advances), and a fetch
 * failure leaves the watermark and table untouched. */

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
#include "cytadel/db/kev_sync.h"
#include "cytadel/net/nvd_fetch.h"

/* ----- loopback fixture (one scripted response per connection) ------------ */
typedef struct {
    int listen_fd;
    char *body;       /* NULL => send 0 bytes then close (transport failure) */
    size_t body_len;
} fixture_t;

static int bind_ephemeral(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 4) == 0);
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &blen) == 0);
    *out_port = ntohs(bound.sin_port);
    return fd;
}

static void *fixture_main(void *arg) {
    fixture_t *fx = arg;
    int fd = accept(fx->listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }
    char req[2048];
    (void)recv(fd, req, sizeof(req), 0);
    if (fx->body != NULL) {
        (void)send(fd, fx->body, fx->body_len, 0);
    }
    close(fd);
    return NULL;
}

static char *http_ok_json(const char *json, size_t *out_len) {
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
    cfg->base_url = url_buf; /* ignored by fetch_get, set for completeness */
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

static void kev_watermark(sqlite3 *h, char *out, size_t cap) {
    sqlite3_stmt *st = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(
                          h, "SELECT COALESCE(last_mod_watermark,'') FROM sync_state WHERE feed='kev';",
                          -1, &st, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(st), SQLITE_ROW);
    snprintf(out, cap, "%s", (const char *)sqlite3_column_text(st, 0));
    sqlite3_finalize(st);
}

static const char *const KEV_JSON =
    "{\"title\":\"CISA KEV\",\"catalogVersion\":\"2026.07.23\",\"count\":2,\"vulnerabilities\":["
    "{\"cveID\":\"CVE-2021-44228\",\"vendorProject\":\"Apache\",\"product\":\"Log4j2\","
    "\"vulnerabilityName\":\"Log4Shell\",\"dateAdded\":\"2021-12-10\",\"shortDescription\":\"RCE\","
    "\"requiredAction\":\"Patch\",\"dueDate\":\"2021-12-24\",\"knownRansomwareCampaignUse\":\"Known\","
    "\"notes\":\"https://example.test\"},"
    "{\"cveID\":\"CVE-2023-23397\",\"vendorProject\":\"Microsoft\",\"product\":\"Outlook\","
    "\"vulnerabilityName\":\"Priv esc\",\"dateAdded\":\"2023-03-14\",\"shortDescription\":\"x\","
    "\"requiredAction\":\"Patch\",\"dueDate\":\"2023-03-28\",\"knownRansomwareCampaignUse\":\"Unknown\","
    "\"notes\":\"\"}]}";

static void test_kev_sync_fetches_and_ingests(void) {
    uint16_t port = 0;
    int lfd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = lfd};
    fx.body = http_ok_json(KEV_JSON, &fx.body_len);

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_db(&h);
    char wm0[64];
    kev_watermark(h, wm0, sizeof(wm0));
    CYTADEL_ASSERT_STREQ(wm0, ""); /* seeded NULL */

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port);

    cytadel_kev_sync_counts_t counts;
    cytadel_kev_sync_status_t st = cytadel_kev_sync(db, &cfg, url, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_KEV_SYNC_OK);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 2);
    CYTADEL_ASSERT_EQ(counts.kev_skipped, 0);

    pthread_join(th, NULL);

    CYTADEL_ASSERT_EQ(count_rows(h, "SELECT COUNT(*) FROM kev;"), 2);
    /* placeholder-FK: both CVEs referenced but not NVD-ingested -> placeholder rows exist. */
    CYTADEL_ASSERT(count_rows(h, "SELECT COUNT(*) FROM cves WHERE cve_id IN "
                                 "('CVE-2021-44228','CVE-2023-23397');") == 2);
    char wm1[64];
    kev_watermark(h, wm1, sizeof(wm1));
    CYTADEL_ASSERT(wm1[0] != '\0'); /* watermark advanced to today's date */

    cytadel_db_close(db);
    free(fx.body);
    close(lfd);
}

static void test_kev_sync_fetch_failure_leaves_table_empty(void) {
    uint16_t port = 0;
    int lfd = bind_ephemeral(&port);
    fixture_t fx = {.listen_fd = lfd, .body = NULL, .body_len = 0}; /* 0 bytes -> transport fail */

    pthread_t th;
    CYTADEL_ASSERT(pthread_create(&th, NULL, fixture_main, &fx) == 0);

    sqlite3 *h = NULL;
    cytadel_db_t *db = fresh_db(&h);

    char url[64];
    cytadel_nvd_fetch_config_t cfg;
    make_cfg(&cfg, url, sizeof(url), port); /* max_retries=0 -> fails at once */

    cytadel_kev_sync_counts_t counts;
    cytadel_kev_sync_status_t st = cytadel_kev_sync(db, &cfg, url, &counts);
    CYTADEL_ASSERT_EQ(st, CYTADEL_KEV_SYNC_ERR_FETCH);
    CYTADEL_ASSERT_EQ(counts.kev_ingested, 0);

    pthread_join(th, NULL);

    CYTADEL_ASSERT_EQ(count_rows(h, "SELECT COUNT(*) FROM kev;"), 0);
    char wm[64];
    kev_watermark(h, wm, sizeof(wm));
    CYTADEL_ASSERT_STREQ(wm, ""); /* unchanged -- no partial state */

    cytadel_db_close(db);
    close(lfd);
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_kev_sync_fetches_and_ingests();
    test_kev_sync_fetch_failure_leaves_table_empty();
    CYTADEL_TEST_PASS();
}
