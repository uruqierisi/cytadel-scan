#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/net/service_detect.h"

/* Loopback service fixtures, same shape as test_port_scanner.c's /
 * test_worker_pool.c's: bind a real listener, accept exactly one
 * connection on a background thread, optionally drain a bit of the
 * incoming request, write a canned response, close. */

static int cytadel_test_bind_ephemeral(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 1) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

/* Binds to the first of `candidates` that succeeds -- used only for the
 * HTTP fixture below, which (unlike SSH/FTP, dispatched by banner
 * signature) is dispatched by well-known port number
 * (cytadel_svc_is_http_port()), so it needs a real port from that list
 * rather than an OS-assigned ephemeral one. All candidates are
 * unprivileged (> 1024), so no root is required. */
static int cytadel_test_bind_fixed(const uint16_t *candidates, size_t count, uint16_t *out_port) {
    for (size_t i = 0; i < count; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        CYTADEL_ASSERT(fd >= 0);

        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(candidates[i]);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, 1) == 0) {
            *out_port = candidates[i];
            return fd;
        }
        close(fd);
    }
    CYTADEL_ASSERT(0 && "no candidate HTTP test port was available");
    return -1;
}

typedef struct {
    int listen_fd;
    const char *response;
    size_t response_len;
    bool drain_request; /* read (and discard) a bit of incoming data before responding */
} cytadel_fixture_args_t;

static void *cytadel_fixture_server_main(void *arg) {
    cytadel_fixture_args_t *args = (cytadel_fixture_args_t *)arg;

    int fd = accept(args->listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }

    if (args->drain_request) {
        char buf[512];
        recv(fd, buf, sizeof(buf), 0); /* best-effort; ignore result */
    }

    size_t sent = 0;
    while (sent < args->response_len) {
        ssize_t n = send(fd, args->response + sent, args->response_len - sent, 0);
        if (n <= 0) {
            break;
        }
        sent += (size_t)n;
    }

    close(fd);
    return NULL;
}

static void cytadel_run_fixture(int listen_fd, const char *response, size_t response_len,
                                 bool drain_request, uint16_t port, cytadel_kb_t *kb) {
    cytadel_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.response = response;
    args.response_len = response_len;
    args.drain_request = drain_request;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_fixture_server_main, &args) == 0);

    cytadel_service_detect_opts_t opts;
    opts.connect_timeout_ms = 1000;
    opts.read_timeout_ms = 1000;
    cytadel_service_detect_port("127.0.0.1", port, &opts, kb, NULL);

    pthread_join(thread, NULL);
}

static void test_ssh_banner_detection(void) {
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    static const char banner[] = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu3.6\r\n";
    cytadel_run_fixture(listen_fd, banner, strlen(banner), false, port, kb);

    char key[64];

    snprintf(key, sizeof(key), "Banner/%u", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu3.6");

    snprintf(key, sizeof(key), "SSH/%u/version", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu3.6");

    snprintf(key, sizeof(key), "SSH/%u/protocol", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "2.0");

    snprintf(key, sizeof(key), "Services/ssh/%u", (unsigned)port);
    cytadel_kb_value_t svc;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &svc), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(svc.type, CYTADEL_KB_TYPE_INT);
    CYTADEL_ASSERT_EQ(svc.v.i64, port);

    /* CPE bridge: a known OpenSSH banner must produce the expected CPE. */
    snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key),
                          "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*");

    close(listen_fd);
    cytadel_kb_free(kb);
}

static void test_ftp_greeting_detection(void) {
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    static const char banner[] = "220 (vsFTPd 3.0.5)\r\n";
    cytadel_run_fixture(listen_fd, banner, strlen(banner), false, port, kb);

    char key[64];

    snprintf(key, sizeof(key), "FTP/%u/banner", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "220 (vsFTPd 3.0.5)");

    snprintf(key, sizeof(key), "Services/ftp/%u", (unsigned)port);
    cytadel_kb_value_t svc;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &svc), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(svc.v.i64, port);

    snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key),
                          "cpe:2.3:a:vsftpd_project:vsftpd:3.0.5:*:*:*:*:*:*:*");

    close(listen_fd);
    cytadel_kb_free(kb);
}

static void test_http_baseline_detection(void) {
    static const uint16_t candidates[] = {8080, 8000, 8888};
    uint16_t port;
    int listen_fd =
        cytadel_test_bind_fixed(candidates, sizeof(candidates) / sizeof(candidates[0]), &port);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><head><title>Test Page</title></head><body>hi</body></html>";
    cytadel_run_fixture(listen_fd, response, strlen(response), true, port, kb);

    char key[64];

    snprintf(key, sizeof(key), "HTTP/%u/server", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "nginx/1.24.0");

    snprintf(key, sizeof(key), "HTTP/%u/status", (unsigned)port);
    cytadel_kb_value_t status;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &status), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(status.v.i64, 200);

    snprintf(key, sizeof(key), "HTTP/%u/title", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "Test Page");

    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_value_t svc;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &svc), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(svc.v.i64, port);

    /* Plaintext HTTP (no TLS handshake attempted on these ports) must NOT
     * get the paired Services/https/<port> key (kb-schema.md §7.3). */
    snprintf(key, sizeof(key), "Services/https/%u", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) == NULL);

    snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");

    close(listen_fd);
    cytadel_kb_free(kb);
}

/* Untrusted-input regression test: a peer that sends a large amount of
 * non-UTF8, NUL-containing garbage immediately on connect must never crash
 * or corrupt memory (this is what ASan/UBSan runs of this test binary are
 * specifically checking), and the resulting Banner/<port> value (if any)
 * must never exceed the KB's own value cap. */
static void test_garbage_oversized_banner_is_handled_safely(void) {
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    size_t garbage_len = 20000; /* well beyond CYTADEL_KB_VALUE_MAX_LEN (4096) */
    char *garbage = malloc(garbage_len);
    CYTADEL_ASSERT(garbage != NULL);
    for (size_t i = 0; i < garbage_len; i++) {
        /* Deliberately includes 0x00 bytes and non-UTF8 high bytes --
         * exactly the input the KB's embedded-NUL/UTF-8 validation
         * (kb-schema.md §3) exists to reject. */
        garbage[i] = (char)(unsigned char)((i * 37 + 11) & 0xFF);
    }

    cytadel_run_fixture(listen_fd, garbage, garbage_len, false, port, kb);

    /* No crash getting here is itself the primary assertion. Additionally:
     * whatever ended up in Banner/<port> (it may legitimately be absent,
     * since the raw bytes are near-certainly invalid UTF-8 and/or contain
     * an embedded NUL and the KB rejects rather than truncates such a
     * value) must never exceed the KB's own cap. */
    char key[64];
    snprintf(key, sizeof(key), "Banner/%u", (unsigned)port);
    const char *stored = cytadel_kb_get_str(kb, key);
    if (stored != NULL) {
        CYTADEL_ASSERT(strlen(stored) <= CYTADEL_KB_VALUE_MAX_LEN);
    }

    free(garbage);
    close(listen_fd);
    cytadel_kb_free(kb);
}

/* A connection that never sends anything at all (open port, silent peer)
 * must be handled without hanging past the configured timeout and without
 * writing a bogus Banner/<port> entry. */
static void test_silent_peer_writes_no_banner(void) {
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    cytadel_run_fixture(listen_fd, "", 0, false, port, kb);

    char key[64];
    snprintf(key, sizeof(key), "Banner/%u", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) == NULL);

    close(listen_fd);
    cytadel_kb_free(kb);
}

int main(void) {
    test_ssh_banner_detection();
    test_ftp_greeting_detection();
    test_http_baseline_detection();
    test_garbage_oversized_banner_is_handled_safely();
    test_silent_peer_writes_no_banner();
    CYTADEL_TEST_PASS();
}
