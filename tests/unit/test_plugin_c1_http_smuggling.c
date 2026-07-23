#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 security-audit finding C1 regression test: HTTP request
 * smuggling via an unvalidated http_get() `path`. Before the fix, a path
 * containing CR/LF (or a bare space) was passed straight into the request
 * line's snprintf(), letting a plugin append a second, state-changing
 * request onto the same wire write -- a direct violation of the
 * detection-only guarantee (plugin-api.md §0/§5.3). The fix
 * (api_http.c's cytadel_http_validate_path()) rejects such a path with
 * luaL_error() BEFORE any request bytes -- or even a TCP connection -- are
 * built.
 *
 * This test proves both halves of that guarantee end to end, through the
 * real public engine API only (no reaching into src/plugin's private
 * headers -- same convention as every other tests/unit/test_plugin_*.c
 * file):
 *   1. Both malicious fixtures (smuggle_crlf.lua, smuggle_space.lua) end
 *      up FAILED (http_get() raised, uncaught by the fixture on purpose).
 *   2. The companion legitimate fixture (smuggle_legit.lua) still
 *      succeeds normally.
 *   3. The shared loopback fixture server -- which the three fixtures'
 *      required_keys wildcard dispatches all target on the SAME port --
 *      accept()s exactly ONE connection for the whole run, and the bytes
 *      it receives are a single, well-formed "GET /ok HTTP/1.0" request
 *      line with no embedded "DELETE" substring anywhere. If either
 *      malicious fixture had ever reached the network (a regression of
 *      the fix), that connection would have been the one the server's
 *      single accept() received instead, and this assertion would catch
 *      it either as corrupted/smuggled request content or as the
 *      legitimate request never arriving at all (http_get() call #3 would
 *      then itself fail, also failing this test). */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

static int cytadel_test_bind_ephemeral(uint16_t *out_port) {
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
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

#define CYTADEL_TEST_REQ_BUF_LEN 4096

typedef struct {
    int listen_fd;
    char req_buf[CYTADEL_TEST_REQ_BUF_LEN];
    size_t req_len;
} cytadel_smuggle_fixture_args_t;

static void *cytadel_smuggle_fixture_main(void *arg) {
    cytadel_smuggle_fixture_args_t *args = arg;

    /* Exactly ONE accept() call for the entire test -- see this file's
     * top comment for why that alone is a meaningful regression check. */
    int fd = accept(args->listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }

    /* Read until the blank-line terminator (end of headers) or the
     * buffer/timeout bound -- the legitimate request has no body. */
    while (args->req_len < sizeof(args->req_buf) - 1) {
        ssize_t n = recv(fd, args->req_buf + args->req_len,
                          sizeof(args->req_buf) - 1 - args->req_len, 0);
        if (n <= 0) {
            break;
        }
        args->req_len += (size_t)n;
        if (args->req_len >= 4 &&
            memcmp(args->req_buf + args->req_len - 4, "\r\n\r\n", 4) == 0) {
            break;
        }
    }
    args->req_buf[args->req_len] = '\0';

    static const char response[] = "HTTP/1.0 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    send(fd, response, sizeof(response) - 1, 0);
    close(fd);
    return NULL;
}

typedef struct {
    int64_t script_id;
    cytadel_plugin_result_status_t status;
} cytadel_test_result_record_t;

typedef struct {
    cytadel_test_result_record_t records[8];
    size_t count;
} cytadel_test_result_log_t;

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    (void)bound_port;
    cytadel_test_result_log_t *log = user_data;
    CYTADEL_ASSERT(log->count < sizeof(log->records) / sizeof(log->records[0]));
    log->records[log->count].script_id = script_id;
    log->records[log->count].status = status;
    log->count++;
}

static cytadel_plugin_result_status_t cytadel_test_find_status(const cytadel_test_result_log_t *log,
                                                                 int64_t script_id) {
    for (size_t i = 0; i < log->count; i++) {
        if (log->records[i].script_id == script_id) {
            return log->records[i].status;
        }
    }
    CYTADEL_ASSERT(0 && "script_id not found in result log");
    return CYTADEL_PLUGIN_RESULT_FAILED;
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_smuggle_fixture_args_t args;
    memset(&args, 0, sizeof(args));
    args.listen_fd = listen_fd;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_smuggle_fixture_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/http_smuggle", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 3);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_result_log_t log;
    memset(&log, 0, sizeof(log));

    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    CYTADEL_ASSERT_EQ(log.count, 3);
    /* 1: both malicious paths must be rejected -- invocation FAILED. */
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 973001), CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 973002), CYTADEL_PLUGIN_RESULT_FAILED);
    /* 2: the legitimate request must still succeed normally. */
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 973003), CYTADEL_PLUGIN_RESULT_OK);
    CYTADEL_ASSERT_EQ(findings.count, 1);

    pthread_join(thread, NULL);

    /* 3: the server's single accept() saw exactly one, well-formed
     * request line -- no smuggled second request ever reached the wire. */
    CYTADEL_ASSERT(args.req_len > 0);
    CYTADEL_ASSERT(strncmp(args.req_buf, "GET /ok HTTP/1.0\r\n", strlen("GET /ok HTTP/1.0\r\n")) ==
                    0);
    CYTADEL_ASSERT(strstr(args.req_buf, "DELETE") == NULL);
    CYTADEL_ASSERT(strstr(args.req_buf, "/admin") == NULL);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);

    CYTADEL_TEST_PASS();
}
