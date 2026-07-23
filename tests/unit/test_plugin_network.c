#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5: socket API (open_sock_tcp/send/recv/close_sock, §2.4-§2.7,
 * §4.4's force-close guarantee) and http_get (§2.8), against real loopback
 * fixture servers -- same accept()-on-a-background-thread shape as
 * test_service_detect.c's fixtures. */

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

/* --------------------------------------------------------------------- *
 * Socket API fixture server: accepts exactly 2 connections in sequence
 * (one for sock_test.lua, one for sock_leak.lua), draining "PING\r\n" and
 * replying "PONG\r\n" to the first, and for the second (sock_leak.lua,
 * which never calls close_sock()) waiting to observe the peer close the
 * connection on its own -- proving plugin-api.md §4.4's force-close
 * guarantee (lua_close()'s __gc/__close on the leaked socket userdata).
 * --------------------------------------------------------------------- */

typedef struct {
    int listen_fd;
    bool leak_eof_observed;
} cytadel_socket_fixture_args_t;

static void *cytadel_socket_fixture_main(void *arg) {
    cytadel_socket_fixture_args_t *args = arg;

    /* Connection 1: sock_test.lua -- drain "PING\r\n", reply "PONG\r\n". */
    int fd1 = accept(args->listen_fd, NULL, NULL);
    if (fd1 >= 0) {
        char buf[64];
        recv(fd1, buf, sizeof(buf), 0);
        static const char reply[] = "PONG\r\n";
        send(fd1, reply, sizeof(reply) - 1, 0);
        close(fd1);
    }

    /* Connection 2: sock_leak.lua -- never told to close_sock(); this
     * engine's lua_close() must force-close it anyway. Wait (bounded) for
     * that close to arrive as an orderly EOF. */
    int fd2 = accept(args->listen_fd, NULL, NULL);
    if (fd2 >= 0) {
        char buf[64];
        recv(fd2, buf, sizeof(buf), 0); /* drain "PING\r\n" */

        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(fd2, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        ssize_t n = recv(fd2, buf, sizeof(buf), 0);
        args->leak_eof_observed = (n == 0);
        close(fd2);
    }

    return NULL;
}

static void test_socket_api(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_socket_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.leak_eof_observed = false;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_socket_fixture_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/socket_api", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 2);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    /* By the time this call returns, BOTH invocations' lua_States have
     * already been lua_close()'d (invoke.c's cytadel_plugin_invoke_one()
     * closes unconditionally before returning, and the scheduler runs
     * invocations sequentially) -- including sock_leak.lua's, so its
     * socket is guaranteed already force-closed here. */
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    CYTADEL_ASSERT_EQ(findings.count, 1);
    CYTADEL_ASSERT_STREQ(findings.items[0].evidence, "PONG\r\n");

    pthread_join(thread, NULL);
    CYTADEL_ASSERT(args.leak_eof_observed);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

/* --------------------------------------------------------------------- *
 * http_get fixture server: accepts exactly 1 connection, drains the
 * request, replies with a full HTTP/1.1 response (status/headers/body)
 * the fixture plugin asserts against via the KB.
 * --------------------------------------------------------------------- */

static void *cytadel_http_fixture_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }

    char req[4096];
    recv(fd, req, sizeof(req), 0); /* best-effort drain */

    static const char body[] = "hello from the fixture server";
    char response[512];
    int len = snprintf(response, sizeof(response),
                        "HTTP/1.1 200 OK\r\n"
                        "Content-Type: text/plain\r\n"
                        "X-Fixture: yes\r\n"
                        "Content-Length: %zu\r\n"
                        "Connection: close\r\n"
                        "\r\n"
                        "%s",
                        sizeof(body) - 1, body);
    send(fd, response, (size_t)len, 0);
    close(fd);
    return NULL;
}

static void test_http_get(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_http_fixture_main, &listen_fd) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/http_api", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    CYTADEL_ASSERT_EQ(findings.count, 1);

    cytadel_kb_value_t status, body_len, content_type, x_custom;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/http_api/status", &status), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(status.v.i64, 200);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/http_api/body_len", &body_len),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(body_len.v.i64, (int64_t)strlen("hello from the fixture server"));
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/http_api/content_type", &content_type),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_STREQ(content_type.v.str, "text/plain");
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/http_api/x_custom", &x_custom),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_STREQ(x_custom.v.str, "yes");

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

/* --------------------------------------------------------------------- *
 * http_get 1 MiB body-cap fixture server: sends a body far larger than
 * the cap; the fixture plugin records the length http_get() actually
 * returned to Lua.
 * --------------------------------------------------------------------- */

#define CYTADEL_TEST_BIG_BODY_LEN (2 * 1024 * 1024) /* 2 MiB, well past the 1 MiB cap */

static void *cytadel_http_cap_fixture_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }

    char req[4096];
    recv(fd, req, sizeof(req), 0);

    char header[256];
    int header_len = snprintf(header, sizeof(header),
                               "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                               "Connection: close\r\n\r\n");
    send(fd, header, (size_t)header_len, 0);

    char chunk[65536];
    memset(chunk, 'A', sizeof(chunk));
    size_t remaining = CYTADEL_TEST_BIG_BODY_LEN;
    while (remaining > 0) {
        size_t this_chunk = (remaining < sizeof(chunk)) ? remaining : sizeof(chunk);
        ssize_t n = send(fd, chunk, this_chunk, 0);
        if (n <= 0) {
            break;
        }
        remaining -= (size_t)n;
    }
    close(fd);
    return NULL;
}

static void test_http_get_body_cap(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_http_cap_fixture_main, &listen_fd) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/http_api_cap", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    cytadel_kb_value_t body_len;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/http_cap/body_len", &body_len),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(body_len.v.i64, 1048576); /* §2.8: exactly 1 MiB */

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

int main(void) {
    /* http_get()'s SSL_write()/send() paths can raise SIGPIPE if a
     * fixture server closes its end early -- same reasoning as
     * test_tls_inspect.c's own startup ignore (this binary is its own
     * process, never runs src/cli/main.c's startup path). */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_socket_api();
    test_http_get();
    test_http_get_body_cap();
    CYTADEL_TEST_PASS();
}
