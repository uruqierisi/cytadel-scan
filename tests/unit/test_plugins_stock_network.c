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
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 6: plugins/http_headers.lua is this stock-plugin set's one
 * ACT_SETTINGS gathering plugin that must issue a real http_get() (kb-
 * schema.md §7.6 documents it as the writer of HTTP/<port>/headers/<name>).
 * Every other stock-plugin test lives in test_plugins_stock.c and is driven
 * purely by KB fixtures; this file is the deliberate, narrow exception --
 * same real loopback-fixture-server pattern test_plugin_network.c already
 * uses for the engine's own http_get() tests (accept() on a background
 * thread, no external network, no real target). */

#ifndef CYTADEL_PLUGINS_DIR
#define CYTADEL_PLUGINS_DIR "plugins"
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

typedef struct {
    int listen_fd;
    const char *response; /* full raw HTTP response bytes to send verbatim */
    size_t response_len;
} cytadel_fixture_args_t;

static void *cytadel_fixture_respond_main(void *arg) {
    cytadel_fixture_args_t *args = arg;
    int fd = accept(args->listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }
    char req[4096];
    recv(fd, req, sizeof(req), 0); /* best-effort drain */
    send(fd, args->response, args->response_len, 0);
    close(fd);
    return NULL;
}

/* Accepts a connection and closes it immediately without sending anything
 * -- the "malformed/hostile" case: a server that speaks no HTTP at all. */
static void *cytadel_fixture_hangup_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }
    char req[4096];
    recv(fd, req, sizeof(req), 0);
    close(fd);
    return NULL;
}

/* Positive: a response carrying every tracked header (mixed-case names, to
 * also prove http_get()'s own header-name lowercasing -- plugin-api.md
 * §2.8 -- is what this plugin actually relies on) must all be written to
 * the KB. */
static void test_http_headers_positive(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    static const char response[] =
        "HTTP/1.1 200 OK\r\n"
        "Strict-Transport-Security: max-age=63072000; includeSubDomains\r\n"
        "Content-Security-Policy: default-src 'self'\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "X-Frame-Options: DENY\r\n"
        "Set-Cookie: sessionid=abc123; Secure; HttpOnly\r\n"
        "Referrer-Policy: no-referrer\r\n"
        "X-Powered-By: PHP/8.2.0\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Length: 2\r\n"
        "Connection: close\r\n"
        "\r\n"
        "ok";

    cytadel_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.response = response;
    args.response_len = sizeof(response) - 1;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_fixture_respond_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_PLUGINS_DIR, &registry);
    CYTADEL_ASSERT_EQ(rc, 0);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings = {0};
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    static const struct {
        const char *header;
        const char *expected;
    } expectations[] = {
        {"strict-transport-security", "max-age=63072000; includeSubDomains"},
        {"content-security-policy", "default-src 'self'"},
        {"x-content-type-options", "nosniff"},
        {"x-frame-options", "DENY"},
        {"set-cookie", "sessionid=abc123; Secure; HttpOnly"},
        {"referrer-policy", "no-referrer"},
        {"x-powered-by", "PHP/8.2.0"},
        {"server", "nginx/1.24.0"},
    };
    for (size_t i = 0; i < sizeof(expectations) / sizeof(expectations[0]); i++) {
        char kb_key[96];
        snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/%s", (unsigned)port,
                 expectations[i].header);
        cytadel_kb_value_t v;
        CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_FOUND);
        CYTADEL_ASSERT_EQ(v.type, CYTADEL_KB_TYPE_STRING);
        CYTADEL_ASSERT_STREQ(v.v.str, expectations[i].expected);
    }

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

/* Negative: a response with none of the tracked headers must leave every
 * HTTP/<port>/headers/(any) key absent. */
static void test_http_headers_negative(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    static const char response[] = "HTTP/1.1 200 OK\r\n"
                                    "Content-Type: text/plain\r\n"
                                    "Content-Length: 2\r\n"
                                    "Connection: close\r\n"
                                    "\r\n"
                                    "ok";

    cytadel_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.response = response;
    args.response_len = sizeof(response) - 1;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_fixture_respond_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_PLUGINS_DIR, &registry);
    CYTADEL_ASSERT_EQ(rc, 0);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings = {0};
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    cytadel_kb_value_t v;
    char kb_key[96];
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/server", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_NOT_FOUND);
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/x-frame-options", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_NOT_FOUND);

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

/* Malformed/hostile: the peer accepts the connection and then hangs up
 * without sending any bytes at all (http_get() must see this as a failed
 * response, not a crash) -- the plugin must not raise, and no KB header
 * keys are written. */
static void test_http_headers_hangup(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_fixture_hangup_main, &listen_fd) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_PLUGINS_DIR, &registry);
    CYTADEL_ASSERT_EQ(rc, 0);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings = {0};
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    cytadel_kb_value_t v;
    char kb_key[96];
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/server", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_NOT_FOUND);

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

/* Counts findings produced by `script_id` in `list`. */
static size_t cytadel_test_net_count(const cytadel_finding_list_t *list, int64_t script_id) {
    size_t n = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].script_id == script_id) {
            n++;
        }
    }
    return n;
}

/* Malformed/hostile: attacker-controlled response headers that individually
 * make set_kb_item() RAISE -- an embedded NUL (strict-transport-security,
 * loop index 0) and an over-length value (content-security-policy, ~5000 B >
 * the 4096 KB limit, loop index 1). Before the http_headers.lua fix, the
 * first raise unwound run() AFTER the _probed sentinel was set, so every
 * later header (x-content-type-options, x-frame-options, ...) was never
 * recorded and http_missing_csp/xcto/xfo each fired a FALSE "missing header"
 * finding. This test proves two things at once: (1) the three absence-based
 * plugins stay SILENT (presence is preserved -- the NUL is stripped and the
 * over-length value clipped, so each key is still written), and (2) headers
 * positioned AFTER the malformed ones in the loop are still recorded, i.e.
 * one bad header no longer hides the rest (ordering-independence). Total
 * response stays under CYTADEL_HTTP_RESPONSE_MAX_LEN (8192) so nothing is
 * dropped by the engine's own read cap -- every drop under test is the
 * plugin's decision, not the transport's. */
static void test_http_headers_hostile_value_preserves_presence(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    char response[8000];
    size_t n = 0;
    n += (size_t)snprintf(response + n, sizeof(response) - n, "HTTP/1.1 200 OK\r\n");
    /* hsts: value with an embedded NUL (loop index 0). */
    n += (size_t)snprintf(response + n, sizeof(response) - n, "Strict-Transport-Security: max-age=");
    response[n++] = '\0';
    n += (size_t)snprintf(response + n, sizeof(response) - n, "63072000\r\n");
    /* csp: ~5000-byte value, over the 4096 KB limit (loop index 1). */
    n += (size_t)snprintf(response + n, sizeof(response) - n, "Content-Security-Policy: ");
    for (int i = 0; i < 5000; i++) {
        response[n++] = 'A';
    }
    n += (size_t)snprintf(response + n, sizeof(response) - n, "\r\n");
    /* valid headers AFTER both hostile ones in TRACKED_HEADERS order. */
    n += (size_t)snprintf(response + n, sizeof(response) - n, "X-Content-Type-Options: nosniff\r\n");
    n += (size_t)snprintf(response + n, sizeof(response) - n, "X-Frame-Options: DENY\r\n");
    n += (size_t)snprintf(response + n, sizeof(response) - n,
                          "Content-Length: 2\r\nConnection: close\r\n\r\nok");
    CYTADEL_ASSERT(n < sizeof(response));

    cytadel_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.response = response;
    args.response_len = n;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_fixture_respond_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_PLUGINS_DIR, &registry);
    CYTADEL_ASSERT_EQ(rc, 0);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings = {0};
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    /* (1) No false "missing header" finding from any of the three absence
     * plugins -- presence was preserved despite the hostile values. */
    CYTADEL_ASSERT_EQ(cytadel_test_net_count(&findings, 100032), 0); /* http_missing_csp  */
    CYTADEL_ASSERT_EQ(cytadel_test_net_count(&findings, 100033), 0); /* http_missing_xcto */
    CYTADEL_ASSERT_EQ(cytadel_test_net_count(&findings, 100034), 0); /* http_missing_xfo  */

    cytadel_kb_value_t v;
    char kb_key[96];

    /* (2) Ordering-independence: headers AFTER the malformed ones were still
     * recorded with their real values -- the loop did not abort. */
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/x-content-type-options", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_STREQ(v.v.str, "nosniff");
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/x-frame-options", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_STREQ(v.v.str, "DENY");

    /* Presence preserved for the hostile headers too: NUL stripped, and the
     * over-length value clipped to the 4096 KB limit. */
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/strict-transport-security", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_FOUND);
    /* The NUL between "max-age=" and "63072000" was stripped, leaving the two
     * fragments joined -- had it survived, set_kb_item would have rejected the
     * write and this key would be NOT_FOUND above. */
    CYTADEL_ASSERT_STREQ(v.v.str, "max-age=63072000");
    snprintf(kb_key, sizeof(kb_key), "HTTP/%u/headers/content-security-policy", (unsigned)port);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, kb_key, &v), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(v.type, CYTADEL_KB_TYPE_STRING);
    CYTADEL_ASSERT(strlen(v.v.str) <= 4096);

    pthread_join(thread, NULL);
    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    close(listen_fd);
}

int main(void) {
    /* Same reasoning as test_plugin_network.c's own startup ignore: this
     * binary is its own process and never runs src/cli/main.c's startup
     * path, so http_get()'s send() can raise SIGPIPE if a fixture server
     * closes its end early unless ignored here. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_http_headers_positive();
    test_http_headers_negative();
    test_http_headers_hangup();
    test_http_headers_hostile_value_preserves_presence();
    CYTADEL_TEST_PASS();
}
