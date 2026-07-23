#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 security-audit finding W2 regression test (Lua-level half):
 * before the fix, the "cytadel.socket" metatable had no __metatable
 * field, so a plugin could call `getmetatable(sock).__gc = nil` (an
 * ordinary table field write -- rawset() is not even required, both
 * getmetatable and plain table assignment are reachable from the
 * run-phase base-library sandbox) to strip the finalizer and defeat
 * §4.4's force-close guarantee entirely at the Lua level. The fix
 * (api_socket.c's cytadel_plugin_api_socket_register_metatable() setting
 * __metatable) locks the metatable: getmetatable() returns a harmless
 * placeholder instead of the real table, and setmetatable() raises.
 *
 * lock_test.lua asserts both of those directly from Lua and reports a
 * finding only if every tampering attempt was rejected; this test just
 * confirms the invocation succeeded with exactly that finding. */

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

static void *cytadel_accept_once_fixture_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd >= 0) {
        /* The plugin only opens/closes the socket -- nothing to send or
         * receive. Hold it open until the plugin's own close_sock() (or,
         * on a test failure, the engine's force-close) triggers an EOF. */
        char buf[16];
        recv(fd, buf, sizeof(buf), 0);
        close(fd);
    }
    return NULL;
}

int main(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_accept_once_fixture_main, &listen_fd) ==
                    0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/socket_metatable_lock",
                                           &registry);
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
    CYTADEL_ASSERT_STREQ(findings.items[0].title, "socket metatable lock check passed");

    pthread_join(thread, NULL);
    close(listen_fd);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
