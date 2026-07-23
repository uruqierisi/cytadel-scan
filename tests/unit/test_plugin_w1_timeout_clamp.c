#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 security-audit finding W1 regression test: before the fix,
 * timeout_ms passed to open_sock_tcp()/recv()/http_get() was only clamped
 * on the LOW side (negative -> 0), so a plugin passing an enormous
 * timeout_ms (e.g. 999999999 ms, ~11.5 days) could make a single blocking
 * C call run far longer than the §4.5 15000 ms run-phase budget --
 * because a blocking syscall executes no Lua VM instructions, the
 * instruction-count runtime-limit hook cannot preempt it while blocked.
 *
 * This test proves the fix end to end: recv()'s timeout_ms is silently
 * clamped (api_socket.c's cytadel_plugin_clamp_timeout_ms() call, via
 * timeout_clamp.c) to at most CYTADEL_PLUGIN_MAX_RUNTIME_MS regardless of
 * what the plugin requested, so the whole invocation -- including the
 * fixture server accept()/connect() -- completes within a small, bounded
 * multiple of that fixed budget, not anywhere close to 999999999 ms.
 *
 * Inherently slow (~15s, the frozen §4.5 default) by construction -- kept
 * in its own file/binary, same reasoning as the existing
 * test_plugin_runtime_limit.c. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

/* Generous upper bound: the fixed §4.5 budget (15000 ms) plus slack for
 * scheduling/connect overhead. Nowhere near the 999999999 ms the fixture
 * actually requested -- if the clamp regressed, this test would time out
 * (or hang the whole suite) rather than merely fail an assertion, which
 * is itself a strong, unambiguous signal of the regression. */
#define CYTADEL_TEST_MAX_ELAPSED_MS 20000

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

/* Accepts the one connection and then deliberately sends nothing at all
 * -- silence is the point: any reply would let recv() return quickly for
 * an unrelated reason, defeating the purpose of this test. */
static void *cytadel_silent_fixture_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }
    /* Hold the connection open until the plugin's recv() gives up
     * (clamped timeout) and close_sock()/the engine closes it. */
    char buf[16];
    recv(fd, buf, sizeof(buf), 0); /* blocks until peer closes; ignore result */
    close(fd);
    return NULL;
}

static long long cytadel_test_elapsed_ms(struct timespec start, struct timespec end) {
    return ((long long)end.tv_sec - (long long)start.tv_sec) * 1000 +
           ((long long)end.tv_nsec - (long long)start.tv_nsec) / 1000000;
}

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    (void)bound_port;
    CYTADEL_ASSERT_EQ(script_id, 974001);
    *(cytadel_plugin_result_status_t *)user_data = status;
}

int main(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_silent_fixture_main, &listen_fd) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/timeout_clamp", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_plugin_result_status_t status = CYTADEL_PLUGIN_RESULT_SKIPPED;

    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &status);
    clock_gettime(CLOCK_MONOTONIC, &end);

    long long elapsed_ms = cytadel_test_elapsed_ms(start, end);

    /* The fixture always error()s (see its own comment) once recv()
     * returns -- the important thing proven here is WHEN it returns. */
    CYTADEL_ASSERT_EQ(status, CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT(elapsed_ms < CYTADEL_TEST_MAX_ELAPSED_MS);

    pthread_join(thread, NULL);
    close(listen_fd);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
