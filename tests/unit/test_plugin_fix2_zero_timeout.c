#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <errno.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Security-review round-2 FIX 2 (CRITICAL) regression test: before the
 * fix, cytadel_plugin_clamp_timeout_ms() (timeout_clamp.c) only floored
 * `remaining_ms` (the time left before the §4.5 deadline) to 1 ms, never
 * the CALLER's own timeout_ms. So a plugin passing timeout_ms = 0 straight
 * through to recv() sailed through unclamped whenever it was already <=
 * the remaining budget -- api_socket.c's recv() then built an all-zero
 * {0,0} struct timeval for SO_RCVTIMEO, which on Linux means "no timeout"
 * (block forever), not "expire immediately". Against a server that never
 * sends anything, that recv() call -- and the worker thread running
 * it -- would then hang forever; the §4.5 instruction-count debug hook
 * cannot preempt a thread blocked in a syscall executing no Lua VM
 * instructions.
 *
 * This test proves the fix returns promptly, WITHOUT itself being able to
 * hang the test suite if the regression is ever reintroduced (the task's
 * explicit constraint). cytadel_plugin_run_all_for_host() is synchronous
 * and gives this test no way to bound its own blocking recv() call from
 * the outside -- so the invocation instead runs on its own pthread (the
 * "runner"), which posts a semaphore when it finishes. The main thread
 * waits on that semaphore with a short, bounded absolute deadline
 * (CYTADEL_TEST_WATCHDOG_SECONDS -- generously larger than the low
 * hundreds of milliseconds a correctly-clamped recv() plus connection
 * setup/teardown should ever take, but tiny compared to "block forever").
 * If the deadline is reached, the fix has regressed: the runner thread is
 * still blocked inside the real recv(2) syscall, which POSIX guarantees is
 * a cancellation point, so pthread_cancel() reliably unblocks and
 * terminates it immediately (rather than needing to wait for it) -- this
 * test then fails via CYTADEL_ASSERT (which itself exit()s the process)
 * instead of hanging. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

/* Generous but still short: a correctly-clamped recv() (timeout_ms=0 ->
 * floored to ~1ms) plus real loopback connect/accept overhead should
 * complete in well under a second. The OLD buggy behavior blocks
 * effectively forever (no timeout at all), so this bound reliably tells
 * fixed apart from regressed without needing to be anywhere near tight. */
#define CYTADEL_TEST_WATCHDOG_SECONDS 3

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

/* Accepts the one connection and then deliberately sends nothing at all --
 * silence is the point, same reasoning as test_plugin_w1_timeout_clamp.c's
 * fixture server. */
static void *cytadel_silent_fixture_main(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) {
        return NULL;
    }
    char buf[16];
    recv(fd, buf, sizeof(buf), 0); /* blocks until peer closes; ignore result */
    close(fd);
    return NULL;
}

typedef struct {
    const cytadel_plugin_registry_t *registry;
    cytadel_kb_t *kb;
    cytadel_finding_list_t *findings;
    cytadel_plugin_result_status_t status;
} cytadel_runner_args_t;

static sem_t cytadel_test_runner_done_sem;

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    (void)bound_port;
    CYTADEL_ASSERT_EQ(script_id, 977001);
    *(cytadel_plugin_result_status_t *)user_data = status;
}

static void *cytadel_test_runner_main(void *arg) {
    cytadel_runner_args_t *args = arg;
    cytadel_plugin_run_all_for_host(args->registry, "127.0.0.1", args->kb, args->findings,
                                     cytadel_test_on_result, &args->status);
    /* Only reached if the invocation above actually returned -- i.e. the
     * clamp fix is working. If pthread_cancel() ever fires on this thread
     * (the watchdog-timeout path in main() below), this line is never
     * reached; the thread is torn down mid-recv() instead. */
    sem_post(&cytadel_test_runner_done_sem);
    return NULL;
}

int main(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t server_thread;
    CYTADEL_ASSERT(pthread_create(&server_thread, NULL, cytadel_silent_fixture_main, &listen_fd) ==
                    0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/fix2_zero_timeout", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));

    CYTADEL_ASSERT(sem_init(&cytadel_test_runner_done_sem, 0, 0) == 0);

    cytadel_runner_args_t runner_args;
    runner_args.registry = registry;
    runner_args.kb = kb;
    runner_args.findings = &findings;
    runner_args.status = CYTADEL_PLUGIN_RESULT_SKIPPED;

    pthread_t runner_thread;
    CYTADEL_ASSERT(pthread_create(&runner_thread, NULL, cytadel_test_runner_main, &runner_args) ==
                    0);

    struct timespec deadline;
    clock_gettime(CLOCK_REALTIME, &deadline); /* sem_timedwait() uses CLOCK_REALTIME, not MONOTONIC */
    deadline.tv_sec += CYTADEL_TEST_WATCHDOG_SECONDS;

    int wait_rc;
    do {
        wait_rc = sem_timedwait(&cytadel_test_runner_done_sem, &deadline);
    } while (wait_rc != 0 && errno == EINTR);

    if (wait_rc != 0) {
        /* Watchdog fired: the runner thread is still blocked inside the
         * real recv(2) syscall (a POSIX cancellation point) -- FIX 2 has
         * regressed. Cancel and reap it so this process can still exit
         * cleanly (rather than leaving a stray thread behind), then fail
         * loudly and fast instead of hanging the suite. */
        pthread_cancel(runner_thread);
        pthread_join(runner_thread, NULL);
        sem_destroy(&cytadel_test_runner_done_sem);
        fprintf(stderr,
                "%s:%d: FIX 2 REGRESSION: recv(sock, 512, timeout_ms=0) did not return within "
                "%d second(s) -- timeout_ms=0 is no longer being floored to >= 1ms before "
                "reaching SO_RCVTIMEO, so the {0,0} timeval is blocking forever (Linux "
                "semantics: an all-zero timeval disables the timeout).\n",
                __FILE__, __LINE__, CYTADEL_TEST_WATCHDOG_SECONDS);
        exit(1);
    }

    /* Fast path: the runner posted the semaphore itself, so it has already
     * returned (or is about to) -- this join is bounded, not blocking. */
    CYTADEL_ASSERT(pthread_join(runner_thread, NULL) == 0);
    sem_destroy(&cytadel_test_runner_done_sem);

    /* The fixture always error()s once recv() returns (see its own
     * comment) -- the important thing this test proves is WHEN it
     * returns, not the resulting status, but this is still a useful sanity
     * check that the invocation actually ran the fixture's run() body. */
    CYTADEL_ASSERT_EQ(runner_args.status, CYTADEL_PLUGIN_RESULT_FAILED);

    pthread_join(server_thread, NULL);
    close(listen_fd);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
