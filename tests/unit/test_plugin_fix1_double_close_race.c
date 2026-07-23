#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
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

/* Security-review round-2 FIX 1 (CRITICAL) regression test: before the
 * fix, invoke.c's cytadel_plugin_invoke_cleanup() (the engine-side fd
 * tracker's force-close sweep) ran BEFORE lua_close(L) on every path. That
 * closes the real fd number and marks the tracker's slot -1, but has no
 * way to reach into the still-live socket userdata and clear ITS OWN
 * sock->fd field -- so the immediately-following lua_close(L) then runs
 * __gc on that same userdata, sees sock->fd still >= 0 (stale), and
 * close()s the SAME fd number a second time. Because this scanner's
 * workers are pthreads sharing one process-global fd table, if the OS had
 * already handed that freed fd number to a COMPLETELY UNRELATED thread's
 * brand-new resource in the gap between the two close() calls, that
 * second close() silently severs it out from under that other thread.
 *
 * This is fundamentally a RACE: reliably observing it requires something
 * else to actually grab the freed fd number in the microseconds-wide
 * window between the two close() calls. This test creates that race
 * directly: "leaker" threads continuously run the leak_never_close.lua
 * fixture (tests/plugins/fixtures/socket_fd_leak_loop/ -- opens exactly
 * one socket per invocation and never close_sock()'s it, so every
 * invocation's teardown exercises this exact double-close code path)
 * while "victim" threads concurrently, independently, and continuously
 * open+use+close their own small resources (a pipe(2) pair, written to
 * and immediately read back on the SAME thread) that draw fd numbers from
 * that SAME process-wide fd table. A pipe was chosen over another TCP
 * socket deliberately: it needs no network peer, so the round trip is as
 * fast as possible, maximizing how many independent "is this exact fd
 * number free right now" windows each victim thread offers per second --
 * which is what makes catching a sub-microsecond race between two
 * unrelated threads' fd churn feasible within a bounded test duration at
 * all. If a stray double-close ever lands on a currently-open victim pipe
 * fd, that pipe's read-back either fails outright or returns the wrong
 * byte (the fd having been silently torn down and, in principle, possibly
 * even reused yet again by something else in between) -- either way the
 * victim thread records it as a failure.
 *
 * Like any race-based regression test, this is probabilistic, not a
 * mathematical guarantee -- but with the buggy ordering reinstated (see
 * this file's own verification notes), thousands of leaker iterations
 * racing against continuously-cycling victim threads reliably produced
 * observable failures during this fix's own verification, and zero
 * failures with the fix applied. The iteration counts below were chosen
 * to keep the test's wall-clock cost bounded (a few seconds) while still
 * giving the race a realistic chance to manifest.
 *
 * Security-review round-3 finding W-2 (WARNING), stated plainly rather
 * than papered over: this test does NOT, and (as long as api_socket.c's
 * guard has genuine belt-and-braces coverage -- see the round-4 note
 * below) CANNOT, isolate FIX 1's invoke.c call-ordering (cleanup sweep
 * after lua_close(), not before) from api_socket.c's own independent
 * tracked+closed guard (cytadel_plugin_socket_close(), also added in
 * round 2). Reverting the ordering ALONE, with the guard still in place
 * and working correctly, does not reproduce the double-close at all: with
 * the ordering reverted, invoke.c's cleanup sweep (force_close_all() then
 * cytadel_plugin_fd_tracker_free()) runs BEFORE lua_close(L) -- so by the
 * time lua_close()'s own __gc pass calls cytadel_plugin_socket_close()
 * with a stale sock->fd >= 0, ctx->open_fds has already been force-closed
 * AND freed. cytadel_plugin_fd_tracker_is_tracked() still reports that
 * slot as tracked (its `count` is preserved across free() -- see
 * fd_tracker.c/.h) and cytadel_plugin_fd_tracker_is_closed() reports it as
 * closed (the `freed` flag), so the guard correctly skips close() again --
 * no second close ever happens, so this test (and, by the same reasoning,
 * no other black-box or race-based test observing the double-close
 * SYMPTOM) can fail from that reversion alone. The guard, on its own, is
 * already a complete and sufficient fix for the double-close hazard
 * regardless of ordering; this test is therefore a JOINT regression test
 * of FIX 1's ordering AND the guard TOGETHER, not of the ordering in
 * isolation. It reliably fails when BOTH are reverted together (the
 * pre-round-2 state) and reliably passes with the current code. See
 * tests/unit/test_plugin_r3w2_double_close_guard.c for a deterministic
 * (non-probabilistic) regression test of the guard itself.
 *
 * Security-review round-4: the guard's own coverage briefly regressed
 * (finding W-1 -- round 3's cytadel_plugin_fd_tracker_free() reset `count`
 * to 0, which made is_tracked() misreport a freed tracker's slots as
 * "never tracked" and let this exact reverted-ordering scenario fall
 * through to a real close() again; see test_plugin_r4w1_guard_survives_free.c),
 * now fixed and covered directly. Separately, round 4 added
 * tests/unit/test_plugin_r4w2_order_invariant.c, which proves the invoke.c
 * ordering itself directly (via a CYTADEL_BUILD_TESTING-only
 * instrumentation hook, not the double-close symptom this test and the
 * guard both revolve around) -- closing the "cannot isolate the ordering"
 * gap this comment described, without weakening the guard to make it
 * possible. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

#define CYTADEL_LEAKER_THREADS 4
#define CYTADEL_LEAKER_ITERATIONS 400
#define CYTADEL_VICTIM_THREADS 4

/* nanosleep() wrapper, same reasoning as test_plugin_w2_fd_force_close.c's
 * own (usleep() is not declared under this file's _POSIX_C_SOURCE). */
static void cytadel_test_sleep_poll_interval(void) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 500L * 1000L; /* 500us */
    nanosleep(&ts, NULL);
}

static int cytadel_test_bind_ephemeral(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 32) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

typedef struct {
    int listen_fd;
    uint16_t port;
    _Atomic bool stop;
} cytadel_drain_fixture_args_t;

/* Drains the accept backlog for the whole test's lifetime, accepting and
 * immediately closing every connection the leak_never_close.lua fixture
 * makes -- same shape as test_plugin_w2_fd_force_close.c's own drain
 * thread (this test only cares about the CLIENT/plugin side of each
 * connection). */
static void *cytadel_drain_fixture_main(void *arg) {
    cytadel_drain_fixture_args_t *args = arg;
    for (;;) {
        int fd = accept(args->listen_fd, NULL, NULL);
        if (fd < 0) {
            break;
        }
        close(fd);
        if (atomic_load(&args->stop)) {
            break; /* this was the wake-up connection -- stop, don't loop again */
        }
    }
    return NULL;
}

/* Same "close(listen_fd) alone does not reliably wake a thread blocked in
 * accept() on Linux" reasoning as test_plugin_w2_fd_force_close.c's own
 * shutdown helper. */
static void cytadel_test_stop_drain_thread(cytadel_drain_fixture_args_t *args) {
    atomic_store(&args->stop, true);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(args->port);
    connect(fd, (struct sockaddr *)&addr, sizeof(addr)); /* best-effort wake-up */
    close(fd);
}

typedef struct {
    const cytadel_plugin_registry_t *registry;
    cytadel_kb_t *kb; /* one KB per leaker thread -- kb-schema.md §6 single-writer-thread rule */
} cytadel_leaker_args_t;

static void *cytadel_leaker_main(void *arg) {
    cytadel_leaker_args_t *args = arg;
    for (int i = 0; i < CYTADEL_LEAKER_ITERATIONS; i++) {
        cytadel_finding_list_t findings;
        memset(&findings, 0, sizeof(findings));
        /* Every invocation opens exactly one socket and never
         * close_sock()'s it -- invoke.c's teardown for this invocation
         * exercises the exact lua_close()/cleanup-sweep ordering this
         * test targets. */
        cytadel_plugin_run_all_for_host(args->registry, "127.0.0.1", args->kb, &findings, NULL,
                                         NULL);
        cytadel_finding_list_free(&findings);
    }
    return NULL;
}

typedef struct {
    _Atomic bool stop;
    _Atomic long failures;
    _Atomic long iterations;
} cytadel_victim_shared_t;

/* Continuously opens a pipe(2) pair (drawing fd numbers from the SAME
 * process-wide fd table open_sock_tcp()'s sockets do), writes one unique
 * tag byte into it, and immediately reads it back on this SAME thread --
 * as fast a "does this fd number still genuinely belong to me" probe as
 * this test can construct. Runs until `shared->stop` is set by main(). */
static void *cytadel_victim_main(void *arg) {
    cytadel_victim_shared_t *shared = arg;
    unsigned char tag = 0;
    while (!atomic_load(&shared->stop)) {
        int fds[2];
        if (pipe(fds) != 0) {
            atomic_fetch_add(&shared->failures, 1);
            continue;
        }
        tag++;
        unsigned char readback = (unsigned char)(tag ^ 0xFF); /* deliberately wrong until proven right */
        ssize_t w = write(fds[1], &tag, 1);
        ssize_t r = (w == 1) ? read(fds[0], &readback, 1) : -1;
        if (w != 1 || r != 1 || readback != tag) {
            atomic_fetch_add(&shared->failures, 1);
        }
        close(fds[0]);
        close(fds[1]);
        atomic_fetch_add(&shared->iterations, 1);
    }
    return NULL;
}

int main(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_drain_fixture_args_t drain_args;
    drain_args.listen_fd = listen_fd;
    drain_args.port = port;
    atomic_init(&drain_args.stop, false);

    pthread_t drain_thread;
    CYTADEL_ASSERT(pthread_create(&drain_thread, NULL, cytadel_drain_fixture_main, &drain_args) ==
                    0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/socket_fd_leak_loop", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    /* Victim threads start first, so they are already racing by the time
     * the first leaker invocation's teardown runs. */
    cytadel_victim_shared_t victim_shared;
    atomic_init(&victim_shared.stop, false);
    atomic_init(&victim_shared.failures, 0);
    atomic_init(&victim_shared.iterations, 0);

    pthread_t victim_threads[CYTADEL_VICTIM_THREADS];
    for (int i = 0; i < CYTADEL_VICTIM_THREADS; i++) {
        CYTADEL_ASSERT(pthread_create(&victim_threads[i], NULL, cytadel_victim_main,
                                       &victim_shared) == 0);
    }

    cytadel_kb_t *kbs[CYTADEL_LEAKER_THREADS];
    cytadel_leaker_args_t leaker_args[CYTADEL_LEAKER_THREADS];
    pthread_t leaker_threads[CYTADEL_LEAKER_THREADS];
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);

    for (int i = 0; i < CYTADEL_LEAKER_THREADS; i++) {
        kbs[i] = cytadel_kb_create();
        cytadel_kb_set_int(kbs[i], key, port);
        leaker_args[i].registry = registry;
        leaker_args[i].kb = kbs[i];
        CYTADEL_ASSERT(pthread_create(&leaker_threads[i], NULL, cytadel_leaker_main,
                                       &leaker_args[i]) == 0);
    }

    for (int i = 0; i < CYTADEL_LEAKER_THREADS; i++) {
        CYTADEL_ASSERT(pthread_join(leaker_threads[i], NULL) == 0);
    }

    /* Give the victims a brief extra window after the last leaker
     * teardown completes -- lua_close()'s own __gc pass and the
     * force-close sweep both still need to finish for the very last
     * invocation, and any resulting stray close() needs a chance to land
     * on a victim fd that is still in flight. */
    for (int i = 0; i < 20; i++) {
        cytadel_test_sleep_poll_interval();
    }

    atomic_store(&victim_shared.stop, true);
    for (int i = 0; i < CYTADEL_VICTIM_THREADS; i++) {
        CYTADEL_ASSERT(pthread_join(victim_threads[i], NULL) == 0);
    }

    cytadel_test_stop_drain_thread(&drain_args);
    pthread_join(drain_thread, NULL);
    close(listen_fd);

    for (int i = 0; i < CYTADEL_LEAKER_THREADS; i++) {
        cytadel_kb_free(kbs[i]);
    }
    cytadel_plugin_registry_free(registry);

    long iterations = atomic_load(&victim_shared.iterations);
    long failures = atomic_load(&victim_shared.failures);
    CYTADEL_ASSERT(iterations > 0); /* sanity: the victim threads actually ran */

    if (failures != 0) {
        fprintf(stderr,
                "%s: FIX 1 REGRESSION: %ld/%ld victim pipe round-trips were corrupted by a "
                "stray fd double-close raced in from a leaker thread's teardown -- see "
                "invoke.c's cytadel_plugin_invoke_cleanup() call-ordering comment.\n",
                __FILE__, failures, iterations);
        exit(1);
    }

    CYTADEL_TEST_PASS();
}
