#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <dirent.h>
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

/* Milestone 5 security-audit finding W2 regression test (engine-side
 * half -- "the real guarantee"): invoke.c's fd tracker (fd_tracker.h)
 * must force-close every fd opened via open_sock_tcp() and never
 * explicitly close_sock()'d, independent of whether the socket
 * userdata's __gc/__close ever ran. Runs the leak_never_close.lua
 * fixture (which always leaks its one socket) many times in a loop and
 * asserts the process's total open-fd count (/proc/self/fd) never grows
 * across iterations -- if invoke.c's force-close sweep regressed (e.g.
 * reverted to relying solely on lua_close()'s own __gc pass, or a bug in
 * the tracker itself), this would show up as a steadily increasing fd
 * count and eventually exhaust the process's fd table.
 *
 * Both the "client" (the engine, via open_sock_tcp()) and the "server"
 * (this test's own accept() thread) side of every loopback connection
 * live in this SAME process, so /proc/self/fd counts both. To avoid a
 * false-positive race (measuring fd count while the server thread is
 * still mid-accept()/close() for the connection just made), the server
 * thread bumps an atomic counter only after it has fully closed its side
 * of a connection, and the main loop waits for that counter before
 * measuring -- eliminating the race rather than papering over it with an
 * arbitrary sleep.
 *
 * Security-review round-2 FIX 4: strengthened with a per-iteration dup2()
 * sentinel probe (see cytadel_test_dup2_sentinel_probe()'s own comment)
 * confirming the specific fd number this iteration's socket most likely
 * used is not merely closed afterward but immediately reusable as a fully
 * functional fd. This is still fundamentally a single-threaded,
 * non-racing test, though, so -- exactly like the plain fd-count check
 * above it -- it CANNOT by itself distinguish "closed once" from "closed
 * twice" (FIX 1's actual bug): both leave the fd number closed and
 * reusable when nothing else is racing to grab it in between the two
 * close() calls. tests/unit/test_plugin_fix1_double_close_race.c races
 * independent "victim" threads against this same fixture's leaked sockets
 * to put a live third-party resource in that gap -- but, per security-
 * review round-3 finding W-2 (see that file's own updated header comment),
 * it can only ever fail when BOTH FIX 1's invoke.c call-ordering AND
 * api_socket.c's own tracked+closed guard are reverted together, never
 * from reverting the ordering alone: the guard is independently
 * sufficient to suppress the double-close SYMPTOM regardless of ordering,
 * so no black-box or race-based test -- including that one -- can isolate
 * the ordering by itself through that symptom.
 * tests/unit/test_plugin_r3w2_double_close_guard.c covers the guard's own
 * correctness deterministically instead, and security-review round 4's
 * tests/unit/test_plugin_r4w2_order_invariant.c covers the invoke.c call
 * ordering directly (via a test-only instrumentation hook, not the
 * downstream symptom), closing the gap this comment used to describe as
 * untestable. This file (test_plugin_w2_fd_force_close.c) covers a
 * fourth, distinct concern from all three: the engine-side fd tracker's
 * force-close sweep itself never leaks an fd at scale, independent of
 * ordering or double-close safety.
 *
 * Shutdown note: close()ing listen_fd from the main thread does NOT
 * reliably unblock another thread already parked inside accept() on that
 * fd on Linux (a close() from a different thread does not interrupt a
 * concurrent blocking syscall using the same fd -- a well-known Linux
 * quirk, unlike e.g. FreeBSD). So the drain thread is woken by making one
 * final, real loopback connection after setting a stop flag, rather than
 * relying on close() alone -- otherwise pthread_join() below could hang
 * forever waiting for a thread stuck in its last accept(). */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

#define CYTADEL_TEST_ITERATIONS 40
/* 500us * 4000 = 2s worst-case wait per iteration before giving up. */
#define CYTADEL_TEST_WAIT_POLL_NS (500L * 1000L)
#define CYTADEL_TEST_WAIT_POLL_MAX 4000

/* nanosleep() wrapper -- usleep() is POSIX.1-2001 but removed from
 * POSIX.1-2008 (and not declared under a strict _POSIX_C_SOURCE=200809L
 * feature-test macro on this toolchain); nanosleep() is the still-current
 * POSIX replacement. */
static void cytadel_test_sleep_poll_interval(void) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = CYTADEL_TEST_WAIT_POLL_NS;
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
    CYTADEL_ASSERT(listen(fd, 16) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

typedef struct {
    int listen_fd;
    uint16_t port;
    _Atomic long accepted_count; /* bumped only after close()ing the server side */
    _Atomic bool stop;           /* set by main() once the test loop is done */
} cytadel_drain_fixture_args_t;

/* Drains the accept backlog for the whole test's lifetime -- every
 * connection is accepted and immediately closed server-side; this test
 * only cares about the CLIENT (plugin) side fd, not the server's. Exits
 * once `stop` is set AND one more (wake-up) connection has been drained --
 * see this file's top comment for why a plain close(listen_fd) alone is
 * not a reliable way to unblock this thread's final accept(). */
static void *cytadel_drain_fixture_main(void *arg) {
    cytadel_drain_fixture_args_t *args = arg;
    for (;;) {
        int fd = accept(args->listen_fd, NULL, NULL);
        if (fd < 0) {
            break;
        }
        close(fd);
        if (atomic_load(&args->stop)) {
            break; /* this was the wake-up connection -- stop, don't count it */
        }
        atomic_fetch_add(&args->accepted_count, 1);
    }
    return NULL;
}

/* Sets the stop flag and connects once to `port` so the drain thread's
 * blocked accept() actually wakes up and observes the flag. */
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

static long cytadel_test_count_open_fds(void) {
    DIR *d = opendir("/proc/self/fd");
    if (d == NULL) {
        return -1; /* not on Linux/no /proc -- caller must skip the assertion */
    }
    long count = 0;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (entry->d_name[0] == '.') {
            continue;
        }
        count++;
    }
    closedir(d); /* closed before counting is "done" from the caller's POV */
    return count - 1; /* exclude the fd opendir() itself held during the scan */
}

/* Security-review round-2 FIX 4: opens a throwaway socket fd purely to
 * learn which fd number the OS is about to hand out next -- Linux's fd
 * allocator always returns the lowest currently-free number, so this is a
 * (best-effort, not guaranteed -- see the caller) prediction of which fd
 * number the fixture's very next open_sock_tcp() call, and therefore this
 * iteration's engine-side force-close sweep / lua_close() teardown, will
 * most likely reuse. Returns that predicted fd number (already closed --
 * it is a PREDICTION, not a reservation) on success, or -1 on failure
 * (caller must skip the probe below for this iteration). */
static int cytadel_test_predict_next_fd(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    close(fd);
    return fd;
}

/* Security-review round-2 FIX 4: called AFTER an iteration's invocation
 * (and its teardown) has fully completed. dup2()s a fresh sentinel pipe
 * read-end onto `predicted_fd` and proves the result is a genuinely fresh,
 * fully-working fd -- a byte written into the pipe's write end round-trips
 * correctly through it.
 *
 * This is deliberately OPPORTUNISTIC/best-effort, not a strict per-
 * iteration requirement: `predicted_fd` (cytadel_test_predict_next_fd())
 * is only ever a prediction, and this test's own drain thread is
 * concurrently accept()ing/close()ing real connections on similarly low fd
 * numbers throughout -- either can legitimately make `predicted_fd` a
 * miss by the time this runs (e.g. the drain thread's own churn grabbed
 * it first, or Linux's dup2() returned the documented, benign EBUSY when
 * racing a concurrent open()/dup() elsewhere in the process on that same
 * slot). None of that says anything about correctness either way, so a
 * pipe()/dup2() failure here is silently skipped rather than asserted.
 * Once dup2() DOES succeed, though, the resulting fd must behave exactly
 * like the ordinary, uncontended fd it is -- the write()/read()/byte-match
 * checks below ARE hard assertions, unconditionally. Does NOT (and, per
 * this file's own top-of-file comment, cannot) distinguish "closed once"
 * from "closed twice" -- see test_plugin_fix1_double_close_race.c for
 * that. Silently returns if `predicted_fd` was itself invalid (< 0, i.e.
 * cytadel_test_predict_next_fd() failed) -- there is nothing to probe in
 * that case either. */
static void cytadel_test_dup2_sentinel_probe(int predicted_fd) {
    if (predicted_fd < 0) {
        return;
    }
    int sentinel[2];
    if (pipe(sentinel) != 0) {
        return; /* opportunistic -- nothing to probe with this iteration */
    }
    if (predicted_fd == sentinel[1]) {
        /* Degenerate overlap: dup2() below would clobber the pipe's WRITE
         * end with a dup of its read end, leaving nothing usable as a
         * write end at all. Too rare to bother threading through the
         * write()/read() checks below correctly -- just skip this
         * iteration's probe. */
        close(sentinel[0]);
        close(sentinel[1]);
        return;
    }
    if (predicted_fd != sentinel[0]) {
        /* Normal case: dup2() closes whatever was at predicted_fd (if
         * anything) and makes it a second fd for the SAME pipe read end as
         * sentinel[0]. */
        if (dup2(sentinel[0], predicted_fd) != predicted_fd) {
            close(sentinel[0]);
            close(sentinel[1]);
            return; /* prediction miss or a benign concurrent-open race (EBUSY) -- skip */
        }
        close(sentinel[0]); /* now redundant -- predicted_fd is an equally-valid duplicate */
    }
    /* else: predicted_fd == sentinel[0] already -- pipe() itself happened
     * to hand out the predicted number as the read end, so there is
     * nothing left to dup2() (POSIX: dup2(fd, fd) is defined as a no-op
     * that returns fd without closing it) -- do NOT close sentinel[0] in
     * this branch, since sentinel[0] IS predicted_fd and closing it here
     * would tear down the very fd this probe is about to read from. */

    unsigned char tag = 0xA5;
    unsigned char readback = 0x00;
    CYTADEL_ASSERT(write(sentinel[1], &tag, 1) == 1);
    CYTADEL_ASSERT(read(predicted_fd, &readback, 1) == 1);
    CYTADEL_ASSERT_EQ(readback, tag);

    close(sentinel[1]);
    close(predicted_fd);
}

int main(void) {
    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    cytadel_drain_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.port = port;
    atomic_init(&args.accepted_count, 0);
    atomic_init(&args.stop, false);

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_drain_fixture_main, &args) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/socket_fd_leak_loop", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    long baseline_fds = -1;

    for (int i = 0; i < CYTADEL_TEST_ITERATIONS; i++) {
        /* FIX 4: predicted BEFORE this iteration's invocation runs -- see
         * cytadel_test_predict_next_fd()'s own comment. */
        int predicted_fd = cytadel_test_predict_next_fd();

        cytadel_finding_list_t findings;
        memset(&findings, 0, sizeof(findings));

        /* Every invocation opens exactly one socket and never
         * close_sock()'s it -- by the time this call returns, invoke.c's
         * engine-side sweep has already force-closed the CLIENT side
         * (independent of lua_close()'s own __gc pass). */
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        cytadel_finding_list_free(&findings);

        /* Wait for the SERVER side to finish closing its half of this
         * same connection too, so the fd count below reflects a fully
         * settled state rather than racing the drain thread. */
        long want = i + 1;
        int waited = 0;
        while (atomic_load(&args.accepted_count) < want && waited < CYTADEL_TEST_WAIT_POLL_MAX) {
            cytadel_test_sleep_poll_interval();
            waited++;
        }
        CYTADEL_ASSERT(atomic_load(&args.accepted_count) >= want);

        /* FIX 4: see cytadel_test_dup2_sentinel_probe()'s own comment --
         * a no-op if the prediction above was invalid. */
        cytadel_test_dup2_sentinel_probe(predicted_fd);

        long fds = cytadel_test_count_open_fds();
        if (fds < 0) {
            continue; /* no /proc -- skip the per-iteration assertion below */
        }

        if (i == 1) {
            /* Skip iteration 0 as the warm-up baseline (first-touch
             * allocator/registry-internal allocations can still be
             * settling); iteration 1 onward must be perfectly stable. */
            baseline_fds = fds;
        } else if (i > 1) {
            CYTADEL_ASSERT_EQ(fds, baseline_fds);
        }
    }

    cytadel_test_stop_drain_thread(&args);
    pthread_join(thread, NULL);
    close(listen_fd);

    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
