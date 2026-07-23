#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"
#include "debug_support.h"
#include "invoke.h"
#include "plugin_header.h"

/* Security-review round-4 finding W-2 regression test.
 *
 * Round 3's own test_plugin_fix1_double_close_race.c and
 * test_plugin_r3w2_double_close_guard.c both stated plainly that FIX 1's
 * invoke.c call ordering (lua_close(L) before
 * cytadel_plugin_invoke_cleanup(), never the reverse) cannot be isolated
 * from api_socket.c's own tracked+closed guard by any test that only
 * watches for the downstream double-close SYMPTOM: the guard alone is
 * already sufficient to suppress it regardless of ordering. Round 4's own
 * W-1 fix (fd_tracker.c/.h, api_socket.c) restored that guard to genuine
 * belt-and-braces coverage (it had regressed to missing exactly the
 * post-free case FIX 1's ordering bug would trigger) -- which means the
 * symptom is now suppressed in EVERY case again, including a deliberately
 * reverted ordering. A symptom-based test is therefore now, more than
 * ever, incapable of catching an ordering regression on its own.
 *
 * This test resolves that by observing the ORDERING INVARIANT DIRECTLY
 * instead of its downstream symptom: invoke.c's
 * cytadel_plugin_test_invoke_order_hook (a CYTADEL_BUILD_TESTING-only
 * instrumentation point -- see invoke.c's own top-of-file comment) fires
 * "lua_close_done" from inside invoke.c's cytadel_plugin_close_state()
 * helper, immediately after the lua_close(L) call THAT HELPER makes, and
 * "cleanup_begin" as cytadel_plugin_invoke_cleanup()'s own first statement,
 * immediately on entry, on every path through cytadel_plugin_invoke_one().
 * This test runs exactly one real invocation (of the same
 * leak_never_close.lua fixture the round-2/round-3 tests use, so a real
 * tracked socket exists in ctx.open_fds and the "interesting" final code
 * path in invoke.c -- the one FIX 1 actually changed -- is the one
 * exercised) and asserts those two events fired in that exact order.
 *
 * Security-review round-5 finding W-A: round 4's original version of this
 * mechanism fired both events from free-standing macro calls placed next
 * to the lua_close(L)/cleanup call sites, rather than from inside the
 * operations themselves -- which meant a reviewer could revert invoke.c's
 * actual ordering (move cytadel_plugin_invoke_cleanup() above lua_close(L)
 * on the final path) while leaving BOTH macro calls untouched, and this
 * test still passed, because the macros still fired in textual order even
 * though lua_close(L) itself now ran last. Round 5's fix moved
 * "lua_close_done" inside cytadel_plugin_close_state() (the only function
 * in invoke.c allowed to call lua_close(L)) and "cleanup_begin" inside
 * cytadel_plugin_invoke_cleanup() itself, so the events are now bound to
 * the operations, not to source-line positions -- reverting invoke.c's
 * call ordering (swapping the cytadel_plugin_close_state()/
 * cytadel_plugin_invoke_cleanup() call pair on any path) flips the
 * recorded event order and fails this test, independent of where either
 * macro call site physically sits in the file.
 *
 * Security-review round-5 suggestion S-2: the original version of this test
 * only ever exercised ONE of cytadel_plugin_invoke_one()'s four
 * lua_close(L)/cleanup call sites -- the final (successful-run) path, via
 * cytadel_plugin_run_all_for_host() -- leaving the three failure paths
 * (luaL_loadfile() failure, the definer-chunk's lua_pcall() failure, and
 * "no run() function defined") with their own identical hook pairs
 * completely untested. A W-A-class revert confined to just one of THOSE
 * three call sites would have gone unnoticed even after the W-A fix above.
 * cytadel_check_direct_invoke_order() below calls
 * cytadel_plugin_invoke_one() directly (invoke.h is reachable here the same
 * way debug_support.h is -- see this test's CMakeLists.txt entry), bypassing
 * loader.c's registration gate entirely, so each of the three failure
 * fixtures below can be fed straight to invoke.c without loader.c also
 * rejecting them first (registration_missing_run/missing_run.lua, in
 * particular, would never reach invoke.c at all through the normal
 * register-then-run pipeline, since loader.c's own §4.1 step 5 check
 * already rejects it at registration time).
 *
 * Security-review round-6 (S-2 path-drift hazard, residual #7): S-2's own
 * four-fixture design above still only asserted event COUNT and NAME
 * ("lua_close_done" then "cleanup_begin"), never WHICH of invoke.c's four
 * call sites actually fired -- nothing bound a fixture to a path. If
 * invoke_syntax_error/syntax_error.lua (deliberately unparseable) were ever
 * "fixed" by a well-meaning cleanup or linter, it would silently start
 * failing at call_rc instead of load_rc: path "load_rc" would lose ALL
 * coverage while this test kept passing, because the two events still fire
 * in the same relative order regardless of which call site produces them.
 * invoke.c's CYTADEL_PLUGIN_INVOKE_ORDER_HOOK() now fires
 * "<verb>:<site_id>" (site_id is a real argument at each of invoke.c's four
 * call sites -- see that file's own comment), so
 * cytadel_check_direct_invoke_order() below takes an `expected_site`
 * parameter and asserts the FULL "lua_close_done:<site>" /
 * "cleanup_begin:<site>" strings, not just event order -- a fixture that
 * silently drifts to a different call site now fails this test instead of
 * passing it unnoticed.
 *
 * This also covers round-6's residual #7: before this round, the "final"
 * call site (site_id "final") was only ever exercised via a SUCCESSFUL
 * run() (the socket_fd_leak_loop fixture below, via
 * cytadel_plugin_run_all_for_host()) -- a future `run_rc != LUA_OK` early
 * return with reversed close_state()/cleanup() ordering on that SAME final
 * call site, reached only through a run() FAILURE, could have passed
 * 37/37 with nothing driving that specific control-flow edge.
 * invoke_run_error/run_error.lua (a run() that is defined, so call_rc
 * succeeds and the "no_run" path is not taken, but unconditionally raises
 * as soon as it executes) closes that gap via
 * cytadel_check_direct_invoke_order() too, independent of the
 * success-path coverage below. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

#define CYTADEL_TEST_MAX_EVENTS 8

typedef struct {
    char names[CYTADEL_TEST_MAX_EVENTS][32];
    int count;
} cytadel_test_event_log_t;

static cytadel_test_event_log_t g_events;

/* Single-threaded (this test never spawns a leaker/victim thread pair the
 * way the round-2/round-3 races do -- one invocation, called directly on
 * this thread), so a plain global is sufficient; no atomics needed. */
static void cytadel_test_order_hook(const char *event) {
    if (g_events.count < CYTADEL_TEST_MAX_EVENTS) {
        snprintf(g_events.names[g_events.count], sizeof(g_events.names[0]), "%s", event);
        g_events.count++;
    }
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
    CYTADEL_ASSERT(listen(fd, 4) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

/* Accepts exactly one connection (the fixture's own open_sock_tcp() call)
 * and closes it server-side -- this test only cares about the client
 * (plugin) side fd invoke.c's teardown manages. */
static void *cytadel_test_accept_once(void *arg) {
    int listen_fd = *(int *)arg;
    int fd = accept(listen_fd, NULL, NULL);
    if (fd >= 0) {
        close(fd);
    }
    return NULL;
}

/* Security-review round-5 suggestion S-2 (extended by round-6's path-id
 * fix): calls cytadel_plugin_invoke_one() DIRECTLY (bypassing loader.c's
 * registration gate -- see this file's top-of-file comment) against
 * `lua_path`, with the order-invariant hook installed, and asserts the
 * FULL "lua_close_done:<expected_site>" then "cleanup_begin:<expected_site>"
 * event pair fired, in that order -- not just event order in the abstract,
 * but that THIS fixture drove exactly the call site `expected_site` names
 * (one of "load_rc" / "call_rc" / "no_run" / "final" -- see invoke.c's
 * cytadel_plugin_invoke_one()). A fixture that silently drifts to a
 * different call site (e.g. a "fixed" syntax_error.lua that now parses)
 * fails this assertion instead of passing it unnoticed (round-6 S-2
 * path-drift hazard fix). A hand-built, mostly-zeroed header is enough
 * here: none of these fixtures' failure modes ever reach code that reads
 * any field but script_id/script_name/source_path, and every string is a
 * literal (never freed) -- this function deliberately never calls
 * cytadel_plugin_header_free(). */
static void cytadel_check_direct_invoke_order(const char *lua_path, const char *expected_site) {
    cytadel_plugin_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.script_id = 990100;
    hdr.script_name = "round-5 S-2 direct-invoke fixture";
    hdr.source_path = (char *)lua_path;

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));

    memset(&g_events, 0, sizeof(g_events));
    cytadel_plugin_test_invoke_order_hook = cytadel_test_order_hook;

    cytadel_plugin_invoke_one(&hdr, "127.0.0.1", NULL, -1, &findings);

    cytadel_plugin_test_invoke_order_hook = NULL;
    cytadel_finding_list_free(&findings);

    char expected_close[64];
    char expected_cleanup[64];
    snprintf(expected_close, sizeof(expected_close), "lua_close_done:%s", expected_site);
    snprintf(expected_cleanup, sizeof(expected_cleanup), "cleanup_begin:%s", expected_site);

    CYTADEL_ASSERT_EQ(g_events.count, 2);
    CYTADEL_ASSERT_STREQ(g_events.names[0], expected_close);
    CYTADEL_ASSERT_STREQ(g_events.names[1], expected_cleanup);
}

int main(void) {
    /* The three early-return failure paths first -- each a single, short,
     * deterministic direct call, no threads/sockets involved (round-5
     * suggestion S-2), each bound to its own expected call site (round-6). */
    cytadel_check_direct_invoke_order(CYTADEL_TEST_FIXTURES_DIR
                                       "/invoke_syntax_error/syntax_error.lua",
                                       "load_rc");
    cytadel_check_direct_invoke_order(CYTADEL_TEST_FIXTURES_DIR
                                       "/invoke_toplevel_error/toplevel_error.lua",
                                       "call_rc");
    cytadel_check_direct_invoke_order(CYTADEL_TEST_FIXTURES_DIR
                                       "/registration_missing_run/missing_run.lua",
                                       "no_run");

    /* The "final" call site's run()-FAILURE half (round-6 residual #7):
     * call_rc succeeds and run() is defined (so this is NOT the "no_run"
     * path), but run() itself raises, so run_rc != LUA_OK -- distinct
     * control-flow edge from the run()-SUCCESS half of this same call site
     * exercised via socket_fd_leak_loop below. */
    cytadel_check_direct_invoke_order(CYTADEL_TEST_FIXTURES_DIR
                                       "/invoke_run_error/run_error.lua",
                                       "final");

    uint16_t port = 0;
    int listen_fd = cytadel_test_bind_ephemeral(&port);

    pthread_t accept_thread;
    CYTADEL_ASSERT(pthread_create(&accept_thread, NULL, cytadel_test_accept_once, &listen_fd) == 0);

    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/socket_fd_leak_loop", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    memset(&g_events, 0, sizeof(g_events));
    cytadel_plugin_test_invoke_order_hook = cytadel_test_order_hook;

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    /* Exactly one invocation: one registered plugin, and
     * leak_never_close.lua's own required_keys is a single
     * service-wildcard "Services/www/" entry (§2.2a/§4.6) that dispatches
     * once per matching KB port -- this test's kb only has the one
     * "Services/www/<port>" entry set above, so exactly one bound-port
     * invocation results. */
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
    cytadel_finding_list_free(&findings);

    /* Reset the process-global hook immediately -- it must never leak past
     * this test into any test binary linked after it (moot here, since
     * every test is its own process, but matches the hook's own documented
     * contract in debug_support.h). */
    cytadel_plugin_test_invoke_order_hook = NULL;

    pthread_join(accept_thread, NULL);
    close(listen_fd);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);

    /* Exactly two events, in order: lua_close(L) always completes before
     * cytadel_plugin_invoke_cleanup() begins -- and (round-6) this is
     * specifically the "final" call site's run()-SUCCESS half, the
     * complement of invoke_run_error/run_error.lua's run()-FAILURE half
     * checked above via cytadel_check_direct_invoke_order(). */
    CYTADEL_ASSERT_EQ(g_events.count, 2);
    CYTADEL_ASSERT_STREQ(g_events.names[0], "lua_close_done:final");
    CYTADEL_ASSERT_STREQ(g_events.names[1], "cleanup_begin:final");

    CYTADEL_TEST_PASS();
}
