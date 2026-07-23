#define _POSIX_C_SOURCE 200809L

#include "debug_support.h"

/* Security-review round-4 finding W-3: this whole translation unit is now
 * gated on CYTADEL_BUILD_TESTING (only defined on the `cytadel` target when
 * BUILD_TESTING is ON -- src/plugin/CMakeLists.txt) as defense in depth,
 * on top of debug_support.c only being added to that target's sources
 * under the same condition. See debug_support.h's own top-of-file comment
 * for the full rationale. If CYTADEL_BUILD_TESTING is not defined,
 * everything below (including "#endif" at the very end of this file)
 * compiles away to nothing.
 *
 * Security-review round-5 finding W-B: the claim that used to sit here --
 * that the #include above leaves real preprocessing tokens in this TU
 * either way, so this is never an empty-translation-unit warning -- is
 * FALSE. debug_support.h emits no declarations at all when
 * CYTADEL_BUILD_TESTING is unset (its entire body is itself guarded by the
 * same #ifdef), so with the macro undefined this file genuinely reduces to
 * nothing but comments and an #include of a header that expands to
 * nothing: `gcc -Wpedantic` reports "ISO C forbids an empty translation
 * unit" for exactly that case. This TU is never actually compiled that way
 * in practice -- src/plugin/CMakeLists.txt only adds debug_support.c to
 * the `cytadel` target's sources at all when BUILD_TESTING is ON, and
 * defines CYTADEL_BUILD_TESTING on that same target in the same
 * `if(BUILD_TESTING)` block (see that file's own comment, which is the
 * correct one) -- so the empty-TU case never reaches the compiler. But
 * that safety comes entirely from the CMake wiring, not from anything in
 * this file; do not rely on or repeat the "#include already leaves
 * tokens" claim. */
#ifdef CYTADEL_BUILD_TESTING

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <lauxlib.h>

#include "api_socket.h"
#include "cytadel/plugin/plugin.h"
#include "fd_tracker.h"
#include "field_utils.h"
#include "loader.h"
#include "plugin_ctx.h"
#include "plugin_header.h"
#include "sandbox.h"

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on
 * cytadel_plugin_debug_check_env_isolated(). Reimplements exactly steps
 * 2-4 of the run-phase pipeline (§4.2: fresh lua_State, run-phase sandbox,
 * luaL_loadfile + _ENV rebind + lua_pcall) -- deliberately stops there
 * (never invokes run()) and instead inspects the REAL global table
 * directly via lua_getglobal(), which is untouched by _ENV rebinding and
 * therefore the correct place to observe whether a bare top-level global
 * assignment in the loaded chunk escaped the sandbox. */
int cytadel_plugin_debug_check_env_isolated(const char *lua_path, const char *global_name) {
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        return -1;
    }
    *(void **)lua_getextraspace(L) = NULL;

    cytadel_finding_list_t dummy_findings;
    dummy_findings.items = NULL;
    dummy_findings.count = 0;
    dummy_findings.capacity = 0;

    cytadel_plugin_ctx_t ctx;
    ctx.kb = NULL;
    ctx.ip = "127.0.0.1";
    ctx.bound_port = -1;
    ctx.header = NULL;
    ctx.findings = &dummy_findings;
    ctx.open_fds.fds = NULL; /* run() is never invoked here -- never populated either way */
    ctx.open_fds.count = 0;
    ctx.open_fds.capacity = 0;
    ctx.open_fds.freed = false;
    cytadel_plugin_ctx_set(L, &ctx);

    lua_pushcfunction(L, cytadel_plugin_msgh);
    int msgh_idx = lua_gettop(L);

    cytadel_plugin_push_run_sandbox(L);
    int env_idx = lua_gettop(L);

    int load_rc = luaL_loadfile(L, lua_path);
    if (load_rc != LUA_OK) {
        lua_close(L);
        cytadel_finding_list_free(&dummy_findings);
        return -1;
    }
    int chunk_idx = lua_gettop(L);
    cytadel_plugin_rebind_env(L, chunk_idx, env_idx);

    int call_rc = lua_pcall(L, 0, 0, msgh_idx);
    if (call_rc != LUA_OK) {
        lua_close(L);
        cytadel_finding_list_free(&dummy_findings);
        return -1;
    }

    lua_getglobal(L, global_name); /* the REAL global table -- never rebound */
    bool leaked = !lua_isnil(L, -1);
    lua_pop(L, 1);

    lua_close(L);
    cytadel_finding_list_free(&dummy_findings);
    return leaked ? 0 : 1;
}

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on this function.
 * Security-review round-3 finding W-1 (WARNING) regression check.
 * Deliberately constructs the exact state open_sock_tcp() (api_socket.c)
 * leaves a socket userdata in when cytadel_plugin_fd_tracker_add()'s own
 * realloc() fails under OOM: a live, fully open fd, paired with
 * track_idx == (size_t)-1 (untracked). Calls
 * cytadel_plugin_socket_close() directly on that pairing and proves the
 * real fd still gets close()'d -- before the fix, the old
 * is_closed()-only guard treated "untracked" the same as "already
 * closed" and returned without ever calling close(), leaking the fd for
 * the rest of the process's lifetime. */
int cytadel_plugin_debug_check_untracked_socket_closes(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return -1; /* unrelated test-setup failure */
    }
    close(fds[1]);
    int fd = fds[0];

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        close(fd);
        return -1;
    }

    cytadel_plugin_ctx_t ctx;
    ctx.kb = NULL;
    ctx.ip = "127.0.0.1";
    ctx.bound_port = -1;
    ctx.header = NULL;
    ctx.findings = NULL;
    ctx.open_fds.fds = NULL; /* an empty tracker -- (size_t)-1 is untracked regardless */
    ctx.open_fds.count = 0;
    ctx.open_fds.capacity = 0;
    ctx.open_fds.freed = false;
    cytadel_plugin_ctx_set(L, &ctx);

    cytadel_plugin_socket_t sock;
    sock.fd = fd;
    sock.track_idx = (size_t)-1; /* simulates an fd_tracker_add() OOM failure */

    cytadel_plugin_socket_close(L, &sock);

    lua_close(L);

    /* Security-review round-4 suggestion 2: only close(fd) on the FAILURE
     * path (still_valid, i.e. the leak this check exists to catch) -- if
     * cytadel_plugin_socket_close() correctly closed it above, fd is
     * already a dead descriptor and calling close() on it again here would
     * itself be a second close on an already-closed fd inside this very
     * test process -- exactly the bug class this whole file exists to
     * detect, now committed inside the detector. */
    bool still_valid = (fcntl(fd, F_GETFD) != -1);
    if (still_valid) {
        close(fd); /* clean up the leak this check exists to catch */
    }
    return still_valid ? 0 : 1;
}

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on this function.
 * Security-review round-3 finding W-2 (WARNING) supplementary check: proves
 * -- deterministically, not probabilistically -- that
 * cytadel_plugin_socket_close()'s tracked+closed guard (security-review
 * round-2 FIX 1) makes a second close on an already-tracked-closed slot a
 * genuine no-op, independent of any thread race. Builds a one-slot tracker
 * whose only entry is already marked closed (-1), pairs it with a socket
 * userdata whose sock->fd field is still stale (>= 0, exactly as it would
 * be if something else had already closed the real fd and updated only the
 * tracker, e.g. invoke.c's end-of-invocation force-close sweep, without
 * reaching back into this userdata), and confirms
 * cytadel_plugin_socket_close() does NOT call close() on it again --
 * i.e. the real (still-live, from this test's own point of view) fd number
 * stays untouched.
 *
 * Round-4 W-2: this test (and test_plugin_fix1_double_close_race.c) only
 * ever proves the GUARD works, not the invoke.c call ORDERING the guard is
 * meant to backstop -- see tests/unit/test_plugin_r4w2_order_invariant.c
 * for a direct, ordering-level regression test built on invoke.c's own
 * CYTADEL_PLUGIN_INVOKE_ORDER_HOOK() instrumentation, which is not fooled
 * by this guard's suppression of the downstream double-close symptom. */
int cytadel_plugin_debug_check_double_close_guard(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return -1;
    }
    close(fds[1]);
    int fd = fds[0];

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        close(fd);
        return -1;
    }

    /* Security-review round-4 suggestion 3: heap-allocated, not a stack
     * array -- ctx.open_fds points the tracker at this buffer, and while
     * socket_close()'s current logic never calls
     * cytadel_plugin_fd_tracker_free() on it, a future change that did
     * would call free() on whatever ctx.open_fds.fds points to; a stack
     * array there would make that a free() on stack memory. malloc'd here,
     * freed unconditionally below regardless of which return path is
     * taken. */
    int *tracked_fds = malloc(sizeof(int));
    if (tracked_fds == NULL) {
        lua_close(L);
        close(fd);
        return -1;
    }
    tracked_fds[0] = -1; /* already marked closed by "someone else" */

    cytadel_plugin_ctx_t ctx;
    ctx.kb = NULL;
    ctx.ip = "127.0.0.1";
    ctx.bound_port = -1;
    ctx.header = NULL;
    ctx.findings = NULL;
    ctx.open_fds.fds = tracked_fds;
    ctx.open_fds.count = 1;
    ctx.open_fds.capacity = 1;
    ctx.open_fds.freed = false;
    cytadel_plugin_ctx_set(L, &ctx);

    cytadel_plugin_socket_t sock;
    sock.fd = fd;      /* stale -- deliberately still >= 0 */
    sock.track_idx = 0; /* a genuinely tracked slot, already closed */

    cytadel_plugin_socket_close(L, &sock);

    lua_close(L);
    free(tracked_fds);

    bool still_valid = (fcntl(fd, F_GETFD) != -1);
    close(fd); /* always ours to close -- this call must never have touched it */

    /* sock.fd must also have been set to -1 (the idempotent view-update
     * half of the guard), independent of whether close() was (wrongly)
     * called again. */
    bool view_updated = (sock.fd == -1);

    return (still_valid && view_updated) ? 1 : 0;
}

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on this function.
 * Security-review round-4 finding W-1 regression check: builds a tracker
 * via the REAL cytadel_plugin_fd_tracker_add()/mark_closed()/free() API
 * sequence (deliberately not a hand-rolled reimplementation of the
 * tracker's internal fields -- round 3's own W-1 regression came from
 * reasoning about tracker state without checking what fd_tracker_free()
 * actually did to it, so this test uses the real functions to avoid
 * repeating that mistake), matching invoke.c's own
 * cytadel_plugin_invoke_cleanup() sequence: force_close_all() then
 * free(). It then calls cytadel_plugin_socket_close() with a track_idx
 * into that now-freed tracker and a real, live fd (standing in for a
 * "victim" resource that happened to reuse the fd number the tracker's
 * own placeholder entry once referred to), and proves the guard still
 * recognizes that slot as "tracked and already closed" -- i.e. still
 * skips close() -- even though the tracker backing it has already been
 * freed. Before the round-4 fix, cytadel_plugin_fd_tracker_is_tracked()
 * returned false for every index once the tracker was freed (free() used
 * to reset `count` to 0), which made this exact call fall through to a
 * real close() on the live fd -- the double-close round 2's FIX 1 exists
 * to prevent. */
int cytadel_plugin_debug_check_double_close_guard_survives_free(void) {
    int fds[2];
    if (pipe(fds) != 0) {
        return -1;
    }
    close(fds[1]);
    int fd = fds[0]; /* stands in for a "victim" resource */

    lua_State *L = luaL_newstate();
    if (L == NULL) {
        close(fd);
        return -1;
    }

    cytadel_plugin_ctx_t ctx;
    ctx.kb = NULL;
    ctx.ip = "127.0.0.1";
    ctx.bound_port = -1;
    ctx.header = NULL;
    ctx.findings = NULL;
    ctx.open_fds.fds = NULL;
    ctx.open_fds.count = 0;
    ctx.open_fds.capacity = 0;
    ctx.open_fds.freed = false;
    cytadel_plugin_ctx_set(L, &ctx); /* without this, cytadel_plugin_socket_close()'s own
                                       * cytadel_plugin_ctx_get() sees NULL and this test
                                       * would (incorrectly) exercise the ctx == NULL
                                       * fallback path instead of the tracker guard */

    /* A placeholder fd number -- never a real, live fd this test owns; it
     * only needs to occupy a real tracker slot that force_close_all() then
     * marks closed, exactly like invoke.c's own end-of-invocation sweep
     * would for a socket already close_sock()'d earlier in the same
     * invocation. -1 itself would already read as "closed", so use a
     * clearly-fake positive placeholder instead to prove force_close_all()
     * (not just a pre-set -1) is what marks it. */
    size_t idx = cytadel_plugin_fd_tracker_add(&ctx.open_fds, 999999);
    if (idx == (size_t)-1) {
        lua_close(L);
        close(fd);
        return -1; /* unrelated OOM -- cannot construct this scenario */
    }
    cytadel_plugin_fd_tracker_force_close_all(&ctx.open_fds); /* closes the placeholder, marks -1 */
    cytadel_plugin_fd_tracker_free(&ctx.open_fds); /* the exact invoke_cleanup() sequence */

    cytadel_plugin_socket_t sock;
    sock.fd = fd;       /* live -- must NOT be closed by the call below */
    sock.track_idx = idx; /* into the now-freed tracker */

    cytadel_plugin_socket_close(L, &sock);

    lua_close(L);

    bool still_valid = (fcntl(fd, F_GETFD) != -1);
    close(fd); /* always ours to close -- this call must never have touched it */
    bool view_updated = (sock.fd == -1);

    return (still_valid && view_updated) ? 1 : 0;
}

static int cytadel_test_index_sentinel(lua_State *L) {
    lua_pushliteral(L, CYTADEL_TEST_INDEX_SENTINEL);
    return 1;
}

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on this function.
 * Security-review round-3 finding C-1 (CRITICAL) supplementary check:
 * proves -- deterministically, via the raw Lua C API, independent of
 * whether a plugin could ever reach this state through the sandboxed Lua
 * surface at all (sandbox.c's __metatable lock on _ENV now prevents that
 * entirely -- see this function's own use in tests/unit and that fix's own
 * comment) -- that cytadel_plugin_raw_getfield() (field_utils.c) genuinely
 * never invokes a table's __index metamethod, while an ordinary
 * lua_getfield() on the exact same table WOULD. lua_setmetatable() (the C
 * API call, used directly here) does not consult a table's __metatable
 * protection field at all -- only Lua's own setmetatable() library
 * function does -- so this is the one way to construct "a table with a
 * hostile __index metatable" in this test even though the sandbox itself
 * can no longer produce one. */
int cytadel_plugin_debug_check_raw_getfield_bypasses_index(void) {
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        return -1;
    }

    lua_newtable(L);
    int tbl_idx = lua_gettop(L);
    lua_pushinteger(L, 42);
    lua_setfield(L, tbl_idx, "present");

    lua_newtable(L); /* the malicious metatable */
    lua_pushcfunction(L, cytadel_test_index_sentinel);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, tbl_idx); /* C API -- bypasses any __metatable lock */

    /* Sanity-check the attack harness itself first: an ORDINARY
     * lua_getfield() for a field that is genuinely absent must actually
     * invoke __index and return the sentinel -- if it does not, the
     * metatable above is not doing what the rest of this function assumes,
     * and neither of the checks below would prove anything. */
    lua_getfield(L, tbl_idx, "absent");
    bool getfield_invokes_index =
        lua_isstring(L, -1) && strcmp(lua_tostring(L, -1), CYTADEL_TEST_INDEX_SENTINEL) == 0;
    lua_pop(L, 1);

    /* The real check: cytadel_plugin_raw_getfield() must NEVER invoke
     * __index -- for an absent field it must yield nil (never the
     * sentinel), and for a present field it must yield the real value
     * directly. */
    cytadel_plugin_raw_getfield(L, tbl_idx, "absent");
    bool raw_absent_is_nil = lua_isnil(L, -1);
    lua_pop(L, 1);

    cytadel_plugin_raw_getfield(L, tbl_idx, "present");
    bool raw_present_is_42 = lua_isinteger(L, -1) && lua_tointeger(L, -1) == 42;
    lua_pop(L, 1);

    lua_close(L);
    return (getfield_invokes_index && raw_absent_is_nil && raw_present_is_42) ? 1 : 0;
}

/* TEST-SUPPORT ONLY -- see debug_support.h's doc comment on this function.
 * Security-review round-4 suggestion 5: reimplements loader.c's
 * cytadel_plugin_register_one_file() pipeline (§4.1 steps 1-5) far enough
 * to reach the exact same `cytadel_plugin_raw_getfield(L, env_idx, "run")`
 * call loader.c itself makes, but attaches a hostile __index metatable
 * directly onto env_idx via the raw C API (exactly like
 * cytadel_plugin_debug_check_raw_getfield_bypasses_index() above) between
 * the registration chunk's own lua_pcall() completing and that lookup
 * running -- something no plugin's own Lua code could ever do once
 * sandbox.c's __metatable lock is attached, but which proves the
 * raw_getfield call site itself (not just the lock) is what keeps this
 * specific lookup safe. */
int cytadel_plugin_debug_check_loader_run_lookup_ignores_hostile_index(const char *lua_path) {
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        return -1;
    }

    cytadel_plugin_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));

    lua_pushcfunction(L, cytadel_plugin_msgh);
    int msgh_idx = lua_gettop(L);

    cytadel_plugin_push_metadata_sandbox(L, &hdr);
    int env_idx = lua_gettop(L);

    int load_rc = luaL_loadfile(L, lua_path);
    if (load_rc != LUA_OK) {
        cytadel_plugin_header_free(&hdr);
        lua_close(L);
        return -1;
    }
    int chunk_idx = lua_gettop(L);
    cytadel_plugin_rebind_env(L, chunk_idx, env_idx);

    int call_rc = lua_pcall(L, 0, 0, msgh_idx);
    if (call_rc != LUA_OK) {
        cytadel_plugin_header_free(&hdr);
        lua_close(L);
        return -1;
    }

    /* The adversarial step: attach a hostile __index metatable directly to
     * env_idx via the raw C API, bypassing sandbox.c's __metatable lock --
     * no plugin's own Lua code could ever do this, only this white-box
     * test harness (lua_setmetatable() does not consult __metatable at
     * all; only Lua's own setmetatable() library function does). */
    lua_newtable(L);
    lua_pushcfunction(L, cytadel_test_index_sentinel);
    lua_setfield(L, -2, "__index");
    lua_setmetatable(L, env_idx);

    /* The exact call loader.c's own §4.1 step 5 check makes. */
    cytadel_plugin_raw_getfield(L, env_idx, "run");
    bool got_sentinel = lua_isstring(L, -1) &&
                         strcmp(lua_tostring(L, -1), CYTADEL_TEST_INDEX_SENTINEL) == 0;
    bool has_run = lua_isfunction(L, -1);
    lua_pop(L, 1);

    cytadel_plugin_header_free(&hdr);
    lua_close(L);

    if (got_sentinel) {
        return 0; /* regression: the hostile __index fired */
    }
    /* Security-review round-5 suggestion S-1: `lua_path`'s fixture is
     * expected to define no run() -- absence is the correct, expected
     * outcome this function exists to check for. Previously this was
     * merely documented and `has_run` was discarded via `(void)has_run`,
     * which meant that if the fixture ever drifted to define a run() (e.g.
     * an edit to registration_missing_run's fixture file), raw_getfield()
     * would return that real function, got_sentinel would be false exactly
     * as in the correct case, and this function would return 1 (pass)
     * WITHOUT the hostile __index having been exercised at all -- a silent
     * no-op wearing a green checkmark. Failing loudly here instead turns
     * that drift into an unmistakable test-setup error rather than a test
     * that quietly stopped checking anything. */
    if (has_run) {
        return -1;
    }
    return 1;
}

#endif /* CYTADEL_BUILD_TESTING */
