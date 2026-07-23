#ifndef CYTADEL_PLUGIN_DEBUG_SUPPORT_H
#define CYTADEL_PLUGIN_DEBUG_SUPPORT_H

/* TEST-SUPPORT ONLY. Security-review round-4 finding W-3: these functions
 * used to be declared in the PUBLIC include/cytadel/plugin/plugin.h and
 * debug_support.c used to be compiled unconditionally into every build of
 * the `cytadel` static library -- production code never called any of
 * them, but they were structurally reachable by anything that linked
 * `cytadel` (no install()/BUILD_SHARED_LIBS/--whole-archive currently ships
 * them, but nothing prevented a future build-system change from doing so).
 * cytadel_plugin_debug_check_env_isolated() in particular is a
 * load-and-execute-arbitrary-Lua-file entry point (luaL_loadfile + a full
 * run-phase sandbox) driven by a caller-supplied filesystem path -- exactly
 * the kind of thing that must never be part of this library's public
 * surface.
 *
 * Fix: this header is now private to src/plugin (not under
 * include/cytadel/plugin/), debug_support.c is only added to the `cytadel`
 * target's sources under `if(BUILD_TESTING)` (src/plugin/CMakeLists.txt),
 * and everything below is additionally guarded by CYTADEL_BUILD_TESTING
 * (only defined on the `cytadel` target when BUILD_TESTING is ON) as
 * defense in depth in case a future change ever re-adds debug_support.c to
 * target_sources() unconditionally. tests/unit/CMakeLists.txt adds
 * src/plugin to the include path of exactly the test executables that need
 * this header (the same "private header made reachable across a module
 * boundary" technique src/plugin's own CMakeLists.txt already uses for
 * src/net's tls_session.h). */

#ifdef CYTADEL_BUILD_TESTING

#ifdef __cplusplus
extern "C" {
#endif

/* TEST-SUPPORT ONLY (tests/unit, tests/plugins) -- production code never
 * calls this. Loads `lua_path` through the exact same run-phase
 * sandbox-build + _ENV-rebind + register()+run() pipeline
 * cytadel_plugin_run_all_for_host() uses internally (plugin-api.md §4.2
 * steps 2-4, §5.2), but instead of invoking run(), checks whether a bare
 * top-level global assignment named `global_name` in that chunk (e.g. a
 * fixture that does `leaked = "should not escape"` at file scope) ended up
 * on the lua_State's REAL global table -- which it must never do; if it
 * did, _ENV rebinding was skipped or broken and the sandbox is defeated.
 * Exists so the sandbox/_ENV-isolation unit tests do not need to reach
 * into src/plugin's private headers to observe this engine-internal
 * invariant directly.
 *
 * Returns 1 if isolated (the real global was NOT set -- correct), 0 if
 * leaked (the real global WAS set -- a sandbox bug), or -1 if `lua_path`
 * could not be loaded/run at all (a fixture-authoring error unrelated to
 * the isolation check itself; the caller should treat this as a test
 * failure too, just with a different diagnostic). */
int cytadel_plugin_debug_check_env_isolated(const char *lua_path, const char *global_name);

/* TEST-SUPPORT ONLY (tests/unit) -- production code never calls this.
 * Security-review round-3 finding W-1 (WARNING) regression check: directly
 * exercises api_socket.c's cytadel_plugin_socket_close() with a socket
 * userdata whose track_idx == (size_t)-1 -- exactly the state
 * open_sock_tcp() leaves a socket in when the engine-side fd tracker's own
 * cytadel_plugin_fd_tracker_add() (fd_tracker.c) fails to register it (an
 * OOM realloc() failure) -- and proves the real fd still gets close()'d
 * rather than silently leaked for the rest of the process's lifetime.
 * Opens a throwaway pipe(2) fd itself (no network dependency needed).
 * Returns 1 if the fd was genuinely closed (correct), 0 if it is still
 * open afterward (the W-1 leak this exists to catch), or -1 on an
 * unrelated test-setup failure (pipe()/lua_State creation). */
int cytadel_plugin_debug_check_untracked_socket_closes(void);

/* TEST-SUPPORT ONLY (tests/unit) -- production code never calls this.
 * Security-review round-3 finding W-2 (WARNING) supplementary regression
 * check: deterministically (no thread race needed) proves
 * cytadel_plugin_socket_close()'s tracked+closed guard (security-review
 * round-2 FIX 1) makes a second close on an already-tracked-closed slot a
 * true no-op -- the real fd it is called with is never touched. See
 * tests/unit/test_plugin_r4w2_order_invariant.c for the round-4 companion
 * that verifies the invoke.c call ORDERING directly, independent of
 * whether this guard exists. Returns 1 if the guard behaved correctly (no
 * second close, and the socket userdata's own view was still updated to
 * closed), 0 if it did not, or -1 on an unrelated test-setup failure. */
int cytadel_plugin_debug_check_double_close_guard(void);

/* TEST-SUPPORT ONLY (tests/unit) -- production code never calls this.
 * Security-review round-4 finding W-1 regression check: proves the
 * tracked+closed guard above (cytadel_plugin_debug_check_double_close_guard())
 * still works correctly after the tracker backing it has been
 * cytadel_plugin_fd_tracker_free()'d -- i.e. proves the exact scenario
 * round 4 found broken: invoke.c's cytadel_plugin_invoke_cleanup() always
 * calls force_close_all() THEN free() before returning; if the ordering
 * fix (lua_close(L) before cleanup) were ever reverted, a socket
 * userdata's __gc/__close would call cytadel_plugin_socket_close() with a
 * track_idx into a tracker that has ALREADY been freed by the time __gc
 * runs. Round 3's guard implementation collapsed "freed" into "untracked"
 * (fd_tracker_free() reset `count` to 0), which made the guard fall
 * through to a real close() in exactly that case -- reintroducing the
 * double-close round 2's FIX 1 exists to prevent. This test builds a
 * tracker via the real cytadel_plugin_fd_tracker_add()/mark_closed()/free()
 * API sequence (not a hand-rolled reimplementation of tracker internals,
 * to avoid the exact kind of reasoning gap that caused round 3's
 * regression in the first place), then calls
 * cytadel_plugin_socket_close() with a track_idx into that now-freed
 * tracker and a real, live fd standing in for a resource that coincidentally
 * reused the freed fd number. Returns 1 if the guard survived the free()
 * (fd left untouched, socket userdata's view updated to closed), 0 if it
 * did not, or -1 on an unrelated test-setup failure. */
int cytadel_plugin_debug_check_double_close_guard_survives_free(void);

/* TEST-SUPPORT ONLY. The __index metamethod cytadel_plugin_debug_check_
 * raw_getfield_bypasses_index() and
 * cytadel_plugin_debug_check_loader_run_lookup_ignores_hostile_index()
 * below install pushes a distinctive sentinel string rather than raising,
 * so those checks can tell "the metamethod fired" apart from "it did not"
 * with plain value comparisons and no lua_pcall() needed anywhere in
 * either function. */
#define CYTADEL_TEST_INDEX_SENTINEL "__CYTADEL_TEST_INDEX_METAMETHOD_FIRED__"

/* TEST-SUPPORT ONLY (tests/unit) -- production code never calls this.
 * Security-review round-3 finding C-1 (CRITICAL) supplementary regression
 * check: proves -- deterministically, via the raw Lua C API, independent of
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
 * can no longer produce one. Returns 1 if raw_getfield() behaved correctly
 * (and the attack harness itself was confirmed valid), 0 if it did not, or
 * -1 on an unrelated test-setup failure (lua_State creation). */
int cytadel_plugin_debug_check_raw_getfield_bypasses_index(void);

/* TEST-SUPPORT ONLY (tests/unit) -- production code never calls this.
 * Security-review round-4 suggestion 5: a CLOSER regression check than
 * cytadel_plugin_debug_check_raw_getfield_bypasses_index() above for C-1's
 * raw_getfield() half specifically AT loader.c's own call site (loader.c's
 * `cytadel_plugin_raw_getfield(L, env_idx, "run")` check), rather than on
 * an isolated ad hoc table unrelated to the real registration pipeline.
 * tests/unit/test_plugin_r3c1_env_metatable_abort.c's own header comment
 * already notes the gap this closes: that fixture-based test cannot
 * exercise loader.c's raw_getfield call in a state where env_idx actually
 * HAS a hostile metatable, because sandbox.c's __metatable lock rejects
 * the plugin's own `setmetatable(_ENV, ...)` attempt before the attack
 * ever reaches that point. This function reimplements loader.c's
 * registration pipeline (steps 1-5) far enough to reach the exact same
 * `cytadel_plugin_raw_getfield(L, env_idx, "run")` call, but -- like
 * cytadel_plugin_debug_check_raw_getfield_bypasses_index() above --
 * attaches a hostile __index metatable directly onto env_idx via the raw
 * lua_setmetatable() C API call (bypassing the __metatable lock the same
 * way that function's own harness does, since no plugin's own Lua code
 * could ever do this itself) immediately before making that lookup,
 * proving the lookup neither invokes the hostile __index NOR aborts even
 * in that doubly-adversarial state. `lua_path` should point at a fixture
 * with a valid register{} header and no run() function (e.g.
 * tests/plugins/fixtures/registration_missing_run/missing_run.lua) --
 * the absence of run() is the expected, correct outcome this checks for.
 * Returns 1 if the lookup behaved correctly (raw, no metamethod invoked,
 * run() reported absent), 0 if the hostile __index fired (a regression at
 * this exact call site), or -1 on an unrelated test-setup failure --
 * INCLUDING (security-review round-5 suggestion S-1) `lua_path`'s fixture
 * unexpectedly defining a run() function: that means the hostile __index
 * was never actually exercised by this call (raw_getfield() returned the
 * real run() before __index could ever be consulted), so this function
 * cannot tell "correct" from "silently untested" and reports it as a
 * setup error rather than a pass. Callers must pass a fixture whose own
 * header comment documents it never defines run(). */
int cytadel_plugin_debug_check_loader_run_lookup_ignores_hostile_index(const char *lua_path);

/* Security-review round-4 finding W-2 (as fixed by round-5 finding W-A,
 * extended by round-6 item 2): test-only instrumentation hook, defined (as
 * a plain, NULL-by-default function pointer) in invoke.c under its own
 * CYTADEL_BUILD_TESTING guard -- see that file's top-of-file comment for
 * the full mechanism and why it exists. A test sets this to a callback
 * before calling cytadel_plugin_run_all_for_host() / cytadel_plugin_invoke_one()
 * to observe, event by event, the exact order in which one invocation's
 * lua_close(L) and cytadel_plugin_invoke_cleanup() calls happen --
 * "lua_close_done:<site_id>" fires from inside invoke.c's
 * cytadel_plugin_close_state() helper, immediately after the lua_close(L)
 * call THAT HELPER makes, and "cleanup_begin:<site_id>" fires as
 * cytadel_plugin_invoke_cleanup()'s own first statement, immediately on
 * entry -- on every path through cytadel_plugin_invoke_one(), PROVIDED
 * every lua_close(L) call in that file is routed through
 * cytadel_plugin_close_state() (round-5 W-A: binding each event to its
 * operation, not to a source-line position next to a call site, is what
 * makes reordering the two CALLS the only way to change the recorded
 * order; round-6 item 3's structural check
 * (tests/unit/check_invoke_lua_close_invariant.c, hardened by round-7
 * item W-1 to match `lua_close` as a whole token rather than only
 * `lua_close(` call sites -- see that tool's own top-of-file and
 * cytadel_find_token_occurrences() comments) enforces the "routed
 * through" half of this precondition by mechanically proving `lua_close`
 * is never textually NAMED anywhere in invoke.c except inside
 * cytadel_plugin_close_state()'s own body -- since this hook alone cannot
 * (it only observes that cytadel_plugin_close_state() finished running,
 * not that lua_close(L) was the call that actually happened inside it).
 * That structural proof is still a text-position check, not a
 * control-flow or link-time one: it cannot tell whether a `lua_close`
 * reference sitting inside the body is on a path that actually executes
 * (vs. dead code within the body), and it cannot see a wrapper defined in
 * a different translation unit that itself calls lua_close(L) -- both are
 * outside what a single-file text parser can prove; see that checker's
 * own comments for the full reasoning). `<site_id>` (round-6 item 2) identifies which of
 * cytadel_plugin_invoke_one()'s four lua_close(L)/cleanup call sites fired
 * ("load_rc" / "call_rc" / "no_run" / "final" -- see that function), so a
 * test can bind a fixture to the exact path it is meant to exercise instead
 * of only checking event order in the abstract. Tests must reset this back
 * to NULL when done (it is process-global, not scoped to one invocation). */
extern void (*cytadel_plugin_test_invoke_order_hook)(const char *event);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_BUILD_TESTING */

#endif /* CYTADEL_PLUGIN_DEBUG_SUPPORT_H */
