#define _POSIX_C_SOURCE 200809L

#include "invoke.h"

#include <time.h>

#include <lauxlib.h>

#include "fd_tracker.h"
#include "field_utils.h"
#include "log.h"
#include "plugin_ctx.h"
#include "plugin_limits.h"
#include "sandbox.h"

#ifdef CYTADEL_BUILD_TESTING
#include <stdio.h> /* snprintf() -- builds "<verb>:<site>" event strings below */

#include "debug_support.h"

/* Security-review round-4 finding W-2: test-only instrumentation point
 * (compiled only into CYTADEL_BUILD_TESTING builds -- see debug_support.h
 * and src/plugin/CMakeLists.txt's BUILD_TESTING gating). Lets a regression
 * test observe DIRECTLY, in a live cytadel_plugin_invoke_one() call,
 * whether lua_close(L) always completes before
 * cytadel_plugin_invoke_cleanup() begins on every path through this
 * function, instead of inferring the ordering from whether a stray
 * double-close symptom is observable. That symptom-based approach stopped
 * working once round-4's W-1 fix restored api_socket.c's tracked+closed
 * guard to genuine belt-and-braces coverage (fd_tracker.c/.h): the guard
 * alone now suppresses any double-close regardless of this ordering, so a
 * test that only watches for the symptom can no longer distinguish correct
 * from reverted ordering (see tests/unit/test_plugin_r4w2_order_invariant.c
 * for the test built on this hook, and that file's own header comment for
 * the full reasoning). NULL (a no-op) in every production build and in
 * every test that does not explicitly set it -- defined here, declared
 * `extern` in debug_support.h.
 *
 * Security-review round-5 finding W-A: this macro must only ever be called
 * from inside cytadel_plugin_close_state() (for "lua_close_done") and as
 * cytadel_plugin_invoke_cleanup()'s own first statement (for
 * "cleanup_begin") -- never as a free-standing statement placed next to a
 * call site, which round 4's version did and which a subsequent reordering
 * of the call sites (leaving the macro calls behind) silently defeated. See
 * cytadel_plugin_close_state()'s own comment below for the exact
 * regression this caused and how binding the events to the operations
 * instead of to source-line positions fixes it.
 *
 * Security-review round-6 item 2 (S-2 path-drift hazard fix): the fired
 * event string is now "<verb>:<site_id>" (e.g. "lua_close_done:load_rc"),
 * not just "<verb>" -- `site_id` is a real C argument passed at each of
 * this file's four call sites (see cytadel_plugin_invoke_one() below), so
 * it travels WITH the call itself, the same way the verb already does; a
 * future edit that changes which branch a fixture takes (e.g. "fixing"
 * invoke_syntax_error/syntax_error.lua so it parses) changes the recorded
 * site_id right along with it instead of leaving a stale, silently-passing
 * assertion behind. tests/unit/test_plugin_r4w2_order_invariant.c asserts
 * the full "<verb>:<site_id>" string per fixture, not just event order. */
void (*cytadel_plugin_test_invoke_order_hook)(const char *event) = NULL;
#define CYTADEL_PLUGIN_INVOKE_ORDER_HOOK(verb, site_id)                       \
    do {                                                                      \
        if (cytadel_plugin_test_invoke_order_hook != NULL) {                  \
            char cytadel_hook_event_[64];                                     \
            snprintf(cytadel_hook_event_, sizeof(cytadel_hook_event_),        \
                      verb ":%s", (site_id));                                 \
            cytadel_plugin_test_invoke_order_hook(cytadel_hook_event_);       \
        }                                                                     \
    } while (0)
#else
/* `site_id` must still be referenced (not just `verb`, which is always a
 * string literal) so a non-CYTADEL_BUILD_TESTING build does not warn
 * -Wunused-parameter on cytadel_plugin_close_state()'s/
 * cytadel_plugin_invoke_cleanup()'s own site_id parameter. */
#define CYTADEL_PLUGIN_INVOKE_ORDER_HOOK(verb, site_id) ((void)(site_id))
#endif

/* Instruction-count granularity for the LUA_MASKCOUNT hook (§4.5): how
 * many VM instructions elapse between wall-clock deadline checks. 1000 is
 * frequent enough to catch a tight infinite loop (e.g. `while true do end`)
 * well within a small fraction of the 15s budget, without paying a
 * clock_gettime() syscall on literally every single instruction. */
#define CYTADEL_PLUGIN_HOOK_INSTRUCTION_COUNT 1000

/* Security-review round-5 finding W-A (CRITICAL fix to round-4's own W-2
 * deliverable): every lua_close(L) call in this file MUST go through this
 * helper, never call lua_close(L) directly. A free-standing
 * CYTADEL_PLUGIN_INVOKE_ORDER_HOOK("lua_close_done") placed by hand next to
 * a lua_close(L) call site only proves the two statements are textually
 * adjacent -- it says nothing about whether lua_close(L) actually ran
 * before whatever comes after it, because nothing stops a future edit from
 * moving ONE of the two statements and leaving the other behind. That is
 * exactly what happened in round 5's own reviewer experiment: relocating
 * cytadel_plugin_invoke_cleanup() above lua_close(L) on the final path,
 * while leaving both CYTADEL_PLUGIN_INVOKE_ORDER_HOOK() macro calls exactly
 * where they were, made the hook log "lua_close_done" then "cleanup_begin"
 * in the "correct" order even though lua_close(L) itself now ran LAST --
 * i.e. the round-2 FIX 1 double-close bug, fully reinstated, with the
 * regression test that was supposed to catch it still green.
 *
 * Firing "lua_close_done" from inside this helper -- immediately after the
 * lua_close(L) call this helper itself makes, and nowhere else -- ties the
 * event to the OPERATION instead of to a source-line position. No matter
 * where in cytadel_plugin_invoke_one() a call to this helper is moved to,
 * the event still fires if and only if lua_close(L) has just returned.
 * Complemented by cytadel_plugin_invoke_cleanup() firing "cleanup_begin" as
 * its own first statement (see that function) -- so reordering the CALLS
 * to these two functions is now the only way to change the recorded event
 * order, which is exactly the property this test is supposed to verify.
 *
 * Security-review round-6 item 3: this is still, ultimately, a documented
 * CONVENTION -- "every lua_close(L) call in this file MUST go through this
 * helper" is enforced by nothing at compile time. A structural check
 * (tests/unit/check_invoke_lua_close_invariant.c, run as its own CTest
 * entry) closes that gap by parsing this file's own source text and
 * mechanically proving `lua_close(` appears exactly once in it and only
 * inside this function's body -- see that tool's own top-of-file comment
 * for the exact "hollow" mutation (blank this call, add a free-standing
 * lua_close(L) elsewhere) it was built and verified against.
 *
 * `site_id` (round-6 item 2) identifies which of this file's four call
 * sites is closing this lua_State -- see the CYTADEL_PLUGIN_INVOKE_ORDER_HOOK
 * macro above for why it travels as a real argument rather than a
 * free-standing marker next to each call site. */
static void cytadel_plugin_close_state(lua_State *L, const char *site_id) {
    lua_close(L);
    CYTADEL_PLUGIN_INVOKE_ORDER_HOOK("lua_close_done", site_id);
}

/* §4.5: "a debug hook ... checks a wall-clock deadline stored in the
 * state's extra space (lua_getextraspace(L)) ... to avoid a registry
 * round-trip on every hook tick." lua_getextraspace() returns a
 * LUA_EXTRASPACE-byte blob (sizeof(void*) with this vendored build's
 * default luaconf.h) -- enough to hold a POINTER to a deadline struct that
 * cytadel_plugin_invoke_one() owns on its own C stack frame for the
 * duration of the run() call, not the deadline value itself. */
static void cytadel_plugin_runtime_hook(lua_State *L, lua_Debug *ar) {
    (void)ar;
    struct timespec *deadline = *(struct timespec **)lua_getextraspace(L);
    if (deadline == NULL) {
        return; /* not yet installed (or already cleared) -- no-op */
    }
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (now.tv_sec > deadline->tv_sec ||
        (now.tv_sec == deadline->tv_sec && now.tv_nsec > deadline->tv_nsec)) {
        /* luaL_error() unwinds via Lua's normal error mechanism -- this
         * triggers <close>/__gc socket cleanup exactly as any other error
         * would (§4.4), and is caught by cytadel_plugin_invoke_one()'s
         * enclosing lua_pcall() like any other plugin failure (§4.3). */
        luaL_error(L, "plugin exceeded max execution time (%d ms)", CYTADEL_PLUGIN_MAX_RUNTIME_MS);
    }
}

/* Milestone 5 security-audit finding W2 (as hardened by the round-2
 * security-review FIX 1): the backstop half of the §4.4 force-close
 * guarantee, independent of Lua-level __gc/__close (which a plugin could,
 * in principle, defeat -- see api_socket.c's __metatable lock for the
 * complementary Lua-side hardening). Force-closes every fd this
 * invocation's open_sock_tcp() calls registered into ctx->open_fds and
 * never had explicitly close_sock()'d (or already force-closed by
 * lua_close()'s own __gc/__close pass, or by a prior error unwind), then
 * releases the tracker's own storage. Must be called exactly once per
 * invocation, after every lua_pcall() this function makes has returned AND
 * AFTER lua_close(L) -- never before.
 *
 * FIX 1 (CRITICAL, security-review round 2): this used to run BEFORE
 * lua_close(L). That is a double-close bug: force_close_all() below calls
 * close() on the real fd and marks the tracker's slot -1, but it has no way
 * to reach into the (still-live, not yet garbage-collected) socket
 * userdata and clear ITS OWN sock->fd field -- only the userdata's __gc/
 * __close (cytadel_plugin_api_socket_gc(), api_socket.c) can do that, and
 * that finalizer had not run yet. So the immediately-following lua_close(L)
 * would then run __gc on that same userdata, see sock->fd still >= 0 (the
 * stale, already-closed value), and close() it again -- and because this
 * scanner's workers are pthreads sharing one process-global fd table, the
 * OS may already have handed that fd number to a completely different
 * worker's brand-new socket by then, so this second close() could sever
 * another, unrelated, live connection out from under it.
 *
 * Calling this AFTER lua_close(L) instead fixes that structurally: ctx (and
 * therefore ctx->open_fds) is a local on THIS function's own stack frame
 * and stays valid for lua_close(L)'s entire duration, so lua_close()'s own
 * __gc/__close pass still runs first and normally, correctly closing every
 * still-open socket and marking the tracker consistent via
 * cytadel_plugin_socket_close() (api_socket.c) exactly as it always has.
 * This sweep then runs as a pure backstop afterward for anything __gc/
 * __close could not reach (e.g. a socket whose fd_tracker registration
 * itself failed under OOM) -- it no longer races lua_close() at all.
 * api_socket.c's cytadel_plugin_socket_close() also has an independent,
 * belt-and-braces guard (cytadel_plugin_fd_tracker_is_tracked() +
 * cytadel_plugin_fd_tracker_is_closed() together) so even a future
 * reordering mistake here could not reintroduce a live double-close --
 * security-review round-4 finding W-1 fixed a regression in that guard's
 * OWN coverage (fd_tracker.c/.h: a freed tracker used to read as
 * "untracked", not "closed", which defeated the guard for exactly this
 * scenario), and round-4 finding W-2 added
 * tests/unit/test_plugin_r4w2_order_invariant.c, which asserts this
 * ordering DIRECTLY via CYTADEL_PLUGIN_INVOKE_ORDER_HOOK.
 *
 * Security-review round-5 finding W-A: round 4's version of that
 * instrumentation fired "lua_close_done"/"cleanup_begin" from free-standing
 * macro calls placed NEXT TO each call site, which only proved the two
 * statements were textually adjacent, not that lua_close(L) had actually
 * run first -- see cytadel_plugin_close_state()'s own comment above for the
 * exact reviewer experiment that broke it. "cleanup_begin" now fires as
 * this function's OWN first statement below (bound to this function being
 * entered, not to a line position in the caller), paired with
 * "lua_close_done" firing from inside cytadel_plugin_close_state() -- every
 * caller below MUST call cytadel_plugin_close_state(L, site_id), never
 * lua_close(L) directly, or this pairing breaks.
 *
 * Safe to call on a ctx whose open_fds was never populated (registration-
 * equivalent failure paths below, before run() ever executed) --
 * force_close_all() and free() are both no-ops on an empty/zeroed
 * tracker.
 *
 * `site_id` (round-6 item 2) identifies which of this file's four call
 * sites this cleanup call belongs to -- see
 * CYTADEL_PLUGIN_INVOKE_ORDER_HOOK's own comment above. */
static void cytadel_plugin_invoke_cleanup(const cytadel_plugin_header_t *header,
                                            cytadel_plugin_ctx_t *ctx, const char *site_id) {
    CYTADEL_PLUGIN_INVOKE_ORDER_HOOK("cleanup_begin", site_id);
    size_t force_closed = cytadel_plugin_fd_tracker_force_close_all(&ctx->open_fds);
    if (force_closed > 0) {
        cytadel_log_debug(
            "plugin %lld %s: engine force-closed %zu socket(s) left open at end of run "
            "(§4.4 guarantee, independent of __gc/__close)",
            (long long)header->script_id, header->script_name, force_closed);
    }
    cytadel_plugin_fd_tracker_free(&ctx->open_fds);
}

cytadel_plugin_result_status_t cytadel_plugin_invoke_one(const cytadel_plugin_header_t *header,
                                                           const char *ip, cytadel_kb_t *kb,
                                                           int bound_port,
                                                           cytadel_finding_list_t *findings) {
    /* §4.2 step 2: "fresh lua_State for this one (plugin, target)
     * invocation. Fresh per invocation, not reused/pooled." */
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        cytadel_log_error("plugin run: out of memory creating lua_State for script_id %lld (%s)",
                           (long long)header->script_id, header->script_name);
        return CYTADEL_PLUGIN_RESULT_FAILED;
    }
    *(void **)lua_getextraspace(L) = NULL; /* no runtime-limit deadline installed yet */

    cytadel_plugin_ctx_t ctx;
    ctx.kb = kb;
    ctx.ip = ip;
    ctx.bound_port = bound_port;
    ctx.header = header;
    ctx.findings = findings;
    ctx.open_fds.fds = NULL; /* W2: no sockets tracked until open_sock_tcp() runs */
    ctx.open_fds.count = 0;
    ctx.open_fds.capacity = 0;
    ctx.open_fds.freed = false; /* round-4 W-1: must be explicitly initialized, this is a
                                  * field-by-field (not `= {0}`) struct init */
    cytadel_plugin_ctx_set(L, &ctx);

    lua_pushcfunction(L, cytadel_plugin_msgh);
    int msgh_idx = lua_gettop(L);

    cytadel_plugin_push_run_sandbox(L); /* §4.2 step 3 */
    int env_idx = lua_gettop(L);

    int load_rc = luaL_loadfile(L, header->source_path); /* §4.2 step 4 (part 1) */
    if (load_rc != LUA_OK) {
        cytadel_log_error("plugin %lld %s failed: %s", (long long)header->script_id,
                           header->script_name, lua_tostring(L, -1));
        /* FIX 1: lua_close(L) BEFORE the cleanup sweep on every path -- via
         * cytadel_plugin_close_state(), never lua_close(L) directly -- see
         * that helper's and cytadel_plugin_invoke_cleanup()'s comments. */
        cytadel_plugin_close_state(L, "load_rc");
        cytadel_plugin_invoke_cleanup(header, &ctx, "load_rc");
        return CYTADEL_PLUGIN_RESULT_FAILED;
    }
    int chunk_idx = lua_gettop(L);
    cytadel_plugin_rebind_env(L, chunk_idx, env_idx); /* §4.2 step 4 (part 2) / §5.2 */

    int call_rc = lua_pcall(L, 0, 0, msgh_idx); /* §4.2 step 4 (part 3): defines run() */
    if (call_rc != LUA_OK) {
        cytadel_log_error("plugin %lld %s failed: %s", (long long)header->script_id,
                           header->script_name, lua_tostring(L, -1));
        /* FIX 1: lua_close(L) BEFORE the cleanup sweep on every path -- via
         * cytadel_plugin_close_state(), never lua_close(L) directly -- see
         * that helper's and cytadel_plugin_invoke_cleanup()'s comments. */
        cytadel_plugin_close_state(L, "call_rc");
        cytadel_plugin_invoke_cleanup(header, &ctx, "call_rc");
        return CYTADEL_PLUGIN_RESULT_FAILED;
    }

    /* Security-review round-3 finding C-1 (CRITICAL): raw, not lua_getfield
     * -- this lookup runs AFTER the definer-chunk's lua_pcall() (line 146
     * above) has already returned, i.e. OUTSIDE any protected call on this
     * lua_State, exactly like loader.c's equivalent check -- see that
     * file's comment on this exact fix for the full rationale
     * (setmetatable(_ENV, {__index = ...}) plus no run() defined could
     * otherwise abort() the whole process here, mid-scan, over one
     * plugin's invocation). */
    cytadel_plugin_raw_getfield(L, env_idx, "run");
    if (!lua_isfunction(L, -1)) {
        cytadel_log_error(
            "plugin %lld %s failed: no run() function defined when this invocation executed",
            (long long)header->script_id, header->script_name);
        /* FIX 1: lua_close(L) BEFORE the cleanup sweep on every path -- via
         * cytadel_plugin_close_state(), never lua_close(L) directly -- see
         * that helper's and cytadel_plugin_invoke_cleanup()'s comments. */
        cytadel_plugin_close_state(L, "no_run");
        cytadel_plugin_invoke_cleanup(header, &ctx, "no_run");
        return CYTADEL_PLUGIN_RESULT_FAILED;
    }

    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += CYTADEL_PLUGIN_MAX_RUNTIME_MS / 1000;
    deadline.tv_nsec += (long)(CYTADEL_PLUGIN_MAX_RUNTIME_MS % 1000) * 1000000L;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    *(void **)lua_getextraspace(L) = &deadline;
    lua_sethook(L, cytadel_plugin_runtime_hook, LUA_MASKCOUNT, CYTADEL_PLUGIN_HOOK_INSTRUCTION_COUNT);

    int run_rc = lua_pcall(L, 0, 0, msgh_idx); /* §4.2 step 5 */

    cytadel_plugin_result_status_t status;
    if (run_rc != LUA_OK) {
        cytadel_log_error("plugin %lld %s failed: %s", (long long)header->script_id,
                           header->script_name, lua_tostring(L, -1));
        status = CYTADEL_PLUGIN_RESULT_FAILED;
    } else {
        status = CYTADEL_PLUGIN_RESULT_OK;
    }

    /* §4.2 step 6: unconditional on every path above. lua_close()'s own
     * __gc/__close pass (Lua 5.4 is specified to close all to-be-closed
     * variables and invoke pending __gc finalizers before freeing state) is
     * the PRIMARY §4.4 close path for the common case (an untampered
     * socket a plugin simply forgot to close_sock()) -- see
     * api_socket.c's cytadel_plugin_socket_close(). Via
     * cytadel_plugin_close_state(), never lua_close(L) directly -- see that
     * helper's comment (round-5 W-A). */
    cytadel_plugin_close_state(L, "final");

    /* FIX 1 (security-review round 2): the engine-side force-close sweep
     * now runs AFTER lua_close(L), as a pure backstop for whatever __gc/
     * __close could not reach (e.g. an fd whose tracker registration
     * itself failed under OOM) -- see cytadel_plugin_invoke_cleanup()'s own
     * comment for why running this before lua_close() was a double-close
     * bug, and api_socket.c's cytadel_plugin_socket_close() for the
     * independent belt-and-braces guard against ever reintroducing it.
     * Round-5 W-A: cytadel_plugin_close_state() above and
     * cytadel_plugin_invoke_cleanup() below are this pair's own direct,
     * ordering-level regression coverage -- each fires its own event as its
     * OWN first/last statement (not from a line position next to the
     * other's call site), so this is the last of four calls to EACH of
     * cytadel_plugin_close_state() and cytadel_plugin_invoke_cleanup() --
     * see tests/unit/test_plugin_r4w2_order_invariant.c and
     * cytadel_plugin_close_state()'s own comment for the exact regression
     * this now catches that round 4's version did not, and round-6 item 3's
     * tests/unit/check_invoke_lua_close_invariant.c for the structural
     * (not merely test-observed) enforcement of "lua_close(L) only inside
     * cytadel_plugin_close_state()". */
    cytadel_plugin_invoke_cleanup(header, &ctx, "final");

    return status;
}
