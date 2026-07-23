#ifndef CYTADEL_PLUGIN_FD_TRACKER_H
#define CYTADEL_PLUGIN_FD_TRACKER_H

#include <stdbool.h>
#include <stddef.h>

/* Engine-side tracking of every fd opened via open_sock_tcp() for exactly
 * one (plugin, target[, port]) invocation (plugin_ctx.h's
 * cytadel_plugin_ctx_t) -- the real §4.4 force-close guarantee, Milestone
 * 5 security-audit finding W2. A plugin can defeat ordinary Lua-level
 * cleanup by tampering with the socket userdata's metatable (e.g.
 * `getmetatable(sock).__gc = nil`, if the metatable were left
 * unprotected -- see api_socket.c's __metatable lock, which closes that
 * specific hole) or, in principle, by some other future Lua-level trick;
 * this tracker does not rely on Lua's own finalization (__gc/__close) at
 * all. invoke.c force-closes every still-open tracked fd right after
 * run()'s lua_pcall() returns, independent of whether __gc/__close ever
 * ran.
 *
 * Not thread-safe -- and does not need to be: exactly one
 * cytadel_plugin_fd_tracker_t exists per invocation, embedded in that
 * invocation's stack-local cytadel_plugin_ctx_t (invoke.c), which is never
 * shared across lua_States or threads (plugin-api.md §4.2 step 2: a fresh
 * lua_State per invocation, never pooled/reused). Each src/core
 * worker-pool thread runs its own independent sequence of invocations,
 * each with its own tracker instance on that thread's own C stack -- there
 * is no shared mutable state between them. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int *fds;   /* owned; fds[i] is an open, tracked fd, or -1 once closed. NULL after free(). */
    size_t count;    /* number of slots ever registered by add() -- see free()'s own comment
                       * for why this is deliberately NOT reset back to 0 by free(). */
    size_t capacity;
    /* Security-review round-4 W-1 (regression from round 3's fix): set true
     * by cytadel_plugin_fd_tracker_free(). See that function's and
     * is_closed()/is_tracked()'s own comments -- this is what lets the
     * belt-and-braces guard in api_socket.c's cytadel_plugin_socket_close()
     * keep working correctly even after the tracker backing this ctx has
     * already been freed at the end of an invocation. */
    bool freed;
} cytadel_plugin_fd_tracker_t;

/* Registers `fd` (must be >= 0) as newly tracked/open. Returns the index
 * to store as the socket userdata's track_idx (api_socket.h) so later
 * close paths (close_sock()/__gc/__close, or the end-of-invocation force-
 * close sweep) can find this exact slot again -- deliberately NOT a
 * search-by-fd-value lookup, since fd numbers can be reused by the OS
 * across opens/closes within the same invocation and a value-based lookup
 * could then touch the wrong slot. Returns (size_t)-1 on allocation
 * failure; the fd is then simply untracked by this best-effort engine-side
 * safety net (close_sock()/__gc/__close remain the primary close path
 * regardless). */
size_t cytadel_plugin_fd_tracker_add(cytadel_plugin_fd_tracker_t *tracker, int fd);

/* Marks the fd at `track_idx` as closed (sets that slot to -1) WITHOUT
 * closing it itself -- the caller (close_sock()/__gc/__close in
 * api_socket.c) has already close()'d the real fd; this only keeps the
 * tracker consistent so the end-of-invocation sweep below does not
 * double-close it. No-op if `tracker` is NULL, if track_idx == (size_t)-1,
 * or if track_idx is out of range against `tracker->count`.
 *
 * Security-review round-5 finding W-C: also a no-op (never touches
 * tracker->fds) if `tracker->freed` is true -- once freed, fds is NULL and
 * `count` is deliberately preserved non-zero (round-4 W-1), so an in-range
 * track_idx would otherwise index a NULL pointer. Not reachable today (see
 * api_socket.c's cytadel_plugin_socket_close(), whose is_closed() check
 * already short-circuits true for a freed tracker before this would ever
 * be called), but guarded explicitly rather than relying on that caller
 * discipline alone.
 *
 * Security-review round-6 item 4: both guards above (`tracker == NULL` and
 * `tracker->freed`) are real, load-bearing checks in fd_tracker.c's own
 * implementation -- this comment previously documented only the `freed`
 * half and separately (incorrectly) claimed passing a NULL `tracker` "is
 * not valid" for every real caller, which understated what the code
 * actually guards against. Neither guard is reachable through this
 * tracker's real callers today (see above), but both are checked
 * explicitly, not merely assumed. */
void cytadel_plugin_fd_tracker_mark_closed(cytadel_plugin_fd_tracker_t *tracker, size_t track_idx);

/* Force-closes every still-tracked (>= 0) fd in `tracker` and marks each
 * slot closed (idempotent -- safe to call more than once, or on an empty
 * tracker). Called by invoke.c as the end-of-invocation backstop sweep,
 * after lua_close(L) has already run its own __gc/__close pass (security-
 * review round-2 FIX 1 -- see invoke.c's cytadel_plugin_invoke_cleanup()
 * comment for why AFTER, not before). Returns 0 (touches nothing) if
 * `tracker` is NULL; otherwise returns the number of fds actually
 * force-closed here (0 in the common case where every socket was already
 * close_sock()'d by the plugin, or closed by lua_close()'s own __gc/__close
 * pass, or was never opened at all).
 *
 * Security-review round-5 finding W-C: also safe (returns 0, touches
 * nothing) if `tracker` has already been cytadel_plugin_fd_tracker_free()'d
 * -- freed leaves fds == NULL while `count` stays deliberately non-zero
 * (round-4 W-1), so without this guard a post-free call here would loop
 * i < count and dereference a NULL fds[] pointer. Not reachable through
 * this tracker's one real caller today (cytadel_plugin_invoke_cleanup()
 * always calls this exactly once, strictly before free()), but guarded
 * explicitly since round 4's own fix treats "called after free" as an
 * expected state elsewhere in this API (is_closed()/is_tracked()), not one
 * that can never occur.
 *
 * Security-review round-6 item 4: this comment previously documented only
 * the `freed` half of the guard fd_tracker.c actually implements
 * (`tracker == NULL || tracker->freed`) -- both halves are real, checked
 * conditions, both are documented here now. */
size_t cytadel_plugin_fd_tracker_force_close_all(cytadel_plugin_fd_tracker_t *tracker);

/* Security-review round-2 FIX 1 (belt and braces): returns true if the fd
 * at `track_idx` is already marked closed (-1) in `tracker`, if `tracker`
 * has already been freed (cytadel_plugin_fd_tracker_free() -- see that
 * function's own comment for why "freed" is safe to treat as "closed"
 * here), or if `track_idx` is untracked/out of range (treated as "closed"
 * -- there is nothing IN THE TRACKER for a caller to double-close via THIS
 * mechanism).
 *
 * Security-review round-3 finding W-1 (WARNING): that "untracked" case
 * does NOT mean "the real fd is already closed" or "there is nothing to
 * close" -- it means the tracker never learned about this fd at all (e.g.
 * cytadel_plugin_fd_tracker_add()'s own realloc() failed under OOM, so
 * open_sock_tcp() (api_socket.c) handed back a live, fully open socket
 * userdata with track_idx == (size_t)-1). A caller that treats this
 * function's true return value alone as "safe to skip close()" will LEAK
 * that fd forever in exactly that case -- untracked and "already closed"
 * are semantically different states that must never be collapsed into one
 * boolean. Callers that need to distinguish them (api_socket.c's
 * cytadel_plugin_socket_close() is the only one) MUST check
 * cytadel_plugin_fd_tracker_is_tracked() first and only treat a true
 * return from THIS function as "already closed, skip close()" when that
 * check also returned true; an untracked slot must always fall through to
 * a real close() call. tracker == NULL is treated the same as "not
 * tracked" -- true, for the same reason.
 *
 * Security-review round-4 finding W-1 (regression fix): a `tracker` with
 * `freed == true` returns true here for EVERY `track_idx` that was ever a
 * genuinely tracked slot (track_idx < tracker->count -- see is_tracked()'s
 * own comment for why count is deliberately preserved across free()),
 * regardless of what that slot's last fds[] value was (fds[] itself no
 * longer exists to even ask). This is only correct because this tracker's
 * one caller (invoke.c's cytadel_plugin_invoke_cleanup()) always calls
 * cytadel_plugin_fd_tracker_force_close_all() -- which closes and marks -1
 * every still-open slot -- immediately before cytadel_plugin_fd_tracker_free()
 * runs; by the time `freed` is true, every slot this tracker ever knew
 * about is therefore guaranteed to already be closed for real. A
 * hypothetical future caller that frees a tracker WITHOUT force-closing
 * everything in it first would make this function silently misreport an
 * actually-still-open fd as closed (a leak, not a double-close) -- see
 * cytadel_plugin_fd_tracker_free()'s own comment for this precondition. */
bool cytadel_plugin_fd_tracker_is_closed(const cytadel_plugin_fd_tracker_t *tracker,
                                          size_t track_idx);

/* Security-review round-3 finding W-1 (WARNING): returns true iff
 * `track_idx` genuinely refers to a live slot in `tracker` (i.e. this fd
 * WAS successfully registered by cytadel_plugin_fd_tracker_add() -- track_idx
 * is neither (size_t)-1 nor out of range, and `tracker` is non-NULL). The
 * complement of "untracked" -- see cytadel_plugin_fd_tracker_is_closed()'s
 * own comment for why this must be checked separately from, and BEFORE,
 * that function whenever the caller's decision is "should I skip close()
 * on this fd".
 *
 * Security-review round-4 finding W-1 (regression fix): this remains true
 * for a previously-valid `track_idx` even after cytadel_plugin_fd_tracker_free()
 * has run on `tracker`, because free() deliberately does NOT reset `count`
 * back to 0 (only fds/capacity/freed change) -- see free()'s own comment.
 * Round 3's fix had free() implicitly reset the tracker to "nothing was
 * ever tracked" (by zeroing count), which made THIS function start
 * returning false for every post-free lookup and defeated the
 * tracked-vs-closed guard in api_socket.c's cytadel_plugin_socket_close()
 * for exactly the case (a socket userdata's __gc/__close firing during
 * lua_close(L) after invoke.c's cleanup sweep had already run -- i.e. the
 * FIX 1 ordering bug reintroduced) it exists to catch. */
bool cytadel_plugin_fd_tracker_is_tracked(const cytadel_plugin_fd_tracker_t *tracker,
                                           size_t track_idx);

/* Frees tracker->fds and marks the struct freed (fds = NULL, capacity = 0,
 * freed = true). Safe on a zero-initialized or already-freed tracker. Does
 * NOT itself close any still-open fds -- callers MUST call
 * cytadel_plugin_fd_tracker_force_close_all() first (invoke.c's
 * cytadel_plugin_invoke_cleanup(), this tracker's only caller, always
 * does). This is a hard precondition, not merely a recommendation: once
 * `freed` is true, cytadel_plugin_fd_tracker_is_closed() unconditionally
 * reports every previously-tracked slot as closed (see that function's own
 * comment) -- calling this on a tracker that still has a genuinely open
 * (>= 0) slot would make that slot's fd silently unreachable from any
 * close() path (an engine-side leak) rather than a double-close.
 *
 * Security-review round-4 finding W-1 (regression fix): unlike round 3's
 * version, `count` is deliberately left UNCHANGED by this call (only
 * fds/capacity/freed change) -- see cytadel_plugin_fd_tracker_is_tracked()'s
 * comment for why a reset-to-0 `count` was itself the round-3 regression. */
void cytadel_plugin_fd_tracker_free(cytadel_plugin_fd_tracker_t *tracker);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_FD_TRACKER_H */
