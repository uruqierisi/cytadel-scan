#include "fd_tracker.h"

#include <stdlib.h>
#include <unistd.h>

size_t cytadel_plugin_fd_tracker_add(cytadel_plugin_fd_tracker_t *tracker, int fd) {
    if (tracker->count == tracker->capacity) {
        size_t new_capacity = (tracker->capacity == 0) ? 8 : tracker->capacity * 2;
        int *grown = realloc(tracker->fds, new_capacity * sizeof(*grown));
        if (grown == NULL) {
            return (size_t)-1;
        }
        tracker->fds = grown;
        tracker->capacity = new_capacity;
    }
    tracker->fds[tracker->count] = fd;
    return tracker->count++;
}

void cytadel_plugin_fd_tracker_mark_closed(cytadel_plugin_fd_tracker_t *tracker, size_t track_idx) {
    /* Security-review round-5 finding W-C: `tracker->freed` must be checked
     * BEFORE indexing tracker->fds[] -- once freed is true, fds is NULL
     * (cytadel_plugin_fd_tracker_free() below) and `count` is deliberately
     * left non-zero (round-4 W-1's whole point), so a track_idx that is
     * in-range against `count` would otherwise dereference a NULL fds[]
     * pointer here. Not reachable today (api_socket.c:83's mark_closed()
     * call site is unreachable post-free because cytadel_plugin_socket_close()
     * checks cytadel_plugin_fd_tracker_is_closed() first and that already
     * returns true for a freed tracker -- see that function's own comment),
     * but round 4's own premise is that post-free calls into this tracker
     * are an EXPECTED, not merely hypothetical, state -- see
     * cytadel_plugin_fd_tracker_force_close_all()'s matching guard below and
     * this function's own header comment (fd_tracker.h). */
    if (tracker == NULL || tracker->freed || track_idx == (size_t)-1 ||
        track_idx >= tracker->count) {
        return;
    }
    tracker->fds[track_idx] = -1;
}

size_t cytadel_plugin_fd_tracker_force_close_all(cytadel_plugin_fd_tracker_t *tracker) {
    /* Security-review round-5 finding W-C: without this guard, calling
     * force_close_all() on an already-freed tracker (fds == NULL, count
     * deliberately preserved non-zero by free() -- round-4 W-1) loops
     * i < count and dereferences tracker->fds[i], a NULL-pointer read --
     * deterministic SIGSEGV. Not reachable through invoke.c today (its one
     * caller, cytadel_plugin_invoke_cleanup(), always calls this exactly
     * once per invocation, strictly before cytadel_plugin_fd_tracker_free()
     * -- see that function's own comment), but round 4's fix made "freed"
     * an expected, checkable state rather than a state that can never recur,
     * so this function must tolerate being called on one -- a no-op (0
     * closed) is the correct answer: everything a freed tracker ever knew
     * about was already force-closed before free() ran (free()'s own
     * documented precondition). */
    if (tracker == NULL || tracker->freed) {
        return 0;
    }
    size_t closed = 0;
    for (size_t i = 0; i < tracker->count; i++) {
        if (tracker->fds[i] >= 0) {
            close(tracker->fds[i]);
            tracker->fds[i] = -1;
            closed++;
        }
    }
    return closed;
}

bool cytadel_plugin_fd_tracker_is_closed(const cytadel_plugin_fd_tracker_t *tracker,
                                          size_t track_idx) {
    if (tracker == NULL || track_idx == (size_t)-1 || track_idx >= tracker->count) {
        return true; /* untracked -- see this function's header comment (W-1) */
    }
    if (tracker->freed) {
        /* Round-4 W-1: fds[] no longer exists to even ask -- but by this
         * tracker's documented free() precondition, everything it ever
         * tracked was already force-closed before free() ran, so "freed"
         * is itself a safe, sufficient answer of "closed". */
        return true;
    }
    return tracker->fds[track_idx] < 0;
}

bool cytadel_plugin_fd_tracker_is_tracked(const cytadel_plugin_fd_tracker_t *tracker,
                                           size_t track_idx) {
    /* Round-4 W-1: deliberately keyed off `count`, not `freed` -- `count`
     * is never reset by free() (see that function's own comment), so this
     * keeps reporting true for a previously-valid track_idx even after the
     * tracker has been freed. */
    return tracker != NULL && track_idx != (size_t)-1 && track_idx < tracker->count;
}

void cytadel_plugin_fd_tracker_free(cytadel_plugin_fd_tracker_t *tracker) {
    free(tracker->fds);
    tracker->fds = NULL;
    tracker->capacity = 0;
    tracker->freed = true;
    /* `count` is intentionally left untouched -- see this function's and
     * is_tracked()'s header comments (round-4 W-1 fix). */
}
