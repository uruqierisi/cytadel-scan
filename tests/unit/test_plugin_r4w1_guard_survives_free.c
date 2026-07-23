#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"
#include "debug_support.h"

/* Security-review round-4 finding W-1 regression test -- see
 * debug_support.c's cytadel_plugin_debug_check_double_close_guard_survives_free()
 * for the full mechanism.
 *
 * Round 3 fixed api_socket.c's cytadel_plugin_socket_close() to distinguish
 * "untracked" (fd_tracker_add()'s own OOM -- must still close()) from
 * "tracked and already closed" (must NOT close() again) via a new
 * cytadel_plugin_fd_tracker_is_tracked() check performed BEFORE trusting
 * cytadel_plugin_fd_tracker_is_closed(). That fix's own
 * cytadel_plugin_fd_tracker_free() implementation, though, reset the
 * tracker's `count` back to 0 -- which made is_tracked() return false for
 * EVERY previously-tracked index once the tracker was freed, not just
 * genuinely-never-tracked ones. invoke.c's cytadel_plugin_invoke_cleanup()
 * always calls force_close_all() THEN fd_tracker_free() on that same
 * ctx.open_fds, and lua_close(L) (immediately before cleanup, per FIX 1's
 * ordering) can still run __gc/__close on socket userdata pointing into
 * it. If FIX 1's lua_close()-before-cleanup ordering were ever reverted
 * (cleanup running first), a socket's __gc/__close would then call
 * cytadel_plugin_socket_close() with a track_idx into an ALREADY-FREED
 * tracker -- round 3's guard misread that as "untracked" and fell through
 * to a real close() on a live fd, reintroducing round 2 FIX 1's
 * double-close hazard even with the "fixed" guard in place. This is
 * deterministic: no thread race, no network I/O, no real fd-number reuse
 * needed (the test constructs the exact post-free tracker state directly
 * via the tracker's own real API). */
int main(void) {
    int result = cytadel_plugin_debug_check_double_close_guard_survives_free();
    CYTADEL_ASSERT_EQ(result, 1);
    CYTADEL_TEST_PASS();
}
