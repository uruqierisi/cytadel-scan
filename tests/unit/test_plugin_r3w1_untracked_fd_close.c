#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"

/* TEST-SUPPORT ONLY: the cytadel_plugin_debug_check_* declarations live in
 * this PRIVATE src/plugin header, not in the public plugin.h (round-4 W-3).
 * Reachable here via the target_include_directories() entry in this
 * directory's CMakeLists.txt. */
#include "debug_support.h"

/* Security-review round-3 finding W-1 (WARNING) regression test -- see
 * debug_support.c's cytadel_plugin_debug_check_untracked_socket_closes()
 * for the full mechanism. Deterministic: constructs a socket userdata
 * whose track_idx == (size_t)-1 (exactly the state open_sock_tcp() leaves
 * a socket in when cytadel_plugin_fd_tracker_add()'s own realloc() fails
 * under OOM) and proves cytadel_plugin_socket_close() still closes the
 * real fd, rather than treating "untracked" the same as "already closed"
 * (the old bug -- see fd_tracker.h's own updated comment on
 * cytadel_plugin_fd_tracker_is_closed() for why those two states must
 * never be collapsed into one boolean). */
int main(void) {
    int result = cytadel_plugin_debug_check_untracked_socket_closes();
    CYTADEL_ASSERT_EQ(result, 1);
    CYTADEL_TEST_PASS();
}
