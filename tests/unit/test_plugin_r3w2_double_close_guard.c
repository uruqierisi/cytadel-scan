#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"

/* TEST-SUPPORT ONLY: the cytadel_plugin_debug_check_* declarations live in
 * this PRIVATE src/plugin header, not in the public plugin.h (round-4 W-3).
 * Reachable here via the target_include_directories() entry in this
 * directory's CMakeLists.txt. */
#include "debug_support.h"

/* Security-review round-3 finding W-2 (WARNING) supplementary regression
 * test -- see debug_support.c's cytadel_plugin_debug_check_double_close_
 * guard() for the full mechanism. Deterministic (no thread race needed):
 * proves cytadel_plugin_socket_close()'s tracked+closed guard
 * (security-review round-2 FIX 1) makes a second close on an
 * already-tracked-closed slot a genuine no-op.
 *
 * This intentionally does NOT prove FIX 1's invoke.c call-ordering
 * (cleanup sweep after lua_close(), not before) in isolation -- see
 * test_plugin_fix1_double_close_race.c's own updated header comment for
 * why: as long as this guard exists, it alone is already sufficient to
 * suppress the double-close SYMPTOM regardless of that ordering, so no
 * test that only watches for the symptom (probabilistic or deterministic)
 * can observe a difference between correct and reverted ordering while the
 * guard is present. Security-review round 4 resolved this properly rather
 * than accepting it as a permanent gap: tests/unit/test_plugin_r4w2_order_invariant.c
 * observes the ordering DIRECTLY via invoke.c's own
 * CYTADEL_BUILD_TESTING-only instrumentation hook
 * (cytadel_plugin_test_invoke_order_hook), which is not fooled by this
 * guard's suppression of the symptom -- reverting the ordering alone now
 * has a test that fails because of it. This test remains valuable as a
 * distinct, deterministic check of the guard's OWN correctness
 * (round-4 finding W-1 found and fixed a real regression in that
 * coverage -- see test_plugin_r4w1_guard_survives_free.c), a concern the
 * ordering test does not exercise. */
int main(void) {
    int result = cytadel_plugin_debug_check_double_close_guard();
    CYTADEL_ASSERT_EQ(result, 1);
    CYTADEL_TEST_PASS();
}
