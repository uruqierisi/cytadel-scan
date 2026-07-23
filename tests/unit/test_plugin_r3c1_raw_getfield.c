#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"

/* TEST-SUPPORT ONLY: the cytadel_plugin_debug_check_* declarations live in
 * this PRIVATE src/plugin header, not in the public plugin.h (round-4 W-3).
 * Reachable here via the target_include_directories() entry in this
 * directory's CMakeLists.txt. */
#include "debug_support.h"

/* Security-review round-3 finding C-1 (CRITICAL) supplementary regression
 * test -- see debug_support.c's cytadel_plugin_debug_check_raw_getfield_
 * bypasses_index() for the full mechanism. Deterministic (no lua_State
 * sandboxing/pcall needed, no thread race): constructs a table with a
 * hostile __index metamethod directly via the raw Lua C API and proves
 * cytadel_plugin_raw_getfield() (field_utils.c -- the exact function now
 * used at both src/plugin/loader.c:63 and src/plugin/invoke.c:157, the two
 * call sites this round's audit found unprotected) never invokes it, while
 * an ordinary lua_getfield() on the same table would.
 *
 * This is independent of sandbox.c's separate __metatable lock on _ENV (see
 * test_plugin_r3c1_env_metatable_abort.c for that fixture-based, phase-
 * entangled proof) -- this test isolates raw_getfield's own bypass property
 * regardless of whether that lock exists at all. */
int main(void) {
    int result = cytadel_plugin_debug_check_raw_getfield_bypasses_index();
    CYTADEL_ASSERT_EQ(result, 1);
    CYTADEL_TEST_PASS();
}
