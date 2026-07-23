#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"
#include "debug_support.h"

/* Security-review round-4 suggestion 5 regression test -- see
 * debug_support.c's
 * cytadel_plugin_debug_check_loader_run_lookup_ignores_hostile_index() for
 * the full mechanism.
 *
 * test_plugin_r3c1_env_metatable_abort.c's own header comment already
 * documents the gap this test closes: that fixture-based test cannot
 * exercise loader.c's `cytadel_plugin_raw_getfield(L, env_idx, "run")`
 * call in a state where env_idx actually HAS a hostile __index metatable,
 * because sandbox.c's separate __metatable lock rejects the attack
 * fixture's own `setmetatable(_ENV, ...)` attempt before that point is
 * ever reached -- both call sites are only reachable through that same
 * attack, which the lock now blocks at the very first step regardless of
 * which phase is running. test_plugin_r3c1_raw_getfield.c instead proves
 * cytadel_plugin_raw_getfield() never invokes __index in ISOLATION, on an
 * ad hoc table with no relationship to the real registration pipeline.
 *
 * This test is the missing middle ground: it reimplements loader.c's own
 * registration pipeline far enough to reach the EXACT SAME raw_getfield
 * call loader.c's §4.1 step 5 check makes, then attaches a hostile
 * __index metatable directly onto env_idx via the raw C API (something no
 * plugin's own Lua code could ever do once the __metatable lock exists,
 * but which this white-box test harness can, exactly like
 * test_plugin_r3c1_raw_getfield.c's own harness does on its own ad hoc
 * table) immediately before making that lookup -- proving the raw_getfield
 * call site itself, not just the lock, is what keeps this specific lookup
 * safe even in that doubly-adversarial state. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

int main(void) {
    /* A valid register{} header with no run() function -- the absence of
     * run() is the correct, expected outcome for this fixture (see this
     * file's own header comment / registration_missing_run/missing_run.lua's
     * own comment); the check under test is purely about whether the
     * hostile __index metamethod fires during the lookup, not about
     * whether run() is found. */
    int result = cytadel_plugin_debug_check_loader_run_lookup_ignores_hostile_index(
        CYTADEL_TEST_FIXTURES_DIR "/registration_missing_run/missing_run.lua");
    CYTADEL_ASSERT_EQ(result, 1);
    CYTADEL_TEST_PASS();
}
