#include "cytadel_test.h"

#include "cytadel/plugin/plugin.h"

/* Milestone 5 Part 2: registration phase (docs/contracts/plugin-api.md
 * §4.1) -- metadata capture/validation, "a broken plugin is skipped, never
 * aborts the scan," duplicate script_id rejection, missing run() rejection,
 * and dependency-graph validation (missing dependency / cycle are both
 * hard startup errors). Fixtures live under tests/plugins/fixtures/ (never
 * under the real plugins/ directory -- see CMakeLists.txt for how
 * CYTADEL_TEST_FIXTURES_DIR is threaded through as a compile definition
 * pointing at the source tree's tests/plugins/fixtures). */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

static void test_registration_ok(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/registration_ok", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);
    cytadel_plugin_registry_free(registry);
}

static void test_registration_bad_header_is_skipped_not_fatal(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/registration_bad_header",
                                           &registry);
    /* A malformed header must not abort the whole registry load -- it is
     * simply not counted (§4.1 step 7). */
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 0);
    cytadel_plugin_registry_free(registry);
}

static void test_registration_missing_run_is_skipped(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/registration_missing_run",
                                           &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 0);
    cytadel_plugin_registry_free(registry);
}

static void test_registration_duplicate_script_id_keeps_first_only(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/registration_dup_id", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    /* dup_a.lua and dup_b.lua both declare script_id 900004 -- filenames
     * sort dup_a.lua before dup_b.lua, so dup_a wins and dup_b is skipped
     * as a collision; either way exactly one survives. */
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);
    cytadel_plugin_registry_free(registry);
}

static void test_dependency_order_fixture_registers_both(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/dep_order", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 2);
    /* Actual topological ORDER is asserted via the scheduler's on_result
     * callback in test_plugin_scheduler.c (Part 4) -- registration alone
     * has no observable ordering surface yet. */
    cytadel_plugin_registry_free(registry);
}

static void test_dependency_cycle_is_hard_startup_error(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/dep_cycle", &registry);
    CYTADEL_ASSERT_EQ(rc, -1);
    CYTADEL_ASSERT(registry == NULL);
}

static void test_missing_dependency_is_hard_startup_error(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/dep_missing", &registry);
    CYTADEL_ASSERT_EQ(rc, -1);
    CYTADEL_ASSERT(registry == NULL);
}

static void test_nonexistent_plugins_dir_is_an_error(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/does_not_exist", &registry);
    CYTADEL_ASSERT_EQ(rc, -1);
    CYTADEL_ASSERT(registry == NULL);
}

int main(void) {
    test_registration_ok();
    test_registration_bad_header_is_skipped_not_fatal();
    test_registration_missing_run_is_skipped();
    test_registration_duplicate_script_id_keeps_first_only();
    test_dependency_order_fixture_registers_both();
    test_dependency_cycle_is_hard_startup_error();
    test_missing_dependency_is_hard_startup_error();
    test_nonexistent_plugins_dir_is_an_error();
    CYTADEL_TEST_PASS();
}
