#include "cytadel_test.h"

#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 §4.5: an infinite-loop plugin must be killed by the
 * instruction-count debug hook + wall-clock deadline and marked FAILED,
 * without hanging the test suite. The runtime limit itself (15000 ms) is
 * a frozen contract default, not configurable by this test -- this test
 * is therefore inherently slow (~15s) by design, kept in its own file so
 * it is easy to identify/exclude from a fast local loop if ever needed. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    (void)bound_port;
    CYTADEL_ASSERT_EQ(script_id, 990001);
    *(cytadel_plugin_result_status_t *)user_data = status;
}

int main(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/runtime_limit", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));

    cytadel_plugin_result_status_t status = CYTADEL_PLUGIN_RESULT_SKIPPED;
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &status);

    CYTADEL_ASSERT_EQ(status, CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT_EQ(findings.count, 0);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
