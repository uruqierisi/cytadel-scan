#include "cytadel_test.h"

#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 security-audit finding W3 regression test: report_vuln{}'s
 * fields were allocated (strdup'd) before every optional field's type had
 * been validated, so a wrong-typed optional field could longjmp
 * (luaL_error) past freeing whatever was already allocated for earlier
 * fields in that call -- see bad_optional_field.lua's own comment and
 * api_report.c's cytadel_report_vuln_validate_fields() (the fix: validate
 * every field's type up front, before any allocation).
 *
 * This test itself only asserts observable plugin behavior (the loop of
 * rejected calls doesn't corrupt anything, and the API keeps working
 * normally afterward) -- the actual "no heap growth" proof is that this
 * whole test binary, run under the build-asan configuration
 * (-fsanitize=address,undefined, LeakSanitizer enabled by default on
 * Linux), exits cleanly with no leak report. 2000 iterations means even a
 * single leaked allocation per call would be an unmistakable, easily
 * triaged LeakSanitizer report, not a subtle one-time miss. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

int main(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/report_vuln_leak_loop", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));

    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    /* Every one of the 2000 wrong-typed calls was individually caught by
     * the fixture's own pcall() (so run() itself never errored), and the
     * one valid trailing call succeeded normally. */
    CYTADEL_ASSERT_EQ(findings.count, 1);
    CYTADEL_ASSERT_STREQ(findings.items[0].title, "report_vuln leak loop check passed");

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
