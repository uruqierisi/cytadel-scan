#include "cytadel_test.h"

#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 security-audit finding W4 regression test: http_get()'s
 * request buffer (`req`) was malloc'd before opts.headers was validated,
 * so a wrong-typed header value's luaL_error() (raised while appending
 * headers) could longjmp past freeing it -- see bad_header_value.lua's
 * own comment and api_http.c's cytadel_http_validate_headers_table() (the
 * fix: validate the whole headers table before `req` is ever allocated).
 *
 * Same reasoning as test_plugin_w3_report_vuln_leak.c: this test asserts
 * observable plugin behavior only; the "no heap growth" proof is that
 * this binary, run under the build-asan configuration, exits with no
 * LeakSanitizer report across 2000 rejected calls. No fixture server is
 * needed -- with the fix, header validation happens before any network
 * connection is ever attempted. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

int main(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/http_headers_leak_loop", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));

    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);

    CYTADEL_ASSERT_EQ(findings.count, 1);
    CYTADEL_ASSERT_STREQ(findings.items[0].title, "http header leak loop check passed");

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
