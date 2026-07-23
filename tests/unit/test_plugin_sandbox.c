#include "cytadel_test.h"

#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* TEST-SUPPORT ONLY: the cytadel_plugin_debug_check_* declarations live in
 * this PRIVATE src/plugin header, not in the public plugin.h (round-4 W-3).
 * Reachable here via the target_include_directories() entry in this
 * directory's CMakeLists.txt. */
#include "debug_support.h"

/* Milestone 5: sandbox enforcement (docs/contracts/plugin-api.md §5) and
 * _ENV isolation (§5.2) -- fixtures under tests/plugins/fixtures/
 * sandbox_escape/ and .../env_isolation/. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

typedef struct {
    int64_t script_id;
    cytadel_plugin_result_status_t status;
} cytadel_test_result_record_t;

typedef struct {
    cytadel_test_result_record_t records[16];
    size_t count;
} cytadel_test_result_log_t;

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    (void)bound_port;
    cytadel_test_result_log_t *log = user_data;
    CYTADEL_ASSERT(log->count < sizeof(log->records) / sizeof(log->records[0]));
    log->records[log->count].script_id = script_id;
    log->records[log->count].status = status;
    log->count++;
}

static cytadel_plugin_result_status_t cytadel_test_find_status(const cytadel_test_result_log_t *log,
                                                                 int64_t script_id) {
    for (size_t i = 0; i < log->count; i++) {
        if (log->records[i].script_id == script_id) {
            return log->records[i].status;
        }
    }
    CYTADEL_ASSERT(0 && "script_id not found in result log");
    return CYTADEL_PLUGIN_RESULT_FAILED;
}

static void test_sandbox_escape_fixtures(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/sandbox_escape", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 5);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_result_log_t log;
    memset(&log, 0, sizeof(log));

    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    CYTADEL_ASSERT_EQ(log.count, 5);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 950001), CYTADEL_PLUGIN_RESULT_OK);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 950002), CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 950003), CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 950004), CYTADEL_PLUGIN_RESULT_FAILED);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 950005), CYTADEL_PLUGIN_RESULT_FAILED);

    /* The engine survived every failed invocation (no crash, no hang --
     * reaching this line at all proves that) and the one passing check
     * reported exactly the one finding it was written to report. */
    CYTADEL_ASSERT_EQ(findings.count, 1);
    CYTADEL_ASSERT_STREQ(findings.items[0].title, "sandbox dangerous-surface check passed");

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
}

static void test_env_isolation(void) {
    int result = cytadel_plugin_debug_check_env_isolated(
        CYTADEL_TEST_FIXTURES_DIR "/env_isolation/leak.lua", "cytadel_test_leaked_global");
    CYTADEL_ASSERT_EQ(result, 1); /* isolated -- the real global table was NOT touched */
}

int main(void) {
    test_sandbox_escape_fixtures();
    test_env_isolation();
    CYTADEL_TEST_PASS();
}
