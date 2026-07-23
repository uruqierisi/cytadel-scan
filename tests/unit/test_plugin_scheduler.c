#include "cytadel_test.h"

#include <stdbool.h>
#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 5 Part 4: scheduler (docs/contracts/plugin-api.md §4.2/§4.6) --
 * required_keys gating (exact key), service-wildcard per-port dispatch,
 * dependency-order scheduling, and report_vuln{} schema validation. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

typedef struct {
    int64_t script_id;
    int bound_port;
    cytadel_plugin_result_status_t status;
} cytadel_test_record_t;

typedef struct {
    cytadel_test_record_t records[16];
    size_t count;
} cytadel_test_log_t;

static void cytadel_test_on_result(int64_t script_id, const char *script_name, int bound_port,
                                    cytadel_plugin_result_status_t status, void *user_data) {
    (void)script_name;
    cytadel_test_log_t *log = user_data;
    CYTADEL_ASSERT(log->count < sizeof(log->records) / sizeof(log->records[0]));
    log->records[log->count].script_id = script_id;
    log->records[log->count].bound_port = bound_port;
    log->records[log->count].status = status;
    log->count++;
}

static void test_required_keys_exact_gating(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/required_keys", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    /* First: KB lacks Services/ssh/22 -- must be SKIPPED. */
    cytadel_kb_t *kb1 = cytadel_kb_create();
    cytadel_finding_list_t findings1;
    memset(&findings1, 0, sizeof(findings1));
    cytadel_test_log_t log1;
    memset(&log1, 0, sizeof(log1));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb1, &findings1, cytadel_test_on_result,
                                     &log1);
    CYTADEL_ASSERT_EQ(log1.count, 1);
    CYTADEL_ASSERT_EQ(log1.records[0].status, CYTADEL_PLUGIN_RESULT_SKIPPED);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb1, "Test/required_keys/ran", &(cytadel_kb_value_t){0}),
                       CYTADEL_KB_GET_NOT_FOUND);
    cytadel_finding_list_free(&findings1);
    cytadel_kb_free(kb1);

    /* Second: KB has Services/ssh/22 -- must run. */
    cytadel_kb_t *kb2 = cytadel_kb_create();
    cytadel_kb_set_int(kb2, "Services/ssh/22", 22);
    cytadel_finding_list_t findings2;
    memset(&findings2, 0, sizeof(findings2));
    cytadel_test_log_t log2;
    memset(&log2, 0, sizeof(log2));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb2, &findings2, cytadel_test_on_result,
                                     &log2);
    CYTADEL_ASSERT_EQ(log2.count, 1);
    CYTADEL_ASSERT_EQ(log2.records[0].status, CYTADEL_PLUGIN_RESULT_OK);
    cytadel_kb_value_t ran;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb2, "Test/required_keys/ran", &ran), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(ran.type, CYTADEL_KB_TYPE_BOOL);
    CYTADEL_ASSERT(ran.v.b);
    cytadel_finding_list_free(&findings2);
    cytadel_kb_free(kb2);

    cytadel_plugin_registry_free(registry);
}

static void test_service_wildcard_dispatch(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc =
        cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/service_dispatch", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    /* No Services/www/ entries at all -- SKIPPED, no dispatch. */
    cytadel_kb_t *kb_empty = cytadel_kb_create();
    cytadel_finding_list_t findings_empty;
    memset(&findings_empty, 0, sizeof(findings_empty));
    cytadel_test_log_t log_empty;
    memset(&log_empty, 0, sizeof(log_empty));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb_empty, &findings_empty,
                                     cytadel_test_on_result, &log_empty);
    CYTADEL_ASSERT_EQ(log_empty.count, 1);
    CYTADEL_ASSERT_EQ(log_empty.records[0].status, CYTADEL_PLUGIN_RESULT_SKIPPED);
    CYTADEL_ASSERT_EQ(log_empty.records[0].bound_port, -1);
    cytadel_finding_list_free(&findings_empty);
    cytadel_kb_free(kb_empty);

    /* Two matching ports -- one dispatch per port, correct bound port each
     * time (§2.2a). */
    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_kb_set_int(kb, "Services/www/80", 80);
    cytadel_kb_set_int(kb, "Services/www/8080", 8080);
    /* A different service token must NOT be dispatched to this plugin. */
    cytadel_kb_set_int(kb, "Services/ssh/22", 22);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_log_t log;
    memset(&log, 0, sizeof(log));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    CYTADEL_ASSERT_EQ(log.count, 2);
    bool saw_80 = false, saw_8080 = false;
    for (size_t i = 0; i < log.count; i++) {
        CYTADEL_ASSERT_EQ(log.records[i].status, CYTADEL_PLUGIN_RESULT_OK);
        if (log.records[i].bound_port == 80) {
            saw_80 = true;
        }
        if (log.records[i].bound_port == 8080) {
            saw_8080 = true;
        }
    }
    CYTADEL_ASSERT(saw_80);
    CYTADEL_ASSERT(saw_8080);

    cytadel_kb_value_t v80, v8080;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/service_dispatch/port/80", &v80),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(v80.v.i64, 80);
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/service_dispatch/port/8080", &v8080),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(v8080.v.i64, 8080);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
}

static void test_dependency_order(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/dep_order", &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 2);

    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_log_t log;
    memset(&log, 0, sizeof(log));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    CYTADEL_ASSERT_EQ(log.count, 2);
    /* 920001 (a_settings, no deps) must be attempted before 920002
     * (b_gather, depends on 920001) -- the scheduler walks the registry's
     * fixed topological order (§4.1). */
    CYTADEL_ASSERT_EQ(log.records[0].script_id, 920001);
    CYTADEL_ASSERT_EQ(log.records[1].script_id, 920002);
    CYTADEL_ASSERT_EQ(log.records[0].status, CYTADEL_PLUGIN_RESULT_OK);
    CYTADEL_ASSERT_EQ(log.records[1].status, CYTADEL_PLUGIN_RESULT_OK);

    cytadel_kb_value_t saw;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, "Test/dep_order/gather_saw_settings", &saw),
                       CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT(saw.v.b);

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
}

static void test_report_vuln_validation(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/report_vuln_validation",
                                           &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 3);

    cytadel_kb_t *kb = cytadel_kb_create();
    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_log_t log;
    memset(&log, 0, sizeof(log));
    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    CYTADEL_ASSERT_EQ(log.count, 3);
    for (size_t i = 0; i < log.count; i++) {
        if (log.records[i].script_id == 995001 || log.records[i].script_id == 995002) {
            CYTADEL_ASSERT_EQ(log.records[i].status, CYTADEL_PLUGIN_RESULT_FAILED);
        } else if (log.records[i].script_id == 995003) {
            CYTADEL_ASSERT_EQ(log.records[i].status, CYTADEL_PLUGIN_RESULT_OK);
        } else {
            CYTADEL_ASSERT(0 && "unexpected script_id");
        }
    }

    /* Only the valid plugin's two report_vuln()/security_report() calls
     * produced findings -- the two invalid calls raised before ever
     * reaching cytadel_finding_list_append(). */
    CYTADEL_ASSERT_EQ(findings.count, 2);

    const cytadel_finding_t *primary = NULL;
    const cytadel_finding_t *alias = NULL;
    for (size_t i = 0; i < findings.count; i++) {
        if (strcmp(findings.items[i].title, "Fixture Valid Finding") == 0) {
            primary = &findings.items[i];
        } else if (strcmp(findings.items[i].title, "Fixture Valid Finding via alias") == 0) {
            alias = &findings.items[i];
        }
    }
    CYTADEL_ASSERT(primary != NULL);
    CYTADEL_ASSERT(alias != NULL);

    CYTADEL_ASSERT_EQ(primary->severity, 3);
    CYTADEL_ASSERT_EQ(primary->port, 4321);
    CYTADEL_ASSERT_STREQ(primary->solution, "Override solution for this specific finding.");
    CYTADEL_ASSERT_EQ(primary->cve_count, 2);
    CYTADEL_ASSERT_STREQ(primary->cve[0], "CVE-2024-0001");
    CYTADEL_ASSERT_STREQ(primary->cve[1], "CVE-2024-0002");
    CYTADEL_ASSERT_STREQ(primary->cpe, "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*");
    CYTADEL_ASSERT_STREQ(primary->cvss_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
    CYTADEL_ASSERT_EQ(primary->script_id, 995003);

    /* security_report{} (the alias) omitted solution/cvss_vector -- both
     * must fall back to the plugin header's own defaults. */
    CYTADEL_ASSERT_EQ(alias->severity, 0);
    CYTADEL_ASSERT_EQ(alias->port, 0);
    CYTADEL_ASSERT_STREQ(alias->solution, "N/A -- test fixture.");
    CYTADEL_ASSERT_STREQ(alias->cvss_vector, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
}

int main(void) {
    test_required_keys_exact_gating();
    test_service_wildcard_dispatch();
    test_dependency_order();
    test_report_vuln_validation();
    CYTADEL_TEST_PASS();
}
