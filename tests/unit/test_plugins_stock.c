#include "cytadel_test.h"

#include <stdbool.h>
#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/net/host_scan.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/net/target.h"
#include "cytadel/plugin/plugin.h"

/* Milestone 6: fixture-driven tests for the real, shipped stock plugins in
 * plugins/ (docs/contracts/plugin-api.md / kb-schema.md, both FROZEN). This
 * is the one exception in this codebase to "tests never load the real
 * plugins/ directory" (that convention -- see test_plugin_registry.c's own
 * header comment -- exists for tests of the ENGINE's scheduling mechanics,
 * which use small synthetic fixtures under tests/plugins/fixtures/ so they
 * never depend on this milestone's stock-plugin content). These tests are
 * the opposite: they exist specifically to verify the stock plugins'
 * *content* is correct, so they load plugins/ itself.
 *
 * The registry is loaded ONCE in main() and reused read-only across every
 * test below; each test builds its own fresh KB + findings list. Every
 * scenario here is driven purely by KB fixtures -- no live network I/O
 * (plugins/README.md's "Adding a new plugin" step 7). Plugins gated on
 * the "Services/www" wildcard (e.g. http_missing_csp.lua) necessarily also dispatch
 * this directory's http_headers.lua (the ACT_SETTINGS gathering plugin,
 * also gated on that same wildcard) in the same run -- that plugin attempts
 * a real loopback connect to whatever port the test KB names, which is
 * never actually listening in these tests, so it fails fast with
 * ECONNREFUSED (ECONNREFUSED is returned immediately by the kernel for a
 * loopback port with no listener -- no timeout wait) and no-ops. That is a
 * side effect of the shared "Services/www" wildcard gate, not something this file
 * relies on for correctness; http_headers.lua's own gathering behavior is
 * separately verified against a real fixture server in
 * test_plugins_stock_network.c. */

#ifndef CYTADEL_PLUGINS_DIR
#define CYTADEL_PLUGINS_DIR "plugins"
#endif

typedef struct {
    int64_t script_id;
    int bound_port;
    cytadel_plugin_result_status_t status;
} cytadel_test_record_t;

typedef struct {
    cytadel_test_record_t records[64];
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

/* Finds the (first) recorded status for `script_id`. If `bound_port >= 0`,
 * also requires the record's bound_port to match (used to disambiguate a
 * service-wildcard plugin dispatched against several ports in the same
 * test). Fails the test outright if no matching record was logged at all
 * (a plugin that isn't even attempted is itself a bug in either the
 * fixture or the plugin's required_keys). */
static cytadel_plugin_result_status_t cytadel_test_status_for(const cytadel_test_log_t *log,
                                                                int64_t script_id,
                                                                int bound_port) {
    for (size_t i = 0; i < log->count; i++) {
        if (log->records[i].script_id == script_id &&
            (bound_port < 0 || log->records[i].bound_port == bound_port)) {
            return log->records[i].status;
        }
    }
    fprintf(stderr, "cytadel_test_status_for: script_id %lld (bound_port %d) never recorded\n",
            (long long)script_id, bound_port);
    exit(1);
}

/* Number of findings in `list` produced by `script_id`. */
static size_t cytadel_test_count_findings(const cytadel_finding_list_t *list, int64_t script_id) {
    size_t n = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].script_id == script_id) {
            n++;
        }
    }
    return n;
}

/* Returns the sole finding produced by `script_id` -- fails the test if
 * there is not EXACTLY one. */
static const cytadel_finding_t *cytadel_test_one_finding(const cytadel_finding_list_t *list,
                                                           int64_t script_id) {
    const cytadel_finding_t *found = NULL;
    size_t n = 0;
    for (size_t i = 0; i < list->count; i++) {
        if (list->items[i].script_id == script_id) {
            found = &list->items[i];
            n++;
        }
    }
    CYTADEL_ASSERT_EQ(n, 1);
    return found;
}

/* --------------------------------------------------------------------- *
 * FTP
 * --------------------------------------------------------------------- */

static void test_ftp_anonymous_banner_hint(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100001;

    /* Positive: banner mentions "anonymous". */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ftp/21", 21);
        cytadel_kb_set_str(kb, "FTP/21/banner", "220 Anonymous FTP access enabled");
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 0);
        CYTADEL_ASSERT_STREQ(f->evidence, "220 Anonymous FTP access enabled");
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: ordinary banner, no mention. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ftp/21", 21);
        cytadel_kb_set_str(kb, "FTP/21/banner", "220 (vsFTPd 3.0.5)");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: no banner at all -- must not crash, no finding.
     * Also: required_keys unsatisfied entirely -- SKIPPED, no lua_State. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ftp/21", 21);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_SKIPPED);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_ftp_cleartext_protocol(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100002;

    /* Positive: service present (with banner) -- always fires. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ftp/21", 21);
        cytadel_kb_set_str(kb, "FTP/21/banner", "220 (ProFTPD 1.3.5)");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 1);
        CYTADEL_ASSERT(strstr(f->evidence, "ProFTPD") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: service present but NO banner -- must not crash,
     * must still fire with a generic evidence string. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ftp/21", 21);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT(strstr(f->evidence, "port 21") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no FTP service at all -- SKIPPED. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_SKIPPED);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

/* --------------------------------------------------------------------- *
 * SSH
 * --------------------------------------------------------------------- */

static void test_ssh_sshv1_supported(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100010;

    /* Positive: "1.99" (dual-protocol backward compat). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/protocol", "1.99");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 3);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive: bare "1.5". */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/protocol", "1.5");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: "2.0". */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/protocol", "2.0");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: empty string, and garbage that isn't a version at
     * all -- must not crash. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/protocol", "");
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        /* SSH/22/protocol deliberately absent -- only Services/ssh/22 set. */
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_ssh_known_vulnerable_openssh(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100011;

    /* Positive band A: very old (< 6.6). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-OpenSSH_6.0");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive band B: regreSSHion range (8.5-9.7). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-OpenSSH_9.6");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        CYTADEL_ASSERT_EQ(f->cve_count, 1);
        CYTADEL_ASSERT_STREQ(f->cve[0], "CVE-2024-6387");
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: safe zone between the two bands (>= 6.6, < 8.5). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-OpenSSH_7.4");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: just above band B. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-OpenSSH_9.8");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: version string that isn't OpenSSH at all. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-Custom_1.0");
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_ssh_version_disclosure(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100012;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_kb_set_str(kb, "SSH/22/version", "SSH-2.0-OpenSSH_9.6");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 0);
        CYTADEL_ASSERT_STREQ(f->evidence, "SSH-2.0-OpenSSH_9.6");
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: service present, no version captured. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/ssh/22", 22);
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

/* --------------------------------------------------------------------- *
 * TLS (all dispatched via Services/https/443)
 * --------------------------------------------------------------------- */

static void test_tls_cert_expired(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100020;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/cert_expired", true);
        cytadel_kb_set_str(kb, "TLS/443/not_after", "2020-01-01T00:00:00Z");
        cytadel_kb_set_str(kb, "TLS/443/cn", "expired.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 3);
        CYTADEL_ASSERT(strstr(f->evidence, "2020-01-01T00:00:00Z") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: not expired. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/cert_expired", false);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: handshake fact missing entirely (cert_expired
     * absent) -- must not crash, no finding. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: Services/https present but TLS never actually
     * completed (TLS/443/enabled absent) -- must not crash, no finding,
     * even though cert_expired is (nonsensically) set true. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/cert_expired", true);
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, 443), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_cert_not_yet_valid(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100021;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/cert_not_yet_valid", true);
        cytadel_kb_set_str(kb, "TLS/443/not_before", "2099-01-01T00:00:00Z");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/cert_not_yet_valid", false);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_cert_self_signed(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100022;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/self_signed", true);
        cytadel_kb_set_str(kb, "TLS/443/cn", "self-signed.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_bool(kb, "TLS/443/self_signed", false);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_cert_hostname_mismatch(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100023;

    /* Positive: no match at all. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "Host/hostname", "www.example.com");
        cytadel_kb_set_str(kb, "TLS/443/cn", "other.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: exact CN match. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "Host/hostname", "www.example.com");
        cytadel_kb_set_str(kb, "TLS/443/cn", "www.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: leading-wildcard CN match. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "Host/hostname", "www.example.com");
        cytadel_kb_set_str(kb, "TLS/443/cn", "*.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: match via SAN, not CN. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "Host/hostname", "www.example.com");
        cytadel_kb_set_str(kb, "TLS/443/cn", "other.example.com");
        cytadel_kb_set_str(kb, "TLS/443/san", "www.example.com,other2.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: no Host/hostname at all -- must not crash/guess. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/cn", "other.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: hostname present but neither cn nor san recorded. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "Host/hostname", "www.example.com");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

/* --------------------------------------------------------------------- *
 * M9 Gap #2 regression gate: 100023 end-to-end through the REAL engine.
 *
 * The KB-fixture cases just above (test_tls_cert_hostname_mismatch) prove
 * the plugin's own matching logic is correct once Host/hostname exists --
 * but they hand-poke Host/hostname straight into a synthetic KB with
 * cytadel_kb_set_str(), which was always possible and proves nothing about
 * whether the ENGINE actually produces that fact during a real scan. For a
 * long stretch it did not: src/net/host_scan.c never wrote Host/hostname
 * at all, so in a real scan this plugin's "if not hostname then ... return
 * end" (its required fact) was NEVER satisfied, no matter how mismatched a
 * certificate was -- a structurally dead plugin hiding behind a fully
 * green fixture suite.
 *
 * This test closes that gap: it drives the REAL cytadel_host_scan() (no
 * network I/O -- an empty port list plus --skip-discovery, exactly like
 * test_host_scan.c's own pattern) to get a Host/hostname fact that the
 * ENGINE, not the test, produced, then hands that same KB to the plugin
 * scheduler. This is the positive case that was IMPOSSIBLE before the
 * host_scan.c fix: no call to cytadel_host_scan() could ever have put
 * Host/hostname in the KB, so this exact test would have failed both the
 * direct KB assertion below AND the finding-count assertion. (Verified by
 * hand: reverting host_scan.c's Host/hostname write and rebuilding makes
 * the `hostname != NULL` assertion below fail immediately, before the
 * plugin is even dispatched -- see the task's regression-gate report for
 * the exact failure output.) */
static void test_tls_cert_hostname_mismatch_engine_integration(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100023;

    /* Positive: engine-produced Host/hostname (from a hostname target spec)
     * feeds a mismatched certificate -- must fire exactly once. */
    {
        cytadel_target_t target;
        memset(&target, 0, sizeof(target));
        snprintf(target.host, sizeof(target.host), "www.example.com");
        snprintf(target.ip, sizeof(target.ip), "203.0.113.20"); /* TEST-NET-3, unroutable */

        cytadel_port_list_t ports;
        ports.ports = NULL;
        ports.count = 0; /* no network I/O: cytadel_port_scan() no-ops on an empty list */

        cytadel_host_scan_opts_t opts = {0};
        opts.discovery_timeout_ms = 1000;
        opts.connect_timeout_ms = 1000;
        opts.skip_discovery = true; /* deterministic: no ICMP/TCP-ping */
        opts.plugin_registry = NULL; /* dispatched explicitly below, after
                                         injecting the TLS facts a real
                                         handshake would have produced --
                                         this unit test performs no TLS I/O */

        cytadel_host_result_t result;
        memset(&result, 0, sizeof(result));
        int rc = cytadel_host_scan(&target, &ports, &opts, &result);
        CYTADEL_ASSERT_EQ(rc, 0);
        CYTADEL_ASSERT(result.kb != NULL);

        /* The engine fix itself, asserted directly: before it landed, this
         * key was never written by cytadel_host_scan() under any
         * circumstance, so this line alone is the regression trip-wire. */
        const char *hostname = cytadel_kb_get_str(result.kb, "Host/hostname");
        CYTADEL_ASSERT(hostname != NULL);
        CYTADEL_ASSERT_STREQ(hostname, "www.example.com");

        /* Inject the TLS facts a real handshake/cert-inspection would have
         * recorded (kb-schema.md §7.5) -- a non-covering cert. */
        cytadel_kb_set_int(result.kb, "Services/https/443", 443);
        cytadel_kb_set_bool(result.kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(result.kb, "TLS/443/cn", "other.invalid");
        cytadel_kb_set_str(result.kb, "TLS/443/san", "x.invalid,y.invalid");

        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, target.ip, result.kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);

        cytadel_finding_list_free(&findings);
        cytadel_host_result_free(&result);
    }

    /* Negative (no false positive): same engine-produced Host/hostname, but
     * the certificate's CN legitimately covers it -- must NOT fire. */
    {
        cytadel_target_t target;
        memset(&target, 0, sizeof(target));
        snprintf(target.host, sizeof(target.host), "www.example.com");
        snprintf(target.ip, sizeof(target.ip), "203.0.113.21");

        cytadel_port_list_t ports;
        ports.ports = NULL;
        ports.count = 0;

        cytadel_host_scan_opts_t opts = {0};
        opts.discovery_timeout_ms = 1000;
        opts.connect_timeout_ms = 1000;
        opts.skip_discovery = true;
        opts.plugin_registry = NULL;

        cytadel_host_result_t result;
        memset(&result, 0, sizeof(result));
        int rc = cytadel_host_scan(&target, &ports, &opts, &result);
        CYTADEL_ASSERT_EQ(rc, 0);

        const char *hostname = cytadel_kb_get_str(result.kb, "Host/hostname");
        CYTADEL_ASSERT(hostname != NULL);
        CYTADEL_ASSERT_STREQ(hostname, "www.example.com");

        cytadel_kb_set_int(result.kb, "Services/https/443", 443);
        cytadel_kb_set_bool(result.kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(result.kb, "TLS/443/cn", "www.example.com");

        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, target.ip, result.kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);

        cytadel_finding_list_free(&findings);
        cytadel_host_result_free(&result);
    }

    /* Revert-proof of the dead state itself: an IPv4-literal target must
     * NOT get Host/hostname (there's nothing to hostname-mismatch against
     * a bare IP) -- this is the exact pre-fix condition the plugin's own
     * "no Host/hostname recorded" early return exists for, reproduced here
     * via the real engine rather than a hand-built fixture. Zero findings,
     * even with a wildly mismatched cert. */
    {
        cytadel_target_t target;
        memset(&target, 0, sizeof(target));
        snprintf(target.host, sizeof(target.host), "203.0.113.22");
        snprintf(target.ip, sizeof(target.ip), "203.0.113.22");

        cytadel_port_list_t ports;
        ports.ports = NULL;
        ports.count = 0;

        cytadel_host_scan_opts_t opts = {0};
        opts.discovery_timeout_ms = 1000;
        opts.connect_timeout_ms = 1000;
        opts.skip_discovery = true;
        opts.plugin_registry = NULL;

        cytadel_host_result_t result;
        memset(&result, 0, sizeof(result));
        int rc = cytadel_host_scan(&target, &ports, &opts, &result);
        CYTADEL_ASSERT_EQ(rc, 0);
        CYTADEL_ASSERT(cytadel_kb_get_str(result.kb, "Host/hostname") == NULL);

        cytadel_kb_set_int(result.kb, "Services/https/443", 443);
        cytadel_kb_set_bool(result.kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(result.kb, "TLS/443/cn", "totally.unrelated.invalid");

        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, target.ip, result.kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);

        cytadel_finding_list_free(&findings);
        cytadel_host_result_free(&result);
    }
}

static void test_tls_weak_sig_alg(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100024;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "md5WithRSAEncryption");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 3);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "sha1WithRSAEncryption");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "sha256WithRSAEncryption");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: empty string value, and no sig_alg at all. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_weak_key_size(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100025;

    /* Positive: weak RSA. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_int(kb, "TLS/443/key_bits", 1024);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "sha256WithRSAEncryption");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: strong RSA. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_int(kb, "TLS/443/key_bits", 2048);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "sha256WithRSAEncryption");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: EC key, small bit count but strong for its family --
     * proves the RSA threshold is not misapplied to EC keys. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_int(kb, "TLS/443/key_bits", 256);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "ecdsa-with-SHA256");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive: weak EC (below the ~224-bit curve-order floor). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_int(kb, "TLS/443/key_bits", 192);
        cytadel_kb_set_str(kb, "TLS/443/sig_alg", "ecdsa-with-SHA256");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: key_bits present but no sig_alg to infer the
     * algorithm family from -- must skip, not guess/crash. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_int(kb, "TLS/443/key_bits", 512);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_deprecated_protocol(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100026;

    static const struct {
        const char *version;
        int expect_finding;
        int severity;
    } cases[] = {
        {"SSLv3", 1, 3},   {"TLSv1", 1, 2},   {"TLSv1.1", 1, 2},
        {"TLSv1.2", 0, 0}, {"TLSv1.3", 0, 0}, {"DTLSv1.2", 0, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/version", cases[i].version);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        if (cases[i].expect_finding) {
            const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
            CYTADEL_ASSERT_EQ(f->severity, cases[i].severity);
        } else {
            CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        }
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_tls_weak_cipher(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100027;

    static const struct {
        const char *cipher;
        int expect_finding;
        int severity;
    } cases[] = {
        {"TLS_RSA_WITH_NULL_SHA", 1, 3},
        {"ECDHE-RSA-RC4-SHA", 1, 2},
        {"DES-CBC3-SHA", 1, 2},
        {"ECDHE-RSA-AES256-GCM-SHA384", 0, 0},
        {"", 0, 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/https/443", 443);
        cytadel_kb_set_bool(kb, "TLS/443/enabled", true);
        cytadel_kb_set_str(kb, "TLS/443/cipher", cases[i].cipher);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        if (cases[i].expect_finding) {
            const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
            CYTADEL_ASSERT_EQ(f->severity, cases[i].severity);
        } else {
            CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        }
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

/* --------------------------------------------------------------------- *
 * HTTP Headers (all dispatched via Services/www/<port> or
 * Services/https/<port>; ports are deliberately distinct, unused loopback
 * ports so http_headers.lua's incidental ECONNREFUSED probe never collides
 * across tests run in sequence).
 * --------------------------------------------------------------------- */

static void test_http_missing_hsts(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100031;
    const int port = 18443;
    char key[64];
    snprintf(key, sizeof(key), "Services/https/%d", port);

    /* Positive: TLS on, no HSTS header captured. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char tls_key[32];
        snprintf(tls_key, sizeof(tls_key), "TLS/%d/enabled", port);
        cytadel_kb_set_bool(kb, tls_key, true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: HSTS header present. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char tls_key[32], hdr_key[64];
        snprintf(tls_key, sizeof(tls_key), "TLS/%d/enabled", port);
        cytadel_kb_set_bool(kb, tls_key, true);
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/strict-transport-security", port);
        cytadel_kb_set_str(kb, hdr_key, "max-age=63072000; includeSubDomains");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: header present but EMPTY -- presence, not
     * content, is the signal (plugin-api.md kb-schema §7.6). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char tls_key[32], hdr_key[64];
        snprintf(tls_key, sizeof(tls_key), "TLS/%d/enabled", port);
        cytadel_kb_set_bool(kb, tls_key, true);
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/strict-transport-security", port);
        cytadel_kb_set_str(kb, hdr_key, "");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: not even TLS-confirmed -- must not fire. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_missing_csp(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100032;
    const int port = 18081;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/content-security-policy", port);
        cytadel_kb_set_str(kb, hdr_key, "default-src 'self'");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: present but empty -- still "present". */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/content-security-policy", port);
        cytadel_kb_set_str(kb, hdr_key, "");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_missing_xcto(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100033;
    const int port = 18082;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    /* Positive: absent entirely. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: exact conforming value. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/x-content-type-options", port);
        cytadel_kb_set_str(kb, hdr_key, "nosniff");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: case-insensitive match. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/x-content-type-options", port);
        cytadel_kb_set_str(kb, hdr_key, "NoSniff");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: present but wrong/empty value -- must still fire,
     * with evidence reflecting the observed (not expected) value. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/x-content-type-options", port);
        cytadel_kb_set_str(kb, hdr_key, "");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT(strstr(f->evidence, "expected 'nosniff'") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_missing_xfo(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100034;
    const int port = 18083;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    /* Positive: neither XFO nor CSP present. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: XFO present. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/x-frame-options", port);
        cytadel_kb_set_str(kb, hdr_key, "DENY");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no XFO, but CSP has frame-ancestors (case-insensitive). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/content-security-policy", port);
        cytadel_kb_set_str(kb, hdr_key, "default-src 'self'; Frame-Ancestors 'self'");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: CSP present but WITHOUT frame-ancestors -- must
     * still fire (CSP alone is not a substitute unless it has the
     * directive). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char probed_key[64];
        snprintf(probed_key, sizeof(probed_key), "HTTP/%d/headers/_probed", port);
        cytadel_kb_set_bool(kb, probed_key, true);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/content-security-policy", port);
        cytadel_kb_set_str(kb, hdr_key, "default-src 'self'");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT(strstr(f->evidence, "default-src") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_insecure_cookie_flags(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100035;
    const int port = 18084;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    /* Positive: over TLS, both flags missing. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char tls_key[32], hdr_key[64];
        snprintf(tls_key, sizeof(tls_key), "TLS/%d/enabled", port);
        cytadel_kb_set_bool(kb, tls_key, true);
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/set-cookie", port);
        cytadel_kb_set_str(kb, hdr_key, "sessionid=abc123; Path=/");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive: not over TLS, only HttpOnly missing (Secure is moot). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char hdr_key[64];
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/set-cookie", port);
        cytadel_kb_set_str(kb, hdr_key, "id=1");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: both flags present, case-insensitively. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char tls_key[32], hdr_key[64];
        snprintf(tls_key, sizeof(tls_key), "TLS/%d/enabled", port);
        cytadel_kb_set_bool(kb, tls_key, true);
        snprintf(hdr_key, sizeof(hdr_key), "HTTP/%d/headers/set-cookie", port);
        cytadel_kb_set_str(kb, hdr_key, "id=1; SECURE; HTTPONLY");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: no Set-Cookie header at all -- must not crash. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_server_version_disclosure(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100036;
    const int port = 18085;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char server_key[32], cpe_key[24];
        snprintf(server_key, sizeof(server_key), "HTTP/%d/server", port);
        cytadel_kb_set_str(kb, server_key, "nginx/1.24.0");
        snprintf(cpe_key, sizeof(cpe_key), "CPE/%d", port);
        cytadel_kb_set_str(kb, cpe_key, "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 0);
        CYTADEL_ASSERT_STREQ(f->evidence, "Server: nginx/1.24.0");
        CYTADEL_ASSERT_STREQ(f->cpe, "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*");
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no version digit at all. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char server_key[32];
        snprintf(server_key, sizeof(server_key), "HTTP/%d/server", port);
        cytadel_kb_set_str(kb, server_key, "cloudflare");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no Server header captured at all. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_directory_listing(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100037;
    const int port = 18086;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char title_key[32];
        snprintf(title_key, sizeof(title_key), "HTTP/%d/title", port);
        cytadel_kb_set_str(kb, title_key, "Index of /");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive: case-insensitive, subdirectory. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char title_key[32];
        snprintf(title_key, sizeof(title_key), "HTTP/%d/title", port);
        cytadel_kb_set_str(kb, title_key, "INDEX OF /uploads/");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: ordinary page title. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char title_key[32];
        snprintf(title_key, sizeof(title_key), "HTTP/%d/title", port);
        cytadel_kb_set_str(kb, title_key, "Welcome to nginx!");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: title present but empty; and title absent. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char title_key[32];
        snprintf(title_key, sizeof(title_key), "HTTP/%d/title", port);
        cytadel_kb_set_str(kb, title_key, "");
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_http_known_vulnerable_server(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100038;
    const int port = 18087;
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%d", port);

    static const struct {
        const char *server;
        int expect_finding;
    } cases[] = {
        {"Apache/2.2.15 (CentOS)", 1},   {"nginx/1.14.0", 1},
        {"Microsoft-IIS/6.0", 1},        {"Apache/2.4.51", 0},
        {"nginx/1.24.0", 0},             {"Microsoft-IIS/10.0", 0},
        {"lighttpd", 0},                 {"Custom-Server/abc", 0},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, key, port);
        char server_key[32];
        snprintf(server_key, sizeof(server_key), "HTTP/%d/server", port);
        cytadel_kb_set_str(kb, server_key, cases[i].server);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id),
                           cases[i].expect_finding ? 1 : 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

/* --------------------------------------------------------------------- *
 * General
 * --------------------------------------------------------------------- */

static void test_telnet_cleartext_protocol(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100040;

    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/telnet/23", 23);
        /* Valid UTF-8 (control bytes < 0x80 are legal single-byte code
         * points) but still representative of the odd, mostly-non-printable
         * text a raw telnet IAC negotiation banner can look like. */
        CYTADEL_ASSERT_EQ(
            cytadel_kb_set_str(kb, "Banner/23", "\x01\x02 garbled telnet negotiation junk \x03"),
            0);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->severity, 2);
        CYTADEL_ASSERT(strstr(f->evidence, "garbled telnet negotiation junk") != NULL);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile: no banner captured -- must not crash. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/telnet/23", 23);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no telnet service at all -- SKIPPED. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_SKIPPED);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

static void test_db_exposed_cleartext(cytadel_plugin_registry_t *registry) {
    const int64_t id = 100041;

    /* Positive: exactly one DB present. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/mysql/3306", 3306);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        const cytadel_finding_t *f = cytadel_test_one_finding(&findings, id);
        CYTADEL_ASSERT_EQ(f->port, 3306);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Positive: two DBs present -- two independent findings. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/mysql/3306", 3306);
        cytadel_kb_set_int(kb, "Services/redis/6379", 6379);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 2);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Negative: no DB service present -- required_keys={} means it still
     * runs (never SKIPPED), just produces nothing. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_finding_list_t findings = {0};
        cytadel_test_log_t log = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings,
                                         cytadel_test_on_result, &log);
        CYTADEL_ASSERT_EQ(cytadel_test_status_for(&log, id, -1), CYTADEL_PLUGIN_RESULT_OK);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 0);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }

    /* Malformed/hostile edge case: the KB int value happens to be 0 (never
     * produced by the real engine, which always echoes the port itself,
     * but Lua's truthiness treats integer 0 as TRUE unlike C -- this
     * confirms the plugin relies on presence, not the value, exactly as
     * kb-schema.md §7.3 specifies). */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        cytadel_kb_set_int(kb, "Services/postgresql/5432", 0);
        cytadel_finding_list_t findings = {0};
        cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, NULL, NULL);
        CYTADEL_ASSERT_EQ(cytadel_test_count_findings(&findings, id), 1);
        cytadel_finding_list_free(&findings);
        cytadel_kb_free(kb);
    }
}

int main(void) {
    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_PLUGINS_DIR, &registry);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 24);

    test_ftp_anonymous_banner_hint(registry);
    test_ftp_cleartext_protocol(registry);

    test_ssh_sshv1_supported(registry);
    test_ssh_known_vulnerable_openssh(registry);
    test_ssh_version_disclosure(registry);

    test_tls_cert_expired(registry);
    test_tls_cert_not_yet_valid(registry);
    test_tls_cert_self_signed(registry);
    test_tls_cert_hostname_mismatch(registry);
    test_tls_cert_hostname_mismatch_engine_integration(registry);
    test_tls_weak_sig_alg(registry);
    test_tls_weak_key_size(registry);
    test_tls_deprecated_protocol(registry);
    test_tls_weak_cipher(registry);

    test_http_missing_hsts(registry);
    test_http_missing_csp(registry);
    test_http_missing_xcto(registry);
    test_http_missing_xfo(registry);
    test_http_insecure_cookie_flags(registry);
    test_http_server_version_disclosure(registry);
    test_http_directory_listing(registry);
    test_http_known_vulnerable_server(registry);

    test_telnet_cleartext_protocol(registry);
    test_db_exposed_cleartext(registry);

    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
