#include "cytadel_test.h"

#include <stdint.h>
#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Security-review round-3 finding C-1 (CRITICAL) regression test.
 *
 * tests/plugins/fixtures/env_metatable_attack/ contains two files:
 *
 *   - attack.lua: a valid register{...} header, followed by
 *     `setmetatable(_ENV, {__index = ...})` and NO `run` function.
 *     src/plugin/loader.c's own §4.1 step 5 check ("does this plugin
 *     define run()?") used to be a plain, unprotected
 *     lua_getfield(L, env_idx, "run") reachable outside any lua_pcall on
 *     that lua_State -- a malicious _ENV metatable reaching it could
 *     abort() the whole scanner process over this one file. With the fix
 *     (sandbox.c's __metatable lock on _ENV, defense-in-depth alongside
 *     field_utils.h's cytadel_plugin_raw_getfield() at that same call
 *     site -- see this fixture's own header comment), the setmetatable()
 *     call itself raises "cannot change a protected metatable", caught by
 *     the registration chunk's own lua_pcall(): an entirely ordinary
 *     registration failure. This one C test call
 *     (cytadel_plugin_registry_load()) is exactly where the crash used to
 *     happen -- reaching the assertions below at all already proves the
 *     engine survived it.
 *
 *   - sibling_ok.lua: an entirely ordinary, well-behaved plugin in the
 *     SAME directory. Its successful registration and dispatch proves the
 *     engine keeps registering/scanning normally rather than merely
 *     failing to crash.
 *
 * invoke.c:157 has the IDENTICAL fix (cytadel_plugin_raw_getfield()) for
 * the equivalent run-phase check, but -- because the same __metatable lock
 * on _ENV blocks the setmetatable() call itself before any plugin's
 * top-level code could ever reach that point -- there is no way to
 * construct a black-box Lua fixture that exercises invoke.c:157's fix in
 * isolation from loader.c:63's; both call sites are only reachable via the
 * exact same `setmetatable(_ENV, ...)` attack, which the lock now rejects
 * at the very first attempt regardless of which phase is running. This is
 * stated plainly rather than papered over: this test proves the FIX AS A
 * WHOLE closes the attack (both call sites' fix combined with the lock);
 * see test_plugin_r3c1_raw_getfield.c for a deterministic, phase-independent
 * white-box proof that cytadel_plugin_raw_getfield() itself -- the fix
 * applied at BOTH loader.c:63 and invoke.c:157 -- never invokes __index,
 * regardless of whether the lock exists at all. */

#ifndef CYTADEL_TEST_FIXTURES_DIR
#define CYTADEL_TEST_FIXTURES_DIR "tests/plugins/fixtures"
#endif

typedef struct {
    int64_t script_id;
    cytadel_plugin_result_status_t status;
} cytadel_test_result_record_t;

typedef struct {
    cytadel_test_result_record_t records[4];
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

int main(void) {
    /* No real listener needed -- sibling_ok.lua only calls get_scan_port()
     * and report_vuln{}, neither of which touches the network. */
    const uint16_t port = 18001;

    cytadel_plugin_registry_t *registry = NULL;
    int rc = cytadel_plugin_registry_load(CYTADEL_TEST_FIXTURES_DIR "/env_metatable_attack",
                                           &registry);
    /* Reaching this line at all (rather than the process having aborted
     * inside cytadel_plugin_registry_load()) is itself the core C-1 proof. */
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(registry != NULL);

    /* attack.lua must have been rejected at registration (a clean,
     * logged-and-skipped failure -- plugin-api.md §4.1 step 7), so only
     * sibling_ok.lua is in the registry. */
    CYTADEL_ASSERT_EQ(cytadel_plugin_registry_count(registry), 1);

    cytadel_kb_t *kb = cytadel_kb_create();
    char key[64];
    snprintf(key, sizeof(key), "Services/www/%u", (unsigned)port);
    cytadel_kb_set_int(kb, key, port);

    cytadel_finding_list_t findings;
    memset(&findings, 0, sizeof(findings));
    cytadel_test_result_log_t log;
    memset(&log, 0, sizeof(log));

    cytadel_plugin_run_all_for_host(registry, "127.0.0.1", kb, &findings, cytadel_test_on_result,
                                     &log);

    /* The engine kept scanning: the surviving sibling plugin was
     * dispatched and completed OK with its finding recorded. */
    CYTADEL_ASSERT_EQ(log.count, 1);
    CYTADEL_ASSERT_EQ(cytadel_test_find_status(&log, 978001), CYTADEL_PLUGIN_RESULT_OK);
    CYTADEL_ASSERT_EQ(findings.count, 1);
    CYTADEL_ASSERT_STREQ(findings.items[0].title, "C1 sibling check passed");

    cytadel_finding_list_free(&findings);
    cytadel_kb_free(kb);
    cytadel_plugin_registry_free(registry);
    CYTADEL_TEST_PASS();
}
