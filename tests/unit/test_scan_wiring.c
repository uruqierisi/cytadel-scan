#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; matches this project's
                                 * own convention (see src/db/scan_persist.c). Must be defined
                                 * before any header is included. */

#include "scan_wiring.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel/kb/kb.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/report/report.h"
#include "cytadel_test.h"

/* M9 Phase 0: main.c is the FIRST PRODUCTION CALLER of the CPE evaluator --
 * this file proves the wiring that makes that true end to end (KB fact ->
 * resolver -> cytadel_scan_detect_and_persist() -> a real scan_results row),
 * independent of main() itself (which is not a useful unit-test surface --
 * it does real network I/O, real argv/env parsing, and calls exit()).
 *
 * Gate map (mirrors this milestone's own required-tests list):
 *   1. test_gate_creates_running_scan_then_finalize_completes
 *   2. test_undecidable_survives_the_wiring_path (the headline gate, at
 *      THIS milestone's real call site -- see its own header comment for
 *      the revert-proof procedure)
 *   3. test_direct_finding_persists_and_renders_in_report
 *   4. test_unresolvable_service_is_never_silently_clean (+ hostile CPE
 *      strings that must not crash the resolver)
 *   5. test_db_open_failure_refuses_before_any_scan_structure
 *   6. test_finalize_status_transitions
 */

/* ------------------------------------------------------------------ */
/* Fixture helpers (same shape as tests/unit/test_scan_persist.c's own).  */
/* ------------------------------------------------------------------ */

static cytadel_db_t *open_migrated_memory_db(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    return db;
}

static void insert_cve(sqlite3 *handle, const char *cve_id, int severity) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cves (cve_id, published, last_modified, description, "
                            "severity, source, ingested_at) VALUES (?, '2020-01-01T00:00:00.000Z', "
                            "'2020-01-01T00:00:00.000Z', '', ?, 'nvd', '2020-01-01T00:00:00.000Z');",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 2, severity), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void insert_cpe_row(sqlite3 *handle, const char *cve_id, const char *vendor,
                            const char *product, const char *version, const char *start_inc,
                            const char *start_exc, const char *end_inc, const char *end_exc,
                            int vulnerable) {
    static int uri_counter = 0;
    char cpe23_uri[64];
    int written = snprintf(cpe23_uri, sizeof(cpe23_uri), "cpe:2.3:a:x:y:fixture-row-%d:*:*:*:*:*:*:*",
                            uri_counter++);
    CYTADEL_ASSERT(written > 0 && (size_t)written < sizeof(cpe23_uri));

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, "
                            "version, version_start_including, version_start_excluding, "
                            "version_end_including, version_end_excluding, vulnerable) VALUES "
                            "(?, ?, 'a', ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, cpe23_uri, -1, SQLITE_TRANSIENT), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, vendor, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 4, product, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 5, version, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 6, start_inc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 7, start_exc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 8, end_inc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 9, end_exc, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 10, vulnerable), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

typedef struct {
    bool found;
    char match_status[32];
} scan_result_status_t;

static scan_result_status_t select_match_status(sqlite3 *handle, long long scan_id, const char *host,
                                                   const char *cve_id) {
    scan_result_status_t out;
    memset(&out, 0, sizeof(out));

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT match_status FROM scan_results WHERE scan_id = ? AND "
                                         "host = ? AND cve_id = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, host, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, cve_id, -1, SQLITE_STATIC), SQLITE_OK);

    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        out.found = true;
        const char *ms = (const char *)sqlite3_column_text(stmt, 0);
        CYTADEL_ASSERT(ms != NULL);
        size_t n = strnlen(ms, sizeof(out.match_status) - 1);
        memcpy(out.match_status, ms, n);
        out.match_status[n] = '\0';
    }
    sqlite3_finalize(stmt);
    return out;
}

static int count_scan_results_for_host(sqlite3 *handle, long long scan_id, const char *host) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT COUNT(*) FROM scan_results WHERE scan_id = ? AND host = ?;", -1,
                           &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, host, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    int n = sqlite3_column_int(stmt, 0);
    sqlite3_finalize(stmt);
    return n;
}

static const char *select_scans_status(sqlite3 *handle, long long scan_id, char *buf, size_t buf_len) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "SELECT status FROM scans WHERE scan_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    const char *s = (const char *)sqlite3_column_text(stmt, 0);
    CYTADEL_ASSERT(s != NULL);
    size_t n = strnlen(s, buf_len - 1);
    memcpy(buf, s, n);
    buf[n] = '\0';
    sqlite3_finalize(stmt);
    return buf;
}

/* Builds a minimal, single-open-port, UP host_result_t backed by a fresh KB
 * the caller owns and must cytadel_kb_free() -- deliberately NOT built via
 * cytadel_host_scan() (no real network I/O in this test file at all) and
 * deliberately NEVER released via cytadel_host_result_free() (result->ports
 * below points at caller-owned stack storage, not a heap allocation that
 * function expects to free). */
static void init_single_port_result(cytadel_host_result_t *result, cytadel_port_result_t *port_slot,
                                      const char *host, uint16_t port, cytadel_kb_t *kb) {
    memset(result, 0, sizeof(*result));
    size_t host_len = strnlen(host, sizeof(result->host) - 1);
    memcpy(result->host, host, host_len);
    result->host[host_len] = '\0';
    memcpy(result->ip, result->host, host_len + 1);
    result->state = CYTADEL_HOST_UP;
    port_slot->port = port;
    port_slot->state = CYTADEL_PORT_OPEN;
    result->ports = port_slot;
    result->port_count = 1;
    result->kb = kb;
    result->findings.items = NULL;
    result->findings.count = 0;
    result->findings.capacity = 0;
}

/* ------------------------------------------------------------------ */
/* Gate 1: scan_create-at-gate ordering + finalize.                     */
/* ------------------------------------------------------------------ */

static void test_gate_creates_running_scan_then_finalize_completes(void) {
    cytadel_db_t *db = NULL;
    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(
        cytadel_scan_wiring_open_gate(":memory:", "10.0.0.0/24", "alice", "interactive", &db, &scan_id),
        CYTADEL_SCAN_GATE_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT(scan_id > 0);

    sqlite3 *handle = cytadel_db_handle(db);
    char status_buf[32];
    /* The durable record exists, mid-gate, BEFORE any persist phase ever
     * runs -- exactly the mandatory authorization-gate rule's "log the confirmation", durably. */
    CYTADEL_ASSERT_STREQ(select_scans_status(handle, scan_id, status_buf, sizeof(status_buf)), "running");

    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_STREQ(select_scans_status(handle, scan_id, status_buf, sizeof(status_buf)), "completed");

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 2 (THE HEADLINE GATE): UNDECIDABLE must survive the real wiring  */
/* path -- KB CPE fact -> resolver -> cytadel_scan_wiring_persist_host() */
/* -> cytadel_scan_detect_and_persist() -> cytadel_cpe_match_evaluate(). */
/* ------------------------------------------------------------------ */

/* REVERT-PROOF PROCEDURE (executed manually during this milestone's
 * verification, not left as a permanently-broken build): temporarily edit
 * src/db/scan_persist.c's finalize_verdict() so the `any_undecidable`
 * branch instead sets `verdict.status = CYTADEL_SCAN_MATCH_NOT_AFFECTED;`
 * (collapsing UNDECIDABLE into a false-clean verdict), rebuild, and rerun
 * this test. It MUST fail its `CYTADEL_ASSERT_STREQ(..., "undetermined")`
 * assertion below -- if it does not fail, this test is not exercising the
 * real call site and must be fixed. Revert the edit afterward; this comment
 * exists so a future maintainer can reproduce that proof without guessing
 * which line to break. */
static void test_undecidable_survives_the_wiring_path(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* detected "1.0.0-cr1" against versionEndExcluding="1.0.0" -- the exact
     * UNDECIDABLE construction this task names (unrecognized detached
     * alpha residual "cr1", see tests/unit/test_version_compare.c's own
     * truth table). */
    insert_cve(handle, "CVE-2099-09001", 3);
    insert_cpe_row(handle, "CVE-2099-09001", "acme", "widget", "*", "", "", "", "1.0.0", 1);

    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(
        cytadel_scan_create(db, "10.0.0.5", "operator@example.com", "flag", &scan_id),
        CYTADEL_SCAN_PERSIST_OK);

    /* The KB fact main.c's real service-detection phase (src/net/cpe_map.c)
     * would have written for this port -- this is the ONLY thing this test
     * fabricates instead of running a real scan; everything downstream
     * (resolver, persist phase, DB write) is the real production path. */
    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);
    CYTADEL_ASSERT_EQ(
        cytadel_kb_set_str(kb, "CPE/8080", "cpe:2.3:a:acme:widget:1.0.0-cr1:*:*:*:*:*:*:*"), 0);

    cytadel_host_result_t result;
    cytadel_port_result_t port_slot;
    init_single_port_result(&result, &port_slot, "10.0.0.5", 8080, kb);

    cytadel_scan_wiring_host_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.detections_attempted, 1);
    CYTADEL_ASSERT_EQ(counts.unresolvable_services, 0);
    CYTADEL_ASSERT_EQ(counts.rows_inserted, 1);
    CYTADEL_ASSERT_EQ(counts.malformed_events, 0);

    scan_result_status_t row = select_match_status(handle, scan_id, "10.0.0.5", "CVE-2099-09001");
    CYTADEL_ASSERT(row.found);
    /* THE assertion: must read back 'undetermined' -- never 'confirmed',
     * never 'not_affected'. See this function's own header comment for the
     * revert-proof procedure that exercises this exact line. */
    CYTADEL_ASSERT_STREQ(row.match_status, "undetermined");
    CYTADEL_ASSERT(strcmp(row.match_status, "confirmed") != 0);
    CYTADEL_ASSERT(strcmp(row.match_status, "not_affected") != 0);

    cytadel_kb_free(kb);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 3: a direct plugin finding lands AND reaches the rendered report. */
/* ------------------------------------------------------------------ */

static void test_direct_finding_persists_and_renders_in_report(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "192.168.1.10", "operator@example.com", "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_OK);

    /* A plugin finding with NO CVE hint at all (e.g. a self-signed
     * certificate check) -- exactly the composition test_scan_persist.c
     * never exercised: a report must show plugin findings, not only
     * version-CVE matches. Never freed via cytadel_finding_list_free() --
     * every field below is a string literal, not a heap allocation. */
    cytadel_finding_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.severity = 2;
    finding.title = (char *)"Self-Signed TLS Certificate";
    finding.evidence = (char *)"CN=localhost, self-signed, not_after=2020-01-01";
    finding.port = 443;
    finding.solution = (char *)"Deploy a CA-signed certificate";
    finding.cve = NULL;
    finding.cve_count = 0;
    finding.cpe = NULL;
    finding.cvss_vector = NULL;
    finding.script_id = 100050;
    finding.script_name = (char *)"Self-Signed Certificate Check";

    cytadel_host_result_t result;
    memset(&result, 0, sizeof(result));
    static const char *const kHost = "192.168.1.10";
    size_t host_len = strlen(kHost);
    memcpy(result.host, kHost, host_len + 1);
    memcpy(result.ip, kHost, host_len + 1);
    result.state = CYTADEL_HOST_UP;
    result.ports = NULL;
    result.port_count = 0;
    result.kb = NULL; /* no open ports to resolve in this test -- never dereferenced */
    result.findings.items = &finding;
    result.findings.count = 1;
    result.findings.capacity = 1;

    cytadel_scan_wiring_host_counts_t counts;
    CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.findings_persisted, 1);
    CYTADEL_ASSERT_EQ(counts.detections_attempted, 0);
    CYTADEL_ASSERT_EQ(counts.unresolvable_services, 0);

    /* Row exists, match_status='confirmed', cve_id IS NULL. */
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                         "SELECT match_status, cve_id, plugin_id, evidence FROM "
                                         "scan_results WHERE scan_id = ? AND host = ?;",
                                         -1, &stmt, NULL),
                      SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, "192.168.1.10", -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_ROW);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 0), "confirmed");
    CYTADEL_ASSERT(sqlite3_column_type(stmt, 1) == SQLITE_NULL);
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 2), "100050");
    CYTADEL_ASSERT_STREQ((const char *)sqlite3_column_text(stmt, 3),
                          "CN=localhost, self-signed, not_after=2020-01-01");
    sqlite3_finalize(stmt);

    /* Now render the report and prove the finding's evidence actually
     * reaches the rendered artifact -- the composition that was absent
     * before this milestone. */
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_OK);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);
    CYTADEL_ASSERT(out.data != NULL);
    /* The finding's evidence (db-schema.md's own "evidence -- the detection
     * proof") and remediation both reach the rendered artifact -- title/
     * script_name are NOT scan_results columns (only plugin_id, derived
     * from script_id, is persisted -- see this file's own SELECT above),
     * so those are deliberately not asserted here. */
    CYTADEL_ASSERT(strstr(out.data, "CN=localhost, self-signed, not_after=2020-01-01") != NULL);
    CYTADEL_ASSERT(strstr(out.data, "Deploy a CA-signed certificate") != NULL);
    CYTADEL_ASSERT(strstr(out.data, "100050") != NULL);
    /* "Configuration finding (no CVE)" is report_html.c's own fixed literal
     * for a confirmed row with no cve_id -- proves this finding rendered as
     * its own finding card, not silently folded away. */
    CYTADEL_ASSERT(strstr(out.data, "Configuration finding (no CVE)") != NULL);
    cytadel_report_buf_free(&out);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 4: unresolvable service != silent clean, and the resolver never  */
/* crashes on hostile/garbage/oversized CPE text.                       */
/* ------------------------------------------------------------------ */

static void test_unresolvable_service_is_never_silently_clean(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "10.0.0.9", "operator@example.com", "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_OK);

    /* Case A: no CPE/<port> fact at all (the ordinary "banner had no
     * recognized marker/version" outcome) -- unresolvable. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        CYTADEL_ASSERT(kb != NULL);

        cytadel_host_result_t result;
        cytadel_port_result_t port_slot;
        init_single_port_result(&result, &port_slot, "10.0.0.9", 9001, kb);

        cytadel_scan_wiring_host_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.unresolvable_services, 1);
        CYTADEL_ASSERT_EQ(counts.detections_attempted, 0);
        /* Never silently recorded as a clean/no-CVE result. */
        CYTADEL_ASSERT_EQ(count_scan_results_for_host(cytadel_db_handle(db), scan_id, "10.0.0.9"), 0);

        cytadel_kb_free(kb);
    }

    /* Case B: a HOSTILE CPE/<port> string -- too few ':'-delimited fields
     * (not the real "cpe:2.3:a:vendor:product:version:..." shape at all).
     * Must resolve to unresolvable, never crash. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        CYTADEL_ASSERT(kb != NULL);
        CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "CPE/9002", "not-a-cpe-string-at-all"), 0);

        cytadel_scan_resolved_service_t resolved;
        CYTADEL_ASSERT(!cytadel_scan_wiring_resolve_port(kb, 9002, &resolved));

        cytadel_host_result_t result;
        cytadel_port_result_t port_slot;
        init_single_port_result(&result, &port_slot, "10.0.0.9", 9002, kb);

        cytadel_scan_wiring_host_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.unresolvable_services, 1);
        CYTADEL_ASSERT_EQ(counts.detections_attempted, 0);

        cytadel_kb_free(kb);
    }

    /* Case C: a HOSTILE, OVERSIZED vendor field (300 bytes, well past
     * CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN's 256-byte cap) inside an
     * otherwise well-shaped CPE string -- still well-formed UTF-8, no
     * embedded NUL (kb_set_str() would reject either of those outright),
     * but structurally hostile to a fixed-size vendor buffer. Must resolve
     * to unresolvable (never truncate-and-continue, never overflow a
     * stack buffer -- this is exactly the case ASan is watching). */
    {
        char oversized_cpe[512];
        size_t pos = 0;
        memcpy(oversized_cpe, "cpe:2.3:a:", 10);
        pos = 10;
        memset(oversized_cpe + pos, 'A', 300);
        pos += 300;
        int written = snprintf(oversized_cpe + pos, sizeof(oversized_cpe) - pos,
                                 ":product:1.0:*:*:*:*:*:*:*");
        CYTADEL_ASSERT(written > 0 && pos + (size_t)written < sizeof(oversized_cpe));

        cytadel_kb_t *kb = cytadel_kb_create();
        CYTADEL_ASSERT(kb != NULL);
        CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "CPE/9003", oversized_cpe), 0);

        cytadel_scan_resolved_service_t resolved;
        CYTADEL_ASSERT(!cytadel_scan_wiring_resolve_port(kb, 9003, &resolved));

        cytadel_host_result_t result;
        cytadel_port_result_t port_slot;
        init_single_port_result(&result, &port_slot, "10.0.0.9", 9003, kb);

        cytadel_scan_wiring_host_counts_t counts;
        CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                          CYTADEL_SCAN_PERSIST_OK);
        CYTADEL_ASSERT_EQ(counts.unresolvable_services, 1);
        CYTADEL_ASSERT_EQ(counts.detections_attempted, 0);

        cytadel_kb_free(kb);
    }

    /* Case D: an empty version field ("cpe:2.3:a:vendor:product::*:*:*:*:*:*:*")
     * -- well-formed shape, but nothing to match against. Unresolvable, not
     * a crash, not a match against an empty string. */
    {
        cytadel_kb_t *kb = cytadel_kb_create();
        CYTADEL_ASSERT(kb != NULL);
        CYTADEL_ASSERT_EQ(cytadel_kb_set_str(kb, "CPE/9004", "cpe:2.3:a:vendor:product::*:*:*:*:*:*:*"),
                          0);

        cytadel_scan_resolved_service_t resolved;
        CYTADEL_ASSERT(!cytadel_scan_wiring_resolve_port(kb, 9004, &resolved));

        cytadel_kb_free(kb);
    }

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 7 (M9 Gap #3 fix): one finding's per-row rejection must NEVER      */
/* poison the rest of the host/scan -- the exact db_ok-latch-level         */
/* property the original bug broke (src/cli/main.c's `db_ok` used to see   */
/* CYTADEL_SCAN_PERSIST_ERR_DB for this and stop persisting to every        */
/* subsequent host, then flip scans.status to 'failed' for the WHOLE scan). */
/* ------------------------------------------------------------------ */

/* REVERT-PROOF (executed manually during this milestone's verification):
 * temporarily change cytadel_scan_persist_finding()'s scan_results-insert
 * SQLITE_CONSTRAINT branch (src/db/scan_persist.c) back to the OLD
 * fatal-abort behavior (fall through to the generic fatal ERR_DB branch
 * instead of returning CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED), rebuild, and
 * rerun this test. It MUST fail: cytadel_scan_wiring_persist_host() returns
 * CYTADEL_SCAN_PERSIST_ERR_DB instead of CYTADEL_SCAN_PERSIST_OK, the THIRD
 * finding is never even attempted (this loop returns immediately on the
 * first ERR_DB -- see scan_wiring.c's own comment), and (mirroring
 * src/cli/main.c's real db_ok latch) the scan would be finalized as
 * 'failed' instead of 'completed'. Revert the edit afterward; report the
 * observed failure. */
static void test_finding_row_skip_does_not_poison_the_scan(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    /* Forces the scan_results insert for the middle finding (plugin_id
     * derived from script_id 555002) to fail with SQLITE_CONSTRAINT -- the
     * same proven forced-trigger technique test_scan_persist.c's own
     * test_malformed_data_count_rolls_back_with_its_transaction() uses. */
    CYTADEL_ASSERT_EQ(
        sqlite3_exec(handle,
                     "CREATE TEMP TRIGGER force_wiring_seq_fail BEFORE INSERT ON scan_results "
                     "WHEN NEW.plugin_id = '555002' "
                     "BEGIN SELECT RAISE(ABORT, 'test-forced failure'); END;",
                     NULL, NULL, NULL),
        SQLITE_OK);

    long long scan_id = -1;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "10.0.0.20", "operator@example.com", "flag", &scan_id),
                      CYTADEL_SCAN_PERSIST_OK);

    cytadel_finding_t findings[3];
    memset(findings, 0, sizeof(findings));

    findings[0].severity = 1;
    findings[0].title = (char *)"Finding One";
    findings[0].evidence = (char *)"evidence one";
    findings[0].port = 80;
    findings[0].script_id = 555001;

    findings[1].severity = 1;
    findings[1].title = (char *)"Finding Two (forced to fail)";
    findings[1].evidence = (char *)"evidence two";
    findings[1].port = 81;
    findings[1].script_id = 555002;

    findings[2].severity = 1;
    findings[2].title = (char *)"Finding Three";
    findings[2].evidence = (char *)"evidence three";
    findings[2].port = 82;
    findings[2].script_id = 555003;

    cytadel_host_result_t result;
    memset(&result, 0, sizeof(result));
    static const char *const kHost = "10.0.0.20";
    size_t host_len = strlen(kHost);
    memcpy(result.host, kHost, host_len + 1);
    memcpy(result.ip, kHost, host_len + 1);
    result.state = CYTADEL_HOST_UP;
    result.ports = NULL;
    result.port_count = 0;
    result.kb = NULL;
    result.findings.items = findings;
    result.findings.count = 3;
    result.findings.capacity = 3;

    cytadel_scan_wiring_host_counts_t counts;
    /* THE assertion: the overall call must still succeed (never ERR_DB) --
     * one per-row skip must not poison persistence for this host/scan. */
    CYTADEL_ASSERT_EQ(cytadel_scan_wiring_persist_host(db, scan_id, &result, &counts),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(counts.findings_persisted, 2);
    CYTADEL_ASSERT_EQ(counts.findings_skipped, 1);
    CYTADEL_ASSERT_EQ(count_scan_results_for_host(handle, scan_id, "10.0.0.20"), 2);

    /* THE db_ok-latch-level assertion: the scan can still reach 'completed'
     * -- exactly the property the M9 Gap #3 bug broke. */
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_OK);
    char status_buf[32];
    CYTADEL_ASSERT_STREQ(select_scans_status(handle, scan_id, status_buf, sizeof(status_buf)), "completed");

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 5: a DB that cannot be opened/migrated refuses BEFORE any scan   */
/* structure exists -- and structurally cannot reach a network probe.   */
/* ------------------------------------------------------------------ */

static void test_db_open_failure_refuses_before_any_scan_structure(void) {
    cytadel_db_t *db = (cytadel_db_t *)0x1; /* poison -- must be reset to NULL on failure */
    long long scan_id = 999;                /* poison -- must be left untouched on failure */

    /* A path whose parent directory does not exist: sqlite3_open_v2()'s
     * own SQLITE_OPEN_CREATE cannot create a missing directory, so this is
     * guaranteed to fail cytadel_db_open() itself, exactly like a
     * production deployment pointing CYTADEL_DB_PATH at an unwritable/
     * nonexistent location. */
    cytadel_scan_gate_status_t status =
        cytadel_scan_wiring_open_gate("/cytadel-test-nonexistent-dir-xyz/db.sqlite", "10.0.0.0/24",
                                       "operator@example.com", "flag", &db, &scan_id);

    CYTADEL_ASSERT_EQ(status, CYTADEL_SCAN_GATE_ERR_OPEN);
    CYTADEL_ASSERT(db == NULL);
    /* out_scan_id is documented as "left unset" on failure -- this asserts
     * the poison value, proving this function never wrote through it. */
    CYTADEL_ASSERT_EQ(scan_id, 999);

    /* Structural proof, not just a behavioral one: this whole call took no
     * target-list/port-range/scan-options argument of any kind -- there is
     * no parameter through which this function COULD have reached
     * cytadel_target_list_parse() or the worker pool even if its DB calls
     * had succeeded. src/cli/main.c's own ordering places this call before
     * target expansion for exactly this reason. */
}

/* ------------------------------------------------------------------ */
/* Gate 6: finalize status transitions -- completed vs. failed.         */
/* ------------------------------------------------------------------ */

static void test_finalize_status_transitions(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    char status_buf[32];

    long long scan_id_ok = -1;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "10.0.0.1", "operator@example.com", "flag", &scan_id_ok),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id_ok, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_STREQ(select_scans_status(handle, scan_id_ok, status_buf, sizeof(status_buf)),
                          "completed");

    long long scan_id_fail = -1;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, "10.0.0.2", "operator@example.com", "flag", &scan_id_fail),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, scan_id_fail, CYTADEL_SCAN_FINALIZE_FAILED),
                      CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT_STREQ(select_scans_status(handle, scan_id_fail, status_buf, sizeof(status_buf)), "failed");

    /* A finalize against a scan_id that does not exist is a DB-level
     * failure (zero rows changed), never silently reported as success. */
    CYTADEL_ASSERT_EQ(cytadel_scan_finalize(db, 999999, CYTADEL_SCAN_FINALIZE_COMPLETED),
                      CYTADEL_SCAN_PERSIST_ERR_DB);

    cytadel_db_close(db);
}

int main(void) {
    test_gate_creates_running_scan_then_finalize_completes();
    test_undecidable_survives_the_wiring_path();
    test_direct_finding_persists_and_renders_in_report();
    test_finding_row_skip_does_not_poison_the_scan();
    test_unresolvable_service_is_never_silently_clean();
    test_db_open_failure_refuses_before_any_scan_structure();
    test_finalize_status_transitions();

    CYTADEL_TEST_PASS();
}
