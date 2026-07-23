#define _POSIX_C_SOURCE 200809L /* matches test_report_html.c's own project-wide convention */

#include "cytadel/report/report.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel_test.h"

/* Milestone 8 slice 4: the JSON report generator (src/report/report_json.c).
 * Mirrors test_report_html.c's own fixture helpers and gate coverage,
 * adapted for JSON's flat `findings` array (no host-grouping / clean-host
 * logic -- that is an HTML-only concept) and cJSON-based parse-back
 * verification instead of raw-byte HTML-marker scoping:
 *
 *   - Valid JSON: the WHOLE document parses back via
 *     cJSON_ParseWithLength() even under a hostile evidence payload
 *     (control bytes, quotes, `<script>`) -- a malformed document here
 *     would mean this module produced INVALID JSON, not just unescaped
 *     HTML.
 *   - Per-site escaping: for EVERY scan_results/scans string field this
 *     module emits, a shared hostile payload is asserted to round-trip
 *     byte-for-byte through cJSON's own parser (cJSON unescapes `\"` back
 *     to `"`, `` back to the raw control byte, etc. -- getting the
 *     ORIGINAL bytes back on parse proves this module escaped correctly)
 *     AND, on the raw (pre-parse) output bytes, the literal `<script>`
 *     substring is asserted present UNESCAPED (proving JSON rules, not
 *     HTML rules, per escape.h's own json() contract).
 *   - UNDECIDABLE surfaced verbatim, never coerced/omitted
 *     (cpe-matching.md SS3.1/SS3.3/SS6 item 4).
 *   - Snapshot, not live-joined (db-schema.md SS10 assumption 6).
 *   - malformed_data_count present with the exact stored value.
 *   - CHECK-constrained fields (status, authorization_method,
 *     match_status) need no escaper-mutation proof: the schema itself
 *     rejects any value outside their fixed enum, DB-level, independent of
 *     this module -- proven directly against sqlite3, same reasoning as
 *     test_report_html.c's own test_status_and_authorization_method_reject_
 *     hostile_values().
 */

/* ------------------------------------------------------------------ */
/* Fixture helpers (duplicated from test_report_html.c -- each test file  */
/* compiles to its own standalone executable, per this project's "no      */
/* external test framework, one file = one binary" convention).          */
/* ------------------------------------------------------------------ */

static cytadel_db_t *open_migrated_memory_db(void) {
    cytadel_db_t *db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(":memory:", &db), CYTADEL_DB_OK);
    CYTADEL_ASSERT(db != NULL);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(db), CYTADEL_DB_OK);
    return db;
}

static long long create_scan(cytadel_db_t *db, const char *target_spec) {
    long long scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, target_spec, "tester", "interactive", &scan_id),
                       CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);
    return scan_id;
}

static long long create_scan_full(cytadel_db_t *db, const char *target_spec, const char *authorized_by) {
    long long scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, target_spec, authorized_by, "interactive", &scan_id),
                       CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);
    return scan_id;
}

static void set_scan_timestamps(sqlite3 *handle, long long scan_id, const char *started_at,
                                  const char *finished_at, const char *authorization_confirmed_at) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle,
                                          "UPDATE scans SET started_at = ?, finished_at = ?, "
                                          "authorization_confirmed_at = ? WHERE scan_id = ?;",
                                          -1, &stmt, NULL),
                       SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, started_at, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, finished_at, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 3, authorization_confirmed_at, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 4, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void assert_column_rejects_value(sqlite3 *handle, const char *sql_update, const char *value,
                                          long long scan_id) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, sql_update, -1, &stmt, NULL), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 2, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_CONSTRAINT);
    sqlite3_finalize(stmt);
}

static void set_malformed_data_count(sqlite3 *handle, long long scan_id, long long count) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "UPDATE scans SET malformed_data_count = ? WHERE scan_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 1, count), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 2, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void insert_cve(sqlite3 *handle, const char *cve_id, int severity) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO cves (cve_id, published, last_modified, description, severity, "
                            "source, ingested_at) VALUES (?, '2020-01-01T00:00:00.000Z', "
                            "'2020-01-01T00:00:00.000Z', '', ?, 'nvd', '2020-01-01T00:00:00.000Z');",
                            -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 2, severity), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

static void update_cve_severity(sqlite3 *handle, const char *cve_id, int severity) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(handle, "UPDATE cves SET severity = ? WHERE cve_id = ?;", -1, &stmt, NULL),
                       SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, 1, severity), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 2, cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

typedef struct {
    const char *host;
    int port;
    const char *service; /* NULL -> SQL NULL */
    const char *plugin_id;
    const char *cve_id; /* NULL -> SQL NULL */
    int severity;
    const char *evidence;
    const char *remediation; /* NULL -> SQL NULL */
    int kev_flag;
    bool has_epss;
    double epss_score;
    const char *match_status;
    const char *detected_at;
} test_row_t;

static void insert_scan_result(sqlite3 *handle, long long scan_id, const test_row_t *r) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle,
                            "INSERT INTO scan_results (scan_id, host, port, service, plugin_id, cve_id, "
                            "severity, evidence, remediation, kev_flag, epss_score, detected_at, "
                            "match_status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                            -1, &stmt, NULL),
        SQLITE_OK);
    int idx = 1;
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, idx++, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->host, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, idx++, r->port), SQLITE_OK);
    if (r->service != NULL) {
        CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->service, -1, SQLITE_STATIC), SQLITE_OK);
    } else {
        CYTADEL_ASSERT_EQ(sqlite3_bind_null(stmt, idx++), SQLITE_OK);
    }
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->plugin_id, -1, SQLITE_STATIC), SQLITE_OK);
    if (r->cve_id != NULL) {
        CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->cve_id, -1, SQLITE_STATIC), SQLITE_OK);
    } else {
        CYTADEL_ASSERT_EQ(sqlite3_bind_null(stmt, idx++), SQLITE_OK);
    }
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, idx++, r->severity), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->evidence, -1, SQLITE_STATIC), SQLITE_OK);
    if (r->remediation != NULL) {
        CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->remediation, -1, SQLITE_STATIC), SQLITE_OK);
    } else {
        CYTADEL_ASSERT_EQ(sqlite3_bind_null(stmt, idx++), SQLITE_OK);
    }
    CYTADEL_ASSERT_EQ(sqlite3_bind_int(stmt, idx++, r->kev_flag), SQLITE_OK);
    if (r->has_epss) {
        CYTADEL_ASSERT_EQ(sqlite3_bind_double(stmt, idx++, r->epss_score), SQLITE_OK);
    } else {
        CYTADEL_ASSERT_EQ(sqlite3_bind_null(stmt, idx++), SQLITE_OK);
    }
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->detected_at, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, idx++, r->match_status, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

#define DEFAULT_DETECTED_AT "2020-06-15T12:00:00.000Z"

/* ------------------------------------------------------------------ */
/* Byte-exact substring search (mirrors test_report_html.c's own          */
/* find_bytes()/contains_bytes(), duplicated here for the same reason).   */
/* ------------------------------------------------------------------ */

static const char *find_bytes(const char *hay, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > hay_len) {
        return NULL;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return hay + i;
        }
    }
    return NULL;
}

static bool contains_bytes(const char *hay, size_t hay_len, const char *needle) {
    return find_bytes(hay, hay_len, needle) != NULL;
}

/* ------------------------------------------------------------------ */
/* cJSON helpers.                                                       */
/* ------------------------------------------------------------------ */

static cJSON *parse_or_fail(const cytadel_report_buf_t *out) {
    cJSON *doc = cJSON_ParseWithLength(out->data, out->len);
    CYTADEL_ASSERT(doc != NULL);
    return doc;
}

static cJSON *require_field(const cJSON *obj, const char *key) {
    CYTADEL_ASSERT(obj != NULL);
    cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    CYTADEL_ASSERT(item != NULL);
    return item;
}

static void assert_string_field(const cJSON *obj, const char *key, const char *expected) {
    cJSON *item = require_field(obj, key);
    CYTADEL_ASSERT(cJSON_IsString(item));
    CYTADEL_ASSERT_STREQ(cJSON_GetStringValue(item), expected);
}

static void assert_null_field(const cJSON *obj, const char *key) {
    cJSON *item = require_field(obj, key);
    CYTADEL_ASSERT(cJSON_IsNull(item));
}

static void assert_int_field(const cJSON *obj, const char *key, long long expected) {
    cJSON *item = require_field(obj, key);
    CYTADEL_ASSERT(cJSON_IsNumber(item));
    CYTADEL_ASSERT_EQ((long long)cJSON_GetNumberValue(item), expected);
}

static void assert_bool_field(const cJSON *obj, const char *key, bool expected) {
    cJSON *item = require_field(obj, key);
    CYTADEL_ASSERT(cJSON_IsBool(item));
    CYTADEL_ASSERT_EQ(cJSON_IsTrue(item) ? 1 : 0, expected ? 1 : 0);
}

/* Finds the first element of the "findings" array whose "host" equals
 * `host` -- since every fixture below inserts one row per distinct host,
 * this is enough to pick the finding under test unambiguously. */
static cJSON *find_finding_by_host(cJSON *doc, const char *host) {
    cJSON *findings = require_field(doc, "findings");
    CYTADEL_ASSERT(cJSON_IsArray(findings));
    int n = cJSON_GetArraySize(findings);
    for (int i = 0; i < n; i++) {
        cJSON *item = cJSON_GetArrayItem(findings, i);
        cJSON *h = cJSON_GetObjectItemCaseSensitive(item, "host");
        if (h != NULL && cJSON_IsString(h) && strcmp(cJSON_GetStringValue(h), host) == 0) {
            return item;
        }
    }
    CYTADEL_ASSERT(false);
    return NULL;
}

/* Shared hostile payload for every per-site escaper proof below: a quote
 * (discriminates "was this escaped at all"), a `<script>` tag (must survive
 * LITERAL per JSON rules -- the html escapers would mangle it, proving this
 * really is cytadel_escape_json() and not an HTML escaper misapplied), and
 * a raw control byte (must become \u00XX). */
#define HOSTILE_PAYLOAD "a\"b<script>alert(1)</script>\x01tail"

/* ------------------------------------------------------------------ */
/* Test 1: basic structure + valid-JSON-under-hostile-evidence.          */
/* ------------------------------------------------------------------ */

static void test_basic_structure_and_valid_json(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "10.0.0.0/24");

    insert_cve(handle, "CVE-2020-0001", 4);
    test_row_t r = {"10.0.0.5", 443, "https", "tls_weak_cipher", "CVE-2020-0001", 4, HOSTILE_PAYLOAD,
                     "Disable RC4 ciphers", 1, true, 0.9321, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* Valid JSON even under a hostile evidence payload -- a malformed
     * document here would mean the escaper broke the JSON grammar itself. */
    cJSON *doc = parse_or_fail(&out);

    cJSON *scan = require_field(doc, "scan");
    assert_int_field(scan, "scan_id", scan_id);
    assert_string_field(scan, "target_spec", "10.0.0.0/24");
    assert_int_field(scan, "malformed_data_count", 0);

    cJSON *summary = require_field(doc, "summary");
    cJSON *sev = require_field(summary, "severity_counts");
    assert_int_field(sev, "4", 1);
    assert_int_field(sev, "0", 0);
    assert_int_field(summary, "kev_count", 1);
    assert_int_field(summary, "confirmed_count", 1);
    assert_int_field(summary, "undetermined_count", 0);
    assert_int_field(summary, "not_affected_count", 0);

    cJSON *finding = find_finding_by_host(doc, "10.0.0.5");
    assert_string_field(finding, "cve_id", "CVE-2020-0001");
    assert_int_field(finding, "severity", 4);
    assert_bool_field(finding, "kev_flag", true);
    assert_string_field(finding, "match_status", "confirmed");
    assert_string_field(finding, "evidence", HOSTILE_PAYLOAD);

    /* `<script>` present LITERALLY (unescaped) in the raw pre-parse output
     * -- proves JSON rules, not HTML rules (escape.h's json() contract). */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "<script>alert(1)</script>"));
    /* The quote was escaped (raw bytes show \" , not a bare '"'). */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "a\\\"b<script>"));
    /* The control byte (0x01) was escaped as , never emitted raw. */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "\\u0001tail"));

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* Invalid-arg / not-found status contract -- same enum/space as
 * cytadel_report_html(). */
static void test_invalid_arg_and_not_found(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(NULL, 1, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, 0, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, -5, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, 999, &out), CYTADEL_REPORT_ERR_NOT_FOUND);
    cytadel_report_buf_free(&out);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* malformed_data_count present with the exact stored value.            */
/* ------------------------------------------------------------------ */

static void test_malformed_data_count_present(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_with = create_scan(db, "192.168.1.0/24");
    set_malformed_data_count(handle, scan_with, 3);
    long long scan_without = create_scan(db, "192.168.2.0/24");

    cytadel_report_buf_t out_with;
    cytadel_report_buf_init(&out_with);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_with, &out_with), CYTADEL_REPORT_OK);
    cJSON *doc_with = parse_or_fail(&out_with);
    assert_int_field(require_field(doc_with, "scan"), "malformed_data_count", 3);
    cJSON_Delete(doc_with);
    cytadel_report_buf_free(&out_with);

    cytadel_report_buf_t out_without;
    cytadel_report_buf_init(&out_without);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_without, &out_without), CYTADEL_REPORT_OK);
    cJSON *doc_without = parse_or_fail(&out_without);
    assert_int_field(require_field(doc_without, "scan"), "malformed_data_count", 0);
    cJSON_Delete(doc_without);
    cytadel_report_buf_free(&out_without);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Snapshot, never a live join (db-schema.md SS10 assumption 6).        */
/* ------------------------------------------------------------------ */

static void test_snapshot_not_live_joined(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "203.0.113.10");

    insert_cve(handle, "CVE-2021-9999", 4);
    test_row_t r = {"203.0.113.10", 22, "ssh", "ssh_known_vulnerable_openssh", "CVE-2021-9999", 4,
                     "OpenSSH_7.2p2", NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    /* The live `cves` row is revised downward AFTER the scan_results row was
     * written -- the JSON report must still reflect the point-in-time
     * snapshot severity, never a fresh join to today's `cves.severity`. */
    update_cve_severity(handle, "CVE-2021-9999", 0);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    cJSON *finding = find_finding_by_host(doc, "203.0.113.10");
    assert_int_field(finding, "severity", 4); /* NOT 0 -- the live-updated value */
    assert_int_field(require_field(require_field(doc, "summary"), "severity_counts"), "4", 1);

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* UNDECIDABLE surfaced verbatim, never coerced/omitted.                 */
/* ------------------------------------------------------------------ */

static void test_undetermined_surfaced_verbatim(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "198.51.100.0/24");

    insert_cve(handle, "CVE-2022-1234", 3);
    test_row_t r = {"198.51.100.7", 8443, "https", "http_known_vulnerable_server", "CVE-2022-1234", 3,
                     "Server: Widget/1.0-cr1 (unrankable pre-release scheme)", NULL, 0, false, 0.0,
                     "undetermined", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    /* Present in the findings array, with match_status VERBATIM. */
    cJSON *finding = find_finding_by_host(doc, "198.51.100.7");
    assert_string_field(finding, "match_status", "undetermined");
    assert_string_field(finding, "cve_id", "CVE-2022-1234");

    /* Present in the summary counts too -- never folded into confirmed_count
     * or not_affected_count. */
    cJSON *summary = require_field(doc, "summary");
    assert_int_field(summary, "undetermined_count", 1);
    assert_int_field(summary, "confirmed_count", 0);
    assert_int_field(summary, "not_affected_count", 0);

    /* findings array has exactly one element -- the row was not silently
     * dropped. */
    cJSON *findings = require_field(doc, "findings");
    CYTADEL_ASSERT_EQ(cJSON_GetArraySize(findings), 1);

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* not_affected: present in findings + summary, never silently dropped
 * either (this module's own audit-trail row model -- db-schema.md's "one
 * row per distinct candidate cve_id regardless of verdict"). */
static void test_not_affected_present(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "10.10.0.0/24");

    insert_cve(handle, "CVE-2023-0002", 1);
    test_row_t r = {"10.10.0.9", 21, "ftp", "ftp_cleartext_protocol", "CVE-2023-0002", 1,
                     "FTP banner did not match any vulnerable range", NULL, 0, false, 0.0, "not_affected",
                     DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    cJSON *finding = find_finding_by_host(doc, "10.10.0.9");
    assert_string_field(finding, "match_status", "not_affected");
    assert_int_field(require_field(doc, "summary"), "not_affected_count", 1);

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Nullable fields render as JSON `null`, never "" or an omitted key.    */
/* ------------------------------------------------------------------ */

static void test_nullable_fields_render_null(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "nullable-fields-scan");

    /* scan.finished_at is NULL while status = 'running' (schema default). */
    test_row_t r = {"10.40.0.1", 0, NULL, "os_fingerprint", NULL, 2, "host-level finding, no CVE", NULL, 0, false,
                     0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    assert_null_field(require_field(doc, "scan"), "finished_at");

    cJSON *finding = find_finding_by_host(doc, "10.40.0.1");
    assert_null_field(finding, "service");
    assert_null_field(finding, "cve_id");
    assert_null_field(finding, "remediation");
    assert_null_field(finding, "epss_score");
    assert_int_field(finding, "port", 0); /* host-level finding, port 0 -- still a number, not null */

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* EXHAUSTIVE per-site escaper coverage: every scan_results/scans string   */
/* field this module emits, each with its own hostile-payload assertion.  */
/* ------------------------------------------------------------------ */

static void test_scan_object_string_sites(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_id = create_scan_full(db, HOSTILE_PAYLOAD, HOSTILE_PAYLOAD);
    set_scan_timestamps(handle, scan_id, HOSTILE_PAYLOAD, HOSTILE_PAYLOAD, HOSTILE_PAYLOAD);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    cJSON *scan = require_field(doc, "scan");
    assert_string_field(scan, "target_spec", HOSTILE_PAYLOAD);
    assert_string_field(scan, "authorized_by", HOSTILE_PAYLOAD);
    assert_string_field(scan, "started_at", HOSTILE_PAYLOAD);
    assert_string_field(scan, "finished_at", HOSTILE_PAYLOAD);
    assert_string_field(scan, "authorization_confirmed_at", HOSTILE_PAYLOAD);

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* status / authorization_method: CHECK-constrained, cannot carry a hostile
 * payload -- proven by SQLite itself refusing the write, same reasoning as
 * test_report_html.c's own analogous test. */
static void test_status_and_authorization_method_reject_hostile_values(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "reject-test");

    assert_column_rejects_value(handle, "UPDATE scans SET status = ? WHERE scan_id = ?;", HOSTILE_PAYLOAD, scan_id);
    assert_column_rejects_value(handle, "UPDATE scans SET authorization_method = ? WHERE scan_id = ?;",
                                 HOSTILE_PAYLOAD, scan_id);

    cytadel_db_close(db);
}

/* match_status: CHECK-constrained to exactly 'confirmed'/'undetermined'/
 * 'not_affected' -- same non-injectable reasoning, proven the same way. The
 * THREE legitimate values are separately proven "surfaced verbatim" by
 * test_undetermined_surfaced_verbatim() / test_not_affected_present() /
 * test_basic_structure_and_valid_json() above. */
static void test_match_status_rejects_hostile_values(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    long long scan_id = create_scan(db, "match-status-reject-test");
    insert_cve(cytadel_db_handle(db), "CVE-2025-9000", 2);
    test_row_t r = {"10.50.0.1", 80, "http", "http_missing_hsts", "CVE-2025-9000", 2, "evidence text", NULL, 0,
                     false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(cytadel_db_handle(db), scan_id, &r);

    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(sqlite3_prepare_v2(cytadel_db_handle(db),
                                          "UPDATE scan_results SET match_status = ? WHERE scan_id = ?;", -1, &stmt,
                                          NULL),
                       SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, HOSTILE_PAYLOAD, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 2, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_CONSTRAINT);
    sqlite3_finalize(stmt);

    cytadel_db_close(db);
}

static void test_finding_string_sites(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "finding-sites-scan");

    insert_cve(handle, HOSTILE_PAYLOAD, 2);
    test_row_t r = {HOSTILE_PAYLOAD, 8080, HOSTILE_PAYLOAD, HOSTILE_PAYLOAD, HOSTILE_PAYLOAD, 2, HOSTILE_PAYLOAD,
                     HOSTILE_PAYLOAD, 0, false, 0.0, "confirmed", HOSTILE_PAYLOAD};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_json(db, scan_id, &out), CYTADEL_REPORT_OK);
    cJSON *doc = parse_or_fail(&out);

    cJSON *finding = find_finding_by_host(doc, HOSTILE_PAYLOAD);
    assert_string_field(finding, "service", HOSTILE_PAYLOAD);
    assert_string_field(finding, "plugin_id", HOSTILE_PAYLOAD);
    assert_string_field(finding, "cve_id", HOSTILE_PAYLOAD);
    assert_string_field(finding, "evidence", HOSTILE_PAYLOAD);
    assert_string_field(finding, "remediation", HOSTILE_PAYLOAD);
    assert_string_field(finding, "detected_at", HOSTILE_PAYLOAD);

    cJSON_Delete(doc);
    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

int main(void) {
    test_basic_structure_and_valid_json();
    test_invalid_arg_and_not_found();
    test_malformed_data_count_present();
    test_snapshot_not_live_joined();
    test_undetermined_surfaced_verbatim();
    test_not_affected_present();
    test_nullable_fields_render_null();
    test_scan_object_string_sites();
    test_status_and_authorization_method_reject_hostile_values();
    test_match_status_rejects_hostile_values();
    test_finding_string_sites();

    CYTADEL_TEST_PASS();
}
