#define _POSIX_C_SOURCE 200809L /* snprintf()/strnlen()-adjacent conventions match src/db's own
                                 * project-wide "define before any header" rule; not strictly
                                 * required by anything this file calls, kept for consistency. */

#include "cytadel/report/report.h"

#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel_test.h"

/* Milestone 8 slice 3: the branded HTML report generator
 * (src/report/report_html.c). This test proves, through the REAL DB
 * boundary and a REAL render, every one of this milestone's binding gates:
 *
 *   - Gate 2 (docs/contracts/db-schema.md SS6 malformed_data_count): the
 *     data-quality banner appears iff the count is nonzero, with the exact
 *     count rendered.
 *   - Gate 3 (docs/contracts/cpe-matching.md SS3.1/SS3.3/SS6 item 4):
 *       (a) severity/kev_flag/epss_score are SNAPSHOTS read from
 *           scan_results, never re-joined against a since-changed cves row;
 *       (b) an 'undetermined' row is ALWAYS rendered as its own visible
 *           "could not determine" record;
 *       (c) a host with a nonzero undetermined count NEVER renders "no
 *           vulnerabilities found", while a host with zero confirmed AND
 *           zero undetermined MAY.
 *   - THE per-interpolation-site escaper gate: for one attribute site
 *     (evidence in title="..."), one URL site (cve_id in the NVD href),
 *     and one body site (evidence in a <p>), a hostile, CONTEXT-
 *     DISCRIMINATING payload is asserted neutralized in exactly the way
 *     only the correct escaper produces. Each of these three sites was
 *     independently mutated to the WRONG escaper, rebuilt, and confirmed to
 *     make its own assertion FAIL -- see this milestone's write-up for the
 *     exact mutation diff and the observed failing assertion/output for
 *     each; every mutation was reverted immediately after the failure was
 *     captured.
 */

/* ------------------------------------------------------------------ */
/* Fixture helpers.                                                    */
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

/* Full-control variant: seeds a hostile authorized_by (a real, bindable CLI
 * operator-identity string -- no CHECK constraint restricts this column,
 * db-schema.md SS6) alongside target_spec. */
static long long create_scan_full(cytadel_db_t *db, const char *target_spec, const char *authorized_by) {
    long long scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(db, target_spec, authorized_by, "interactive", &scan_id),
                       CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);
    return scan_id;
}

/* started_at/finished_at/authorization_confirmed_at are always
 * strftime()-written by cytadel_scan_create() in normal operation -- never
 * attacker-influenced via that API. But the schema places NO CHECK/format
 * constraint on these TEXT columns (db-schema.md SS6), so this module's own
 * escaping must not assume upstream cleanliness here either (this project's
 * "never trust upstream validation" rule, applied the same way the cve_id
 * sites already bypass cve_id_valid.h). This raw UPDATE seeds hostile
 * content directly, mirroring insert_cve()'s own bypass rationale. */
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

/* Attempts to write `value` into a CHECK-constrained column and asserts
 * SQLite itself rejects it (SQLITE_CONSTRAINT) -- used to justify why
 * `status`/`authorization_method` need no hostile-payload escaper proof:
 * the schema's own CHECK makes an HTML-meta-character value impossible to
 * ever store there in the first place, DB-level, independent of any
 * application code. */
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

/* Only needed to satisfy scan_results.cve_id's FK -- deliberately inserted
 * DIRECTLY (never through the NVD ingest / cve_id_valid.h grammar check),
 * mirroring how a hostile cve_id would still legitimately reach this
 * table (the report's escapers must defend it regardless of upstream
 * validation, per report.h's own threat-model comment). */
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
    const char *match_status; /* "confirmed" | "undetermined" | "not_affected" */
    const char *detected_at; /* always bound (schema NOT NULL); a fixed benign
                                 default in most tests, a hostile payload in
                                 the sites that specifically test this column */
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

/* Default, benign detected_at used by every test row that isn't itself
 * testing the detected_at column. */
#define DEFAULT_DETECTED_AT "2020-06-15T12:00:00.000Z"

/* ------------------------------------------------------------------ */
/* Byte-exact substring search helpers (never strlen()-bounded on `hay`, */
/* mirroring test_report_escape.c's own contains_bytes()).               */
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

/* Slices out one host-block <section>...</section> by its data-host="..."
 * attribute, so per-host assertions (e.g. the clean-host gate) cannot be
 * confused by a DIFFERENT host's section elsewhere in the same document. */
static bool host_section_bounds(const char *html, size_t html_len, const char *host, const char **out_start,
                                  size_t *out_len) {
    char needle[128];
    int n = snprintf(needle, sizeof(needle), "data-host=\"%s\"", host);
    CYTADEL_ASSERT(n > 0 && (size_t)n < sizeof(needle));

    const char *start = find_bytes(html, html_len, needle);
    if (start == NULL) {
        return false;
    }
    size_t remaining = html_len - (size_t)(start - html);
    const char *end_marker = find_bytes(start, remaining, "</section>");
    if (end_marker == NULL) {
        return false;
    }
    *out_start = start;
    *out_len = (size_t)(end_marker - start) + strlen("</section>");
    return true;
}

/* Generic scoped-content extractor: finds `start_marker` in
 * hay[0..hay_len), then `end_marker` after it, and returns the byte range
 * strictly between them. This is the workhorse for per-site assertions
 * below -- every site's rendered value sits between a known, unique-enough
 * static marker (a literal template fragment this module itself writes,
 * e.g. "<p class=\"evidence\">Evidence: " or "title=\"") and a closing
 * delimiter (e.g. "</p>" or the attribute's closing '"'), so extracting
 * exactly that range lets an assertion target ONE interpolation site
 * without being confused by another occurrence of the same escaped
 * substring elsewhere in the document (the CSS selector / cover-page
 * table close tags that already tripped up two earlier whole-document
 * searches in this file's history). */
static bool extract_between(const char *hay, size_t hay_len, const char *start_marker, const char *end_marker,
                              const char **out_start, size_t *out_len) {
    const char *s = find_bytes(hay, hay_len, start_marker);
    if (s == NULL) {
        return false;
    }
    const char *content = s + strlen(start_marker);
    size_t remaining = hay_len - (size_t)(content - hay);
    const char *e = find_bytes(content, remaining, end_marker);
    if (e == NULL) {
        return false;
    }
    *out_start = content;
    *out_len = (size_t)(e - content);
    return true;
}

/* Extracts the scoped content between `start_marker` and `end_marker` in
 * hay[0..hay_len) and asserts it is byte-for-byte equal to `expected`.
 * Fails (via CYTADEL_ASSERT) if the markers are not found, if the
 * extracted range is too long for the internal buffer, or if the content
 * does not match -- covering both "the site never rendered at all" and
 * "the site rendered the wrong (unescaped/wrongly-escaped) bytes". */
static void assert_extracted_streq(const char *hay, size_t hay_len, const char *start_marker,
                                     const char *end_marker, const char *expected) {
    const char *content = NULL;
    size_t content_len = 0;
    CYTADEL_ASSERT(extract_between(hay, hay_len, start_marker, end_marker, &content, &content_len));
    char buf[512];
    CYTADEL_ASSERT(content_len < sizeof(buf));
    memcpy(buf, content, content_len);
    buf[content_len] = '\0';
    CYTADEL_ASSERT_STREQ(buf, expected);
}

/* ------------------------------------------------------------------ */
/* Test 1: basic structure -- cover, wordmark, findings render at all.  */
/* ------------------------------------------------------------------ */

static void test_basic_structure(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "10.0.0.0/24");

    insert_cve(handle, "CVE-2020-0001", 4);
    test_row_t r = {"10.0.0.5", 443, "https", "tls_weak_cipher", "CVE-2020-0001", 4,
                     "weak cipher RC4-MD5 offered", "Disable RC4 ciphers", 1, true, 0.9321, "confirmed",
                     DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "<!DOCTYPE html>"));
    /* Cover brand: the CYTADEL wordmark and the self-contained base64 logo
     * (data: URI, no external asset reference -- keeps the report single-file). */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "class=\"wordmark\">CYTADEL</div>"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "class=\"logo\""));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "src=\"data:image/jpeg;base64,"));
    /* Single-file guarantee: no external asset references anywhere. */
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "<link "));
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "http://"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "10.0.0.0/24"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "10.0.0.5"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "CVE-2020-0001"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "Critical"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "kev-badge"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "0.9321"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "Disable RC4 ciphers"));
    /* --cytadel-primary / --sev-critical custom properties present, with a
     * BRAND marker comment -- palette-swappable, never a hardcoded inline
     * color in the body markup. */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "--cytadel-primary:"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "--cytadel-accent:"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "--sev-critical:"));
    /* The palette stays swappable: a BRAND marker comment brackets the vars
     * (the exact prose can change; the marker + END BRAND must remain). */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "BRAND:"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "END BRAND"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "page-break-after: always"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* Invalid-arg / not-found status contract. */
static void test_invalid_arg_and_not_found(void) {
    cytadel_db_t *db = open_migrated_memory_db();

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(NULL, 1, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, 0, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, -5, &out), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, 999, &out), CYTADEL_REPORT_ERR_NOT_FOUND);
    CYTADEL_ASSERT_STREQ(cytadel_report_status_to_string(CYTADEL_REPORT_ERR_NOT_FOUND), "NOT_FOUND");
    cytadel_report_buf_free(&out);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 2: data-quality banner iff malformed_data_count > 0.            */
/* ------------------------------------------------------------------ */

static void test_gate2_data_quality_banner(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_with = create_scan(db, "192.168.1.0/24");
    set_malformed_data_count(handle, scan_with, 3);

    long long scan_without = create_scan(db, "192.168.2.0/24");
    /* malformed_data_count stays at its schema DEFAULT 0. */

    cytadel_report_buf_t out_with;
    cytadel_report_buf_init(&out_with);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_with, &out_with), CYTADEL_REPORT_OK);
    /* NOTE: the bare class name "data-quality-banner" also appears in the
     * <style> block's own CSS selector regardless of whether the banner
     * div is ever emitted -- assert on the actual rendered <div ...>
     * marker, not the class-name substring alone, or this assertion would
     * pass even with the banner deleted entirely. */
    CYTADEL_ASSERT(contains_bytes(out_with.data, out_with.len, "<div class=\"data-quality-banner\">"));
    CYTADEL_ASSERT(contains_bytes(out_with.data, out_with.len, "3 record(s) had malformed data"));
    cytadel_report_buf_free(&out_with);

    cytadel_report_buf_t out_without;
    cytadel_report_buf_init(&out_without);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_without, &out_without), CYTADEL_REPORT_OK);
    CYTADEL_ASSERT(!contains_bytes(out_without.data, out_without.len, "<div class=\"data-quality-banner\">"));
    cytadel_report_buf_free(&out_without);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 3(a): severity/kev/epss are SNAPSHOTS, never re-joined to cves. */
/* ------------------------------------------------------------------ */

static void test_gate3_snapshot_not_live_joined(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "203.0.113.10");

    insert_cve(handle, "CVE-2021-9999", 4); /* Critical at insert time */
    test_row_t r = {"203.0.113.10", 22, "ssh", "ssh_known_vulnerable_openssh", "CVE-2021-9999", 4,
                     "OpenSSH_7.2p2", NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    /* The live `cves` row is later revised downward -- the report must
     * still reflect what scan_results captured at detection time. */
    update_cve_severity(handle, "CVE-2021-9999", 0);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "finding sev-4"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "sev-count-critical\">Critical: 1"));
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "sev-count-info\">Info: 1"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 3(b): undetermined always rendered as its own visible state.   */
/* ------------------------------------------------------------------ */

static void test_gate3_undetermined_visible(void) {
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
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "Could not determine -- manual review needed"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "CVE-2022-1234"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "undetermined-finding"));
    /* Summary count is nonzero, not silently folded into not_affected. */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "Undetermined (manual review needed): 1"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "Not affected (ruled out, audit trail): 0"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Gate 3(c): clean-host logic.                                        */
/* ------------------------------------------------------------------ */

static void test_gate3_clean_host_logic(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "10.10.0.0/24");

    insert_cve(handle, "CVE-2023-0001", 2);
    insert_cve(handle, "CVE-2023-0002", 1);

    /* Host A: ONLY an undetermined row -- must NEVER render "no
     * vulnerabilities found" for this host. */
    test_row_t undetermined_only = {"10.10.0.5", 80, "http", "http_missing_hsts", "CVE-2023-0001", 2,
                                      "no Strict-Transport-Security header (ambiguous scheme)", NULL, 0, false,
                                      0.0, "undetermined", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &undetermined_only);

    /* Host B: ONLY a not_affected row -- confirmed == 0 AND undetermined ==
     * 0, so "no vulnerabilities found" IS permitted, alongside the
     * not_affected audit-trail count. */
    test_row_t not_affected_only = {"10.10.0.9", 21, "ftp", "ftp_cleartext_protocol", "CVE-2023-0002", 1,
                                      "FTP banner did not match any vulnerable range", NULL, 0, false, 0.0,
                                      "not_affected", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &not_affected_only);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    const char *host_a_start = NULL;
    size_t host_a_len = 0;
    CYTADEL_ASSERT(host_section_bounds(out.data, out.len, "10.10.0.5", &host_a_start, &host_a_len));
    CYTADEL_ASSERT(!contains_bytes(host_a_start, host_a_len, "No vulnerabilities found."));
    CYTADEL_ASSERT(contains_bytes(host_a_start, host_a_len, "No confirmed vulnerabilities"));
    CYTADEL_ASSERT(contains_bytes(host_a_start, host_a_len, "1 check(s) undetermined"));

    const char *host_b_start = NULL;
    size_t host_b_len = 0;
    CYTADEL_ASSERT(host_section_bounds(out.data, out.len, "10.10.0.9", &host_b_start, &host_b_len));
    CYTADEL_ASSERT(contains_bytes(host_b_start, host_b_len, "No vulnerabilities found."));
    CYTADEL_ASSERT(contains_bytes(host_b_start, host_b_len, "1 check(s) ruled not affected"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* Per-interpolation-site escaper proofs (context-discriminating         */
/* payloads -- a bare <script> would NOT discriminate between escapers). */
/* ------------------------------------------------------------------ */

/* ATTR site: evidence rendered inside title="...". A `"` in evidence must
 * become &quot; -- with html_body (which does NOT escape '"') at this site
 * instead, the raw quote would break out of the attribute.
 *
 * REVERT-PROOF (performed and reverted; see this milestone's write-up for
 * the full command transcript): with the `cytadel_escape_html_attr(out,
 * row->evidence, ...)` call at this exact site (render_confirmed_card()'s
 * title="..." for the finding div) temporarily replaced by
 * `cytadel_escape_html_body(out, row->evidence, ...)`, this test's
 * `!contains_bytes(..., "title=\"x\" onmouseover=alert(1)")` assertion
 * FAILED -- the rebuilt binary rendered the raw, attribute-breaking
 * `title="x" onmouseover=alert(1)"` sequence verbatim (html_body does not
 * touch '"'). Reverted immediately after confirming the failure. */
static void test_attr_site_evidence_quote_breakout(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "172.16.0.0/24");

    insert_cve(handle, "CVE-2024-5555", 2);
    test_row_t r = {"172.16.0.20", 8080, "http", "http_headers", "CVE-2024-5555", 2,
                     "x\" onmouseover=alert(1)", NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* Correctly escaped form present: quote -> &quot; inside the title
     * attribute, breakout payload otherwise intact and inert as text. */
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "title=\"x&quot; onmouseover=alert(1)\""));
    /* The broken, un-escaped form must never appear. */
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "title=\"x\" onmouseover=alert(1)"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* URL site: cve_id used to build the NVD href. A "javascript:" value must
 * never survive into the emitted href="..." attribute VALUE specifically
 * (the SAME cve_id also legitimately appears, verbatim, inside the link's
 * title="..." tooltip -- a title is never navigated/executed by a browser,
 * so that occurrence is not itself a vulnerability and must not be
 * confused with the href site by this test's assertions).
 *
 * REVERT-PROOF (performed and reverted): with append_nvd_href_attr()'s
 * `cytadel_escape_url(&url_buf, cve_id, cve_id_len)` call temporarily
 * replaced by `cytadel_escape_html_body(&url_buf, cve_id, cve_id_len)`
 * (html_body touches neither ':' nor '/'), this test's
 * `!contains_bytes(href_start, href_len, "javascript:")` assertion FAILED --
 * the rebuilt binary emitted
 * `href="https://nvd.nist.gov/vuln/detail/javascript:alert(1)"` verbatim.
 * Reverted immediately after confirming the failure. */
static void test_url_site_cve_id_javascript_href(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "203.0.113.99");

    /* Deliberately bypassing cve_id_valid.h's grammar check (a raw insert,
     * as report.h's own threat model requires this module to assume) to
     * prove the escaper -- not upstream validation -- is what neutralizes
     * this. */
    insert_cve(handle, "javascript:alert(1)", 3);
    test_row_t r = {"203.0.113.99", 443, "https", "http_known_vulnerable_server", "javascript:alert(1)", 3,
                     "hostile cve_id field", NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* Scope the assertion to the href="..." attribute VALUE itself (not
     * the whole document, which also legitimately contains
     * "javascript:alert(1)" inside the unrelated title="..." tooltip). */
    const char *href_marker = find_bytes(out.data, out.len, "href=\"");
    CYTADEL_ASSERT(href_marker != NULL);
    const char *href_value_start = href_marker + strlen("href=\"");
    const char *href_value_end =
        find_bytes(href_value_start, out.len - (size_t)(href_value_start - out.data), "\"");
    CYTADEL_ASSERT(href_value_end != NULL);
    size_t href_value_len = (size_t)(href_value_end - href_value_start);

    CYTADEL_ASSERT(!contains_bytes(href_value_start, href_value_len, "javascript:"));
    char href_value_buf[128];
    CYTADEL_ASSERT(href_value_len < sizeof(href_value_buf));
    memcpy(href_value_buf, href_value_start, href_value_len);
    href_value_buf[href_value_len] = '\0';
    CYTADEL_ASSERT_STREQ(href_value_buf, "https://nvd.nist.gov/vuln/detail/#");

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* BODY site: evidence containing a <script> tag and a </td></tr> structure
 * break, rendered as visible text.
 *
 * REVERT-PROOF (performed and reverted): with the
 * `cytadel_escape_html_body(out, row->evidence, ...)` call at the
 * "<p class=\"evidence\">Evidence: " site in render_confirmed_card()
 * temporarily replaced by `cytadel_report_buf_append_lit(out,
 * row->evidence)` (a raw, unescaped append -- valid here only because
 * dup_column() NUL-terminates its copy and this payload has no embedded
 * NUL), this test's `!contains_bytes(..., "<script>alert(1)</script>")`
 * assertion FAILED -- the rebuilt binary emitted the literal, executable
 * `<script>alert(1)</script></td></tr>` sequence verbatim. Reverted
 * immediately after confirming the failure. */
static void test_body_site_evidence_script_and_table_break(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "10.20.30.0/24");

    insert_cve(handle, "CVE-2024-7777", 1);
    test_row_t r = {"10.20.30.40", 21, "ftp", "ftp_anonymous_banner_hint", "CVE-2024-7777", 1,
                     "<script>alert(1)</script></td></tr>", NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* Scope the assertion to the finding's own evidence paragraph -- the
     * cover page's <table class="meta"> template legitimately emits its
     * own literal "</td></tr>\n" closes for every metadata row, which a
     * whole-document search for that substring would otherwise always
     * (and incorrectly) match regardless of whether the escaper ran. */
    const char *marker = find_bytes(out.data, out.len, "<p class=\"evidence\">Evidence: ");
    CYTADEL_ASSERT(marker != NULL);
    const char *content_start = marker + strlen("<p class=\"evidence\">Evidence: ");
    const char *content_end = find_bytes(content_start, out.len - (size_t)(content_start - out.data), "</p>");
    CYTADEL_ASSERT(content_end != NULL);
    size_t content_len = (size_t)(content_end - content_start);

    CYTADEL_ASSERT(!contains_bytes(content_start, content_len, "<script>alert(1)</script>"));
    CYTADEL_ASSERT(!contains_bytes(content_start, content_len, "</td></tr>"));
    CYTADEL_ASSERT(contains_bytes(content_start, content_len,
                                    "&lt;script&gt;alert(1)&lt;/script&gt;&lt;/td&gt;&lt;/tr&gt;"));

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* EXHAUSTIVE per-site coverage (coordinator finding: 3 representative     */
/* sites is not the gate -- EVERY site must have its own hostile           */
/* discriminator and its own mutation-failing assertion). Payload         */
/* constants shared below; each is a real value that is actually reachable */
/* through this schema's own constraints (a field guarded by a CHECK        */
/* constraint gets a `_reject` justification test instead -- see the       */
/* dedicated test at the bottom of this section).                         */
/* ------------------------------------------------------------------ */

/* BODY-only payload: no attribute use anywhere for these fields, so a      */
/* plain script-tag/table-break string is a sufficient discriminator       */
/* (raw survival vs. entity-escaped). */
#define BODY_PAYLOAD "<script>alert(1)</script></td></tr>"
#define BODY_PAYLOAD_ESCAPED "&lt;script&gt;alert(1)&lt;/script&gt;&lt;/td&gt;&lt;/tr&gt;"

/* Combined payload for fields rendered in BOTH a BODY and an ATTR context
 * from the SAME value (host, evidence, plugin_id, and the confirmed
 * card's cve_id link+title): a '"' discriminates the attribute site
 * (html_attr escapes it, html_body does not) and a <script> tag
 * discriminates the body site (html_body/html_attr both escape '<'/'>',
 * json() would not -- see the mutation-sweep script for exactly which
 * wrong escaper is substituted at each site). */
#define COMBINED_PAYLOAD "<script>alert(1)</script>\" onmouseover=alert(2)"
#define COMBINED_BODY_ESCAPED "&lt;script&gt;alert(1)&lt;/script&gt;\" onmouseover=alert(2)"
#define COMBINED_ATTR_ESCAPED "&lt;script&gt;alert(1)&lt;/script&gt;&quot; onmouseover=alert(2)"

/* ---- Cover-page (scans row) BODY sites ---------------------------- */

static void test_cover_page_body_sites(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long scan_id = create_scan_full(db, BODY_PAYLOAD, BODY_PAYLOAD);
    set_scan_timestamps(handle, scan_id, BODY_PAYLOAD, BODY_PAYLOAD, BODY_PAYLOAD);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* Each cover row is scoped by its own preceding <th>Label</th><td>
     * marker -- five independent sites, five independent assertions. */
    assert_extracted_streq(out.data, out.len, "<th>Target</th><td>", "</td>", BODY_PAYLOAD_ESCAPED);
    assert_extracted_streq(out.data, out.len, "<th>Started</th><td>", "</td>", BODY_PAYLOAD_ESCAPED);
    assert_extracted_streq(out.data, out.len, "<th>Finished</th><td>", "</td>", BODY_PAYLOAD_ESCAPED);
    assert_extracted_streq(out.data, out.len, "<th>Authorized By</th><td>", "</td>", BODY_PAYLOAD_ESCAPED);
    assert_extracted_streq(out.data, out.len, "<th>Authorization Confirmed At</th><td>", "</td>",
                            BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- Non-injectable, CHECK-constrained cover-page fields ------------ */

/* `status` and `authorization_method` cannot carry a hostile payload: the
 * schema's own CHECK constraint (db-schema.md SS6) rejects any value
 * outside a small fixed enum, at the SQLite level, independent of any
 * application code. Proven here by attempting the exact same BODY_PAYLOAD
 * used everywhere else and asserting SQLite itself refuses the write
 * (SQLITE_CONSTRAINT) -- these two columns need no escaper-mutation proof
 * because no escaper-observable value can ever reach them. */
static void test_status_and_authorization_method_reject_hostile_values(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "reject-test");

    assert_column_rejects_value(handle, "UPDATE scans SET status = ? WHERE scan_id = ?;", BODY_PAYLOAD, scan_id);
    assert_column_rejects_value(handle, "UPDATE scans SET authorization_method = ? WHERE scan_id = ?;",
                                 BODY_PAYLOAD, scan_id);

    cytadel_db_close(db);
}

/* ---- host: ATTR (data-host) + BODY (h3 heading), same value ---------- */

static void test_host_attr_and_body_sites(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "host-site-scan");

    insert_cve(handle, "CVE-2025-0001", 2);
    test_row_t r = {COMBINED_PAYLOAD, 80, "http", "http_missing_hsts", "CVE-2025-0001", 2, "evidence text", NULL,
                     0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* ATTR site: data-host="...". */
    assert_extracted_streq(out.data, out.len, "data-host=\"", "\">", COMBINED_ATTR_ESCAPED);
    /* BODY site: <h3>Host: ...</h3>. */
    assert_extracted_streq(out.data, out.len, "<h3>Host: ", "</h3>", COMBINED_BODY_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- service: BODY-only, two independent call sites ------------------ */

/* Confirmed-card path: render_host_section()'s port-block header
 * (report_html.c's "<div class=\"port-block\">\n<h4>Port N (SERVICE)"). */
static void test_service_body_site_confirmed_port_header(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "service-confirmed-scan");

    insert_cve(handle, "CVE-2025-0002", 2);
    test_row_t r = {"10.30.0.1", 8080, BODY_PAYLOAD, "http_missing_hsts", "CVE-2025-0002", 2, "evidence text",
                     NULL, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "<h4>Port 8080 (", ")</h4>", BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* Undetermined-card path: render_undetermined_card()'s own port line -- the
 * site the coordinator's independent mutation review found UNCOVERED
 * (report_html.c line ~552, "<p class=\"port-line\">Port: N (SERVICE)"). */
static void test_service_body_site_undetermined_port_line(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "service-undetermined-scan");

    insert_cve(handle, "CVE-2025-0003", 2);
    test_row_t r = {"10.30.0.2", 8081, BODY_PAYLOAD, "http_missing_hsts", "CVE-2025-0003", 2, "evidence text",
                     NULL, 0, false, 0.0, "undetermined", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "<p class=\"port-line\">Port: 8081 (", ")</p>", BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- plugin_id: ATTR (data-plugin-id) + BODY ("Detected by") --------- */

static void test_plugin_id_attr_and_body_sites(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "plugin-id-scan");

    insert_cve(handle, "CVE-2025-0004", 2);
    test_row_t r = {"10.30.0.3", 8082, "http", COMBINED_PAYLOAD, "CVE-2025-0004", 2, "evidence text", NULL, 0,
                     false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* ATTR site: data-plugin-id="...". */
    assert_extracted_streq(out.data, out.len, "data-plugin-id=\"", "\">", COMBINED_ATTR_ESCAPED);
    /* BODY site: <p class="plugin">Detected by: .... */
    assert_extracted_streq(out.data, out.len, "<p class=\"plugin\">Detected by: ", "</p>", COMBINED_BODY_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- cve_id: ATTR (link title) + BODY (link text), confirmed card ---- */

static void test_cve_id_attr_and_body_sites_confirmed_link(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "cve-id-link-scan");

    /* This value has NO scheme grammar (starts with '<', not alpha), so
     * cytadel_escape_url() treats it as "clearly relative" and
     * percent-encodes it -- it does not exercise the URL site's own
     * scheme-rejection branch (that is test_url_site_cve_id_javascript_href
     * above, a separate, dedicated hostile value). This row exists purely
     * to prove the link's OWN title="..." attribute and visible link text
     * are independently escaped. */
    insert_cve(handle, COMBINED_PAYLOAD, 2);
    test_row_t r = {"10.30.0.4", 8083, "http", "http_missing_hsts", COMBINED_PAYLOAD, 2, "evidence text", NULL, 0,
                     false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* ATTR site: the link's own title="...". Scoped starting from "</a>"
     * backwards is awkward with this file's forward-only search helper, so
     * instead scope from the anchor tag onward (the link's title comes
     * after href="..." in document order) to skip past the div's own
     * (unrelated) title="..." attribute that precedes it. */
    const char *anchor = find_bytes(out.data, out.len, "<a href=\"");
    CYTADEL_ASSERT(anchor != NULL);
    size_t anchor_remaining = out.len - (size_t)(anchor - out.data);
    assert_extracted_streq(anchor, anchor_remaining, "\" title=\"", "\">", COMBINED_ATTR_ESCAPED);
    /* BODY site: the link's own visible text, between that title's closing
     * '>' and the "</a>" close. */
    assert_extracted_streq(anchor, anchor_remaining, "\">", "</a>", COMBINED_BODY_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- cve_id: BODY-only, undetermined card heading -------------------- */

static void test_cve_id_body_site_undetermined_heading(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "cve-id-undetermined-scan");

    insert_cve(handle, BODY_PAYLOAD, 2);
    test_row_t r = {"10.30.0.5", 8084, "http", "http_missing_hsts", BODY_PAYLOAD, 2, "evidence text", NULL, 0,
                     false, 0.0, "undetermined", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "\">\n<h5>", " <span class=\"badge undetermined-badge\">",
                            BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- evidence: ATTR (title) + BODY, undetermined card ---------------- */

static void test_evidence_attr_and_body_sites_undetermined(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "evidence-undetermined-scan");

    insert_cve(handle, "CVE-2025-0005", 2);
    test_row_t r = {"10.30.0.6", 8085, "http", "http_missing_hsts", "CVE-2025-0005", 2, COMBINED_PAYLOAD, NULL, 0,
                     false, 0.0, "undetermined", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    /* ATTR site: the undetermined finding div's own title="...". */
    assert_extracted_streq(out.data, out.len, "undetermined-finding\" title=\"", "\">", COMBINED_ATTR_ESCAPED);
    /* BODY site: <p class="evidence">Evidence: .... */
    assert_extracted_streq(out.data, out.len, "<p class=\"evidence\">Evidence: ", "</p>", COMBINED_BODY_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- remediation: BODY-only, confirmed card -------------------------- */

static void test_remediation_body_site(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "remediation-scan");

    insert_cve(handle, "CVE-2025-0006", 2);
    test_row_t r = {"10.30.0.7", 8086, "http", "http_missing_hsts", "CVE-2025-0006", 2, "evidence text",
                     BODY_PAYLOAD, 0, false, 0.0, "confirmed", DEFAULT_DETECTED_AT};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "<p class=\"remediation\">Remediation: ", "</p>",
                            BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

/* ---- detected_at: BODY-only, two independent call sites -------------- */

static void test_detected_at_body_site_confirmed(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "detected-at-confirmed-scan");

    insert_cve(handle, "CVE-2025-0007", 2);
    test_row_t r = {"10.30.0.8", 8087, "http", "http_missing_hsts", "CVE-2025-0007", 2, "evidence text", NULL, 0,
                     false, 0.0, "confirmed", BODY_PAYLOAD};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "<p class=\"detected-at\">Detected: ", "</p>", BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

static void test_detected_at_body_site_undetermined(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);
    long long scan_id = create_scan(db, "detected-at-undetermined-scan");

    insert_cve(handle, "CVE-2025-0008", 2);
    test_row_t r = {"10.30.0.9", 8088, "http", "http_missing_hsts", "CVE-2025-0008", 2, "evidence text", NULL, 0,
                     false, 0.0, "undetermined", BODY_PAYLOAD};
    insert_scan_result(handle, scan_id, &r);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT_EQ(cytadel_report_html(db, scan_id, &out), CYTADEL_REPORT_OK);

    assert_extracted_streq(out.data, out.len, "<p class=\"detected-at\">Detected: ", "</p>", BODY_PAYLOAD_ESCAPED);

    cytadel_report_buf_free(&out);
    cytadel_db_close(db);
}

int main(void) {
    test_basic_structure();
    test_invalid_arg_and_not_found();
    test_gate2_data_quality_banner();
    test_gate3_snapshot_not_live_joined();
    test_gate3_undetermined_visible();
    test_gate3_clean_host_logic();
    test_attr_site_evidence_quote_breakout();
    test_url_site_cve_id_javascript_href();
    test_body_site_evidence_script_and_table_break();

    /* Exhaustive per-site coverage (every remaining dynamic interpolation
     * site, each with its own context-discriminating hostile payload). */
    test_cover_page_body_sites();
    test_status_and_authorization_method_reject_hostile_values();
    test_host_attr_and_body_sites();
    test_service_body_site_confirmed_port_header();
    test_service_body_site_undetermined_port_line();
    test_plugin_id_attr_and_body_sites();
    test_cve_id_attr_and_body_sites_confirmed_link();
    test_cve_id_body_site_undetermined_heading();
    test_evidence_attr_and_body_sites_undetermined();
    test_remediation_body_site();
    test_detected_at_body_site_confirmed();
    test_detected_at_body_site_undetermined();

    CYTADEL_TEST_PASS();
}
