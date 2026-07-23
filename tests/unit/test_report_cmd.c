#define _POSIX_C_SOURCE 200809L /* setenv()/mkstemp(), matching this project's own convention */

#include "report_cmd.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel_test.h"

/* Milestone 8 slice 5: the `cytadel-scan report` CLI subcommand
 * (src/cli/report_cmd.c). The CLI ENTRY POINT itself
 * (cytadel_report_cmd_run(), and main.c's own argv[1] == "report"
 * dispatch) is not cleanly unit-testable in the usual sense -- it reads a
 * real environment variable and does real file I/O by design (that IS its
 * job) -- so per this milestone's own instructions, this file tests:
 *
 *   1. cytadel_report_cmd_parse_args() -- pure, no I/O at all.
 *   2. cytadel_report_cmd_resolve_scan_id() / cytadel_report_cmd_render() --
 *      the two DB-touching but env-var/file-I/O-free pieces, against an
 *      in-memory DB exactly like test_report_html.c/test_report_json.c do.
 *   3. cytadel_report_cmd_run() ITSELF, as a real integration test: a
 *      throwaway on-disk SQLite file (mkstemp) is used as CYTADEL_DB_PATH
 *      (setenv()), a throwaway output path is used for -o, and this test
 *      reads back the file cytadel_report_cmd_run() actually wrote --
 *      proving the full, real entry point (env var -> DB open/migrate ->
 *      resolve -> render -> write) works end to end, not just its pieces
 *      in isolation.
 */

/* ------------------------------------------------------------------ */
/* Fixture helpers (same shape as test_report_html.c/test_report_json.c). */
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

static void set_started_at(sqlite3 *handle, long long scan_id, const char *started_at) {
    sqlite3_stmt *stmt = NULL;
    CYTADEL_ASSERT_EQ(
        sqlite3_prepare_v2(handle, "UPDATE scans SET started_at = ? WHERE scan_id = ?;", -1, &stmt, NULL),
        SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_text(stmt, 1, started_at, -1, SQLITE_STATIC), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_bind_int64(stmt, 2, scan_id), SQLITE_OK);
    CYTADEL_ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
    sqlite3_finalize(stmt);
}

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
/* 1. cytadel_report_cmd_parse_args() -- pure argument validation.       */
/* ------------------------------------------------------------------ */

static void test_parse_latest_ok_defaults(void) {
    const char *argv[] = {"report", "--latest"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(2, (char *const *)argv, &args), CYTADEL_REPORT_CMD_PARSE_OK);
    CYTADEL_ASSERT(args.has_latest);
    CYTADEL_ASSERT(!args.has_scan_id);
    CYTADEL_ASSERT_EQ(args.format, CYTADEL_REPORT_CMD_FORMAT_HTML);
    CYTADEL_ASSERT(args.output_path == NULL);
}

static void test_parse_scan_id_json_output(void) {
    const char *argv[] = {"report", "--scan-id", "42", "--format", "json", "-o", "out.json"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(7, (char *const *)argv, &args), CYTADEL_REPORT_CMD_PARSE_OK);
    CYTADEL_ASSERT(!args.has_latest);
    CYTADEL_ASSERT(args.has_scan_id);
    CYTADEL_ASSERT_EQ(args.scan_id, 42);
    CYTADEL_ASSERT_EQ(args.format, CYTADEL_REPORT_CMD_FORMAT_JSON);
    CYTADEL_ASSERT_STREQ(args.output_path, "out.json");
}

static void test_parse_rejects_both_latest_and_scan_id(void) {
    const char *argv[] = {"report", "--latest", "--scan-id", "1"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(4, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_neither_latest_nor_scan_id(void) {
    const char *argv[] = {"report", "--format", "html"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_non_numeric_scan_id(void) {
    const char *argv[] = {"report", "--scan-id", "abc"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_zero_and_negative_scan_id(void) {
    const char *argv_zero[] = {"report", "--scan-id", "0"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv_zero, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);

    const char *argv_neg[] = {"report", "--scan-id", "-5"};
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv_neg, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_overflowing_scan_id(void) {
    const char *argv[] = {"report", "--scan-id", "999999999999999999999999999999"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_unrecognized_format(void) {
    const char *argv[] = {"report", "--latest", "--format", "xml"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(4, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_missing_flag_values(void) {
    const char *argv1[] = {"report", "--scan-id"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(2, (char *const *)argv1, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);

    const char *argv2[] = {"report", "--latest", "--format"};
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv2, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);

    const char *argv3[] = {"report", "--latest", "-o"};
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv3, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_rejects_unknown_flag(void) {
    const char *argv[] = {"report", "--latest", "--bogus"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(3, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_ERROR);
}

static void test_parse_help(void) {
    const char *argv[] = {"report", "--help"};
    cytadel_report_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(2, (char *const *)argv, &args),
                       CYTADEL_REPORT_CMD_PARSE_HELP);
    CYTADEL_ASSERT(args.want_help);
}

static void test_parse_null_out_args(void) {
    const char *argv[] = {"report", "--latest"};
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_parse_args(2, (char *const *)argv, NULL), CYTADEL_REPORT_CMD_PARSE_ERROR);
}

/* ------------------------------------------------------------------ */
/* 2. cytadel_report_cmd_resolve_scan_id() / cytadel_report_cmd_render(). */
/* ------------------------------------------------------------------ */

static void test_resolve_scan_id_explicit(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_scan_id = true;
    args.scan_id = 4242; /* need not exist -- resolve does not check existence */

    long long out_scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(db, &args, &out_scan_id), CYTADEL_REPORT_OK);
    CYTADEL_ASSERT_EQ(out_scan_id, 4242);

    cytadel_db_close(db);
}

static void test_resolve_scan_id_latest_empty_db(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;

    long long out_scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(db, &args, &out_scan_id), CYTADEL_REPORT_ERR_NOT_FOUND);

    cytadel_db_close(db);
}

static void test_resolve_scan_id_latest_picks_most_recent(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    sqlite3 *handle = cytadel_db_handle(db);

    long long older = create_scan(db, "older-scan");
    set_started_at(handle, older, "2020-01-01T00:00:00.000Z");
    long long newer = create_scan(db, "newer-scan");
    set_started_at(handle, newer, "2025-01-01T00:00:00.000Z");

    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;

    long long out_scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(db, &args, &out_scan_id), CYTADEL_REPORT_OK);
    CYTADEL_ASSERT_EQ(out_scan_id, newer);

    cytadel_db_close(db);
}

static void test_resolve_scan_id_invalid_args(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;
    long long out_scan_id = 0;

    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(NULL, &args, &out_scan_id), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(db, NULL, &out_scan_id), CYTADEL_REPORT_ERR_INVALID_ARG);
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_resolve_scan_id(db, &args, NULL), CYTADEL_REPORT_ERR_INVALID_ARG);

    cytadel_db_close(db);
}

static void test_render_dispatches_html_and_json(void) {
    cytadel_db_t *db = open_migrated_memory_db();
    long long scan_id = create_scan(db, "render-dispatch-scan");

    cytadel_report_buf_t html_out;
    cytadel_report_buf_init(&html_out);
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_render(db, scan_id, CYTADEL_REPORT_CMD_FORMAT_HTML, &html_out),
                       CYTADEL_REPORT_OK);
    CYTADEL_ASSERT(contains_bytes(html_out.data, html_out.len, "<!DOCTYPE html>"));
    cytadel_report_buf_free(&html_out);

    cytadel_report_buf_t json_out;
    cytadel_report_buf_init(&json_out);
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_render(db, scan_id, CYTADEL_REPORT_CMD_FORMAT_JSON, &json_out),
                       CYTADEL_REPORT_OK);
    CYTADEL_ASSERT(contains_bytes(json_out.data, json_out.len, "\"scan\":{"));
    CYTADEL_ASSERT(!contains_bytes(json_out.data, json_out.len, "<!DOCTYPE"));
    cytadel_report_buf_free(&json_out);

    /* A scan_id that names no row surfaces the same NOT_FOUND status
     * through either format. */
    cytadel_report_buf_t missing_out;
    cytadel_report_buf_init(&missing_out);
    CYTADEL_ASSERT_EQ(cytadel_report_cmd_render(db, 999999, CYTADEL_REPORT_CMD_FORMAT_HTML, &missing_out),
                       CYTADEL_REPORT_ERR_NOT_FOUND);
    cytadel_report_buf_free(&missing_out);

    cytadel_db_close(db);
}

/* ------------------------------------------------------------------ */
/* 3. cytadel_report_cmd_run() -- full integration: real env var, real     */
/* on-disk DB file, real output file.                                    */
/* ------------------------------------------------------------------ */

static void make_temp_path(char *buf, size_t buf_len, const char *suffix) {
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    int n = snprintf(buf, buf_len, "%s/cytadel_test_report_cmd_%d%s", tmpdir, (int)getpid(), suffix);
    CYTADEL_ASSERT(n > 0 && (size_t)n < buf_len);
}

static void test_run_end_to_end_json_to_file(void) {
    char db_path[256];
    char out_path[256];
    make_temp_path(db_path, sizeof(db_path), ".sqlite");
    make_temp_path(out_path, sizeof(out_path), ".json");
    unlink(db_path);
    unlink(out_path);

    /* Seed the on-disk DB exactly like a real scan would: open+migrate,
     * create one scan row -- via the SAME public API cytadel-scan itself
     * uses, not a hand-rolled fixture shortcut. */
    cytadel_db_t *seed_db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(db_path, &seed_db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(seed_db), CYTADEL_DB_OK);
    long long scan_id = create_scan(seed_db, "end-to-end-target");
    cytadel_db_close(seed_db);

    CYTADEL_ASSERT_EQ(setenv("CYTADEL_DB_PATH", db_path, 1), 0);

    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;
    args.format = CYTADEL_REPORT_CMD_FORMAT_JSON;
    args.output_path = out_path;

    int rc = cytadel_report_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_SUCCESS);

    FILE *f = fopen(out_path, "rb");
    CYTADEL_ASSERT(f != NULL);
    char content[4096];
    size_t read_len = fread(content, 1, sizeof(content) - 1, f);
    fclose(f);
    content[read_len] = '\0';

    char scan_id_marker[64];
    snprintf(scan_id_marker, sizeof(scan_id_marker), "\"scan_id\":%lld", scan_id);
    CYTADEL_ASSERT(contains_bytes(content, read_len, scan_id_marker));
    CYTADEL_ASSERT(contains_bytes(content, read_len, "\"target_spec\":\"end-to-end-target\""));

    unlink(db_path);
    unlink(out_path);
}

static void test_run_missing_db_path_env_fails(void) {
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_DB_PATH"), 0);

    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;
    args.format = CYTADEL_REPORT_CMD_FORMAT_HTML;

    int rc = cytadel_report_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);
}

static void test_run_nonexistent_scan_id_fails(void) {
    char db_path[256];
    make_temp_path(db_path, sizeof(db_path), "-noscan.sqlite");
    unlink(db_path);

    cytadel_db_t *seed_db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(db_path, &seed_db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(seed_db), CYTADEL_DB_OK);
    cytadel_db_close(seed_db);

    CYTADEL_ASSERT_EQ(setenv("CYTADEL_DB_PATH", db_path, 1), 0);

    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_scan_id = true;
    args.scan_id = 12345;
    args.format = CYTADEL_REPORT_CMD_FORMAT_HTML;

    int rc = cytadel_report_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);

    unlink(db_path);
}

int main(void) {
    test_parse_latest_ok_defaults();
    test_parse_scan_id_json_output();
    test_parse_rejects_both_latest_and_scan_id();
    test_parse_rejects_neither_latest_nor_scan_id();
    test_parse_rejects_non_numeric_scan_id();
    test_parse_rejects_zero_and_negative_scan_id();
    test_parse_rejects_overflowing_scan_id();
    test_parse_rejects_unrecognized_format();
    test_parse_rejects_missing_flag_values();
    test_parse_rejects_unknown_flag();
    test_parse_help();
    test_parse_null_out_args();

    test_resolve_scan_id_explicit();
    test_resolve_scan_id_latest_empty_db();
    test_resolve_scan_id_latest_picks_most_recent();
    test_resolve_scan_id_invalid_args();
    test_render_dispatches_html_and_json();

    test_run_end_to_end_json_to_file();
    test_run_missing_db_path_env_fails();
    test_run_nonexistent_scan_id_fails();

    CYTADEL_TEST_PASS();
}
