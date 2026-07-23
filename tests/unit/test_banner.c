#define _POSIX_C_SOURCE 200809L /* dup()/dup2()/fileno()/unlink(), matching this project's own convention */

#include "banner.h"

#include <cJSON.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cytadel/core/version.h"
#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel_test.h"
#include "report_cmd.h"

/* This file proves the startup ASCII-art banner (src/cli/banner.h/.c):
 *
 *   1. cytadel_banner_should_print() -- the pure, injectable print/suppress
 *      DECISION -- is correct for all four (--no-banner, TTY) combinations.
 *   2. cytadel_banner_print() writes exactly the content asserted, to
 *      whatever stream it is handed -- never any other stream.
 *   3. A STRUCTURAL check that src/cli/banner.c's source text contains no
 *      reference to `stdout` at all (mirrors check_invoke_lua_close_
 *      invariant.c's own "read the source text" technique) -- the
 *      strongest possible proof that this module cannot ever write to
 *      stdout, independent of how it is called.
 *   4. The end-to-end integrity proof this task requires: with the banner
 *      genuinely printed (to stderr) AND `--format json`'s real report
 *      output going to the REAL process stdout (fd 1, exactly as
 *      `cytadel-scan report --format json` does when not given `-o`), the
 *      captured stdout bytes still parse as valid JSON via cJSON --
 *      proving no banner byte ever reached stdout.
 */

/* ------------------------------------------------------------------ */
/* 1. cytadel_banner_should_print() -- pure decision matrix.            */
/* ------------------------------------------------------------------ */

static void test_should_print_tty_and_not_suppressed(void) {
    CYTADEL_ASSERT(cytadel_banner_should_print(false, true));
}

static void test_should_print_suppressed_by_no_banner_flag_even_on_tty(void) {
    CYTADEL_ASSERT(!cytadel_banner_should_print(true, true));
}

static void test_should_print_suppressed_by_non_tty(void) {
    CYTADEL_ASSERT(!cytadel_banner_should_print(false, false));
}

static void test_should_print_suppressed_by_both(void) {
    CYTADEL_ASSERT(!cytadel_banner_should_print(true, false));
}

/* ------------------------------------------------------------------ */
/* 2. cytadel_banner_print() writes the expected content to ITS OWN     */
/*    stream argument only.                                            */
/* ------------------------------------------------------------------ */

static void test_print_null_stream_is_a_safe_no_op(void) {
    /* Must not crash/segfault -- a defensive guard, not a real production
     * call shape (main.c never passes NULL), but cheap to prove. */
    cytadel_banner_print(NULL);
}

static void test_print_writes_wordmark_and_version_to_given_stream(void) {
    FILE *f = tmpfile();
    CYTADEL_ASSERT(f != NULL);

    cytadel_banner_print(f);
    fflush(f);

    long size = ftell(f);
    CYTADEL_ASSERT(size > 0);
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    CYTADEL_ASSERT(buf != NULL);
    size_t read_len = fread(buf, 1, (size_t)size, f);
    buf[read_len] = '\0';
    fclose(f);

    /* The dot-matrix wordmark's widest row and the version tagline both
     * must be present verbatim. */
    CYTADEL_ASSERT(strstr(buf, "#####") != NULL);
    char version_marker[64];
    snprintf(version_marker, sizeof(version_marker), "Cytadel Scan v%s", CYTADEL_VERSION_STRING);
    CYTADEL_ASSERT(strstr(buf, version_marker) != NULL);

    free(buf);
}

/* ------------------------------------------------------------------ */
/* 3. Structural check: banner.c's own source text never mentions       */
/*    `stdout` -- see banner.h's own doc comment for why this is the     */
/*    strongest available guarantee against a future accidental stdout   */
/*    write creeping into this file.                                    */
/* ------------------------------------------------------------------ */

static void test_banner_source_never_references_stdout(void) {
#ifndef CYTADEL_BANNER_SRC_PATH
#error "CYTADEL_BANNER_SRC_PATH must be defined by CMake"
#endif
    FILE *f = fopen(CYTADEL_BANNER_SRC_PATH, "rb");
    CYTADEL_ASSERT(f != NULL);

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    CYTADEL_ASSERT(size > 0);
    rewind(f);

    char *buf = malloc((size_t)size + 1);
    CYTADEL_ASSERT(buf != NULL);
    size_t read_len = fread(buf, 1, (size_t)size, f);
    buf[read_len] = '\0';
    fclose(f);

    CYTADEL_ASSERT(strstr(buf, "stdout") == NULL);

    free(buf);
}

/* ------------------------------------------------------------------ */
/* 4. End-to-end proof: real process stdout stays valid JSON with the   */
/*    banner genuinely active (printed to real stderr) alongside it.    */
/* ------------------------------------------------------------------ */

static void make_temp_path(char *buf, size_t buf_len, const char *suffix) {
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    int n = snprintf(buf, buf_len, "%s/cytadel_test_banner_%d%s", tmpdir, (int)getpid(), suffix);
    CYTADEL_ASSERT(n > 0 && (size_t)n < buf_len);
}

/* Redirects the process's real stdio stream (`stream`, e.g. the actual
 * global `stdout` or `stderr`) to `capture_path`, returning a dup()'d copy
 * of the ORIGINAL underlying fd so the caller can restore it later via
 * restore_stream_capture(). This is the standard freopen()+dup()/dup2()
 * idiom for capturing a C standard stream's real output in-process (the
 * same technique test frameworks like GoogleTest's CaptureStdout() use). */
static int begin_stream_capture(FILE *stream, const char *capture_path) {
    fflush(stream);
    int saved_fd = dup(fileno(stream));
    CYTADEL_ASSERT(saved_fd != -1);
    FILE *reopened = freopen(capture_path, "w+b", stream);
    CYTADEL_ASSERT(reopened != NULL);
    return saved_fd;
}

/* Restores `stream`'s original destination (via the fd captured above),
 * then reads back everything written to `capture_path` while it was
 * redirected into `buf` (NUL-terminated), returning the byte count. */
static size_t end_stream_capture(FILE *stream, int saved_fd, const char *capture_path, char *buf,
                                  size_t buf_cap) {
    fflush(stream);
    CYTADEL_ASSERT(dup2(saved_fd, fileno(stream)) != -1);
    close(saved_fd);
    clearerr(stream);

    FILE *f = fopen(capture_path, "rb");
    CYTADEL_ASSERT(f != NULL);
    size_t read_len = fread(buf, 1, buf_cap - 1, f);
    fclose(f);
    buf[read_len] = '\0';
    return read_len;
}

static bool contains_bytes(const char *hay, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > hay_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static long long seed_scan_db(const char *db_path) {
    cytadel_db_t *seed_db = NULL;
    CYTADEL_ASSERT_EQ(cytadel_db_open(db_path, &seed_db), CYTADEL_DB_OK);
    CYTADEL_ASSERT_EQ(cytadel_db_migrate(seed_db), CYTADEL_DB_OK);
    long long scan_id = 0;
    CYTADEL_ASSERT_EQ(cytadel_scan_create(seed_db, "banner-test-target", "tester", "interactive", &scan_id),
                       CYTADEL_SCAN_PERSIST_OK);
    CYTADEL_ASSERT(scan_id > 0);
    cytadel_db_close(seed_db);
    return scan_id;
}

/* THE claim under test: `cytadel-scan report --format json` (no `-o`, so
 * cytadel_report_cmd_run() writes straight to the real `stdout` FILE*,
 * exactly like the production entry point) produces stdout bytes that
 * parse as valid JSON via cJSON, even with the banner genuinely printed
 * (to real stderr, captured and independently verified below) around it.
 *
 * REVERT-PROOF (performed manually, not committed): temporarily changing
 * cytadel_banner_print()'s `stream` argument to the literal `stdout` (i.e.
 * simulating the exact regression this test guards against) makes the
 * cJSON_ParseWithLength() assertion below fail immediately, because the
 * captured "stdout" bytes then begin with the banner's wordmark/tagline
 * text instead of `{`. */
static void test_report_json_stdout_stays_clean_with_banner_active(void) {
    char db_path[256];
    char stdout_capture_path[256];
    char stderr_capture_path[256];
    make_temp_path(db_path, sizeof(db_path), ".sqlite");
    make_temp_path(stdout_capture_path, sizeof(stdout_capture_path), ".stdout");
    make_temp_path(stderr_capture_path, sizeof(stderr_capture_path), ".stderr");
    unlink(db_path);
    unlink(stdout_capture_path);
    unlink(stderr_capture_path);

    long long scan_id = seed_scan_db(db_path);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_DB_PATH", db_path, 1), 0);

    cytadel_report_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.has_latest = true;
    args.format = CYTADEL_REPORT_CMD_FORMAT_JSON;
    args.output_path = NULL; /* -> real stdout, exactly like no `-o` on the CLI */

    int saved_stdout_fd = begin_stream_capture(stdout, stdout_capture_path);
    int saved_stderr_fd = begin_stream_capture(stderr, stderr_capture_path);

    /* The banner is genuinely "active": should_print() says yes (TTY
     * simulated true, --no-banner not given), and it is printed for real,
     * to stderr -- deliberately BEFORE the report run, mirroring main.c's
     * own ordering (banner printed once at process start, before any
     * scan/report work). */
    CYTADEL_ASSERT(cytadel_banner_should_print(false, true));
    cytadel_banner_print(stderr);

    int rc = cytadel_report_cmd_run(&args);

    char stdout_buf[8192];
    char stderr_buf[8192];
    size_t stdout_len = end_stream_capture(stdout, saved_stdout_fd, stdout_capture_path, stdout_buf,
                                            sizeof(stdout_buf));
    size_t stderr_len = end_stream_capture(stderr, saved_stderr_fd, stderr_capture_path, stderr_buf,
                                            sizeof(stderr_buf));

    CYTADEL_ASSERT_EQ(rc, EXIT_SUCCESS);

    /* The banner really did fire -- proven independently on the captured
     * stderr bytes, not just by should_print()'s return value above. */
    char version_marker[64];
    snprintf(version_marker, sizeof(version_marker), "Cytadel Scan v%s", CYTADEL_VERSION_STRING);
    CYTADEL_ASSERT(contains_bytes(stderr_buf, stderr_len, version_marker));

    /* The claim: stdout is still byte-clean, valid JSON. */
    cJSON *doc = cJSON_ParseWithLength(stdout_buf, stdout_len);
    CYTADEL_ASSERT(doc != NULL);
    CYTADEL_ASSERT(cJSON_IsObject(doc));
    cJSON *scan_obj = cJSON_GetObjectItemCaseSensitive(doc, "scan");
    CYTADEL_ASSERT(scan_obj != NULL);
    cJSON *scan_id_item = cJSON_GetObjectItemCaseSensitive(scan_obj, "scan_id");
    CYTADEL_ASSERT(scan_id_item != NULL);
    CYTADEL_ASSERT_EQ((long long)cJSON_GetNumberValue(scan_id_item), scan_id);
    cJSON_Delete(doc);

    /* Belt-and-suspenders: not one banner byte anywhere in stdout. */
    CYTADEL_ASSERT(!contains_bytes(stdout_buf, stdout_len, version_marker));
    CYTADEL_ASSERT(!contains_bytes(stdout_buf, stdout_len, "#####"));

    unlink(db_path);
    unlink(stdout_capture_path);
    unlink(stderr_capture_path);
    unsetenv("CYTADEL_DB_PATH");
}

int main(void) {
    test_should_print_tty_and_not_suppressed();
    test_should_print_suppressed_by_no_banner_flag_even_on_tty();
    test_should_print_suppressed_by_non_tty();
    test_should_print_suppressed_by_both();

    test_print_null_stream_is_a_safe_no_op();
    test_print_writes_wordmark_and_version_to_given_stream();

    test_banner_source_never_references_stdout();

    test_report_json_stdout_stays_clean_with_banner_active();

    CYTADEL_TEST_PASS();
}
