#include "cytadel_test.h"

#include "log.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static void test_level_from_string_round_trip(void) {
    cytadel_log_level_t lvl;

    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string("debug", &lvl), 0);
    CYTADEL_ASSERT_EQ(lvl, CYTADEL_LOG_DEBUG);

    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string("INFO", &lvl), 0);
    CYTADEL_ASSERT_EQ(lvl, CYTADEL_LOG_INFO);

    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string("Warn", &lvl), 0);
    CYTADEL_ASSERT_EQ(lvl, CYTADEL_LOG_WARN);

    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string("error", &lvl), 0);
    CYTADEL_ASSERT_EQ(lvl, CYTADEL_LOG_ERROR);

    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string("bogus", &lvl), -1);
    CYTADEL_ASSERT_EQ(cytadel_log_level_from_string(NULL, &lvl), -1);

    CYTADEL_ASSERT_STREQ(cytadel_log_level_to_string(CYTADEL_LOG_DEBUG), "DEBUG");
    CYTADEL_ASSERT_STREQ(cytadel_log_level_to_string(CYTADEL_LOG_ERROR), "ERROR");
}

static void test_timestamp_matches_iso8601_utc_ms(void) {
    /* Binding format per docs/contracts/db-schema.md: strict ISO-8601 UTC,
     * millisecond precision, explicit 'Z' suffix -- "YYYY-MM-DDTHH:MM:SS.sssZ"
     * (24 characters). */
    char buf[CYTADEL_ISO8601_BUF_LEN];
    int rc = cytadel_log_format_timestamp_utc(buf, sizeof(buf));
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ((long long)strlen(buf), 24);

    CYTADEL_ASSERT_EQ(buf[4], '-');
    CYTADEL_ASSERT_EQ(buf[7], '-');
    CYTADEL_ASSERT_EQ(buf[10], 'T');
    CYTADEL_ASSERT_EQ(buf[13], ':');
    CYTADEL_ASSERT_EQ(buf[16], ':');
    CYTADEL_ASSERT_EQ(buf[19], '.');
    CYTADEL_ASSERT_EQ(buf[23], 'Z');

    for (int i = 0; i < 23; i++) {
        if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) {
            continue;
        }
        CYTADEL_ASSERT(isdigit((unsigned char)buf[i]));
    }

    /* Buffer too small must fail cleanly, not overflow. */
    char tiny[4];
    CYTADEL_ASSERT_EQ(cytadel_log_format_timestamp_utc(tiny, sizeof(tiny)), -1);
    CYTADEL_ASSERT_EQ(cytadel_log_format_timestamp_utc(NULL, sizeof(buf)), -1);
}

static void test_level_filtering_writes_only_at_or_above_threshold(void) {
    const char *path = "test_log_filtering.tmp.log";
    remove(path);

    CYTADEL_ASSERT_EQ(cytadel_log_init(CYTADEL_LOG_WARN, path), 0);
    cytadel_log_debug("this debug line must not appear");
    cytadel_log_info("this info line must not appear");
    cytadel_log_warn("this warn line must appear");
    cytadel_log_error("this error line must appear");
    cytadel_log_close();

    FILE *f = fopen(path, "r");
    CYTADEL_ASSERT(f != NULL);

    char contents[4096];
    size_t n = fread(contents, 1, sizeof(contents) - 1, f);
    contents[n] = '\0';
    fclose(f);
    remove(path);

    CYTADEL_ASSERT(strstr(contents, "this debug line must not appear") == NULL);
    CYTADEL_ASSERT(strstr(contents, "this info line must not appear") == NULL);
    CYTADEL_ASSERT(strstr(contents, "this warn line must appear") != NULL);
    CYTADEL_ASSERT(strstr(contents, "this error line must appear") != NULL);
    CYTADEL_ASSERT(strstr(contents, "[WARN]") != NULL);
    CYTADEL_ASSERT(strstr(contents, "[ERROR]") != NULL);
}

static void test_audit_bypasses_level_filter(void) {
    /* W1 regression: the mandatory authorization audit trail (project policy
     * rule #2) must be recorded even when the operator has cranked
     * --log-level all the way up to error -- it is not just another
     * filterable INFO/ERROR line. */
    const char *path = "test_log_audit.tmp.log";
    remove(path);

    CYTADEL_ASSERT_EQ(cytadel_log_init(CYTADEL_LOG_ERROR, path), 0);
    cytadel_log_debug("this debug line must not appear");
    cytadel_log_info("this info line must not appear");
    cytadel_log_warn("this warn line must not appear");
    cytadel_log_audit("authorization confirmed: operator='tester' method=flag target='10.0.0.1'");
    cytadel_log_close();

    FILE *f = fopen(path, "r");
    CYTADEL_ASSERT(f != NULL);

    char contents[4096];
    size_t n = fread(contents, 1, sizeof(contents) - 1, f);
    contents[n] = '\0';
    fclose(f);
    remove(path);

    CYTADEL_ASSERT(strstr(contents, "this debug line must not appear") == NULL);
    CYTADEL_ASSERT(strstr(contents, "this info line must not appear") == NULL);
    CYTADEL_ASSERT(strstr(contents, "this warn line must not appear") == NULL);
    CYTADEL_ASSERT(strstr(contents, "authorization confirmed") != NULL);
    CYTADEL_ASSERT(strstr(contents, "[AUDIT]") != NULL);
}

static void test_sanitizer_escapes_control_bytes_in_message(void) {
    /* W2 regression: an untrusted value (e.g. target_spec from argv, or an
     * operator name from $USER) embedded in a log message via %s must not
     * be able to forge an extra, unattributed log line via a raw
     * '\n'/'\r', nor smuggle other control bytes through unescaped. */
    const char *path = "test_log_sanitize.tmp.log";
    remove(path);

    CYTADEL_ASSERT_EQ(cytadel_log_init(CYTADEL_LOG_INFO, path), 0);
    cytadel_log_info("value='%s' end", "line1\nline2\rline3\x01tab\ttail");
    cytadel_log_close();

    FILE *f = fopen(path, "r");
    CYTADEL_ASSERT(f != NULL);

    char contents[4096];
    size_t n = fread(contents, 1, sizeof(contents) - 1, f);
    contents[n] = '\0';
    fclose(f);
    remove(path);

    /* Exactly one line was written -- the embedded '\n'/'\r' did not
     * forge a second, unattributed line. */
    size_t newline_count = 0;
    for (size_t i = 0; i < n; i++) {
        if (contents[i] == '\n') {
            newline_count++;
        }
    }
    CYTADEL_ASSERT_EQ((long long)newline_count, 1);
    CYTADEL_ASSERT(strchr(contents, '\r') == NULL);
    CYTADEL_ASSERT(strchr(contents, '\t') == NULL);
    CYTADEL_ASSERT(strchr(contents, '\x01') == NULL);

    /* The control bytes were escaped, not silently dropped, and the
     * surrounding text is unaffected. */
    CYTADEL_ASSERT(strstr(contents, "\\x0a") != NULL);
    CYTADEL_ASSERT(strstr(contents, "\\x0d") != NULL);
    CYTADEL_ASSERT(strstr(contents, "\\x01") != NULL);
    CYTADEL_ASSERT(strstr(contents, "\\x09") != NULL);
    CYTADEL_ASSERT(strstr(contents, "line1") != NULL);
    CYTADEL_ASSERT(strstr(contents, "line2") != NULL);
    CYTADEL_ASSERT(strstr(contents, "line3") != NULL);
    CYTADEL_ASSERT(strstr(contents, "tail") != NULL);
}

int main(void) {
    test_level_from_string_round_trip();
    test_timestamp_matches_iso8601_utc_ms();
    test_level_filtering_writes_only_at_or_above_threshold();
    test_audit_bypasses_level_filter();
    test_sanitizer_escapes_control_bytes_in_message();
    CYTADEL_TEST_PASS();
}
