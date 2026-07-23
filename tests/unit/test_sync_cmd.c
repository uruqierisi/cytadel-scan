#define _POSIX_C_SOURCE 200809L /* setenv()/unsetenv()/dup2(), matching this project's own convention */

#include "sync_cmd.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/db/db.h"
#include "cytadel_test.h"
#include "log.h" /* CYTADEL_ISO8601_BUF_LEN -- reachable transitively via `cytadel`'s
                   * own public include directory, same as main.c/report_cmd.c. */

/* M9 Phase 4a: the `cytadel-scan sync` CLI subcommand (src/cli/sync_cmd.c).
 * Mirrors test_report_cmd.c's own split -- this file covers:
 *
 *   1. cytadel_sync_cmd_parse_args() -- pure, no I/O.
 *   2. cytadel_sync_cmd_resolve_db_path() / cytadel_sync_cmd_resolve_now() /
 *      cytadel_sync_cmd_build_fetch_config() -- the config-build/now-
 *      resolution logic, independent of main() and of any real DB or
 *      network I/O (unlike report_cmd's resolve_scan_id()/render(), none of
 *      these three genuinely need an open DB -- see sync_cmd.h's own
 *      top-of-file comment for why no cytadel_db_t* appears in any of their
 *      signatures).
 *   3. cytadel_sync_cmd_run() -- the mandatory-DB posture (a bad/absent DB
 *      path fails cleanly, before ANY network I/O is ever attempted) and a
 *      full, real end-to-end run against an unreachable loopback address
 *      (a closed port this test itself finds -- deterministic "connection
 *      refused", no live network, no libcurl retry/backoff re-tested here:
 *      that whole class is nvd_fetch.c's/nvd_sync.c's/nvd_catchup.c's own
 *      test suites' job, not this file's).
 *   4. Secret hygiene: a structural check that sync_cmd.c/.h's own source
 *      text never references the NVD key's environment-variable name at
 *      all (it has no business reading it -- nvd_fetch.c is the only
 *      module that ever does), plus a behavioral belt-and-suspenders check
 *      that a full cytadel_sync_cmd_run() invocation, with a sentinel key
 *      value set in the environment, never emits that value to stdout/
 *      stderr.
 */

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static void make_temp_path(char *buf, size_t buf_len, const char *suffix) {
    const char *tmpdir = getenv("TMPDIR");
    if (tmpdir == NULL || tmpdir[0] == '\0') {
        tmpdir = "/tmp";
    }
    int n = snprintf(buf, buf_len, "%s/cytadel_test_sync_cmd_%d%s", tmpdir, (int)getpid(), suffix);
    CYTADEL_ASSERT(n > 0 && (size_t)n < buf_len);
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

/* Binds an ephemeral loopback port, reads back which port the kernel
 * assigned, then closes the socket without ever listen()-ing on it -- the
 * kernel will not reassign that exact port to anything else for the very
 * short window before this test connects to it, so a subsequent connect()
 * there deterministically fails with ECONNREFUSED (ICMP port-unreachable
 * territory), fast, with no real network access and no fixture server of
 * our own to run (that would just be re-testing nvd_fetch.c/nvd_sync.c's
 * own transport, which this file explicitly does not do). */
static uint16_t find_unused_loopback_port(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &blen) == 0);
    uint16_t port = ntohs(bound.sin_port);
    close(fd);
    return port;
}

/* ------------------------------------------------------------------ */
/* 1. cytadel_sync_cmd_parse_args() -- pure argument validation.        */
/* ------------------------------------------------------------------ */

static void test_parse_defaults_ok(void) {
    const char *argv[] = {"sync"};
    cytadel_sync_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(1, (char *const *)argv, &args), CYTADEL_SYNC_CMD_PARSE_OK);
    CYTADEL_ASSERT(args.db_path == NULL);
    CYTADEL_ASSERT(args.now_override == NULL);
    CYTADEL_ASSERT(!args.want_help);
}

static void test_parse_db_and_now(void) {
    const char *argv[] = {"sync", "--db", "/tmp/x.sqlite", "--now", "2025-06-01T00:00:00.000Z"};
    cytadel_sync_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(5, (char *const *)argv, &args), CYTADEL_SYNC_CMD_PARSE_OK);
    CYTADEL_ASSERT_STREQ(args.db_path, "/tmp/x.sqlite");
    CYTADEL_ASSERT_STREQ(args.now_override, "2025-06-01T00:00:00.000Z");
}

static void test_parse_help_long_and_short(void) {
    const char *argv1[] = {"sync", "--help"};
    cytadel_sync_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(2, (char *const *)argv1, &args), CYTADEL_SYNC_CMD_PARSE_HELP);
    CYTADEL_ASSERT(args.want_help);

    const char *argv2[] = {"sync", "-h"};
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(2, (char *const *)argv2, &args), CYTADEL_SYNC_CMD_PARSE_HELP);
    CYTADEL_ASSERT(args.want_help);
}

static void test_parse_rejects_unknown_flag(void) {
    const char *argv[] = {"sync", "--bogus"};
    cytadel_sync_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(2, (char *const *)argv, &args), CYTADEL_SYNC_CMD_PARSE_ERROR);
}

static void test_parse_rejects_missing_flag_values(void) {
    const char *argv1[] = {"sync", "--db"};
    cytadel_sync_cmd_args_t args;
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(2, (char *const *)argv1, &args), CYTADEL_SYNC_CMD_PARSE_ERROR);

    const char *argv2[] = {"sync", "--now"};
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(2, (char *const *)argv2, &args), CYTADEL_SYNC_CMD_PARSE_ERROR);
}

static void test_parse_null_out_args(void) {
    const char *argv[] = {"sync"};
    CYTADEL_ASSERT_EQ(cytadel_sync_cmd_parse_args(1, (char *const *)argv, NULL), CYTADEL_SYNC_CMD_PARSE_ERROR);
}

/* ------------------------------------------------------------------ */
/* 2. resolve_db_path() / resolve_now() / build_fetch_config().          */
/* ------------------------------------------------------------------ */

static void test_resolve_db_path_explicit_wins_over_env(void) {
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_DB_PATH", "/env/path.sqlite", 1), 0);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.db_path = "/explicit/path.sqlite";

    const char *out = NULL;
    CYTADEL_ASSERT(cytadel_sync_cmd_resolve_db_path(&args, &out));
    CYTADEL_ASSERT_STREQ(out, "/explicit/path.sqlite");

    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_DB_PATH"), 0);
}

static void test_resolve_db_path_falls_back_to_env(void) {
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_DB_PATH", "/env/only.sqlite", 1), 0);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));

    const char *out = NULL;
    CYTADEL_ASSERT(cytadel_sync_cmd_resolve_db_path(&args, &out));
    CYTADEL_ASSERT_STREQ(out, "/env/only.sqlite");

    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_DB_PATH"), 0);
}

static void test_resolve_db_path_neither_given_fails(void) {
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_DB_PATH"), 0);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));

    const char *out = NULL;
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_db_path(&args, &out));
}

static void test_resolve_db_path_invalid_args(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    const char *out = NULL;
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_db_path(NULL, &out));
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_db_path(&args, NULL));
}

static void test_resolve_now_honors_override(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.now_override = "1999-12-31T23:59:59.999Z";

    char buf[CYTADEL_ISO8601_BUF_LEN];
    const char *now = NULL;
    CYTADEL_ASSERT(cytadel_sync_cmd_resolve_now(&args, buf, sizeof(buf), &now));
    CYTADEL_ASSERT_STREQ(now, "1999-12-31T23:59:59.999Z");
    /* Proves this is a BORROW of args->now_override, not a copy through
     * buf -- the exact "now must be injectable" property this milestone's
     * task brief requires being proven, not merely asserted in a comment. */
    CYTADEL_ASSERT(now == args.now_override);
}

static void test_resolve_now_defaults_to_wallclock(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));

    char buf[CYTADEL_ISO8601_BUF_LEN];
    const char *now = NULL;
    CYTADEL_ASSERT(cytadel_sync_cmd_resolve_now(&args, buf, sizeof(buf), &now));
    CYTADEL_ASSERT(now == buf);
    /* Strict ISO-8601 UTC shape: "YYYY-MM-DDTHH:MM:SS.sssZ" (24 chars). */
    size_t len = strlen(now);
    CYTADEL_ASSERT_EQ(len, 24);
    CYTADEL_ASSERT_EQ(now[4], '-');
    CYTADEL_ASSERT_EQ(now[7], '-');
    CYTADEL_ASSERT_EQ(now[10], 'T');
    CYTADEL_ASSERT_EQ(now[13], ':');
    CYTADEL_ASSERT_EQ(now[16], ':');
    CYTADEL_ASSERT_EQ(now[19], '.');
    CYTADEL_ASSERT_EQ(now[23], 'Z');
}

static void test_resolve_now_rejects_undersized_buffer(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));

    char tiny[4];
    const char *now = NULL;
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_now(&args, tiny, sizeof(tiny), &now));
}

static void test_resolve_now_invalid_args(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    char buf[CYTADEL_ISO8601_BUF_LEN];
    const char *now = NULL;
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_now(NULL, buf, sizeof(buf), &now));
    CYTADEL_ASSERT(!cytadel_sync_cmd_resolve_now(&args, buf, sizeof(buf), NULL));
}

static void test_build_fetch_config_default_base_url(void) {
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_API_URL"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_MAX_RETRIES"), 0); /* default assertion below needs it unset */

    cytadel_nvd_fetch_config_t cfg;
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_STREQ(cfg.base_url, CYTADEL_NVD_FETCH_DEFAULT_BASE_URL);

    /* Every other field must match cytadel_nvd_fetch_config_init_default()'s
     * own production defaults verbatim -- this command must not silently
     * diverge from that module's own chosen values. */
    cytadel_nvd_fetch_config_t expected;
    cytadel_nvd_fetch_config_init_default(&expected);
    CYTADEL_ASSERT_EQ(cfg.results_per_page, expected.results_per_page);
    CYTADEL_ASSERT_EQ(cfg.connect_timeout_sec, expected.connect_timeout_sec);
    CYTADEL_ASSERT_EQ(cfg.total_timeout_sec, expected.total_timeout_sec);
    CYTADEL_ASSERT_EQ(cfg.max_retries, expected.max_retries);
    CYTADEL_ASSERT_EQ(cfg.max_response_bytes, expected.max_response_bytes);
}

static void test_build_fetch_config_honors_url_override(void) {
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_API_URL", "https://mirror.example.internal/cves/2.0", 1), 0);

    cytadel_nvd_fetch_config_t cfg;
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_STREQ(cfg.base_url, "https://mirror.example.internal/cves/2.0");

    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_API_URL"), 0);
}

/* The operator retry knob: honored when valid, clamped to the cap, and a
 * garbage/negative value is ignored (built-in default kept) rather than
 * silently mis-tuning the sync. */
static void test_build_fetch_config_honors_max_retries_override(void) {
    cytadel_nvd_fetch_config_t cfg;
    cytadel_nvd_fetch_config_t def;
    cytadel_nvd_fetch_config_init_default(&def);

    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "0", 1), 0);
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_EQ(cfg.max_retries, 0);

    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "2", 1), 0);
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_EQ(cfg.max_retries, 2);

    /* Absurd value clamps to the cap -- never an unbounded retry storm. */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "100000", 1), 0);
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT(cfg.max_retries > 0 && cfg.max_retries <= 20);

    /* Non-numeric and negative are ignored -> built-in default preserved. */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "not-a-number", 1), 0);
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_EQ(cfg.max_retries, def.max_retries);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "-3", 1), 0);
    cytadel_sync_cmd_build_fetch_config(&cfg);
    CYTADEL_ASSERT_EQ(cfg.max_retries, def.max_retries);

    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_MAX_RETRIES"), 0);
}

static void test_build_fetch_config_null_is_safe(void) {
    cytadel_sync_cmd_build_fetch_config(NULL); /* must not crash */
}

/* ------------------------------------------------------------------ */
/* 3. cytadel_sync_cmd_run() -- mandatory-DB posture + full wiring.      */
/* ------------------------------------------------------------------ */

static void test_run_missing_db_path_fails_cleanly(void) {
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_DB_PATH"), 0);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));

    int rc = cytadel_sync_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);
}

static void test_run_unopenable_db_path_fails_cleanly(void) {
    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    /* A path inside a directory that does not exist -- sqlite3_open_v2()
     * itself must fail; no network I/O is ever reachable from here. */
    args.db_path = "/definitely/does/not/exist/cytadel-sync-test.sqlite";

    int rc = cytadel_sync_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);
}

static void test_run_null_args_fails_cleanly(void) {
    int rc = cytadel_sync_cmd_run(NULL);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);
}

/* Full, real cytadel_sync_cmd_run() invocation: a real (in-memory) DB is
 * opened+migrated, the fetch config is built with a real env override, and
 * `now` is injected via --now -- every piece of real production wiring runs
 * except the actual network transfer, which fails immediately and
 * deterministically (connection refused on a loopback port nothing is
 * listening on) rather than by pointing at any live server. This is what
 * proves the pieces above are wired together correctly end to end, without
 * this file re-testing libcurl's own retry/backoff/timeout behavior (that
 * is nvd_fetch.c's/nvd_sync.c's/nvd_catchup.c's own test suites' job). */
static void test_run_end_to_end_wiring_no_network(void) {
    uint16_t port = find_unused_loopback_port();
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u", (unsigned)port);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_API_URL", url, 1), 0);
    /* This test exercises the WIRING, not retry/backoff timing -- a refused
     * connection is now a retryable transport error, so pin retries to 0 (via
     * the same operator env knob build_fetch_config honors) to keep it fast and
     * deterministic. Retry behavior itself is covered by test_nvd_catchup.c. */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "0", 1), 0);
    /* sync now refreshes all three feeds; KEV/EPSS default to real
     * cisa.gov/first.org URLs, so point them at the same dead loopback port to
     * keep this wiring test fully offline and fast. */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_KEV_URL", url, 1), 0);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_EPSS_URL", url, 1), 0);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.db_path = ":memory:";
    args.now_override = "2000-01-01T00:00:00.000Z";

    int rc = cytadel_sync_cmd_run(&args);
    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE); /* connection refused -> feeds fail */

    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_API_URL"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_MAX_RETRIES"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_KEV_URL"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_EPSS_URL"), 0);
}

/* ------------------------------------------------------------------ */
/* 4. Secret hygiene.                                                    */
/* ------------------------------------------------------------------ */

static char *read_whole_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    CYTADEL_ASSERT(f != NULL);
    CYTADEL_ASSERT(fseek(f, 0, SEEK_END) == 0);
    long size = ftell(f);
    CYTADEL_ASSERT(size >= 0);
    CYTADEL_ASSERT(fseek(f, 0, SEEK_SET) == 0);
    char *buf = malloc((size_t)size + 1);
    CYTADEL_ASSERT(buf != NULL);
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[n] = '\0';
    *out_len = n;
    return buf;
}

/* Structural check (mirrors check_invoke_lua_close_invariant.c's own "read
 * the real source text, don't just trust a comment" approach): sync_cmd.c
 * and sync_cmd.h's own source text must never mention the NVD API key's
 * environment-variable name at all -- it has no business reading it, that
 * stays strictly inside nvd_fetch.c (include/cytadel/net/nvd_fetch.h's own
 * "SECRET HYGIENE" contract). This is a structural, not a comment-only,
 * property: sync_cmd's own comments (see sync_cmd.h's top-of-file note)
 * were deliberately written to never spell out that name either, so this
 * check has nothing to explicitly except out. */
static void test_source_never_references_api_key_env_var(void) {
    size_t len_c = 0, len_h = 0;
    char *src_c = read_whole_file(CYTADEL_SYNC_CMD_SRC_DIR "/sync_cmd.c", &len_c);
    char *src_h = read_whole_file(CYTADEL_SYNC_CMD_SRC_DIR "/sync_cmd.h", &len_h);

    CYTADEL_ASSERT(!contains_bytes(src_c, len_c, "NVD_API_KEY"));
    CYTADEL_ASSERT(!contains_bytes(src_h, len_h, "NVD_API_KEY"));
    /* Also never reads any generic "API_KEY"-shaped variable of its own --
     * belt-and-suspenders against a differently-named future key var. */
    CYTADEL_ASSERT(!contains_bytes(src_c, len_c, "getenv(\"NVD"));

    free(src_c);
    free(src_h);
}

/* Behavioral belt-and-suspenders: with a sentinel key VALUE set in the
 * environment, a full cytadel_sync_cmd_run() invocation (same
 * no-real-network shape as test_run_end_to_end_wiring_no_network() above)
 * must never emit that value to stdout or stderr. */
static void test_run_never_leaks_api_key_value(void) {
    const char *sentinel = "CYTADEL-TEST-SENTINEL-KEY-DO-NOT-LEAK";
    CYTADEL_ASSERT_EQ(setenv("NVD_API_KEY", sentinel, 1), 0);

    uint16_t port = find_unused_loopback_port();
    char url[64];
    snprintf(url, sizeof(url), "http://127.0.0.1:%u", (unsigned)port);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_API_URL", url, 1), 0);
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_NVD_MAX_RETRIES", "0", 1), 0); /* fail fast; see wiring test */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_KEV_URL", url, 1), 0);         /* keep all three feeds offline */
    CYTADEL_ASSERT_EQ(setenv("CYTADEL_EPSS_URL", url, 1), 0);

    char out_path[256];
    make_temp_path(out_path, sizeof(out_path), "-capture.txt");
    unlink(out_path);

    fflush(stdout);
    fflush(stderr);
    int saved_stdout_fd = dup(STDOUT_FILENO);
    CYTADEL_ASSERT(saved_stdout_fd >= 0);
    int saved_stderr_fd = dup(STDERR_FILENO);
    CYTADEL_ASSERT(saved_stderr_fd >= 0);

    int capture_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    CYTADEL_ASSERT(capture_fd >= 0);
    CYTADEL_ASSERT(dup2(capture_fd, STDOUT_FILENO) >= 0);
    CYTADEL_ASSERT(dup2(capture_fd, STDERR_FILENO) >= 0);
    close(capture_fd);

    cytadel_sync_cmd_args_t args;
    memset(&args, 0, sizeof(args));
    args.db_path = ":memory:";
    args.now_override = "2000-01-01T00:00:00.000Z";
    int rc = cytadel_sync_cmd_run(&args);

    fflush(stdout);
    fflush(stderr);
    CYTADEL_ASSERT(dup2(saved_stdout_fd, STDOUT_FILENO) >= 0);
    CYTADEL_ASSERT(dup2(saved_stderr_fd, STDERR_FILENO) >= 0);
    close(saved_stdout_fd);
    close(saved_stderr_fd);

    CYTADEL_ASSERT_EQ(rc, EXIT_FAILURE);

    size_t len = 0;
    char *content = read_whole_file(out_path, &len);
    CYTADEL_ASSERT(!contains_bytes(content, len, sentinel));
    free(content);

    unlink(out_path);
    CYTADEL_ASSERT_EQ(unsetenv("NVD_API_KEY"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_API_URL"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_NVD_MAX_RETRIES"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_KEV_URL"), 0);
    CYTADEL_ASSERT_EQ(unsetenv("CYTADEL_EPSS_URL"), 0);
}

int main(void) {
    test_parse_defaults_ok();
    test_parse_db_and_now();
    test_parse_help_long_and_short();
    test_parse_rejects_unknown_flag();
    test_parse_rejects_missing_flag_values();
    test_parse_null_out_args();

    test_resolve_db_path_explicit_wins_over_env();
    test_resolve_db_path_falls_back_to_env();
    test_resolve_db_path_neither_given_fails();
    test_resolve_db_path_invalid_args();

    test_resolve_now_honors_override();
    test_resolve_now_defaults_to_wallclock();
    test_resolve_now_rejects_undersized_buffer();
    test_resolve_now_invalid_args();

    test_build_fetch_config_default_base_url();
    test_build_fetch_config_honors_url_override();
    test_build_fetch_config_honors_max_retries_override();
    test_build_fetch_config_null_is_safe();

    test_run_missing_db_path_fails_cleanly();
    test_run_unopenable_db_path_fails_cleanly();
    test_run_null_args_fails_cleanly();
    test_run_end_to_end_wiring_no_network();

    test_source_never_references_api_key_env_var();
    test_run_never_leaks_api_key_value();

    CYTADEL_TEST_PASS();
}
