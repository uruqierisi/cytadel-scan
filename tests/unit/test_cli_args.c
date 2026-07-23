#include "cytadel_test.h"

#include "cli_args.h"

static void test_valid_parse(void) {
    char *argv[] = {
        (char *)"cytadel-scan",
        (char *)"--i-am-authorized",
        (char *)"--authorized-by", (char *)"alice",
        (char *)"--log-level", (char *)"debug",
        (char *)"192.168.1.0/24",
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT(args.has_i_am_authorized);
    CYTADEL_ASSERT_STREQ(args.authorized_by, "alice");
    CYTADEL_ASSERT_EQ(args.log_level, CYTADEL_LOG_DEBUG);
    CYTADEL_ASSERT(args.has_log_level);
    CYTADEL_ASSERT_STREQ(args.target_spec, "192.168.1.0/24");
}

static void test_defaults_when_flags_omitted(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"10.0.0.1" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT(!args.has_i_am_authorized);
    CYTADEL_ASSERT(args.authorized_by == NULL);
    CYTADEL_ASSERT_EQ(args.log_level, CYTADEL_LOG_INFO);
    CYTADEL_ASSERT(!args.has_log_level);
    CYTADEL_ASSERT(args.log_file == NULL);
}

static void test_unknown_flag_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--bogus-flag", (char *)"target" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_help_short_circuits(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--help" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_HELP);
    CYTADEL_ASSERT(args.want_help);
}

static void test_version_short_circuits(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--version" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_VERSION);
    CYTADEL_ASSERT(args.want_version);
}

static void test_missing_target_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--i-am-authorized" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_missing_flag_value_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--authorized-by" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_invalid_log_level_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--log-level", (char *)"verbose", (char *)"target" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_extra_positional_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"target-one", (char *)"target-two" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

/* Milestone 3: --targets-file alone (no positional target-spec) is valid. */
static void test_targets_file_alone_satisfies_target_requirement(void) {
    char *argv[] = {
        (char *)"cytadel-scan", (char *)"--i-am-authorized",
        (char *)"--targets-file", (char *)"hosts.txt",
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT(args.target_spec == NULL);
    CYTADEL_ASSERT_STREQ(args.targets_file, "hosts.txt");
}

/* Neither a positional target-spec nor --targets-file is still an error. */
static void test_missing_target_and_no_targets_file_is_rejected(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--i-am-authorized" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_max_workers_and_discovery_timeout_parse(void) {
    char *argv[] = {
        (char *)"cytadel-scan",
        (char *)"--max-workers", (char *)"16",
        (char *)"--discovery-timeout-ms", (char *)"250",
        (char *)"10.0.0.1",
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT_EQ(args.max_workers, 16);
    CYTADEL_ASSERT(args.has_max_workers);
    CYTADEL_ASSERT_EQ(args.discovery_timeout_ms, 250);
    CYTADEL_ASSERT(args.has_discovery_timeout_ms);
}

static void test_max_workers_defaults_when_omitted(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"10.0.0.1" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT_EQ(args.max_workers, CYTADEL_CLI_DEFAULT_MAX_WORKERS);
    CYTADEL_ASSERT(!args.has_max_workers);
    CYTADEL_ASSERT_EQ(args.discovery_timeout_ms, CYTADEL_CLI_DEFAULT_DISCOVERY_TIMEOUT_MS);
    CYTADEL_ASSERT(!args.has_discovery_timeout_ms);
}

static void test_max_workers_zero_is_rejected(void) {
    char *argv[] = {
        (char *)"cytadel-scan", (char *)"--max-workers", (char *)"0", (char *)"10.0.0.1",
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_max_workers_over_hard_cap_is_rejected(void) {
    char *argv[] = {
        (char *)"cytadel-scan", (char *)"--max-workers", (char *)"1025", (char *)"10.0.0.1",
    };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_ERROR);
}

static void test_no_banner_flag_parses(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"--no-banner", (char *)"10.0.0.1" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT(args.no_banner);
}

static void test_no_banner_defaults_false(void) {
    char *argv[] = { (char *)"cytadel-scan", (char *)"10.0.0.1" };
    int argc = (int)(sizeof(argv) / sizeof(argv[0]));

    cytadel_cli_args_t args;
    cytadel_cli_parse_status_t status = cytadel_cli_parse_args(argc, argv, &args);

    CYTADEL_ASSERT_EQ(status, CYTADEL_CLI_PARSE_OK);
    CYTADEL_ASSERT(!args.no_banner);
}

int main(void) {
    test_valid_parse();
    test_defaults_when_flags_omitted();
    test_unknown_flag_is_rejected();
    test_help_short_circuits();
    test_version_short_circuits();
    test_missing_target_is_rejected();
    test_missing_flag_value_is_rejected();
    test_invalid_log_level_is_rejected();
    test_extra_positional_is_rejected();
    test_targets_file_alone_satisfies_target_requirement();
    test_missing_target_and_no_targets_file_is_rejected();
    test_max_workers_and_discovery_timeout_parse();
    test_max_workers_defaults_when_omitted();
    test_max_workers_zero_is_rejected();
    test_max_workers_over_hard_cap_is_rejected();
    test_no_banner_flag_parses();
    test_no_banner_defaults_false();
    CYTADEL_TEST_PASS();
}
