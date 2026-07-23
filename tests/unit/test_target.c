#include "cytadel_test.h"

#include "cytadel/net/target.h"

static void test_valid_ipv4_literal(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status = cytadel_target_parse("127.0.0.1", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_OK);
    CYTADEL_ASSERT_STREQ(target.host, "127.0.0.1");
    CYTADEL_ASSERT_STREQ(target.ip, "127.0.0.1");
}

static void test_valid_hostname_resolves(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status = cytadel_target_parse("localhost", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_OK);
    CYTADEL_ASSERT_STREQ(target.host, "localhost");
    CYTADEL_ASSERT_STREQ(target.ip, "127.0.0.1");
}

static void test_cidr_is_rejected_as_multi(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status =
        cytadel_target_parse("192.168.1.0/24", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_MULTI);
    CYTADEL_ASSERT(strstr(err, "Milestone 3") != NULL);
}

static void test_host_list_is_rejected_as_multi(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status =
        cytadel_target_parse("10.0.0.1,10.0.0.2", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_MULTI);
}

static void test_whitespace_host_list_is_rejected_as_multi(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status =
        cytadel_target_parse("10.0.0.1 10.0.0.2", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_MULTI);
}

static void test_garbage_hostname_is_rejected(void) {
    cytadel_target_t target;
    char err[256];
    /* .invalid is reserved by RFC 2606 to never resolve -- deterministic
     * without depending on live network/DNS availability. */
    cytadel_target_status_t status =
        cytadel_target_parse("this-host-does-not-exist.invalid", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_RESOLVE);
}

static void test_empty_spec_is_rejected(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status = cytadel_target_parse("", &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_INVALID);
}

static void test_null_spec_is_rejected(void) {
    cytadel_target_t target;
    char err[256];
    cytadel_target_status_t status = cytadel_target_parse(NULL, &target, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_ERR_INVALID);
}

int main(void) {
    test_valid_ipv4_literal();
    test_valid_hostname_resolves();
    test_cidr_is_rejected_as_multi();
    test_host_list_is_rejected_as_multi();
    test_whitespace_host_list_is_rejected_as_multi();
    test_garbage_hostname_is_rejected();
    test_empty_spec_is_rejected();
    test_null_spec_is_rejected();
    CYTADEL_TEST_PASS();
}
