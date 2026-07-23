#include "cytadel_test.h"

#include "cytadel/net/cidr.h"
#include "cytadel/net/scan_types.h"

static void test_slash_24_count_and_endpoints(void) {
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("192.168.1.0/24", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 256);

    char first[CYTADEL_NET_IP_STR_MAX];
    char last[CYTADEL_NET_IP_STR_MAX];
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 0, first, sizeof(first)), 0);
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 255, last, sizeof(last)), 0);
    CYTADEL_ASSERT_STREQ(first, "192.168.1.0");
    CYTADEL_ASSERT_STREQ(last, "192.168.1.255");

    /* Out of range -- host_count() is 256, so index 256 does not exist. */
    char scratch[CYTADEL_NET_IP_STR_MAX];
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 256, scratch, sizeof(scratch)), -1);
}

static void test_slash_32_single_host(void) {
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("10.0.0.5/32", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 1);

    char addr[CYTADEL_NET_IP_STR_MAX];
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 0, addr, sizeof(addr)), 0);
    CYTADEL_ASSERT_STREQ(addr, "10.0.0.5");
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 1, addr, sizeof(addr)), -1);
}

static void test_slash_31_point_to_point(void) {
    /* RFC 3021: two usable addresses, no network/broadcast concept -- both
     * are scanned under the same "scan every address" rule. */
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("10.0.0.4/31", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 2);

    char a[CYTADEL_NET_IP_STR_MAX];
    char b[CYTADEL_NET_IP_STR_MAX];
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 0, a, sizeof(a)), 0);
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 1, b, sizeof(b)), 0);
    CYTADEL_ASSERT_STREQ(a, "10.0.0.4");
    CYTADEL_ASSERT_STREQ(b, "10.0.0.5");
}

static void test_slash_30_includes_network_and_broadcast(void) {
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("10.0.0.0/30", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 4);

    /* Policy: network (.0) and broadcast (.3) addresses are included, not
     * excluded -- documented in cidr.h/target_list.h/--help. */
    char addr[CYTADEL_NET_IP_STR_MAX];
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 0, addr, sizeof(addr)), 0);
    CYTADEL_ASSERT_STREQ(addr, "10.0.0.0");
    CYTADEL_ASSERT_EQ(cytadel_cidr_nth_address(&cidr, 3, addr, sizeof(addr)), 0);
    CYTADEL_ASSERT_STREQ(addr, "10.0.0.3");
}

static void test_slash_28_count(void) {
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("172.16.5.0/28", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 16);
}

static void test_slash_0_host_count_does_not_overflow(void) {
    /* Guards the "prefix 0 and the shift" case explicitly -- must not be
     * undefined behavior or wrap around to 0. */
    cytadel_cidr_t cidr;
    char err[256];
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("0.0.0.0/0", &cidr, err, sizeof(err)), CYTADEL_CIDR_OK);
    CYTADEL_ASSERT_EQ((long long)cytadel_cidr_host_count(&cidr), 4294967296LL);
}

static void test_invalid_prefix_33_is_rejected(void) {
    cytadel_cidr_t cidr;
    char err[256];
    cytadel_cidr_status_t status = cytadel_cidr_parse("10.0.0.0/33", &cidr, err, sizeof(err));
    CYTADEL_ASSERT_EQ(status, CYTADEL_CIDR_ERR_BAD_PREFIX);
}

static void test_invalid_prefix_negative_is_rejected(void) {
    cytadel_cidr_t cidr;
    char err[256];
    cytadel_cidr_status_t status = cytadel_cidr_parse("10.0.0.0/-1", &cidr, err, sizeof(err));
    CYTADEL_ASSERT_EQ(status, CYTADEL_CIDR_ERR_BAD_PREFIX);
}

static void test_missing_slash_is_malformed(void) {
    cytadel_cidr_t cidr;
    char err[256];
    cytadel_cidr_status_t status = cytadel_cidr_parse("10.0.0.0", &cidr, err, sizeof(err));
    CYTADEL_ASSERT_EQ(status, CYTADEL_CIDR_ERR_MALFORMED);
}

static void test_bad_address_is_rejected(void) {
    cytadel_cidr_t cidr;
    char err[256];
    cytadel_cidr_status_t status = cytadel_cidr_parse("999.0.0.0/24", &cidr, err, sizeof(err));
    CYTADEL_ASSERT_EQ(status, CYTADEL_CIDR_ERR_BAD_ADDRESS);
}

static void test_null_args_are_rejected(void) {
    cytadel_cidr_t cidr;
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse(NULL, &cidr, NULL, 0), CYTADEL_CIDR_ERR_MALFORMED);
    CYTADEL_ASSERT_EQ(cytadel_cidr_parse("10.0.0.0/24", NULL, NULL, 0), CYTADEL_CIDR_ERR_MALFORMED);
    CYTADEL_ASSERT_EQ(cytadel_cidr_host_count(NULL), 0);
}

int main(void) {
    test_slash_24_count_and_endpoints();
    test_slash_32_single_host();
    test_slash_31_point_to_point();
    test_slash_30_includes_network_and_broadcast();
    test_slash_28_count();
    test_slash_0_host_count_does_not_overflow();
    test_invalid_prefix_33_is_rejected();
    test_invalid_prefix_negative_is_rejected();
    test_missing_slash_is_malformed();
    test_bad_address_is_rejected();
    test_null_args_are_rejected();
    CYTADEL_TEST_PASS();
}
