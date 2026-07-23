#include "cytadel_test.h"

#include "cytadel/net/port_range.h"

static void test_single_port(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status = cytadel_port_range_parse("22", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 1);
    CYTADEL_ASSERT_EQ(list.ports[0], 22);

    cytadel_port_list_free(&list);
}

static void test_range(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("1-1024", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 1024);
    CYTADEL_ASSERT_EQ(list.ports[0], 1);
    CYTADEL_ASSERT_EQ(list.ports[1023], 1024);

    cytadel_port_list_free(&list);
}

static void test_comma_list(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("22,80,443", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 3);
    CYTADEL_ASSERT_EQ(list.ports[0], 22);
    CYTADEL_ASSERT_EQ(list.ports[1], 80);
    CYTADEL_ASSERT_EQ(list.ports[2], 443);

    cytadel_port_list_free(&list);
}

static void test_mixed_range_and_list(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("1-100,8080", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 101);
    CYTADEL_ASSERT_EQ(list.ports[0], 1);
    CYTADEL_ASSERT_EQ(list.ports[99], 100);
    CYTADEL_ASSERT_EQ(list.ports[100], 8080);

    cytadel_port_list_free(&list);
}

static void test_dedup(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("22,22,80,22", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 2);
    CYTADEL_ASSERT_EQ(list.ports[0], 22);
    CYTADEL_ASSERT_EQ(list.ports[1], 80);

    cytadel_port_list_free(&list);
}

static void test_dedup_overlapping_ranges(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("1-10,5-15", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT_EQ(list.count, 15);

    cytadel_port_list_free(&list);
}

static void test_malformed_alpha_is_rejected(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status = cytadel_port_range_parse("abc", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_MALFORMED);
}

static void test_zero_port_is_out_of_bounds(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status = cytadel_port_range_parse("0", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_OUT_OF_BOUNDS);
}

static void test_over_max_port_is_out_of_bounds(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("70000", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_OUT_OF_BOUNDS);
}

static void test_backwards_range_is_malformed(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("100-50", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_MALFORMED);
}

static void test_empty_spec_is_rejected(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status = cytadel_port_range_parse("", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_MALFORMED);
}

static void test_trailing_comma_is_rejected(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status = cytadel_port_range_parse("22,", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_MALFORMED);
}

static void test_double_dash_is_rejected(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse("1-10-20", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_ERR_MALFORMED);
}

static void test_default_spec_is_valid(void) {
    cytadel_port_list_t list;
    char err[256];
    cytadel_port_range_status_t status =
        cytadel_port_range_parse(CYTADEL_DEFAULT_PORT_SPEC, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_PORT_RANGE_OK);
    CYTADEL_ASSERT(list.count > 0);

    cytadel_port_list_free(&list);
}

int main(void) {
    test_single_port();
    test_range();
    test_comma_list();
    test_mixed_range_and_list();
    test_dedup();
    test_dedup_overlapping_ranges();
    test_malformed_alpha_is_rejected();
    test_zero_port_is_out_of_bounds();
    test_over_max_port_is_out_of_bounds();
    test_backwards_range_is_malformed();
    test_empty_spec_is_rejected();
    test_trailing_comma_is_rejected();
    test_double_dash_is_rejected();
    test_default_spec_is_valid();
    CYTADEL_TEST_PASS();
}
