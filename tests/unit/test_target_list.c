#include "cytadel_test.h"

#include <stdio.h>

#include "cytadel/net/target_list.h"

static void test_single_literal(void) {
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status = cytadel_target_list_parse("10.0.0.1", NULL, &list, err,
                                                                       sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 1);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "10.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[0].host, "10.0.0.1");

    cytadel_target_list_free(&list);
}

static void test_cidr_expansion_via_list(void) {
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status = cytadel_target_list_parse("10.0.0.0/30", NULL, &list, err,
                                                                       sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 4);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "10.0.0.0");
    CYTADEL_ASSERT_STREQ(list.targets[1].ip, "10.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[2].ip, "10.0.0.2");
    CYTADEL_ASSERT_STREQ(list.targets[3].ip, "10.0.0.3");

    cytadel_target_list_free(&list);
}

static void test_mixed_list_dedup_preserves_first_occurrence_order(void) {
    /* "127.0.0.1,127.0.0.2,127.0.0.0/30" -- the CIDR re-covers .1 and .2,
     * already present as literals; those duplicates must be dropped, and
     * the survivors must keep their original relative order: the two
     * literals first (as originally given), then the two new addresses
     * the CIDR contributes (.0 and .3). */
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("127.0.0.1,127.0.0.2,127.0.0.0/30", NULL, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 4);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "127.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[1].ip, "127.0.0.2");
    CYTADEL_ASSERT_STREQ(list.targets[2].ip, "127.0.0.0");
    CYTADEL_ASSERT_STREQ(list.targets[3].ip, "127.0.0.3");

    cytadel_target_list_free(&list);
}

static void test_hostname_and_literal_dedup_to_same_ip(void) {
    /* "127.0.0.1" and "localhost" resolve to the same address -- the
     * earlier-given literal spelling must survive, not the later hostname
     * spelling. */
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("127.0.0.1,localhost", NULL, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 1);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "127.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[0].host, "127.0.0.1");

    cytadel_target_list_free(&list);
}

static void test_targets_file_comments_and_blanks(void) {
    const char *path = "test_targets_file_comments.tmp.txt";
    FILE *f = fopen(path, "w");
    CYTADEL_ASSERT(f != NULL);
    fputs("# a full-line comment\n", f);
    fputs("\n", f);
    fputs("   \n", f);
    fputs("10.0.0.1\n", f);
    fputs("10.0.0.2   # inline comment\n", f);
    fclose(f);

    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status = cytadel_target_list_parse(NULL, path, &list, err,
                                                                       sizeof(err));
    remove(path);

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 2);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "10.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[1].ip, "10.0.0.2");

    cytadel_target_list_free(&list);
}

static void test_targets_file_missing_is_rejected(void) {
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse(NULL, "this_file_does_not_exist.tmp.txt", &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_FILE);
}

static void test_targets_file_malformed_line_is_rejected(void) {
    const char *path = "test_targets_file_malformed.tmp.txt";
    FILE *f = fopen(path, "w");
    CYTADEL_ASSERT(f != NULL);
    fputs("10.0.0.1\n", f);
    fputs("10.0.0.0/99\n", f); /* invalid prefix */
    fclose(f);

    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status = cytadel_target_list_parse(NULL, path, &list, err,
                                                                       sizeof(err));
    remove(path);

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_INVALID);
}

static void test_spec_and_file_combine(void) {
    const char *path = "test_targets_file_combine.tmp.txt";
    FILE *f = fopen(path, "w");
    CYTADEL_ASSERT(f != NULL);
    fputs("10.0.0.2\n", f);
    fclose(f);

    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("10.0.0.1", path, &list, err, sizeof(err));
    remove(path);

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_OK);
    CYTADEL_ASSERT_EQ(list.count, 2);
    CYTADEL_ASSERT_STREQ(list.targets[0].ip, "10.0.0.1");
    CYTADEL_ASSERT_STREQ(list.targets[1].ip, "10.0.0.2");

    cytadel_target_list_free(&list);
}

static void test_over_cap_cidr_rejected_without_materializing(void) {
    /* A /8 is 16,777,216 addresses -- must be rejected immediately via the
     * host-count check, never actually looped/allocated. */
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("10.0.0.0/8", NULL, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_TOO_MANY);
}

static void test_invalid_cidr_prefix_in_list_is_rejected(void) {
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("10.0.0.0/33", NULL, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_INVALID);
}

static void test_no_spec_and_no_file_is_rejected(void) {
    cytadel_target_list_t list;
    char err[256];
    cytadel_target_list_status_t status = cytadel_target_list_parse(NULL, NULL, &list, err,
                                                                       sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_EMPTY);
}

static void test_unresolvable_hostname_is_rejected(void) {
    cytadel_target_list_t list;
    char err[256];
    /* .invalid is reserved by RFC 2606 to never resolve. */
    cytadel_target_list_status_t status =
        cytadel_target_list_parse("this-host-does-not-exist.invalid", NULL, &list, err, sizeof(err));

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_LIST_ERR_RESOLVE);
}

int main(void) {
    test_single_literal();
    test_cidr_expansion_via_list();
    test_mixed_list_dedup_preserves_first_occurrence_order();
    test_hostname_and_literal_dedup_to_same_ip();
    test_targets_file_comments_and_blanks();
    test_targets_file_missing_is_rejected();
    test_targets_file_malformed_line_is_rejected();
    test_spec_and_file_combine();
    test_over_cap_cidr_rejected_without_materializing();
    test_invalid_cidr_prefix_in_list_is_rejected();
    test_no_spec_and_no_file_is_rejected();
    test_unresolvable_hostname_is_rejected();
    CYTADEL_TEST_PASS();
}
