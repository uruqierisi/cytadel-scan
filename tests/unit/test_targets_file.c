#include "cytadel_test.h"

#include <stdio.h>
#include <string.h>

#include "cytadel/net/targets_file.h"

/* Milestone 3 boundary-fix regression: a content line of exactly the
 * documented max length (CYTADEL_TARGETS_FILE_LINE_MAX - 1 bytes, per
 * targets_file.h and the "longer than %d bytes" error message in
 * targets_file.c) must be accepted, not rejected -- fgets()'s buffer needs
 * room for the max content *plus* the trailing '\n' *plus* the NUL
 * terminator, which the original CYTADEL_TARGETS_FILE_LINE_MAX-sized
 * buffer did not have. */

static void cytadel_test_write_line(FILE *f, const char *prefix, char pad_char,
                                     size_t total_line_len) {
    /* Writes exactly total_line_len bytes of content (prefix, then
     * pad_char repeated to fill out the rest) followed by a single '\n'. */
    size_t prefix_len = strlen(prefix);
    CYTADEL_ASSERT(prefix_len <= total_line_len);
    fputs(prefix, f);
    for (size_t i = prefix_len; i < total_line_len; i++) {
        fputc(pad_char, f);
    }
    fputc('\n', f);
}

static void test_exactly_max_length_line_is_accepted(void) {
    const char *path = "test_targets_file_max_len.tmp.txt";
    FILE *f = fopen(path, "w");
    CYTADEL_ASSERT(f != NULL);

    /* "10.0.0.1 #" + padding + '\n' == exactly CYTADEL_TARGETS_FILE_LINE_MAX - 1
     * content bytes -- the documented max. The trailing "#..." padding is a
     * comment, so the line still trims down to just "10.0.0.1". */
    cytadel_test_write_line(f, "10.0.0.1 #", 'x', CYTADEL_TARGETS_FILE_LINE_MAX - 1);
    fclose(f);

    cytadel_targets_file_lines_t lines;
    char err[256];
    cytadel_targets_file_status_t status = cytadel_targets_file_read(path, &lines, err, sizeof(err));
    remove(path);

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGETS_FILE_OK);
    CYTADEL_ASSERT_EQ(lines.count, 1);
    CYTADEL_ASSERT_STREQ(lines.lines[0], "10.0.0.1");

    cytadel_targets_file_lines_free(&lines);
}

static void test_one_byte_over_max_length_line_is_rejected(void) {
    const char *path = "test_targets_file_over_max_len.tmp.txt";
    FILE *f = fopen(path, "w");
    CYTADEL_ASSERT(f != NULL);

    /* One byte longer than the documented max -- must still be a hard
     * error, never silently truncated. */
    cytadel_test_write_line(f, "10.0.0.1 #", 'x', CYTADEL_TARGETS_FILE_LINE_MAX);
    fclose(f);

    cytadel_targets_file_lines_t lines;
    char err[256];
    cytadel_targets_file_status_t status = cytadel_targets_file_read(path, &lines, err, sizeof(err));
    remove(path);

    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGETS_FILE_ERR_LINE_TOO_LONG);
    CYTADEL_ASSERT(strlen(err) > 0);
}

int main(void) {
    test_exactly_max_length_line_is_accepted();
    test_one_byte_over_max_length_line_is_rejected();
    CYTADEL_TEST_PASS();
}
