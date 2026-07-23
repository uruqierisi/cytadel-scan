#ifndef CYTADEL_TEST_H
#define CYTADEL_TEST_H

/* Header-only assertion helper (docs/build-plan.md §4). No external test
 * framework dependency -- each test file compiles to its own small
 * executable and exit(1)s on the first failed assertion. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CYTADEL_ASSERT(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "%s:%d: assertion failed: %s\n", __FILE__, __LINE__, #cond); \
            exit(1); \
        } \
    } while (0)

#define CYTADEL_ASSERT_EQ(actual, expected) \
    do { \
        long long cytadel_test_actual_ = (long long)(actual); \
        long long cytadel_test_expected_ = (long long)(expected); \
        if (cytadel_test_actual_ != cytadel_test_expected_) { \
            fprintf(stderr, \
                    "%s:%d: assertion failed: %s == %s (got %lld, expected %lld)\n", \
                    __FILE__, __LINE__, #actual, #expected, \
                    cytadel_test_actual_, cytadel_test_expected_); \
            exit(1); \
        } \
    } while (0)

#define CYTADEL_ASSERT_STREQ(actual, expected) \
    do { \
        const char *cytadel_test_actual_ = (actual); \
        const char *cytadel_test_expected_ = (expected); \
        if (cytadel_test_actual_ == NULL || cytadel_test_expected_ == NULL || \
            strcmp(cytadel_test_actual_, cytadel_test_expected_) != 0) { \
            fprintf(stderr, \
                    "%s:%d: assertion failed: %s == %s (got \"%s\", expected \"%s\")\n", \
                    __FILE__, __LINE__, #actual, #expected, \
                    (cytadel_test_actual_ != NULL) ? cytadel_test_actual_ : "(null)", \
                    (cytadel_test_expected_ != NULL) ? cytadel_test_expected_ : "(null)"); \
            exit(1); \
        } \
    } while (0)

#define CYTADEL_TEST_PASS() \
    do { \
        printf("PASS: %s\n", __FILE__); \
        return 0; \
    } while (0)

#endif /* CYTADEL_TEST_H */
