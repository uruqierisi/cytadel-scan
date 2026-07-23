#include "cytadel_test.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#include "strerror_safe.h"

/* Milestone 3 security fix regression: cytadel_strerror_safe() must always
 * return a NUL-terminated, non-empty string, both for a well-known errno
 * and for values libc has nothing to say about, and it must be safe to
 * call from many threads concurrently (this is exactly what a
 * ThreadSanitizer build of this test is for -- see docs referenced from
 * strerror_safe.h on why plain strerror() is not safe here). */

static void test_known_errno_returns_readable_message(void) {
    char buf[CYTADEL_STRERROR_BUF_LEN];
    const char *msg = cytadel_strerror_safe(EACCES, buf, sizeof(buf));

    CYTADEL_ASSERT(msg != NULL);
    CYTADEL_ASSERT(msg == buf); /* documented contract: message always lands in buf */
    CYTADEL_ASSERT(strlen(msg) > 0);
    CYTADEL_ASSERT(strlen(msg) < sizeof(buf)); /* NUL-terminated within buflen */
}

static void test_unrecognized_errno_still_returns_nonempty_terminated_string(void) {
    char buf[CYTADEL_STRERROR_BUF_LEN];
    /* An errno value no libc assigns any meaning to -- exercises the
     * "strerror_r() itself failed / returned nothing usable" fallback
     * path, which must still produce a safe, non-empty string rather than
     * leaving buf blank or uninitialized. */
    const char *msg = cytadel_strerror_safe(-999999, buf, sizeof(buf));

    CYTADEL_ASSERT(msg != NULL);
    CYTADEL_ASSERT(msg == buf);
    CYTADEL_ASSERT(strlen(msg) > 0);
    CYTADEL_ASSERT(strlen(msg) < sizeof(buf));
}

static void test_tiny_buffer_is_still_nul_terminated(void) {
    char buf[4];
    const char *msg = cytadel_strerror_safe(EACCES, buf, sizeof(buf));

    CYTADEL_ASSERT(msg != NULL);
    CYTADEL_ASSERT(strlen(msg) < sizeof(buf)); /* truncated, never overflowed */
}

static void test_null_and_zero_length_buffers_are_a_safe_no_op(void) {
    CYTADEL_ASSERT(cytadel_strerror_safe(EACCES, NULL, 16) == NULL);

    char buf[8] = "unset";
    const char *ret = cytadel_strerror_safe(EACCES, buf, 0);
    CYTADEL_ASSERT(ret == buf);
    CYTADEL_ASSERT_STREQ(buf, "unset"); /* untouched, per the documented no-op contract */
}

/* Concurrency hammer: many threads call cytadel_strerror_safe() with a mix
 * of a well-known errno and an unrecognized one, entirely on their own
 * stack buffers. Under ThreadSanitizer this is the regression test for the
 * exact bug this milestone's security fix addresses -- strerror()'s shared
 * static buffer race across worker-pool threads. With the thread-safe
 * helper there should be no shared mutable state at all, so TSan must
 * report zero data races here. */
#define CYTADEL_TEST_STRERROR_THREADS 8
#define CYTADEL_TEST_STRERROR_ITERS 500

static void *cytadel_test_strerror_hammer_thread(void *arg) {
    int id = *(int *)arg;
    int errnum = (id % 2 == 0) ? EACCES : -999999;

    for (int i = 0; i < CYTADEL_TEST_STRERROR_ITERS; i++) {
        char buf[CYTADEL_STRERROR_BUF_LEN];
        const char *msg = cytadel_strerror_safe(errnum, buf, sizeof(buf));
        if (msg == NULL || msg[0] == '\0') {
            fprintf(stderr, "thread %d: unexpected empty/NULL message at iter %d\n", id, i);
            exit(1);
        }
    }
    return NULL;
}

static void test_concurrent_calls_do_not_race(void) {
    pthread_t threads[CYTADEL_TEST_STRERROR_THREADS];
    int ids[CYTADEL_TEST_STRERROR_THREADS];

    for (int i = 0; i < CYTADEL_TEST_STRERROR_THREADS; i++) {
        ids[i] = i;
        CYTADEL_ASSERT(pthread_create(&threads[i], NULL, cytadel_test_strerror_hammer_thread,
                                       &ids[i]) == 0);
    }
    for (int i = 0; i < CYTADEL_TEST_STRERROR_THREADS; i++) {
        CYTADEL_ASSERT(pthread_join(threads[i], NULL) == 0);
    }
}

int main(void) {
    test_known_errno_returns_readable_message();
    test_unrecognized_errno_still_returns_nonempty_terminated_string();
    test_tiny_buffer_is_still_nul_terminated();
    test_null_and_zero_length_buffers_are_a_safe_no_op();
    test_concurrent_calls_do_not_race();
    CYTADEL_TEST_PASS();
}
