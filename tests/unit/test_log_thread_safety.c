#include "cytadel_test.h"

#include <pthread.h>
#include <stdio.h>

#include "log.h"

/* Race regression test (Milestone 3): hammers cytadel_log*() from many
 * threads concurrently and asserts every resulting line in the log file is
 * well-formed -- i.e. never "torn" (two threads' writes interleaved
 * mid-line) or merged/split by the lack of a lock around
 * cytadel_log_vwrite()'s critical section (log.c). Each thread writes a
 * payload made entirely of one repeated character unique to that thread;
 * a torn write would show up either as a payload containing a mix of
 * characters, a malformed "thread=/seq=/payload=" structure, or a total
 * line count different from (threads * lines-per-thread). */

#define CYTADEL_TEST_LOG_THREADS 8
#define CYTADEL_TEST_LOG_LINES_PER_THREAD 200
#define CYTADEL_TEST_LOG_PAYLOAD_LEN 64

static void *cytadel_test_hammer_thread(void *arg) {
    int id = *(int *)arg;

    char payload[CYTADEL_TEST_LOG_PAYLOAD_LEN + 1];
    memset(payload, 'A' + id, CYTADEL_TEST_LOG_PAYLOAD_LEN);
    payload[CYTADEL_TEST_LOG_PAYLOAD_LEN] = '\0';

    for (int seq = 0; seq < CYTADEL_TEST_LOG_LINES_PER_THREAD; seq++) {
        cytadel_log_info("thread=%d seq=%d payload=%s", id, seq, payload);
    }
    return NULL;
}

static void test_concurrent_logging_produces_well_formed_lines(void) {
    const char *path = "test_log_thread_safety.tmp.log";
    remove(path);
    CYTADEL_ASSERT_EQ(cytadel_log_init(CYTADEL_LOG_INFO, path), 0);

    pthread_t threads[CYTADEL_TEST_LOG_THREADS];
    int ids[CYTADEL_TEST_LOG_THREADS];
    for (int i = 0; i < CYTADEL_TEST_LOG_THREADS; i++) {
        ids[i] = i;
        CYTADEL_ASSERT(pthread_create(&threads[i], NULL, cytadel_test_hammer_thread, &ids[i]) == 0);
    }
    for (int i = 0; i < CYTADEL_TEST_LOG_THREADS; i++) {
        CYTADEL_ASSERT(pthread_join(threads[i], NULL) == 0);
    }
    cytadel_log_close();

    FILE *f = fopen(path, "r");
    CYTADEL_ASSERT(f != NULL);

    long long line_count = 0;
    char line[8192];
    while (fgets(line, sizeof(line), f) != NULL) {
        size_t len = strlen(line);
        /* Every line this test writes is well under the buffer, so a line
         * not ending in '\n' means it either got cut in half by a torn
         * concurrent write, or overflowed the read buffer -- either way,
         * a hard failure here. */
        CYTADEL_ASSERT(len > 0 && line[len - 1] == '\n');
        line_count++;

        char *tpos = strstr(line, "thread=");
        CYTADEL_ASSERT(tpos != NULL);
        int id = -1;
        int seq = -1;
        int matched = sscanf(tpos, "thread=%d seq=%d payload=", &id, &seq);
        CYTADEL_ASSERT_EQ(matched, 2);
        CYTADEL_ASSERT(id >= 0 && id < CYTADEL_TEST_LOG_THREADS);
        CYTADEL_ASSERT(seq >= 0 && seq < CYTADEL_TEST_LOG_LINES_PER_THREAD);

        char *ppos = strstr(line, "payload=");
        CYTADEL_ASSERT(ppos != NULL);
        ppos += strlen("payload=");
        char expected_char = (char)('A' + id);
        int payload_len_seen = 0;
        while (*ppos != '\0' && *ppos != '\n' && *ppos != '\r') {
            CYTADEL_ASSERT_EQ(*ppos, expected_char);
            ppos++;
            payload_len_seen++;
        }
        CYTADEL_ASSERT_EQ(payload_len_seen, CYTADEL_TEST_LOG_PAYLOAD_LEN);
    }
    fclose(f);
    remove(path);

    CYTADEL_ASSERT_EQ(line_count,
                       (long long)(CYTADEL_TEST_LOG_THREADS * CYTADEL_TEST_LOG_LINES_PER_THREAD));
}

int main(void) {
    test_concurrent_logging_produces_well_formed_lines();
    CYTADEL_TEST_PASS();
}
