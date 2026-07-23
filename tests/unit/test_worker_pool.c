#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/core/worker_pool.h"
#include "cytadel/net/port_range.h"
#include "cytadel/net/target.h"

/* Hermetic loopback fixture, same shape as test_port_scanner.c's: binds a
 * real TCP listener on an OS-assigned ephemeral 127.0.0.1 port. Bound
 * specifically to 127.0.0.1 (not INADDR_ANY), so a connection aimed at a
 * *different* loopback address (127.0.0.2, .3, ...) on the same port
 * number is not accepted -- this is what lets the tests below tell targets
 * apart deterministically even though every address in 127.0.0.0/8 routes
 * to the loopback interface. */
static int cytadel_test_bind_loopback_listener(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 4) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

static cytadel_target_t cytadel_test_make_target(const char *ip) {
    cytadel_target_t t;
    char err[128];
    cytadel_target_status_t status = cytadel_target_parse(ip, &t, err, sizeof(err));
    CYTADEL_ASSERT_EQ(status, CYTADEL_TARGET_OK);
    return t;
}

/* Frees result.ports for every populated slot (idempotent / safe on a
 * zeroed slot). Used at the end of every test below. */
static void cytadel_test_free_results(cytadel_worker_result_t *results, size_t count) {
    for (size_t i = 0; i < count; i++) {
        cytadel_host_result_free(&results[i].result);
    }
}

/* Runs the "some targets have listeners, some don't" fixture with a given
 * max_workers, asserting every result slot lands on the *correct* target
 * regardless of how many worker threads actually did the work -- this is
 * the concurrency-determinism regression the milestone calls for. */
static void cytadel_test_run_fixture(int max_workers) {
    uint16_t port_a, port_b, port_c;
    int fd_a = cytadel_test_bind_loopback_listener(&port_a);
    int fd_b = cytadel_test_bind_loopback_listener(&port_b);
    int fd_c = cytadel_test_bind_loopback_listener(&port_c);

    cytadel_port_list_t ports;
    uint16_t port_values[3] = { port_a, port_b, port_c };
    ports.ports = port_values;
    ports.count = 3;

    /* Only 127.0.0.1 has anything listening on these three ports; every
     * other target below is a distinct loopback address with nothing
     * bound to it, so its three ports must all classify closed. */
    cytadel_target_t targets[5] = {
        cytadel_test_make_target("127.0.0.1"),
        cytadel_test_make_target("127.0.0.2"),
        cytadel_test_make_target("127.0.0.3"),
        cytadel_test_make_target("127.0.0.4"),
        cytadel_test_make_target("127.0.0.5"),
    };
    size_t target_count = sizeof(targets) / sizeof(targets[0]);

    /* Zero-initialized (not just field-by-field) so any field this test
     * doesn't explicitly care about -- e.g. Milestone 5's plugin_registry
     * -- defaults to NULL/0 rather than reading uninitialized stack
     * garbage; cytadel_host_scan() treats a NULL plugin_registry as "skip
     * the plugin phase," which is exactly what this test wants. */
    cytadel_host_scan_opts_t opts = {0};
    opts.discovery_timeout_ms = 1000;
    opts.connect_timeout_ms = 1000;
    opts.skip_discovery = true; /* deterministic: no ICMP/TCP-ping flakiness */

    cytadel_worker_result_t *results = calloc(target_count, sizeof(cytadel_worker_result_t));
    CYTADEL_ASSERT(results != NULL);

    int rc = cytadel_worker_pool_run(targets, target_count, &ports, &opts, max_workers, results);
    CYTADEL_ASSERT_EQ(rc, 0);

    for (size_t i = 0; i < target_count; i++) {
        CYTADEL_ASSERT_EQ(results[i].scan_rc, 0);
        CYTADEL_ASSERT_EQ(results[i].result.state, CYTADEL_HOST_UP);
        CYTADEL_ASSERT_STREQ(results[i].result.host, targets[i].host);
        CYTADEL_ASSERT_EQ(results[i].result.port_count, 3);

        size_t expected_open = (i == 0) ? 3 : 0;
        size_t open_count = 0;
        for (size_t p = 0; p < results[i].result.port_count; p++) {
            if (results[i].result.ports[p].state == CYTADEL_PORT_OPEN) {
                open_count++;
            }
        }
        CYTADEL_ASSERT_EQ((long long)open_count, (long long)expected_open);
    }

    cytadel_test_free_results(results, target_count);
    free(results);
    close(fd_a);
    close(fd_b);
    close(fd_c);
}

static void test_more_workers_than_targets(void) {
    cytadel_test_run_fixture(64); /* max_workers > target_count (5) */
}

static void test_fewer_workers_than_targets(void) {
    cytadel_test_run_fixture(2); /* max_workers < target_count (5) */
}

static void test_single_target(void) {
    uint16_t port;
    int fd = cytadel_test_bind_loopback_listener(&port);

    cytadel_port_list_t ports;
    uint16_t port_values[1] = { port };
    ports.ports = port_values;
    ports.count = 1;

    cytadel_target_t targets[1] = { cytadel_test_make_target("127.0.0.1") };

    /* Zero-initialized -- see the identical comment on this same pattern
     * earlier in this file. */
    cytadel_host_scan_opts_t opts = {0};
    opts.discovery_timeout_ms = 1000;
    opts.connect_timeout_ms = 1000;
    opts.skip_discovery = true;

    cytadel_worker_result_t results[1];
    memset(results, 0, sizeof(results));

    int rc = cytadel_worker_pool_run(targets, 1, &ports, &opts, 8, results);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(results[0].scan_rc, 0);
    CYTADEL_ASSERT_EQ(results[0].result.state, CYTADEL_HOST_UP);
    CYTADEL_ASSERT_EQ(results[0].result.port_count, 1);
    CYTADEL_ASSERT_EQ(results[0].result.ports[0].state, CYTADEL_PORT_OPEN);

    cytadel_test_free_results(results, 1);
    close(fd);
}

static void test_empty_queue_is_a_no_op(void) {
    cytadel_port_list_t ports;
    ports.ports = NULL;
    ports.count = 0;

    int rc = cytadel_worker_pool_run(NULL, 0, &ports, NULL, 4, NULL);
    CYTADEL_ASSERT_EQ(rc, 0);
}

int main(void) {
    test_more_workers_than_targets();
    test_fewer_workers_than_targets();
    test_single_target();
    test_empty_queue_is_a_no_op();
    CYTADEL_TEST_PASS();
}
