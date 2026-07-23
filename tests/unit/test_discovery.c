#include "cytadel_test.h"

#include "cytadel/net/discovery.h"

/* Unit-tests the pure decision function only (no real sockets): given the
 * capability probe's answer, does discovery pick ICMP or fall back to
 * TCP-ping? The real cytadel_net_can_use_raw_sockets() is exercised
 * indirectly via cytadel_discovery_probe() in the manual/integration run,
 * not here -- its actual return value is environment-dependent (root vs.
 * unprivileged container), which is exactly why the decision itself is
 * factored out into a pure, stubbable function. */

static void test_raw_available_chooses_icmp(void) {
    cytadel_discovery_method_t method = cytadel_discovery_choose_method(true);
    CYTADEL_ASSERT_EQ(method, CYTADEL_DISCOVERY_METHOD_ICMP);
}

static void test_raw_unavailable_falls_back_to_tcp_ping(void) {
    cytadel_discovery_method_t method = cytadel_discovery_choose_method(false);
    CYTADEL_ASSERT_EQ(method, CYTADEL_DISCOVERY_METHOD_TCP_PING);
}

static void test_skip_discovery_reports_up_without_probing(void) {
    /* skip_discovery short-circuits before any capability probe or I/O --
     * safe to run in any test environment, including sandboxes with no
     * network access at all. */
    cytadel_discovery_result_t result = cytadel_discovery_probe("127.0.0.1", 100, true);
    CYTADEL_ASSERT_EQ(result.state, CYTADEL_HOST_UP);
    CYTADEL_ASSERT_EQ(result.method_used, CYTADEL_DISCOVERY_METHOD_SKIPPED);
}

int main(void) {
    test_raw_available_chooses_icmp();
    test_raw_unavailable_falls_back_to_tcp_ping();
    test_skip_discovery_reports_up_without_probing();
    CYTADEL_TEST_PASS();
}
