#include "cytadel_test.h"

#include "cytadel/kb/kb.h"
#include "cytadel/net/host_scan.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/net/target.h"

/* Regression coverage for host_scan.c's host/ip copy into
 * cytadel_host_result_t: target->host/ip is copied at the exact maximum
 * length cytadel_target_parse()/target_list.c's CIDR path can ever produce
 * (CYTADEL_NET_HOST_STR_MAX - 1 / CYTADEL_NET_IP_STR_MAX - 1 bytes), and
 * must land byte-for-byte in out_result->host/ip -- never silently
 * truncated into a different (and therefore misleading, if it were then
 * scanned or reported under the wrong name) string. */
static void test_max_length_host_and_ip_are_copied_without_truncation(void) {
    cytadel_target_t target;
    memset(&target, 0, sizeof(target));

    /* Fill host with the longest string that fits (all 'a's), leaving room
     * for the NUL -- exactly the boundary a same-sized strncpy() would be
     * asked to copy in full. */
    size_t host_len = sizeof(target.host) - 1;
    memset(target.host, 'a', host_len);
    target.host[host_len] = '\0';

    size_t ip_len = sizeof(target.ip) - 1;
    memset(target.ip, 'b', ip_len);
    target.ip[ip_len] = '\0';

    cytadel_port_list_t ports;
    ports.ports = NULL;
    ports.count = 0; /* no network I/O: cytadel_port_scan() no-ops on an empty list */

    cytadel_host_scan_opts_t opts = {0};
    opts.discovery_timeout_ms = 1000;
    opts.connect_timeout_ms = 1000;
    opts.skip_discovery = true; /* deterministic: no ICMP/TCP-ping against a fake IP */

    cytadel_host_result_t result;
    memset(&result, 0, sizeof(result));

    int rc = cytadel_host_scan(&target, &ports, &opts, &result);
    CYTADEL_ASSERT_EQ(rc, 0);

    /* Byte-for-byte, not just "didn't crash" -- proves no truncation and no
     * off-by-one on the manual NUL terminator. */
    CYTADEL_ASSERT_STREQ(result.host, target.host);
    CYTADEL_ASSERT_EQ(strlen(result.host), host_len);
    CYTADEL_ASSERT_STREQ(result.ip, target.ip);
    CYTADEL_ASSERT_EQ(strlen(result.ip), ip_len);

    cytadel_host_result_free(&result);
}

/* Regression gate for the M9 Gap #2 defect: tls_cert_hostname_mismatch.lua
 * (script_id 100023) reads KB fact Host/hostname, but for a long stretch
 * host_scan.c never wrote that key at all -- the plugin's own required
 * fact simply never existed in a real scan's KB, so the plugin was
 * structurally dead (every invocation hit its "no Host/hostname recorded"
 * early return) no matter how mismatched a certificate actually was. This
 * writes Host/hostname from the operator's own target spec (mirroring the
 * cytadel_target_is_ipv4_literal() check host_scan.c already uses to pick
 * the TLS SNI HostName) -- never a guess, never DNS, just the name the
 * operator typed. If host_scan.c's write of Host/hostname is ever removed
 * or misordered again, this test fails immediately. */
static void test_hostname_written_for_hostname_target(void) {
    cytadel_target_t target;
    memset(&target, 0, sizeof(target));
    snprintf(target.host, sizeof(target.host), "scan-me.example.com");
    /* Deliberately a TEST-NET-3 (RFC 5737) address: never routable, so
     * skip_discovery=true below is what keeps this deterministic (no
     * accidental network dependency), not the address's unreachability. */
    snprintf(target.ip, sizeof(target.ip), "203.0.113.10");

    cytadel_port_list_t ports;
    ports.ports = NULL;
    ports.count = 0; /* no network I/O: cytadel_port_scan() no-ops on an empty list */

    cytadel_host_scan_opts_t opts = {0};
    opts.discovery_timeout_ms = 1000;
    opts.connect_timeout_ms = 1000;
    opts.skip_discovery = true; /* deterministic: no ICMP/TCP-ping against a fake IP */

    cytadel_host_result_t result;
    memset(&result, 0, sizeof(result));

    int rc = cytadel_host_scan(&target, &ports, &opts, &result);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(result.kb != NULL);

    const char *hostname = cytadel_kb_get_str(result.kb, "Host/hostname");
    CYTADEL_ASSERT(hostname != NULL);
    CYTADEL_ASSERT_STREQ(hostname, target.host);

    cytadel_host_result_free(&result);
}

/* Mirror case: an IPv4-literal target must NOT get a Host/hostname fact --
 * you cannot hostname-mismatch a bare IP, so writing one here would be a
 * guess, not a fact (kb-schema.md §7.1's "absence is correct" principle). */
static void test_hostname_absent_for_ipv4_literal_target(void) {
    cytadel_target_t target;
    memset(&target, 0, sizeof(target));
    snprintf(target.host, sizeof(target.host), "203.0.113.10");
    snprintf(target.ip, sizeof(target.ip), "203.0.113.10");

    cytadel_port_list_t ports;
    ports.ports = NULL;
    ports.count = 0;

    cytadel_host_scan_opts_t opts = {0};
    opts.discovery_timeout_ms = 1000;
    opts.connect_timeout_ms = 1000;
    opts.skip_discovery = true;

    cytadel_host_result_t result;
    memset(&result, 0, sizeof(result));

    int rc = cytadel_host_scan(&target, &ports, &opts, &result);
    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT(result.kb != NULL);

    const char *hostname = cytadel_kb_get_str(result.kb, "Host/hostname");
    CYTADEL_ASSERT(hostname == NULL);

    cytadel_host_result_free(&result);
}

int main(void) {
    test_max_length_host_and_ip_are_copied_without_truncation();
    test_hostname_written_for_hostname_target();
    test_hostname_absent_for_ipv4_literal_target();
    CYTADEL_TEST_PASS();
}
