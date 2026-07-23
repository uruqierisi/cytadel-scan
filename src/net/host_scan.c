#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/host_scan.h"

#include <stdio.h>
#include <string.h>

#include "cytadel/kb/kb.h"
#include "cytadel/net/discovery.h"
#include "cytadel/net/port_scanner.h"
#include "cytadel/net/service_detect.h"
#include "log.h"

int cytadel_host_scan(const cytadel_target_t *target, const cytadel_port_list_t *ports,
                       const cytadel_host_scan_opts_t *opts, cytadel_host_result_t *out_result) {
    if (target == NULL || ports == NULL || out_result == NULL) {
        return -1;
    }

    memset(out_result, 0, sizeof(*out_result));
    /* target->host/ip are already bounds-checked, NUL-terminated strings
     * (cytadel_target_parse()/target_list.c's CIDR-expansion path both
     * guarantee this -- see target.h/target_list.c), and out_result->host/
     * ip are identically-sized buffers, so this copy never actually
     * truncates. strnlen()+memcpy() (the same bounded-copy idiom target.c
     * itself uses) makes that explicit instead of relying on strncpy(),
     * whose destination-size-terminated overload can't prove that to GCC's
     * -Wstringop-truncation and warns regardless. */
    size_t host_len = strnlen(target->host, sizeof(out_result->host) - 1);
    memcpy(out_result->host, target->host, host_len);
    out_result->host[host_len] = '\0';
    size_t ip_len = strnlen(target->ip, sizeof(out_result->ip) - 1);
    memcpy(out_result->ip, target->ip, ip_len);
    out_result->ip[ip_len] = '\0';

    int discovery_timeout_ms = (opts != NULL) ? opts->discovery_timeout_ms : 1000;
    int connect_timeout_ms = (opts != NULL) ? opts->connect_timeout_ms : 3000;
    bool skip_discovery = (opts != NULL) && opts->skip_discovery;

    /* Milestone 4: one KB per host (kb-schema.md §1/§6), created here and
     * owned by out_result for the remainder of this host's scan -- the
     * caller (src/core's worker pool, one thread per in-flight host)
     * never shares this KB with another thread, matching kb.h's
     * concurrency-model assumption. Created (and populated with the
     * engine-owned Host/ip + Scan/start_time keys, kb-schema.md §7.1/§7.8)
     * before discovery runs, so even a "host is down" outcome still has a
     * KB recording that fact. */
    cytadel_kb_t *kb = cytadel_kb_create();
    if (kb == NULL) {
        cytadel_log_error("host scan: failed to create KB for %s (%s)", target->host, target->ip);
        return -1;
    }
    out_result->kb = kb;

    cytadel_kb_set_str(kb, "Host/ip", target->ip);
    /* kb-schema.md §7.1 Host/hostname: "the hostname this target is known
     * by." We have no reverse-DNS lookup (and none is planned for this
     * milestone), but we DO already know a truthful hostname whenever the
     * operator typed one: target->host is the exact, unmodified spec they
     * supplied on the command line (target.h), and
     * cytadel_target_is_ipv4_literal() is the same test host_scan.c already
     * uses below to decide the TLS SNI HostName -- mirror it here. Written
     * for a hostname target; left absent for an IPv4-literal target (you
     * cannot hostname-mismatch a bare IP, so the absence is itself
     * meaningful, not a gap -- kb-schema.md's "absence, not a guessed/empty
     * value, is correct" applies exactly the same way here as it does to
     * Host/mac and HostDetails/os[_confidence] below, which really do have
     * no detection path yet). */
    if (!cytadel_target_is_ipv4_literal(target->host)) {
        cytadel_kb_set_str(kb, "Host/hostname", target->host);
    }
    char scan_start[CYTADEL_ISO8601_BUF_LEN];
    if (cytadel_log_format_timestamp_utc(scan_start, sizeof(scan_start)) == 0) {
        cytadel_kb_set_str(kb, "Scan/start_time", scan_start);
    }
    /* Host/mac (ARP, local-segment only) and HostDetails/os[_confidence]
     * (kb-schema.md §7.1) are left absent this milestone: neither
     * detection path exists yet (no ARP probe, no OS fingerprinting
     * heuristic), and kb-schema.md is explicit that absence -- not a
     * guessed/empty value -- is the correct representation. Same reasoning
     * for Scan/plugin_count (kb-schema.md §7.8): no plugin scheduler
     * existed until Milestone 5, so there was nothing truthful to count
     * yet; writing 0 would read as "zero plugins were evaluated" rather
     * than "plugin evaluation does not exist yet," so it is left unwritten
     * (TODO(M5)) rather than faked. */

    cytadel_discovery_result_t discovery =
        cytadel_discovery_probe(target->ip, discovery_timeout_ms, skip_discovery);
    out_result->state = discovery.state;
    cytadel_kb_set_str(kb, "Host/state", (discovery.state == CYTADEL_HOST_UP) ? "up" : "down");

    cytadel_log_info("host discovery: %s (%s) is %s (method=%s)", target->host, target->ip,
                      (discovery.state == CYTADEL_HOST_UP) ? "up" : "down",
                      (discovery.method_used == CYTADEL_DISCOVERY_METHOD_ICMP)       ? "icmp"
                      : (discovery.method_used == CYTADEL_DISCOVERY_METHOD_TCP_PING) ? "tcp-ping"
                                                                                       : "skipped");

    if (discovery.state != CYTADEL_HOST_UP) {
        return 0;
    }

    cytadel_port_scan_opts_t scan_opts;
    scan_opts.connect_timeout_ms = connect_timeout_ms;
    scan_opts.backend = NULL; /* auto-select (cytadel_scan_backend_select()) */

    cytadel_port_result_t *results = NULL;
    size_t result_count = 0;
    if (cytadel_port_scan(target->ip, ports, &scan_opts, &results, &result_count) != 0) {
        cytadel_log_error("port scan failed for %s (%s)", target->host, target->ip);
        return -1;
    }

    out_result->ports = results;
    out_result->port_count = result_count;

    /* kb-schema.md §7.2: Ports/tcp/<port>, one key per port actually
     * probed -- port_scanner.c itself stays KB-agnostic (see its header
     * comment), so this is where that write happens, for every entry
     * cytadel_port_scan() produced (open, closed, and filtered alike --
     * the contract only requires that un-probed ports have no key, not
     * that non-open ports be omitted). */
    for (size_t i = 0; i < result_count; i++) {
        char key[32];
        snprintf(key, sizeof(key), "Ports/tcp/%u", (unsigned)results[i].port);
        cytadel_kb_set_int(kb, key, (int64_t)results[i].state);
    }

    /* kb-schema.md §7.3-§7.5 (service-detection / tls-inspector writer
     * roles): for every OPEN port, run banner/protocol detection and (for
     * TLS-candidate ports) certificate inspection. Closed/filtered ports
     * are never probed further -- there is nothing listening to detect. */
    cytadel_service_detect_opts_t detect_opts;
    detect_opts.connect_timeout_ms = connect_timeout_ms;
    detect_opts.read_timeout_ms = connect_timeout_ms;
    /* RFC 6066 §3: the TLS SNI HostName must be a DNS name, never an IP
     * literal -- forward the user-typed name for a hostname target, NULL
     * for an IP-literal target (cytadel_target_is_ipv4_literal(), target.h).
     * Constant across every port, so resolve it once. */
    const char *sni_hostname =
        cytadel_target_is_ipv4_literal(target->host) ? NULL : target->host;
    for (size_t i = 0; i < result_count; i++) {
        if (results[i].state == CYTADEL_PORT_OPEN) {
            cytadel_service_detect_port(target->ip, results[i].port, &detect_opts, kb,
                                         sni_hostname);
        }
    }

    /* Milestone 5: the plugin schedule (docs/contracts/plugin-api.md §4.2/
     * §4.6) runs strictly AFTER service-detection/TLS-inspection above --
     * kb-schema.md's own "open assumptions" section is explicit that
     * "port/service discovery is assumed to run before the Lua plugin
     * scheduling phase begins for a given target," which is exactly the
     * ordering this function already has. Skipped entirely if the caller
     * didn't supply a registry (opts->plugin_registry == NULL) -- e.g. a
     * Milestone 1-4-only caller/test. */
    if (opts != NULL && opts->plugin_registry != NULL) {
        cytadel_plugin_run_all_for_host(opts->plugin_registry, target->ip, kb,
                                         &out_result->findings, NULL, NULL);
    }

    return 0;
}
