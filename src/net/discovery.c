#include "cytadel/net/discovery.h"

#include "cytadel/net/capability.h"
#include "icmp_probe.h"
#include "log.h"
#include "tcp_ping.h"

cytadel_discovery_method_t cytadel_discovery_choose_method(bool raw_sockets_available) {
    return raw_sockets_available ? CYTADEL_DISCOVERY_METHOD_ICMP
                                  : CYTADEL_DISCOVERY_METHOD_TCP_PING;
}

cytadel_discovery_result_t cytadel_discovery_probe(const char *ip, int probe_timeout_ms,
                                                     bool skip_discovery) {
    cytadel_discovery_result_t result;
    result.state = CYTADEL_HOST_DOWN;
    result.method_used = CYTADEL_DISCOVERY_METHOD_TCP_PING;

    if (skip_discovery) {
        cytadel_log_debug("host discovery skipped for %s (--skip-discovery); treating as up", ip);
        result.state = CYTADEL_HOST_UP;
        result.method_used = CYTADEL_DISCOVERY_METHOD_SKIPPED;
        return result;
    }

    bool raw_available = cytadel_net_can_use_raw_sockets();
    cytadel_discovery_method_t method = cytadel_discovery_choose_method(raw_available);

    if (method == CYTADEL_DISCOVERY_METHOD_ICMP) {
        cytadel_icmp_result_t icmp_result = cytadel_icmp_echo_probe(ip, probe_timeout_ms);
        if (icmp_result != CYTADEL_ICMP_UNAVAILABLE) {
            cytadel_log_debug("host discovery for %s used ICMP echo", ip);
            result.method_used = CYTADEL_DISCOVERY_METHOD_ICMP;
            result.state = (icmp_result == CYTADEL_ICMP_REPLY_UP) ? CYTADEL_HOST_UP
                                                                    : CYTADEL_HOST_DOWN;
            return result;
        }
        /* Raw socket capability changed between cytadel_net_can_use_raw_
         * sockets() and the real attempt (or the capability probe raced
         * with something else) -- fall back rather than erroring. Host
         * discovery must never require root. */
        cytadel_log_debug("ICMP raw socket unavailable for %s at probe time; "
                           "falling back to TCP ping", ip);
    }

    bool up = cytadel_tcp_ping_probe(ip, probe_timeout_ms);
    cytadel_log_debug("host discovery for %s used TCP ping (fallback)", ip);
    result.method_used = CYTADEL_DISCOVERY_METHOD_TCP_PING;
    result.state = up ? CYTADEL_HOST_UP : CYTADEL_HOST_DOWN;
    return result;
}
