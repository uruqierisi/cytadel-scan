#ifndef CYTADEL_NET_DISCOVERY_H
#define CYTADEL_NET_DISCOVERY_H

#include <stdbool.h>

#include "cytadel/net/scan_types.h"

/* Single-host discovery (Milestone 2): decide up/down before port
 * scanning. Prefers an ICMP echo probe (needs a raw socket, typically
 * unprivileged in WSL/containers) and falls back to a TCP-ping probe
 * (connect attempts against a few common ports) when raw sockets are
 * unavailable -- never requires root. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_DISCOVERY_METHOD_ICMP     = 0,
    CYTADEL_DISCOVERY_METHOD_TCP_PING = 1,
    /* --skip-discovery / treat-as-up: no probe was sent at all. */
    CYTADEL_DISCOVERY_METHOD_SKIPPED  = 2
} cytadel_discovery_method_t;

typedef struct {
    cytadel_host_state_t state;
    cytadel_discovery_method_t method_used;
} cytadel_discovery_result_t;

/* Pure decision function (no I/O): which discovery method should be
 * attempted first, given whether raw sockets are currently available?
 * Unit-testable without a real socket by stubbing the bool the capability
 * probe (cytadel_net_can_use_raw_sockets(), capability.h) would return. */
cytadel_discovery_method_t cytadel_discovery_choose_method(bool raw_sockets_available);

/* Runs host discovery against `ip` (already-resolved IPv4 dotted-quad).
 *
 * If skip_discovery is true, performs no I/O at all and returns UP with
 * method CYTADEL_DISCOVERY_METHOD_SKIPPED -- lets an operator force-scan a
 * host that blocks every discovery probe (--skip-discovery).
 *
 * Otherwise: queries cytadel_net_can_use_raw_sockets() and follows
 * cytadel_discovery_choose_method()'s choice. If ICMP is chosen but the
 * raw socket cannot actually be opened at probe time (a defensive
 * second check against a race between the capability probe and the real
 * attempt), falls back to TCP-ping rather than erroring -- discovery never
 * requires root. probe_timeout_ms bounds each individual probe (an ICMP
 * echo wait, or each TCP-ping connect attempt). */
cytadel_discovery_result_t cytadel_discovery_probe(const char *ip, int probe_timeout_ms,
                                                     bool skip_discovery);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_DISCOVERY_H */
