#ifndef CYTADEL_NET_CAPABILITY_H
#define CYTADEL_NET_CAPABILITY_H

#include <stdbool.h>

/* Runtime privilege probes for src/net. Raw-socket operations (ICMP echo
 * discovery today; a future SYN-scan backend later) need CAP_NET_RAW or
 * root, which is typically unavailable in WSL/containers -- this module
 * lets callers detect that at runtime and fall back gracefully instead of
 * requiring the operator to run as root. */

#ifdef __cplusplus
extern "C" {
#endif

/* Best-effort check: can this process open a raw socket right now? Probes
 * by actually attempting socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) and
 * closing it immediately on success -- this is the same privilege check
 * the kernel itself enforces, so it is more reliable than checking
 * geteuid() == 0 (which misses CAP_NET_RAW-only grants) or guessing from
 * environment variables.
 *
 * Never requires root to call (the probe itself simply fails closed on
 * EPERM/EACCES and returns false). Used both by host discovery (ICMP vs.
 * TCP-ping fallback, see discovery.h) and by scan-backend selection
 * (connect vs. a future SYN backend, see scan_backend.h) so both decisions
 * share one implementation. */
bool cytadel_net_can_use_raw_sockets(void);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_CAPABILITY_H */
