#ifndef CYTADEL_NET_TCP_PING_H
#define CYTADEL_NET_TCP_PING_H

#include <stdbool.h>

/* Private to src/net -- only discovery.c calls this. TCP-ping fallback
 * host-discovery method: since raw ICMP sockets are typically unavailable
 * unprivileged, "is this host up" is instead answered by attempting a TCP
 * connect() to a handful of common ports, reusing the same connect probe
 * the port scanner itself uses (tcp_connect.h). */

/* Tries connect() against a small fixed set of common ports (80, 443, 22)
 * in turn, each bounded by per_probe_timeout_ms. The host is considered up
 * as soon as any port reports OPEN or CLOSED (a CLOSED classification
 * still means the host itself responded with a TCP RST) -- filtered
 * results move on to the next port. Returns false only if every port in
 * the set comes back filtered (no response at all). */
bool cytadel_tcp_ping_probe(const char *ip, int per_probe_timeout_ms);

#endif /* CYTADEL_NET_TCP_PING_H */
