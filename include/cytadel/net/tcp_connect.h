#ifndef CYTADEL_NET_TCP_CONNECT_H
#define CYTADEL_NET_TCP_CONNECT_H

#include <stdint.h>

#include "cytadel/net/scan_types.h"

/* The single non-blocking TCP connect() probe primitive used by both the
 * connect scan backend (scan_backend.h) and the TCP-ping discovery
 * fallback (discovery.h) -- one implementation, so both call sites share
 * the exact same timeout/classification behavior. */

#ifdef __cplusplus
extern "C" {
#endif

/* Attempts a non-blocking connect() to ip:port and classifies the result:
 *   CYTADEL_PORT_OPEN     -- connect() succeeded.
 *   CYTADEL_PORT_CLOSED   -- connection actively refused (RST / ECONNREFUSED).
 *   CYTADEL_PORT_FILTERED -- no response within timeout_ms, or any other
 *                            connect()/socket() failure (unreachable, host
 *                            down, out of local resources, ...) -- treated
 *                            as "could not determine," never as "closed."
 *
 * Detection-only: the socket is closed immediately after connecting (or
 * after the timeout/error), no bytes are ever sent or read. Every socket
 * fd this function opens is closed on every return path, including all
 * error paths. `ip` must be a valid IPv4 dotted-quad literal (already
 * resolved -- this function does not perform DNS resolution). */
cytadel_port_state_t cytadel_net_tcp_connect_probe(const char *ip, uint16_t port,
                                                     int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TCP_CONNECT_H */
