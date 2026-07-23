#ifndef CYTADEL_NET_SCAN_BACKEND_H
#define CYTADEL_NET_SCAN_BACKEND_H

#include <stdint.h>

#include "cytadel/net/scan_types.h"

/* Capability seam for the port scanner: a `cytadel_scan_backend_t` is a
 * single "probe one port" function pointer, selected at scan start. This
 * lets a privileged raw-socket SYN backend be added later (needs
 * CAP_NET_RAW/root plus libpcap for response capture -- explicitly out of
 * scope for Milestone 2) without changing port_scanner.c's call sites: it
 * would just add another cytadel_scan_backend_t and extend
 * cytadel_scan_backend_select()'s capability check. Milestone 2 ships only
 * the TCP-connect backend. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_SCAN_BACKEND_CONNECT = 0
    /* CYTADEL_SCAN_BACKEND_SYN reserved for a future milestone; see the
     * header comment above and cytadel_net_can_use_raw_sockets()
     * (capability.h). */
} cytadel_scan_backend_kind_t;

/* Probes a single port on ip and returns its classification. Same
 * detection-only, close-immediately contract as
 * cytadel_net_tcp_connect_probe() (tcp_connect.h), which is what the
 * connect backend below delegates to. */
typedef cytadel_port_state_t (*cytadel_scan_backend_probe_fn)(const char *ip, uint16_t port,
                                                                int timeout_ms);

typedef struct {
    cytadel_scan_backend_kind_t kind;
    cytadel_scan_backend_probe_fn probe;
} cytadel_scan_backend_t;

/* The TCP-connect backend (Milestone 2's only backend). Returns a pointer
 * to a static, immutable instance -- never NULL, nothing to free. */
const cytadel_scan_backend_t *cytadel_scan_backend_connect(void);

/* Returns the best backend currently available: a SYN backend if
 * cytadel_net_can_use_raw_sockets() reports raw-socket capability (not
 * implemented yet -- Milestone 2 has no SYN backend to select, so this
 * currently always returns the connect backend regardless of capability),
 * otherwise the TCP-connect backend. Never returns NULL. */
const cytadel_scan_backend_t *cytadel_scan_backend_select(void);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SCAN_BACKEND_H */
