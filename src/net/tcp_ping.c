#include "tcp_ping.h"

#include <stddef.h>

#include "cytadel/net/scan_types.h"
#include "cytadel/net/tcp_connect.h"

/* Common ports likely to have *something* listening (or at least
 * responding with RST) on most hosts -- good enough as a coarse
 * up/down signal when ICMP is unavailable. Not a substitute for the real
 * port scan that follows discovery. */
static const uint16_t CYTADEL_TCP_PING_PORTS[] = { 80, 443, 22 };
#define CYTADEL_TCP_PING_PORT_COUNT \
    (sizeof(CYTADEL_TCP_PING_PORTS) / sizeof(CYTADEL_TCP_PING_PORTS[0]))

bool cytadel_tcp_ping_probe(const char *ip, int per_probe_timeout_ms) {
    if (ip == NULL) {
        return false;
    }

    for (size_t i = 0; i < CYTADEL_TCP_PING_PORT_COUNT; i++) {
        cytadel_port_state_t state =
            cytadel_net_tcp_connect_probe(ip, CYTADEL_TCP_PING_PORTS[i], per_probe_timeout_ms);
        if (state == CYTADEL_PORT_OPEN || state == CYTADEL_PORT_CLOSED) {
            /* Either an accepted connection or an active RST -- both prove
             * something is alive and answering at this address. */
            return true;
        }
    }

    return false;
}
