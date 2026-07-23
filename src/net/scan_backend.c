#include "cytadel/net/scan_backend.h"

#include "cytadel/net/tcp_connect.h"

static const cytadel_scan_backend_t g_connect_backend = {
    .kind = CYTADEL_SCAN_BACKEND_CONNECT,
    .probe = cytadel_net_tcp_connect_probe
};

const cytadel_scan_backend_t *cytadel_scan_backend_connect(void) {
    return &g_connect_backend;
}

const cytadel_scan_backend_t *cytadel_scan_backend_select(void) {
    /* TODO(future milestone): once a SYN backend exists, branch here on
     * cytadel_net_can_use_raw_sockets() (capability.h) and libpcap
     * availability (CYTADEL_HAVE_PCAP, docs/build-plan.md §2) to prefer
     * it. Milestone 2 has only the connect backend, so raw-socket
     * capability is not even queried yet -- there is nothing to select
     * between. */
    return cytadel_scan_backend_connect();
}
