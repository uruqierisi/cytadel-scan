#include "cytadel/net/port_scanner.h"

#include <stdlib.h>

#include "log.h"

int cytadel_port_scan(const char *ip, const cytadel_port_list_t *ports,
                       const cytadel_port_scan_opts_t *opts,
                       cytadel_port_result_t **out_results, size_t *out_count) {
    if (ip == NULL || ports == NULL || out_results == NULL || out_count == NULL) {
        return -1;
    }

    *out_results = NULL;
    *out_count = 0;

    if (ports->count == 0) {
        return 0;
    }

    const cytadel_scan_backend_t *backend =
        (opts != NULL && opts->backend != NULL) ? opts->backend : cytadel_scan_backend_select();
    int timeout_ms = (opts != NULL) ? opts->connect_timeout_ms : 3000;

    cytadel_port_result_t *results = calloc(ports->count, sizeof(cytadel_port_result_t));
    if (results == NULL) {
        cytadel_log_error("port scan: out of memory allocating %zu result entries", ports->count);
        return -1;
    }

    for (size_t i = 0; i < ports->count; i++) {
        uint16_t port = ports->ports[i];
        cytadel_port_state_t state = backend->probe(ip, port, timeout_ms);
        results[i].port = port;
        results[i].state = state;
        cytadel_log_debug("port scan: %s:%u -> %s", ip, (unsigned)port,
                           (state == CYTADEL_PORT_OPEN)     ? "open"
                           : (state == CYTADEL_PORT_CLOSED) ? "closed"
                                                             : "filtered");
    }

    *out_results = results;
    *out_count = ports->count;
    return 0;
}
