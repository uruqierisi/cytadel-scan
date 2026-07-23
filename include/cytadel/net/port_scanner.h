#ifndef CYTADEL_NET_PORT_SCANNER_H
#define CYTADEL_NET_PORT_SCANNER_H

#include <stddef.h>

#include "cytadel/net/port_range.h"
#include "cytadel/net/scan_backend.h"
#include "cytadel/net/scan_types.h"

/* Single-host TCP port scanner (Milestone 2). Iterates a
 * cytadel_port_list_t sequentially, probing each port through a
 * cytadel_scan_backend_t (tcp-connect today; a future SYN backend later,
 * see scan_backend.h). No threading yet -- concurrent multi-host/multi-port
 * scanning is Milestone 3. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    /* Per-port connect timeout in milliseconds, forwarded to the backend's
     * probe function. */
    int connect_timeout_ms;
    /* Backend to scan with. NULL selects cytadel_scan_backend_select()'s
     * choice at call time. */
    const cytadel_scan_backend_t *backend;
} cytadel_port_scan_opts_t;

/* Scans every port in `ports` against `ip` (already-resolved IPv4
 * dotted-quad) using opts->backend (or the auto-selected backend if
 * opts->backend is NULL / opts is NULL). Allocates *out_results as a fresh
 * array with one entry per port in `ports`, in the same order; the caller
 * owns it and must free() it (or embed it in a cytadel_host_result_t and
 * call cytadel_host_result_free()).
 *
 * Milestone 4: host_scan.c is where each cytadel_port_result_t gets
 * written into that host's KB as Ports/tcp/<port>
 * (docs/contracts/kb-schema.md §7.2) -- this function itself stays
 * KB-agnostic by design, so it remains unit-testable independent of
 * src/kb.
 *
 * Returns 0 on success (including the case where ports->count == 0, which
 * yields *out_count == 0 and *out_results == NULL), -1 on invalid
 * arguments or allocation failure (nothing is left partially allocated). */
int cytadel_port_scan(const char *ip, const cytadel_port_list_t *ports,
                       const cytadel_port_scan_opts_t *opts,
                       cytadel_port_result_t **out_results, size_t *out_count);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_PORT_SCANNER_H */
