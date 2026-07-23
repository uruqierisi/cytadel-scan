#ifndef CYTADEL_NET_SCAN_TYPES_H
#define CYTADEL_NET_SCAN_TYPES_H

#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"

/* Shared result/state types for src/net (Milestone 2: single-host TCP
 * connect scanning + discovery; Milestone 4 adds the per-host KB --
 * cytadel_host_result_t.kb below -- populated by cytadel_host_scan()
 * itself, per host, per docs/contracts/kb-schema.md). */

#ifdef __cplusplus
extern "C" {
#endif

/* Longest target spec (hostname or IPv4 literal) this module stores.
 * RFC 1035 caps a full hostname at 255 bytes; +1 for the NUL. */
#define CYTADEL_NET_HOST_STR_MAX 256

/* Long enough for a dotted-quad IPv4 literal ("255.255.255.255\0" = 16
 * bytes) with headroom to reuse the same buffer size for a future IPv6
 * literal (INET6_ADDRSTRLEN is 46). */
#define CYTADEL_NET_IP_STR_MAX 46

/* Per-port classification. Values are pinned to
 * docs/contracts/kb-schema.md §7.2 `Ports/tcp/<port>` (FROZEN): 0=closed,
 * 1=open, 2=filtered. A future Milestone 4 KB-population pass stores these
 * ints unchanged via set_kb_item("Ports/tcp/<port>", state) -- do not
 * renumber this enum without re-checking that contract. */
typedef enum {
    CYTADEL_PORT_CLOSED   = 0,
    CYTADEL_PORT_OPEN     = 1,
    CYTADEL_PORT_FILTERED = 2
} cytadel_port_state_t;

typedef struct {
    uint16_t port;
    cytadel_port_state_t state;
} cytadel_port_result_t;

/* Mirrors docs/contracts/kb-schema.md §7.1 `Host/state` ("up"/"down"),
 * kept as an enum on the C side; the string mapping only matters once
 * src/kb exists (TODO(M4)). */
typedef enum {
    CYTADEL_HOST_DOWN = 0,
    CYTADEL_HOST_UP   = 1
} cytadel_host_state_t;

typedef struct {
    char host[CYTADEL_NET_HOST_STR_MAX]; /* original target spec (hostname or IPv4 literal) */
    char ip[CYTADEL_NET_IP_STR_MAX];     /* resolved IPv4 dotted-quad */
    cytadel_host_state_t state;

    /* Heap array owned by this struct, one entry per port actually probed
     * (ports not scanned have no entry -- matches kb-schema.md §7.2 "only
     * written for ports actually probed"). NULL / 0 when the host was
     * down and no port scan ran. */
    cytadel_port_result_t *ports;
    size_t port_count;

    /* Milestone 4: this host's KB (docs/contracts/kb-schema.md), created
     * and fully populated by cytadel_host_scan() itself (Host/ip,
     * Host/state, Scan/start_time, Ports/tcp/<port>, and every
     * service-detection/TLS-inspection fact for each open port -- see
     * host_scan.c). One KB per host, owned by this result struct; freed
     * by cytadel_host_result_free() below. NULL only if KB allocation
     * itself failed (cytadel_host_scan() returns -1 in that case) or the
     * struct was never populated (a freshly zeroed/calloc'd result). */
    cytadel_kb_t *kb;

    /* Milestone 5: every finding this host's plugin schedule reported
     * (docs/contracts/plugin-api.md §2.9's report_vuln{}/
     * security_report{}), populated by cytadel_host_scan() itself after
     * service-detection/TLS-inspection completes (see host_scan.c) --
     * empty (count == 0, items == NULL) if no plugin registry was
     * supplied to cytadel_host_scan_opts_t.plugin_registry (e.g. no
     * plugins/ directory yet, or a caller/test that only wants
     * Milestone 1-4 port/service/TLS facts) or if the host was down. */
    cytadel_finding_list_t findings;
} cytadel_host_result_t;

/* Frees result->ports, result->kb, and result->findings (if any) and
 * zeroes the struct. Safe to call on an already-freed/zeroed result
 * (idempotent) and on a NULL pointer (no-op). */
void cytadel_host_result_free(cytadel_host_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SCAN_TYPES_H */
