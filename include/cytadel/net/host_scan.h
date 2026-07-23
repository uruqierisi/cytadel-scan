#ifndef CYTADEL_NET_HOST_SCAN_H
#define CYTADEL_NET_HOST_SCAN_H

#include <stdbool.h>

#include "cytadel/net/port_range.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/net/target.h"
#include "cytadel/plugin/plugin.h"

/* Single-host scan orchestration: discovery, then -- if the host is up --
 * a TCP connect port scan, followed by (Milestone 4) per-open-port service
 * detection and TLS inspection, all recorded into that host's KB
 * (docs/contracts/kb-schema.md). This is the one entry point src/cli
 * calls; it owns no CLI parsing itself (target.h/port_range.h/
 * cli_args.h already did that). */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int discovery_timeout_ms; /* per-probe timeout used by host discovery */
    int connect_timeout_ms;   /* per-port timeout used by the port scanner */
    bool skip_discovery;      /* --skip-discovery: treat the host as up, no probe */

    /* Milestone 5: borrowed pointer to a registry built once at scan
     * startup (cytadel_plugin_registry_load(), docs/contracts/
     * plugin-api.md §4.1) and shared read-only across every worker thread
     * -- the registry itself (topological plugin order, captured headers)
     * never changes once loaded, so concurrent read-only access from
     * multiple hosts' worker threads is race-free by construction (each
     * worker still creates its own fresh lua_State per invocation --
     * plugin-api.md §4.2 step 2 -- so no lua_State is ever shared across
     * threads either). May be NULL to skip the plugin phase entirely
     * (e.g. a Milestone 1-4-only caller/test, or no plugins/ directory
     * configured). Not owned by this struct or by cytadel_host_scan() --
     * the caller (src/cli/main.c) loads it once and frees it once, after
     * every worker has finished. */
    const cytadel_plugin_registry_t *plugin_registry;
} cytadel_host_scan_opts_t;

/* Runs discovery against `target`, then a port scan over `ports` if (and
 * only if) the host is up, then (for every OPEN port) service detection
 * and TLS inspection. Always populates out_result->host/ip/state and
 * out_result->kb; populates out_result->ports/port_count and this host's
 * Ports/tcp, Services, Banner, SSH/HTTP/FTP, TLS, and CPE KB namespaces
 * only when the host was discovered up (both remain NULL/0, and
 * the KB has only Host/ip, Host/state="down", and Scan/start_time, if it
 * was down).
 *
 * The caller owns *out_result and must release it exactly once via
 * cytadel_host_result_free() (which also frees out_result->kb). Returns 0
 * on success (including "host is down" -- that is a valid scan outcome,
 * not a failure), -1 on allocation failure (out_result is still safe to
 * pass to cytadel_host_result_free() in that case). */
int cytadel_host_scan(const cytadel_target_t *target, const cytadel_port_list_t *ports,
                       const cytadel_host_scan_opts_t *opts, cytadel_host_result_t *out_result);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_HOST_SCAN_H */
