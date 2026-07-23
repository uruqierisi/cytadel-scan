#ifndef CYTADEL_NET_SERVICE_DETECT_H
#define CYTADEL_NET_SERVICE_DETECT_H

#include <stdint.h>

#include "cytadel/kb/kb.h"

/* Service + banner detection, and TLS inspection, entry point (Milestone 4,
 * Parts B/C). This is the ONE public entry point src/net exposes for this
 * milestone's detection work -- host_scan.c (Part D) calls this once per
 * OPEN port after the port scan completes; every protocol parser (SSH/
 * HTTP/FTP), the CPE bridge, the service-token vocabulary, the generic
 * banner grab, and TLS inspection are private implementation details of
 * src/net (same-directory quote-included .c files: banner_grab.c,
 * svc_ssh.c, svc_ftp.c, svc_token.c, cpe_map.c, http_probe.c,
 * tls_session.c, tls_inspect.c) reached only through this function, the
 * same "one public orchestration entry point, several private primitives"
 * shape host_scan.h already uses for discovery.h/port_scanner.h.
 *
 * Detection only (the detection-only rule): every code path this function can
 * reach either passively reads a banner or sends a single, well-known,
 * read-only probe (a minimal HTTP GET, or a TLS ClientHello) -- never an
 * exploit payload, never any other HTTP verb, never a write beyond the
 * probe itself. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int connect_timeout_ms; /* bounds every connect()/TLS handshake this call may perform */
    int read_timeout_ms;    /* bounds every banner/HTTP-response read this call may perform */
} cytadel_service_detect_opts_t;

/* Runs service detection (and, for TLS-candidate ports, TLS inspection)
 * against `ip`:`port` -- callers must only invoke this for ports the port
 * scanner (port_scanner.h) already classified CYTADEL_PORT_OPEN; this
 * function does not itself re-probe port state. Writes zero or more
 * kb-schema.md keys into `kb` (Banner/<port>, SSH/<port>/(version|protocol),
 * HTTP/<port>/(server|status|title), FTP/<port>/banner,
 * Services/<token>/<port>, CPE/<port>, TLS/<port>/(...) -- depending on
 * what is actually detected) -- an unresponsive/unrecognized
 * service on an open port is not an error, it simply results in fewer (or
 * zero) keys written.
 *
 * `sni_hostname`: the value to send as the TLS SNI HostName if a TLS
 * handshake is attempted on `port` (cytadel_svc_is_tls_candidate_port()) --
 * NULL omits the SNI extension entirely (the caller must pass NULL when
 * `ip`'s target was specified as an IP literal; RFC 6066 SS3 does not permit
 * an IP address there), non-NULL sends that hostname verbatim (the caller's
 * target's real, user-supplied hostname -- security-review finding W4).
 * Ignored on any port this function does not attempt TLS on.
 *
 * Every socket/TLS session this function opens is closed on every path,
 * including every early-return/failure path in its private helpers
 * (banner_grab.c, http_probe.c, tls_session.c). Never crashes or reads out
 * of bounds regardless of how malformed, oversized, or actively hostile
 * the peer's response is -- every parser this function can reach performs
 * only bounds-checked, length-tracked parsing of untrusted network data
 * (no strcpy/sprintf/strtok). `opts` may be NULL to use this module's
 * built-in default timeouts. */
void cytadel_service_detect_port(const char *ip, uint16_t port,
                                  const cytadel_service_detect_opts_t *opts, cytadel_kb_t *kb,
                                  const char *sni_hostname);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SERVICE_DETECT_H */
