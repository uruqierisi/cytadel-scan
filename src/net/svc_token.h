#ifndef CYTADEL_NET_SVC_TOKEN_H
#define CYTADEL_NET_SVC_TOKEN_H

#include <stdbool.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* The frozen service-token vocabulary (docs/contracts/kb-schema.md §2):
 * "www", "https", "ssh", "ftp", "smb", "rdp", "telnet", "smtp", "pop3",
 * "imap", "dns", "snmp", "mysql", "postgresql", "redis". This file is the
 * SINGLE source of truth for that vocabulary on the engine side -- every
 * Services/<token>/<port> write in src/net goes through
 * cytadel_svc_token_write() below, so there is exactly one place that can
 * emit a token, and it is exactly the frozen list. Extending the
 * vocabulary requires updating kb-schema.md first (per its own §2), then
 * this file to match -- never the other way around. Kept private to
 * src/net (same-directory quote-include). */

#ifdef __cplusplus
extern "C" {
#endif

/* Writes Services/<token>/<port> = <port> (kb-schema.md §7.3: "Value is
 * the port number itself"), where <token> is exactly one of the frozen
 * vocabulary strings above. `token` MUST already be one of those strings
 * (callers pass a string literal from svc_token.c's own well-known-port
 * table or an equivalent hard-coded constant -- never attacker-controlled
 * text) -- this function does not itself re-validate against the
 * vocabulary list beyond what the KB's own key-charset validation already
 * enforces, since every caller in this codebase is trusted to only ever
 * pass a frozen token. Returns 0 on success, -1 on failure (already
 * logged by the underlying cytadel_kb_set_int() call). */
int cytadel_svc_token_write(cytadel_kb_t *kb, const char *token, uint16_t port);

/* Best-effort well-known TCP port -> frozen service token mapping (used as
 * the detection fallback when no banner-signature match applies, and as a
 * confirmation source when a banner signature does match -- see
 * service_detect.c). Returns the token string (a pointer to a
 * process-lifetime string literal, never freed by the caller) or NULL if
 * `port` has no well-known mapping in the frozen vocabulary. */
const char *cytadel_svc_token_for_well_known_port(uint16_t port);

/* True for ports this milestone attempts a TLS handshake on before (or
 * instead of) a plaintext banner grab -- kb-schema.md §7.5's
 * "TLS-capable ports (443/8443/993/995/...)" list from the milestone
 * brief. Not exhaustive (a full port-agnostic "try TLS on anything"
 * probe is out of scope for Milestone 4), but covers the common TLS-
 * wrapped services. */
bool cytadel_svc_is_tls_candidate_port(uint16_t port);

/* True for ports this milestone treats as "speaks HTTP" -- used both for
 * the plaintext HTTP probe dispatch and (when the port is also a TLS
 * candidate and the handshake succeeds) to decide whether to layer an
 * HTTP GET on top of the TLS session and write the paired
 * Services/www/<port> + Services/https/<port> keys per kb-schema.md
 * §7.3's `Services/https/443` row. */
bool cytadel_svc_is_http_port(uint16_t port);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SVC_TOKEN_H */
