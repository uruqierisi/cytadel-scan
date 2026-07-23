#ifndef CYTADEL_NET_TARGET_H
#define CYTADEL_NET_TARGET_H

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/net/scan_types.h"

/* Single-host target parsing (Milestone 2). Accepts exactly one target:
 * an IPv4 literal, or a hostname resolved via getaddrinfo(). CIDR ranges
 * and comma/whitespace-separated host lists are explicitly rejected here
 * with a clear "that's Milestone 3" message rather than silently scanning
 * only the first address or being ignored.
 *
 * IPv6 is out of scope for Milestone 2, but this module is structured so
 * it can be added later without an API break: cytadel_target_parse()
 * already resolves via AF_UNSPEC and only *selects* the first IPv4 result,
 * rather than restricting the getaddrinfo() hints to AF_INET outright. A
 * future milestone that wants IPv6 support extends the selection logic
 * (and cytadel_target_t.ip's buffer, already sized via
 * CYTADEL_NET_IP_STR_MAX for a future IPv6 literal), not the parsing
 * entry point. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_TARGET_OK = 0,
    /* spec looks like a CIDR range or a comma/whitespace-separated host
     * list -- multiple targets are Milestone 3, not silently ignored. */
    CYTADEL_TARGET_ERR_MULTI,
    /* spec is empty, too long, or otherwise not a syntactically valid
     * single hostname/IPv4 literal. */
    CYTADEL_TARGET_ERR_INVALID,
    /* spec parsed as a single hostname but name resolution failed, or
     * resolved only to non-IPv4 addresses. */
    CYTADEL_TARGET_ERR_RESOLVE
} cytadel_target_status_t;

typedef struct {
    char host[CYTADEL_NET_HOST_STR_MAX]; /* copy of the original spec */
    char ip[CYTADEL_NET_IP_STR_MAX];     /* resolved IPv4 dotted-quad */
} cytadel_target_t;

/* Parses `spec` as a single target. On CYTADEL_TARGET_OK, *out_target is
 * fully populated. On any error status, a human-readable explanation is
 * written into err_buf (bounds-checked, always NUL-terminated; safe to
 * pass err_buf_len == 0 / err_buf == NULL to skip the message) and
 * *out_target is left unmodified.
 *
 * Never allocates on the heap; performs its own getaddrinfo()/
 * freeaddrinfo() pairing internally with no leak on any path. */
cytadel_target_status_t cytadel_target_parse(const char *spec,
                                              cytadel_target_t *out_target,
                                              char *err_buf, size_t err_buf_len);

/* True iff `spec` is syntactically an IPv4 dotted-quad literal (the exact
 * same inet_pton(AF_INET, ...) test cytadel_target_parse()'s own fast path
 * above uses to decide "no DNS round trip needed") -- false for a hostname,
 * NULL, or anything else. Exposed as its own function (rather than forcing
 * every caller that only needs this yes/no answer to run a full
 * cytadel_target_parse() call, which also resolves the address) so callers
 * that already hold a `cytadel_target_t.host` (the original, unmodified
 * spec the user typed) can cheaply tell "was this target specified as a
 * bare IP, or as a name?" -- e.g. host_scan.c uses this to decide whether
 * Host/hostname (kb-schema.md SS7.1) should be written at all, and whether
 * the TLS SNI extension should carry that name (see tls_session.h's
 * cytadel_net_tls_connect_sni()) or be omitted entirely for an IP-literal
 * target (RFC 6066 SS3: an IP address is not a valid SNI HostName). Never
 * performs DNS resolution itself. */
bool cytadel_target_is_ipv4_literal(const char *spec);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TARGET_H */
