#ifndef CYTADEL_NET_TLS_SESSION_H
#define CYTADEL_NET_TLS_SESSION_H

#include <stdint.h>

#include <openssl/ssl.h>

/* TLS connect/handshake primitive (Milestone 4, Part C). Kept private to
 * src/net (same-directory quote-include).
 *
 * INSPECTION ONLY -- this scanner never validates certificate trust
 * (SSL_VERIFY_NONE) and never fails a handshake because of an invalid,
 * expired, self-signed, or hostname-mismatched certificate. That is
 * deliberate: the entire point of tls_inspect.c is to report exactly what
 * certificate a service presents, including a broken one -- a scanner
 * that refused to complete the handshake with a self-signed cert could
 * never detect (and report) that the target is using a self-signed cert
 * in the first place. This does not touch the *scanner's own* memory
 * safety in any way (OpenSSL's verification bypass only affects whether
 * the handshake succeeds/fails, not how the resulting session is used --
 * every certificate field this module reads afterward is still
 * bounds-checked exactly as if verification had been on, see
 * tls_inspect.c). */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    int fd;
} cytadel_tls_session_t;

/* Connects to ip:port and completes a TLS handshake. The TCP connect
 * itself is bounded by `timeout_ms` via the same non-blocking
 * connect()+poll(POLLOUT) pattern used throughout src/net; once connected,
 * the socket is switched to blocking mode with SO_RCVTIMEO/SO_SNDTIMEO set
 * to `timeout_ms`, so the handshake itself (and any later SSL_read()/
 * SSL_write() on this session, e.g. http_probe.c's TLS variant) is bounded
 * by the same timeout without needing non-blocking OpenSSL I/O state
 * handling.
 *
 * Returns 0 and populates *out_session (ctx/ssl/fd all valid, fd >= 0) on
 * a successful handshake. Returns -1 on ANY failure (socket, connect,
 * SSL_CTX_new, SSL_new, SSL_set_fd, or the handshake itself) -- this is
 * reported as "no TLS on this port," never a fatal error for the
 * surrounding scan (a plain TCP service on a TLS-candidate port, or a
 * server that resets/times out the handshake, is an entirely expected
 * outcome). *out_session is always zeroed with fd == -1 on failure, so it
 * is always safe to pass to cytadel_net_tls_session_close() regardless of
 * this function's return value.
 *
 * SNI: sends `ip` itself as the TLS SNI HostName (security-review finding
 * W4: this IS non-conformant -- RFC 6066 SS3 defines SNI as a hostname, not
 * an IP address literal -- and, contrary to what an earlier version of this
 * comment claimed, SNI-based certificate selection is the entire purpose of
 * the extension, so this CAN cause a name-based virtual-hosting/shared-
 * frontend server to hand back its default vhost certificate rather than
 * the one a real client requesting `ip` by name would see). This legacy
 * behavior is kept, unchanged, ONLY because it is relied on by callers
 * outside src/net (src/plugin/api_http.c's http_get() binding) that never
 * have anything but a bare IP address available in the first place (the
 * plugin API's `ctx->ip` is always an address, never a hostname) -- for
 * those callers an IP-as-SNI ClientHello is at least deterministic and
 * matches this project's pre-existing, already-shipped behavior; fixing it
 * for that path is a separate, out-of-scope change (it touches src/plugin,
 * not src/net, and needs its own review). The src/net-internal host-scan ->
 * service-detection -> TLS-inspection flow that W4 is actually about no
 * longer calls this function -- it calls cytadel_net_tls_connect_sni()
 * below, which sends the real target hostname (or omits SNI entirely for
 * an IP-literal target, per RFC 6066) instead. */
int cytadel_net_tls_connect(const char *ip, uint16_t port, int timeout_ms,
                             cytadel_tls_session_t *out_session);

/* Same as cytadel_net_tls_connect() above, except the TLS SNI HostName sent
 * in the ClientHello is controlled explicitly via `sni_hostname` instead of
 * always being `ip`:
 *   - `sni_hostname` non-NULL: sent verbatim as the SNI HostName. Callers
 *     must pass the target's real, user-supplied hostname here (never an
 *     IP-literal string) -- this is what lets a name-based virtual-hosting
 *     server route to the correct certificate for that name.
 *   - `sni_hostname` NULL: the SNI extension is omitted from the
 *     ClientHello entirely (SSL_set_tlsext_host_name() is never called).
 *     Callers must pass NULL when the target was specified as an IP
 *     literal -- RFC 6066 SS3 defines the SNI HostName as a fully qualified
 *     domain name, so sending an IP address literal there is invalid; the
 *     safe, conformant choice for an IP-literal target is no SNI at all,
 *     not an incorrect one.
 * This is the entry point service_detect.c's TLS-candidate-port path uses
 * (host_scan.c decides, once per host, whether the target is a hostname or
 * an IP literal via cytadel_target_is_ipv4_literal() and threads that
 * decision all the way down to this call). Every other aspect (timeout
 * bounding, ctx/ssl/fd lifetime, return-value/error semantics,
 * always-safe-to-close *out_session) is identical to
 * cytadel_net_tls_connect() above. */
int cytadel_net_tls_connect_sni(const char *ip, const char *sni_hostname, uint16_t port,
                                 int timeout_ms, cytadel_tls_session_t *out_session);

/* Frees ssl (best-effort SSL_shutdown() first), ctx, and closes fd -- in
 * that order, on every path. Safe to call on a zeroed/partially
 * initialized session (every field NULL/-1, e.g. after a failed
 * cytadel_net_tls_connect() or on a stack variable the caller zero-
 * initialized itself) and idempotent (every field is reset to its "empty"
 * value after being freed, so calling this twice on the same session is
 * safe -- ordinary single-owner cleanup discipline, matching
 * cytadel_kb_free()/cytadel_host_result_free() elsewhere in this
 * codebase). No-op if session is NULL. */
void cytadel_net_tls_session_close(cytadel_tls_session_t *session);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TLS_SESSION_H */
