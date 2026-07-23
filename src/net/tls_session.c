#define _POSIX_C_SOURCE 200809L

#include "tls_session.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "log.h"
#include "strerror_safe.h"

/* Same non-blocking connect()+poll(POLLOUT) shape as tcp_connect.c's probe
 * and banner_grab.c's cytadel_banner_connect() -- see http_probe.c's
 * identical helper for why this is duplicated per-module rather than
 * shared (an established pattern in this codebase already, not new to
 * Milestone 4). Returns the connected fd (>= 0) on success, -1 on any
 * failure (fd already closed). */
static int cytadel_tls_raw_connect(const char *ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("tls: socket() failed for %s:%u: %s", ip, (unsigned)port,
                          cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        return fd;
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;
    int poll_rc = poll(&pfd, 1, (timeout_ms < 0) ? 0 : timeout_ms);
    if (poll_rc <= 0) {
        close(fd);
        return -1;
    }

    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0 || so_error != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* Shared implementation behind both cytadel_net_tls_connect() and
 * cytadel_net_tls_connect_sni() (tls_session.h) -- identical in every
 * respect except which value (if any) gets sent as the TLS SNI HostName;
 * see tls_session.h's doc comments on both public entry points for the
 * exact SNI contract `sni_hostname` implements here (NULL == omit the
 * extension, non-NULL == sent verbatim). */
static int cytadel_net_tls_connect_impl(const char *ip, const char *sni_hostname, uint16_t port,
                                         int timeout_ms, cytadel_tls_session_t *out_session) {
    if (out_session != NULL) {
        memset(out_session, 0, sizeof(*out_session));
        out_session->fd = -1;
    }
    if (ip == NULL || port == 0 || out_session == NULL) {
        return -1;
    }
    /* Security-review round-3 finding S-1 (SUGGESTION, defense in depth):
     * floor to 1 ms, never 0 -- matches api_socket.c's
     * cytadel_plugin_raw_tcp_connect() (security-review round-2 FIX 2).
     * cytadel_tls_raw_connect()'s poll(POLLOUT, timeout_ms) below treats 0
     * as "don't block" (harmless), but the SO_RCVTIMEO/SO_SNDTIMEO timeval
     * built from this same timeout_ms further down (once connected, before
     * the TLS handshake) is where an all-zero {0,0} value is dangerous: on
     * Linux that means "no timeout" (block forever), not "expire
     * immediately". The only current caller (api_http.c's http_get() TLS
     * path) already clamps its timeout_ms to at least 1 before reaching
     * here (cytadel_plugin_clamp_timeout_ms(), api_http.c:513), so this is
     * defense in depth for this primitive itself -- consistent with, not a
     * substitute for, that clamp -- since nothing here guarantees every
     * future caller will remember to clamp first. */
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }

    int fd = cytadel_tls_raw_connect(ip, port, timeout_ms);
    if (fd < 0) {
        return -1;
    }

    /* Switch back to blocking + bound every subsequent read/write
     * (handshake included) with a kernel-level timeout, so SSL_connect()/
     * SSL_read()/SSL_write() never need non-blocking OpenSSL I/O-state
     * handling (SSL_ERROR_WANT_READ/WANT_WRITE retry loops) -- a timed-out
     * blocking call simply fails, which this module already treats as
     * "no TLS here," the correct outcome either way. */
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        cytadel_log_warn("tls: SSL_CTX_new() failed for %s:%u", ip, (unsigned)port);
        close(fd);
        return -1;
    }

    /* INSPECTION ONLY: never validate trust -- see this header's comment.
     * Also allow the widest protocol range so a legacy/misconfigured
     * server's actual negotiated version is what gets reported (that is
     * itself a fact worth detecting, e.g. a server that only offers
     * TLSv1.0), rather than the engine's own OpenSSL refusing to attempt
     * anything below its default minimum. */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    SSL_CTX_set_min_proto_version(ctx, 0);
    SSL_CTX_set_max_proto_version(ctx, 0);

    SSL *ssl = SSL_new(ctx);
    if (ssl == NULL) {
        cytadel_log_warn("tls: SSL_new() failed for %s:%u", ip, (unsigned)port);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    if (SSL_set_fd(ssl, fd) != 1) {
        cytadel_log_warn("tls: SSL_set_fd() failed for %s:%u", ip, (unsigned)port);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    /* SNI: see this function's two public wrappers (tls_session.h) for the
     * full contract -- `sni_hostname` is NULL (omit the extension, the
     * RFC 6066-conformant choice for an IP-literal target) or a real
     * hostname to send verbatim. Never `ip` here; a bare IPv4-literal SNI
     * IS non-conformant (RFC 6066 SS3) and DOES affect which certificate a
     * name-based virtual-hosting/shared-frontend server hands back. */
    if (sni_hostname != NULL) {
        SSL_set_tlsext_host_name(ssl, sni_hostname);
    }

    int rc = SSL_connect(ssl);
    if (rc != 1) {
        cytadel_log_debug("tls: handshake did not complete for %s:%u", ip, (unsigned)port);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(fd);
        return -1;
    }

    out_session->ctx = ctx;
    out_session->ssl = ssl;
    out_session->fd = fd;
    return 0;
}

int cytadel_net_tls_connect(const char *ip, uint16_t port, int timeout_ms,
                             cytadel_tls_session_t *out_session) {
    /* Legacy SNI-is-`ip` behavior, preserved as-is for callers outside
     * src/net -- see this function's own doc comment in tls_session.h. */
    return cytadel_net_tls_connect_impl(ip, ip, port, timeout_ms, out_session);
}

int cytadel_net_tls_connect_sni(const char *ip, const char *sni_hostname, uint16_t port,
                                 int timeout_ms, cytadel_tls_session_t *out_session) {
    return cytadel_net_tls_connect_impl(ip, sni_hostname, port, timeout_ms, out_session);
}

void cytadel_net_tls_session_close(cytadel_tls_session_t *session) {
    if (session == NULL) {
        return;
    }

    if (session->ssl != NULL) {
        /* Best-effort only -- a detection scanner has no need for a full
         * bidirectional TLS shutdown handshake; one SSL_shutdown() call
         * sends a close_notify without blocking on the peer's reply
         * (matches the "close immediately" style already used by
         * tcp_connect.c's probe). Return value intentionally ignored: any
         * outcome still leads to freeing the session below. */
        SSL_shutdown(session->ssl);
        SSL_free(session->ssl);
        session->ssl = NULL;
    }
    if (session->ctx != NULL) {
        SSL_CTX_free(session->ctx);
        session->ctx = NULL;
    }
    if (session->fd >= 0) {
        close(session->fd);
        session->fd = -1;
    }
}
