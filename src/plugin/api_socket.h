#ifndef CYTADEL_PLUGIN_API_SOCKET_H
#define CYTADEL_PLUGIN_API_SOCKET_H

#include <stddef.h>
#include <stdint.h>

#include <lua.h>

/* Socket userdata (docs/contracts/plugin-api.md §2.4-§2.7, §4.4) and the
 * shared raw-TCP-connect primitive api_socket.c/api_http.c both use.
 * Private to src/plugin. */

#ifdef __cplusplus
extern "C" {
#endif

#define CYTADEL_SOCKET_MT "cytadel.socket"

typedef struct {
    int fd; /* -1 once closed (idempotent close -- §2.7) */
    /* W2 security-audit fix: index into this invocation's ctx->open_fds
     * tracker (plugin_ctx.h/fd_tracker.h) -- (size_t)-1 if this socket
     * could not be tracked (an fd_tracker allocation failure at
     * open_sock_tcp() time; extremely rare, best-effort only). Used so
     * every close path (close_sock()/__gc/__close, and invoke.c's
     * end-of-invocation force-close sweep) shares one single source of
     * truth for "is this fd still open" and never double-closes it. */
    size_t track_idx;
} cytadel_plugin_socket_t;

/* Idempotent close: closes sock->fd if >= 0 and sets it to -1; a no-op if
 * already -1. Shared by close_sock() (api_socket.c) and the metatable's
 * __gc/__close (§4.4's "sockets ... not explicitly released via
 * close_sock are still force-closed when the engine calls lua_close()").
 * Also marks this socket's slot in the current invocation's ctx->open_fds
 * tracker as closed (via cytadel_plugin_ctx_get(L)) so invoke.c's
 * engine-side force-close sweep (W2) never double-closes the same fd. */
void cytadel_plugin_socket_close(lua_State *L, cytadel_plugin_socket_t *sock);

/* Non-blocking connect()+poll(POLLOUT), same shape as tcp_connect.c's
 * probe and http_probe.c's/tls_session.c's private connect helpers
 * (duplicated per-module, matching this codebase's existing convention --
 * see those files' own header comments) -- but, unlike tcp_connect.c's
 * probe, does NOT close the fd on success: this is used by open_sock_tcp()
 * (api_socket.c) and http_get()'s plain-TCP path (api_http.c), both of
 * which need the live connection afterward. The socket is switched to
 * blocking mode with SO_RCVTIMEO/SO_SNDTIMEO set to `timeout_ms` before
 * returning (same pattern as tls_session.c's cytadel_net_tls_connect()),
 * so a later send()/recv() with no more specific timeout still has a
 * kernel-enforced bound.
 *
 * On success, returns 0 and writes the connected fd (>= 0) to *out_fd. On
 * failure, returns -1, *out_fd is untouched, and a short, plugin-api.md
 * §2.4-shaped error string ("timeout", "refused", "unreachable", or a
 * short OS-level description) is written into err_buf (err_buf_len bytes,
 * always NUL-terminated, even on truncation). */
int cytadel_plugin_raw_tcp_connect(const char *ip, uint16_t port, int timeout_ms, int *out_fd,
                                    char *err_buf, size_t err_buf_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_API_SOCKET_H */
