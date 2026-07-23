#define _POSIX_C_SOURCE 200809L

#include "api_functions.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <lauxlib.h>

#include "api_socket.h"
#include "fd_tracker.h"
#include "plugin_ctx.h"
#include "strerror_safe.h"
#include "timeout_clamp.h"

void cytadel_plugin_socket_close(lua_State *L, cytadel_plugin_socket_t *sock) {
    if (sock == NULL || sock->fd < 0) {
        return; /* §2.7: idempotent -- closing an already-closed socket is a silent no-op */
    }
    /* W2 / security-review round-2 FIX 1 (belt and braces): ctx should
     * never be NULL here in practice (every socket userdata is only ever
     * created inside the run-phase sandbox, where cytadel_plugin_ctx_set()
     * has always already run), but the NULL check keeps this safe as a
     * standalone primitive regardless. */
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);

    /* Security-review round-3 finding W-1 (WARNING): "tracked" and "closed"
     * are two independent questions -- see fd_tracker.h's own comment on
     * cytadel_plugin_fd_tracker_is_closed(). sock->track_idx == (size_t)-1
     * (this socket's registration into ctx->open_fds itself failed under
     * OOM -- see open_sock_tcp()'s comment in this file) is UNTRACKED, not
     * "already closed" -- collapsing the two (as the old
     * `is_closed() -> skip close()` check below used to) silently leaked
     * that fd forever: nothing else was ever going to close it, since
     * neither the tracker's own mark-closed bookkeeping nor invoke.c's
     * end-of-invocation force-close sweep know it exists. Only a genuinely
     * TRACKED slot that is ALSO already marked closed is safe to skip.
     *
     * Security-review round-4 finding W-1 (regression + fix): a slot stays
     * "tracked" by cytadel_plugin_fd_tracker_is_tracked() even after
     * ctx->open_fds has been cytadel_plugin_fd_tracker_free()'d (e.g. by
     * invoke.c's end-of-invocation cleanup running before a socket
     * userdata's own __gc/__close does, if the FIX 1 ordering were ever
     * reverted) -- and cytadel_plugin_fd_tracker_is_closed() reports such a
     * freed slot as closed too. So `tracked && is_closed(...)` below still
     * correctly takes the skip-close() branch in that scenario. This was
     * NOT true of round 3's implementation (free() reset the tracker's
     * `count` to 0, which made is_tracked() start returning false for
     * every post-free lookup, defeating this exact guard) -- see
     * fd_tracker.c/.h for the fix. */
    bool tracked = ctx != NULL && cytadel_plugin_fd_tracker_is_tracked(&ctx->open_fds, sock->track_idx);
    if (tracked && cytadel_plugin_fd_tracker_is_closed(&ctx->open_fds, sock->track_idx)) {
        /* The tracker already considers this slot closed -- e.g. invoke.c's
         * end-of-invocation force-close sweep beat this call to it. Do NOT
         * close() again: this scanner's workers are pthreads sharing one
         * process-global fd namespace, so by the time we get here the fd
         * number could already belong to a completely unrelated
         * connection on another thread. Just make this userdata's own
         * view consistent (idempotent -- matches the sock->fd < 0 guard
         * above) and return. */
        sock->fd = -1;
        return;
    }
    /* Mark this socket's slot closed in the invocation's fd tracker BEFORE
     * actually closing it, so invoke.c's end-of-invocation force-close
     * sweep (which shares that same tracker) can never race ahead of this
     * and double-close the same fd number. Only meaningful for a tracked
     * slot -- an untracked fd (W-1) has no tracker slot to mark and always
     * falls straight through to the real close() below, exactly as it
     * must. */
    if (tracked) {
        cytadel_plugin_fd_tracker_mark_closed(&ctx->open_fds, sock->track_idx);
    }
    close(sock->fd);
    sock->fd = -1;
}

int cytadel_plugin_raw_tcp_connect(const char *ip, uint16_t port, int timeout_ms, int *out_fd,
                                    char *err_buf, size_t err_buf_len) {
    if (err_buf != NULL && err_buf_len > 0) {
        err_buf[0] = '\0';
    }
    /* FIX 2 (CRITICAL, security-review round 2): floor to 1 ms, never 0 --
     * this connect()'s poll(POLLOUT, timeout_ms) itself treats 0 as "don't
     * block" (harmless), but the SO_RCVTIMEO/SO_SNDTIMEO timeval built from
     * this same timeout_ms further down (once connected) is where a 0
     * value is dangerous: an all-zero {0,0} timeval means "no timeout"
     * (block forever) on Linux, not "expire immediately". Every real
     * caller (api_socket.c's open_sock_tcp(), api_http.c's http_get())
     * already routes its timeout_ms through cytadel_plugin_clamp_timeout_ms()
     * first, which floors to 1 as its own single source of truth -- this
     * floor here is defense in depth for this primitive itself, since it
     * is not otherwise guaranteed every future caller will remember to
     * clamp first. */
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        snprintf(err_buf, err_buf_len, "%s", cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(fd);
        snprintf(err_buf, err_buf_len, "%s", "socket setup failed");
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        snprintf(err_buf, err_buf_len, "%s", "invalid IPv4 address");
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        if (errno == EINPROGRESS) {
            struct pollfd pfd;
            pfd.fd = fd;
            pfd.events = POLLOUT;
            pfd.revents = 0;
            int poll_rc = poll(&pfd, 1, timeout_ms);
            if (poll_rc == 0) {
                close(fd);
                snprintf(err_buf, err_buf_len, "%s", "timeout");
                return -1;
            }
            if (poll_rc < 0) {
                close(fd);
                snprintf(err_buf, err_buf_len, "%s", "poll failed");
                return -1;
            }
            int so_error = 0;
            socklen_t so_error_len = sizeof(so_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
                close(fd);
                snprintf(err_buf, err_buf_len, "%s", "getsockopt failed");
                return -1;
            }
            if (so_error == ECONNREFUSED) {
                close(fd);
                snprintf(err_buf, err_buf_len, "%s", "refused");
                return -1;
            }
            if (so_error == EHOSTUNREACH || so_error == ENETUNREACH) {
                close(fd);
                snprintf(err_buf, err_buf_len, "%s", "unreachable");
                return -1;
            }
            if (so_error != 0) {
                close(fd);
                char errbuf[CYTADEL_STRERROR_BUF_LEN];
                snprintf(err_buf, err_buf_len, "%s",
                         cytadel_strerror_safe(so_error, errbuf, sizeof(errbuf)));
                return -1;
            }
        } else if (errno == ECONNREFUSED) {
            close(fd);
            snprintf(err_buf, err_buf_len, "%s", "refused");
            return -1;
        } else if (errno == EHOSTUNREACH || errno == ENETUNREACH) {
            close(fd);
            snprintf(err_buf, err_buf_len, "%s", "unreachable");
            return -1;
        } else {
            close(fd);
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            snprintf(err_buf, err_buf_len, "%s", cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
            return -1;
        }
    }

    /* Connected -- switch back to blocking with a kernel-enforced
     * send/recv timeout (same pattern as tls_session.c's
     * cytadel_net_tls_connect()), so send()/recv() never need non-blocking
     * retry-loop handling; a timed-out blocking call simply fails with
     * EAGAIN/EWOULDBLOCK, which api_socket.c's send()/recv() bindings
     * already translate to "timeout". */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags != -1) {
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
    }
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    *out_fd = fd;
    return 0;
}

/* §2.4 open_sock_tcp(port [, timeout_ms]) -> socket userdata | nil, err.
 * Net stack effect: consumes 1-2 args, returns 1 (userdata) or 2
 * (nil, err) results. */
int cytadel_plugin_api_open_sock_tcp(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    lua_Integer port = luaL_checkinteger(L, 1);
    lua_Integer timeout_ms = luaL_optinteger(L, 2, 5000);
    /* W1 security-audit fix: a plugin-supplied timeout_ms must never be
     * allowed to exceed (or, once a deadline is installed, to outlast the
     * remaining time of) the §4.5 run-phase budget -- see timeout_clamp.h's
     * cytadel_plugin_clamp_timeout_ms() for the full rationale. */
    timeout_ms = cytadel_plugin_clamp_timeout_ms(L, timeout_ms);

    if (port < 1 || port > 65535) {
        /* %I (lua_Integer), not libc's %lld -- lua_pushvfstring()'s
         * format-spec set is not printf's. */
        return luaL_error(L, "open_sock_tcp: port %I out of range 1-65535", port);
    }

    int fd = -1;
    char err_buf[64];
    if (cytadel_plugin_raw_tcp_connect(ctx->ip, (uint16_t)port, (int)timeout_ms, &fd, err_buf,
                                        sizeof(err_buf)) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, err_buf);
        return 2;
    }

    /* W2 security-audit fix, reordered by FIX 5 (security-review round 2,
     * "cheap robustness"): register this fd with the invocation's
     * engine-side tracker (plugin_ctx.h/fd_tracker.h) BEFORE calling
     * lua_newuserdatauv() below, not after. lua_newuserdatauv() itself can
     * raise (Lua-side OOM allocating the userdata) -- if that happened
     * while this fd was still unregistered, the fd would be orphaned:
     * never returned to Lua (so no userdata ever exists for __gc/__close
     * to fire on) AND never tracked (so invoke.c's end-of-invocation
     * force-close sweep would not know about it either), leaking it for
     * the rest of this process's lifetime. Registering first means even
     * that OOM path still leaves the fd owned by the tracker, so the
     * force-close sweep closes it once this invocation's lua_pcall()
     * unwinds from the OOM error. A tracking failure (OOM in the tracker's
     * own realloc()) is itself still best-effort only -- the socket
     * remains fully usable, just relying solely on the (now-locked, see
     * cytadel_plugin_api_socket_register_metatable()) __gc/__close
     * finalizer as its safety net in that rare case. */
    size_t track_idx = cytadel_plugin_fd_tracker_add(&ctx->open_fds, fd);

    cytadel_plugin_socket_t *sock = lua_newuserdatauv(L, sizeof(*sock), 0);
    sock->fd = fd;
    sock->track_idx = track_idx;
    luaL_setmetatable(L, CYTADEL_SOCKET_MT);
    return 1;
}

/* §2.5 send(sock, data) -> integer | nil, err. Net stack effect: consumes
 * 2 args, returns 1 or 2 results. */
int cytadel_plugin_api_send(lua_State *L) {
    cytadel_plugin_socket_t *sock = luaL_checkudata(L, 1, CYTADEL_SOCKET_MT);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 2, &len);

    if (sock->fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "closed");
        return 2;
    }

    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(sock->fd, data + sent, len - sent, 0);
        if (n > 0) {
            sent += (size_t)n;
            continue;
        }
        if (n == 0) {
            lua_pushnil(L);
            lua_pushstring(L, "closed");
            return 2;
        }
        if (errno == EPIPE || errno == ECONNRESET) {
            lua_pushnil(L);
            lua_pushstring(L, "reset");
            return 2;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            lua_pushnil(L);
            lua_pushstring(L, "timeout");
            return 2;
        }
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        lua_pushnil(L);
        lua_pushstring(L, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return 2;
    }

    lua_pushinteger(L, (lua_Integer)sent);
    return 1;
}

/* Hard cap purely to prevent a pathological max_len from driving an
 * unbounded single allocation -- not part of the contract's documented
 * behavior (§2.6 does not specify a cap), but a realistic detection
 * plugin's reads are always far smaller than this, and clamping only
 * changes behavior for an unrealistic max_len a legitimate plugin would
 * never pass. */
#define CYTADEL_PLUGIN_RECV_MAX_LEN (16 * 1024 * 1024)

/* §2.6 recv(sock, max_len [, timeout_ms]) -> string | nil, err. Net stack
 * effect: consumes 2-3 args, returns 1 or 2 results. */
int cytadel_plugin_api_recv(lua_State *L) {
    cytadel_plugin_socket_t *sock = luaL_checkudata(L, 1, CYTADEL_SOCKET_MT);
    lua_Integer max_len = luaL_checkinteger(L, 2);
    lua_Integer timeout_ms = luaL_optinteger(L, 3, 5000);

    if (max_len <= 0) {
        /* %I (lua_Integer), not libc's %lld. */
        return luaL_error(L, "recv: max_len must be positive (got %I)", max_len);
    }
    if (max_len > CYTADEL_PLUGIN_RECV_MAX_LEN) {
        max_len = CYTADEL_PLUGIN_RECV_MAX_LEN;
    }
    /* W1 security-audit fix, floor single-sourced by FIX 2 (security-review
     * round 2) -- see timeout_clamp.h's cytadel_plugin_clamp_timeout_ms()
     * for the full rationale. This used to be preceded by its own local
     * `if (timeout_ms < 0) timeout_ms = 0;` pre-clamp; that is now
     * redundant (and was itself insufficient -- it never floored an
     * explicit 0) since cytadel_plugin_clamp_timeout_ms() floors to 1 up
     * front unconditionally. */
    timeout_ms = cytadel_plugin_clamp_timeout_ms(L, timeout_ms);

    if (sock->fd < 0) {
        lua_pushnil(L);
        lua_pushstring(L, "closed");
        return 2;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char *buf = malloc((size_t)max_len);
    if (buf == NULL) {
        return luaL_error(L, "recv: out of memory allocating a %I-byte buffer", max_len);
    }

    ssize_t n = recv(sock->fd, buf, (size_t)max_len, 0);
    if (n > 0) {
        /* §2.6: "1 or more bytes" -- lua_pushlstring copies buf into a
         * fresh Lua string; safe to free() our own copy right after. */
        lua_pushlstring(L, buf, (size_t)n);
        free(buf);
        return 1;
    }
    free(buf);

    if (n == 0) {
        lua_pushnil(L);
        lua_pushstring(L, "closed"); /* §2.6: "no 'returns empty string' case" */
        return 2;
    }
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        lua_pushnil(L);
        lua_pushstring(L, "timeout");
        return 2;
    }
    char errbuf[CYTADEL_STRERROR_BUF_LEN];
    lua_pushnil(L);
    lua_pushstring(L, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
    return 2;
}

/* §2.7 close_sock(sock) -> (nothing). Net stack effect: consumes 1 arg,
 * returns 0 results. */
int cytadel_plugin_api_close_sock(lua_State *L) {
    cytadel_plugin_socket_t *sock = luaL_checkudata(L, 1, CYTADEL_SOCKET_MT);
    cytadel_plugin_socket_close(L, sock);
    return 0;
}

/* __gc / __close (§2.4, §4.4): both simply force-close the fd if still
 * open. Lua 5.4's __close receives (obj, err_or_nil) -- the second
 * argument is ignored here (this scanner has nothing meaningful to do
 * with "which error triggered this close," only that cleanup must
 * happen). */
static int cytadel_plugin_api_socket_gc(lua_State *L) {
    cytadel_plugin_socket_t *sock = luaL_checkudata(L, 1, CYTADEL_SOCKET_MT);
    cytadel_plugin_socket_close(L, sock);
    return 0;
}

void cytadel_plugin_api_socket_register_metatable(lua_State *L) {
    /* luaL_newmetatable() is idempotent per-state (it only creates+
     * registers if not already present in this L's registry, otherwise
     * just pushes the existing one) -- safe even though this is called
     * once per fresh lua_State (never actually hits the "already exists"
     * branch in this engine's usage, but this makes the function correct
     * regardless). Net stack effect: 0 (the metatable itself is popped at
     * the end). */
    if (luaL_newmetatable(L, CYTADEL_SOCKET_MT)) {
        lua_pushcfunction(L, cytadel_plugin_api_socket_gc);
        lua_setfield(L, -2, "__gc");
        lua_pushcfunction(L, cytadel_plugin_api_socket_gc);
        lua_setfield(L, -2, "__close");
        lua_pushstring(L, CYTADEL_SOCKET_MT);
        lua_setfield(L, -2, "__name");
        /* W2 security-audit fix: lock the metatable. Both getmetatable()
         * and rawset() are reachable from the run-phase sandbox's base
         * library (plugin-api.md §5.1), so without this a plugin could do
         * `getmetatable(sock).__gc = nil` (an ordinary table field write --
         * rawset() is not even required) to strip the finalizer and defeat
         * §4.4's force-close guarantee entirely at the Lua level. Setting
         * __metatable to a non-nil value makes Lua's getmetatable() return
         * THIS value instead of the real metatable table (lbaselib.c's
         * luaB_getmetatable() checks for __metatable itself), so the
         * plugin never gets a handle on the real table to mutate; the same
         * field also makes setmetatable(sock, ...) raise "cannot change a
         * protected metatable" (lauxlib/lvm's luaL_setmetatable /
         * lua_setmetatable path). This is Lua-level defense in depth --
         * the actual, unconditional guarantee against a leaked fd is
         * invoke.c's engine-side fd tracker (fd_tracker.h), which does not
         * depend on this lock or on __gc/__close ever running at all. */
        lua_pushstring(L, CYTADEL_SOCKET_MT);
        lua_setfield(L, -2, "__metatable");
    }
    lua_pop(L, 1);
}
