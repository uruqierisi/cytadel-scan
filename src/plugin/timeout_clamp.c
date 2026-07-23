#define _POSIX_C_SOURCE 200809L

#include "timeout_clamp.h"

#include <time.h>

#include "plugin_limits.h"

lua_Integer cytadel_plugin_clamp_timeout_ms(lua_State *L, lua_Integer timeout_ms) {
    /* FIX 2 (CRITICAL, security-review round 2): floor the CALLER's
     * timeout_ms itself, not just `remaining_ms` below. Before this, a
     * plugin-supplied timeout_ms of 0 (or negative) sailed straight
     * through this function unchanged whenever it was already <=
     * remaining_ms (the `if (timeout_ms > remaining_ms)` branch below only
     * ever clamps DOWNWARD) -- e.g. recv(sock, 512, 0), http_get{timeout_ms
     * = 0}, or open_sock_tcp(port, -1). Every real caller (api_socket.c's
     * open_sock_tcp()/recv(), api_http.c's http_get()) turns the returned
     * value into a struct timeval's tv_sec/tv_usec for SO_RCVTIMEO/
     * SO_SNDTIMEO -- and on Linux an all-zero {0,0} timeval means "no
     * timeout" (block forever), the exact opposite of what a timeout_ms of
     * 0 should mean. That let a plugin wedge a worker thread forever,
     * defeating the §4.5 runtime-limit hook (which cannot fire while the
     * thread is blocked in a syscall executing no Lua VM instructions).
     * Flooring to 1 ms here, unconditionally, up front, is the single
     * source of truth for "never produce an all-zero timeval" -- every
     * caller-local `if (timeout_ms < 0) timeout_ms = 0;` pre-clamp is now
     * redundant and has been removed in favor of this one. */
    if (timeout_ms < 1) {
        timeout_ms = 1;
    }
    if (timeout_ms > CYTADEL_PLUGIN_MAX_RUNTIME_MS) {
        timeout_ms = CYTADEL_PLUGIN_MAX_RUNTIME_MS;
    }

    struct timespec *deadline = *(struct timespec **)lua_getextraspace(L);
    if (deadline != NULL) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long long remaining_ms = ((long long)deadline->tv_sec - (long long)now.tv_sec) * 1000 +
                                  ((long long)deadline->tv_nsec - (long long)now.tv_nsec) / 1000000;
        if (remaining_ms < 1) {
            remaining_ms = 1;
        }
        if (timeout_ms > remaining_ms) {
            timeout_ms = (lua_Integer)remaining_ms;
        }
    }

    return timeout_ms;
}
