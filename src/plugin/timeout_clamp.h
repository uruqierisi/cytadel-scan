#ifndef CYTADEL_PLUGIN_TIMEOUT_CLAMP_H
#define CYTADEL_PLUGIN_TIMEOUT_CLAMP_H

#include <lua.h>

/* Milestone 5 security-audit finding W1 (as hardened by round-2 FIX 2):
 * clamps a plugin-supplied timeout_ms to at least 1 ms and at most
 * CYTADEL_PLUGIN_MAX_RUNTIME_MS (plugin_limits.h -- the fixed §4.5
 * run-phase wall-clock budget), and -- since every real caller of this
 * helper (api_socket.c's open_sock_tcp()/recv(), api_http.c's http_get())
 * only ever runs from inside run(), i.e. after invoke.c has already
 * installed the §4.5 runtime-limit deadline into this lua_State's extra
 * space -- further clamps it to the time actually remaining before that
 * deadline. This matters because a blocking C call (connect()/recv()/
 * SSL_read()) executes no Lua VM instructions while blocked, so the §4.5
 * instruction-count debug hook cannot fire during it; without the
 * remaining-budget clamp, a single `timeout_ms = 15000` blocking call
 * issued right before the deadline could still run for another full 15s
 * past it.
 *
 * The lower-bound floor of 1 ms (never 0) applies both to the caller's raw
 * timeout_ms up front AND to a remaining budget of zero or less -- some of
 * this engine's timeout plumbing (SO_RCVTIMEO/SO_SNDTIMEO) treats an
 * all-zero {0,0} timeval as "no timeout" (block forever) on Linux, the
 * opposite of the intended "expire immediately," so 1 ms is the smallest
 * value that reliably still means "time out almost immediately" everywhere
 * it is used. Flooring the caller's raw timeout_ms (not just the remaining
 * budget) is FIX 2's fix: a plugin-supplied timeout_ms of 0 previously
 * sailed straight through whenever it was already <= the remaining budget,
 * producing exactly that block-forever {0,0} timeval and wedging a worker
 * thread permanently. If no deadline has been installed yet (defensive
 * only -- should not happen for any real caller), only the fixed-cap/
 * fixed-floor clamps apply.
 *
 * A real function (not `static inline` in a shared header) so its
 * clock_gettime()/CLOCK_MONOTONIC use can be isolated behind this
 * translation unit's own `_POSIX_C_SOURCE 200809L` feature-test macro
 * (timeout_clamp.c) without forcing every other translation unit that
 * merely includes plugin_ctx.h to also define that macro before its own
 * first system header include. */
lua_Integer cytadel_plugin_clamp_timeout_ms(lua_State *L, lua_Integer timeout_ms);

#endif /* CYTADEL_PLUGIN_TIMEOUT_CLAMP_H */
