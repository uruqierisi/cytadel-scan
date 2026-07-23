#ifndef CYTADEL_PLUGIN_LIMITS_H
#define CYTADEL_PLUGIN_LIMITS_H

/* §4.5: "If run() exceeds 15000 ms (default; may become configurable
 * later ...)." This single constant is shared by invoke.c (the
 * instruction-count runtime-limit debug hook that enforces the deadline)
 * and every blocking network primitive exposed to plugins
 * (api_socket.c's open_sock_tcp()/recv(), api_http.c's http_get()) --
 * Milestone 5 security-audit finding W1: a plugin-supplied timeout_ms must
 * never itself be allowed to exceed this budget, or a single blocking C
 * call could run past the wall-clock deadline the §4.5 hook is watching
 * for (a blocking syscall executes no Lua VM instructions while blocked,
 * so the instruction-count hook cannot fire during it). See
 * timeout_clamp.h's cytadel_plugin_clamp_timeout_ms() for where this is
 * applied. */
#define CYTADEL_PLUGIN_MAX_RUNTIME_MS 15000

#endif /* CYTADEL_PLUGIN_LIMITS_H */
