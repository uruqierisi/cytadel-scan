#ifndef CYTADEL_PLUGIN_CTX_H
#define CYTADEL_PLUGIN_CTX_H

#include <lua.h>

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"
#include "fd_tracker.h"
#include "plugin_header.h"

/* Per-invocation context (docs/contracts/plugin-api.md §2/§4.2) every
 * run-phase C-backed API function (api_*.c) needs: the target's KB, the
 * target's IP (for open_sock_tcp/http_get), the service-wildcard-dispatch
 * bound port (§2.2a, -1 if this is an ordinary exact-key invocation), the
 * current plugin's header (report_vuln's solution/cvss_vector fallback,
 * log() attribution), the findings sink report_vuln{}/security_report{}
 * append to, and (Milestone 5 security-audit finding W2) the engine-side
 * fd tracker every open_sock_tcp() call registers into so invoke.c can
 * force-close any still-open sockets after run() returns, independent of
 * Lua-level __gc/__close.
 *
 * Lifetime: one cytadel_plugin_ctx_t is stack-allocated by invoke.c for the
 * duration of exactly one (plugin, target[, port]) invocation and stashed
 * into that invocation's lua_State via the registry (CYTADEL_PLUGIN_CTX_KEY
 * below) -- never shared across lua_States, never outlives the invocation
 * that created it. Each of this engine's many short-lived lua_States gets
 * its own ctx, matching plugin-api.md §4.2 step 2's "fresh lua_State ...
 * not reused/pooled" isolation guarantee. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    cytadel_kb_t *kb;
    const char *ip;
    int bound_port; /* -1 if not a service-wildcard dispatch (§2.2a) */
    const cytadel_plugin_header_t *header;
    cytadel_finding_list_t *findings;
    cytadel_plugin_fd_tracker_t open_fds; /* W2: engine-side force-close tracking */
} cytadel_plugin_ctx_t;

/* Registry key cytadel_plugin_ctx_get()/cytadel_plugin_ctx_set() use to
 * stash/retrieve the light userdata pointer to a cytadel_plugin_ctx_t.
 * Any unique, stable C string works as a registry key (Lua's registry is
 * keyed by arbitrary Lua value; using a C string literal's address would
 * be fragile across translation units, so this uses the *contents* of a
 * distinctive string instead, exactly like Lua's own convention for
 * registry keys, e.g. LUA_LOADED_TABLE). */
#define CYTADEL_PLUGIN_CTX_KEY "cytadel.plugin.ctx"

/* Stashes `ctx` (a light userdata pointer) into L's registry. Net stack
 * effect: 0. Must be called before any API function below might be
 * invoked (i.e. before the run-phase chunk executes). */
static inline void cytadel_plugin_ctx_set(lua_State *L, cytadel_plugin_ctx_t *ctx) {
    lua_pushlightuserdata(L, ctx);
    lua_setfield(L, LUA_REGISTRYINDEX, CYTADEL_PLUGIN_CTX_KEY);
}

/* Retrieves the pointer stashed by cytadel_plugin_ctx_set(), or NULL if
 * none was ever set on this lua_State. Net stack effect: 0. Every api_*.c
 * function calls this first to reach the KB/findings/ip/bound_port it
 * needs. */
static inline cytadel_plugin_ctx_t *cytadel_plugin_ctx_get(lua_State *L) {
    lua_getfield(L, LUA_REGISTRYINDEX, CYTADEL_PLUGIN_CTX_KEY);
    cytadel_plugin_ctx_t *ctx = (cytadel_plugin_ctx_t *)lua_touserdata(L, -1);
    lua_pop(L, 1);
    return ctx;
}

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_CTX_H */
