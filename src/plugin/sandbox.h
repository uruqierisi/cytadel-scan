#ifndef CYTADEL_PLUGIN_SANDBOX_H
#define CYTADEL_PLUGIN_SANDBOX_H

#include <lua.h>

#include "plugin_header.h"

/* Sandbox construction (docs/contracts/plugin-api.md §4.1/§4.2/§5 --
 * FROZEN CONTRACT). Private to src/plugin. Every function below documents
 * its net Lua stack effect explicitly, per this project's standing rule
 * ("track the Lua stack precisely"). */

#ifdef __cplusplus
extern "C" {
#endif

/* Message handler for lua_pcall's `msgh` argument (plugin-api.md §4.3):
 * stringifies whatever error value is on the stack (via luaL_tolstring,
 * so a non-string error object -- e.g. error({...}) -- never crashes the
 * handler itself) and replaces it with a full traceback
 * (luaL_traceback(L, L, msg, 1)) for logging. Net stack effect: the single
 * argument (the raw error value) is replaced by a single string result
 * (the traceback) -- i.e. 1 argument in, 1 result out, matching what
 * lua_pcall expects from a message handler. */
int cytadel_plugin_msgh(lua_State *L);

/* Pushes a fresh table containing the vetted base/string/table/math subset
 * (plugin-api.md §5.1's shared row, identical in both sandbox phases) --
 * does NOT add `register` or any §2 API function; callers add those
 * themselves. Net stack effect: +1 (the new table is left on top). */
void cytadel_plugin_push_base_sandbox(lua_State *L);

/* Builds the METADATA-phase sandbox (§4.1 step 2 / §5.1's "yes" column):
 * cytadel_plugin_push_base_sandbox() plus the single engine function
 * `register`, bound with one upvalue -- a light userdata pointing at
 * `capture_dest`, which cytadel_plugin_register_capture() (register.c)
 * fills in as the chunk's top-level register{...} call executes.
 * `capture_dest` must remain valid (i.e. stay alive on the caller's C
 * stack) for as long as this env table might still be used, i.e. through
 * the caller's lua_pcall() of the loaded chunk. Net stack effect: +1 (the
 * new table is left on top). */
void cytadel_plugin_push_metadata_sandbox(lua_State *L, cytadel_plugin_header_t *capture_dest);

/* Builds the RUN-phase sandbox (§4.2 step 3 / §5.1's "yes" column):
 * cytadel_plugin_push_base_sandbox() plus a harmless no-op `register`
 * (register.c's cytadel_plugin_register_noop -- "so the chunk's top-level
 * register{...} call doesn't error out the second time it's executed")
 * plus every C-backed API function from §2 (api_kb.c/api_socket.c/
 * api_http.c/api_report.c/api_log.c), plus the "cytadel.socket" metatable
 * registration (§2.4/§4.4). This lua_State's registry must already have
 * an invocation context installed (plugin_ctx.h's
 * cytadel_plugin_ctx_set()) before this is called, and definitely before
 * the loaded chunk ever runs -- every §2 function fetches that context on
 * every call. Net stack effect: +1 (the new table is left on top). */
void cytadel_plugin_push_run_sandbox(lua_State *L);

/* Rebinds the loaded chunk's _ENV upvalue (docs/contracts/plugin-api.md
 * §5.2 -- "the sole sandboxing mechanism"; MANDATORY, skipping this
 * silently defeats every restriction above). `chunk_idx` is the stack
 * index of the value luaL_loadfile() pushed (a Lua function); `env_idx` is
 * the stack index of a sandbox table built by one of the push_*_sandbox()
 * functions above. Net stack effect: 0 (this only mutates the chunk's
 * upvalue slot; the "lua_pushvalue" it performs internally is balanced by
 * the "lua_setupvalue" pop of that same pushed copy). */
void cytadel_plugin_rebind_env(lua_State *L, int chunk_idx, int env_idx);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_SANDBOX_H */
