#include "loader.h"

#include <stdlib.h>
#include <string.h>

#include <lauxlib.h>

#include "field_utils.h"
#include "log.h"
#include "sandbox.h"

bool cytadel_plugin_register_one_file(const char *path, cytadel_plugin_header_t *out_hdr) {
    memset(out_hdr, 0, sizeof(*out_hdr));

    /* plugin-api.md §4.1 step 1: "fresh lua_State via luaL_newstate()." */
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        cytadel_log_error("plugin registration: out of memory creating lua_State for '%s'", path);
        return false;
    }

    /* Stack layout from here on: [1]=msgh, [2]=env (metadata sandbox),
     * then [3]=chunk once luaL_loadfile succeeds. msgh/env indices stay
     * valid (lower than anything pushed afterward) for the rest of this
     * function. */
    lua_pushcfunction(L, cytadel_plugin_msgh);
    int msgh_idx = lua_gettop(L);

    cytadel_plugin_push_metadata_sandbox(L, out_hdr); /* §4.1 step 2 */
    int env_idx = lua_gettop(L);

    int load_rc = luaL_loadfile(L, path); /* §4.1 step 3 (part 1) */
    if (load_rc != LUA_OK) {
        cytadel_log_error("plugin registration: failed to load '%s': %s", path,
                           lua_tostring(L, -1));
        cytadel_plugin_header_free(out_hdr);
        lua_close(L);
        return false;
    }
    int chunk_idx = lua_gettop(L);

    cytadel_plugin_rebind_env(L, chunk_idx, env_idx); /* §4.1 step 3 (part 2) / §5.2 */

    int call_rc = lua_pcall(L, 0, 0, msgh_idx); /* §4.1 step 4 */
    if (call_rc != LUA_OK) {
        cytadel_log_error("plugin registration: '%s' failed: %s", path, lua_tostring(L, -1));
        cytadel_plugin_header_free(out_hdr);
        lua_close(L);
        return false;
    }

    if (!out_hdr->captured) {
        cytadel_log_error(
            "plugin registration: '%s' never called register{...} at its top level", path);
        cytadel_plugin_header_free(out_hdr);
        lua_close(L);
        return false;
    }

    /* §4.1 step 5: confirm a global `run` function was defined. With
     * _ENV rebound to the sandbox table (env_idx), a top-level
     * `function run() ... end` is exactly `env_idx.run = <function>` --
     * so this checks env_idx, never the real global table.
     *
     * Security-review round-3 finding C-1 (CRITICAL): this used to be a
     * plain lua_getfield(), which honours a __index metamethod. setmetatable
     * is in the sandbox's base-library allowlist (sandbox.c) and this check
     * runs AFTER the register-phase chunk's lua_pcall() (line 43 above) has
     * already returned -- i.e. OUTSIDE any protected call on this lua_State.
     * A plugin whose top-level code did
     * `setmetatable(_ENV, {__index = function() error(...) end}})` and
     * defined no `run` could make this exact lookup raise with no enclosing
     * pcall to catch it, longjmping into Lua's default panic handler and
     * abort()ing the whole scanner process over one malicious/malformed
     * plugin file. cytadel_plugin_raw_getfield() (field_utils.h) uses
     * lua_rawget() instead, which never invokes __index, closing this
     * regardless of whether a metatable is (still) attached to env_idx --
     * sandbox.c's cytadel_plugin_push_base_sandbox() also now locks env_idx's
     * own metatable slot so a plugin cannot attach one to _ENV in the first
     * place; this raw lookup is the second, independent layer that keeps
     * this specific call site safe even if that lock were ever weakened. */
    cytadel_plugin_raw_getfield(L, env_idx, "run");
    bool has_run = lua_isfunction(L, -1);
    lua_pop(L, 1);
    if (!has_run) {
        cytadel_log_error(
            "plugin registration: '%s' (script_id %lld) does not define a global run() function",
            path, (long long)out_hdr->script_id);
        cytadel_plugin_header_free(out_hdr);
        lua_close(L);
        return false;
    }

    size_t path_len = strlen(path);
    out_hdr->source_path = malloc(path_len + 1);
    if (out_hdr->source_path == NULL) {
        cytadel_log_error("plugin registration: out of memory copying path '%s'", path);
        cytadel_plugin_header_free(out_hdr);
        lua_close(L);
        return false;
    }
    memcpy(out_hdr->source_path, path, path_len + 1);

    lua_close(L); /* §4.1 step 6: unconditional, success path */
    return true;
}
