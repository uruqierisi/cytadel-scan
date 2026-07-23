#include "sandbox.h"

#include <stddef.h>

#include <lauxlib.h>
#include <lualib.h>

#include "api_functions.h"
#include "register.h"

int cytadel_plugin_msgh(lua_State *L) {
    /* luaL_tolstring() never itself raises for a non-string error value --
     * plugin-api.md §4.3: "the engine converts whatever is on the stack
     * ... with luaL_tolstring before logging -- never assumes the error
     * value is a string" (error({...}) and similar are handled). */
    const char *msg = luaL_tolstring(L, 1, NULL);
    luaL_traceback(L, L, msg, 1);
    lua_remove(L, -2); /* drop the luaL_tolstring() copy, keep only the traceback */
    return 1;
}

void cytadel_plugin_push_base_sandbox(lua_State *L) {
    /* Standard Lua sandboxing technique: luaopen_*() functions always
     * install themselves onto lua_pushglobaltable(L) (Lua 5.4's base/
     * string/table/math library C implementations have no "install into
     * an arbitrary table" mode) -- there is no way to make luaL_openlibs()
     * populate a table of our choosing directly. Instead, load the full
     * stdlib into this (fresh, per-invocation) state's REAL global table
     * as usual, then copy just the vetted subset (plugin-api.md §5.1) by
     * reference into a brand-new sandbox table. The real global table
     * still holding the full stdlib is harmless: it is never reachable
     * from the loaded chunk once cytadel_plugin_rebind_env() rebinds
     * _ENV away from it (§5.2) -- this function must therefore run before
     * any plugin chunk is loaded on this lua_State, and at most once per
     * lua_State (calling luaL_openlibs() twice on the same state is not
     * needed and not done anywhere in this module). */
    luaL_openlibs(L);

    lua_newtable(L);
    int env_idx = lua_gettop(L);

    static const char *const base_fns[] = {
        "assert",   "error",         "ipairs",  "pairs",         "next",
        "pcall",    "xpcall",        "select",  "tostring",      "tonumber",
        "type",     "rawequal",      "rawget",  "rawset",        "rawlen",
        "setmetatable", "getmetatable",
    };
    for (size_t i = 0; i < sizeof(base_fns) / sizeof(base_fns[0]); i++) {
        lua_getglobal(L, base_fns[i]);
        lua_setfield(L, env_idx, base_fns[i]);
    }

    /* string/table/math are copied as whole table references (not
     * deep-copied) -- the standard, accepted sandboxing shortcut: none of
     * these three stock libraries expose filesystem/process/network
     * primitives, so sharing the same table object across every plugin
     * invocation carries no sandbox-escape risk, only saves a pointless
     * deep copy on every one of the many short-lived lua_States this
     * engine creates (plugin-api.md §4.1 step 1 / §4.2 step 2: fresh state
     * per registration attempt and per (plugin, target) invocation). */
    static const char *const lib_tables[] = {"string", "table", "math"};
    for (size_t i = 0; i < sizeof(lib_tables) / sizeof(lib_tables[0]); i++) {
        lua_getglobal(L, lib_tables[i]);
        lua_setfield(L, env_idx, lib_tables[i]);
    }

    /* Security-review round-3 finding C-1 (CRITICAL, defense in depth):
     * lock this table's own metatable slot so a plugin can never do
     * `setmetatable(_ENV, {__index = function() error(...) end}})`.
     * setmetatable()/getmetatable() are both in the base-library allowlist
     * above (plugin-api.md §5.1 lists them for BOTH the metadata and
     * run-phase sandboxes) -- without this, a plugin could install a
     * metamethod on its own _ENV that intercepts every subsequent read of
     * it, including the engine's OWN lua_getfield(L, env_idx, "run")-style
     * lookups (loader.c §4.1 step 5, invoke.c §4.2 step 4b), several of
     * which run OUTSIDE any lua_pcall on this lua_State -- an uncaught
     * error there falls through to Lua's default panic handler and
     * abort()s the whole scanner process over one plugin file.
     *
     * This does NOT restrict what a plugin can do with setmetatable() on
     * ITS OWN tables (an ordinary, common Lua pattern for class-style OOP,
     * etc.) -- setting __metatable via lua_setmetatable() here protects
     * ONLY this one table object (env_idx itself), the same well-known
     * Lua sandboxing idiom api_socket.c's cytadel_socket metatable already
     * uses to protect ITS table (see
     * cytadel_plugin_api_socket_register_metatable()'s own comment for the
     * mechanism: Lua's getmetatable() library function returns this
     * placeholder instead of the real metatable, and setmetatable() on a
     * table with __metatable set always raises "cannot change a protected
     * metatable" -- lbaselib.c). Checked against plugin-api.md §5.1's
     * table: nothing there documents _ENV's own metatable as a surface a
     * plugin is entitled to manipulate (§5.2 describes _ENV purely as the
     * mechanism the ENGINE uses to scope globals, never as something a
     * plugin author is expected to reach into), so this closes an
     * unintended/undocumented capability rather than removing a documented
     * one -- no legitimate plugin-api.md-conformant plugin pattern is
     * affected.
     *
     * The engine's own C code above (lua_getglobal()/lua_setfield() while
     * building this table) already ran before this metatable is attached,
     * so none of that construction is affected either. Also applied to
     * the metadata-phase sandbox (cytadel_plugin_push_metadata_sandbox()
     * calls this same function), closing the identical attack against
     * loader.c's own §4.1 step 5 check.
     *
     * Security-review round-4 suggestion 4: this metatable is attached HERE,
     * at the END of this function, but cytadel_plugin_push_metadata_sandbox()
     * and cytadel_plugin_push_run_sandbox() below both call this function
     * FIRST and then continue calling lua_setfield(L, env_idx, ...) on this
     * SAME table afterward (adding `register`, and -- in the run-phase
     * sandbox -- every §2 API function). That ordering is correct ONLY
     * because this metatable sets nothing but __metatable: lua_setfield()
     * is equivalent to a plain t[k]=v assignment, which only consults a
     * table's __newindex metamethod when the key is ABSENT from the table
     * itself -- and this metatable has no __newindex, so every one of those
     * later lua_setfield() calls behaves as an ordinary raw table write
     * regardless of when (before or after) this metatable was attached. If
     * this metatable ever gains a __newindex entry in the future, that
     * invariant breaks silently for both derived sandboxes: `register` and
     * every §2 API function are ABSENT from env_idx at the point this
     * metatable is attached (they are added afterward, by
     * cytadel_plugin_push_metadata_sandbox() / cytadel_plugin_push_run_sandbox()
     * below) -- so a future __newindex would fire for exactly those writes,
     * not skip them. The only valid remediation is to move the
     * lua_setmetatable() call HERE (this function, cytadel_plugin_push_base_sandbox()
     * -- the metatable is attached only here; cytadel_plugin_push_metadata_sandbox()
     * and cytadel_plugin_push_run_sandbox() below merely call this function
     * first and then keep writing to the same table) to AFTER this
     * function's own setfield loops above, so every key this module ever
     * writes onto env_idx is already present before the metatable (and any
     * future __newindex) is attached (security-review round-5 suggestion
     * S-3: the previously written second remediation option here --
     * "re-verify that __newindex still cannot fire for a key already known
     * to be present at attach time" -- does not describe this code and has
     * been removed; at attach time those keys are not yet present, so there
     * is nothing to re-verify). */
    lua_newtable(L);
    lua_pushliteral(L, "cytadel: _ENV's metatable is protected");
    lua_setfield(L, -2, "__metatable");
    lua_setmetatable(L, env_idx);
}

void cytadel_plugin_push_metadata_sandbox(lua_State *L, cytadel_plugin_header_t *capture_dest) {
    cytadel_plugin_push_base_sandbox(L); /* attaches the __metatable lock -- see that
                                           * function's own comment (round-4 suggestion 4)
                                           * for why setfield-after-attach below is safe */
    int env_idx = lua_gettop(L);

    lua_pushlightuserdata(L, capture_dest);
    lua_pushcclosure(L, cytadel_plugin_register_capture, 1);
    lua_setfield(L, env_idx, "register");
}

void cytadel_plugin_push_run_sandbox(lua_State *L) {
    cytadel_plugin_api_socket_register_metatable(L);

    cytadel_plugin_push_base_sandbox(L); /* attaches the __metatable lock -- see that
                                           * function's own comment (round-4 suggestion 4)
                                           * for why setfield-after-attach below is safe */
    int env_idx = lua_gettop(L);

    lua_pushcfunction(L, cytadel_plugin_register_noop);
    lua_setfield(L, env_idx, "register");

    static const struct {
        const char *name;
        lua_CFunction fn;
    } api_fns[] = {
        {"get_kb_item", cytadel_plugin_api_get_kb_item},
        {"set_kb_item", cytadel_plugin_api_set_kb_item},
        {"get_port_state", cytadel_plugin_api_get_port_state},
        {"get_scan_port", cytadel_plugin_api_get_scan_port},
        {"open_sock_tcp", cytadel_plugin_api_open_sock_tcp},
        {"send", cytadel_plugin_api_send},
        {"recv", cytadel_plugin_api_recv},
        {"close_sock", cytadel_plugin_api_close_sock},
        {"http_get", cytadel_plugin_api_http_get},
        /* report_vuln / security_report: exact aliases -- same C function
         * registered under both names (plugin-api.md §2.9). */
        {"report_vuln", cytadel_plugin_api_report_vuln},
        {"security_report", cytadel_plugin_api_report_vuln},
        {"log", cytadel_plugin_api_log},
    };
    for (size_t i = 0; i < sizeof(api_fns) / sizeof(api_fns[0]); i++) {
        lua_pushcfunction(L, api_fns[i].fn);
        lua_setfield(L, env_idx, api_fns[i].name);
    }
}

void cytadel_plugin_rebind_env(lua_State *L, int chunk_idx, int env_idx) {
    lua_pushvalue(L, env_idx);
    lua_setupvalue(L, chunk_idx, 1); /* upvalue 1 of a top-level chunk is always _ENV (§5.2) */
}
