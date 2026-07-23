#include "cytadel/plugin/plugin.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

int cytadel_plugin_lua_smoke_test(void) {
    lua_State *L = luaL_newstate();
    if (L == NULL) {
        return -1;
    }

    /* luaL_dostring == luaL_loadstring + lua_pcall(0, LUA_MULTRET, 0): a
     * bare embedding smoke check, deliberately NOT going through this
     * module's sandbox (sandbox.c, added in a later part) -- this only
     * proves the link/toolchain works, before any _ENV-rebinding or
     * library-exposure policy exists to test. */
    int rc = luaL_dostring(L, "return 1+1");
    int ok = 0;
    if (rc == LUA_OK && lua_isinteger(L, -1) && lua_tointeger(L, -1) == 2) {
        ok = 1;
    }

    /* Unconditional teardown on every path, per this milestone's standing
     * rule (plugin-api.md §4.3: "lua_State creation/close is unconditional
     * on every path"). */
    lua_close(L);

    return ok ? 0 : -1;
}
