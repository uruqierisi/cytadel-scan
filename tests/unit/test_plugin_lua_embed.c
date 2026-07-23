#include "cytadel_test.h"

#include <lauxlib.h>
#include <lua.h>
#include <lualib.h>

#include "cytadel/plugin/plugin.h"

/* Milestone 5 Part 1: proves the CMake/Lua::Lua toolchain link works before
 * any sandboxing/scheduler code is built on top of it (docs/build-plan.md
 * §2's Lua 5.4 wrapper, this repo's CMakeLists.txt). Two independent
 * checks: (1) the library-level smoke helper (src/plugin/lua_smoke.c),
 * and (2) the exact same embed/eval/teardown sequence written directly in
 * this test file, so a regression in either the library wrapper or the
 * raw link itself is caught. */

static void test_library_smoke_helper(void) {
    CYTADEL_ASSERT_EQ(cytadel_plugin_lua_smoke_test(), 0);
}

static void test_direct_embed_eval_teardown(void) {
    lua_State *L = luaL_newstate();
    CYTADEL_ASSERT(L != NULL);

    int rc = luaL_dostring(L, "return 1+1");
    CYTADEL_ASSERT_EQ(rc, LUA_OK);
    CYTADEL_ASSERT(lua_isinteger(L, -1));
    CYTADEL_ASSERT_EQ(lua_tointeger(L, -1), 2);
    lua_pop(L, 1);

    lua_close(L);
}

int main(void) {
    test_library_smoke_helper();
    test_direct_embed_eval_teardown();
    CYTADEL_TEST_PASS();
}
