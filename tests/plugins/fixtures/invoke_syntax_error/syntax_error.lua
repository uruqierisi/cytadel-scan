-- Security-review round-5 suggestion S-2: deliberately invalid Lua syntax
-- (an unclosed `function` block) so luaL_loadfile() itself fails with
-- LUA_OK != load_rc -- this fixture exists purely to exercise
-- invoke.c's cytadel_plugin_invoke_one() load-failure path (the first of
-- its four lua_close(L)/cleanup call sites) directly, via
-- tests/unit/test_plugin_r4w2_order_invariant.c's
-- cytadel_plugin_invoke_one() call (bypassing loader.c's own registration
-- gate, which would otherwise also reject this file for the same reason,
-- never reaching invoke.c at all in a normal register-then-invoke flow).
-- Never meant to be loaded by loader.c in production.
function run(
    print("this file must never parse successfully")
