-- Security-review round-5 suggestion S-2: syntactically valid Lua that
-- raises unconditionally as soon as its top-level chunk executes -- i.e.
-- luaL_loadfile() succeeds but the definer-chunk's lua_pcall() does not
-- (call_rc != LUA_OK). Exists purely to exercise invoke.c's
-- cytadel_plugin_invoke_one() definer-chunk-failure path (its second of
-- four lua_close(L)/cleanup call sites) directly, via
-- tests/unit/test_plugin_r4w2_order_invariant.c's cytadel_plugin_invoke_one()
-- call (bypassing loader.c's own registration gate, which would also
-- reject this file at registration time for the identical reason -- its
-- own top-level lua_pcall() fails the same way). Never meant to be loaded
-- by loader.c in production.
error("intentional top-level failure -- round-5 S-2 invoke.c coverage fixture")

function run()
end
