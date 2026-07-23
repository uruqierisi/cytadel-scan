-- Security-review round-6 item 2 (S-2 path-drift hazard fix, residual #7):
-- syntactically valid Lua whose definer-chunk succeeds (call_rc == LUA_OK)
-- and DOES define a global run() function -- so invoke.c's
-- cytadel_plugin_invoke_one() reaches its FINAL lua_close(L)/cleanup call
-- site (site_id "final") -- but that run() unconditionally raises as soon
-- as it executes, so run_rc != LUA_OK there.
--
-- Before this fixture, the "final" call site was only ever exercised via a
-- SUCCESSFUL run() (test_plugin_r4w2_order_invariant.c's
-- socket_fd_leak_loop fixture, driven through
-- cytadel_plugin_run_all_for_host()) -- round-6's own review noted that a
-- future accidental reversal of the close_state()/cleanup() call pair on
-- that final path, reached only via a run() FAILURE, could go completely
-- unnoticed: nothing drove that specific control-flow edge. This fixture
-- closes that gap via
-- tests/unit/test_plugin_r4w2_order_invariant.c's
-- cytadel_check_direct_invoke_order() (bypassing loader.c's own
-- registration gate, which never runs run() at all -- so the run()-failure
-- path can only be reached here, through a direct
-- cytadel_plugin_invoke_one() call). Never meant to be loaded by loader.c
-- in production.
function run()
    error("intentional run() failure -- round-6 item 2 path-id coverage fixture")
end
