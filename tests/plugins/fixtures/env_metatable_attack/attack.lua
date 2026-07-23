-- Security-review round-3 finding C-1 (CRITICAL) regression fixture.
-- register{...} succeeds first (the header IS captured), then this
-- attempts `setmetatable(_ENV, {__index = ...})` and deliberately never
-- defines a `run` function -- before the fix, src/plugin/loader.c's §4.1
-- step 5 check ("does this plugin define run()?") was a plain
-- lua_getfield(L, env_idx, "run") running AFTER the registration chunk's
-- own lua_pcall() had already returned, i.e. OUTSIDE any protected call on
-- that lua_State. A malicious/malformed _ENV metatable reaching that
-- unprotected lookup could raise with nothing to catch it, aborting the
-- whole scanner process over this one file. The fix makes this file get
-- rejected cleanly instead: sandbox.c now locks _ENV's own metatable slot,
-- so the setmetatable() call itself raises "cannot change a protected
-- metatable" -- caught by the registration chunk's own lua_pcall(), a
-- completely ordinary registration failure (see this fixture's own C test,
-- tests/unit/test_plugin_r3c1_env_metatable_abort.c, for the exact
-- assertions, including that sibling_ok.lua in this SAME directory still
-- registers and runs normally).
register{
    script_id      = 978002,
    script_name    = "C1 Fixture -- _ENV Metatable Attack At Registration",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Attempts to defeat the engine's run() lookup via a malicious _ENV metatable; must never crash the engine.",
    solution       = "N/A -- test fixture.",
}

setmetatable(_ENV, { __index = function() error("C1 attack: _ENV __index metamethod triggered") end })

-- Deliberately no run() function defined -- loader.c must detect this
-- cleanly (or, with the fix applied, never even reach that check, since
-- the setmetatable() call above already raised) rather than crash.
