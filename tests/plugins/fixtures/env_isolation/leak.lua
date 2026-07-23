-- A bare top-level global assignment. Under a correctly rebound _ENV
-- (plugin-api.md §5.2) this sets sandbox_table.cytadel_test_leaked_global,
-- NOT the lua_State's real global table -- cytadel_plugin_debug_check_env_
-- isolated() (plugin.h, test-support only) checks the REAL global table
-- directly via lua_getglobal(), independent of _ENV, and must find this
-- absent.
cytadel_test_leaked_global = "should never escape the sandbox"

register{
    script_id      = 980001,
    script_name    = "Fixture Env Leak",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Sets a bare global at file scope to test _ENV isolation.",
    solution       = "N/A -- test fixture.",
}

function run()
end
