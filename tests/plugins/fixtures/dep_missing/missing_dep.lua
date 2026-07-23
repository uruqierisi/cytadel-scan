-- Declares a dependency on a script_id no plugin in this fixture directory
-- registers -- a hard startup error (plugin-api.md §4.1).
register{
    script_id      = 940001,
    script_name    = "Fixture Missing Dependency",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {999999},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Depends on a script_id that does not exist.",
    solution       = "N/A -- test fixture.",
}

function run()
end
