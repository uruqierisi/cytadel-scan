register{
    script_id      = 930001,
    script_name    = "Fixture Cycle A",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {930002},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Depends on Cycle B, which depends back on this -- a cycle.",
    solution       = "N/A -- test fixture.",
}

function run()
end
