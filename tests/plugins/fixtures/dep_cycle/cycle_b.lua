register{
    script_id      = 930002,
    script_name    = "Fixture Cycle B",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {930001},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Depends on Cycle A, which depends back on this -- a cycle.",
    solution       = "N/A -- test fixture.",
}

function run()
end
