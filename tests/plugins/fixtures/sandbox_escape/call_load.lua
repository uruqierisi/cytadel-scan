register{
    script_id      = 950005,
    script_name    = "Fixture Call load",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Proves load is unreachable (calling it raises, caught as FAILED).",
    solution       = "N/A -- test fixture.",
}

function run()
    load("return 1")()
end
