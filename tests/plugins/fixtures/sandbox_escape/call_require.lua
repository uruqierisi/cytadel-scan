register{
    script_id      = 950004,
    script_name    = "Fixture Call require",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Proves require is unreachable (calling it raises, caught as FAILED).",
    solution       = "N/A -- test fixture.",
}

function run()
    require("os")
end
