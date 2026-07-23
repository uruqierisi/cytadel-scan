-- report_vuln{} with severity outside 0-4 -- must luaL_error (§2.9).
register{
    script_id      = 995002,
    script_name    = "Fixture Severity Out Of Range",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls report_vuln{} with severity = 5 -- must fail loud.",
    solution       = "N/A -- test fixture.",
}

function run()
    report_vuln{
        severity = 5,
        title    = "out of range severity",
        evidence = "severity 5 is not in 0-4",
        port     = 0,
    }
end
