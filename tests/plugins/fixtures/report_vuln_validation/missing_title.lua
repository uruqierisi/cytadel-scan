-- report_vuln{} missing the required 'title' field -- must luaL_error,
-- which run() does not catch, so this invocation is marked FAILED.
register{
    script_id      = 995001,
    script_name    = "Fixture Missing Title",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls report_vuln{} without a title -- must fail loud.",
    solution       = "N/A -- test fixture.",
}

function run()
    report_vuln{
        severity = 1,
        evidence = "no title here",
        port     = 0,
    }
end
