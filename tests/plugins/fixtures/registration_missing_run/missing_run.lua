-- Valid header, but never defines a global run() function -- registration
-- must fail (§4.1 step 5) and be skipped.
register{
    script_id      = 900003,
    script_name    = "Fixture Missing Run Plugin",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Registers successfully but never defines run().",
    solution       = "N/A -- test fixture.",
}
