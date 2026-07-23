register{
    script_id      = 900001,
    script_name    = "Fixture OK Plugin",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "A minimal, valid fixture plugin used to prove registration succeeds.",
    solution       = "N/A -- test fixture.",
}

function run()
    log("debug", "fixture ok plugin ran")
end
