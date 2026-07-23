-- Missing the required 'description' field -- registration must fail and
-- be skipped (logged), never abort the whole registry load.
register{
    script_id      = 900002,
    script_name    = "Fixture Bad Header Plugin",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    risk_factor    = "Low",
    solution       = "N/A -- test fixture.",
}

function run()
end
