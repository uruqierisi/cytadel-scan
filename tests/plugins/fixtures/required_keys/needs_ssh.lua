-- Exact-key required_keys gating fixture: must run only when
-- "Services/ssh/22" is present in the target KB (plugin-api.md §4.6).
register{
    script_id      = 960001,
    script_name    = "Fixture Needs SSH",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ssh/22" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Runs only when Services/ssh/22 is present in the KB.",
    solution       = "N/A -- test fixture.",
}

function run()
    set_kb_item("Test/required_keys/ran", true)
end
