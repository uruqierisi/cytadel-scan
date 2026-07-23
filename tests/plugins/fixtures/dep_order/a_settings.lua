-- Depended upon by b_gather.lua -- must run/be-attempted before it.
register{
    script_id      = 920001,
    script_name    = "Fixture Dep Order Settings",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_SETTINGS",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Writes a KB fact that b_gather.lua depends on being attempted first.",
    solution       = "N/A -- test fixture.",
}

function run()
    set_kb_item("Test/dep_order/settings_ran", true)
end
