-- Depends on a_settings.lua (script_id 920001) -- the scheduler must have
-- already attempted that plugin before this one runs for the same target.
register{
    script_id      = 920002,
    script_name    = "Fixture Dep Order Gather",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {920001},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Reads the KB fact a_settings.lua writes, to prove ordering.",
    solution       = "N/A -- test fixture.",
}

function run()
    local ran_first = get_kb_item("Test/dep_order/settings_ran")
    set_kb_item("Test/dep_order/gather_saw_settings", ran_first == true)
end
