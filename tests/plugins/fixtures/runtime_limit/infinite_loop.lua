-- Must be killed by the §4.5 runtime-limit hook (15000ms default) and
-- marked FAILED, without hanging the test suite (the hook's
-- LUA_MASKCOUNT instruction-count granularity guarantees the wall-clock
-- check actually runs inside a tight loop like this one).
register{
    script_id      = 990001,
    script_name    = "Fixture Infinite Loop",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "An intentional infinite loop to exercise the runtime-limit hook.",
    solution       = "N/A -- test fixture.",
}

function run()
    while true do
    end
end
