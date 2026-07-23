-- Verifies every dangerous stdlib surface is nil in the run-phase sandbox
-- (plugin-api.md §5.1): os/io/package/require/load/loadfile/dofile/debug/
-- print/collectgarbage/_G. Expected result: OK (a passing check reports a
-- finding so the C test can confirm the check body actually executed, not
-- merely that run() returned without erroring for an unrelated reason).
register{
    script_id      = 950001,
    script_name    = "Fixture Check Dangerous Nil",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Fails run() if any sandboxed-away stdlib surface is reachable.",
    solution       = "N/A -- test fixture.",
}

function run()
    local dangerous = {
        "os", "io", "package", "require", "load", "loadfile", "dofile",
        "debug", "print", "collectgarbage", "_G", "unpack",
    }
    for _, name in ipairs(dangerous) do
        -- Reading an undefined global under a rebound _ENV yields nil, not
        -- an error -- exactly what proves isolation here.
        local v = _ENV and _ENV[name] or nil
        if v ~= nil then
            error("sandbox escape: '" .. name .. "' is reachable (type " .. type(v) .. ")")
        end
    end

    report_vuln{
        severity = 0,
        title    = "sandbox dangerous-surface check passed",
        evidence = "os/io/package/require/load/loadfile/dofile/debug/print/collectgarbage/_G/unpack all nil",
        port     = 0,
    }
end
