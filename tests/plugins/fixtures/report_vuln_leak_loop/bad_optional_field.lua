-- Milestone 5 security-audit finding W3 regression: before the fix,
-- title/evidence (and description/solution/cve/cpe/cvss_vector) were
-- allocated before every optional field's type was validated, so a
-- wrong-typed optional field's luaL_error() longjmped past freeing
-- whatever had already been allocated for earlier fields in that same
-- call -- directly plugin-triggerable heap growth, one leak per
-- pcall-wrapped call. Looping this many times under a pcall (so a single
-- rejected call never aborts run() itself) and then letting the process
-- exit cleanly is what lets ASan's LeakSanitizer catch any regression.
register{
    script_id      = 977001,
    script_name    = "W3 Fixture -- report_vuln{} Wrong-Typed Field Loop",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls report_vuln{} with a wrong-typed optional field, in a pcall loop.",
    solution       = "N/A -- test fixture.",
}

function run()
    local iterations = 2000

    for i = 1, iterations do
        local ok = pcall(function()
            report_vuln{
                severity    = 1,
                title       = "leak loop finding",
                evidence    = "evidence text",
                port        = 0,
                -- W3: wrong-typed optional field (must be a string or nil).
                description = { "wrong type -- should be a string" },
            }
        end)
        if ok then
            error("report_vuln{} accepted a table 'description' field, which must be rejected")
        end
    end

    -- One valid call at the end proves the API still works normally after
    -- many rejected calls (no corrupted internal state from the loop).
    report_vuln{
        severity = 0,
        title    = "report_vuln leak loop check passed",
        evidence = tostring(iterations) .. " wrong-typed report_vuln{} calls all rejected cleanly",
        port     = 0,
    }
end
