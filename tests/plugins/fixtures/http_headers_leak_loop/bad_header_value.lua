-- Milestone 5 security-audit finding W4 regression: before the fix, the
-- request buffer `req` was malloc'd BEFORE opts.headers was validated, so
-- a wrong-typed header value's luaL_error() (raised while appending
-- headers) longjmped past freeing it -- directly plugin-triggerable heap
-- growth, one leak per pcall-wrapped call. Because header validation now
-- happens before `req` is even allocated, none of these calls ever touch
-- the network at all (no server needed for this fixture).
register{
    script_id      = 978001,
    script_name    = "W4 Fixture -- http_get{} Wrong-Typed Header Loop",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls http_get{} with a wrong-typed opts.headers value, in a pcall loop.",
    solution       = "N/A -- test fixture.",
}

function run()
    local iterations = 2000

    for i = 1, iterations do
        local ok = pcall(function()
            -- W4: wrong-typed header value (must be a string) -- rejected
            -- before `req` is allocated or any connection is attempted,
            -- so an arbitrary port number (nothing needs to be listening
            -- on it) is fine here.
            return http_get(54321, "/x", { headers = { ["X-Test"] = 12345 } })
        end)
        if ok then
            error("http_get{} accepted a non-string header value, which must be rejected")
        end
    end

    report_vuln{
        severity = 0,
        title    = "http header leak loop check passed",
        evidence = tostring(iterations) .. " wrong-typed opts.headers calls all rejected cleanly",
        port     = 0,
    }
end
