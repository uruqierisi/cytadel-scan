-- Companion to smuggle_crlf.lua/smuggle_space.lua: a normal, well-formed
-- request against the SAME fixture server/port must still work exactly as
-- before, and must be the ONLY request the server ever sees (proving the
-- two malicious siblings above never touched the network at all).
register{
    script_id      = 973003,
    script_name    = "C1 Fixture -- Legitimate Request Still Works",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "A normal http_get() against the shared fixture server.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local resp, err = http_get(port, "/ok", { timeout_ms = 2000 })
    if not resp then
        error("legitimate http_get failed: " .. tostring(err))
    end

    set_kb_item("Test/c1/status", resp.status)

    report_vuln{
        severity = 0,
        title    = "c1 smuggling check -- legitimate request",
        evidence = "status=" .. tostring(resp.status),
        port     = port,
    }
end
