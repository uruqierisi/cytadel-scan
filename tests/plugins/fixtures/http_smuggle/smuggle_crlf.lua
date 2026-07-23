-- Milestone 5 security-audit finding C1 regression: a path containing an
-- embedded CR/LF must be rejected by http_get() BEFORE any request bytes
-- reach the wire -- otherwise a plugin could smuggle a second,
-- state-changing request (e.g. DELETE) after the intended GET/HEAD,
-- violating the detection-only guarantee (plugin-api.md §0/§5.3).
--
-- Deliberately NOT wrapped in pcall(): http_get() must raise, and this
-- whole invocation must end up FAILED -- never silently "succeed" and
-- never touch the network at all.
register{
    script_id      = 973001,
    script_name    = "C1 Fixture -- CRLF-Injected Path Rejected",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Attempts an HTTP request-smuggling path via CRLF injection.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    http_get(port, "/x\r\nDELETE /admin HTTP/1.1\r\nHost: evil\r\n\r\n", { timeout_ms = 2000 })
end
