register{
    script_id      = 972001,
    script_name    = "Fixture HTTP API",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Issues http_get against a loopback fixture server and records the result.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()

    local resp, err = http_get(port, "/test", { method = "GET", timeout_ms = 3000 })
    if not resp then
        error("http_get GET failed: " .. tostring(err))
    end

    -- Only GET/HEAD are supported -- any other verb must raise (§2.8).
    local ok = pcall(function() return http_get(port, "/", { method = "POST" }) end)
    if ok then
        error("http_get accepted method=POST, which must be rejected")
    end

    set_kb_item("Test/http_api/status", resp.status)
    set_kb_item("Test/http_api/body_len", #resp.body)
    set_kb_item("Test/http_api/content_type", resp.headers["content-type"] or "(absent)")
    set_kb_item("Test/http_api/x_custom", resp.headers["x-fixture"] or "(absent)")

    report_vuln{
        severity = 0,
        title    = "http_get check",
        evidence = "status=" .. tostring(resp.status),
        port     = port,
    }
end
