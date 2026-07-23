-- Records the body length http_get() returns against a fixture server that
-- sends a body far larger than the 1 MiB cap (§2.8: "bodies larger than
-- that are truncated to the cap").
register{
    script_id      = 972002,
    script_name    = "Fixture HTTP Body Cap",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Confirms http_get() truncates an oversized body to the 1 MiB cap.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local resp, err = http_get(port, "/big", { method = "GET", timeout_ms = 5000 })
    if not resp then
        error("http_get failed: " .. tostring(err))
    end
    set_kb_item("Test/http_cap/body_len", #resp.body)
end
