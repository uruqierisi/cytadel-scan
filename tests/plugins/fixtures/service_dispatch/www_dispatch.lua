-- Service-wildcard dispatch fixture (plugin-api.md §2.2a/§4.6): must run
-- once per matching Services/www/<port> entry, with get_scan_port()
-- returning the bound port on each dispatch.
register{
    script_id      = 970001,
    script_name    = "Fixture WWW Dispatch",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Records the bound port from get_scan_port() on each dispatch.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    if port == nil then
        error("get_scan_port() returned nil for a service-wildcard dispatch")
    end
    set_kb_item("Test/service_dispatch/port/" .. port, port)
end
