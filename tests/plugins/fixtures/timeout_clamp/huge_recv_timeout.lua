-- Milestone 5 security-audit finding W1 regression: recv()'s timeout_ms
-- must be clamped to at most the §4.5 run-phase budget (15000 ms), never
-- allowed through unclamped. The fixture server accepts the connection
-- but deliberately never sends any data, so without the fix this recv()
-- call -- given an enormous timeout_ms -- would block for a huge fraction
-- of a day rather than returning within roughly the 15s budget.
register{
    script_id      = 974001,
    script_name    = "W1 Fixture -- Huge recv() Timeout Clamped",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls recv() with an enormous timeout_ms against a silent server.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end

    -- Roughly 11.5 days if this were not clamped. Must return (with an
    -- error, since the server never sends anything) within roughly the
    -- 15000 ms run-phase budget instead.
    local data, rerr = recv(sock, 512, 999999999)
    close_sock(sock)

    if data then
        error("recv() unexpectedly returned data from a silent server")
    end

    error("recv() timed out as expected (clamped): " .. tostring(rerr))
end
