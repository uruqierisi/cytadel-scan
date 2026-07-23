-- Security-review round-2 FIX 2 regression: recv()'s timeout_ms must be
-- floored to at least 1 ms internally, never left at the caller's literal
-- 0 -- an all-zero {0,0} SO_RCVTIMEO timeval means "no timeout" (block
-- forever) on Linux, not "expire immediately". This fixture explicitly
-- passes timeout_ms = 0 against a server that never sends anything, so
-- without the fix this recv() call would block the whole worker thread
-- forever (the §4.5 instruction-count runtime-limit hook cannot fire
-- while blocked in a syscall executing no Lua VM instructions).
register{
    script_id      = 977001,
    script_name    = "FIX2 Fixture -- recv() timeout_ms=0 Must Not Block Forever",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Calls recv() with timeout_ms = 0 against a silent server.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end

    -- timeout_ms = 0 must be floored to 1ms internally, never treated as
    -- "block forever". Must return quickly (with an error, since the
    -- server never sends anything) rather than hanging.
    local data, rerr = recv(sock, 512, 0)
    close_sock(sock)

    if data then
        error("recv() unexpectedly returned data from a silent server")
    end

    error("recv() returned as expected (clamped, not blocked forever): " .. tostring(rerr))
end
