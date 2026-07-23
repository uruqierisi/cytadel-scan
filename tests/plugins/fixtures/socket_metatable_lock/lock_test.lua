-- Milestone 5 security-audit finding W2 regression (Lua-level half): a
-- plugin must never be able to reach the socket userdata's real,
-- mutable metatable -- getmetatable()/setmetatable() are both reachable
-- from the run-phase base-library sandbox (plugin-api.md §5.1), and
-- before the fix `getmetatable(sock).__gc = nil` was an ordinary,
-- unprotected table field write that silently defeated §4.4's
-- force-close guarantee at the Lua level.
register{
    script_id      = 975001,
    script_name    = "W2 Fixture -- Socket Metatable Is Locked",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Verifies getmetatable(sock)/setmetatable(sock, ...) cannot reach or replace the real socket metatable.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end

    -- getmetatable() must never return the real, mutable metatable table.
    local mt = getmetatable(sock)
    if type(mt) == "table" then
        close_sock(sock)
        error("sandbox escape: getmetatable(sock) returned the real metatable table")
    end

    -- Attempting to mutate whatever getmetatable() DID return must raise
    -- (it is not a table a plugin can write fields into).
    local ok1 = pcall(function()
        getmetatable(sock).__gc = nil
    end)
    if ok1 then
        close_sock(sock)
        error("getmetatable(sock).__gc = nil unexpectedly succeeded")
    end

    -- setmetatable() on a protected-metatable object must also raise.
    local ok2 = pcall(setmetatable, sock, {})
    if ok2 then
        close_sock(sock)
        error("setmetatable(sock, {}) unexpectedly succeeded")
    end

    close_sock(sock)

    report_vuln{
        severity = 0,
        title    = "socket metatable lock check passed",
        evidence = "getmetatable/setmetatable tampering both rejected",
        port     = port,
    }
end
