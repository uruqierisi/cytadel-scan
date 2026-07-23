-- Deliberately never calls close_sock() -- proves plugin-api.md §4.4's
-- force-close guarantee: lua_close() at the end of this invocation must
-- still close the underlying fd via the "cytadel.socket" metatable's
-- __gc/__close.
register{
    script_id      = 971002,
    script_name    = "Fixture Socket Leak",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Opens a socket and never closes it, relying on lua_close() to force-close.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end
    send(sock, "PING\r\n")
    -- No close_sock() call here -- intentional.
end
