-- Milestone 5 security-audit finding W2 regression (engine-side half):
-- opens a socket and NEVER calls close_sock() -- relies entirely on the
-- engine's force-close guarantee (§4.4/W2's fd tracker in invoke.c, not
-- Lua's own __gc/__close) to release the fd when this invocation ends.
-- The C test runs this fixture many times in a loop and asserts the
-- process's open-fd count never grows, proving no fd leak at scale.
register{
    script_id      = 976001,
    script_name    = "W2 Fixture -- Socket Leaked, Engine Must Force-Close",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Opens a socket and never closes it, in a loop across many invocations.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end
    -- No close_sock() call -- intentional, every invocation.
end
