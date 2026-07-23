register{
    script_id      = 971001,
    script_name    = "Fixture Socket API",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Connects to a loopback fixture server, sends/recvs, and reports a finding.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        error("open_sock_tcp failed: " .. tostring(err))
    end

    local sent, serr = send(sock, "PING\r\n")
    if not sent then
        close_sock(sock)
        error("send failed: " .. tostring(serr))
    end

    local reply, rerr = recv(sock, 512, 3000)
    if not reply then
        close_sock(sock)
        error("recv failed: " .. tostring(rerr))
    end

    close_sock(sock)
    -- Idempotent -- closing an already-closed socket must be a silent no-op (§2.7).
    close_sock(sock)

    report_vuln{
        severity = 0,
        title    = "socket api check",
        evidence = reply,
        port     = port,
    }
end
