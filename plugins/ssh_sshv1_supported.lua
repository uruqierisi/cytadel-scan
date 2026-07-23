-- plugins/ssh_sshv1_supported.lua
--
-- Detects SSH protocol-1 support (or dual SSH-1/SSH-2 backward-compat mode,
-- signaled by a "1.99" protoversion per RFC 4253) from the parsed
-- SSH/<port>/protocol KB fact the engine's service-detection stage (or an
-- earlier ACT_SETTINGS plugin) already extracted from the version-exchange
-- banner. SSH-1 has well-known, structural cryptographic weaknesses (weak
-- integrity protection, vulnerable to known plaintext-recovery attacks) and
-- has been deprecated for many years.
--
-- Dispatched via the "Services/ssh/*" wildcard (plugin-api.md §4.6), not
-- hard-coded to port 22: src/net/svc_ssh.c detects SSH by its unambiguous
-- "SSH-" banner prefix and writes Services/ssh/<port> for whatever port it
-- is actually found on (a common hardening convention runs SSH on a
-- non-default port), so a fixed "Services/ssh/22" gate would silently miss
-- every SSH-1/dual-protocol daemon running elsewhere.

register{
    script_id      = 100010,
    script_name    = "SSH Protocol 1 Supported",
    script_version = "1.0.0",
    family         = "SSH",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ssh/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "High",
    description    = "Checks the SSH protocol version reported during the version-exchange " ..
                      "banner for SSH-1 support (a bare '1.x' protoversion, or the '1.99' " ..
                      "backward-compatibility value that means the server still accepts " ..
                      "SSH-1 connections).",
    solution       = "Disable SSH protocol 1 support entirely; configure the SSH daemon to " ..
                      "accept only protocol 2 connections.",
}

function run()
    local port = get_scan_port()
    local protocol = get_kb_item("SSH/" .. port .. "/protocol")
    if not protocol then
        log("debug", "no SSH/" .. port .. "/protocol recorded, not applicable")
        return
    end

    -- RFC 4253 §5's protoversion grammar allows a bare "1" (no minor
    -- version) in addition to "1.x"/"1.99" -- sub(1,2) alone would miss a
    -- lone "1", so that exact value is checked separately.
    if protocol ~= "1" and protocol:sub(1, 2) ~= "1." then
        return
    end

    local version = get_kb_item("SSH/" .. port .. "/version") or protocol

    report_vuln{
        severity    = 3, -- High
        title       = "SSH Protocol 1 Supported",
        description = "The SSH service on port " .. port .. " reports protocol version '" ..
                       protocol .. "' during the version exchange, indicating it accepts " ..
                       "SSH protocol 1 connections (either exclusively, or in backward-" ..
                       "compatible dual-protocol mode). SSH-1 has known structural " ..
                       "cryptographic weaknesses.",
        evidence    = version,
        port        = port,
    }
end
