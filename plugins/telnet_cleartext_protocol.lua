-- plugins/telnet_cleartext_protocol.lua
--
-- Flags a Telnet service (port 23) as an inherently unencrypted remote-
-- access protocol: all traffic, including any login credentials, is sent
-- in cleartext. Purely a presence check against the frozen "telnet"
-- service token (kb-schema.md §2/§7.3) -- no connection is attempted.

register{
    script_id      = 100040,
    script_name    = "Telnet Service Exposes Unencrypted Remote Access",
    script_version = "1.0.0",
    family         = "General",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/telnet/23" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Telnet transmits all traffic, including any login credentials, in " ..
                      "cleartext. Any network position between the client and this host can " ..
                      "passively capture credentials and session data.",
    solution       = "Disable Telnet and use SSH (or another encrypted remote-access " ..
                      "protocol) instead. If Telnet access is unavoidable, restrict it to a " ..
                      "trusted, isolated management network.",
}

function run()
    local port = 23
    local banner = get_kb_item("Banner/" .. port)
    local evidence
    if banner then
        evidence = "Banner/" .. port .. ": " .. banner
    else
        evidence = "Telnet service detected on port " .. port .. " (port/protocol signature; " ..
                   "no banner text captured)."
    end

    report_vuln{
        severity    = 2, -- Medium
        title       = "Telnet Service Exposes Unencrypted Remote Access",
        description = "A Telnet service was detected on port " .. port ..
                       ". Telnet transmits all traffic, including credentials, in cleartext.",
        evidence    = evidence,
        port        = port,
    }
end
