-- plugins/tls_cert_not_yet_valid.lua
--
-- Flags a TLS certificate whose validity period has not started yet
-- (notBefore is in the future), using the tls-inspector's own computed
-- TLS/<port>/cert_not_yet_valid fact. Usually indicates a clock-skew issue
-- on the target or a certificate issued/staged ahead of its intended
-- deployment date.

register{
    script_id      = 100021,
    script_name    = "TLS Certificate Not Yet Valid",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks whether the X.509 certificate presented during the TLS " ..
                      "handshake has a notBefore date that has not yet arrived.",
    solution       = "Verify the certificate's intended validity window and the target " ..
                      "system's clock; reissue the certificate if it was generated with an " ..
                      "incorrect notBefore date.",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    if get_kb_item("TLS/" .. port .. "/cert_not_yet_valid") ~= true then
        return
    end

    local not_before = get_kb_item("TLS/" .. port .. "/not_before") or "(unknown)"
    local cn = get_kb_item("TLS/" .. port .. "/cn") or "(unknown)"

    report_vuln{
        severity    = 2, -- Medium
        title       = "TLS Certificate Not Yet Valid",
        description = "The X.509 certificate presented on port " .. port .. " (CN=" .. cn ..
                       ") has a notBefore date of " .. not_before .. ", which has not yet " ..
                       "arrived. Clients that correctly validate certificates will reject " ..
                       "connections to this service until that date.",
        evidence    = "cn=" .. cn .. ", not_before=" .. not_before,
        port        = port,
    }
end
