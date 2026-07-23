-- plugins/tls_cert_self_signed.lua
--
-- Flags a self-signed leaf certificate (issuer DN == subject DN, already
-- structurally compared by the tls-inspector -- TLS/<port>/self_signed).
-- Self-signed certificates cannot be validated by a standard trust store,
-- so clients either fail the connection or must be explicitly configured
-- to trust it out of band.

register{
    script_id      = 100022,
    script_name    = "Self-Signed TLS Certificate",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks whether the leaf certificate's issuer and subject Distinguished " ..
                      "Names are identical (self-signed), meaning no external Certificate " ..
                      "Authority vouches for it.",
    solution       = "Issue the certificate from a trusted internal or public Certificate " ..
                      "Authority, or ensure clients are explicitly configured to trust this " ..
                      "specific certificate/CA out of band.",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    if get_kb_item("TLS/" .. port .. "/self_signed") ~= true then
        return
    end

    local cn = get_kb_item("TLS/" .. port .. "/cn") or "(unknown)"
    local issuer = get_kb_item("TLS/" .. port .. "/issuer") or "(unknown)"

    report_vuln{
        severity    = 2, -- Medium
        title       = "Self-Signed TLS Certificate",
        description = "The certificate presented on port " .. port .. " (CN=" .. cn ..
                       ") is self-signed (issuer == subject). Standard client trust stores " ..
                       "will not validate this certificate.",
        evidence    = "cn=" .. cn .. ", issuer=" .. issuer,
        port        = port,
    }
end
