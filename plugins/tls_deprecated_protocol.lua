-- plugins/tls_deprecated_protocol.lua
--
-- Flags a deprecated TLS/SSL protocol version actually negotiated during
-- the handshake (TLS/<port>/version, OpenSSL's SSL_get_version() string --
-- "SSLv3", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"). Matched by exact
-- string equality (not substring) so "TLSv1" never accidentally matches
-- "TLSv1.1"/"TLSv1.2".

register{
    script_id      = 100026,
    script_name    = "Deprecated TLS Protocol Version Negotiated",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the TLS protocol version actually negotiated during the " ..
                      "handshake for SSLv3, TLSv1.0, or TLSv1.1, all of which are deprecated " ..
                      "and lack modern cryptographic protections.",
    solution       = "Disable deprecated protocol versions on this service and require " ..
                      "TLS 1.2 or later.",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    local version = get_kb_item("TLS/" .. port .. "/version")
    if not version then
        return
    end

    local severity
    if version == "SSLv3" then
        severity = 3 -- High
    elseif version == "TLSv1" or version == "TLSv1.1" then
        severity = 2 -- Medium
    else
        return
    end

    report_vuln{
        severity    = severity,
        title       = "Deprecated TLS Protocol Version Negotiated (" .. version .. ")",
        description = "The TLS handshake on port " .. port .. " negotiated " .. version ..
                       ", a deprecated protocol version lacking modern cryptographic " ..
                       "protections.",
        evidence    = "TLS/" .. port .. "/version=" .. version,
        port        = port,
        solution    = "Disable " .. version .. " (and any older protocol) on this service " ..
                       "and require TLS 1.2 or later.",
    }
end
