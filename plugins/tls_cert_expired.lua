-- plugins/tls_cert_expired.lua
--
-- Flags an expired TLS certificate using the tls-inspector's own
-- wall-clock-vs-notAfter comparison (TLS/<port>/cert_expired), already
-- computed by the C engine (src/net/tls_inspect.c) at scan time.
--
-- Dispatched via the "Services/https/*" wildcard, per plugin-api.md §4.6's
-- documented pattern for the TLS/http-header plugin family. Note (scope
-- limitation, not a plugin bug): Services/https/<port> is only written by
-- the current engine for TLS-confirmed ports that are ALSO recognized HTTP
-- ports (443/8443 today, src/net/svc_token.c). TLS-only, non-HTTP
-- protocols (IMAPS/POP3S/SMTPS/LDAPS on 993/995/465/636) negotiate TLS and
-- populate TLS/<port>/* facts today, but do not yet get a Services/https
-- token, so this plugin family will not currently dispatch against those
-- ports -- see plugins/README.md.

register{
    script_id      = 100020,
    script_name    = "TLS Certificate Expired",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "High",
    description    = "Checks whether the X.509 certificate presented during the TLS " ..
                      "handshake has already expired (notAfter is in the past).",
    solution       = "Renew the TLS certificate and configure automated renewal (e.g. " ..
                      "ACME/Let's Encrypt) to prevent recurrence.",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    if get_kb_item("TLS/" .. port .. "/cert_expired") ~= true then
        return
    end

    local not_after = get_kb_item("TLS/" .. port .. "/not_after") or "(unknown)"
    local cn = get_kb_item("TLS/" .. port .. "/cn") or "(unknown)"

    report_vuln{
        severity    = 3, -- High
        title       = "TLS Certificate Expired",
        description = "The X.509 certificate presented on port " .. port .. " (CN=" .. cn ..
                       ") expired on " .. not_after .. ". Clients that correctly validate " ..
                       "certificates will reject connections to this service.",
        evidence    = "cn=" .. cn .. ", not_after=" .. not_after,
        port        = port,
    }
end
