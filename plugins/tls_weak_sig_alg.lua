-- plugins/tls_weak_sig_alg.lua
--
-- Flags a certificate signed with a cryptographically weak/deprecated
-- signature algorithm (MD5 or SHA-1), read from the tls-inspector's own
-- OBJ_obj2txt() rendering of the certificate's signature algorithm OID
-- (TLS/<port>/sig_alg).

register{
    script_id      = 100024,
    script_name    = "TLS Certificate Signed With A Weak Signature Algorithm",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the certificate's signature algorithm for MD5 or SHA-1, both of " ..
                      "which are considered cryptographically weak for certificate signing.",
    solution       = "Reissue the certificate using a modern signature algorithm (SHA-256 or " ..
                      "stronger).",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    local sig_alg = get_kb_item("TLS/" .. port .. "/sig_alg")
    if not sig_alg then
        return
    end
    local lc = sig_alg:lower()

    local severity, label
    if lc:find("md5", 1, true) then
        severity, label = 3, "MD5" -- High: MD5 collisions are practically exploitable.
    elseif lc:find("sha1", 1, true) then
        severity, label = 2, "SHA-1" -- Medium: deprecated but harder to abuse for certs today.
    else
        return
    end

    report_vuln{
        severity    = severity,
        title       = "TLS Certificate Signed With A Weak Signature Algorithm (" .. label .. ")",
        description = "The X.509 certificate on port " .. port .. " was signed using " ..
                       label .. " (" .. sig_alg .. "), a cryptographically weak/deprecated " ..
                       "signature algorithm.",
        evidence    = "sig_alg=" .. sig_alg,
        port        = port,
        solution    = "Reissue the certificate using a modern signature algorithm (SHA-256 " ..
                       "or stronger, e.g. sha256WithRSAEncryption or ecdsa-with-SHA256).",
    }
end
