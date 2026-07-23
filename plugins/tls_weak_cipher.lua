-- plugins/tls_weak_cipher.lua
--
-- Flags a weak/legacy cipher suite actually negotiated during the TLS
-- handshake (TLS/<port>/cipher, OpenSSL's SSL_get_cipher() name). Matches
-- well-known weak-cipher-suite name fragments only (case-insensitive,
-- literal substring search -- never a Lua pattern, since cipher-suite
-- names are external, engine-supplied strings).

register{
    script_id      = 100027,
    script_name    = "Weak TLS Cipher Suite Negotiated",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the TLS cipher suite actually negotiated during the handshake " ..
                      "against well-known weak/legacy cipher-suite name fragments (NULL, " ..
                      "EXPORT, anonymous key exchange, RC4, DES/3DES, MD5-based MAC).",
    solution       = "Reconfigure the server's TLS cipher suite preference list to remove " ..
                      "weak/legacy suites and prefer modern AEAD ciphers (e.g. AES-GCM or " ..
                      "ChaCha20-Poly1305) with forward secrecy (ECDHE).",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    local cipher = get_kb_item("TLS/" .. port .. "/cipher")
    if not cipher then
        return
    end
    local lc = cipher:lower()

    local severity, reason
    if lc:find("null", 1, true) then
        severity, reason = 3, "NULL encryption (no confidentiality)"
    elseif lc:find("export", 1, true) then
        severity, reason = 3, "an EXPORT-grade cipher (deliberately weakened)"
    elseif lc:find("anon", 1, true) then
        severity, reason = 3, "anonymous key exchange (no peer authentication)"
    elseif lc:find("rc4", 1, true) then
        severity, reason = 2, "the RC4 stream cipher (broken)"
    elseif lc:find("des", 1, true) then
        severity, reason = 2, "a DES/3DES block cipher (weak, small block size)"
    elseif lc:find("md5", 1, true) then
        severity, reason = 2, "an MD5-based MAC (collision-weak)"
    else
        return
    end

    report_vuln{
        severity    = severity,
        title       = "Weak TLS Cipher Suite Negotiated",
        description = "The TLS handshake on port " .. port .. " negotiated the cipher suite " ..
                       "'" .. cipher .. "', which uses " .. reason .. ".",
        evidence    = "TLS/" .. port .. "/cipher=" .. cipher,
        port        = port,
    }
end
