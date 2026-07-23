-- plugins/tls_weak_key_size.lua
--
-- Flags an undersized public key. TLS/<port>/key_bits (src/net/tls_inspect.c,
-- via EVP_PKEY_bits()) reports bit-length uniformly for both RSA moduli and
-- EC curve orders, but a "small" bit count means very different things for
-- each family (a 256-bit EC key is strong; a 256-bit RSA key is trivially
-- broken) -- the KB does not separately record the key algorithm, so this
-- check infers the family HEURISTICALLY from the certificate's signature
-- algorithm (TLS/<port>/sig_alg) and applies a family-appropriate
-- threshold. If the signature algorithm cannot be read, this check skips
-- entirely rather than risk flagging a perfectly strong EC key as weak.

register{
    script_id      = 100025,
    script_name    = "Weak TLS Certificate Public Key Size",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the certificate's public key size against family-appropriate " ..
                      "minimums (RSA: 2048 bits; EC: ~224 bits), inferring the key family " ..
                      "heuristically from the certificate's signature algorithm.",
    solution       = "Reissue the certificate with an appropriately sized key (RSA 2048-bit " ..
                      "or larger, or a standard modern elliptic curve).",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    local key_bits = get_kb_item("TLS/" .. port .. "/key_bits")
    if key_bits == nil then
        return
    end

    local sig_alg = get_kb_item("TLS/" .. port .. "/sig_alg")
    if not sig_alg then
        log("debug", "no TLS/" .. port .. "/sig_alg to infer key algorithm family, skipping " ..
                      "key-size check to avoid a false positive on an EC key")
        return
    end
    local lc = sig_alg:lower()
    local is_rsa = lc:find("rsa", 1, true) ~= nil
    local is_ec = lc:find("ecdsa", 1, true) ~= nil or lc:find("ed25519", 1, true) ~= nil or
                  lc:find("ed448", 1, true) ~= nil

    local evidence = "key_bits=" .. key_bits .. ", sig_alg=" .. sig_alg
    local note = "Algorithm family inferred heuristically from the certificate's signature " ..
                 "algorithm, which may occasionally differ from the subject public key " ..
                 "algorithm in cross-signed certificates."

    if is_rsa and key_bits < 2048 then
        report_vuln{
            severity    = 2, -- Medium
            title       = "Weak RSA Public Key Size",
            description = "The RSA public key presented on port " .. port .. " is only " ..
                           key_bits .. " bits. Current guidance requires at least 2048-bit " ..
                           "RSA keys. " .. note,
            evidence    = evidence,
            port        = port,
        }
    elseif is_ec and key_bits < 224 then
        report_vuln{
            severity    = 2, -- Medium
            title       = "Weak Elliptic-Curve Public Key Size",
            description = "The elliptic-curve public key presented on port " .. port ..
                           " is only " .. key_bits .. " bits, below the ~224-bit curve-order " ..
                           "minimum modern guidance recommends. " .. note,
            evidence    = evidence,
            port        = port,
        }
    end
end
