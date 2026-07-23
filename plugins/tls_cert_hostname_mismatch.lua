-- plugins/tls_cert_hostname_mismatch.lua
--
-- Compares the certificate's Common Name and Subject Alternative Names
-- against the host's own resolved hostname (Host/hostname, written by
-- host-discovery's reverse-DNS lookup). If reverse DNS never resolved a
-- hostname for this target, there is nothing meaningful to compare against
-- and this check is silently not applicable (skipped) -- it never guesses.
--
-- Supports a single leading-wildcard label ("*.example.com") in CN/SAN
-- entries, matching the common real-world case; it does not implement the
-- full RFC 6125 matching algorithm (e.g. multiple wildcard labels, IP
-- SANs), which is a deliberate scope simplification for this check.

register{
    script_id      = 100023,
    script_name    = "TLS Certificate Hostname Mismatch",
    script_version = "1.0.0",
    family         = "TLS",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Compares the certificate's Common Name and Subject Alternative Names " ..
                      "against the host's resolved hostname; reports a mismatch if neither " ..
                      "matches (including a single-label leading wildcard).",
    solution       = "Issue a certificate whose CN/SAN list includes the hostname(s) this " ..
                      "service is actually reached by.",
}

local function wildcard_matches(pattern, host)
    local suffix = pattern:match("^%*%.(.+)$")
    if not suffix then
        return false
    end
    return host:sub(-(#suffix + 1)) == "." .. suffix
end

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    local hostname = get_kb_item("Host/hostname")
    if not hostname then
        log("debug", "no Host/hostname recorded, cannot check certificate hostname match")
        return
    end
    local hostname_lc = hostname:lower()

    local cn = get_kb_item("TLS/" .. port .. "/cn")
    local san = get_kb_item("TLS/" .. port .. "/san")

    local candidates = {}
    if cn then
        candidates[#candidates + 1] = cn
    end
    if san then
        for entry in san:gmatch("[^,]+") do
            candidates[#candidates + 1] = entry
        end
    end
    if #candidates == 0 then
        log("debug", "no TLS/" .. port .. "/cn or /san recorded, cannot check hostname match")
        return
    end

    for _, candidate in ipairs(candidates) do
        local candidate_lc = candidate:lower()
        if candidate_lc == hostname_lc or wildcard_matches(candidate_lc, hostname_lc) then
            return -- a match was found -- not applicable
        end
    end

    report_vuln{
        severity    = 2, -- Medium
        title       = "TLS Certificate Hostname Mismatch",
        description = "Neither the certificate's Common Name nor any Subject Alternative " ..
                       "Name on port " .. port .. " matches this host's resolved name (" ..
                       hostname .. "). Clients performing hostname verification will reject " ..
                       "this certificate for that name.",
        evidence    = "Host/hostname=" .. hostname .. ", cn=" .. (cn or "(none)") ..
                       ", san=" .. (san or "(none)"),
        port        = port,
    }
end
