-- plugins/http_missing_hsts.lua
--
-- Flags an HTTPS service that does not return a Strict-Transport-Security
-- header, read from HTTP/<port>/headers/strict-transport-security
-- (gathered by http_headers.lua). Only relevant over TLS -- gated on the
-- "Services/https/*" wildcard, matching TLS/<port>/enabled.
--
-- Only fires once HTTP/<port>/headers/_probed confirms http_headers.lua
-- actually received a response on this port -- `dependencies = {100030}`
-- is ordering only (plugin-api.md §4.1) and does NOT guarantee that
-- plugin's own GET succeeded (see http_headers.lua's header comment).

register{
    script_id      = 100031,
    script_name    = "Missing HTTP Strict-Transport-Security (HSTS) Header",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },
    required_keys  = { "Services/https/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether an HTTPS service returns a Strict-Transport-Security " ..
                      "response header instructing browsers to enforce HTTPS-only " ..
                      "connections for this host.",
    solution       = "Add a 'Strict-Transport-Security: max-age=63072000; includeSubDomains' " ..
                      "response header (only after confirming the site is fully served over " ..
                      "HTTPS).",
}

function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end

    if get_kb_item("HTTP/" .. port .. "/headers/_probed") ~= true then
        log("debug", "http_headers.lua never confirmed a response on port " .. port ..
                      ", not applicable (no observation to report)")
        return
    end

    if get_kb_item("HTTP/" .. port .. "/headers/strict-transport-security") then
        return
    end

    report_vuln{
        severity    = 1, -- Low
        title       = "Missing HTTP Strict-Transport-Security (HSTS) Header",
        description = "The HTTPS service on port " .. port .. " did not return a " ..
                       "Strict-Transport-Security header on the baseline GET /, so browsers " ..
                       "are not instructed to enforce HTTPS-only connections for this host.",
        evidence    = "No Strict-Transport-Security response header observed on GET / " ..
                       "(port " .. port .. ").",
        port        = port,
    }
end
