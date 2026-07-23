-- plugins/http_missing_csp.lua
--
-- Flags a web service that does not return a Content-Security-Policy
-- header, read from HTTP/<port>/headers/content-security-policy (gathered
-- by http_headers.lua). Only fires once HTTP/<port>/headers/_probed
-- confirms http_headers.lua actually received a response on this port --
-- `dependencies = {100030}` is ordering only (plugin-api.md §4.1) and does
-- NOT guarantee that plugin's own GET succeeded, so this check must not
-- treat "no response was ever observed" the same as "a response arrived
-- with no CSP header" (see http_headers.lua's header comment).

register{
    script_id      = 100032,
    script_name    = "Missing Content-Security-Policy Header",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether the web service returns a Content-Security-Policy " ..
                      "header, a defense-in-depth control against XSS and other content-" ..
                      "injection attacks.",
    solution       = "Define and deploy a Content-Security-Policy appropriate to the " ..
                      "application (starting in report-only mode if needed to validate it " ..
                      "against existing page behavior first).",
}

function run()
    local port = get_scan_port()

    if get_kb_item("HTTP/" .. port .. "/headers/_probed") ~= true then
        log("debug", "http_headers.lua never confirmed a response on port " .. port ..
                      ", not applicable (no observation to report)")
        return
    end

    if get_kb_item("HTTP/" .. port .. "/headers/content-security-policy") then
        return
    end

    report_vuln{
        severity    = 1, -- Low
        title       = "Missing Content-Security-Policy Header",
        description = "The web service on port " .. port .. " did not return a Content-" ..
                       "Security-Policy header on the baseline GET /.",
        evidence    = "No Content-Security-Policy response header observed on GET / " ..
                       "(port " .. port .. ").",
        port        = port,
    }
end
