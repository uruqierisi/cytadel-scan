-- plugins/http_missing_xfo.lua
--
-- Flags a web service missing clickjacking protection: no X-Frame-Options
-- header AND no Content-Security-Policy frame-ancestors directive (either
-- one alone is sufficient defense, so this only fires when both are
-- absent). Read from HTTP/<port>/headers/x-frame-options and
-- .../content-security-policy (gathered by http_headers.lua).
--
-- Only fires once HTTP/<port>/headers/_probed confirms http_headers.lua
-- actually received a response on this port -- `dependencies = {100030}`
-- is ordering only (plugin-api.md §4.1) and does NOT guarantee that
-- plugin's own GET succeeded (see http_headers.lua's header comment).

register{
    script_id      = 100034,
    script_name    = "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether the web service sets X-Frame-Options, or a Content-" ..
                      "Security-Policy with a frame-ancestors directive, to prevent the page " ..
                      "from being embedded in a hostile iframe (clickjacking).",
    solution       = "Add 'X-Frame-Options: DENY' (or 'SAMEORIGIN'), or a Content-Security-" ..
                      "Policy 'frame-ancestors' directive.",
}

function run()
    local port = get_scan_port()

    if get_kb_item("HTTP/" .. port .. "/headers/_probed") ~= true then
        log("debug", "http_headers.lua never confirmed a response on port " .. port ..
                      ", not applicable (no observation to report)")
        return
    end

    if get_kb_item("HTTP/" .. port .. "/headers/x-frame-options") then
        return
    end

    local csp = get_kb_item("HTTP/" .. port .. "/headers/content-security-policy")
    if csp and csp:lower():find("frame-ancestors", 1, true) then
        log("debug", "no X-Frame-Options but CSP frame-ancestors present, not applicable")
        return
    end

    local evidence = "No X-Frame-Options header observed on GET / (port " .. port .. ")."
    if csp then
        evidence = evidence .. " Content-Security-Policy is present but has no " ..
                   "frame-ancestors directive: " .. csp
    end

    report_vuln{
        severity    = 1, -- Low
        title       = "Missing Clickjacking Protection",
        description = "The web service on port " .. port .. " does not set X-Frame-Options " ..
                       "or a CSP frame-ancestors directive.",
        evidence    = evidence,
        port        = port,
    }
end
