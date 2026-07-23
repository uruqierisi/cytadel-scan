-- plugins/http_missing_xcto.lua
--
-- Flags a web service missing (or misconfigured) X-Content-Type-Options,
-- read from HTTP/<port>/headers/x-content-type-options (gathered by
-- http_headers.lua). The only conforming value is "nosniff" -- any other
-- value present is treated the same as absent (misconfigured).
--
-- Only fires once HTTP/<port>/headers/_probed confirms http_headers.lua
-- actually received a response on this port -- `dependencies = {100030}`
-- is ordering only (plugin-api.md §4.1) and does NOT guarantee that
-- plugin's own GET succeeded (see http_headers.lua's header comment).

register{
    script_id      = 100033,
    script_name    = "Missing Or Misconfigured X-Content-Type-Options Header",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether the web service returns 'X-Content-Type-Options: " ..
                      "nosniff', which prevents browsers from MIME-sniffing responses away " ..
                      "from the declared Content-Type.",
    solution       = "Add 'X-Content-Type-Options: nosniff' to every response.",
}

function run()
    local port = get_scan_port()

    if get_kb_item("HTTP/" .. port .. "/headers/_probed") ~= true then
        log("debug", "http_headers.lua never confirmed a response on port " .. port ..
                      ", not applicable (no observation to report)")
        return
    end

    local value = get_kb_item("HTTP/" .. port .. "/headers/x-content-type-options")

    if value and value:lower():find("nosniff", 1, true) then
        return
    end

    local evidence
    if value then
        evidence = "X-Content-Type-Options: " .. value .. " (expected 'nosniff')"
    else
        evidence = "No X-Content-Type-Options response header observed on GET / (port " ..
                   port .. ")."
    end

    report_vuln{
        severity    = 1, -- Low
        title       = "Missing Or Misconfigured X-Content-Type-Options Header",
        description = "The web service on port " .. port .. " does not return a conforming " ..
                       "'X-Content-Type-Options: nosniff' header.",
        evidence    = evidence,
        port        = port,
    }
end
