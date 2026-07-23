-- plugins/http_insecure_cookie_flags.lua
--
-- Flags cookies set without the Secure flag (when the service is reachable
-- over TLS) and/or the HttpOnly flag, read from
-- HTTP/<port>/headers/set-cookie (gathered by http_headers.lua). Note
-- (heuristic limitation, documented rather than silently assumed): per
-- plugin-api.md §2.8, when a response repeats a header name (multiple
-- Set-Cookie headers), http_get() joins the values with ", " -- this check
-- therefore inspects the whole joined string for the presence of the
-- Secure/HttpOnly attribute tokens ANYWHERE in it, so a response setting
-- several cookies where only SOME are missing a flag will not be
-- distinguished from one another. This is a best-effort, whole-response
-- signal, not a guaranteed per-cookie result.

register{
    script_id      = 100035,
    script_name    = "Cookie Set Without Secure/HttpOnly Flag",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the Set-Cookie response header(s) for the Secure flag (when the " ..
                      "service is reachable over TLS) and the HttpOnly flag.",
    solution       = "Set the Secure flag on every cookie served over HTTPS, and set " ..
                      "HttpOnly on any cookie that does not need to be read by client-side " ..
                      "JavaScript.",
}

function run()
    local port = get_scan_port()
    local cookie = get_kb_item("HTTP/" .. port .. "/headers/set-cookie")
    if not cookie then
        return
    end
    local lc = cookie:lower()

    local use_tls = get_kb_item("TLS/" .. port .. "/enabled") == true
    local missing_secure = use_tls and not lc:find("secure", 1, true)
    local missing_httponly = not lc:find("httponly", 1, true)

    if not missing_secure and not missing_httponly then
        return
    end

    local missing = {}
    if missing_secure then
        missing[#missing + 1] = "Secure"
    end
    if missing_httponly then
        missing[#missing + 1] = "HttpOnly"
    end
    local severity = missing_secure and 2 or 1 -- Medium if Secure is missing over TLS, else Low

    report_vuln{
        severity    = severity,
        title       = "Cookie Set Without " .. table.concat(missing, "/") .. " Flag",
        description = "At least one cookie returned by the web service on port " .. port ..
                       " is missing the " .. table.concat(missing, " and ") ..
                       " attribute. Multiple Set-Cookie headers, if present, are joined by " ..
                       "the HTTP client into one string (plugin-api.md §2.8), so this is a " ..
                       "best-effort, whole-response signal rather than a guaranteed " ..
                       "per-cookie result.",
        evidence    = "Set-Cookie: " .. cookie,
        port        = port,
    }
end
