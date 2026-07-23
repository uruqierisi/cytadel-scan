-- plugins/http_directory_listing.lua
--
-- Heuristic directory-listing (autoindex) detector based purely on the
-- baseline response's parsed <title> (HTTP/<port>/title -- already
-- populated by the C engine's own baseline probe, src/net/http_probe.c;
-- this check needs no network access of its own). Apache/nginx/lighttpd's
-- default autoindex pages conventionally title the page literally
-- "Index of <path>" (e.g. "Index of /", "Index of /uploads/"), which is a
-- strong, low-false-positive signal precisely because it is each server's
-- own fixed template text, not user content.

register{
    script_id      = 100037,
    script_name    = "Directory Listing Enabled (Heuristic)",
    script_version = "1.0.0",
    family         = "Web Servers",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks the baseline response's HTML <title> for the conventional " ..
                      "'Index of ...' autoindex pattern used by Apache/nginx/lighttpd's " ..
                      "default directory-listing template.",
    solution       = "Disable directory autoindexing (e.g. Apache 'Options -Indexes', nginx " ..
                      "'autoindex off;') unless a browsable directory listing is " ..
                      "intentionally required.",
}

function run()
    local port = get_scan_port()
    local title = get_kb_item("HTTP/" .. port .. "/title")
    if not title then
        return
    end
    local lc = title:lower()

    if not (lc:find("index of /", 1, true) or lc == "index of") then
        return
    end

    report_vuln{
        severity    = 2, -- Medium
        title       = "Directory Listing Enabled (Heuristic)",
        description = "The baseline response's HTML <title> on port " .. port .. " matches " ..
                       "the conventional 'Index of ...' autoindex pattern, suggesting " ..
                       "directory listing is enabled for the web root. This is a heuristic, " ..
                       "title-text-based signal, not a direct enumeration of exposed files.",
        evidence    = "Page <title> on GET / (port " .. port .. "): " .. title,
        port        = port,
    }
end
