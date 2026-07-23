-- plugins/http_known_vulnerable_server.lua
--
-- Heuristic, banner-version-based check flagging clearly end-of-life major
-- web-server release lines (Apache < 2.4, nginx < 1.20, Microsoft-IIS <=
-- 7.x). Deliberately conservative: the Server header can be spoofed, left
-- stale by a reverse proxy, or the specific installation may carry
-- vendor/distro backports, so no specific CVE is asserted -- only a
-- generic "outdated/EOL" signal at Low severity.

register{
    script_id      = 100038,
    script_name    = "Outdated / End-of-Life Web Server Version (Heuristic)",
    script_version = "1.0.0",
    family         = "Web Servers",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Parses the HTTP Server header and flags well-known end-of-life " ..
                      "release lines for Apache httpd, nginx, and Microsoft IIS. Heuristic, " ..
                      "banner-based -- does not confirm any specific CVE applies.",
    solution       = "Upgrade to a currently-supported release of the detected web server " ..
                      "and keep it patched, or place a current, actively-maintained reverse " ..
                      "proxy in front of it.",
}

function run()
    local port = get_scan_port()
    local server = get_kb_item("HTTP/" .. port .. "/server")
    if not server then
        return
    end

    local product, major_s, minor_s = server:match("^([%w%.%-]+)/(%d+)%.(%d+)")
    if not product then
        return
    end
    local major, minor = tonumber(major_s), tonumber(minor_s)
    product = product:lower()

    local eol, note
    if product == "apache" and (major < 2 or (major == 2 and minor < 4)) then
        eol = true
        note = "Apache httpd versions before 2.4 are end-of-life and no longer receive " ..
               "security patches."
    elseif product == "nginx" and (major == 0 or (major == 1 and minor < 20)) then
        eol = true
        note = "This nginx release line predates nginx's actively maintained mainline/" ..
               "stable branches and may be missing security fixes."
    elseif product == "microsoft-iis" and major <= 7 then
        eol = true
        note = "Microsoft IIS 7.x and earlier shipped with end-of-life Windows Server " ..
               "releases with no security updates."
    end

    if not eol then
        return
    end

    local cpe = get_kb_item("CPE/" .. port)

    report_vuln{
        severity    = 1, -- Low
        title       = "Outdated / End-of-Life Web Server Version (Heuristic)",
        description = "The Server header ('" .. server .. "') indicates an outdated/end-of-" ..
                       "life web server release: " .. note .. " This is a heuristic, banner-" ..
                       "based observation -- the Server header can be spoofed, stale behind " ..
                       "a proxy, or the installation may carry backported fixes.",
        evidence    = "Server: " .. server,
        port        = port,
        solution    = "Upgrade to a currently-supported release of " .. product .. ".",
        cpe         = cpe,
    }
end
