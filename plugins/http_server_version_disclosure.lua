-- plugins/http_server_version_disclosure.lua
--
-- Purely informational: the HTTP Server response header discloses the
-- exact web-server software/version, lowering attacker fingerprinting
-- effort. Reads HTTP/<port>/server -- already populated by the C engine's
-- own baseline service-detection probe (src/net/http_probe.c), so this
-- check needs no network access of its own and has no dependency on
-- http_headers.lua.

register{
    script_id      = 100036,
    script_name    = "HTTP Server Version Disclosed",
    script_version = "1.0.0",
    family         = "Web Servers",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Checks whether the HTTP Server response header discloses a specific " ..
                      "version number.",
    solution       = "Consider configuring the web server (or a reverse proxy in front of " ..
                      "it) to omit or generalize the Server header; this provides only " ..
                      "modest security-through-obscurity benefit.",
}

function run()
    local port = get_scan_port()
    local server = get_kb_item("HTTP/" .. port .. "/server")
    if not server then
        return
    end

    if not server:find("%d") then
        -- No digit at all (e.g. a bare "Apache" with no version) -- nothing versioned to
        -- disclose.
        return
    end

    local cpe = get_kb_item("CPE/" .. port)

    report_vuln{
        severity    = 0, -- Info
        title       = "HTTP Server Version Disclosed",
        description = "The web server on port " .. port .. " discloses its exact software " ..
                       "name/version in the HTTP Server response header. This is " ..
                       "informational: it lowers fingerprinting effort but is not itself a " ..
                       "vulnerability.",
        evidence    = "Server: " .. server,
        port        = port,
        cpe         = cpe,
    }
end
