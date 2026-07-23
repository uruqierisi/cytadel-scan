-- plugins/ftp_anonymous_banner_hint.lua
--
-- Detects whether an FTP server's own greeting banner explicitly mentions
-- "anonymous" access. This is a deliberately conservative, TEXT-ONLY check:
-- it never opens a control connection or attempts a USER/PASS exchange (no
-- login of any kind, anonymous or otherwise, is attempted). Some FTP
-- daemons are configured with a pre-login welcome banner that advertises
-- anonymous access policy; this only reports on the presence of that
-- advertisement, never on whether anonymous login would actually succeed.
--
-- False-positive note: most FTP daemons (vsftpd/ProFTPD defaults) do not
-- mention "anonymous" in their greeting at all, so this check fires rarely
-- and only on servers whose operator chose to advertise the policy in text.
--
-- Dispatched via the "Services/ftp/*" wildcard (plugin-api.md §4.6), not
-- hard-coded to port 21: src/net/service_detect.c FTP-detects by
-- well-known port OR a case-insensitive "ftp" banner-text signature on any
-- port (src/net/svc_ftp.c writes Services/ftp/<port> for whatever port it
-- is actually found on), so a fixed "Services/ftp/21" gate would silently
-- miss an FTP daemon running elsewhere.

register{
    script_id      = 100001,
    script_name    = "FTP Banner Advertises Anonymous Access",
    script_version = "1.0.0",
    family         = "FTP",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ftp/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Checks whether the FTP service's own greeting banner (captured by the " ..
                      "engine's service-detection stage before any plugin runs) explicitly " ..
                      "mentions 'anonymous'. This is a passive, banner-text-only observation " ..
                      "-- no login of any kind is attempted.",
    solution       = "If anonymous FTP access is not intentionally required, disable it and " ..
                      "remove any banner text advertising it.",
}

function run()
    local port = get_scan_port()
    local banner = get_kb_item("FTP/" .. port .. "/banner") or get_kb_item("Banner/" .. port)
    if not banner then
        log("debug", "no FTP banner recorded for port " .. port .. ", not applicable")
        return
    end

    if not banner:lower():find("anonymous", 1, true) then
        return
    end

    report_vuln{
        severity    = 0, -- Info: a text mention is not a confirmed capability.
        title       = "FTP Banner Advertises Anonymous Access",
        description = "The FTP greeting banner on port " .. port .. " explicitly mentions " ..
                       "'anonymous'. This may indicate the operator intentionally advertises " ..
                       "anonymous access. No login was attempted -- this does NOT confirm " ..
                       "anonymous access actually succeeds.",
        evidence    = banner,
        port        = port,
    }
end
