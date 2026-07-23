-- plugins/ftp_cleartext_protocol.lua
--
-- Flags plain FTP (control channel, port 21) as an inherently unencrypted
-- protocol: commands and any credentials exchanged over it are sent in
-- cleartext unless the session is explicitly upgraded via AUTH TLS (FTPS).
-- This check does not attempt to negotiate AUTH TLS itself (that would
-- require initiating a real protocol exchange beyond passive detection);
-- it simply reports the exposure inherent to any plain FTP service found
-- listening, using whatever banner text is already on hand as evidence.
--
-- Dispatched via the "Services/ftp/*" wildcard (plugin-api.md §4.6), not
-- hard-coded to port 21: src/net/service_detect.c FTP-detects by
-- well-known port OR a case-insensitive "ftp" banner-text signature on any
-- port (src/net/svc_ftp.c writes Services/ftp/<port> for whatever port it
-- is actually found on), so a fixed "Services/ftp/21" gate would silently
-- miss an FTP daemon running elsewhere.

register{
    script_id      = 100002,
    script_name    = "FTP Service Uses Unencrypted Control Channel",
    script_version = "1.0.0",
    family         = "FTP",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ftp/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "FTP's control channel (and, for plain FTP, its data channel) is " ..
                      "unencrypted by default. Any credentials or file contents transferred " ..
                      "can be observed by a passive network position unless the session " ..
                      "explicitly negotiates FTPS (AUTH TLS).",
    solution       = "Disable plaintext FTP and migrate to SFTP or FTPS, or restrict port 21 " ..
                      "to trusted management networks only.",
}

function run()
    local port = get_scan_port()
    local banner = get_kb_item("FTP/" .. port .. "/banner") or get_kb_item("Banner/" .. port)
    local evidence
    if banner then
        evidence = "FTP banner on port " .. port .. ": " .. banner
    else
        evidence = "FTP service detected on port " .. port .. " (port/protocol signature; no " ..
                   "banner text captured)."
    end

    report_vuln{
        severity    = 1, -- Low
        title       = "FTP Service Uses Unencrypted Control Channel",
        description = "An FTP service was detected on port " .. port .. ". FTP transmits " ..
                       "commands and credentials in cleartext by default.",
        evidence    = evidence,
        port        = port,
    }
end
