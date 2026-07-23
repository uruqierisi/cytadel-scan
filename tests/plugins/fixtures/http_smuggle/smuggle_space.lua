-- Milestone 5 security-audit finding C1 regression: a path containing a
-- bare space is not a well-formed request target and would break the
-- "METHOD SP path SP HTTP-version" request-line grammar -- must also be
-- rejected before any request bytes reach the wire.
--
-- Deliberately NOT wrapped in pcall() -- see smuggle_crlf.lua's comment.
register{
    script_id      = 973002,
    script_name    = "C1 Fixture -- Space-Containing Path Rejected",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Attempts an http_get() with a bare space in the path.",
    solution       = "N/A -- test fixture.",
}

function run()
    local port = get_scan_port()
    http_get(port, "/a b", { timeout_ms = 2000 })
end
