register{
    script_id      = 950003,
    script_name    = "Fixture Call io.open",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Proves io.open is unreachable (calling it raises, caught as FAILED).",
    solution       = "N/A -- test fixture.",
}

function run()
    io.open("/etc/passwd", "r")
end
