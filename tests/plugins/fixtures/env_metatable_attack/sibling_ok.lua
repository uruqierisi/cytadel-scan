-- Sibling of attack.lua in this SAME directory: an entirely ordinary,
-- well-behaved plugin. Its successful registration and dispatch (see
-- tests/unit/test_plugin_r3c1_env_metatable_abort.c) proves the engine
-- keeps registering and scanning normally even with a malicious sibling
-- plugin file dropped into the same plugins directory.
register{
    script_id      = 978001,
    script_name    = "C1 Fixture -- Well-Behaved Sibling",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "An ordinary plugin that must keep working despite a malicious sibling.",
    solution       = "N/A -- test fixture.",
}

function run()
    report_vuln{
        severity = 0,
        title    = "C1 sibling check passed",
        evidence = "the engine kept registering/scanning after rejecting a malicious sibling plugin",
        port     = get_scan_port(),
    }
end
