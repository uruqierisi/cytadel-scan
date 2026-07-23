-- A fully valid report_vuln{} call, including every optional field, to
-- confirm the happy path is collected correctly alongside the two
-- deliberately-invalid fixtures in this same directory.
register{
    script_id      = 995003,
    script_name    = "Fixture Valid Finding",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    risk_factor    = "High",
    description    = "Always reports one fully-populated finding.",
    solution       = "N/A -- test fixture.",
}

function run()
    report_vuln{
        severity    = 3,
        title       = "Fixture Valid Finding",
        description = "This finding always fires to exercise the happy path.",
        evidence    = "synthetic evidence",
        port        = 4321,
        solution    = "Override solution for this specific finding.",
        cve         = { "CVE-2024-0001", "CVE-2024-0002" },
        cpe         = "cpe:2.3:a:example:widget:1.0:*:*:*:*:*:*:*",
        cvss_vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
    }

    -- security_report is an exact alias of report_vuln (§2.9).
    security_report{
        severity = 0,
        title    = "Fixture Valid Finding via alias",
        evidence = "security_report alias check",
        port     = 0,
    }
end
