-- Directly (unwrapped) attempts os.execute(): since 'os' is nil in the
-- run-phase sandbox, indexing it raises "attempt to index a nil value",
-- which run() does not catch -- this invocation must be marked FAILED
-- (never crash the engine, never silently succeed).
register{
    script_id      = 950002,
    script_name    = "Fixture Call os.execute",
    script_version = "1.0.0",
    family         = "Test",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Proves os.execute is unreachable (calling it raises, caught as FAILED).",
    solution       = "N/A -- test fixture.",
}

function run()
    os.execute("true")
end
