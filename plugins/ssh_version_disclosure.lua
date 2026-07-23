-- plugins/ssh_version_disclosure.lua
--
-- Purely informational: the SSH version-exchange banner discloses the exact
-- server software/version, which lowers attacker fingerprinting effort.
-- This is not itself a vulnerability -- most SSH daemons (including
-- OpenSSH) disclose this by default and there is limited practical benefit
-- to hiding it -- so this is reported at Info severity only.
--
-- Dispatched via the "Services/ssh/*" wildcard (plugin-api.md §4.6), not
-- hard-coded to port 22: src/net/svc_ssh.c detects SSH by its unambiguous
-- "SSH-" banner prefix and writes Services/ssh/<port> for whatever port it
-- is actually found on (a common hardening convention runs SSH on a
-- non-default port), so a fixed "Services/ssh/22" gate would silently miss
-- an SSH daemon running elsewhere.

register{
    script_id      = 100012,
    script_name    = "SSH Server Version Banner Disclosed",
    script_version = "1.0.0",
    family         = "SSH",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ssh/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Records the exact SSH server software/version string disclosed in the " ..
                      "protocol banner, for reporting/inventory purposes.",
    solution       = "No action required. If reducing fingerprintability is a goal, note " ..
                      "that most SSH servers (including OpenSSH) do not support suppressing " ..
                      "the version string, and doing so provides only marginal benefit.",
}

function run()
    local port = get_scan_port()
    local version = get_kb_item("SSH/" .. port .. "/version")
    if not version then
        return
    end

    report_vuln{
        severity    = 0, -- Info
        title       = "SSH Server Version Banner Disclosed",
        description = "The SSH server on port " .. port .. " discloses its exact software " ..
                       "and version in the protocol banner.",
        evidence    = version,
        port        = port,
    }
end
