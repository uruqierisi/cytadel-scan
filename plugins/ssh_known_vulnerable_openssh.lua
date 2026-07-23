-- plugins/ssh_known_vulnerable_openssh.lua
--
-- Heuristic, banner-version-based check for OpenSSH release bands with
-- well-known associated CVEs. Banner-based version inference is inherently
-- imprecise: distributions routinely backport security fixes without
-- changing the advertised version string, so this check can both
-- false-positive (patched-but-old-looking banner) and false-negative
-- (custom/stripped banner). Both severities below are kept moderate and the
-- finding text says so explicitly, per this project's "quiet and right over
-- loud and wrong" policy for heuristic checks.
--
-- Dispatched via the "Services/ssh/*" wildcard (plugin-api.md §4.6), not
-- hard-coded to port 22: src/net/svc_ssh.c detects SSH by its unambiguous
-- "SSH-" banner prefix and writes Services/ssh/<port> for whatever port it
-- is actually found on (a common hardening convention runs SSH on a
-- non-default port), so a fixed "Services/ssh/22" gate would silently miss
-- every vulnerable-band daemon running elsewhere.

register{
    script_id      = 100011,
    script_name    = "OpenSSH Version In A Known-Vulnerable Range (Heuristic)",
    script_version = "1.0.0",
    family         = "SSH",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ssh/*" },
    cve            = { "CVE-2024-6387" },
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Parses the OpenSSH version reported in the SSH banner and flags it if " ..
                      "it falls within a small set of well-known vulnerable release bands. " ..
                      "This is a HEURISTIC, banner-text check only -- it does not confirm the " ..
                      "installed binary was never patched/backported.",
    solution       = "Upgrade OpenSSH to the latest release for your platform and confirm " ..
                      "your distribution has applied all relevant security backports.",
}

-- (a_major, a_minor) < (b_major, b_minor), lexicographic on (major, minor).
local function lt(a_major, a_minor, b_major, b_minor)
    return a_major < b_major or (a_major == b_major and a_minor < b_minor)
end

-- (a_major, a_minor) >= (b_major, b_minor).
local function ge(a_major, a_minor, b_major, b_minor)
    return not lt(a_major, a_minor, b_major, b_minor)
end

-- (a_major, a_minor) <= (b_major, b_minor).
local function le(a_major, a_minor, b_major, b_minor)
    return lt(a_major, a_minor, b_major, b_minor) or (a_major == b_major and a_minor == b_minor)
end

function run()
    local port = get_scan_port()
    local version = get_kb_item("SSH/" .. port .. "/version")
    if not version then
        log("debug", "no SSH/" .. port .. "/version recorded, not applicable")
        return
    end

    local major_s, minor_s = version:match("OpenSSH_(%d+)%.(%d+)")
    if not major_s then
        log("debug", "SSH version string did not match an OpenSSH_X.Y pattern, skipping " ..
                      "heuristic version check")
        return
    end
    local major, minor = tonumber(major_s), tonumber(minor_s)

    if lt(major, minor, 4, 4) then
        report_vuln{
            severity    = 2, -- Medium: same signal-handler race condition class as
                             -- CVE-2024-6387 -- versions below 4.4p1 were never patched for
                             -- the original CVE-2006-5051, which CVE-2024-6387's advisory
                             -- (Qualys) documents as reintroduced in 8.5-9.7. Banner-based
                             -- confirmation cannot establish the target's C library.
            title       = "OpenSSH Version Predates The CVE-2006-5051 Fix (regreSSHion-Class " ..
                           "Race Condition, Heuristic)",
            description = "The SSH banner reports OpenSSH " .. major .. "." .. minor ..
                           ", a release line that predates the fix for CVE-2006-5051, the " ..
                           "signal-handler race condition CVE-2024-6387 (regreSSHion) later " ..
                           "reintroduced in OpenSSH 8.5-9.7. This is a heuristic, banner-" ..
                           "based observation -- it cannot confirm the target's C library or " ..
                           "whether a distribution backport already applies a fix.",
            evidence    = version,
            port        = port,
            solution    = "Upgrade to a current, supported OpenSSH release.",
            cve         = { "CVE-2024-6387" },
        }
    elseif lt(major, minor, 6, 6) then
        report_vuln{
            severity    = 1, -- Low: generic "very old", no single pinned CVE.
            title       = "Outdated OpenSSH Version (Heuristic)",
            description = "The SSH banner reports OpenSSH " .. major .. "." .. minor ..
                           ", a release line old enough to predate many years of security " ..
                           "fixes. This is a heuristic, banner-based observation.",
            evidence    = version,
            port        = port,
            solution    = "Upgrade to a current, supported OpenSSH release.",
        }
    elseif ge(major, minor, 8, 5) and le(major, minor, 9, 7) then
        report_vuln{
            severity    = 2, -- Medium: real RCE (regreSSHion) but glibc/Linux-only and
                             -- banner-based confirmation cannot establish the target OS libc.
            title       = "OpenSSH Version In The regreSSHion (CVE-2024-6387) Band (Heuristic)",
            description = "The SSH banner reports OpenSSH " .. major .. "." .. minor ..
                           ", which falls in the 8.5-9.7 band affected by CVE-2024-6387 " ..
                           "(regreSSHion, a signal-handler race condition leading to remote " ..
                           "code execution) on glibc-based Linux systems. This is a " ..
                           "heuristic, banner-based observation -- it cannot confirm the " ..
                           "target's C library or whether a distribution backport already " ..
                           "applies the fix.",
            evidence    = version,
            port        = port,
            solution    = "Upgrade to OpenSSH 9.8 or later, or confirm your distribution has " ..
                           "backported the CVE-2024-6387 fix.",
            cve         = { "CVE-2024-6387" },
        }
    end
end
