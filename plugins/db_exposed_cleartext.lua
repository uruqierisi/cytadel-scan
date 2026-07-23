-- plugins/db_exposed_cleartext.lua
--
-- Flags well-known database ports reachable on the network. This is a
-- pure exposure/attack-surface observation: it only confirms the service
-- is reachable via its conventional port/protocol signature -- it does
-- NOT attempt authentication and cannot determine from a port/banner
-- signature alone whether the deployment requires TLS for client
-- connections, so severity is kept at Low and the finding text says so
-- explicitly.
--
-- required_keys is intentionally empty: this plugin checks several
-- independent, unrelated services with OR semantics (any one of
-- MySQL/PostgreSQL/Redis being present is independently reportable), which
-- required_keys' AND-only gating (plugin-api.md §4.6) cannot express in a
-- single declarative gate -- so this plugin gates itself internally instead.

register{
    script_id      = 100041,
    script_name    = "Database Service Exposed On Its Conventional Port",
    script_version = "1.0.0",
    family         = "General",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = {},
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether a well-known database service (MySQL, PostgreSQL, " ..
                      "Redis) is reachable on its conventional port. Confirms exposure only " ..
                      "-- does not attempt authentication or determine TLS requirements.",
    solution       = "Ensure database services are not reachable from untrusted networks " ..
                      "(firewall/security-group rules), require strong authentication, and " ..
                      "enable TLS for client connections where supported.",
}

local DB_SERVICES = {
    { token = "mysql",      port = 3306, label = "MySQL" },
    { token = "postgresql", port = 5432, label = "PostgreSQL" },
    { token = "redis",      port = 6379, label = "Redis" },
}

function run()
    for _, db in ipairs(DB_SERVICES) do
        local present = get_kb_item("Services/" .. db.token .. "/" .. db.port)
        if present then
            local banner = get_kb_item("Banner/" .. db.port)
            local evidence
            if banner then
                evidence = "Banner/" .. db.port .. ": " .. banner
            else
                evidence = "Services/" .. db.token .. "/" .. db.port .. " detected " ..
                           "(port/protocol signature)."
            end

            report_vuln{
                severity    = 1, -- Low
                title       = db.label .. " Database Port Exposed",
                description = "A " .. db.label .. " database service was detected listening " ..
                               "on port " .. db.port .. ". This check only confirms the " ..
                               "service is reachable; it does not test authentication or TLS.",
                evidence    = evidence,
                port        = db.port,
            }
        end
    end
end
