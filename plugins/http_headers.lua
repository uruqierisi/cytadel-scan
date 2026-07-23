-- plugins/http_headers.lua
--
-- ACT_SETTINGS gathering plugin (kb-schema.md §7.6): issues a single
-- baseline GET / against each detected HTTP(S) port and records a fixed
-- allowlist of security-relevant response headers under
-- HTTP/<port>/headers/<name>, so downstream ACT_GATHER_INFO check plugins
-- (http_missing_*.lua, http_insecure_cookie_flags.lua) can read them
-- without each issuing their own duplicate request. Only a fixed allowlist
-- of header names is ever written (not every header the response happens
-- to send) -- this keeps every KB key this plugin ever writes within
-- kb-schema.md §2's segment charset (a handful of legal HTTP header names
-- use bytes outside that charset, e.g. bytes RFC 7230's tchar allows like
-- '!'/'#'/'$' -- none of the allowlisted names below use any of those, so
-- this is always safe).
--
-- On a SUCCESSFUL probe (a response was actually received), this also
-- writes a boolean sentinel, HTTP/<port>/headers/_probed = true. This is
-- NOT itself a tracked header (no real HTTP header is named "_probed"); it
-- exists so the http_missing_*.lua / http_insecure_cookie_flags.lua family
-- can tell "the header was absent from a response we actually saw" apart
-- from "we never got a response at all" (`dependencies = {100030}` is
-- ordering only, per plugin-api.md §4.1 -- it does not mean this plugin's
-- GET succeeded). Without this sentinel, a target that tarpits, rate-
-- limits, or drops this plugin's connection (e.g. after an earlier probe
-- already tripped an IPS) would cause every downstream "missing header"
-- check to fabricate a "no header observed" finding for an observation
-- that never happened -- see plugins/README.md's HTTP Headers section.
--
-- Reports no findings itself (ACT_SETTINGS, per plugin-api.md §1.3).

register{
    script_id      = 100030,
    script_name    = "HTTP Response Header Collection",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_SETTINGS",
    dependencies   = {},
    required_keys  = { "Services/www/*" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Info",
    description    = "Issues a baseline GET / request against each detected HTTP(S) port and " ..
                      "records a fixed set of security-relevant response headers into the KB " ..
                      "for downstream checks to consume.",
    solution       = "N/A -- this plugin only gathers data; it reports no findings.",
}

local TRACKED_HEADERS = {
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "set-cookie",
    "referrer-policy",
    "x-powered-by",
    "server",
}

function run()
    local port = get_scan_port()
    local use_tls = get_kb_item("TLS/" .. port .. "/enabled") == true

    local resp, err = http_get(port, "/", { method = "GET", timeout_ms = 4000, tls = use_tls })
    if not resp then
        log("debug", "http_headers: GET / failed on port " .. port .. ": " .. tostring(err))
        return
    end

    -- A response was actually received -- record the positive "we probed
    -- this port and observed a real reply" sentinel BEFORE writing any
    -- individual header key, so downstream checks can distinguish a
    -- confirmed-absent header from a probe that never completed.
    set_kb_item("HTTP/" .. port .. "/headers/_probed", true)

    -- Header VALUES are attacker-controlled. set_kb_item() RAISES on a
    -- value that is over-length (>4096 B, kb-schema.md §3), NUL-bearing, or
    -- invalid UTF-8; an uncaught raise here would unwind run() AFTER the
    -- _probed sentinel is already set, hiding every header after the hostile
    -- one and making the absence-based checks (http_missing_csp/xcto/xfo)
    -- report a header as "missing" when it was actually present. Sanitize
    -- each value in place -- strip NULs, clip to the KB limit -- so PRESENCE
    -- is still recorded (key written) and those checks stay silent; pcall is
    -- the final backstop so any residual rejection skips one key, never the
    -- rest of the loop.
    for _, name in ipairs(TRACKED_HEADERS) do
        local value = resp.headers[name]
        if value then
            value = value:gsub("\0", "")
            if #value > 4096 then
                value = value:sub(1, 4096)
            end
            pcall(set_kb_item, "HTTP/" .. port .. "/headers/" .. name, value)
        end
    end
end
