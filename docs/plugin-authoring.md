# Writing a Cytadel Scan plugin

This is a practical, worked-example guide to writing a Lua detection plugin. It does not restate
the frozen contract — **`docs/contracts/plugin-api.md` is authoritative**; read it in full before
writing anything non-trivial, and treat every example below as illustrating that contract, not
replacing it. `docs/contracts/kb-schema.md` (also frozen) defines every KB key you can read.
`plugins/README.md` is the catalog of everything already shipped, including what was deliberately
**not** written and why — check it before starting a new plugin so you don't duplicate an existing
check or reinvent a deliberately-omitted one.

## The non-negotiable rule: detection only

A plugin inspects a version, banner, certificate field, or response header the target already
sends over a plain connection or a read-only HTTP `GET`/`HEAD`. It never authenticates, logs in,
writes data, or performs any state-changing request. This is not just a review convention — the
run-phase sandbox **structurally** has no primitive for it: there is no `http_post`, no raw socket,
no filesystem/process access (`plugin-api.md` §5). If a real-world check would require completing
a state-changing action (a real login, a crafted non-`GET`/`HEAD` request), either write a
narrower banner/config-only observation instead, or don't ship it — see `plugins/README.md`'s "Why
no live anonymous-login attempt" and "Deliberately omitted" sections for real examples of both
choices.

## The two-phase model

Every plugin file is loaded twice per scan lifecycle:

1. **Registration** (once per file, at scan startup, before any target is scanned): the engine
   executes your file's top level in a metadata-only sandbox. The **only** things a plugin file may
   do at its top level are: call `register{...}` exactly once, define local helper functions, and
   define a global `run()` function. No KB/socket/HTTP/`report_vuln` call is reachable here — doing
   so is a hard registration error, and a broken file is logged and skipped (it never aborts the
   scan for other plugins). After every file is attempted, the engine builds one fixed topological
   run order from every header's `dependencies` list.
2. **Run** (once per target, per plugin, in that fixed order — and once per matching port for a
   service-wildcard plugin, see below): your `run()` function is invoked in a fresh `lua_State`,
   this time with the full KB/socket/HTTP/log/`report_vuln` API available. `run()` reads facts,
   optionally does its own read-only socket/HTTP probe, and optionally calls `report_vuln{...}`.
   Letting `run()` return without calling `report_vuln` is the normal, expected "nothing to report"
   outcome — there is no separate "not applicable" function.

## The `register{...}` header

Every field is documented in `plugin-api.md` §1.2; the required ones are `script_id`,
`script_name`, `script_version`, `family`, `category` (`"ACT_SETTINGS"` or `"ACT_GATHER_INFO"`),
`risk_factor`, `description`, and `solution`. Pick a `script_id` in the `100000`–`199999` in-tree
range that doesn't collide with anything in `plugins/README.md`'s catalog tables (`900000+` is
reserved for local/custom plugins outside this tree).

```lua
register{
    script_id      = 100031,
    script_name    = "Missing HTTP Strict-Transport-Security (HSTS) Header",
    script_version = "1.0.0",
    family         = "HTTP Headers",
    category       = "ACT_GATHER_INFO",
    dependencies   = { 100030 },              -- ordering only, see below
    required_keys  = { "Services/https/*" },  -- gating, see below
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Low",
    description    = "Checks whether an HTTPS service returns a Strict-Transport-Security " ..
                      "response header instructing browsers to enforce HTTPS-only connections.",
    solution       = "Add a 'Strict-Transport-Security: max-age=63072000; includeSubDomains' " ..
                      "response header (only after confirming the site is fully served over " ..
                      "HTTPS).",
}
```

(This is the real header from `plugins/http_missing_hsts.lua`.)

`dependencies` vs. `required_keys` — these solve two different problems:

- **`dependencies`** (array of `script_id`s) is an *ordering* constraint: it guarantees the listed
  plugins were already attempted for this target before yours runs. Use it when you depend on an
  earlier `ACT_SETTINGS` plugin having populated a KB key — but it does **not** gate execution on
  that plugin actually having succeeded.
- **`required_keys`** is the *data-availability gate*: your plugin only runs if every listed KB key
  is satisfied. This is what actually skips your plugin when the relevant service isn't present.

## `required_keys`: exact key vs. service wildcard

Two grammatical forms only (`plugin-api.md` §4.6, frozen):

- **Exact key** — a literal KB key, e.g. `{ "Services/ftp/21" }`. Your plugin runs at most once per
  target, hard-codes the canonical port, and `get_scan_port()` returns `nil`. Use this for
  fixed-port protocols (SSH/FTP/Telnet-style).
- **Service wildcard** — exactly one `"Services/<svc>/*"` entry (`<svc>` from the frozen vocabulary
  in `kb-schema.md` §2: `www`, `https`, `ssh`, `ftp`, …). Your plugin is dispatched **once per
  matching `Services/<svc>/<port>` entry**, and reads the bound port via `get_scan_port()`. Use
  this for a check that should cover every port a service was found on (the `ssh`/`www`/`tls`/
  `http-header` families all use this today — e.g. `ssh_known_vulnerable_openssh.lua` gates on
  `"Services/ssh/*"` specifically so it still fires when SSH is hardened onto a non-default port).

No mid-path or suffix wildcards, no wildcard outside `Services/` — anything else is a registration
error.

## Reading KB facts

`get_kb_item(key)` returns the stored value, or `nil` if the key was never written for this host —
**always guard for `nil`, never treat it as `false`/`0`/empty**. Only read keys that
`kb-schema.md` §7 actually documents as written by some stage, and check the writing C code
(`src/net/*`) directly if you're not sure a key is populated in the case you care about.
`get_port_state(port)` is a convenience boolean for `Ports/tcp/<port> == 1` (open).

```lua
-- plugins/tls_cert_expired.lua (real, unmodified)
function run()
    local port = get_scan_port()
    if get_kb_item("TLS/" .. port .. "/enabled") ~= true then
        return
    end
    if get_kb_item("TLS/" .. port .. "/cert_expired") ~= true then
        return
    end

    local not_after = get_kb_item("TLS/" .. port .. "/not_after") or "(unknown)"
    local cn = get_kb_item("TLS/" .. port .. "/cn") or "(unknown)"

    report_vuln{
        severity    = 3, -- High
        title       = "TLS Certificate Expired",
        description = "The X.509 certificate presented on port " .. port .. " (CN=" .. cn ..
                       ") expired on " .. not_after .. ". Clients that correctly validate " ..
                       "certificates will reject connections to this service.",
        evidence    = "cn=" .. cn .. ", not_after=" .. not_after,
        port        = port,
    }
end
```

Notice the pattern: re-check the wildcard's own gating fact (`TLS/<port>/enabled`) before reading
anything else for that port, then guard the specific fact you care about, then build `evidence`
from real observed data only — never a fabricated value.

## Emitting a finding: `report_vuln{...}`

`severity` (0-4), `title`, `evidence`, and `port` are required; `description`, `solution`, `cve`,
`cpe`, and `cvss_vector` are optional (`solution`/`cvss_vector` fall back to the header's defaults
if omitted). A schema violation (missing required field, wrong type, `severity` outside `0..4`)
raises a Lua error immediately — this is intentionally fail-loud so a malformed call surfaces as a
plugin bug during development, not a silently dropped finding.

```lua
report_vuln{
    severity    = 2, -- Medium
    title       = "FTP Anonymous Login Enabled",
    evidence    = "230 Login successful.",
    port        = 21,
    solution    = "Disable anonymous FTP access.",
}
```

### Optional CPE hints

If your plugin can read a confident, already-resolved CPE string from the KB (`CPE/<port>`, written
by service detection or a protocol-specific plugin when the version was determined precisely
enough), pass it straight through as the `cpe` field so the C engine's CVE-matching stage can
enrich the finding. Don't build a CPE string yourself from a partial/heuristic guess — the CPE
matching authority is the engine (`docs/contracts/kb-schema.md` §7.7), not the plugin, and CVE
enrichment happens independently of whatever you pass here.

```lua
-- plugins/http_server_version_disclosure.lua (real, unmodified)
local cpe = get_kb_item("CPE/" .. port)

report_vuln{
    severity    = 0, -- Info
    title       = "HTTP Server Version Disclosed",
    description = "The web server on port " .. port .. " discloses its exact software " ..
                   "name/version in the HTTP Server response header.",
    evidence    = "Server: " .. server,
    port        = port,
    cpe         = cpe,   -- nil is fine; report_vuln treats an omitted/nil cpe as "no hint"
}
```

## Heuristics must say they're heuristics

Any check that infers a vulnerability from a banner-reported version string (rather than a
directly-observed config fact like a missing header or an expired cert) **must** say so
explicitly, in both the header's `description` and every `report_vuln` call's own `description`,
and must keep `severity` conservative rather than asserting a specific CVE with confidence a bare
banner string cannot support. `plugins/ssh_known_vulnerable_openssh.lua` is the canonical example —
every one of its three findings spells out "heuristic, banner-based observation... cannot confirm
the target's C library or whether a distribution backport already applies a fix" in the finding
text itself, and keeps severity at Low/Medium rather than treating the regreSSHion CVE as
confirmed. `plugins/http_known_vulnerable_server.lua` follows the same pattern for web-server
version bands. See `plugins/README.md`'s "Severity rationale" section for the project's full
severity-by-evidence-quality policy.

## Logging

Use `log(level, message)` (`"debug"`, `"info"`, `"warn"`, or `"error"`) — there is no `print` in
the run-phase sandbox, so all plugin output is structured and attributable. Use `"debug"` for
routine "not applicable to this target" branches; reserve `"warn"`/`"error"` for genuinely
unexpected conditions.

## Testing a new plugin

1. Add a positive case, a negative case, and at least one malformed/hostile-input case to
   `tests/unit/test_plugins_stock.c` (pure KB-driven cases) or
   `tests/unit/test_plugins_stock_network.c` (only if your plugin issues a live `http_get`/socket
   call — follow the existing loopback-fixture-server pattern in that file).
2. Update `plugins/README.md`'s catalog table (and, if relevant, its "Deliberately omitted"
   section) so the plugin inventory stays accurate.
3. Build and run the unit test suite (`ctest --test-dir build -L unit --output-on-failure`) — see
   the top-level `README.md` for the full build instructions.

## Checklist before you ship a plugin

- [ ] Read `docs/contracts/plugin-api.md` and `docs/contracts/kb-schema.md` in full, not just this
      guide.
- [ ] `script_id` is unique and in the correct numeric range.
- [ ] `required_keys` uses the right form (exact key vs. `Services/<svc>/*` wildcard) for your
      protocol.
- [ ] Every `get_kb_item` read is guarded for `nil` — you checked the writing C code, not just
      assumed a key exists.
- [ ] `evidence` is always real observed data, never fabricated.
- [ ] If this is a heuristic, both the header and every `report_vuln` call say so, and severity is
      conservative.
- [ ] `severity`/`solution`/`cve`/`cpe` reflect this specific finding, not just copy-pasted header
      defaults where a narrower value is available.
- [ ] Nothing here performs (or could perform) a state-changing action against the target.
- [ ] Tests added (positive, negative, malformed input), `plugins/README.md` updated.
