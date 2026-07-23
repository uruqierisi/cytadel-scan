# Cytadel Scan — Lua Plugin API Contract

**Status: FROZEN.** This document is a Milestone 0 design contract. Once implementation
begins (Milestone 6 and the C engine work that supports it), nothing in this file changes
without an explicit stop-and-ask, per the project's engineering policy. New *additive* functions/fields may be
proposed later as a new, separately-versioned appendix — they must never silently alter the
meaning of anything specified here.

Target runtime: **Lua 5.4**, embedded in the C11 engine (`liblua`, static or vendored, no
external `require` of system Lua). All semantics below are verified against the Lua 5.4
reference manual, not assumed from 5.1/5.3 behavior. Where a 5.4-specific mechanism matters
(`_ENV` upvalues, to-be-closed variables, `lua_close` finalizer guarantees, integer subtype),
it is called out explicitly because the C engine implementation depends on getting it exactly
right.

## 0. Shared design canon (must agree with `kb-schema.md` and the DB schema contract)

- Severity scale, used everywhere a numeric severity appears: `Info=0, Low=1, Medium=2,
  High=3, Critical=4`.
- The KB (`kb-schema.md`) is an in-memory, per-scan-target key/value store. Keys are strings
  such as `Ports/tcp/80`, `Services/ssh/22`, `HostDetails/os`, `Banner/22`, `SSH/22/version`,
  `HTTP/80/server`, `TLS/443/cert_expired`. Values are tagged `string | integer | boolean`.
  Absent key → `nil` when read from Lua. This contract does not redefine KB keys; it only
  defines how Lua reads/writes them.
- Plugins are **detection only**. There is no primitive in this API for authentication
  bypass, payload delivery, command execution, file write on the target, or any state-changing
  operation beyond a plain TCP connect / a read-only HTTP `GET`/`HEAD`. `http_get` deliberately
  has no `http_post`/`http_put`/`http_delete` sibling in this contract.
- A finding's `cpe`/`cve` fields are optional hints supplied by the plugin; the C engine (not
  the plugin) is the authority that matches detected service+version against the vulnerability
  DB via CPE and enriches the finding. A plugin that omits `cpe`/`cve` still produces a valid,
  reportable finding based on its own `severity`.

---

## 1. Plugin metadata header schema

### 1.1 Chosen form: a `register{ ... }` call

A plugin file is a single Lua chunk. Its **only** top-level statements must be:

1. Exactly one call to the engine-provided function `register{ ... }`, passing a single
   table literal (NASL-equivalent metadata header).
2. Local helper function definitions (optional).
3. Exactly one definition of a global function `run()` (the entry point invoked in the run
   phase — see §3).

No other top-level statements are permitted (no I/O, no socket calls, no KB access at top
level). This is enforced structurally: the metadata-phase sandbox (§4.2) does not expose
`get_kb_item`, `open_sock_tcp`, `report_vuln`, etc. at all, so any attempt to call them outside
`run()` fails loudly with "attempt to call a nil value" and the plugin is rejected at
registration time rather than misbehaving at scan time.

`register` is a rejected-form choice against the alternative ("return a metadata table"):
`register{...}` is chosen because (a) it reads like the NASL header idiom this project's
authors already know, (b) it lets the engine validate and capture the header via a C function
with `luaL_check*` calls at the exact point of declaration, and (c) it cleanly separates
"header data" from "the value the chunk returns," so the chunk's return value stays unused and
reserved.

### 1.2 Field reference

| Field           | Lua type                          | Required | Semantics |
|-----------------|------------------------------------|----------|-----------|
| `script_id`     | integer                            | yes | Globally unique across all loaded plugin files. Engine rejects a file whose `script_id` collides with an already-registered plugin (that later file is skipped, logged, scan continues). Convention (non-normative): `100000-199999` reserved for in-tree checks, `900000+` for local/custom plugins. |
| `script_name`   | string                             | yes | Short human-readable name, e.g. `"FTP Anonymous Login Enabled"`. Non-empty. |
| `script_version`| string                             | yes | Free-form version of the *check itself* (e.g. `"1.0.0"`), not of the target software. Non-empty. |
| `family`        | string                             | yes | Grouping used in catalog/report views, e.g. `"FTP"`, `"SSH"`, `"Web Servers"`, `"TLS"`, `"General"`. Free string; unrecognized values are bucketed under `"General"` for display but still stored verbatim. |
| `category`      | string enum                        | yes | One of `"ACT_SETTINGS"`, `"ACT_GATHER_INFO"` (see §1.3). Detection-only categories — there is no attack/exploit category in this enum and there never will be. |
| `dependencies`  | array of integers (`script_id`s)   | no, default `{}` | Plugins that must be *scheduled and attempted before* this one for the same target. Ordering constraint only — see §4.1 for the distinction between `dependencies` and `required_keys`. |
| `required_keys` | array of strings (KB key patterns) | no, default `{}` | KB key patterns that must all be satisfied for this target before `run()` is invoked. Two grammatical forms are legal (full grammar + dispatch semantics in §4.6): an **exact key** (default, e.g. `{"Services/ftp/21"}` or `{"HostDetails/os"}`) and a **service wildcard** `"Services/<svc>/*"` (e.g. `{"Services/www/*"}`) that triggers per-service dispatch. If a required key is unsatisfied, the plugin is skipped for that target (not an error). |
| `cve`           | array of strings                   | no, default `{}` | CVE IDs this check is generally associated with, for catalog/documentation purposes. A specific `report_vuln` call may supply a different/narrower `cve` list for the actual finding (see §2). |
| `cvss_vector`   | string or `nil`                    | no | CVSS vector string (e.g. `"CVSS:3.1/AV:N/AC:L/..."`) for catalog display. Not validated for CVSS syntax by this contract; the DB-schema layer owns CVSS parsing. |
| `risk_factor`   | string enum                        | yes | One of `"Info"`, `"Low"`, `"Medium"`, `"High"`, `"Critical"` (must match the canon severity names exactly, case-sensitive). This is the **default/catalog** severity shown before the plugin has ever run against a target — the authoritative *actual* severity of a given finding is the `severity` integer passed to `report_vuln` at run time, which may legitimately differ per target. |
| `description`   | string                             | yes | Human-readable explanation of what the check inspects and why it matters. Non-empty. |
| `solution`      | string                             | yes | Default remediation guidance, used if a specific `report_vuln` call does not override `solution`. Non-empty. |

Validation happens entirely inside the C implementation of `register` at registration time
(`luaL_error` on any violation, aborting only that plugin file's load — see §4.1).

### 1.3 `category` enum (detection-only, append-only)

| Value | Meaning |
|---|---|
| `ACT_SETTINGS` | Gathers/records a fact into the KB (banner capture, version parse, config read) without itself rendering a severity judgement. Conventionally has no `dependencies` and is depended on by `ACT_GATHER_INFO` plugins. |
| `ACT_GATHER_INFO` | Inspects a service/banner/certificate/header/config value and may call `report_vuln` with a finding. This is the category almost all checks use. |

This enum may only be **appended to** in a future milestone (e.g. a later `ACT_END` for
rollup/summary plugins); existing values are never repurposed, and no attack/exploit category
(`ACT_ATTACK`, `ACT_DENIAL`, `ACT_KILL_HOST`, etc., as NASL has) is ever added — that would
violate the non-negotiable detection-only rule in the project's engineering policy. `category` is pure
classification metadata; it does not affect scheduling (`dependencies` does that).

### 1.4 Full example header

```lua
register{
    script_id      = 100001,
    script_name    = "FTP Anonymous Login Enabled",
    script_version = "1.0.0",
    family         = "FTP",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ftp/21" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks whether the FTP service on port 21 accepts an anonymous " ..
                      "login (USER anonymous / PASS <email>).",
    solution       = "Disable anonymous FTP access unless it is explicitly required, " ..
                      "and if required, restrict it to a read-only, non-sensitive " ..
                      "directory tree.",
}
```

---

## 2. C-backed API functions exposed to plugins

All functions below are only present in the **run-phase** sandbox (§4.2), i.e. only reachable
from inside `run()` and functions it calls. They are ordinary Lua globals in that sandbox
(there is no `cytadel.` namespace table — flat globals, matching the flat NASL-style idiom
used for `register`).

### 2.1 `get_kb_item(key)`

- **Args:** `key: string`
- **Returns:** `string | integer | boolean` if the key exists, else `nil`. No second error
  return — a missing key is a normal, expected outcome, not a failure.
- **Type mapping:** the KB stores a tagged value; the engine pushes it as
  `lua_pushlstring`/`lua_pushinteger`/`lua_pushboolean` to match the tag exactly. A plugin
  must not assume a particular type without checking — use `type(v)` when a key could
  legitimately hold more than one shape (rare; most keys have one fixed type documented in
  `kb-schema.md`).
- **Example:** `local os = get_kb_item("HostDetails/os")` → `"Linux"` or `nil`.

### 2.2 `set_kb_item(key, value)`

- **Args:** `key: string`, `value: string | integer | boolean`
- **Returns:** nothing (no success/failure boolean — reconciled with `kb-schema.md`, which
  originally assumed a boolean return; this contract owns the signature and is authoritative).
- Fail-loud on any validation failure — a Lua error is raised (`luaL_error`) and the value is
  **not** stored (reject, never truncate), for:
  - a `value` of any other Lua type (`table`, `function`, `nil`, `userdata`);
  - a syntactically invalid key or a key longer than 255 bytes (`kb-schema.md` §2);
  - a string `value` longer than 4096 bytes (`CYTADEL_KB_VALUE_MAX_LEN`, `kb-schema.md` §3).
  This is deliberate: a silently dropped fact could cause a false negative in later CVE
  matching, so the plugin author learns about it immediately as a bug.
- Writes are immediate and synchronous against the in-memory KB — there is no transaction/
  rollback if the plugin later errors (see §4.3).
- **Example:** `set_kb_item("FTP/21/anonymous_login", true)`

### 2.2a `get_scan_port()`

- **Args:** none.
- **Returns:** `integer` — the port this invocation is **bound** to, when the plugin was
  scheduled via a `Services/<svc>/*` service-wildcard `required_keys` entry (per-service
  dispatch, §4.6). Returns `nil` for an ordinary exact-key plugin that was not dispatched
  per-service.
- This is how a per-service plugin (the `www`/`tls`/`http-header` family) learns which port
  the current run targets, instead of hard-coding a canonical port the way an exact-key plugin
  (e.g. FTP on 21) does. Additive to the API and invisible to exact-key plugins.
- **Example:** `local port = get_scan_port()  -- e.g. 80 on one run, 443 on the next`

### 2.3 `get_port_state(port)`

- **Args:** `port: integer`
- **Returns:** `boolean`, always (never `nil`). `true` iff the port is **open** — i.e.
  `get_kb_item("Ports/tcp/" .. port) == 1` (the `open` value of the `Ports/tcp/<port>` int
  enum in `kb-schema.md` §7.2, where `0=closed, 1=open, 2=filtered`). `closed`/`filtered`/absent
  all yield `false`.
  - *Contract reconciliation (Milestone 5):* an earlier draft described this as equivalent to
    `get_kb_item(...) == true`, which contradicted the frozen `int` typing of that KB key
    (`kb-schema.md` §7.2 is authoritative on the type). Corrected to the open-state comparison,
    the only reading consistent with both documents and this section's own example. No behavior
    a plugin author would have relied on changes — the function still returns a boolean "is this
    port open".
- **Example:** `if not get_port_state(21) then return end`

### 2.4 `open_sock_tcp(port [, timeout_ms])`

- **Args:** `port: integer`, `timeout_ms: integer` (optional, default `5000`) — applies to the
  connect step.
- **Returns:** on success, a socket **userdata** with metatable `"cytadel.socket"`; on
  failure, `nil, err` where `err` is one of `"timeout"`, `"refused"`, `"unreachable"`, or a
  short OS-level description string.
- Plain TCP connect only — no TLS negotiation here (TLS inspection, where needed, is done via
  `http_get{ tls = true }` for HTTP-over-TLS; there is no general-purpose raw TLS socket in
  this contract because it is not needed for detection-only banner work in Milestone 0-6 scope
  and would expand the sandboxed C surface unnecessarily — YAGNI).
- **5.4 note:** the socket userdata's metatable defines both `__gc` (best-effort finalizer)
  and `__close`, so plugin authors may — and are encouraged to — write
  `local sock <close> = open_sock_tcp(port)` to get deterministic cleanup on early `return`
  or on error, per Lua 5.4's to-be-closed variables (§3.3.8 of the reference manual). Explicit
  `close_sock(sock)` remains the primary, recommended pattern; `<close>` is a safety net.
- **Example:** `local sock, err = open_sock_tcp(21, 3000)`

### 2.5 `send(sock, data)`

- **Args:** `sock:` socket userdata, `data: string`
- **Returns:** `integer` bytes sent on success, or `nil, err` on failure (`"closed"`,
  `"timeout"`, `"reset"`, or a short description).
- No partial-send-with-error dual return — either all of `data` was written and the byte
  count is returned, or it wasn't and you get `nil, err`. Keeps the plugin-author contract
  simple.
- **Example:** `send(sock, "USER anonymous\r\n")`

### 2.6 `recv(sock, max_len [, timeout_ms])`

- **Args:** `sock:` socket userdata, `max_len: integer` (hard cap on bytes read in this call),
  `timeout_ms: integer` (optional, default `5000`)
- **Returns:** `string` (1 or more bytes) on success; `nil, "timeout"` if no data arrived in
  time; `nil, "closed"` on an orderly remote close / EOF; `nil, err` for other errors. There is
  no "returns empty string" case — empty reads are always represented as `nil, "closed"`.
- **Example:** `local line, err = recv(sock, 512, 3000)`

### 2.7 `close_sock(sock)`

- **Args:** `sock:` socket userdata
- **Returns:** nothing.
- Idempotent: closing an already-closed socket is a silent no-op, never an error. This is the
  primary, recommended way to release a socket; see §2.4 for the `<close>` safety-net
  behavior and §4.4 for the guarantee that any socket left open when the plugin's `lua_State`
  is torn down is force-closed by the engine regardless.

### 2.8 `http_get(port, path [, opts])`

- **Args:**
  - `port: integer`
  - `path: string` (e.g. `"/"`, `"/robots.txt"`)
  - `opts: table`, optional, fields all optional:
    - `method: string` — `"GET"` (default) or `"HEAD"`. No other verbs are supported by this
      contract (detection-only — no `POST`/`PUT`/`DELETE`, deliberately, to avoid any
      state-changing request against the target).
    - `headers: table<string,string>` — extra request headers to send.
    - `timeout_ms: integer` — default `5000`.
    - `tls: boolean` — default `false`. `true` wraps the connection in TLS before issuing the
      request (for `https`-style probing on the given port, e.g. 443/8443).
- **Returns:** on success, a table `{ status = integer, headers = table<string,string>, body =
  string }`. `headers` keys are lower-cased; if the response repeats a header name, values are
  joined with `", "` per HTTP semantics. `body` is capped at **1,048,576 bytes (1 MiB)** —
  bodies larger than that are truncated to the cap; this is a fixed, documented limit for
  Milestone 0-6 scope, not a plugin-configurable option. On failure, `nil, err` (`"timeout"`,
  `"refused"`, `"unreachable"`, `"tls_error"`, or a short description).
- **Example:** `local resp, err = http_get(80, "/", { timeout_ms = 3000 })`

### 2.9 `report_vuln(finding)` / `security_report(finding)`

These are **exact aliases** — the same C function is registered under both Lua global names.
There is no separate positional-argument (`security_report(port, severity, description, ...)`)
form; NASL-style positional calling is intentionally not offered, to avoid maintaining two
divergent argument-parsing/validation paths for one frozen entry point. `security_report`
exists purely for naming familiarity with NASL-derived expectations; new plugins should prefer
`report_vuln` in this project's own code for clarity.

- **Args:** a single table `finding` with fields:

  | Field | Type | Required | Semantics |
  |---|---|---|---|
  | `severity` | integer 0-4 | yes | Authoritative severity of *this* finding (canon scale). May differ from the plugin header's `risk_factor` default. |
  | `title` | string | yes | Short finding title. |
  | `description` | string | no | Human-readable detail of what was observed. |
  | `evidence` | string | yes | Raw proof — banner text, response snippet, header value — that justifies the finding. Never a crafted exploit payload/response. |
  | `port` | integer | yes | Port the finding relates to; use `0` for a host-level finding not tied to a specific port. |
  | `solution` | string | no | Overrides the header's default `solution` for this specific finding; if omitted, the engine falls back to the plugin header's `solution`. |
  | `cve` | array of strings | no, default `{}` | CVE IDs for this specific finding (may differ from/narrow the header's `cve`). |
  | `cpe` | string | no | CPE URI/string identifying the detected product+version, so the C engine can perform CVE enrichment via the vuln DB. |
  | `cvss_vector` | string | no | Overrides the header's default for this finding. |

- **Returns:** nothing on success. Raises a Lua error (`luaL_error`) on schema violation
  (missing required field, `severity` out of `0..4`, wrong Lua type for any field) —
  deliberately fail-loud so a malformed `report_vuln` call surfaces as a plugin-development
  bug immediately rather than silently dropping a finding.
- **Example:**

  ```lua
  report_vuln{
      severity    = 2,
      title       = "FTP Anonymous Login Enabled",
      evidence    = "230 Login successful.",
      port        = 21,
      solution    = "Disable anonymous FTP access.",
  }
  ```

### 2.10 `log(level, message)`

- **Args:** `level: string` — one of `"debug"`, `"info"`, `"warn"`, `"error"`; `message:
  string`.
- **Returns:** nothing. An unrecognized `level` raises a Lua error (fail loud on a
  plugin-author typo rather than silently downgrading the log level).
- All plugin output goes through this function — there is no `print` in the run-phase sandbox
  (see §5), so log output is always structured and attributable to a specific plugin/target by
  the engine's own logger (`src/log`).
- **Example:** `log("debug", "banner did not match expected FTP greeting, skipping")`

### 2.11 Signaling "not applicable" / "done"

There is **no dedicated function** for this. A plugin signals "nothing to report for this
target" simply by letting `run()` return normally without having called `report_vuln`. This is
the expected, common-case outcome for most invocations (most targets won't be vulnerable to
most checks). Conventionally, a plugin does an early guard-and-return:

```lua
function run()
    local banner = get_kb_item("Banner/21")
    if not banner or not banner:match("^220") then
        log("debug", "no FTP 220 banner observed, not applicable")
        return
    end
    -- ... continue checking
end
```

`run()`'s return value, if any, is ignored by the engine — only whether `lua_pcall` reported an
error is examined (§4.3). `run()` must not return anything meaningful; the engine invokes it
expecting zero results.

---

## 3. Complete example plugin

This is the authoring pattern all Milestone 6 plugins follow. It is runnable as written against
the API defined above (module logic only — see §4 for exactly how the engine loads/executes
it).

```lua
-- plugins/ftp_anonymous_login.lua
--
-- Detects whether the FTP service on port 21 accepts an anonymous login.
-- Detection only: attempts a standard anonymous credential pair and observes
-- the server's own response code. No file transfer, no directory listing,
-- no write attempt is performed.

register{
    script_id      = 100001,
    script_name    = "FTP Anonymous Login Enabled",
    script_version = "1.0.0",
    family         = "FTP",
    category       = "ACT_GATHER_INFO",
    dependencies   = {},
    required_keys  = { "Services/ftp/21" },
    cve            = {},
    cvss_vector    = nil,
    risk_factor    = "Medium",
    description    = "Checks whether the FTP service listening on port 21 accepts an " ..
                      "anonymous login (USER anonymous / PASS <email>). Anonymous FTP " ..
                      "access can expose files or server information unintentionally.",
    solution       = "Disable anonymous FTP access unless it is explicitly required. " ..
                      "If required, restrict it to a read-only, non-sensitive directory.",
}

-- Reads one line ("...\r\n"-terminated or EOF/timeout-bounded) from an FTP
-- control connection. FTP replies are short; 512 bytes is generous headroom.
local function read_reply(sock)
    local line, err = recv(sock, 512, 4000)
    if not line then
        return nil, err
    end
    return line
end

function run()
    local port = 21

    -- required_keys already guarantees Services/ftp/21 is set, but the banner
    -- itself is optional context recorded by an earlier service-ID stage.
    local banner = get_kb_item("Banner/" .. port)
    if banner then
        log("debug", "FTP banner: " .. banner)
    end

    local sock, err = open_sock_tcp(port, 3000)
    if not sock then
        log("debug", "could not connect to FTP on port " .. port .. ": " .. tostring(err))
        return
    end

    -- <close> is a safety net; we still close explicitly on every path below.
    local greeting = read_reply(sock)
    if not greeting or not greeting:match("^220") then
        log("debug", "no FTP 220 greeting observed, not applicable")
        close_sock(sock)
        return
    end

    local sent, serr = send(sock, "USER anonymous\r\n")
    if not sent then
        log("debug", "failed to send USER command: " .. tostring(serr))
        close_sock(sock)
        return
    end

    local user_reply, uerr = read_reply(sock)
    if not user_reply then
        log("debug", "no reply to USER command: " .. tostring(uerr))
        close_sock(sock)
        return
    end

    -- 331 = username OK, need password. Some servers grant access at 230 directly.
    local evidence = greeting .. user_reply
    local logged_in = false

    if user_reply:match("^331") then
        send(sock, "PASS anonymous@example.com\r\n")
        local pass_reply = read_reply(sock)
        if pass_reply then
            evidence = evidence .. pass_reply
            logged_in = pass_reply:match("^230") ~= nil
        end
    elseif user_reply:match("^230") then
        logged_in = true
    end

    send(sock, "QUIT\r\n")
    close_sock(sock)

    if not logged_in then
        log("debug", "anonymous FTP login rejected")
        return
    end

    set_kb_item("FTP/21/anonymous_login", true)

    report_vuln{
        severity    = 2, -- Medium
        title       = "FTP Anonymous Login Enabled",
        description = "The FTP service on port " .. port .. " accepted an anonymous " ..
                       "login (USER anonymous / PASS anonymous@example.com).",
        evidence    = evidence,
        port        = port,
        solution    = "Disable anonymous FTP access unless it is explicitly required.",
        cve         = {},
    }
end
```

---

## 4. Execution model & sandboxing

### 4.1 Registration phase (once per plugin file, at scan startup — not per target)

For every `*.lua` file under `plugins/`:

1. Engine creates a fresh `lua_State` via `luaL_newstate()`.
2. Engine builds a **metadata-phase sandbox** table (§4.2) containing only: the vetted subset
   of the base library, `string`, `table`, `math`, and the single engine function `register`.
   No KB/socket/report/log functions exist in this sandbox — calling one is a hard, immediate
   Lua error.
3. Engine calls `luaL_loadfile(L, path)`, then rebinds the loaded chunk's `_ENV` upvalue to the
   sandbox table (see §5.2 — this step is mandatory and easy to get wrong; skipping it leaves
   the chunk running against the real global table).
4. Engine calls `lua_pcall(L, 0, 0, msgh)` with a message handler that wraps the error via
   `luaL_traceback` for logging. This single call executes the whole chunk top to bottom: the
   `register{...}` call (captured into a C-side struct — table field, not Lua value, so it
   outlives this `lua_State`) and the definition (not invocation) of the global `run` function.
5. After the call returns successfully, the engine additionally checks that a global `run`
   function was defined in the sandbox table (`lua_getfield` + `lua_isfunction`); if not, this
   is a registration error.
6. `lua_close(L)` unconditionally (success or failure path).
7. On any failure in steps 3-5 (compile error, `register` validation error via `luaL_error`,
   duplicate `script_id`, missing `run`), the engine logs the error, **discards this one
   plugin file**, and continues loading the rest. A broken plugin never aborts the scan.

Once every file is registered, the engine builds a dependency graph from each header's
`dependencies` list (referencing other `script_id`s), validates that every referenced
`script_id` actually exists, detects cycles (a cycle is a hard startup error naming the
plugins involved), and produces one fixed topological run order shared by all targets in the
scan.

**`dependencies` vs. `required_keys`:** `dependencies` is an *ordering* constraint only — it
guarantees the listed plugins were already attempted (run or skipped) for this target before
this one starts, which matters when an earlier `ACT_SETTINGS` plugin is expected to populate
KB keys this plugin reads. It does **not** gate execution on the dependency having actually
produced a finding. `required_keys` is the *data-availability gate*: it directly checks KB
contents, independent of which plugin (if any) wrote them.

### 4.2 Run phase (once per target, per plugin, only if gating passes)

For each target, walking plugins in the fixed topological order from §4.1:

1. Check `required_keys` (grammar and dispatch in §4.6). For an exact-key plugin: every key
   must satisfy `get_kb_item(key) ~= nil` against this target's KB; if any is missing, skip
   this plugin for this target — log at `debug`, no `lua_State` is even created (cheap
   short-circuit). For a service-wildcard plugin: the scheduler enumerates the matching
   `Services/<svc>/<port>` KB entries and produces **one (plugin, target, port) invocation per
   matching port**; a target with no matching service is skipped. Each such invocation then
   runs steps 2-6 below with its bound port exposed via `get_scan_port()` (§2.2a).
2. Otherwise, create a **fresh** `lua_State` for this one (plugin, target) invocation. Fresh
   per invocation, not reused/pooled — this keeps failure/resource cleanup trivial (§4.4) and
   guarantees no state leaks between targets or between plugins. Isolation is prioritized over
   the small extra interpreter-startup cost, consistent with KISS for Milestone 0-6 scope.
3. Build the **run-phase sandbox** (§4.2 functions in §2, plus base/`string`/`table`/`math`,
   plus a harmless no-op `register` so the chunk's top-level `register{...}` call doesn't error
   out the second time it's executed).
4. `luaL_loadfile` + rebind `_ENV` (identical mechanism to §4.1 step 3) + `lua_pcall(L, 0, 0,
   msgh)` to execute the chunk (defines `run` again, harmlessly re-registers).
5. `lua_getglobal(L, "run")`, then `lua_pcall(L, 0, 0, msgh)` to invoke it, with a max-runtime
   guard installed first (§4.5).
6. Regardless of the result of step 5, `lua_close(L)` unconditionally.

### 4.3 Error handling across the C boundary

- The engine **never** uses `lua_call` for plugin code — always `lua_pcall`, with a message
  handler (`msgh`) that captures a traceback via `luaL_traceback(L, L, msg, 1)` for
  development-mode logging.
- Because a plugin can raise a non-string error object (`error({...})`), the engine converts
  whatever is on the stack after a failed `lua_pcall` with `luaL_tolstring` before logging —
  never assumes the error value is a string.
- On failure at any point in §4.1 or §4.2, the engine logs `plugin <script_id> <script_name>
  failed: <message>` at `error` level, marks that (plugin, target) as `FAILED` (not a finding,
  not "not applicable" — a distinct execution-status value the report layer can surface), and
  continues to the next plugin. **A plugin error must never crash the engine or abort the
  scan of other targets/plugins.**
- KB writes are **not transactional**: if a plugin calls `set_kb_item` and then errors later in
  the same `run()`, the earlier writes remain in the KB. This is an intentional simplicity
  trade-off (documented so `kb-schema.md` and plugin authors don't assume otherwise) — plugins
  should only `set_kb_item` values they're confident are correct at the point they write them,
  not as a draft they intend to revise before finishing.
- `lua_State` creation/close is unconditional on every path (§4.1 step 6, §4.2 step 6) — no
  early return skips `lua_close`.

### 4.4 Resource cleanup guarantee (Lua 5.4-specific)

Sockets opened via `open_sock_tcp` and not explicitly released via `close_sock` are still
force-closed when the engine calls `lua_close(L)` at the end of a run invocation (§4.2 step 6),
because Lua 5.4's `lua_close` is specified to close all active to-be-closed variables and invoke
pending `__gc` finalizers for all remaining collectable objects before freeing state — this is
an explicit 5.4 guarantee (stronger than the informally-timed finalization in 5.1/5.3), and the
socket userdata's metatable implements both `__close` and `__gc` for exactly this reason (§2.4).
Plugin authors should still call `close_sock` explicitly for deterministic, timely cleanup
rather than relying on this as anything other than a safety net for early-return/error paths.

### 4.5 Runtime limit

Before invoking `run()` (§4.2 step 5), the engine installs an instruction-count debug hook
(`lua_sethook(L, hook, LUA_MASKCOUNT, N)`) that checks a wall-clock deadline stored in the
state's extra space (`lua_getextraspace(L)`, a fixed-size per-`lua_State` blob available since
Lua 5.3/5.4, used here to avoid a registry round-trip on every hook tick). If `run()` exceeds
**15000 ms** (default; may become configurable later — an additive change, not a contract
break), the hook calls `luaL_error(L, "plugin exceeded max execution time")`, which unwinds via
the normal Lua error mechanism, triggers `<close>`/`__gc` socket cleanup exactly as any other
error would (§4.4), and is caught by the enclosing `lua_pcall` in §4.2 step 5 like any other
plugin failure (§4.3). No OS thread or `alarm()`-style mechanism is needed.

### 4.6 `required_keys` grammar & per-service dispatch (FROZEN)

An entry in `required_keys` is exactly one of two forms. Both are frozen legal grammar as of
this contract, so broadening wildcard use to more plugin families later is an additive,
non-breaking change — no plugin author or scheduler change is forced by that future rollout.

1. **Exact key** (default, primary form): a literal KB key with no wildcard, e.g.
   `"Services/ftp/21"`, `"HostDetails/os"`, `"TLS/443/enabled"`. Semantics: the key must be
   present (`get_kb_item(key) ~= nil`). An exact-key plugin runs **once** per target and gets
   `nil` from `get_scan_port()`; it hard-codes whatever canonical port it targets. This is the
   form used by the ssh/ftp/smb/rdp/telnet-style checks whose port is fixed by convention.

2. **Service wildcard**: the form `"Services/<svc>/*"` — a `Services/`-rooted pattern with
   exactly one trailing `/*` and no other wildcard. `<svc>` is a token from the frozen
   service vocabulary in `kb-schema.md` §2 (`www`, `https`, `ssh`, `ftp`, …). Semantics:
   **per-service dispatch** — the scheduler expands the plugin into one run per KB entry
   matching `Services/<svc>/<port>`, binding that port (readable via `get_scan_port()`, §2.2a).
   This is what the `www`/`tls`/`http-header` plugin family uses **now** so a single check
   covers every HTTP(S) port on a host without duplicating the plugin per port.

Rules and constraints (Milestone 0-6 scope):

- Wildcards are valid **only** in the `Services/` namespace and **only** as a whole trailing
  segment `/*`. No mid-path wildcard (`"HTTP/*/server"`), no suffix wildcard
  (`"Services/www/8*"`), no wildcard outside `Services/`. Any other `*` usage is a registration
  error (`luaL_error` in `register`, plugin skipped).
- A plugin's `required_keys` may contain **at most one** `Services/<svc>/*` wildcard. That
  wildcard is the dispatch driver. Any additional entries alongside it must be exact keys and
  act as extra presence gates evaluated per dispatched port (e.g. a TLS check may declare
  `{ "Services/https/*" }`, and the run itself reads `TLS/<port>/enabled` for the bound port).
- Because `kb-schema.md` §7.3 writes `Services/www/<port>` for **both** plain-HTTP and
  HTTP-over-TLS ports (and additionally `Services/https/<port>` for the TLS ones), a header
  plugin keyed on `"Services/www/*"` naturally covers 80 and 443 alike and uses
  `http_get{ tls = true }` when `TLS/<port>/enabled` is set for the bound port.
- `dependencies` ordering (§4.1) is unchanged by dispatch: all of a service-wildcard plugin's
  per-port invocations occur within that plugin's single slot in the topological order.

## 5. Sandboxing

### 5.1 Stdlib exposure

| Library | Metadata-phase sandbox | Run-phase sandbox |
|---|---|---|
| base (`assert`,`error`,`ipairs`,`pairs`,`next`,`pcall`,`xpcall`,`select`,`tostring`,`tonumber`,`type`,`rawequal`,`rawget`,`rawset`,`rawlen`,`setmetatable`,`getmetatable`,`unpack`\*) | yes | yes |
| `string` | yes | yes |
| `table` | yes | yes |
| `math` | yes | yes |
| `register` | yes (captures header) | yes (no-op stub, see §4.2) |
| KB/socket/HTTP/report/log functions (§2) | **no** | yes |
| `os` | no | no |
| `io` | no | no |
| `package` / `require` | no | no |
| `dofile` / `loadfile` / `load` | no | no |
| `debug` | no | no (used internally by the engine for the message handler before sandboxing; never exposed to the plugin's `_ENV`) |
| `coroutine` | no | no (not needed for Milestone 0-6 scope; may be added later, additive) |
| `print` | no | no — use `log(level, message)` (§2.10) so all output is structured and attributable |
| `collectgarbage` | no | no |
| `_G` | no | no — the sandbox table is never exposed under the name `_G`, so a plugin cannot reach back to a real global table even indirectly |

\* `table.unpack`/`unpack` naming follows Lua 5.4 (`table.unpack`; there is no standalone
global `unpack` in 5.4 — omit it from the base set above, it's listed only for readers coming
from 5.1 background. Plugins use `table.unpack`.)

### 5.2 `_ENV` rebinding mechanism (why this matters)

Lua 5.2+ (including 5.4) has no `setfenv`/`LUA_GLOBALSINDEX`. A chunk's globals are accessed
through its `_ENV` upvalue. `lua_load` (and therefore `luaL_loadfile`) initializes a freshly
loaded chunk's `_ENV` upvalue to the state's real global table (`LUA_RIDX_GLOBALS` in the
registry) by default. **If the engine skips the rebind step, the plugin runs with full access
to the real Lua global table regardless of what sandbox table was built**, silently defeating
every restriction in §5.1. The engine must, immediately after `luaL_loadfile` succeeds and
before calling `lua_pcall`:

```c
lua_pushvalue(L, sandbox_env_index);
lua_setupvalue(L, chunk_index, 1); /* upvalue 1 of a top-level chunk is always _ENV */
```

This is the sole sandboxing mechanism — there is no separate "restricted state" concept in Lua
5.4 the engine can rely on instead.

### 5.3 Socket use restricted to detection

`open_sock_tcp`/`send`/`recv`/`http_get` are the only network primitives exposed. There is no
raw-socket, UDP, listen/bind, or protocol-crafting primitive, and no way for a plugin to reach
the filesystem, spawn a process, or load another Lua file. Detection-only is enforced by the
sandbox surface itself, not merely by convention in plugin code review.

---

## 6. Open assumptions for other Milestone-0 contracts

For the C-engine author (`kb-schema.md`/engine implementation):

- `get_kb_item`/`set_kb_item` value typing is exactly three tags — `string`, `integer`
  (`lua_Integer`, Lua 5.4's distinct integer subtype — not `float`), `boolean` — mapped 1:1 to
  Lua types. If a KB key's documented type in `kb-schema.md` is a float/double, this contract
  as written does not support it; either the KB schema author avoids float-valued keys or this
  contract needs an amendment (flag if `kb-schema.md` needs a float type).
- `Ports/tcp/<port>` and `Services/<proto>/<port>` are assumed to be populated by a core engine
  stage (or an `ACT_SETTINGS` plugin) *before* any `ACT_GATHER_INFO` plugin's `required_keys`
  gate is checked — i.e., port/service discovery is assumed to run before the Lua plugin
  scheduling phase begins for a given target.
- An **exact-key** plugin targets one canonical port baked into its `required_keys` (e.g.
  port 21 for FTP) and hard-codes that port. A **service-wildcard** plugin (`Services/<svc>/*`,
  §4.6) is dispatched once per matching port and reads its port from `get_scan_port()`. The
  `www`/`tls`/`http-header` family uses the wildcard form now; the ssh/ftp/smb/rdp checks use
  the exact-key form. Detecting an exact-key protocol on a non-standard port still requires a
  duplicate plugin (different `script_id`); broadening more families to the wildcard form later
  is a non-breaking, additive change since the grammar is already frozen (§4.6).

For the DB-schema author (`db-schema.md`):

- A finding row must be able to store `cpe` (nullable string) and `cve` (nullable list —
  either a join table or a delimited/JSON column) exactly as passed to `report_vuln` (§2.9),
  plus the execution-status concept from §4.3 (`FAILED` as distinct from "ran, no finding").
- `severity` persisted on a finding is always the integer 0-4 from `report_vuln`, never the
  plugin header's `risk_factor` string — the header value is catalog/documentation metadata
  only and is not itself written to any finding row.
