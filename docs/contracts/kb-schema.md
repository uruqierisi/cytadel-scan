# Cytadel Scan — Knowledge Base (KB) Schema

**Status: FROZEN CONTRACT.** This document defines the complete KB key
namespace for Milestone 1 onward. It is immutable during implementation —
any change requires an explicit stop-and-ask per the project's engineering policy.

Audience: the engine/KB store, the plugin layer (plugin API + stock
plugins), the CPE→CVE matching layer, and the report/docs layers
(reporting must read the same keys it documents).

---

## 1. Scope and Design Canon

- The KB is an **in-memory, per-host** key/value store. One KB instance
  exists per scanned host and is discarded (or archived for debugging)
  once that host's plugin schedule completes.
- The KB stores **facts** discovered about a host (open ports, banners,
  certificate details, detected software/versions). It is **not** a
  findings store — vulnerabilities, misconfigurations, and any severity
  judgement are reported exclusively via `report_vuln{...}` /
  `security_report(...)` as defined by the plugin API contract. Nothing
  with a severity or CVE attached belongs in the KB.
- Severity scale (for reference, not used by the KB itself): `Info=0,
  Low=1, Medium=2, High=3, Critical=4`.
- Keys are `/`-delimited strings. Values are one of three primitive
  types: `string`, `int`, `bool`. There are no lists/tables/nested
  structures — composite data is flattened into multiple keys or encoded
  as a delimited string (see §3).

---

## 2. Naming Rules

- A key is one or more **segments** joined by `/`. No leading slash, no
  trailing slash, no empty segments (`//` is invalid).
- Segment charset: `[A-Za-z0-9_.-]+`. No whitespace, no control
  characters, no additional `/`. Keys are validated by the KB store on
  every `set_kb_item` call; an invalid key is rejected (see §4).
- **Case sensitivity**: keys are case-sensitive and must be written
  exactly as specified in the tables below. Readers must match case
  exactly — `HTTP/80/server` and `http/80/server` are different keys.
- **Fixed top-level namespace segments** (`Host`, `HostDetails`, `Ports`,
  `Services`, `Banner`, `SSH`, `HTTP`, `FTP`, `SMB`, `RDP`, `TLS`, `CPE`,
  `Scan`, …) use the exact casing shown in §6. New top-level namespaces
  introduced later must follow the same `PascalCase`/`UPPERCASE-acronym`
  convention already in use and must be added to this document first.
- **`<port>` segment**: the decimal ASCII representation of the port
  number, no zero-padding, no leading `+`. Example: `443`, not `0443`.
  Valid range 1–65535.
- **`<service>` segment** (used under `Services/<service>/<port>`):
  a lowercase short token drawn from a frozen service-token vocabulary
  that mirrors conventional short service names (`www`, `https`, `ssh`,
  `ftp`, `smb`, `rdp`, `telnet`, `smtp`, `pop3`, `imap`, `dns`, `snmp`,
  `mysql`, `postgresql`, `redis`, …). This vocabulary **must** be shared
  verbatim with the CPE-mapping table and the plugin layer's
  service-detection plugin so that `Services/<token>/<port>` and CPE
  `part:vendor:product` mappings stay joinable. Extending the vocabulary
  requires updating this file.
- Sub-keys within a per-service or per-feature namespace (e.g. `version`,
  `server`, `cn`, `not_after`) use `lower_snake_case`.
- **Maximum key length**: 255 bytes total (mirrors typical fixed-buffer
  identifier limits and keeps the engine-side hash table simple).
  `set_kb_item` on an over-length key fails (see §4).

---

## 3. Value Type System

| KB type  | C representation      | Lua representation           | Notes |
|----------|------------------------|-------------------------------|-------|
| `int`    | `int64_t`               | Lua number (integer subtype) | Used for ports, counts, status codes, enumerated states, key sizes. |
| `bool`   | `int` (0/1) internally, tagged `KB_TYPE_BOOL` | Lua `true`/`false` | Never conflated with `int` — a reader asking for a bool gets a real Lua boolean, not `0`/`1`. |
| `string` | owned heap buffer (`char *`, NUL-terminated), UTF-8 | Lua string | Max length **4096 bytes** (`CYTADEL_KB_VALUE_MAX_LEN`). No embedded NUL. |

Rules:

- The KB store is the single owner of every stored value; plugins never
  receive a pointer they must free — Lua's GC (for the copied Lua-side
  value) and the KB's internal allocator (for the stored copy) are
  independent. `set_kb_item` **copies** the value in; `get_kb_item`
  **copies** the value out to a fresh Lua value.
- **No composite types.** Lists are represented either as multiple keys
  (preferred — e.g. one key per open port) or, where the data is
  genuinely one fact with an internal list shape (e.g. a certificate's
  Subject Alternative Names), as a single comma-joined string value
  (e.g. `TLS/443/san` = `"example.com,www.example.com"`). This keeps the
  C-side KB struct a flat `{type, int64|bool|char*}` union with no
  recursive (de)serialization.
- Oversized or malformed values/keys are **rejected, not truncated**
  (silent truncation of, e.g., a SAN list or a CVE-relevant version
  string could cause a false negative in CPE matching). `set_kb_item`
  logs a warning via the engine logger and reports failure back to the
  calling plugin.
  - **Reconciled with `plugin-api.md` §2.2 (authoritative):** `set_kb_item`
    returns **nothing**. It does not return a boolean success flag.
    Instead it is fail-loud — any validation failure (unsupported value
    type, invalid or over-length key, over-length string value) raises a
    Lua error and stores nothing (reject, never truncate). A plugin
    therefore does not test a return value; a rejected write surfaces
    immediately as a plugin bug.

---

## 4. Absent-Key / Error Semantics

- `get_kb_item(key)` on a key that has never been written, or was
  written on a code path that did not execute for this host, returns
  Lua `nil`. There is no distinct "key never existed" vs. "key was
  explicitly cleared" state in Milestone 1 — the KB has no delete
  operation; plugins must treat `nil` as "unknown," never as "false" or
  `0`.
- `get_kb_item(key)` on a syntactically invalid key (violates §2) is a
  plugin bug; the engine logs an error and returns `nil` rather than
  aborting the whole scan.
- `set_kb_item(key, value)` on a syntactically invalid key, an
  over-length key, an over-length string value, or an unsupported Lua
  value type (table, function, userdata, `nil`) fails validation, is
  **not** stored, is logged at WARN level with the offending plugin's
  `script_id`, and **raises a Lua error** (fail-loud; per `plugin-api.md`
  §2.2 — `set_kb_item` has no boolean return, see §3).
- `set_kb_item` is last-write-wins. There is no versioning/history; a
  later plugin overwriting an earlier plugin's key silently replaces it.
  Plugins that need to aggregate (e.g. "all detected HTTP methods")
  must do so via distinct keys (`HTTP/80/methods/get`,
  `HTTP/80/methods/post`, …), not by trying to append to a shared key.

---

## 5. `required_keys` Declaration Mechanics

`required_keys` is a plugin-metadata field whose grammar and dispatch
semantics are **owned by `plugin-api.md` §4.6 (authoritative)**. This
section states how those two frozen forms map onto the namespace defined
here; where any wording differs, `plugin-api.md` wins.

- A `required_keys` entry is exactly one of two forms:
  - an **exact key** (default, primary form), e.g. `"Host/state"`,
    `"Services/ftp/21"`, `"TLS/443/enabled"` — the plugin needs that
    specific fact. **Literal port numbers are allowed and expected** in
    this form: an exact-key plugin targets one canonical port, runs once
    per host, and hard-codes that port (`get_scan_port()` returns `nil`
    for it). This is the form ssh/ftp/smb/rdp/telnet checks use.
  - a **service wildcard**, written as `"Services/<svc>/*"`, e.g.
    `"Services/www/*"` — where `<svc>` is a token from the frozen
    service vocabulary (§2). This triggers **per-service dispatch**: the
    scheduler runs the plugin once per matching `Services/<svc>/<port>`
    entry and binds that port, which the plugin reads via
    `get_scan_port()` and then uses for per-port KB reads
    (`get_kb_item("HTTP/" .. port .. "/server")`). The `www`/`tls`/
    `http-header` family uses this form now.
- Wildcards are legal **only** in the `Services/` namespace and **only**
  as a whole trailing `/*` segment. No mid-path wildcard
  (`"HTTP/*/server"` is invalid), no suffix wildcard, no wildcard under
  `Ports/*`, `Banner/*`, `SSH/*`, `TLS/*`, etc. A plugin may carry **at
  most one** `Services/<svc>/*` wildcard; any additional entries must be
  exact keys acting as extra per-port presence gates (see `plugin-api.md`
  §4.6).
- A plugin gates as "eligible to run" only when **every** `required_keys`
  entry is satisfied (exact key present; service-wildcard has ≥1 matching
  `Services/<svc>/<port>`). `dependencies` (the plugin-id ordering field)
  governs *when* in the schedule the plugin may run; `required_keys`
  governs *whether* (and, for a wildcard, *how many times*) it runs for
  this host.

---

## 6. Concurrency / Ownership Model

- One KB instance per host. Hosts are scanned in parallel (worker pool);
  each worker owns exactly one host's KB for the duration of that host's
  scan, so **no cross-host contention** exists by construction.
- Within a single host, plugins are scheduled **sequentially** in
  dependency order on that host's worker (Milestone 1 does not run two
  plugins for the same host concurrently), so the KB store does not need
  internal locking for plugin-vs-plugin access on the same host.
- The engine's report generator reads a host's KB **after** that host's
  plugin schedule has fully completed (read-only, single-threaded pass),
  so no writer-vs-reader race exists either.
- If a future milestone introduces intra-host plugin parallelism, the
  KB store implementation must add a mutex around its hash table at that
  point; this contract does not need to change, only the C
  implementation's internal locking.

---

## 7. Key Namespace Reference

Legend for **Writer** / **Reader** columns: `host-discovery`,
`port-scanner`, `service-detection`, `tls-inspector`, `engine` (core
scan loop / scheduler, not a plugin), or `plugin` (any stock or
third-party Lua plugin — specific plugin family named where relevant).

### 7.1 Host / state

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `Host/state` | string | `"up"` | host-discovery | engine (scheduler gate — skip plugins if `"down"`), any plugin | Enum: `"up"` \| `"down"`. |
| `Host/ip` | string | `"10.0.0.15"` | engine (set at KB creation from the scan target) | all plugins, reporting | Dotted-quad IPv4 or RFC 5952-compressed IPv6. |
| `Host/hostname` | string | `"web01.internal.example"` | host-discovery (reverse DNS) | reporting, `plugin` (vhost-aware HTTP checks) | Absent (`nil`) if reverse DNS fails or is not attempted. |
| `Host/mac` | string | `"aa:bb:cc:dd:ee:ff"` | host-discovery (ARP, local-segment scans only) | reporting | Absent on routed/non-local-L2 targets. Lowercase colon-separated hex. |
| `Host/rtt_ms` | int | `2` | host-discovery | engine (timeout tuning), reporting | Round-trip time observed during discovery probe. |
| `HostDetails/os` | string | `"Linux 5.x"` | service-detection (TTL/window/banner heuristics) or a dedicated OS-fingerprint `plugin` | reporting, risk-scoring plugins | Best-guess, free-text — not a CPE. |
| `HostDetails/os_confidence` | int | `70` | same writer as `HostDetails/os` | reporting | 0–100 confidence score; only meaningful alongside `HostDetails/os`. |

### 7.2 Ports

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `Ports/tcp/<port>` | int | `Ports/tcp/443` = `1` | port-scanner | `plugin` (via `get_port_state`), service-detection, reporting | Enum: `0`=closed, `1`=open, `2`=filtered. Only written for ports actually probed; an un-probed port has no key (`nil`, not `0`). |
| `Ports/udp/<port>` | int | `Ports/udp/53` = `1` | port-scanner (UDP mode) | same as above | Same enum; UDP scans commonly cannot distinguish open from filtered, so `2` may mean "open\|filtered" for UDP — plugins must not treat `2` as a hard "closed." |
| **Cross-contract note (RESOLVED)**: `plugin-api.md` §2.3 confirms `get_port_state(port)` reads `Ports/tcp/<port>` (TCP default); a UDP-aware plugin calls `get_kb_item("Ports/udp/" .. port)` directly. | | | | | |

### 7.3 Services

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `Services/<service>/<port>` | int | `Services/www/80` = `80` | service-detection | `plugin` (via `required_keys` prefix wildcard `"Services/<service>/*"`), reporting | `<service>` is a token from the frozen vocabulary (§2). Value is the port number itself (acts as both a presence marker and a convenience echo of the port, avoiding a separate bool key). Presence of the key is the "is this service on this port" signal — plugins should check for `nil` first, not compare the value. |
| `Services/ssh/22` | int | `22` | service-detection | `plugin` (SSH checks) | |
| `Services/ftp/21` | int | `21` | service-detection | `plugin` (FTP checks) | |
| `Services/smb/445` | int | `445` | service-detection | `plugin` (SMB checks) | |
| `Services/rdp/3389` | int | `3389` | service-detection | `plugin` (RDP checks) | |
| `Services/https/443` | int | `443` | service-detection (after TLS handshake success on an HTTP-speaking port) | `plugin`, tls-inspector | Written in addition to `Services/www/443` when the port is confirmed to be HTTP-over-TLS; a plain-HTTP port on 443 (rare but possible) would get `Services/www/443` without a matching `TLS/443/*` block. |

### 7.4 Banners (raw + parsed)

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `Banner/<port>` | string | `Banner/22` = `"SSH-2.0-OpenSSH_9.6"` | service-detection (generic first-line banner grab on connect) | `plugin` (fallback for services with no dedicated parser), reporting | Capped at `CYTADEL_KB_VALUE_MAX_LEN` (4096 B); longer banners are truncated **at the banner-grab layer** before the `set_kb_item` call (this is a network-layer read-size cap, distinct from the KB's own reject-on-oversize rule in §3, which still applies as the final backstop). |
| `SSH/<port>/version` | string | `SSH/22/version` = `"SSH-2.0-OpenSSH_9.6"` | service-detection or `plugin` (`ssh_banner.lua`) | `plugin` (CVE-matching via CPE), reporting | Full banner string, same content as `Banner/22` for SSH but kept as a protocol-specific parsed key for clarity/consistency with other `SSH/*` keys. |
| `SSH/<port>/protocol` | string | `SSH/22/protocol` = `"2.0"` | same writer as `SSH/<port>/version` | `plugin` | Parsed protocol version only (no product/version). |
| `HTTP/<port>/server` | string | `HTTP/80/server` = `"nginx/1.24.0"` | service-detection or `plugin` (`http_banner.lua`) via `http_get` | `plugin` (CVE-matching), reporting | Raw `Server:` response header value, unparsed. |
| `HTTP/<port>/status` | int | `HTTP/80/status` = `200` | same writer | `plugin`, reporting | HTTP status code from the baseline `GET /` probe used to establish the banner. |
| `HTTP/<port>/title` | string | `HTTP/80/title` = `"Welcome to nginx!"` | `plugin` (`http_banner.lua`) | reporting | Parsed `<title>` of the baseline response body, if HTML. Absent if not HTML or no `<title>`. |
| `FTP/<port>/banner` | string | `FTP/21/banner` = `"220 (vsFTPd 3.0.5)"` | service-detection or `plugin` (`ftp_banner.lua`) | `plugin`, reporting | Raw FTP greeting line. |
| `SMB/<port>/os` | string | `SMB/445/os` = `"Windows Server 2019"` | `plugin` (`smb_info.lua`, via SMB negotiate) | reporting | |
| `RDP/<port>/nla_enabled` | bool | `RDP/3389/nla_enabled` = `true` | `plugin` (`rdp_info.lua`) | `plugin` (a config-check plugin flags NLA-disabled as a finding via `report_vuln`), reporting | Fact only — the corresponding finding, if any, is reported separately, not stored here. |

### 7.5 TLS

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `TLS/<port>/enabled` | bool | `TLS/443/enabled` = `true` | tls-inspector | `plugin` (gate before reading other `TLS/<port>/*` keys), reporting | `true` iff a TLS handshake completed on that port during probing. |
| `TLS/<port>/version` | string | `TLS/443/version` = `"TLSv1.2"` | tls-inspector | `plugin` (weak-protocol checks), reporting | Negotiated protocol version string. |
| `TLS/<port>/cipher` | string | `TLS/443/cipher` = `"ECDHE-RSA-AES256-GCM-SHA384"` | tls-inspector | `plugin` (weak-cipher checks), reporting | OpenSSL cipher-suite name as negotiated. |
| `TLS/<port>/cert_expired` | bool | `TLS/443/cert_expired` = `false` | tls-inspector | `plugin`, reporting | Computed at scan time from `not_after` vs. wall clock. |
| `TLS/<port>/cert_not_yet_valid` | bool | `TLS/443/cert_not_yet_valid` = `false` | tls-inspector | `plugin` | Computed from `not_before` vs. wall clock. |
| `TLS/<port>/self_signed` | bool | `TLS/443/self_signed` = `true` | tls-inspector | `plugin`, reporting | `true` if issuer DN == subject DN (leaf cert is its own issuer). |
| `TLS/<port>/cn` | string | `TLS/443/cn` = `"web01.internal.example"` | tls-inspector | `plugin`, reporting | Subject Common Name. |
| `TLS/<port>/san` | string | `TLS/443/san` = `"web01.internal.example,www.web01.internal.example"` | tls-inspector | `plugin`, reporting | Comma-joined Subject Alternative Names (see §3 — flattened list). |
| `TLS/<port>/not_before` | string | `TLS/443/not_before` = `"2025-01-01T00:00:00Z"` | tls-inspector | `plugin`, reporting | ISO-8601 UTC. |
| `TLS/<port>/not_after` | string | `TLS/443/not_after` = `"2026-01-01T00:00:00Z"` | tls-inspector | `plugin`, reporting | ISO-8601 UTC. |
| `TLS/<port>/issuer` | string | `TLS/443/issuer` = `"C=US, O=Let's Encrypt, CN=R11"` | tls-inspector | `plugin`, reporting | Full issuer DN as rendered by OpenSSL's oneline format. |
| `TLS/<port>/serial` | string | `TLS/443/serial` = `"03A1B2C3"` | tls-inspector | reporting | Hex, uppercase, no `0x` prefix, no colons. |
| `TLS/<port>/sig_alg` | string | `TLS/443/sig_alg` = `"sha256WithRSAEncryption"` | tls-inspector | `plugin` (weak-signature checks) | |
| `TLS/<port>/key_bits` | int | `TLS/443/key_bits` = `2048` | tls-inspector | `plugin` (weak-key-size checks) | Public key size in bits (RSA) or curve order bit-length (EC). |

### 7.6 HTTP security headers

Security-header plugins consume presence/value keys under a dedicated
sub-namespace so `HTTP/<port>/server` etc. above are not polluted with
one key per possible header.

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `HTTP/<port>/headers/<header-name>` | string | `HTTP/443/headers/strict-transport-security` = `"max-age=63072000; includeSubDomains"` | `plugin` (`http_headers.lua`, via `http_get`) | `plugin` (security-header-check plugins), reporting | `<header-name>` is the HTTP header name, **lowercased**, with any internal spaces impossible (header names never contain them) and hyphens kept as-is (hyphens are already valid in §2's segment charset). Key is only written when the header is present in the response; absence of the key means the header was not present — plugins must not treat `nil` as `""`. |
| `HTTP/<port>/headers/x-frame-options` | string | `"DENY"` | `plugin` (`http_headers.lua`) | `plugin` (clickjacking check) | |
| `HTTP/<port>/headers/content-security-policy` | string | `"default-src 'self'"` | `plugin` (`http_headers.lua`) | `plugin` (CSP-quality check) | |
| `HTTP/<port>/headers/x-content-type-options` | string | `"nosniff"` | `plugin` (`http_headers.lua`) | `plugin` (MIME-sniffing check) | |

### 7.7 CPE (vulnerability-matching bridge)

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `CPE/<port>` | string | `CPE/22` = `"cpe:2.3:a:openbsd:openssh:9.6:*:*:*:*:*:*:*"` | service-detection (or a `plugin` that owns deep version parsing for its protocol, e.g. `ssh_banner.lua`) | the **engine's C-side DB-matching stage** (the sole CVE-matching authority — see below) | **This is the join key the schema must index on.** CPE 2.3 formatted string built once version + product are confidently known; absent if the version could not be determined precisely enough for a safe CPE (avoid false CPEs from a bare banner guess). **CVE/CPE matching is done in the C engine, not in a Lua plugin** (reconciled with `plugin-api.md` §0): a plugin may *emit* a `cpe` hint via `report_vuln`, but the engine — using the single shared CPE-version comparator (`db-schema.md` §10.3) — is what queries `cve_cpe_matches` and enriches findings. There is no `cve_match.lua`; plugins never compare versions. |

### 7.8 Engine / scan metadata

| Key | Type | Example | Writer | Typical Reader(s) | Notes |
|---|---|---|---|---|---|
| `Scan/start_time` | string | `"2026-07-18T09:00:00Z"` | engine | reporting | ISO-8601 UTC, set once per host when that host's KB is created. |
| `Scan/plugin_count` | int | `142` | engine | reporting | Number of plugins evaluated (not necessarily executed — see `required_keys` gating) for this host. |

---

## 8. Cross-Contract Items (RESOLVED at Milestone 0 sign-off)

1. **RESOLVED (B).** `set_kb_item` returns nothing and is fail-loud
   (raises on any validation failure) — `plugin-api.md` §2.2 is
   authoritative; §3/§4 above reconciled.
2. **RESOLVED.** `get_port_state(port)` reads `Ports/tcp/<port>`; UDP via
   direct `get_kb_item` (§7.2, `plugin-api.md` §2.3).
3. **RESOLVED (A).** Two frozen `required_keys` forms — exact key (with
   literal ports, default) and `Services/<svc>/*` service wildcard
   (per-service dispatch, port bound via `get_scan_port()`). Grammar is
   owned by `plugin-api.md` §4.6; §5 above reconciled. The `www`/`tls`/
   `http-header` family uses the wildcard form now.
4. **OPEN (implementation-time, not a contract conflict).** The
   `<service>` token vocabulary (§2) must be emitted identically by the
   engine's service-detection stage and consumed identically by the
   plugins; the CVE-matching layer keys on CPE `(vendor, product)`,
   which the detection layer maps from the service token — that mapping
   is a Milestone 4/7 detection-rules concern, tracked there.

**CVE/CPE matching (C)** is engine-side C using one shared version
comparator; there is no `cve_match.lua` (§7.7, `plugin-api.md` §0,
`db-schema.md` §10.3).
