# Cytadel Scan — Stock Plugins

This directory holds the in-tree, detection-only Lua plugins loaded by the
engine at scan startup (`docs/contracts/plugin-api.md`, FROZEN). Every
plugin here inspects a fact already gathered into the per-host KB
(`docs/contracts/kb-schema.md`, FROZEN) — a banner, a certificate field, a
response header, a protocol/version string — and, where warranted, calls
`report_vuln{...}`. **None of these plugins exploit anything.** Where a
real-world check would require completing a state-changing action against
the target (a real login, a crafted request beyond a plain read-only
GET/HEAD, a full protocol handshake this milestone's API does not expose),
it is either written as a narrowly-scoped, clearly-labelled banner/config
observation instead, or omitted entirely — see "Deliberately omitted"
below.

`script_id` numbering used here: `100001`–`100041`, inside the
contract's documented `100000`–`199999` in-tree range (`plugin-api.md`
§1.2).

## Plugin catalog

### FTP (family `"FTP"`)

| Plugin | `script_id` | `required_keys` | Severity | What it detects |
|---|---|---|---|---|
| `ftp_anonymous_banner_hint.lua` | 100001 | `Services/ftp/21` | Info | The FTP greeting banner text mentions "anonymous". **Text-only** — no login of any kind is attempted (see "Why no live anonymous-login attempt" below). |
| `ftp_cleartext_protocol.lua` | 100002 | `Services/ftp/21` | Low | Plain FTP is inherently unencrypted; flags any detected FTP service. |

#### Why no live anonymous-login attempt

`docs/contracts/plugin-api.md` §3's own reference example plugin
(`ftp_anonymous_login.lua`) demonstrates the API by performing a real
`USER anonymous` / `PASS ...` exchange and checking for a `230` response.
This milestone's task brief is more specific and stricter for what actually
ships in this directory: FTP anonymous-login detection here is
**banner-text only** — no control-channel login of any kind, anonymous or
otherwise, is attempted. Rationale: completing an anonymous login is a real
(if conventionally "public") authenticated session against the target —
it can be logged, audited, or alerted on by the target's own systems — and
this project's non-negotiable rule is that checks "inspect versions /
config / banners / certificates / headers only — never exploitation" (and,
more specifically here, never *establish access*, even access a service
nominally offers to the public). `plugin-api.md`'s example remains valid,
correct reference documentation of the socket API's shape; this directory
simply does not ship a plugin that uses it for a live login attempt.

### SSH (family `"SSH"`)

| Plugin | `script_id` | `required_keys` | Severity | What it detects |
|---|---|---|---|---|
| `ssh_sshv1_supported.lua` | 100010 | `Services/ssh/22` | High | `SSH/22/protocol` starts with `"1."` (bare SSH-1, or the `"1.99"` dual-protocol backward-compat value) — SSH-1 has structural cryptographic weaknesses. |
| `ssh_known_vulnerable_openssh.lua` | 100011 | `Services/ssh/22` | Low or Medium | Heuristic, banner-version-parsed OpenSSH release-band check (`< 6.6`: generic outdated, Low; `8.5–9.7`: CVE-2024-6387 "regreSSHion" band, Medium). Explicitly labelled heuristic in the finding text — banner strings can be stale/patched/backported. |
| `ssh_version_disclosure.lua` | 100012 | `Services/ssh/22` | Info | The SSH banner discloses exact software/version. Informational only. |

### TLS (family `"TLS"`, all dispatched via the `Services/https/*` wildcard)

| Plugin | `script_id` | Severity | What it detects |
|---|---|---|---|
| `tls_cert_expired.lua` | 100020 | High | `TLS/<port>/cert_expired == true`. |
| `tls_cert_not_yet_valid.lua` | 100021 | Medium | `TLS/<port>/cert_not_yet_valid == true`. |
| `tls_cert_self_signed.lua` | 100022 | Medium | `TLS/<port>/self_signed == true`. |
| `tls_cert_hostname_mismatch.lua` | 100023 | Medium | Neither the cert's CN nor any SAN (including one leading-wildcard label) matches `Host/hostname`. Skipped entirely if `Host/hostname` was never resolved — never guesses. |
| `tls_weak_sig_alg.lua` | 100024 | High (MD5) / Medium (SHA-1) | `TLS/<port>/sig_alg` contains `md5` or `sha1`. |
| `tls_weak_key_size.lua` | 100025 | Medium | RSA key `< 2048` bits, or EC key `< 224` bits — key family inferred **heuristically** from `sig_alg` (skipped if `sig_alg` is absent, to avoid flagging a strong EC key as weak). |
| `tls_deprecated_protocol.lua` | 100026 | High (SSLv3) / Medium (TLSv1/1.1) | `TLS/<port>/version` is an exact match for a deprecated protocol string. |
| `tls_weak_cipher.lua` | 100027 | High (NULL/EXPORT/anon) / Medium (RC4/DES/MD5-MAC) | `TLS/<port>/cipher` contains a well-known weak-suite name fragment. |

All eight gate on `Services/https/*` (the wildcard's bound port), per
`plugin-api.md` §4.6's documented pattern for "the www/tls/http-header
family", then re-check `TLS/<port>/enabled == true` before reading any
other `TLS/<port>/*` fact, exactly as the contract's own §4.6 example
describes.

**Known scope limitation (inherited from the engine, not a plugin bug):**
`Services/https/<port>` is only written by the current
`src/net/service_detect.c` for TLS-confirmed ports that are *also*
recognized HTTP ports (443/8443 today, per `src/net/svc_token.c`'s
well-known-port table). TLS-only, non-HTTP protocols — IMAPS/POP3S/SMTPS/
LDAPS on 993/995/465/636 — successfully negotiate TLS and get full
`TLS/<port>/*` cert/protocol/cipher facts written today, but do not get a
`Services/https/<port>` token, so this plugin family will not currently
dispatch against those ports. Broadening `service_detect.c` to write an
`https`-family token (or a dedicated wildcard) for every TLS-candidate port
is a natural follow-up, but it is an `src/net` engine change — out of scope
for this plugin-only milestone.

### HTTP Headers (family `"HTTP Headers"`)

| Plugin | `script_id` | `required_keys` | Category | Severity | What it does |
|---|---|---|---|---|---|
| `http_headers.lua` | 100030 | `Services/www/*` | `ACT_SETTINGS` | — | Issues one baseline `GET /` per HTTP(S) port and records a **fixed allowlist** of security-relevant headers into `HTTP/<port>/headers/<name>`. Reports no findings itself. |
| `http_missing_hsts.lua` | 100031 | `Services/https/*` | `ACT_GATHER_INFO` | Low | No `Strict-Transport-Security` header (TLS ports only). |
| `http_missing_csp.lua` | 100032 | `Services/www/*` | `ACT_GATHER_INFO` | Low | No `Content-Security-Policy` header. |
| `http_missing_xcto.lua` | 100033 | `Services/www/*` | `ACT_GATHER_INFO` | Low | No `X-Content-Type-Options: nosniff` (absent, or present with a non-conforming value). |
| `http_missing_xfo.lua` | 100034 | `Services/www/*` | `ACT_GATHER_INFO` | Low | No `X-Frame-Options` **and** no CSP `frame-ancestors` fallback. |
| `http_insecure_cookie_flags.lua` | 100035 | `Services/www/*` | `ACT_GATHER_INFO` | Medium (missing `Secure` over TLS) / Low (missing `HttpOnly` only) | `Set-Cookie` lacks `Secure` (TLS ports) and/or `HttpOnly`. Documented heuristic limitation: multiple `Set-Cookie` headers are joined by `http_get()` (§2.8), so this is a whole-response, not guaranteed per-cookie, signal. |

The five `http_missing_*`/cookie checks declare `dependencies = { 100030 }`
(ordering only, per §4.1) and read `HTTP/<port>/headers/<name>` — they do
**not** call `http_get` themselves.

### Web Servers (family `"Web Servers"`)

| Plugin | `script_id` | `required_keys` | Severity | What it detects |
|---|---|---|---|---|
| `http_server_version_disclosure.lua` | 100036 | `Services/www/*` | Info | `HTTP/<port>/server` contains a digit (a version number). Reads engine-populated data only — no network I/O, no dependency on `http_headers.lua`. |
| `http_directory_listing.lua` | 100037 | `Services/www/*` | Medium | `HTTP/<port>/title` matches the conventional Apache/nginx/lighttpd autoindex `"Index of ..."` template. Reads engine-populated data only. |
| `http_known_vulnerable_server.lua` | 100038 | `Services/www/*` | Low | `HTTP/<port>/server` matches a well-known end-of-life release band (Apache `< 2.4`, nginx `< 1.20`, `Microsoft-IIS <= 7.x`). Heuristic — asserts no specific CVE. |

### General (family `"General"`)

| Plugin | `script_id` | `required_keys` | Severity | What it detects |
|---|---|---|---|---|
| `telnet_cleartext_protocol.lua` | 100040 | `Services/telnet/23` | Medium | Any detected Telnet service (inherently cleartext remote access). |
| `db_exposed_cleartext.lua` | 100041 | `{}` (self-gated internally) | Low | MySQL (3306) / PostgreSQL (5432) / Redis (6379) reachable on their conventional port. Exposure-only signal — does not test auth or TLS. `required_keys` is empty because this plugin checks three independent services with OR semantics, which `required_keys`' AND-only gating cannot express in one declarative gate (`plugin-api.md` §4.6); it gates itself internally instead and is always a fast, KB-only no-op when none of the three are present. |

## Deliberately omitted (and why)

- **TRACE method / OPTIONS-advertised methods.** `http_get()`'s frozen
  contract (`plugin-api.md` §2.8) only supports `method = "GET" | "HEAD"` —
  no `OPTIONS`, no `TRACE`. There is no way to perform this check without
  either exploitation-adjacent request crafting or an API change to a
  FROZEN contract. Not written.
- **SSH weak KEX/MAC/cipher algorithm enumeration.** The engine's SSH
  detection (`src/net/svc_ssh.c`) only parses the plaintext version-
  exchange banner (`SSH-<proto>-<software>`); it does not perform (or
  expose to Lua) the subsequent `SSH_MSG_KEXINIT` exchange that would be
  needed to learn the server's offered KEX/host-key/cipher/MAC algorithm
  lists. Implementing a bespoke binary SSH-protocol parser inside a
  sandboxed Lua plugin via raw `recv()` is real, non-exploitative,
  detection-only work — but it is significant unverified protocol-parsing
  surface, and there is no KB key or engine primitive to build it on
  reliably or test it deterministically today. Deferred rather than
  shipped as an ad hoc, under-tested heuristic.
- **rlogin.** `rlogin` has no token in `kb-schema.md` §2's frozen service
  vocabulary and `src/net/svc_token.c` does not map its conventional port
  (513) to any service token, so no `Services/rlogin/*` KB entry can ever
  exist for a `required_keys` gate to match. Out of scope without a
  `kb-schema.md` amendment (a stop-and-ask item, not something this
  milestone changes unilaterally).

## Severity rationale (summary)

Severities follow the canon scale (`Info=0, Low=1, Medium=2, High=3,
Critical=4`, `plugin-api.md` §0) and are deliberately conservative:

- **Info** is used only for pure disclosure (a version string, a banner) —
  never a confirmed weakness.
- **Low** is used for hardening gaps (a missing recommended header, an
  exposed-but-unauthenticated-untested database port, plaintext-by-design
  FTP) and for heuristic/banner-based "outdated software" signals where no
  specific CVE is asserted.
- **Medium** is used for concrete, structurally-verified TLS/HTTP
  configuration weaknesses (self-signed/mismatched/weak-key certs, missing
  cookie flags, deprecated-but-not-broken TLS versions, Telnet).
- **High** is reserved for weaknesses with well-documented, practical
  cryptographic breaks (MD5-signed certs, SSLv3, NULL/EXPORT/anonymous TLS
  ciphers, SSH protocol 1).

Every heuristic, banner-version-based check (`ssh_known_vulnerable_openssh`,
`http_known_vulnerable_server`) says so explicitly in its finding
description and keeps severity at Low/Medium rather than asserting a
specific CVE applies with confidence banner text alone cannot support.

## Adding a new plugin

1. Read `docs/contracts/plugin-api.md` and `docs/contracts/kb-schema.md` in
   full (FROZEN — do not assume, verify against the actual `src/plugin`
   binding code too).
2. Pick a `script_id` in `100000`–`199999` that does not collide with any
   file in this directory (see the tables above).
3. Decide `required_keys`: an exact key with a literal, hard-coded port for
   a fixed-port protocol (SSH/FTP/Telnet-style), or a single
   `"Services/<svc>/*"` wildcard plus optional exact-key presence gates for
   a per-port family (TLS/HTTP-header-style) — see §4.6.
4. Only read facts that are actually populated for the KB keys you gate on
   — check `kb-schema.md` §7 and, if unsure, the writing C code
   (`src/net/*`) directly; do not assume a key exists just because it is
   documented as a *possible* fact.
5. Guard every read (`get_kb_item` returns `nil` for "unknown" — never
   treat `nil` as `false`/`0`/empty) and keep the check narrow enough that
   a missing/malformed value causes an early `return`, never an error.
6. Write the finding's `evidence` from real observed data (never a
   fabricated/crafted value) and keep `severity` conservative — see
   "Severity rationale" above.
7. Add fixture-driven tests: a positive case, a negative case, and at least
   one malformed/hostile input, in `tests/unit/test_plugins_stock.c` (KB-
   only cases) or `tests/unit/test_plugins_stock_network.c` (only if the
   plugin must issue a live `http_get`/socket call, following the existing
   loopback-fixture-server pattern in that file).
8. Update this README's catalog table and, if relevant, the "Deliberately
   omitted" section.
