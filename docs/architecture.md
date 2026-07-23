# Cytadel Scan — Architecture

This document describes the real component map and data flow as implemented today. It does not
restate the frozen contracts under `docs/contracts/` — it says where each one applies and links to
it. If this document and a contract ever disagree, the contract wins; if this document and the
code disagree, the code wins (flag it).

## Design posture (non-negotiable)

1. **Detection only.** Every stage below inspects a version/banner/config/certificate/header a
   target already sends over a plain connection. Nothing writes to, authenticates against, or
   exploits a target. See `AUTHORIZED_USE.md` for what this means concretely.
2. **Mandatory authorization gate.** The default scan invocation cannot reach the target-expansion
   step (below) without an explicit, logged authorization confirmation, and cannot even reach the
   authorization decision without a writable vulnerability database to record it in. `report` and
   `sync` never contact a target and are exempt (see `src/cli/main.c`).
3. **Engine (C) and plugins (Lua) are cleanly separated.** The engine never contains
   product/vendor-specific detection logic beyond generic banner/TLS parsing; everything else is a
   `plugins/*.lua` file, loaded at runtime as data (`docs/build-plan.md` §4 — plugins are never
   compiled into the binary).

## Component map

| Component | Path | Responsibility |
|---|---|---|
| CLI / entry point | `src/cli/` | Argument parsing (`cli_args.c`), the authorization gate decision (`auth_gate.c`), the scan pipeline's DB wiring (`scan_wiring.c`), and the `report`/`sync` subcommands (`report_cmd.c`, `sync_cmd.c`). `main.c` is the only place these are wired together; it owns `main()`. |
| Networking / detection engine | `src/net/` | Target parsing/CIDR expansion (`target.c`, `cidr.c`, `target_list.c`), host discovery (`discovery.c`, `icmp_probe.c`, `tcp_ping.c`, `capability.c`), port scanning (`port_scanner.c`, `scan_backend.c`, `tcp_connect.c`), banner/service detection (`banner_grab.c`, `svc_token.c`, `svc_ssh.c`, `svc_ftp.c`, `http_probe.c`, `service_detect.c`), TLS inspection (`tls_session.c`, `tls_inspect.c`), and CPE-string construction from a detected service (`cpe_map.c`). `host_scan.c` is the per-host orchestrator these all feed into. |
| Worker pool | `src/core/worker_pool.c` | Fixed-size pthread pool that runs `cytadel_host_scan()` concurrently across an already-expanded target list; independent of `main()`/CLI, unit-testable on its own. |
| Knowledge base (KB) | `src/kb/` | The in-memory, per-host fact store — the engine↔plugin interface. See "The KB" below. |
| Plugin engine | `src/plugin/` | Lua 5.4 VM embedding, sandboxing (`sandbox.h`, `plugin_header.c`), the registration-phase loader (`loader.h`, `registry.c`), the dependency graph (`depgraph.c`), the run-phase scheduler (`scheduler.c`), and the C-backed API functions plugins call (`api_kb.c`, `api_log.c`, plus the socket/HTTP bindings — see `docs/contracts/plugin-api.md`). |
| Version/CPE matching | `src/match/` | `version_compare.c` — the single, origin-neutral version comparator shared by every caller. `cpe_match.c` — evaluates one NVD CPE-match row (exact version or range bounds) against a detected version, returning one of four outcomes (see "CPE matching" below). |
| Vulnerability database | `src/db/` | SQLite access (`db.c`, `db_migrations.c`), NVD ingest/sync (`nvd_ingest.c`, `nvd_sync.c`, `nvd_catchup.c` — live), KEV/EPSS ingest (`kev_ingest.c`, `epss_ingest.c` — parse/persist only, **no live fetch driver exists for either**, see README), and scan-result persistence (`scan_persist.c` — the first production caller of the CPE evaluator). |
| Reporting | `src/report/` | Context-specific HTML/attribute/URL/JSON escapers (`escape.c`), and the HTML (`report_html.c`) and JSON (`report_json.c`) renderers, both reading the same point-in-time `scans`/`scan_results` snapshot (`report_scan_lookup.c` resolves `--latest`). |
| Logging | `src/log/` | Internal-only structured logger (`log.c`), used by every module above; not part of the public `include/cytadel/` surface. |
| Stock plugins | `plugins/` | 24 in-tree `*.lua` detection plugins, data (not compiled) — see `plugins/README.md` for the full catalog. |
| Vendored third-party code | `third_party/sqlite/`, `third_party/cjson/` | SQLite and cJSON amalgamations, compiled as isolated static libraries that never link the project's own `-Wall -Wextra -Wpedantic -Werror` flags (third-party code is exempt from that policy, by design — see each directory's `CMakeLists.txt`). |

## End-to-end data flow: a scan

```
CLI args ──► authorization gate (mandatory) ──► DB open + migrate + `scans` row (durable
             │                                    authorization record)
             ▼
     target/port expansion (CIDR, --targets-file, --ports)
             │
             ▼
     worker pool (src/core) — one thread per in-flight host, up to --max-workers
             │
             ▼   (per host, sequentially on that host's worker thread)
     ┌─────────────────────────────────────────────────────────────────┐
     │ cytadel_host_scan() (src/net/host_scan.c)                        │
     │  1. KB created for this host (Host/ip, Host/hostname if a         │
     │     hostname target was given, Scan/start_time)                  │
     │  2. Discovery (ICMP, falling back to TCP-ping) — Host/state       │
     │  3. Port scan (TCP connect only) — Ports/tcp/<port>              │
     │  4. Service detection + TLS inspection for each open port —       │
     │     Services/<svc>/<port>, Banner/<port>, HTTP/*, TLS/*, CPE/*    │
     │  5. Plugin schedule (src/plugin), strictly after step 4 —         │
     │     reads/writes the same KB, reports findings via report_vuln{} │
     └─────────────────────────────────────────────────────────────────┘
             │
             ▼
     Persist phase (src/cli/scan_wiring.c + src/db/scan_persist.c), per host:
       - resolve each open port's CPE (KB's CPE/<port>, if the detection layer
         set one confidently) against `cve_cpe_matches` (src/db)
       - cytadel_cpe_match_evaluate() per candidate row (src/match) — MATCH /
         NO_MATCH / UNDECIDABLE / MALFORMED_ROW
       - three-valued, order-independent fold per cve_id (any MATCH → confirmed;
         else any UNDECIDABLE → undetermined; else not_affected) — see
         docs/contracts/cpe-matching.md §3 and src/db/scan_persist.h's own
         header comment for the exact rule; MALFORMED_ROW is a distinct
         data-quality event, never coerced into a verdict
       - write scan_results rows + roll up scans.malformed_data_count
             │
             ▼
     finalize `scans` row (completed/failed) ──► SQLite vuln DB (CYTADEL_DB_PATH)
             │
             ▼ (separate invocation)
     `cytadel-scan report --latest/--scan-id` (src/report) ──► HTML or JSON
```

## End-to-end data flow: `cytadel-scan sync`

```
CLI args (--db, --now) ──► DB open + migrate (no authorization gate — no target is ever contacted)
             │
             ▼
     cytadel_nvd_catchup() (src/db/nvd_catchup.c): reads sync_state's watermark,
     walks [watermark, now] in bounded windows
             │
             ▼
     cytadel_nvd_sync_window() (src/db/nvd_sync.c): pages one window via
     src/net/nvd_fetch.c (libcurl, CYTADEL_NVD_API_KEY from env if set)
             │
             ▼
     cytadel_nvd_ingest_page() (src/db/nvd_ingest.c): defensive cJSON parse,
     skip-and-log per bad record, upserts `cves` + `cve_cpe_matches`
             │
             ▼
     watermark advances only once a window's final page commits cleanly
```

KEV and EPSS have ingest/persist modules (`kev_ingest.c`, `epss_ingest.c`) built against the same
pattern, but **no fetch driver exists for either feed yet**, and `sync` does not call them — see
the README's "What's deferred" section.

## The KB: the engine↔plugin interface

The knowledge base (`src/kb/`, contract: `docs/contracts/kb-schema.md`, frozen) is an in-memory,
per-host key/value store: `/`-delimited string keys, three value types (`string | int64 | bool`),
no locking (by design — exactly one worker thread owns one host's KB for the duration of that
host's scan, and the plugin scheduler runs plugins for one host sequentially, never concurrently,
against that same KB). It is the **only** channel between the C detection stages and the Lua
plugins: service detection and TLS inspection write facts (`Services/<svc>/<port>`, `Banner/<port>`,
`TLS/<port>/*`, …), and plugins read them via `get_kb_item`/`get_port_state` and may write their own
derived facts back via `set_kb_item`. The KB stores facts only — a plugin's severity judgement is
never written to it; findings go through `report_vuln{}`/`security_report{}` instead
(`docs/contracts/plugin-api.md` §0/§2.9).

## The plugin engine

`src/plugin/` implements `docs/contracts/plugin-api.md` (frozen) in two phases, both driven by
`src/cli/main.c` loading `--plugins-dir` (default `plugins/`) once before the worker pool starts:

- **Registration** (`registry.c`, `loader.h`, once per plugin file, at scan startup): each
  `*.lua` file runs in a metadata-only sandbox that exposes just `register{...}` — no KB/socket
  access exists yet at this phase. A broken plugin file is logged and skipped; it never aborts the
  scan. Once every file is attempted, `depgraph.c` builds one fixed topological order from the
  `dependencies` fields (a cycle, or a `dependencies` entry naming a non-existent `script_id`, is a
  hard startup error).
- **Run** (`scheduler.c`, once per target, per plugin, walking the fixed order): a fresh
  `lua_State` per (plugin, target) invocation, a run-phase sandbox exposing the KB/socket/HTTP/log/
  `report_vuln` functions (`api_kb.c`, `api_log.c`, and the socket/HTTP bindings), gated by
  `required_keys` (exact KB key, or a `Services/<svc>/*` wildcard that dispatches once per matching
  port). See `docs/plugin-authoring.md` for how to write one.

The sandbox surface itself is what enforces detection-only — there is no `os`/`io`, no
`http_post`, and no raw-socket primitive reachable from a plugin (`plugin-api.md` §5), not merely a
code-review convention.

## CPE matching and the three-/four-valued outcomes

`src/match/version_compare.c` is a single, pure, origin-neutral comparator (`docs/contracts/
cpe-matching.md` §1) — it never knows whether either string came from a scan banner or an NVD row,
and its API must not change to carry that context. `src/match/cpe_match.c` evaluates one NVD
CPE-match row (an exact version, or up to four range bounds) against a detected version string and
returns one of **four** outcomes: `MATCH`, `NO_MATCH`, `UNDECIDABLE` (the comparator couldn't
honestly order the two strings — an unsupported version scheme, or malformed input), or
`MALFORMED_ROW` (the NVD row itself is structurally invalid). `src/db/scan_persist.c` is the first
(and, as of this writing, only) production caller, and folds multiple candidate rows for one CVE
into exactly one of three `scan_results.match_status` values (`confirmed` / `undetermined` /
`not_affected`) via an order-independent, three-valued rule — see `docs/contracts/cpe-matching.md`
§3 for the full obligations any future caller must also honor (in particular: never silently
collapse `UNDECIDABLE` into a definite answer). The report layer (`src/report/`) surfaces
`undetermined` as its own always-visible "could not determine — manual review needed" state, never
folded into "no vulnerabilities found."

## Where the frozen contracts sit

| Contract | Governs | Owned by / read by |
|---|---|---|
| `docs/contracts/kb-schema.md` | KB key namespace, types, naming rules | `src/kb`, `src/net` (writers), `src/plugin` (Lua bindings + stock plugins), `src/report` |
| `docs/contracts/plugin-api.md` | The Lua plugin API surface, sandboxing, scheduling | `src/plugin`, `plugins/*.lua` |
| `docs/contracts/db-schema.md` | SQLite schema, severity scale, timestamp convention, version-matching approach | `src/db`, `src/report` |
| `docs/contracts/cpe-matching.md` | The comparator's origin-neutrality, the evaluator's 4 outcomes, and every caller's obligations | `src/match`, `src/db/scan_persist.c`, `src/report` |

None of these are restated here in full — read them directly; this document only says how the
pieces fit together.

## Concurrency model

- One worker thread per in-flight host (`src/core/worker_pool.c`), up to `--max-workers`
  (default 64, hard cap 1024, and never more threads than targets).
- One KB instance per host, owned by that host's single worker thread for the whole scan — no
  locking inside the KB store (`kb-schema.md` §6).
- Within one host, plugins run strictly sequentially in the fixed topological order — no two
  plugins ever run concurrently against the same KB.
- The report generator only ever reads a `scans`/`scan_results` snapshot after persistence has
  completed for that scan — no reader/writer race with an in-progress scan of the same DB (SQLite
  WAL mode additionally lets a `report`/`sync` invocation run concurrently with an in-progress
  scan without blocking on it).

## Known scope limitations (see also the README's "What's deferred")

- Port scanning is TCP-connect only; `src/net/scan_backend.c`'s SYN-scan seam
  (`CYTADEL_SCAN_BACKEND_SYN`) has no implementation.
- `Services/https/<port>` (and therefore the whole TLS/HTTP-header plugin family's dispatch) is
  only written for TLS-confirmed ports that are *also* recognized HTTP ports (443/8443 today) —
  TLS-only, non-HTTP protocols (IMAPS/POP3S/SMTPS/LDAPS) get full `TLS/<port>/*` facts but no
  plugin dispatch against them yet. See `plugins/README.md`.
- `Host/hostname` is the operator-supplied name, not a reverse-DNS result — no reverse-DNS
  resolution exists in this codebase.
- KEV/EPSS ingest exists but has no live fetch driver wired to anything (see above).
