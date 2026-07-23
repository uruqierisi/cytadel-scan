# Cytadel Scan

**A detection-only network vulnerability scanner** — a C11 engine with
embedded-Lua detection plugins, a local SQLite vulnerability database fed from
NVD / CISA KEV / FIRST EPSS, and branded HTML/JSON reporting.

Cytadel inventories a network by fingerprinting services from what they
voluntarily disclose — version banners, TLS certificates, HTTP headers,
configuration visible in normal responses — and matches those observations
against a local CVE database. It is built for **defensive** work: auditing your
own estate, verifying patch levels, and producing remediation evidence.

> ### ⚠️ Detection-only, and authorized use only
>
> Cytadel **inspects; it never exploits.** There is no code path that sends an
> exploit payload, brute-forces a credential, or attempts to gain, alter, or
> damage access to a target. Every check reads only versions, banners, headers,
> and certificates.
>
> Scanning systems you do not own or have **explicit written permission** to
> test may be illegal. Cytadel **refuses to scan** until you affirm
> authorization — via `--i-am-authorized` or the interactive prompt — and it
> logs that affirmation. **You are solely responsible** for having authorization
> for every target. Read [`AUTHORIZED_USE.md`](AUTHORIZED_USE.md) before running.

---

## What it does

- **Discovery** — ICMP echo where the host has `CAP_NET_RAW`, with an automatic
  TCP-ping fallback for unprivileged operators.
- **Port & service detection** — TCP-connect scanning, banner grabbing, and
  service identification (SSH, FTP, HTTP(S), TLS, Telnet, Redis, …).
- **Version/config checks via Lua plugins** — each plugin keys on one concrete
  banner/certificate/header condition and emits a severity-rated finding.
  Plugins are **data**: drop a new `.lua` file in `plugins/` — no engine rebuild.
- **Local vuln intel** — `cytadel-scan sync` ingests NVD 2.0 CVEs (with CISA KEV
  and FIRST EPSS enrichment) into a SQLite DB, defensively, with bounded reads
  and per-record skip-and-log on malformed input.
- **Reporting** — a self-contained, branded HTML report (single file, inline
  assets) or machine-readable JSON.

## Architecture

A single C11 static engine (`libcytadel`) plus a thin CLI (`cytadel-scan`). The
engine and the Lua plugins stay cleanly separated; the vuln DB and the frozen
data contracts (CPE matching, DB/KB schema, plugin API) are versioned under
[`docs/contracts/`](docs/contracts/). See
[`docs/architecture.md`](docs/architecture.md) for the full picture.

```
src/net      TCP/ICMP, banner grab, TLS inspection, service detection
src/plugin   embedded Lua 5.4 engine + the plugin C API
src/db       SQLite schema, migrations, NVD/KEV/EPSS ingest, scan persistence
src/match    CPE 2.3 version-range matching (four-state evaluator)
src/report   HTML + JSON report rendering
src/cli      argument parsing, the authorization gate, the subcommands
plugins/     the stock *.lua detection plugins (see plugins/README.md)
```

## Build

Linux-first, CMake. On a Debian/Ubuntu box:

```sh
sudo apt-get install -y build-essential cmake pkg-config \
    liblua5.4-dev libssl-dev libcurl4-openssl-dev

cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The build finds a system libcurl automatically. If you use a vendored prefix
(e.g. a static build), point CMake at it with `-DCYTADEL_CURL_ROOT=/path`
(and `-DCYTADEL_LUA_ROOT=…`, `-DOPENSSL_ROOT_DIR=…` for vendored Lua/OpenSSL);
or pass `-DCYTADEL_CURL_INCLUDE_DIR=… -DCYTADEL_CURL_LIBRARY=…` explicitly.

Useful options: `-DCYTADEL_WERROR=ON` (warnings-as-errors, on by default),
`-DCYTADEL_SANITIZE=ON` (ASan+UBSan), `-DCYTADEL_TSAN=ON` (ThreadSanitizer).

## Usage

Cytadel keeps its CVE data in a local SQLite DB. Configure paths and the
(optional but recommended) NVD API key via environment — copy
[`.env.example`](.env.example) to `.env`; **never commit `.env`**.

```sh
cp .env.example .env       # then set CYTADEL_DB_PATH, and CYTADEL_NVD_API_KEY if you have one

# 1. Populate/refresh the local vulnerability database from NVD/KEV/EPSS:
cytadel-scan sync --db "$CYTADEL_DB_PATH"

# 2. Scan (authorization is mandatory — the scan is refused without it):
cytadel-scan --i-am-authorized --ports 1-1024 10.0.0.0/24

# 3. Render the most recent scan as a branded report:
cytadel-scan report --latest --format html -o report.html
cytadel-scan report --latest --format json           # machine-readable
```

Run `cytadel-scan --help` for the full option set (`--targets-file`,
`--skip-discovery`, `--max-workers`, `--connect-timeout-ms`, `--plugins-dir`,
`--no-banner`, …).

## Testing

```sh
cmake -S . -B build -DBUILD_TESTING=ON
cmake --build build -j"$(nproc)"
ctest --test-dir build -L unit --output-on-failure
```

Docker-backed end-to-end integration tests (which drive the disposable
vulnerable target) are gated behind `-DCYTADEL_ENABLE_INTEGRATION_TESTS=ON` and
`ctest -L integration`, so a plain unit run needs no Docker. CI
([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs the unit matrix
(Debug/-Werror, Release, ASan+UBSan, TSan) plus the integration job.

## The bundled Docker target is **test-only**

[`docker/`](docker/README.md) defines a **disposable, deliberately
misconfigured, detection-only** environment that exists solely to exercise
Cytadel's stock plugins in the integration tests. It runs on an `internal: true`
Docker network with **no published host ports** and **no real credentials**, and
must **never** be deployed, exposed, or reused outside the test harness.

## Documentation

| Doc | What's in it |
|---|---|
| [AUTHORIZED_USE.md](AUTHORIZED_USE.md) | Detection-only posture, authorization requirement, legal notice |
| [docs/architecture.md](docs/architecture.md) | Engine/plugin/DB/report architecture overview |
| [docs/plugin-authoring.md](docs/plugin-authoring.md) | Writing new Lua detection plugins |
| [docs/contracts/](docs/contracts/) | Frozen contracts: CPE matching, DB schema, KB schema, plugin API |
| [plugins/README.md](plugins/README.md) | Catalogue of the stock detection plugins |
| [packaging/README.md](packaging/README.md) | Packaging, systemd sync scheduling, secret handling |
| [docker/README.md](docker/README.md) | The test-only vulnerable target |

## Security & secrets

Secrets (the NVD API key) come from environment variables or a gitignored
`.env` — never hardcoded, never committed. The live-sync key belongs in an
operator-supplied, root-readable systemd `EnvironmentFile`, never in CI (see
[`packaging/README.md`](packaging/README.md)).

## License

See [`AUTHORIZED_USE.md`](AUTHORIZED_USE.md) for use terms and the no-warranty
notice.
