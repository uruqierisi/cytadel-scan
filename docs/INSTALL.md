# Cytadel Scan — Installation & Usage Guide

A step-by-step walkthrough: install the build dependencies, compile the scanner,
build its vulnerability database, run an authorized scan, and read the report.

> **Before you begin — read this.** Cytadel is **detection-only** and refuses to
> scan any target until you affirm you are authorized. Only scan systems you own
> or have **explicit written permission** to test. See
> [`AUTHORIZED_USE.md`](../AUTHORIZED_USE.md).

**Supported platform:** Linux (first-class). On Windows use **WSL2** (Ubuntu);
on macOS build inside a Linux VM/container. The commands below assume a
Debian/Ubuntu shell — notes for other distros are inline.

---

## Step 1 — Install the build dependencies

Cytadel needs a C11 compiler, CMake, and the dev packages for OpenSSL, Lua 5.4,
and libcurl.

**Debian / Ubuntu / WSL:**

```sh
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config git ca-certificates \
    liblua5.4-dev libssl-dev libcurl4-openssl-dev
```

**Fedora / RHEL / CentOS Stream:**

```sh
sudo dnf install -y gcc cmake pkgconf git openssl-devel compat-lua-devel libcurl-devel
```

**Arch:**

```sh
sudo pacman -S --needed base-devel cmake git openssl lua54 curl
```

Verify the toolchain is present (CMake ≥ 3.16, any recent GCC/Clang):

```sh
cmake --version
cc --version
```

---

## Step 2 — Get the source

```sh
git clone https://github.com/uruqierisi/cytadel-scan.git
cd cytadel-scan
```

---

## Step 3 — Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j"$(nproc)"
```

The build discovers a system libcurl/OpenSSL/Lua automatically. If you keep a
dependency in a non-standard prefix, point CMake at it:

- vendored libcurl: `-DCYTADEL_CURL_ROOT=/path/to/curl` (or pass
  `-DCYTADEL_CURL_INCLUDE_DIR=… -DCYTADEL_CURL_LIBRARY=…` explicitly),
- vendored Lua: `-DCYTADEL_LUA_ROOT=/path/to/lua`,
- vendored OpenSSL: `-DOPENSSL_ROOT_DIR=/path/to/openssl`.

The scanner binary is produced at **`build/src/cli/cytadel-scan`**. (There is no
`make install` step — Cytadel runs straight from the build tree.)

---

## Step 4 — Verify the build

Run the unit test suite (should report `100% tests passed out of 57`):

```sh
ctest --test-dir build -L unit --output-on-failure
```

Confirm the binary runs:

```sh
./build/src/cli/cytadel-scan --version      # -> cytadel-scan 0.1.0
./build/src/cli/cytadel-scan --help         # full option list
```

**Optional — make it convenient to call.** Either add it to your `PATH` for this
shell:

```sh
export PATH="$PWD/build/src/cli:$PATH"
# now just: cytadel-scan --help
```

…or install a symlink system-wide:

```sh
sudo ln -sf "$PWD/build/src/cli/cytadel-scan" /usr/local/bin/cytadel-scan
```

> **Run scans from the repository root.** By default Cytadel loads its detection
> plugins from `./plugins`. If you run it from elsewhere, pass
> `--plugins-dir /full/path/to/cytadel-scan/plugins`.

---

## Step 5 — Configure the environment

Cytadel reads its configuration (database location, optional NVD API key) from
environment variables. Copy the template and fill it in:

```sh
cp .env.example .env
```

Edit `.env`:

```ini
# Where the local vulnerability database lives (created in the next step).
CYTADEL_DB_PATH=./data/cytadel-vuln.sqlite

# Optional but recommended: raises the NVD rate limit. Get one free at
# https://nvd.nist.gov/developers/request-an-api-key  — never commit this file.
CYTADEL_NVD_API_KEY=
```

Load it into your shell (the binary reads real environment variables, so the
`.env` must be exported — it is **not** auto-loaded):

```sh
set -a; . ./.env; set +a
mkdir -p "$(dirname "$CYTADEL_DB_PATH")"
```

`.env` is gitignored — **never commit it or your API key.**

---

## Step 6 — Build the vulnerability database

`sync` pulls CVE data from NVD (enriched with CISA KEV and FIRST EPSS) into the
local SQLite DB. This needs outbound internet access. The first full sync can
take a while; an API key makes it much faster.

```sh
cytadel-scan sync --db "$CYTADEL_DB_PATH"
```

It prints how many windows/pages/CVEs were ingested and advances a watermark, so
re-running later only fetches what changed. Schedule it to run periodically with
the systemd units in [`packaging/`](../packaging/README.md).

---

## Step 7 — Run your first scan

Scanning is **refused** unless you affirm authorization — either interactively
(when your terminal is attached) or with `--i-am-authorized`.

Scan a single host's common ports:

```sh
cytadel-scan --i-am-authorized --ports 1-1024 192.0.2.10
```

Other target forms and useful flags:

```sh
# A whole /24, with an operator name recorded in the authorization audit line:
cytadel-scan --i-am-authorized --authorized-by "you@example.com" 192.0.2.0/24

# A comma-separated mix, and a list read from a file:
cytadel-scan --i-am-authorized "192.0.2.1,192.0.2.0/30,host.example.com"
cytadel-scan --i-am-authorized --targets-file targets.txt

# Skip host discovery (treat every target as up), verbose logging:
cytadel-scan --i-am-authorized --skip-discovery --log-level debug 192.0.2.10
```

Every scan is recorded in `CYTADEL_DB_PATH` (the affirmation is written to the
audit log). Run `cytadel-scan --help` for the full flag set (`--max-workers`,
`--connect-timeout-ms`, `--discovery-timeout-ms`, `--plugins-dir`,
`--no-banner`, …).

---

## Step 8 — Generate a report

Render the most recent scan as a self-contained, branded HTML file:

```sh
cytadel-scan report --latest --format html -o report.html
xdg-open report.html          # or open it in any browser
```

Or emit machine-readable JSON (to stdout, or a file with `-o`):

```sh
cytadel-scan report --latest --format json
cytadel-scan report --scan-id 3 --format json -o scan-3.json
```

`report` reads `CYTADEL_DB_PATH`; use `--latest` for the newest scan or
`--scan-id N` for a specific one.

---

## Putting it together

A complete session from a clean checkout:

```sh
git clone https://github.com/uruqierisi/cytadel-scan.git && cd cytadel-scan
sudo apt-get install -y build-essential cmake pkg-config git \
    liblua5.4-dev libssl-dev libcurl4-openssl-dev
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build -j"$(nproc)"
export PATH="$PWD/build/src/cli:$PATH"
cp .env.example .env && set -a; . ./.env; set +a
mkdir -p "$(dirname "$CYTADEL_DB_PATH")"
cytadel-scan sync --db "$CYTADEL_DB_PATH"
cytadel-scan --i-am-authorized --ports 1-1024 192.0.2.10
cytadel-scan report --latest --format html -o report.html
```

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `libcurl not found` at configure | Install `libcurl4-openssl-dev` (Debian) / `libcurl-devel` (Fedora), or pass `-DCYTADEL_CURL_ROOT=…`. |
| `Cytadel requires Lua 5.4; found 5.x` | Install `liblua5.4-dev` specifically; a stray Lua 5.1/5.3 was picked up. Point CMake at 5.4 with `-DCYTADEL_LUA_ROOT=…`. |
| `refused: … --i-am-authorized was not provided` | Working as designed. Add `--i-am-authorized` (or run in an interactive terminal and confirm the prompt). |
| `CYTADEL_DB_PATH is not set` on scan/report | You didn't load `.env` into the shell. Run `set -a; . ./.env; set +a`. |
| Scan runs but finds nothing / no CVE matches | Run `cytadel-scan sync` first — an empty DB has nothing to match against. |
| No plugins loaded | Run from the repo root, or pass `--plugins-dir /path/to/cytadel-scan/plugins`. |

---

## Trying it safely against the bundled test target

The repository ships a **disposable, test-only** vulnerable environment you can
scan without touching any real system. It runs on an isolated internal Docker
network with no published ports. See [`docker/README.md`](../docker/README.md)
for how to bring it up and scan it — this is the intended way to see Cytadel
produce real findings end-to-end on your own machine.

---

## More documentation

- [Architecture overview](architecture.md)
- [Writing detection plugins](plugin-authoring.md)
- [Frozen data contracts](contracts/) — CPE matching, DB/KB schema, plugin API
- [Stock plugin catalogue](../plugins/README.md)
- [Packaging & scheduled sync](../packaging/README.md)
