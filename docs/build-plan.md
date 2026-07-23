# Cytadel Scan — CMake Build Plan

**Status: PLAN, not the build itself.** This describes how the CMake
build will be structured for Milestone 1 onward. No `CMakeLists.txt` is
written yet. `the engine work` implements against this plan; deviations should
be called out and, if structural, reconciled back into this document.

---

## 1. Top-level layout

```
CMakeLists.txt                     # top-level: project(), options, subdirectories
cmake/
  FindPCAP.cmake                   # custom find module (no bundled CMake module for libpcap)
  CompilerWarnings.cmake           # -Wall -Wextra -Wpedantic (+ optional -Werror) as a fragment
  Sanitizers.cmake                 # CYTADEL_SANITIZE wiring
include/cytadel/
  core/            *.h             # public headers for src/core
  db/              *.h             # public headers for src/db
  kb/              *.h             # public headers for src/kb
  net/             *.h             # public headers for src/net
  plugin/          *.h             # public headers for src/plugin
  report/          *.h             # public headers for src/report
src/
  cli/     CMakeLists.txt + *.c    # cytadel-scan executable sources (main() lives here)
  core/    CMakeLists.txt + *.c    # scan engine / scheduler
  db/      CMakeLists.txt + *.c    # SQLite access layer
  kb/      CMakeLists.txt + *.c    # knowledge-base store (docs/contracts/kb-schema.md)
  log/     CMakeLists.txt + *.c    # logging (internal-only, see note below)
  net/     CMakeLists.txt + *.c    # sockets, port scanning, TLS inspection, pcap fallback
  plugin/  CMakeLists.txt + *.c    # Lua VM embedding, plugin loader/scheduler, Lua API bindings
  report/  CMakeLists.txt + *.c    # report generation (consumes templates/)
plugins/           *.lua           # data files — NOT compiled, installed alongside the binary
templates/         *.html, ...     # report templates — data files, installed alongside the binary
config/            *.conf, ...     # default runtime config — data files
tests/
  unit/        CMakeLists.txt + *.c
  plugins/     CMakeLists.txt + *.lua / *.c harness
  integration/ CMakeLists.txt + *.c / *.sh
```

Each `src/<module>/` and `tests/<kind>/` directory gets its own small
`CMakeLists.txt` (`add_subdirectory()`'d from the top level), matching
the "many small files, high cohesion" style already used in the repo
scaffold rather than one monolithic top-level file that lists every
source.

**Observation for `the engine work` to confirm**: `src/cli` and `src/log` have
no corresponding `include/cytadel/cli/` or `include/cytadel/log/`
directory in the current scaffold. That appears intentional —
`src/cli` is the executable entry point (`main()`), which by definition
has no public API for other modules to consume, and `src/log` looks
like a small internal-only utility. If `plugin`, `report`, or other
modules need to call logging functions across a library boundary,
either (a) `log.h` should live under `include/cytadel/core/` or a new
`include/cytadel/log/`, or (b) `log/` stays a private header included
directly via a relative/target-level include path (`target_include_
directories(... PRIVATE src/log)`), not part of the public
`include/cytadel/**` surface. This plan assumes (b) — logging is an
engine-internal concern, not part of the public library surface — but
flags it for confirmation since it affects whether `include/cytadel/
log/` needs to be created.

---

## 2. Dependencies

| Dependency | Hard/Optional | Discovery mechanism | Imported target | Notes |
|---|---|---|---|---|
| OpenSSL | Hard | `find_package(OpenSSL REQUIRED)` | `OpenSSL::SSL`, `OpenSSL::Crypto` | Bundled `FindOpenSSL.cmake` has provided these imported targets since CMake 3.4. Used by `net/` (TLS inspection) and possibly `db/`/`net/` for hashing. |
| SQLite3 | Hard | `find_package(SQLite3 REQUIRED)` | `SQLite3::SQLite3` | Bundled `FindSQLite3.cmake` has provided this imported target since CMake 3.14. Used by `db/` for the local vuln DB (`the schema work`'s schema). |
| Lua 5.4 | Hard | `find_package(Lua 5.4 REQUIRED)`, version-checked | **No imported target** (see note below) | Bundled `FindLua.cmake` sets `LUA_INCLUDE_DIR`, `LUA_LIBRARIES`, `LUA_VERSION_STRING`, `LUA_FOUND` but — unlike OpenSSL/CURL/SQLite3 — does **not** create an `IMPORTED` target as of current CMake releases. We wrap it ourselves: after `find_package`, verify `LUA_VERSION_STRING` starts with `5.4` (the module can pick up a stray Lua 5.1/5.3 installed on the same system if not version-pinned), then `add_library(Lua::Lua INTERFACE IMPORTED)` and set its `INTERFACE_INCLUDE_DIRECTORIES` / `INTERFACE_LINK_LIBRARIES` from `LUA_INCLUDE_DIR` / `LUA_LIBRARIES` so the rest of the build links against `Lua::Lua` consistently with every other dependency. `the engine work` should re-verify this against the actual CMake version installed in CI before relying on it. |
| libcurl | Hard | `find_package(CURL REQUIRED)` | `CURL::libcurl` | Bundled `FindCURL.cmake` has provided this imported target since CMake 3.12; curl's own `CURLConfig.cmake` (if `find_package(CURL CONFIG)` resolves instead) also exports the same target name. Used by `net/` for `http_get` and any outbound HTTP(S) probing that isn't raw-socket. |
| pthreads | Hard | `set(THREADS_PREFER_PTHREAD_FLAG ON)` then `find_package(Threads REQUIRED)` | `Threads::Threads` | Used by `core/` for the per-host worker pool. |
| libpcap | **Optional** | No bundled CMake `FindPCAP` module exists. Try `pkg_check_modules(PCAP IMPORTED_TARGET libpcap)` first (modern libpcap ≥ 1.9 ships a `libpcap.pc`); if that fails, fall back to a hand-written `cmake/FindPCAP.cmake` doing `find_path(PCAP_INCLUDE_DIR pcap.h)` / `find_library(PCAP_LIBRARY NAMES pcap)` and wrapping the result in `PCAP::PCAP` (`INTERFACE IMPORTED`, matching the same target-name convention as the other deps). | `PCAP::PCAP` | Optional: if not found, `net/` compiles with `CYTADEL_HAVE_PCAP=0` and the port-scanner falls back to a plain TCP-connect scan instead of a raw-socket SYN scan. This also covers the case where pcap is *present* but the process lacks `CAP_NET_RAW`/root at runtime — that is a **runtime** fallback check in `net/`, not a build-time one; the build only decides whether the raw-socket code path is compiled in at all. |

General dependency policy:

- Every `find_package(... REQUIRED)` for a hard dependency happens once,
  at the top level, before `add_subdirectory(src)`, so a missing
  dependency fails configuration immediately with a clear CMake error
  rather than a late, confusing link error inside a leaf module.
- Every module `target_link_libraries`s only the imported targets it
  actually uses (e.g. `db` links `SQLite3::SQLite3`, not `Lua::Lua`) —
  no blanket "link everything into everything."
- `CYTADEL_HAVE_PCAP` (and any other optional-dependency flag) is
  exposed to C code via `target_compile_definitions`, not a generated
  header, to keep the option visible directly in each module's
  `CMakeLists.txt`.

---

## 3. Compiler flags

- `set(CMAKE_C_STANDARD 11)`, `set(CMAKE_C_STANDARD_REQUIRED ON)`,
  `set(CMAKE_C_EXTENSIONS OFF)` at the top level — strict C11, no GNU
  extensions leaking in silently.
- `cmake/CompilerWarnings.cmake` defines an `INTERFACE` library
  (e.g. `cytadel_warnings`) carrying `-Wall -Wextra -Wpedantic` for
  GCC/Clang (guarded by `CMAKE_C_COMPILER_ID`), applied to every
  first-party target via `target_link_libraries(<target> PRIVATE
  cytadel_warnings)`. Third-party code (none vendored at this stage) is
  never built with these flags.
- `option(CYTADEL_WERROR "Treat warnings as errors" ON)` — defaults ON
  since the project's engineering policy requires a clean `-Wall -Wextra` build at every
  milestone gate; adds `-Werror` to `cytadel_warnings` when enabled. Can
  be turned off locally (`-DCYTADEL_WERROR=OFF`) for exploratory work,
  but CI always builds with it ON.
- `option(CYTADEL_SANITIZE "Build with ASan+UBSan" OFF)` — when ON (and
  only for GCC/Clang, only meaningful in `Debug`/`RelWithDebInfo`),
  `cmake/Sanitizers.cmake` adds `-fsanitize=address,undefined
  -fno-omit-frame-pointer -g` to both compile and link flags of an
  `INTERFACE` library (`cytadel_sanitizers`), linked into every target
  the same way as `cytadel_warnings`. Not combined with `CYTADEL_WERROR`
  sanitizer runtime warnings by default (ASan/UBSan diagnostics are
  runtime, not compiler warnings, so they're orthogonal to `-Werror`).
- No `-Wall -Wextra -Wpedantic` / sanitizer flags are applied to Lua,
  OpenSSL, SQLite3, or curl themselves — those are pre-built system
  libraries, not first-party sources we compile.

---

## 4. Target layout

- **`libcytadel` (STATIC)** — one static library built from `src/core`,
  `src/kb`, `src/net`, `src/plugin`, `src/db`, `src/report`, `src/log`.
  This is where essentially all engine logic lives, so it's unit- and
  integration-testable independent of `main()`.
  - Each `src/<module>/CMakeLists.txt` declares an `OBJECT` or plain
    source list consumed by the top-level `libcytadel` target (exact
    choice — one big `add_library(cytadel STATIC ...)` aggregating
    per-module `target_sources()` calls, vs. one static lib per module
    linked together — is an implementation detail `the engine work` decides at
    Milestone 1 kickoff; either is consistent with this plan as long as
    the public headers stay under `include/cytadel/<module>/`).
- **`cytadel-scan` (executable)** — `src/cli/*.c` (including `main()`)
  linked against `libcytadel`. This is the only target that owns
  `main()`; `libcytadel` never does, so it stays link-testable from
  `tests/`.
- **Plugins are data, not a target.** `plugins/*.lua` are never passed
  to `add_executable`/`add_library`. They are staged via
  `install(DIRECTORY plugins/ DESTINATION share/cytadel/plugins
  FILES_MATCHING PATTERN "*.lua")` (or copied into the build tree for
  in-tree test runs via `file(COPY ...)` / `configure_file`) so the
  engine loads them at runtime through the plugin loader in `src/plugin`.
  This is the CMake-level enforcement of the engine/plugin separation
  rule in the project's engineering policy — there is no code path by which a plugin ends up
  statically linked into `cytadel-scan`.
- **`templates/` and `config/`** are likewise data, installed via their
  own `install(DIRECTORY ...)` rules, not compiled.
- **Test runner** — no new external test-framework dependency is
  introduced (the frozen dependency list is libpcap, OpenSSL, Lua,
  libcurl, SQLite3, pthreads; adding e.g. CMocka/Unity would be an
  unlisted dependency). Instead: a small header-only assertion helper
  (e.g. `tests/unit/cytadel_test.h`, to be written in Milestone 1, not
  now) provides `CYTADEL_ASSERT`/`CYTADEL_ASSERT_EQ`-style macros that
  `exit(1)` on failure. Each test source file compiles to its own small
  executable (`add_executable(test_kb_store test_kb_store.c)` linked
  against `libcytadel`), and each is registered individually with
  `add_test()`. This keeps failures isolated (one crashing test binary
  doesn't take down the whole suite) and matches the "many small files"
  convention. `the engine work` should revisit this choice if the suite grows
  large enough that a shared-process test runner becomes worthwhile.

---

## 5. CTest wiring

- Top-level `CMakeLists.txt` calls `enable_testing()` (or
  `include(CTest)` if we later want `CDash`/`BUILD_TESTING` toggling)
  before `add_subdirectory(tests)`.
- `tests/unit/CMakeLists.txt`, `tests/plugins/CMakeLists.txt`, and
  `tests/integration/CMakeLists.txt` each register their own tests via
  `add_test(NAME <test-name> COMMAND <test-executable>)`, then tag them:
  `set_tests_properties(<test-name> PROPERTIES LABELS "unit")` (or
  `"plugin"` / `"integration"`), so `ctest -L unit` / `-L plugin` /
  `-L integration` can run subsets independently — matters because
  integration tests likely need the Docker test target (`the ops work`)
  and shouldn't block a fast local `ctest -L unit` loop.
- `tests/plugins/` tests exercise the Lua plugin loader/scheduler and
  stock plugins against a fake/mock KB and mock network layer (owned by
  `the plugin work` + `the engine work` jointly) — these are still C test executables
  (embedding the Lua VM the same way the engine does) that load a
  `.lua` file from `plugins/` or a `tests/plugins/fixtures/` directory,
  not a separate non-CTest harness.
- `tests/integration/` tests that require a live network target (the
  Docker-based vulnerable test target owned by `the ops work`) are
  gated behind `option(CYTADEL_ENABLE_INTEGRATION_TESTS "Run tests that
  require the Docker test target" OFF)` so a plain `ctest` run in an
  environment without Docker doesn't fail on unavailable infrastructure;
  CI enables it explicitly where Docker is available.
- A plain `ctest --output-on-failure` (with `CYTADEL_ENABLE_INTEGRATION_
  TESTS=OFF`) is the Milestone-1 baseline gate before the security review
  review, per the project's engineering policy's "each must compile, pass its tests" rule.

---

## 6. Confirmed directory layout (as scaffolded today)

```
assets/brand/
cmake/
config/
docker/
docs/contracts/
include/cytadel/core/
include/cytadel/db/
include/cytadel/kb/
include/cytadel/net/
include/cytadel/plugin/
include/cytadel/report/
plugins/
scripts/
src/cli/
src/core/
src/db/
src/kb/
src/log/
src/net/
src/plugin/
src/report/
templates/
tests/integration/
tests/plugins/
tests/unit/
```

All directories above already exist (currently empty except for
top-level `.env.example`, `.gitignore`, the project's engineering policy). This plan does not
introduce any new top-level directory; `cmake/` already exists and is
where `FindPCAP.cmake`, `CompilerWarnings.cmake`, and `Sanitizers.cmake`
will live per §1/§3 above.

---

## 7. Open items for `the engine work` to confirm at Milestone 1 kickoff

1. Verify `FindLua.cmake`'s imported-target behavior (§2) against the
   actual CMake version pinned for this project/CI — if a newer CMake
   has since added `Lua::Lua`, prefer the built-in target and drop the
   manual wrapper.
2. Verify libpcap's `.pc` availability on the target CI/build image
   (Debian/Ubuntu vs. Alpine vs. others) to decide whether the
   pkg-config path or the hand-written `FindPCAP.cmake` path is primary
   in practice — both should still be implemented so the build degrades
   gracefully either way.
3. Decide `libcytadel`'s internal composition (single `add_library`
   aggregating all module sources vs. one static lib per module) — both
   are compatible with this plan; pick whichever keeps incremental
   rebuild times reasonable given the module count.
4. Confirm the `src/log` / `include/cytadel/log` public-vs-private
   header question raised in §1.
