# Each unit test compiles to its own small executable and is registered
# individually with add_test(), labeled "unit" (docs/build-plan.md §4/§5).
# A crashing test binary never takes down the whole suite.

add_executable(test_cli_args test_cli_args.c)
target_link_libraries(test_cli_args PRIVATE cytadel_cli_core cytadel cytadel_warnings)
add_test(NAME test_cli_args COMMAND test_cli_args)
set_tests_properties(test_cli_args PROPERTIES LABELS "unit")

add_executable(test_auth_gate test_auth_gate.c)
target_link_libraries(test_auth_gate PRIVATE cytadel_cli_core cytadel cytadel_warnings)
add_test(NAME test_auth_gate COMMAND test_auth_gate)
set_tests_properties(test_auth_gate PROPERTIES LABELS "unit")

add_executable(test_log test_log.c)
target_link_libraries(test_log PRIVATE cytadel cytadel_warnings)
add_test(NAME test_log COMMAND test_log)
set_tests_properties(test_log PROPERTIES LABELS "unit")

# Milestone 2: src/net (target parsing, port-range parsing, discovery
# decision logic, single-host TCP connect port scanning).
add_executable(test_target test_target.c)
target_link_libraries(test_target PRIVATE cytadel cytadel_warnings)
add_test(NAME test_target COMMAND test_target)
set_tests_properties(test_target PROPERTIES LABELS "unit")

add_executable(test_port_range test_port_range.c)
target_link_libraries(test_port_range PRIVATE cytadel cytadel_warnings)
add_test(NAME test_port_range COMMAND test_port_range)
set_tests_properties(test_port_range PROPERTIES LABELS "unit")

add_executable(test_discovery test_discovery.c)
target_link_libraries(test_discovery PRIVATE cytadel cytadel_warnings)
add_test(NAME test_discovery COMMAND test_discovery)
set_tests_properties(test_discovery PROPERTIES LABELS "unit")

# Loopback integration-style unit test: binds real ephemeral TCP sockets on
# 127.0.0.1, no external network / fixed ports required.
add_executable(test_port_scanner test_port_scanner.c)
target_link_libraries(test_port_scanner PRIVATE cytadel cytadel_warnings)
add_test(NAME test_port_scanner COMMAND test_port_scanner)
set_tests_properties(test_port_scanner PROPERTIES LABELS "unit")

# Security-review fix regression: host_scan.c's host/ip copy into
# cytadel_host_result_t used strncpy() with n == sizeof(dest) - 1 (a
# same-sized-buffer copy GCC's -Wstringop-truncation can't prove is safe at
# -O2/Release), replaced with the strnlen()+memcpy() idiom target.c already
# uses. This proves the boundary (max-length host/ip) still copies
# byte-for-byte with no silent truncation.
add_executable(test_host_scan test_host_scan.c)
target_link_libraries(test_host_scan PRIVATE cytadel cytadel_warnings)
add_test(NAME test_host_scan COMMAND test_host_scan)
set_tests_properties(test_host_scan PROPERTIES LABELS "unit")

# Milestone 3: multi-target expansion (CIDR math, comma lists,
# --targets-file) and the src/core worker pool.
add_executable(test_cidr test_cidr.c)
target_link_libraries(test_cidr PRIVATE cytadel cytadel_warnings)
add_test(NAME test_cidr COMMAND test_cidr)
set_tests_properties(test_cidr PROPERTIES LABELS "unit")

add_executable(test_target_list test_target_list.c)
target_link_libraries(test_target_list PRIVATE cytadel cytadel_warnings)
add_test(NAME test_target_list COMMAND test_target_list)
set_tests_properties(test_target_list PROPERTIES LABELS "unit")

# Security-review fix regression: targets_file.c's fgets() buffer off-by-one
# (a max-length content line was incorrectly rejected).
add_executable(test_targets_file test_targets_file.c)
target_link_libraries(test_targets_file PRIVATE cytadel cytadel_warnings)
add_test(NAME test_targets_file COMMAND test_targets_file)
set_tests_properties(test_targets_file PROPERTIES LABELS "unit")

# These two test binaries call pthread_create()/pthread_join() directly
# (spawning worker threads / hammering the logger themselves), so unlike
# the rest of tests/unit they link Threads::Threads explicitly rather than
# relying solely on it riding in via `cytadel` (build-plan.md §2's "each
# module links only what it uses" policy, applied to the module that is
# the test binary itself here).
add_executable(test_worker_pool test_worker_pool.c)
target_link_libraries(test_worker_pool PRIVATE cytadel cytadel_warnings Threads::Threads)
add_test(NAME test_worker_pool COMMAND test_worker_pool)
set_tests_properties(test_worker_pool PROPERTIES LABELS "unit")

add_executable(test_log_thread_safety test_log_thread_safety.c)
target_link_libraries(test_log_thread_safety PRIVATE cytadel cytadel_warnings Threads::Threads)
add_test(NAME test_log_thread_safety COMMAND test_log_thread_safety)
set_tests_properties(test_log_thread_safety PROPERTIES LABELS "unit")

# Milestone 4: src/kb (docs/contracts/kb-schema.md, FROZEN CONTRACT).
add_executable(test_kb test_kb.c)
target_link_libraries(test_kb PRIVATE cytadel cytadel_warnings)
add_test(NAME test_kb COMMAND test_kb)
set_tests_properties(test_kb PROPERTIES LABELS "unit")

# Milestone 7 slice 1: src/db (docs/contracts/db-schema.md, FROZEN
# CONTRACT). Calls sqlite3_prepare_v2()/bind/step directly against
# cytadel_db_handle()'s raw connection (db-schema.md SS9's query patterns),
# so -- like test_tls_inspect.c linking OpenSSL::SSL/Crypto directly and
# test_plugin_lua_embed.c linking Lua::Lua directly -- this links
# cytadel_sqlite3 explicitly in addition to `cytadel` (build-plan.md §2's
# "the module that needs it links it" policy, applied to the test binary
# itself here) rather than relying on it riding in transitively (src/db
# links cytadel_sqlite3 PRIVATE).
add_executable(test_db test_db.c)
target_link_libraries(test_db PRIVATE cytadel cytadel_warnings cytadel_sqlite3)
add_test(NAME test_db COMMAND test_db)
set_tests_properties(test_db PROPERTIES LABELS "unit")

# Milestone 7 slice 2: src/db/nvd_ingest.c (defensive NVD 2.0 CVE JSON
# ingest). Calls sqlite3_prepare_v2()/bind/step directly against
# cytadel_db_handle()'s raw connection (same reasoning as test_db.c above),
# so links cytadel_sqlite3 explicitly. Also links cytadel_cjson explicitly
# since the hostile-JSON fixtures below are built with cJSON's own C API
# (cJSON_CreateObject()/cJSON_Print() etc.) rather than hand-written JSON
# string literals, for the same "the module that needs it links it" policy
# (build-plan.md §2) applied to this test binary itself.
add_executable(test_nvd_ingest test_nvd_ingest.c)
target_link_libraries(test_nvd_ingest PRIVATE cytadel cytadel_warnings cytadel_sqlite3 cytadel_cjson)
add_test(NAME test_nvd_ingest COMMAND test_nvd_ingest)
set_tests_properties(test_nvd_ingest PROPERTIES LABELS "unit")

# Milestone 7 live NVD fetch: transport (nvd_fetch.c) + pagination/watermark
# driver (nvd_sync.c), driven against a loopback fixture HTTP server. libcurl
# is pulled in transitively through `cytadel` (Curl::Curl linked PRIVATE
# there); sqlite3 header + Threads are direct needs of the test itself.
add_executable(test_nvd_sync test_nvd_sync.c)
target_link_libraries(test_nvd_sync PRIVATE cytadel cytadel_warnings cytadel_sqlite3 Threads::Threads)
add_test(NAME test_nvd_sync COMMAND test_nvd_sync)
set_tests_properties(test_nvd_sync PROPERTIES LABELS "unit")

# Milestone 4: service/banner detection (src/net's banner_grab.c/svc_*.c/
# http_probe.c/cpe_map.c via the public cytadel_service_detect_port()
# entry point). Loopback fixtures spawn their own accept()/respond threads
# (same reasoning as test_worker_pool/test_log_thread_safety above), so
# this links Threads::Threads explicitly.
add_executable(test_service_detect test_service_detect.c)
target_link_libraries(test_service_detect PRIVATE cytadel cytadel_warnings Threads::Threads)
add_test(NAME test_service_detect COMMAND test_service_detect)
set_tests_properties(test_service_detect PROPERTIES LABELS "unit")

# Milestone 4: TLS inspection (src/net's tls_session.c/tls_inspect.c).
# Generates an ephemeral self-signed cert and runs a real in-process
# OpenSSL TLS server on a loopback fixed port, so -- like test_tls_inspect
# calling OpenSSL's own certificate/key-generation API directly -- this
# links OpenSSL::SSL/OpenSSL::Crypto explicitly in addition to
# Threads::Threads (same "module that needs it links it" policy as
# src/net/CMakeLists.txt, applied to the test binary itself here).
add_executable(test_tls_inspect test_tls_inspect.c)
target_link_libraries(test_tls_inspect PRIVATE cytadel cytadel_warnings Threads::Threads
    OpenSSL::SSL OpenSSL::Crypto)
add_test(NAME test_tls_inspect COMMAND test_tls_inspect)
set_tests_properties(test_tls_inspect PROPERTIES LABELS "unit")

# Security-review fix regression: cytadel_strerror_safe() (src/log/strerror_safe.c)
# replaces strerror()'s data race across worker-pool threads. Links
# Threads::Threads directly (same reasoning as test_worker_pool/
# test_log_thread_safety above) since it spawns its own threads to hammer
# the helper concurrently.
add_executable(test_strerror_safe test_strerror_safe.c)
target_link_libraries(test_strerror_safe PRIVATE cytadel cytadel_warnings Threads::Threads)
add_test(NAME test_strerror_safe COMMAND test_strerror_safe)
set_tests_properties(test_strerror_safe PROPERTIES LABELS "unit")

# Milestone 5 Part 1: src/plugin's Lua 5.4 embedding (docs/contracts/
# plugin-api.md, FROZEN CONTRACT). This test calls the Lua C API directly
# (luaL_newstate/luaL_dostring/lua_close) in addition to exercising
# src/plugin's own smoke helper, so -- like test_tls_inspect linking
# OpenSSL::SSL/OpenSSL::Crypto directly -- it links Lua::Lua explicitly
# itself (build-plan.md §2's "the module that needs it links it" policy,
# applied to the test binary itself here) rather than relying solely on it
# riding in transitively via `cytadel` (src/plugin links Lua::Lua PRIVATE).
add_executable(test_plugin_lua_embed test_plugin_lua_embed.c)
target_link_libraries(test_plugin_lua_embed PRIVATE cytadel cytadel_warnings Lua::Lua)
add_test(NAME test_plugin_lua_embed COMMAND test_plugin_lua_embed)
set_tests_properties(test_plugin_lua_embed PROPERTIES LABELS "unit;plugin")

# Milestone 5 Part 2: registration phase (docs/contracts/plugin-api.md
# §4.1) against fixtures under tests/plugins/fixtures/ (never the real
# plugins/ directory -- see that directory's own header comment).
# CYTADEL_TEST_FIXTURES_DIR is an absolute path (not relative to whatever
# working directory ctest happens to run tests from) so these tests are
# location-independent.
add_executable(test_plugin_registry test_plugin_registry.c)
target_link_libraries(test_plugin_registry PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_registry PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_registry COMMAND test_plugin_registry)
set_tests_properties(test_plugin_registry PROPERTIES LABELS "unit;plugin")

# Milestone 5 Part 4: sandbox enforcement + _ENV isolation.
add_executable(test_plugin_sandbox test_plugin_sandbox.c)
target_link_libraries(test_plugin_sandbox PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_sandbox PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_sandbox COMMAND test_plugin_sandbox)
set_tests_properties(test_plugin_sandbox PROPERTIES LABELS "unit;plugin")

# Milestone 5 Part 4: scheduler (required_keys gating, service-wildcard
# dispatch, dependency order, report_vuln validation).
add_executable(test_plugin_scheduler test_plugin_scheduler.c)
target_link_libraries(test_plugin_scheduler PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_scheduler PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_scheduler COMMAND test_plugin_scheduler)
set_tests_properties(test_plugin_scheduler PROPERTIES LABELS "unit;plugin")

# Milestone 5 Part 3: socket API + http_get, against real loopback fixture
# servers -- spawns its own accept()/respond threads (same reasoning as
# test_worker_pool/test_service_detect above), so this links
# Threads::Threads explicitly.
add_executable(test_plugin_network test_plugin_network.c)
target_link_libraries(test_plugin_network PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_network PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_network COMMAND test_plugin_network)
set_tests_properties(test_plugin_network PROPERTIES LABELS "unit;plugin")

# Milestone 5 §4.5: runtime-limit hook. Inherently slow (~15s, the frozen
# contract's fixed default) -- kept in its own executable/test.
add_executable(test_plugin_runtime_limit test_plugin_runtime_limit.c)
target_link_libraries(test_plugin_runtime_limit PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_runtime_limit PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_runtime_limit COMMAND test_plugin_runtime_limit)
set_tests_properties(test_plugin_runtime_limit PROPERTIES LABELS "unit;plugin")

# --------------------------------------------------------------------- #
# Milestone 5 security-audit regression tests (post-Milestone-5 fixes).
# --------------------------------------------------------------------- #

# C1 (CRITICAL): HTTP request smuggling via an unvalidated http_get() path.
# Spawns its own accept() thread -- links Threads::Threads explicitly (same
# reasoning as test_plugin_network above).
add_executable(test_plugin_c1_http_smuggling test_plugin_c1_http_smuggling.c)
target_link_libraries(test_plugin_c1_http_smuggling PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_c1_http_smuggling PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_c1_http_smuggling COMMAND test_plugin_c1_http_smuggling)
set_tests_properties(test_plugin_c1_http_smuggling PROPERTIES LABELS "unit;plugin;security")

# W1: runtime-limit-bypass via an unbounded blocking timeout_ms. Inherently
# slow (~15s, bounded by the same frozen §4.5 default the fix clamps
# against) -- kept in its own executable/test, same reasoning as
# test_plugin_runtime_limit above.
add_executable(test_plugin_w1_timeout_clamp test_plugin_w1_timeout_clamp.c)
target_link_libraries(test_plugin_w1_timeout_clamp PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_w1_timeout_clamp PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_w1_timeout_clamp COMMAND test_plugin_w1_timeout_clamp)
set_tests_properties(test_plugin_w1_timeout_clamp PROPERTIES LABELS "unit;plugin;security")

# W2 (Lua-level half): the "cytadel.socket" metatable must be locked
# (__metatable) so getmetatable()/setmetatable() tampering cannot defeat
# __gc/__close.
add_executable(test_plugin_w2_metatable_lock test_plugin_w2_metatable_lock.c)
target_link_libraries(test_plugin_w2_metatable_lock PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_w2_metatable_lock PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_w2_metatable_lock COMMAND test_plugin_w2_metatable_lock)
set_tests_properties(test_plugin_w2_metatable_lock PROPERTIES LABELS "unit;plugin;security")

# W2 (engine-side half -- "the real guarantee"): invoke.c's fd tracker
# must force-close every leaked socket regardless of Lua-level
# __gc/__close, verified at scale (many iterations) via /proc/self/fd.
add_executable(test_plugin_w2_fd_force_close test_plugin_w2_fd_force_close.c)
target_link_libraries(test_plugin_w2_fd_force_close PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_w2_fd_force_close PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_w2_fd_force_close COMMAND test_plugin_w2_fd_force_close)
set_tests_properties(test_plugin_w2_fd_force_close PROPERTIES LABELS "unit;plugin;security")

# W3: report_vuln{} heap leak on a wrong-typed optional field, plugin-
# triggerable under pcall. "No heap growth" is verified by running this
# binary under the build-asan configuration (LeakSanitizer).
add_executable(test_plugin_w3_report_vuln_leak test_plugin_w3_report_vuln_leak.c)
target_link_libraries(test_plugin_w3_report_vuln_leak PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_w3_report_vuln_leak PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_w3_report_vuln_leak COMMAND test_plugin_w3_report_vuln_leak)
set_tests_properties(test_plugin_w3_report_vuln_leak PROPERTIES LABELS "unit;plugin;security")

# W4: http_get{}'s request buffer leaked on a wrong-typed opts.headers
# value, plugin-triggerable under pcall. Same "no heap growth via ASan"
# verification as W3 above.
add_executable(test_plugin_w4_http_headers_leak test_plugin_w4_http_headers_leak.c)
target_link_libraries(test_plugin_w4_http_headers_leak PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_w4_http_headers_leak PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_w4_http_headers_leak COMMAND test_plugin_w4_http_headers_leak)
set_tests_properties(test_plugin_w4_http_headers_leak PROPERTIES LABELS "unit;plugin;security")

# --------------------------------------------------------------------- #
# Security-review round-2 regression tests (post-round-2 fixes).
# --------------------------------------------------------------------- #

# FIX 1 (CRITICAL): invoke.c used to run the engine-side fd tracker's
# force-close sweep BEFORE lua_close(L), which could double-close a
# just-freed fd number a completely unrelated worker thread had, by then,
# already reused for a live connection. Races independent "victim" threads
# against the leak_never_close.lua fixture's own fd churn to reproduce
# that exact cross-thread fd-reuse window.
add_executable(test_plugin_fix1_double_close_race test_plugin_fix1_double_close_race.c)
target_link_libraries(test_plugin_fix1_double_close_race PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_fix1_double_close_race PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_fix1_double_close_race COMMAND test_plugin_fix1_double_close_race)
set_tests_properties(test_plugin_fix1_double_close_race PROPERTIES LABELS "unit;plugin;security")

# FIX 2 (CRITICAL): cytadel_plugin_clamp_timeout_ms() used to floor only
# the remaining §4.5 budget, never the caller's own timeout_ms, so
# timeout_ms = 0 could produce a block-forever {0,0} SO_RCVTIMEO timeval on
# Linux. Runs the invocation on its own thread with a short, bounded
# watchdog (pthread_cancel() on the recv(2) cancellation point if it fires)
# so a regression fails fast instead of hanging the suite.
add_executable(test_plugin_fix2_zero_timeout test_plugin_fix2_zero_timeout.c)
target_link_libraries(test_plugin_fix2_zero_timeout PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_fix2_zero_timeout PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_fix2_zero_timeout COMMAND test_plugin_fix2_zero_timeout)
set_tests_properties(test_plugin_fix2_zero_timeout PROPERTIES LABELS "unit;plugin;security")

# --------------------------------------------------------------------- #
# Security-review round-3 regression tests (post-round-3 fixes).
# --------------------------------------------------------------------- #

# C-1 (CRITICAL), fixture-based half: loader.c:63/invoke.c:157 used to be
# unprotected lua_getfield(L, env_idx, "run") lookups reachable outside any
# lua_pcall -- a plugin doing setmetatable(_ENV, {__index = ...}) with no
# run() defined could abort() the whole process. Proves registering the
# fixtures directory survives and a well-behaved sibling plugin still
# registers/runs normally. Short and bounded (no network I/O, no threads).
add_executable(test_plugin_r3c1_env_metatable_abort test_plugin_r3c1_env_metatable_abort.c)
target_link_libraries(test_plugin_r3c1_env_metatable_abort PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_r3c1_env_metatable_abort PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_r3c1_env_metatable_abort COMMAND test_plugin_r3c1_env_metatable_abort)
set_tests_properties(test_plugin_r3c1_env_metatable_abort PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# C-1 (CRITICAL), deterministic white-box half: proves
# cytadel_plugin_raw_getfield() (the fix applied at both loader.c:63 and
# invoke.c:157) itself never invokes a table's __index metamethod,
# independent of whether sandbox.c's separate __metatable lock on _ENV
# exists at all. No lua sandbox/network/threads involved.
add_executable(test_plugin_r3c1_raw_getfield test_plugin_r3c1_raw_getfield.c)
target_link_libraries(test_plugin_r3c1_raw_getfield PRIVATE cytadel cytadel_warnings)
add_test(NAME test_plugin_r3c1_raw_getfield COMMAND test_plugin_r3c1_raw_getfield)
set_tests_properties(test_plugin_r3c1_raw_getfield PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# W-1 (WARNING): cytadel_plugin_fd_tracker_is_closed() returning true for an
# UNTRACKED slot (track_idx == (size_t)-1, i.e. fd_tracker_add()'s own
# realloc() failed) used to be misread by cytadel_plugin_socket_close() as
# "already closed, skip close()" -- silently leaking that fd forever.
# Deterministic: no thread race, no network I/O.
add_executable(test_plugin_r3w1_untracked_fd_close test_plugin_r3w1_untracked_fd_close.c)
target_link_libraries(test_plugin_r3w1_untracked_fd_close PRIVATE cytadel cytadel_warnings)
add_test(NAME test_plugin_r3w1_untracked_fd_close COMMAND test_plugin_r3w1_untracked_fd_close)
set_tests_properties(test_plugin_r3w1_untracked_fd_close PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# W-2 (WARNING) supplementary: deterministically proves the is_closed()
# guard itself (security-review round-2 FIX 1) makes a second close on an
# already-tracked-closed slot a true no-op -- see this test's own header
# comment, and test_plugin_fix1_double_close_race.c's updated one, for why
# FIX 1's invoke.c call-ordering cannot be independently isolated by any
# test as long as this guard exists.
add_executable(test_plugin_r3w2_double_close_guard test_plugin_r3w2_double_close_guard.c)
target_link_libraries(test_plugin_r3w2_double_close_guard PRIVATE cytadel cytadel_warnings)
add_test(NAME test_plugin_r3w2_double_close_guard COMMAND test_plugin_r3w2_double_close_guard)
set_tests_properties(test_plugin_r3w2_double_close_guard PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# --------------------------------------------------------------------- #
# Security-review round-4 regression tests (post-round-4 fixes).
# --------------------------------------------------------------------- #

# W-1 (WARNING regression fix): proves api_socket.c's tracked+closed guard
# survives cytadel_plugin_fd_tracker_free() -- round 3's guard collapsed
# "freed" into "untracked" (free() reset `count` to 0), which reopened
# round 2 FIX 1's double-close hazard for exactly the post-cleanup __gc/
# __close case the guard exists to catch. Deterministic: no thread race,
# no network I/O, builds the freed-tracker state via the tracker's own
# real add()/force_close_all()/free() API.
add_executable(test_plugin_r4w1_guard_survives_free test_plugin_r4w1_guard_survives_free.c)
target_link_libraries(test_plugin_r4w1_guard_survives_free PRIVATE cytadel cytadel_warnings)
add_test(NAME test_plugin_r4w1_guard_survives_free COMMAND test_plugin_r4w1_guard_survives_free)
set_tests_properties(test_plugin_r4w1_guard_survives_free PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# W-2 (WARNING): proves invoke.c's lua_close(L)-before-cleanup ORDERING
# directly, via invoke.c's own CYTADEL_BUILD_TESTING-only
# CYTADEL_PLUGIN_INVOKE_ORDER_HOOK() instrumentation, rather than through
# the double-close symptom the (now fully restored) W-1 guard suppresses
# regardless of ordering. Single real invocation, single thread for the
# invocation itself (a background thread only accepts the fixture's one
# loopback connection) -- deterministic and short.
add_executable(test_plugin_r4w2_order_invariant test_plugin_r4w2_order_invariant.c)
target_link_libraries(test_plugin_r4w2_order_invariant PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugin_r4w2_order_invariant PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_r4w2_order_invariant COMMAND test_plugin_r4w2_order_invariant)
set_tests_properties(test_plugin_r4w2_order_invariant PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# C-1 (CRITICAL) suggestion 5: a closer regression check than
# test_plugin_r3c1_raw_getfield.c for C-1's raw_getfield() half AT
# loader.c's own call site (rather than on an isolated ad hoc table), and a
# closer check than test_plugin_r3c1_env_metatable_abort.c (which cannot
# reach a state where env_idx actually has a hostile metatable, since the
# __metatable lock rejects the plugin's own setmetatable() attempt first).
add_executable(test_plugin_r4c1_loader_run_lookup test_plugin_r4c1_loader_run_lookup.c)
target_link_libraries(test_plugin_r4c1_loader_run_lookup PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugin_r4c1_loader_run_lookup PRIVATE
    CYTADEL_TEST_FIXTURES_DIR="${CMAKE_SOURCE_DIR}/tests/plugins/fixtures")
add_test(NAME test_plugin_r4c1_loader_run_lookup COMMAND test_plugin_r4c1_loader_run_lookup)
set_tests_properties(test_plugin_r4c1_loader_run_lookup PROPERTIES LABELS "unit;plugin;security" TIMEOUT 30)

# --------------------------------------------------------------------- #
# Security-review round-6 regression / structural checks (post-round-6 fixes).
# --------------------------------------------------------------------- #

# Item 3: closes the W-A residual STRUCTURALLY. Reads src/plugin/invoke.c's
# own source text (does not link against `cytadel` or run any engine code)
# and mechanically proves "lua_close(" appears exactly once in that file,
# and only inside cytadel_plugin_close_state()'s own function body -- see
# that tool's own top-of-file comment for the exact "hollow" mutation
# (blank the real lua_close(L) call inside that helper, add a free-standing
# one elsewhere) it was built and verified to catch. No fixtures, no
# threads -- a single, deterministic source-text check.
add_executable(check_invoke_lua_close_invariant check_invoke_lua_close_invariant.c)
target_link_libraries(check_invoke_lua_close_invariant PRIVATE cytadel_warnings)
add_test(NAME check_invoke_lua_close_invariant
    COMMAND check_invoke_lua_close_invariant "${CMAKE_SOURCE_DIR}/src/plugin/invoke.c")
set_tests_properties(check_invoke_lua_close_invariant PROPERTIES LABELS "unit;plugin;security")

# Round-4 W-3: the cytadel_plugin_debug_check_* test hooks (and the
# cytadel_plugin_test_invoke_order_hook instrumentation pointer) were moved
# out of the public include/cytadel/plugin/plugin.h into the PRIVATE
# src/plugin/debug_support.h, so they are no longer part of the shipped
# library surface. The tests that drive those hooks are the only consumers,
# so src/plugin goes on their include path (and theirs only). CYTADEL_BUILD_TESTING
# must also be defined for them, since debug_support.h guards its declarations
# with it -- matching the guard around the .c body and the if(BUILD_TESTING)
# gate on its target_sources() entry in src/plugin/CMakeLists.txt.
foreach(_dbg_test
    test_plugin_sandbox
    test_plugin_r3c1_raw_getfield
    test_plugin_r3w1_untracked_fd_close
    test_plugin_r3w2_double_close_guard
    test_plugin_r4w1_guard_survives_free
    test_plugin_r4w2_order_invariant
    test_plugin_r4c1_loader_run_lookup)
    target_include_directories(${_dbg_test} PRIVATE ${CMAKE_SOURCE_DIR}/src/plugin)
    target_compile_definitions(${_dbg_test} PRIVATE CYTADEL_BUILD_TESTING)
endforeach()

# --------------------------------------------------------------------- #
# Milestone 6: stock detection plugins (plugins/, docs/contracts/
# plugin-api.md + kb-schema.md, both FROZEN). Unlike every test above,
# these two executables deliberately load the REAL plugins/ directory (see
# test_plugins_stock.c's own header comment for why that is not a
# violation of test_plugin_registry.c's "never the real plugins/
# directory" convention -- that convention is about tests of the engine's
# scheduling mechanics, not of stock-plugin content).
# --------------------------------------------------------------------- #

# KB-fixture-only: every stock plugin's positive/negative/malformed cases,
# driven purely by KB fixtures, no live network I/O.
add_executable(test_plugins_stock test_plugins_stock.c)
target_link_libraries(test_plugins_stock PRIVATE cytadel cytadel_warnings)
target_compile_definitions(test_plugins_stock PRIVATE
    CYTADEL_PLUGINS_DIR="${CMAKE_SOURCE_DIR}/plugins")
add_test(NAME test_plugins_stock COMMAND test_plugins_stock)
set_tests_properties(test_plugins_stock PROPERTIES LABELS "unit;plugin")

# The one stock plugin that must issue a real http_get() (http_headers.lua,
# kb-schema.md §7.6) -- verified against a real loopback fixture server,
# same accept()-on-a-background-thread pattern as test_plugin_network.c.
add_executable(test_plugins_stock_network test_plugins_stock_network.c)
target_link_libraries(test_plugins_stock_network PRIVATE cytadel cytadel_warnings Threads::Threads)
target_compile_definitions(test_plugins_stock_network PRIVATE
    CYTADEL_PLUGINS_DIR="${CMAKE_SOURCE_DIR}/plugins")
add_test(NAME test_plugins_stock_network COMMAND test_plugins_stock_network)
set_tests_properties(test_plugins_stock_network PROPERTIES LABELS "unit;plugin")

# --------------------------------------------------------------------- #
# Version-range matching, slice A: src/match/version_compare.c
# (docs/contracts/db-schema.md SS3 "Version-range matching approach" /
# SS10 assumption 3, both FROZEN CONTRACT). Range/bound *evaluation*
# (versionStart/EndIncluding/Excluding) is a separate, later slice B and is
# NOT covered here -- this is purely the shared comparator's own truth
# table. No fixtures, no threads, no network I/O.
# --------------------------------------------------------------------- #
add_executable(test_version_compare test_version_compare.c)
target_link_libraries(test_version_compare PRIVATE cytadel cytadel_warnings)
add_test(NAME test_version_compare COMMAND test_version_compare)
set_tests_properties(test_version_compare PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Version-range matching, slice B: src/match/cpe_match.c (docs/contracts/
# db-schema.md SS3 "Version-range matching approach", FROZEN CONTRACT).
# Range/bound *evaluation* against cve_cpe_matches rows, built on top of
# slice A's cytadel_version_compare() (test_version_compare.c above). No
# fixtures, no threads, no network I/O.
# --------------------------------------------------------------------- #
add_executable(test_cpe_match test_cpe_match.c)
target_link_libraries(test_cpe_match PRIVATE cytadel cytadel_warnings)
add_test(NAME test_cpe_match COMMAND test_cpe_match)
set_tests_properties(test_cpe_match PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# KEV/EPSS ingest slice: src/db/kev_ingest.c + src/db/epss_ingest.c
# (docs/contracts/db-schema.md SS4/SS5/SS8/SS9/SS10 assumption 5, FROZEN
# CONTRACT), mirroring src/db/nvd_ingest.c's architecture. Same reasoning as
# test_nvd_ingest.c above for linking cytadel_sqlite3/cytadel_cjson
# explicitly (own prepare/bind/step assertions against
# cytadel_db_handle()'s raw connection; hostile-JSON fixtures built with
# cJSON's own C API).
# --------------------------------------------------------------------- #
add_executable(test_kev_ingest test_kev_ingest.c)
target_link_libraries(test_kev_ingest PRIVATE cytadel cytadel_warnings cytadel_sqlite3 cytadel_cjson)
add_test(NAME test_kev_ingest COMMAND test_kev_ingest)
set_tests_properties(test_kev_ingest PROPERTIES LABELS "unit")

add_executable(test_epss_ingest test_epss_ingest.c)
target_link_libraries(test_epss_ingest PRIVATE cytadel cytadel_warnings cytadel_sqlite3 cytadel_cjson)
add_test(NAME test_epss_ingest COMMAND test_epss_ingest)
set_tests_properties(test_epss_ingest PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# CPE-matching-caller slice: src/db/scan_persist.c (docs/contracts/
# cpe-matching.md SS3/SS6 CPE-MATCH-CALLER-1, docs/contracts/db-schema.md
# SS6/SS7/SS9/SS10, FROZEN CONTRACTS -- SS7's match_status column is the one
# explicitly authorized amendment). The FIRST PRODUCTION CALLER of
# cytadel_cpe_match_evaluate(). Same reasoning as test_db.c above for linking
# cytadel_sqlite3 explicitly (own prepare/bind/step assertions against
# cytadel_db_handle()'s raw connection to build cve_cpe_matches/cves/kev/epss
# fixture rows and to read scan_results back). M9 Gap #3 fix: this file's own
# placeholder-promotion test drives cytadel_nvd_ingest_page() directly
# (mirrors test_kev_ingest.c's own promotion test), so this links
# cytadel_cjson too -- same reasoning as test_nvd_ingest.c/test_kev_ingest.c
# above (nvd_ingest.o, pulled in from the `cytadel` archive, needs cJSON
# symbols resolved in the final test executable).
# --------------------------------------------------------------------- #
add_executable(test_scan_persist test_scan_persist.c)
target_link_libraries(test_scan_persist PRIVATE cytadel cytadel_warnings cytadel_sqlite3 cytadel_cjson)
add_test(NAME test_scan_persist COMMAND test_scan_persist)
set_tests_properties(test_scan_persist PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# M9 Phase 0: src/cli/scan_wiring.c -- the live scan pipeline's DB wiring
# (the mandatory-DB gate, the KB CPE/<port> resolver, and the per-host
# persist phase) that makes src/cli/main.c the FIRST PRODUCTION CALLER of
# the CPE evaluator for real. Links cytadel_cli_core (scan_wiring.c lives
# there, alongside cli_args.c/auth_gate.c/report_cmd.c) and cytadel_sqlite3
# (own prepare/bind/step fixture-seeding and scan_results/scans read-back
# assertions), same reasoning as test_scan_persist.c above.
# --------------------------------------------------------------------- #
add_executable(test_scan_wiring test_scan_wiring.c)
target_link_libraries(test_scan_wiring PRIVATE cytadel_cli_core cytadel cytadel_warnings cytadel_sqlite3)
add_test(NAME test_scan_wiring COMMAND test_scan_wiring)
set_tests_properties(test_scan_wiring PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Live NVD fetch, catch-up slice: src/db/nvd_catchup.c (docs/contracts/
# db-schema.md SS8 step 6, the multi-window catch-up loop nvd_sync.h
# explicitly leaves to its caller). Driven against a loopback fixture HTTP
# server, same reasoning as test_nvd_sync.c above for linking
# cytadel_sqlite3/Threads::Threads explicitly (own prepare/bind/step
# assertions against cytadel_db_handle()'s raw connection to seed/read back
# sync_state.last_mod_watermark; spawns its own accept() thread).
# --------------------------------------------------------------------- #
add_executable(test_nvd_catchup test_nvd_catchup.c)
target_link_libraries(test_nvd_catchup PRIVATE cytadel cytadel_warnings cytadel_sqlite3 Threads::Threads)
add_test(NAME test_nvd_catchup COMMAND test_nvd_catchup)
set_tests_properties(test_nvd_catchup PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Milestone 8 slice 1: src/report/escape.c, the report-output escaper
# module (CRITICAL XSS-defense surface -- see include/cytadel/report/
# escape.h's own header comment for the full threat model). Hostile,
# context-breaking fixtures for all four context-specific escapers
# (html_body/html_attr/url/json), no fixtures, no threads, no network I/O.
# --------------------------------------------------------------------- #
add_executable(test_report_escape test_report_escape.c)
target_link_libraries(test_report_escape PRIVATE cytadel cytadel_warnings)
add_test(NAME test_report_escape COMMAND test_report_escape)
set_tests_properties(test_report_escape PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Milestone 8 slice 3: src/report/report_html.c, the branded HTML report
# generator -- the FIRST caller of src/report/escape.c's four escapers
# against real `scans`/`scan_results` data (docs/contracts/db-schema.md
# SS6/SS7/SS9/SS10, docs/contracts/cpe-matching.md SS3/SS6, all FROZEN
# CONTRACTS). Same reasoning as test_scan_persist.c above for linking
# cytadel_sqlite3 explicitly (own prepare/bind/step assertions against
# cytadel_db_handle()'s raw connection to build scan_results/cves fixture
# rows, including hostile-payload rows for the per-site escaper mutation
# proofs).
# --------------------------------------------------------------------- #
add_executable(test_report_html test_report_html.c)
target_link_libraries(test_report_html PRIVATE cytadel cytadel_warnings cytadel_sqlite3)
add_test(NAME test_report_html COMMAND test_report_html)
set_tests_properties(test_report_html PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Milestone 8 slice 4: src/report/report_json.c, the JSON report generator
# -- mirrors test_report_html.c's own fixture/gate coverage. Links
# cytadel_cjson (cJSON_ParseWithLength()/cJSON_GetObjectItemCaseSensitive()
# etc. -- the hostile-JSON round-trip/validity proofs) alongside
# cytadel_sqlite3 (own prepare/bind/step fixture-seeding), same reasoning as
# test_nvd_ingest.c/test_report_html.c above.
# --------------------------------------------------------------------- #
add_executable(test_report_json test_report_json.c)
target_link_libraries(test_report_json PRIVATE cytadel cytadel_warnings cytadel_sqlite3 cytadel_cjson)
add_test(NAME test_report_json COMMAND test_report_json)
set_tests_properties(test_report_json PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# Milestone 8 slice 5: src/cli/report_cmd.c, the `cytadel-scan report`
# subcommand (argument parsing, scan_id resolution, format dispatch, and a
# full cytadel_report_cmd_run() integration proof against a real on-disk
# DB file + CYTADEL_DB_PATH env var). Links cytadel_cli_core (report_cmd.c
# lives there, alongside cli_args.c/auth_gate.c) and cytadel_sqlite3 (own
# fixture-seeding prepare/bind/step calls, same reasoning as
# test_report_html.c above).
# --------------------------------------------------------------------- #
add_executable(test_report_cmd test_report_cmd.c)
target_link_libraries(test_report_cmd PRIVATE cytadel_cli_core cytadel cytadel_warnings cytadel_sqlite3)
add_test(NAME test_report_cmd COMMAND test_report_cmd)
set_tests_properties(test_report_cmd PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# M9 Phase 4a: src/cli/sync_cmd.c, the `cytadel-scan sync` subcommand --
# wires the already-built NVD delta-sync driver (include/cytadel/db/
# nvd_catchup.h) up to a real command a scheduled timer can invoke. Links
# cytadel_cli_core (sync_cmd.c lives there) -- every DB call this test makes
# goes through cytadel_db_open()/cytadel_db_migrate()'s own typed API (never
# a raw sqlite3_* call of its own), so unlike test_report_cmd.c this does
# not need cytadel_sqlite3 directly. CYTADEL_SYNC_CMD_SRC_DIR is an absolute
# path to this subcommand's own source directory (not relative to whatever
# working directory ctest happens to run from), used only by the
# secret-hygiene structural check (that check reads sync_cmd.c/.h's own
# source text -- see that test's own comment).
# --------------------------------------------------------------------- #
add_executable(test_sync_cmd test_sync_cmd.c)
target_link_libraries(test_sync_cmd PRIVATE cytadel_cli_core cytadel cytadel_warnings)
target_compile_definitions(test_sync_cmd PRIVATE
    CYTADEL_SYNC_CMD_SRC_DIR="${CMAKE_SOURCE_DIR}/src/cli")
add_test(NAME test_sync_cmd COMMAND test_sync_cmd)
set_tests_properties(test_sync_cmd PROPERTIES LABELS "unit")

# --------------------------------------------------------------------- #
# src/cli/banner.c: the cosmetic startup ASCII-art banner. Links
# cytadel_cli_core (banner.c/report_cmd.c both live there) and cytadel_cjson
# (cJSON_ParseWithLength()/cJSON_GetObjectItemCaseSensitive() -- the
# stdout-stays-valid-JSON integrity proof, mirroring test_report_json.c's
# own cJSON round-trip verification). No cytadel_sqlite3 needed directly:
# the DB fixture is seeded purely through cytadel_db_open()/
# cytadel_db_migrate()/cytadel_scan_create()'s own typed API (never a raw
# sqlite3_* call of its own), same reasoning as test_sync_cmd.c above.
# CYTADEL_BANNER_SRC_PATH is an absolute path to banner.c's own source file,
# used only by this test's structural "never references stdout" check
# (reads that file's own source text -- same technique as
# check_invoke_lua_close_invariant.c).
# --------------------------------------------------------------------- #
add_executable(test_banner test_banner.c)
target_link_libraries(test_banner PRIVATE cytadel_cli_core cytadel cytadel_warnings cytadel_cjson)
target_compile_definitions(test_banner PRIVATE
    CYTADEL_BANNER_SRC_PATH="${CMAKE_SOURCE_DIR}/src/cli/banner.c")
add_test(NAME test_banner COMMAND test_banner)
set_tests_properties(test_banner PROPERTIES LABELS "unit")
