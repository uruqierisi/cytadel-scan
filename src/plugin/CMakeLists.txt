# src/plugin: Lua 5.4 plugin engine (Milestone 5, first code realization of
# docs/contracts/plugin-api.md -- FROZEN CONTRACT). Aggregated into the
# top-level `cytadel` static library target, same as every other module
# (docs/build-plan.md §4).
#
# Public header lives under include/cytadel/plugin/plugin.h (already a
# PUBLIC include directory of `cytadel`, set in the top-level
# CMakeLists.txt) -- reachable as "cytadel/plugin/plugin.h" by any target
# linking against `cytadel`.
#
# Lua::Lua (find_package(Lua 5.4 REQUIRED) at the top level, wrapped into an
# INTERFACE IMPORTED target there since CMake's bundled FindLua.cmake does
# not create one itself -- see the top-level CMakeLists.txt comment) is
# linked PRIVATE here per docs/build-plan.md §2's "each module links only
# what it uses" policy: no other module touches the Lua C API directly.
#
# api_http.c's http_get() binding (plugin-api.md §2.8) is built directly on
# src/net's existing tls_session.h/.c (the same TLS-handshake primitive
# service_detect.c/http_probe.c already use -- NOT libcurl, per this
# milestone's scope) rather than duplicating a second TLS-connect
# implementation. tls_session.h is a private header of src/net (not under
# include/cytadel/net/, matching that module's stated "only
# service_detect.h is public" convention), so it is not reachable from
# outside src/net via the normal public include path; the extra PRIVATE
# include directory below makes it reachable from src/plugin's own
# translation units only (never exposed to `cytadel`'s consumers), the same
# "make a specific private header reachable across a module boundary
# without making it public" technique already used for src/log's
# internal-only log.h/strerror_safe.h (see that module's own CMakeLists.txt
# comment) -- the difference here is PRIVATE rather than PUBLIC, since
# tls_session.h must stay invisible to tests/cli, unlike log.h.
target_include_directories(cytadel PRIVATE ${CMAKE_SOURCE_DIR}/src/net)
target_link_libraries(cytadel PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_sources(cytadel PRIVATE
    lua_smoke.c
    field_utils.c
    plugin_header.c
    register.c
    sandbox.c
    depgraph.c
    loader.c
    registry.c
    finding.c
    fd_tracker.c
    timeout_clamp.c
    api_kb.c
    api_socket.c
    api_http.c
    api_report.c
    api_log.c
    invoke.c
    scheduler.c
)

# debug_support.c is TEST-SUPPORT ONLY (security-review round-4 finding W-3).
# Its declarations live in the PRIVATE src/plugin/debug_support.h, never in
# the public include/cytadel/plugin/plugin.h, and the file is only compiled
# into `cytadel` when tests are being built. Its entire body is additionally
# guarded by #ifdef CYTADEL_BUILD_TESTING, so the macro must be defined for
# the target here -- without it the translation unit is empty and -Wpedantic
# rejects it ("ISO C forbids an empty translation unit").
#
# Rationale: cytadel_plugin_debug_check_env_isolated() is a
# load-and-execute-arbitrary-Lua-file entry point (luaL_loadfile + a full
# run-phase sandbox) driven by a caller-supplied path. It must never be part
# of this library's shipped surface, regardless of any future
# BUILD_SHARED_LIBS / install(TARGETS) / --whole-archive change.
if(BUILD_TESTING)
    target_sources(cytadel PRIVATE debug_support.c)
    target_compile_definitions(cytadel PRIVATE CYTADEL_BUILD_TESTING)
endif()

target_link_libraries(cytadel PRIVATE Lua::Lua)
