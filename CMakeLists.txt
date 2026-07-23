# Cytadel Scan — top-level build (C11 engine + embedded-Lua plugins + SQLite
# vuln DB + branded reports). See docs/build-plan.md §2-4 for the design this
# realizes. Detection-only network vulnerability scanner; Linux-first.
#
# Dependency resolution (docs/build-plan.md §2):
#   - OpenSSL, Threads, Lua 5.4  : find_package (OPENSSL_ROOT_DIR / CYTADEL_LUA_ROOT
#                                  hint a vendored install; a system package is
#                                  found with no hint).
#   - SQLite3, cJSON             : VENDORED in third_party/ (own targets, built
#                                  WITHOUT the engine's -Werror), not find_package.
#   - libcurl                    : either a system libcurl passed via
#                                  CYTADEL_CURL_INCLUDE_DIR + CYTADEL_CURL_LIBRARY
#                                  (CI / the Docker scanner image), or a vendored
#                                  static build under CYTADEL_CURL_ROOT (dev loop).
#   - libpcap                    : not required; there is no SYN-scan backend yet,
#                                  so the engine always uses the TCP-connect path
#                                  (CYTADEL_HAVE_PCAP=0).
cmake_minimum_required(VERSION 3.16)
project(cytadel-scan LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ---------------------------------------------------------------------------
# Options (the warnings-as-errors gate: a clean -Wall -Wextra -Wpedantic -Werror build).
# ---------------------------------------------------------------------------
option(CYTADEL_WERROR "Treat compiler warnings as errors" ON)
option(CYTADEL_SANITIZE "Build with ASan+UBSan (Debug/RelWithDebInfo)" OFF)
option(CYTADEL_TSAN "Build with ThreadSanitizer (mutually exclusive with SANITIZE)" OFF)
option(BUILD_TESTING "Build the unit test suite" ON)
option(CYTADEL_ENABLE_INTEGRATION_TESTS
       "Build tests that require the Docker vulnerable target (OFF for a plain ctest)" OFF)

set(CYTADEL_LUA_ROOT "" CACHE PATH
    "Optional prefix of a vendored Lua 5.4 install (include/, lib/); empty = use the system package")
set(CYTADEL_CURL_ROOT "$ENV{HOME}/curl-local" CACHE PATH
    "Prefix of a vendored static libcurl (include/, lib/); used only when CYTADEL_CURL_LIBRARY is unset")
# CYTADEL_CURL_INCLUDE_DIR / CYTADEL_CURL_LIBRARY: when BOTH are set, that
# (system, shared) libcurl is used verbatim and the vendored-static search below
# is skipped. CI and docker/scanner/Dockerfile pass these.

# ---------------------------------------------------------------------------
# Warning + sanitizer INTERFACE targets (cytadel_warnings / cytadel_sanitizers).
# ---------------------------------------------------------------------------
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/CompilerWarnings.cmake)
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Sanitizers.cmake)

# ---------------------------------------------------------------------------
# Hard dependencies, resolved once at the top level before any add_subdirectory
# so a missing one fails configuration with a clear error (docs/build-plan.md §2).
# ---------------------------------------------------------------------------
find_package(OpenSSL REQUIRED)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

# Lua 5.4 — CMake's bundled FindLua does not create an imported target, so wrap
# one ourselves after version-pinning (it can otherwise pick up a stray 5.1/5.3).
if(CYTADEL_LUA_ROOT)
    list(PREPEND CMAKE_PREFIX_PATH "${CYTADEL_LUA_ROOT}")
endif()
find_package(Lua 5.4 REQUIRED)
if(NOT LUA_VERSION_STRING MATCHES "^5\\.4")
    message(FATAL_ERROR "Cytadel requires Lua 5.4; found ${LUA_VERSION_STRING}")
endif()
if(NOT TARGET Lua::Lua)
    add_library(Lua::Lua INTERFACE IMPORTED)
    set_target_properties(Lua::Lua PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${LUA_INCLUDE_DIR}"
        INTERFACE_LINK_LIBRARIES "${LUA_LIBRARIES}")
endif()

# libcurl — nvd_fetch.c is the sole consumer (src/net links Curl::Curl). Three
# supported provisioning paths, in priority order:
#   1. CYTADEL_CURL_INCLUDE_DIR + CYTADEL_CURL_LIBRARY both set explicitly
#      (CI, docker/scanner/Dockerfile): used verbatim, no search.
#   2. A vendored prefix under CYTADEL_CURL_ROOT (the WSL dev loop's static build).
#   3. A system libcurl on the default search paths (a plain apt/dnf box with
#      libcurl-dev installed) — no override, no vendored prefix needed.
# find_path/find_library HINT the vendored prefix first, then fall back to the
# system paths, so all three resolve through the same two calls (the cache vars
# from case 1, if pre-seeded on the command line, make them no-ops).
find_path(CYTADEL_CURL_INCLUDE_DIR curl/curl.h HINTS "${CYTADEL_CURL_ROOT}/include")
find_library(CYTADEL_CURL_LIBRARY NAMES curl libcurl HINTS "${CYTADEL_CURL_ROOT}/lib")
if(NOT CYTADEL_CURL_INCLUDE_DIR OR NOT CYTADEL_CURL_LIBRARY)
    message(FATAL_ERROR
        "libcurl not found. Install a system libcurl dev package (e.g. "
        "libcurl4-openssl-dev), or set CYTADEL_CURL_ROOT to a prefix containing "
        "include/curl/curl.h and lib/libcurl.{a,so}, or pass both "
        "CYTADEL_CURL_INCLUDE_DIR and CYTADEL_CURL_LIBRARY explicitly.")
endif()

add_library(Curl::Curl INTERFACE IMPORTED)
set_target_properties(Curl::Curl PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${CYTADEL_CURL_INCLUDE_DIR}")
if(CYTADEL_CURL_LIBRARY MATCHES "\\.a$")
    # A static archive needs CURL_STATICLIB, and its OpenSSL/MD5 back-references
    # must be resolved in a GNU-ld --start-group with the (also static) OpenSSL
    # archives: src/net links OpenSSL earlier, so CMake would otherwise place it
    # before libcurl and leave curl's EVP_*/MD5_* symbols unresolved.
    set_target_properties(Curl::Curl PROPERTIES
        INTERFACE_COMPILE_DEFINITIONS "CURL_STATICLIB"
        INTERFACE_LINK_LIBRARIES
            "-Wl,--start-group;${CYTADEL_CURL_LIBRARY};${OPENSSL_SSL_LIBRARY};${OPENSSL_CRYPTO_LIBRARY};-Wl,--end-group;Threads::Threads;${CMAKE_DL_LIBS}")
else()
    # A shared libcurl.so carries its own DT_NEEDED deps — link it plainly.
    set_target_properties(Curl::Curl PROPERTIES
        INTERFACE_LINK_LIBRARIES "${CYTADEL_CURL_LIBRARY}")
endif()

# ---------------------------------------------------------------------------
# Vendored third-party (own targets; NOT compiled with the engine's -Werror).
# ---------------------------------------------------------------------------
add_subdirectory(third_party/sqlite)
add_subdirectory(third_party/cjson)

# ---------------------------------------------------------------------------
# The engine static library. Each src/<module>/CMakeLists.txt target_sources()s
# into it and links only what it uses; src/cli builds cytadel_cli_core + the
# cytadel-scan executable on top (docs/build-plan.md §4).
# ---------------------------------------------------------------------------
add_library(cytadel STATIC)
target_include_directories(cytadel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(cytadel
    PRIVATE cytadel_warnings
    PUBLIC cytadel_sanitizers)
# No raw-socket SYN backend exists yet: the port scanner always uses the
# TCP-connect path (runtime CAP_NET_RAW fallback lives in src/net, not here).
target_compile_definitions(cytadel PRIVATE CYTADEL_HAVE_PCAP=0)

add_subdirectory(src/log)
add_subdirectory(src/kb)
add_subdirectory(src/core)
add_subdirectory(src/net)
add_subdirectory(src/plugin)
add_subdirectory(src/match)
add_subdirectory(src/db)
add_subdirectory(src/report)
add_subdirectory(src/cli)

# ---------------------------------------------------------------------------
# Tests. `ctest -L unit` runs the unit suite; integration tests (which drive
# the Docker vulnerable target) are gated OFF by default so a plain ctest in an
# environment without Docker is unaffected.
# ---------------------------------------------------------------------------
if(BUILD_TESTING)
    enable_testing()
    add_subdirectory(tests/unit)
    if(CYTADEL_ENABLE_INTEGRATION_TESTS)
        add_subdirectory(tests/integration)
    endif()
endif()
