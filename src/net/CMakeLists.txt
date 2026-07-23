# src/net: host discovery + TCP connect port scanning, plus multi-target
# expansion (Milestone 2: single-target/single-host; Milestone 3 adds
# cidr.c/targets_file.c/target_list.c for CIDR blocks, comma lists, and
# --targets-file). Aggregated into the top-level `cytadel` static library
# target, same as src/log (docs/build-plan.md §4).
#
# Public headers live under include/cytadel/net/ (already a PUBLIC include
# directory of `cytadel`, set in the top-level CMakeLists.txt) -- reachable
# as "cytadel/net/<name>.h" by any target linking against `cytadel`.
#
# icmp_probe.h/tcp_ping.h are deliberately kept private to this directory
# (not under include/cytadel/net/, and this directory is NOT added to
# `cytadel`'s public include path, unlike src/log): only discovery.c in
# this same module includes them, so there is no reason to expose them
# past src/net's own translation units.
#
# Milestone 4 (Parts B/C): service/banner detection, the CPE bridge, and
# TLS inspection (docs/build-plan.md §1: "net/ ... TLS inspection"). Every
# new private header below (banner_grab.h, svc_token.h, svc_ssh.h,
# svc_ftp.h, http_probe.h, cpe_map.h, tls_session.h, tls_inspect.h)
# follows the same private-header convention as icmp_probe.h/tcp_ping.h --
# only service_detect.h is public (include/cytadel/net/service_detect.h),
# the single orchestration entry point host_scan.c (Part D) calls.
#
# OpenSSL (find_package(OpenSSL REQUIRED) at the top level) is used by
# tls_session.c/tls_inspect.c and http_probe.c (the TLS variant's SSL*
# parameter type) -- linked PRIVATE here per docs/build-plan.md §2's "each
# module links only what it uses" policy; no other module needs it.

target_sources(cytadel PRIVATE
    scan_types.c
    target.c
    cidr.c
    targets_file.c
    target_list.c
    port_range.c
    capability.c
    tcp_connect.c
    icmp_probe.c
    tcp_ping.c
    scan_backend.c
    discovery.c
    port_scanner.c
    banner_grab.c
    svc_token.c
    cpe_map.c
    svc_ssh.c
    svc_ftp.c
    http_probe.c
    tls_session.c
    tls_inspect.c
    service_detect.c
    host_scan.c
    nvd_fetch.c
)
target_link_libraries(cytadel PRIVATE OpenSSL::SSL OpenSSL::Crypto)
# Milestone 7 live NVD fetch: nvd_fetch.c is the sole libcurl consumer.
# Curl::Curl carries CURL_STATICLIB + the static archive's OpenSSL/pthread deps.
target_link_libraries(cytadel PRIVATE Curl::Curl)
