# src/report: Milestone 8 slice 1 -- the report-output escaper module. The
# CRITICAL XSS-defense surface for the branded HTML/JSON reports: every
# value a report renders (banners, HTTP headers, TLS cert CN/SAN, CVE
# descriptions) is stored RAW by design (docs/contracts/kb-schema.md,
# db-schema.md) and is either fully attacker-controlled or untrusted
# third-party data. Aggregated into the top-level `cytadel` static library
# target, same as every other module (docs/build-plan.md §4).
#
# Public header lives under include/cytadel/report/escape.h (already a
# PUBLIC include directory of `cytadel`, set in the top-level
# CMakeLists.txt) -- reachable as "cytadel/report/escape.h" by any target
# linking against `cytadel`. See that header's own top-of-file comment for
# the full threat model and the exact contract of each of the four
# context-specific escapers.
#
# Scope of THIS slice (M8 slice 1, escape.c): escaping primitives ONLY. No
# DB, no report rendering, no HTML template, no CLI. No external
# dependencies (no OpenSSL/SQLite/Lua/etc.).
#
# M8 slice 3 (report_html.c): the branded HTML report generator -- the FIRST
# caller of escape.c's four escapers against real `scans`/`scan_results`
# data (see include/cytadel/report/report.h's own top-of-file comment for
# the full design/contract). Queries the vuln DB directly via
# cytadel_db_handle()'s raw sqlite3 connection (own prepare/bind/step/
# finalize sequences, same style as src/db/scan_persist.c), so this module
# needs cytadel_sqlite3 -- linked PRIVATE here per docs/build-plan.md SS2's
# "each module links only what it uses" policy (src/db/CMakeLists.txt
# already links cytadel_sqlite3 into `cytadel` too; target_link_libraries()
# on an already-linked PRIVATE dependency is a harmless no-op, and listing
# it here documents THIS module's own real dependency rather than relying
# on an incidental transitive link from an unrelated module).
#
# M8 slice 4 (report_json.c): the JSON report generator -- mirrors
# report_html.c's own data layer (same `scans` metadata read, same SS9
# findings SELECT) and escape.h's Context 4 (cytadel_escape_json()) instead
# of the HTML escapers. M8 slice 5 (report_scan_lookup.c):
# cytadel_report_find_latest_scan_id(), the one query the `cytadel-scan
# report --latest` CLI path needs beyond a known scan_id -- kept in this
# module (not src/cli) so no translation unit outside src/db/src/report ever
# hand-writes a query against this schema.

target_sources(cytadel PRIVATE
    escape.c
    report_html.c
    report_json.c
    report_scan_lookup.c
)
target_link_libraries(cytadel PRIVATE cytadel_sqlite3)
