# src/db: Milestone 7 slice 1 -- the vertical DB foundation. First code
# realization of docs/contracts/db-schema.md (FROZEN CONTRACT): open/create
# the SQLite vuln DB, apply the frozen schema via an idempotent migration
# runner. Aggregated into the top-level `cytadel` static library target,
# same as every other module (docs/build-plan.md §4).
#
# Public header lives under include/cytadel/db/ (already a PUBLIC include
# directory of `cytadel`, set in the top-level CMakeLists.txt) -- reachable
# as "cytadel/db/db.h" by any target linking against `cytadel`.
#
# db_migrations.h is deliberately kept private to this directory (not under
# include/cytadel/db/, matching src/net's icmp_probe.h/tcp_ping.h and
# src/kb's kb_validate.h convention): only db.c in this same module includes
# it.
#
# cytadel_sqlite3 (third_party/sqlite/CMakeLists.txt) is linked PRIVATE here
# per docs/build-plan.md §2's "each module links only what it uses" policy
# -- no other module needs SQLite in this slice. Because cytadel_sqlite3
# exposes its include directory and compile definitions PUBLIC, linking it
# (even PRIVATE from `cytadel`'s perspective) still gives db.c/db_migrations.c
# everything they need to `#include <sqlite3.h>` and see the exact
# SQLITE_* compile-time configuration that header was built with.
#
# Milestone 7 slice 2: nvd_ingest.c (defensive NVD 2.0 CVE JSON ingest) adds
# a dependency on the vendored cJSON amalgamation (third_party/cjson/CMakeLists.txt),
# linked PRIVATE for the same "only the module that needs it links it"
# reasoning as cytadel_sqlite3 above -- no other module needs JSON parsing
# in this slice.
#
# KEV/EPSS ingest slice: kev_ingest.c/epss_ingest.c mirror nvd_ingest.c's
# architecture exactly (see both files' own top-of-file comments) and share
# its cJSON/sqlite3 dependencies -- no new target_link_libraries() entry is
# needed. cve_id_valid.h (the ONE shared NVD/CISA/first.org CVE-ID grammar
# check, promoted out of nvd_ingest.c during this slice) is a private,
# header-only addition used by all three of nvd_ingest.c/kev_ingest.c/
# epss_ingest.c -- not listed in target_sources() since it has no
# corresponding .c file to compile.
#
# CPE-matching-caller slice: scan_persist.c is the `scans`/`scan_results`
# persistence layer and the FIRST PRODUCTION CALLER of
# cytadel_cpe_match_evaluate() (src/match/cpe_match.c, linked in via the
# `cytadel` target already -- src/match/CMakeLists.txt). Uses only
# cytadel_sqlite3 (already linked below); no new dependency.
#
# Live NVD fetch, catch-up slice: nvd_catchup.c is the fetch-driver /
# multi-window catch-up wrapper around nvd_sync.c's single-window driver
# (see include/cytadel/db/nvd_catchup.h). Uses only cytadel_sqlite3 (already
# linked below, for its own parameterized watermark read) -- no new
# dependency.

target_sources(cytadel PRIVATE
    db.c
    db_migrations.c
    nvd_ingest.c
    nvd_sync.c
    nvd_catchup.c
    kev_ingest.c
    kev_sync.c
    epss_ingest.c
    epss_sync.c
    scan_persist.c
)
target_link_libraries(cytadel PRIVATE cytadel_sqlite3 cytadel_cjson)
