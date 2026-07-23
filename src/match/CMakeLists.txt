# src/match: version-string comparison (slice A) plus CPE range/bound
# *evaluation* (slice B) of the version-range matching feature --
# docs/contracts/db-schema.md SS3 "Version-range matching approach" / SS10
# assumption 3, both FROZEN CONTRACT. Aggregated into the top-level `cytadel`
# static library target, same as every other module (docs/build-plan.md §4).
#
# Public headers live under include/cytadel/match/ (already a PUBLIC include
# directory of `cytadel`, set in the top-level CMakeLists.txt) -- reachable
# as "cytadel/match/version_compare.h" / "cytadel/match/cpe_match.h" by any
# target linking against `cytadel`.
#
# No external dependencies: version_compare.c is a pure, allocation-free,
# length-bounded string comparator (no OpenSSL/SQLite/Lua/pthreads/etc.),
# matching db-schema.md SS10 assumption 3's requirement that this be a single
# implementation a future Lua binding can wrap directly. cpe_match.c (slice
# B) depends only on version_compare.c's public API -- no new external
# dependency either.

target_sources(cytadel PRIVATE
    version_compare.c
    cpe_match.c
)
