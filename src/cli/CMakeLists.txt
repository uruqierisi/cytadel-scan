# src/cli: the cytadel-scan executable. This is the only target that owns
# main() (docs/build-plan.md §4); `cytadel` never does, so it stays
# link-testable from tests/.
#
# cli_args.c / auth_gate.c hold the testable logic (argument parsing, the
# authorization-gate decision function) and are split into their own small
# internal static library, `cytadel_cli_core`, distinct from both `cytadel`
# (the engine library -- src/cli is explicitly not one of its module
# sources per build-plan.md §4) and the `cytadel-scan` executable (which
# must not be linked into test binaries, since it defines main()). This
# mirrors the same "logic vs. entry point" split build-plan.md already uses
# for `cytadel` vs. `cytadel-scan`, applied one level down so
# tests/unit/CMakeLists.txt can link the CLI logic without pulling in
# main(). This is an the engine work implementation decision for Milestone 1, not
# spelled out by build-plan.md (which only discusses this split for
# libcytadel as a whole).
# Milestone 8 slice 5: report_cmd.c (the `cytadel-scan report` subcommand --
# parsing, scan_id resolution, and format dispatch, split from cli_args.c/
# auth_gate.c for the same "logic vs. entry point" testability reason).
# Needs no direct sqlite3 dependency of its own: every DB query it needs
# (the `--latest` lookup, the HTML/JSON render itself) is already exposed
# as a typed entry point by `cytadel` (include/cytadel/db/db.h,
# include/cytadel/report/report.h).
#
# M9 Phase 0: scan_wiring.c -- the live scan pipeline's DB wiring (the
# mandatory-DB gate, the KB CPE/<port> resolver, and the per-host persist
# phase), split out of main.c for the same "logic vs. entry point"
# testability reason as report_cmd.c. Needs no direct sqlite3 dependency
# either: every DB access goes through `cytadel`'s own typed entry points
# (include/cytadel/db/db.h, include/cytadel/db/scan_persist.h).
# M9 Phase 4a: sync_cmd.c -- the `cytadel-scan sync` subcommand (wires the
# already-built NVD delta-sync driver, include/cytadel/db/nvd_catchup.h, up
# to a real command). Same "logic vs. entry point" split and same "no direct
# sqlite3 dependency" reasoning as report_cmd.c/scan_wiring.c above -- every
# DB access it needs goes through `cytadel`'s own cytadel_db_open()/
# cytadel_db_migrate()/cytadel_nvd_catchup().
# banner.c: the cosmetic startup ASCII-art banner for the live-scan path
# only. Split into its own tiny module (not inlined in main.c) purely so
# the print/suppress DECISION function is directly unit-testable -- same
# "logic vs. entry point" split reasoning as every other file in this
# library, applied to a much smaller/cosmetic surface.
add_library(cytadel_cli_core STATIC
    cli_args.c
    auth_gate.c
    report_cmd.c
    scan_wiring.c
    sync_cmd.c
    banner.c
)
target_link_libraries(cytadel_cli_core
    PUBLIC cytadel
    PRIVATE cytadel_warnings
)
target_include_directories(cytadel_cli_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(cytadel-scan main.c)
target_link_libraries(cytadel-scan PRIVATE cytadel_cli_core cytadel cytadel_warnings)
