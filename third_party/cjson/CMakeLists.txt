# third_party/cjson: the vendored cJSON 1.7.18 amalgamation (see VERSION.txt
# for exact provenance -- MIT, cJSON.c/.h only). Milestone 7 slice 2
# (defensive NVD 2.0 JSON ingest, src/db/nvd_ingest.c) needs a bounded,
# hostile-input-safe JSON parser; cJSON_ParseWithLength() (bounded, never
# assumes NUL termination) plus cJSON's own internal CJSON_NESTING_LIMIT
# (left at its library default of 1000 here -- see cJSON.h) is exactly that.
#
# Isolation requirement identical to third_party/sqlite/CMakeLists.txt's own
# (the project policy's project-wide -Wall -Wextra -Wpedantic -Werror posture does
# not apply to vendored third-party code, and cJSON.c must never be edited
# to satisfy it): built as its own static library target, `cytadel_cjson`,
# which:
#   - does NOT link `cytadel_warnings` -- simply never opting in already
#     keeps this target free of the project's warning flags (those flags
#     never apply project-wide by default, only to targets that explicitly
#     link cytadel_warnings).
#   - ALSO explicitly adds -w (suppress all warnings) below, so this
#     target's warning posture is self-documenting rather than silently
#     depending on cytadel_warnings never being linked.
#   - DOES link `cytadel_sanitizers` (ASan+UBSan / TSan, see
#     cmake/Sanitizers.cmake) when CYTADEL_SANITIZE/CYTADEL_TSAN is ON --
#     giving real redzone/UB coverage across the actual
#     nvd_ingest.c<->cJSON.c boundary this milestone's hostile-input tests
#     exercise, same reasoning as third_party/sqlite/CMakeLists.txt's own
#     cytadel_sqlite3 target.
add_library(cytadel_cjson STATIC cJSON.c)
target_include_directories(cytadel_cjson PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cytadel_cjson PUBLIC cytadel_sanitizers)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(cytadel_cjson PRIVATE -w)
endif()
