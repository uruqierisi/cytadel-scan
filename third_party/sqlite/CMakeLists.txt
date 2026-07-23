# third_party/sqlite: the vendored SQLite amalgamation (see VERSION.txt for
# the exact release/provenance -- public domain, sqlite3.c/.h/sqlite3ext.h
# only, CLI shell.c intentionally omitted).
#
# Milestone 7 slice 1 deliberately does NOT use find_package(SQLite3) (the
# original docs/build-plan.md §2 dependency table assumed a system SQLite3
# via the bundled FindSQLite3.cmake module) -- this milestone's task brief
# instead vendors the amalgamation directly and compiles it in-tree, so
# there is no runtime dependency on whatever SQLite3 package (if any)
# happens to be installed on the build host, and the exact version/compile-
# time options below are pinned and reproducible. docs/build-plan.md is a
# planning document, not a frozen contract (unlike docs/contracts/), so
# this is a documented implementation choice, not a contract deviation.
#
# CRITICAL isolation requirement (this milestone's task brief, the project policy's
# "-Wall -Wextra -Wpedantic -Werror" project-wide posture): sqlite3.c is
# ~250Kloc of third-party amalgamated C that does not compile clean under
# those flags, and must never be edited to make it do so. It is therefore
# built as its OWN static library target, `cytadel_sqlite3`, which:
#   - does NOT link `cytadel_warnings` (the INTERFACE target carrying
#     -Wall/-Wextra/-Wpedantic/-Werror, see cmake/CompilerWarnings.cmake) --
#     simply never opting in is already sufficient, since those flags never
#     apply project-wide by default (only targets that explicitly link
#     cytadel_warnings get them).
#   - ALSO explicitly adds -w (suppress all warnings) below, so this
#     target's warning posture is self-documenting and does not silently
#     change if a future edit to the top-level CMakeLists.txt ever starts
#     setting warnings via CMAKE_C_FLAGS instead of purely through the
#     cytadel_warnings target.
#   - DOES link `cytadel_sanitizers` (ASan+UBSan / TSan, see
#     cmake/Sanitizers.cmake) when CYTADEL_SANITIZE/CYTADEL_TSAN is ON.
#     That target is an orthogonal concern from cytadel_warnings (runtime
#     instrumentation vs. compile-time warning-as-error strictness), and
#     upstream SQLite is itself continuously fuzzed/tested under ASan/UBSan
#     (see sqlite.org's own fuzzing/testing notes), so compiling it with
#     the same sanitizer flags as the rest of the engine gives real
#     redzone/UB coverage across the actual db.c<->sqlite3.c boundary this
#     milestone's tests exercise, instead of only the (weaker) process-wide
#     malloc/free interception a final sanitized executable would still
#     get even from an unsanitized sqlite3.o.
add_library(cytadel_sqlite3 STATIC sqlite3.c)
target_include_directories(cytadel_sqlite3 PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cytadel_sqlite3 PUBLIC cytadel_sanitizers Threads::Threads)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(cytadel_sqlite3 PRIVATE -w)
endif()

# Compile-time configuration for an embedded, single-binary build (no
# SQLite CLI shell, no dynamic extension loading, no separate sqlite3
# process ever touches this file):
#
#   SQLITE_THREADSAFE=1          Full "Serialized" threading mode -- every
#                                 sqlite3_* call is internally mutex-
#                                 protected, safe to call the SAME
#                                 connection from more than one thread.
#                                 The engine runs a fixed-size worker-thread
#                                 pool (src/core/worker_pool.c); Serialized
#                                 is the simplest-to-reason-about safe
#                                 default given that pool's existence, at a
#                                 modest per-call mutex cost this project's
#                                 read/write volumes do not make a
#                                 bottleneck. (A future milestone giving
#                                 each worker its own private connection --
#                                 db-schema.md's documented model -- could
#                                 revisit this to =2/"Multi-thread" mode,
#                                 but =1 is never wrong, only occasionally
#                                 more conservative than strictly needed.)
#   SQLITE_DQS=0                 Disables the legacy "double-quoted string
#                                 literal" misfeature for BOTH DML and DDL.
#                                 With DQS off, a mistyped double-quoted
#                                 identifier that doesn't match any real
#                                 column/table name is a hard parse error
#                                 instead of silently being reinterpreted
#                                 as a string literal -- removes a classic
#                                 SQLite footgun/injection-adjacent
#                                 ambiguity at compile time, for free.
#   SQLITE_DEFAULT_MEMSTATUS=0    Disables SQLite's internal memory-usage
#                                 accounting/statistics machinery (extra
#                                 bookkeeping around every allocation this
#                                 project never queries via
#                                 sqlite3_status()/sqlite3_db_status()) --
#                                 a small, free win for an embedded build
#                                 with no memory-diagnostics UI.
#   SQLITE_OMIT_DEPRECATED        Compiles out interfaces SQLite itself has
#                                 marked deprecated (e.g. sqlite3_aggregate_count(),
#                                 the old non-v2 create_function variants).
#                                 Nothing in this codebase calls any of
#                                 them; omitting them shrinks the compiled
#                                 surface and guarantees no future code
#                                 accidentally depends on a legacy API this
#                                 project has no reason to use.
#   SQLITE_DEFAULT_FOREIGN_KEYS=1 Makes "PRAGMA foreign_keys" default to ON
#                                 for every new connection. db-schema.md
#                                 still mandates explicitly issuing
#                                 "PRAGMA foreign_keys = ON;" on every
#                                 connection (it is not persisted in the DB
#                                 file, and cytadel_db_open() always does
#                                 this regardless -- see src/db/db.c), so
#                                 this compile-time default is defense in
#                                 depth, not a substitute for that PRAGMA.
#   SQLITE_OMIT_LOAD_EXTENSION    Compiles out sqlite3_load_extension()/the
#                                 SQL load_extension() function entirely.
#                                 This is a security-hardening choice (not
#                                 explicitly requested by the milestone
#                                 brief, called out here for an explicit
#                                 stop-and-ask if a future milestone needs
#                                 extension loading): a vuln-scanner engine
#                                 embedding SQLite has no legitimate need to
#                                 dlopen() an arbitrary shared object named
#                                 by a SQL statement, and omitting this
#                                 entirely removes that surface at compile
#                                 time instead of relying on always
#                                 remembering to disable it at runtime via
#                                 sqlite3_db_config(SQLITE_DBCONFIG_ENABLE_LOAD_EXTENSION, 0, ...).
#                                 As a side effect this also drops sqlite3.c's
#                                 need to link libdl on older glibc.
target_compile_definitions(cytadel_sqlite3 PUBLIC
    SQLITE_THREADSAFE=1
    SQLITE_DQS=0
    SQLITE_DEFAULT_MEMSTATUS=0
    SQLITE_OMIT_DEPRECATED
    SQLITE_DEFAULT_FOREIGN_KEYS=1
    SQLITE_OMIT_LOAD_EXTENSION
)
