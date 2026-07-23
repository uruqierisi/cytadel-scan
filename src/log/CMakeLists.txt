# src/log: private logging module, aggregated into the top-level `cytadel`
# static library target (declared in the top-level CMakeLists.txt before
# this subdirectory is added).
#
# log.h is deliberately NOT under include/cytadel/log/ (docs/build-plan.md
# §1 option (b) -- logging is an engine-internal concern, not part of the
# public library surface). It is still reachable from other in-repo targets
# (src/cli, tests/unit) because this directory is added to `cytadel`'s
# PUBLIC include directories below: anything that links against `cytadel`
# picks up "log.h" transitively, without it ever being installed/exported.
#
# Milestone 3: log.c uses a real pthread_mutex_t (see the comment above
# cytadel_log_lock() in log.c). No target_link_libraries(... Threads::Threads)
# call is needed here -- src/core/CMakeLists.txt already links
# Threads::Threads into this same `cytadel` aggregate target, and log.c is
# compiled into that same target, so the link requirement is already
# satisfied program-wide.
#
# strerror_safe.c/.h (Milestone 3 security fix): a small, dependency-free
# thread-safe strerror() replacement used by src/net's probe functions and
# src/core's worker pool wherever a failure path can now run concurrently
# across worker threads -- see strerror_safe.h's header comment for why it
# lives here rather than under src/net or src/core specifically.

target_sources(cytadel PRIVATE log.c strerror_safe.c)
target_include_directories(cytadel PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
