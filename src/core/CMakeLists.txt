# src/core: the scan engine/scheduler. Milestone 3 adds the fixed-size
# worker pool (worker_pool.c) that runs cytadel_host_scan() concurrently
# across an expanded target list -- the engine's first src/core code
# (docs/build-plan.md §1/§4). Aggregated into the top-level `cytadel`
# static library target, same as src/log and src/net.
#
# This is the module that first needs pthreads (top-level CMakeLists.txt's
# dependency-staging comment / docs/build-plan.md §2): Threads::Threads is
# linked here, once, PRIVATE into the shared `cytadel` aggregate target.
# For a STATIC library target, a PRIVATE link dependency still ends up on
# the link line of whatever finally links against `cytadel` (an executable
# needs pthread_create/pthread_join resolved too), it just is not exposed
# as a usage requirement (include dirs/compile defs) to consumers that
# don't need it -- matching build-plan.md §2's "each module links only the
# imported targets it actually uses" policy. src/log's mutex (also
# introduced this milestone, see src/log/log.c) rides on this same link
# requirement since log.c is compiled into this same `cytadel` target.

target_sources(cytadel PRIVATE
    worker_pool.c
)
target_link_libraries(cytadel PRIVATE Threads::Threads)
