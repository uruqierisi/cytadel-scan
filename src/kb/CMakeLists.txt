# src/kb: in-memory, per-host knowledge-base store (Milestone 4, first code
# realization of docs/contracts/kb-schema.md -- FROZEN CONTRACT). Aggregated
# into the top-level `cytadel` static library target, same as every other
# module (docs/build-plan.md §4).
#
# Public header lives under include/cytadel/kb/kb.h (already a PUBLIC
# include directory of `cytadel`, set in the top-level CMakeLists.txt) --
# reachable as "cytadel/kb/kb.h" by any target linking against `cytadel`.
#
# kb_validate.h is deliberately kept private to this directory (not under
# include/cytadel/kb/, matching src/net's icmp_probe.h/tcp_ping.h
# convention): only kb.c in this same module includes it.
#
# No external dependencies (no OpenSSL/pthreads/etc. -- see kb.h's
# concurrency-model header comment for why this module carries no mutex in
# Milestone 4).

target_sources(cytadel PRIVATE
    kb_validate.c
    kb.c
)
