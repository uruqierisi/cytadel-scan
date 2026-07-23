#ifndef CYTADEL_CORE_WORKER_POOL_H
#define CYTADEL_CORE_WORKER_POOL_H

#include <stddef.h>

#include "cytadel/net/host_scan.h"
#include "cytadel/net/port_range.h"
#include "cytadel/net/target.h"

/* Fixed-size worker pool (Milestone 3): the engine's first src/core code.
 * Runs cytadel_host_scan() (src/net, Milestone 2) concurrently across an
 * already-expanded target list (src/net/target_list.c, Milestone 3), using
 * up to `max_workers` pthreads. Deliberately independent of main() (no CLI
 * parsing, no printing) so it is unit-testable on its own -- see
 * worker_pool.c's header comment for the queue's locking discipline. */

#ifdef __cplusplus
extern "C" {
#endif

/* Default matches CYTADEL_MAX_WORKERS in .env.example. */
#define CYTADEL_WORKER_POOL_DEFAULT_MAX_WORKERS 64

/* Hard ceiling on max_workers, regardless of what the caller (--max-workers)
 * requests -- spawning thousands of OS threads for one scan run is never
 * useful and risks exhausting local resources (fds, stack memory) well
 * before it helps throughput. */
#define CYTADEL_WORKER_POOL_HARD_CAP_WORKERS 1024

typedef struct {
    cytadel_host_result_t result; /* populated by cytadel_host_scan(); see host_scan.h for
                                    * exactly which fields are valid depending on scan_rc/state. */
    int scan_rc;                  /* cytadel_host_scan()'s return value for this target: 0 on
                                    * success (including "host is down" -- a valid outcome, not
                                    * an error), -1 if the scan itself failed. result is still
                                    * safe to pass to cytadel_host_result_free() either way. */
} cytadel_worker_result_t;

/* Runs cytadel_host_scan() for every target in `targets[0..target_count)`,
 * writing target[i]'s outcome into out_results[i] -- a fixed, pre-assigned
 * 1:1 index mapping decided before any thread starts, so workers never
 * contend on where to write a result (see worker_pool.c for the full
 * locking-discipline writeup).
 *
 * out_results must already point to an array of target_count
 * cytadel_worker_result_t (e.g. via calloc()) supplied by the caller; this
 * function only writes into existing slots, it never (re)allocates or
 * frees that array. The caller owns out_results' lifetime and must, after
 * this call returns (regardless of its return value), free every
 * out_results[i].result via cytadel_host_result_free() and then free the
 * array itself.
 *
 * max_workers is clamped to [1, CYTADEL_WORKER_POOL_HARD_CAP_WORKERS], then
 * further clamped to target_count -- this function never spawns more
 * worker threads than there are targets to scan (a large CIDR block still
 * uses at most `max_workers` threads total, never one thread per host).
 * target_count == 0 is a valid no-op: returns 0 immediately without
 * spawning any thread.
 *
 * Returns 0 if every worker thread was created and joined without a
 * pool-level (pthread_create/pthread_join) failure -- an individual host's
 * scan failure is reported via that host's out_results[i].scan_rc, not via
 * this return value, so one bad host never aborts the run for the rest.
 * Returns -1 only on a pthread-level infrastructure failure; in that case
 * every worker thread that *was* successfully created is still joined
 * before returning (no detached/leaked threads on any path).
 *
 * A partial pthread_create() failure (at least one worker created, a later
 * one failed) does *not* leave any out_results[] entry unscanned: every
 * worker that did start keeps draining the shared queue (see the locking-
 * discipline comment in worker_pool.c) until every index in
 * [0, target_count) has been claimed by some survivor, regardless of how
 * many siblings failed to start. Only the total-failure case -- the very
 * first pthread_create() call fails, so zero workers are ever created and
 * nothing drains the queue at all -- leaves out_results[] entries exactly
 * as the caller initialized them (never scanned); that case is
 * distinguishable from "scanned, host down" by checking
 * result.host[0] == '\0' (cytadel_host_scan() always fills host/ip on
 * every path it actually runs). */
int cytadel_worker_pool_run(const cytadel_target_t *targets, size_t target_count,
                             const cytadel_port_list_t *ports, const cytadel_host_scan_opts_t *opts,
                             int max_workers, cytadel_worker_result_t *out_results);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CORE_WORKER_POOL_H */
