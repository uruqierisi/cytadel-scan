#define _POSIX_C_SOURCE 200809L

#include "cytadel/core/worker_pool.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "strerror_safe.h"

/* ---------------------------------------------------------------------
 * Locking discipline (read this before touching the queue).
 *
 * The "work queue" is not a linked list or ring buffer guarded by a
 * mutex/condvar -- it is the flat, read-only `targets` array plus a single
 * shared atomic cursor, `next_index`. Every worker thread runs the exact
 * same loop:
 *
 *     for (;;) {
 *         size_t i = atomic_fetch_add_explicit(&ctx->next_index, 1, memory_order_relaxed);
 *         if (i >= ctx->target_count) break;      // queue drained, this worker exits
 *         ... scan targets[i], write the outcome into out_results[i] ...
 *     }
 *
 * INVARIANT: atomic_fetch_add is a single indivisible read-modify-write.
 * That means every value of `i` in [0, target_count) is handed out to
 * exactly one worker, exactly once, no matter how many workers are racing
 * to call it or how the scheduler interleaves them -- there is no way for
 * two workers to claim the same index (no lost updates, no double
 * claims), and `next_index` itself needs no mutex/condvar to stay
 * consistent.
 *
 * Because index claims are disjoint, the moment a worker claims index i it
 * becomes the *sole* writer of out_results[i] for the remainder of the
 * run: no other worker will ever claim i again, so out_results needs no
 * locking either -- this is the "own pre-assigned result slot" design the
 * milestone calls for, not an incidental optimization. `targets` itself is
 * never mutated after cytadel_worker_pool_run() is called, so concurrent
 * reads of targets[i] by different workers are race-free by construction
 * (read-only shared state has no data race regardless of how many readers
 * there are).
 *
 * The only remaining cross-thread synchronization is pthread_create()'s /
 * pthread_join()'s happens-before edge: everything a worker wrote to
 * out_results[] before returning from its thread function is guaranteed
 * visible to the parent thread once pthread_join() returns for that
 * worker. cytadel_worker_pool_run() joins every worker it created before
 * returning, so the caller sees a fully-populated out_results[] with no
 * additional synchronization of its own.
 *
 * memory_order_relaxed is sufficient for next_index (it is not used to
 * publish any other data -- the data being "published" is out_results[i],
 * and that publication is carried by the join, not by the atomic op), so
 * there is no need for acquire/release ordering here.
 * --------------------------------------------------------------------- */

typedef struct {
    const cytadel_target_t *targets;
    size_t target_count;
    const cytadel_port_list_t *ports;
    const cytadel_host_scan_opts_t *opts;
    cytadel_worker_result_t *out_results;
    atomic_size_t next_index;
} cytadel_worker_pool_ctx_t;

static void *cytadel_worker_pool_thread_main(void *arg) {
    cytadel_worker_pool_ctx_t *ctx = (cytadel_worker_pool_ctx_t *)arg;

    for (;;) {
        size_t i = atomic_fetch_add_explicit(&ctx->next_index, 1, memory_order_relaxed);
        if (i >= ctx->target_count) {
            break;
        }

        cytadel_worker_result_t *slot = &ctx->out_results[i];
        int rc = cytadel_host_scan(&ctx->targets[i], ctx->ports, ctx->opts, &slot->result);
        slot->scan_rc = rc;
        if (rc != 0) {
            cytadel_log_error("worker pool: scan failed for target '%s'", ctx->targets[i].host);
        }
    }

    return NULL;
}

int cytadel_worker_pool_run(const cytadel_target_t *targets, size_t target_count,
                             const cytadel_port_list_t *ports, const cytadel_host_scan_opts_t *opts,
                             int max_workers, cytadel_worker_result_t *out_results) {
    if (target_count == 0) {
        return 0;
    }
    if (targets == NULL || ports == NULL || out_results == NULL) {
        return -1;
    }

    if (max_workers < 1) {
        max_workers = 1;
    }
    if (max_workers > CYTADEL_WORKER_POOL_HARD_CAP_WORKERS) {
        max_workers = CYTADEL_WORKER_POOL_HARD_CAP_WORKERS;
    }

    size_t worker_count = (size_t)max_workers;
    if (worker_count > target_count) {
        /* Never one-thread-per-host for a large block -- but also never
         * spawn more threads than there is work, e.g. a single target
         * with --max-workers 64 uses exactly 1 worker, not 64 idle ones. */
        worker_count = target_count;
    }

    cytadel_worker_pool_ctx_t ctx;
    ctx.targets = targets;
    ctx.target_count = target_count;
    ctx.ports = ports;
    ctx.opts = opts;
    ctx.out_results = out_results;
    atomic_init(&ctx.next_index, 0);

    pthread_t *threads = calloc(worker_count, sizeof(pthread_t));
    if (threads == NULL) {
        cytadel_log_error("worker pool: out of memory allocating %zu thread handle(s)", worker_count);
        return -1;
    }

    size_t created = 0;
    int create_failed = 0;
    for (size_t t = 0; t < worker_count; t++) {
        int rc = pthread_create(&threads[t], NULL, cytadel_worker_pool_thread_main, &ctx);
        if (rc != 0) {
            /* Data-race hardening: by the time a later pthread_create()
             * call can fail, earlier-created workers are already running
             * cytadel_worker_pool_thread_main() on other threads and may
             * be calling strerror() of their own (via src/net's probe
             * functions) concurrently with this one -- strerror() is not
             * guaranteed thread-safe (glibc races on a shared static
             * buffer for an unrecognized errno), so this must use the
             * thread-safe helper too, not just the calls inside the
             * worker loop itself. */
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            cytadel_log_error("worker pool: pthread_create failed for worker %zu: %s", t,
                               cytadel_strerror_safe(rc, errbuf, sizeof(errbuf)));
            create_failed = 1;
            break;
        }
        created++;
    }

    /* Every thread that was actually created is joined here, whether or
     * not a later pthread_create() call failed -- no detached/leaked
     * threads on any path. Workers that did start keep draining the
     * shared queue regardless of how many siblings failed to start; a
     * failed pthread_create() only means fewer workers help drain it, it
     * never stops the drain or corrupts already-claimed slots. */
    int join_failed = 0;
    for (size_t t = 0; t < created; t++) {
        int rc = pthread_join(threads[t], NULL);
        if (rc != 0) {
            /* Same reasoning as the pthread_create() failure path above:
             * threads not yet joined in this loop may still be running
             * and calling strerror() concurrently. */
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            cytadel_log_error("worker pool: pthread_join failed for worker %zu: %s", t,
                               cytadel_strerror_safe(rc, errbuf, sizeof(errbuf)));
            join_failed = 1;
        }
    }

    free(threads);

    return (create_failed || join_failed) ? -1 : 0;
}
