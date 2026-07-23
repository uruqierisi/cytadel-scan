#include "depgraph.h"

#include <stdlib.h>
#include <string.h>

/* Linear search over `nodes` for `script_id`. Fine for this milestone's
 * expected plugin counts (tens to low hundreds -- kb-schema.md §7.8's
 * Scan/plugin_count is described the same way); an O(n) lookup called
 * O(n * avg_deps) times during setup is negligible next to the network I/O
 * every plugin invocation itself performs. */
static bool cytadel_depgraph_find_index(const cytadel_depgraph_node_t *nodes, size_t count,
                                         int64_t script_id, size_t *out_index) {
    for (size_t i = 0; i < count; i++) {
        if (nodes[i].script_id == script_id) {
            *out_index = i;
            return true;
        }
    }
    return false;
}

cytadel_depgraph_status_t cytadel_depgraph_toposort(const cytadel_depgraph_node_t *nodes,
                                                      size_t count, size_t *out_order,
                                                      size_t *out_bad_index, int64_t *out_bad_dep,
                                                      bool *out_in_cycle) {
    if (out_in_cycle != NULL) {
        memset(out_in_cycle, 0, count * sizeof(*out_in_cycle));
    }
    if (count == 0) {
        return CYTADEL_DEPGRAPH_OK;
    }

    /* Validate every dependency edge resolves to a known node before doing
     * any graph work. */
    for (size_t i = 0; i < count; i++) {
        for (size_t d = 0; d < nodes[i].dep_count; d++) {
            size_t dep_index = 0;
            if (!cytadel_depgraph_find_index(nodes, count, nodes[i].deps[d], &dep_index)) {
                if (out_bad_index != NULL) {
                    *out_bad_index = i;
                }
                if (out_bad_dep != NULL) {
                    *out_bad_dep = nodes[i].deps[d];
                }
                return CYTADEL_DEPGRAPH_MISSING_DEPENDENCY;
            }
        }
    }

    /* Kahn's algorithm. in_degree[i] = number of this node's own
     * dependencies not yet placed into out_order. A node becomes ready
     * (in_degree == 0) once every plugin it depends on has already been
     * placed. */
    size_t *in_degree = calloc(count, sizeof(*in_degree));
    bool *placed = calloc(count, sizeof(*placed));
    if (in_degree == NULL || placed == NULL) {
        free(in_degree);
        free(placed);
        /* Out of memory during startup graph construction is treated the
         * same as an unresolvable graph (CYCLE is the closest fit of the
         * two failure enums; the caller logs and aborts startup either
         * way) -- there is no dedicated OOM status because this is a
         * fixed, tiny, one-time startup computation where OOM is not a
         * meaningfully different operator-facing outcome from "the plugin
         * set could not be scheduled." */
        return CYTADEL_DEPGRAPH_CYCLE;
    }
    for (size_t i = 0; i < count; i++) {
        in_degree[i] = nodes[i].dep_count;
    }

    size_t placed_count = 0;
    while (placed_count < count) {
        /* Find the lowest-index unplaced node with in_degree == 0 (ties
         * broken by ascending original index -- deterministic output for
         * identical input, which matters for reproducible test
         * expectations and reproducible scan-to-scan plugin ordering). */
        size_t ready = (size_t)-1;
        for (size_t i = 0; i < count; i++) {
            if (!placed[i] && in_degree[i] == 0) {
                ready = i;
                break;
            }
        }
        if (ready == (size_t)-1) {
            /* No unplaced node has in_degree 0: every remaining node is on
             * a cycle or depends (transitively) only on cycle members. */
            for (size_t i = 0; i < count; i++) {
                if (!placed[i] && out_in_cycle != NULL) {
                    out_in_cycle[i] = true;
                }
            }
            free(in_degree);
            free(placed);
            return CYTADEL_DEPGRAPH_CYCLE;
        }

        out_order[placed_count++] = ready;
        placed[ready] = true;

        /* Decrement in_degree for every node that depends on `ready`. */
        for (size_t i = 0; i < count; i++) {
            if (placed[i]) {
                continue;
            }
            for (size_t d = 0; d < nodes[i].dep_count; d++) {
                if (nodes[i].deps[d] == nodes[ready].script_id) {
                    in_degree[i]--;
                }
            }
        }
    }

    free(in_degree);
    free(placed);
    return CYTADEL_DEPGRAPH_OK;
}
