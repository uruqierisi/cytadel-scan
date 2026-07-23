#ifndef CYTADEL_PLUGIN_DEPGRAPH_H
#define CYTADEL_PLUGIN_DEPGRAPH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Dependency-graph topological sort (docs/contracts/plugin-api.md §4.1:
 * "the engine builds a dependency graph from each header's dependencies
 * list ..., validates that every referenced script_id actually exists,
 * detects cycles (a cycle is a hard startup error naming the plugins
 * involved), and produces one fixed topological run order shared by all
 * targets in the scan"). Private to src/plugin; pure algorithm, no Lua/KB
 * dependency, straightforward to reason about/test in isolation. */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int64_t script_id;
    const int64_t *deps; /* borrowed -- not owned by the graph */
    size_t dep_count;
} cytadel_depgraph_node_t;

typedef enum {
    CYTADEL_DEPGRAPH_OK = 0,
    /* A node's dependencies[] referenced a script_id no loaded plugin
     * declared. *out_bad_index / *out_bad_dep identify the offending node
     * and the missing id. */
    CYTADEL_DEPGRAPH_MISSING_DEPENDENCY = 1,
    /* A dependency cycle exists. out_in_cycle[i] is set true for every
     * node index still unresolved when Kahn's algorithm stalls (i.e. every
     * node that is part of, or transitively depends only on, the cycle) so
     * the caller can log all of them by name. */
    CYTADEL_DEPGRAPH_CYCLE = 2
} cytadel_depgraph_status_t;

/* Computes one topological order over `nodes` (Kahn's algorithm: nodes
 * with a satisfied in-degree of 0 -- i.e. every dependency already placed
 * -- are peeled off first, ties broken by ascending original index for
 * determinism). On CYTADEL_DEPGRAPH_OK, out_order[0..count) is a
 * permutation of [0, count) such that for every dependency edge (node i
 * depends on node j), j's position in out_order precedes i's.
 * `out_in_cycle` must point to a `count`-length bool buffer (always
 * written: zeroed on OK/MISSING_DEPENDENCY, populated as described above
 * on CYCLE); the other two out-params are only meaningful on
 * MISSING_DEPENDENCY. Returns CYTADEL_DEPGRAPH_OK trivially for count ==
 * 0. */
cytadel_depgraph_status_t cytadel_depgraph_toposort(const cytadel_depgraph_node_t *nodes,
                                                      size_t count, size_t *out_order,
                                                      size_t *out_bad_index, int64_t *out_bad_dep,
                                                      bool *out_in_cycle);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_DEPGRAPH_H */
