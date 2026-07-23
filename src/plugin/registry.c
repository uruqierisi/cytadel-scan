#define _POSIX_C_SOURCE 200809L

#include "registry_internal.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "depgraph.h"
#include "loader.h"
#include "log.h"

static int cytadel_plugin_strcmp_qsort(const void *a, const void *b) {
    const char *const *sa = a;
    const char *const *sb = b;
    return strcmp(*sa, *sb);
}

/* Scans `plugins_dir` for every directory entry whose name ends in ".lua"
 * (plain files and symlinks alike -- this engine has no notion of nested
 * plugin directories, matching docs/build-plan.md §4: "plugins/ *.lua are
 * ... data"), sorted by filename (qsort + strcmp) for deterministic
 * registration/topo-tie-break order across runs. Returns 0 and fills
 * *out_names / *out_count (a malloc'd array of malloc'd filename strings,
 * caller owns both) on success, including the valid "0 files found" case
 * (*out_names == NULL, *out_count == 0 -- an empty plugins directory is
 * not itself an error). Returns -1 (nothing allocated) if `plugins_dir`
 * cannot be opened at all. */
static int cytadel_plugin_scan_lua_filenames(const char *plugins_dir, char ***out_names,
                                              size_t *out_count) {
    *out_names = NULL;
    *out_count = 0;

    DIR *dir = opendir(plugins_dir);
    if (dir == NULL) {
        cytadel_log_error("plugin registry: cannot open plugins directory '%s'", plugins_dir);
        return -1;
    }

    char **names = NULL;
    size_t count = 0, capacity = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        size_t name_len = strlen(entry->d_name);
        static const char suffix[] = ".lua";
        size_t suffix_len = sizeof(suffix) - 1;
        if (name_len <= suffix_len ||
            strcmp(entry->d_name + name_len - suffix_len, suffix) != 0) {
            continue;
        }

        if (count == capacity) {
            size_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
            char **grown = realloc(names, new_capacity * sizeof(*grown));
            if (grown == NULL) {
                cytadel_log_error("plugin registry: out of memory scanning '%s'", plugins_dir);
                for (size_t i = 0; i < count; i++) {
                    free(names[i]);
                }
                free(names);
                closedir(dir);
                return -1;
            }
            names = grown;
            capacity = new_capacity;
        }

        names[count] = malloc(name_len + 1);
        if (names[count] == NULL) {
            cytadel_log_error("plugin registry: out of memory copying filename in '%s'",
                               plugins_dir);
            for (size_t i = 0; i < count; i++) {
                free(names[i]);
            }
            free(names);
            closedir(dir);
            return -1;
        }
        memcpy(names[count], entry->d_name, name_len + 1);
        count++;
    }
    closedir(dir);

    if (count > 0) {
        qsort(names, count, sizeof(*names), cytadel_plugin_strcmp_qsort);
    }

    *out_names = names;
    *out_count = count;
    return 0;
}

/* Logs every script_id flagged in `in_cycle` (depgraph.c's output), naming
 * both id and script_name, per plugin-api.md §4.1: "a cycle is a hard
 * startup error naming the plugins involved." */
static void cytadel_plugin_log_cycle(const cytadel_plugin_header_t *headers, size_t count,
                                      const bool *in_cycle) {
    cytadel_log_error(
        "plugin registry: dependency cycle detected among the following plugin(s):");
    for (size_t i = 0; i < count; i++) {
        if (in_cycle[i]) {
            cytadel_log_error("  - script_id %lld (%s)", (long long)headers[i].script_id,
                               headers[i].script_name);
        }
    }
}

int cytadel_plugin_registry_load(const char *plugins_dir, cytadel_plugin_registry_t **out_registry) {
    *out_registry = NULL;
    if (plugins_dir == NULL) {
        cytadel_log_error("plugin registry: plugins_dir is NULL");
        return -1;
    }

    char **filenames = NULL;
    size_t filename_count = 0;
    if (cytadel_plugin_scan_lua_filenames(plugins_dir, &filenames, &filename_count) != 0) {
        return -1;
    }

    cytadel_plugin_header_t *headers = NULL;
    size_t header_count = 0;
    if (filename_count > 0) {
        headers = calloc(filename_count, sizeof(*headers));
        if (headers == NULL) {
            cytadel_log_error("plugin registry: out of memory allocating %zu header slot(s)",
                               filename_count);
            for (size_t i = 0; i < filename_count; i++) {
                free(filenames[i]);
            }
            free(filenames);
            return -1;
        }
    }

    for (size_t i = 0; i < filename_count; i++) {
        char path[4096];
        int written = snprintf(path, sizeof(path), "%s/%s", plugins_dir, filenames[i]);
        free(filenames[i]);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            cytadel_log_error("plugin registry: path too long under '%s' for filename", plugins_dir);
            continue;
        }

        cytadel_plugin_header_t candidate;
        if (!cytadel_plugin_register_one_file(path, &candidate)) {
            continue; /* already logged by loader.c; §4.1 step 7 */
        }

        bool duplicate = false;
        for (size_t j = 0; j < header_count; j++) {
            if (headers[j].script_id == candidate.script_id) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) {
            cytadel_log_error(
                "plugin registry: '%s' has script_id %lld, which collides with an "
                "already-registered plugin -- skipped",
                path, (long long)candidate.script_id);
            cytadel_plugin_header_free(&candidate);
            continue;
        }

        headers[header_count++] = candidate;
    }
    free(filenames);

    /* Build the dependency graph over exactly the successfully registered
     * headers (plugin-api.md §4.1's closing paragraphs). */
    cytadel_depgraph_node_t *nodes = NULL;
    size_t *order = NULL;
    bool *in_cycle = NULL;
    if (header_count > 0) {
        nodes = calloc(header_count, sizeof(*nodes));
        order = calloc(header_count, sizeof(*order));
        in_cycle = calloc(header_count, sizeof(*in_cycle));
        if (nodes == NULL || order == NULL || in_cycle == NULL) {
            cytadel_log_error("plugin registry: out of memory building the dependency graph");
            free(nodes);
            free(order);
            free(in_cycle);
            for (size_t i = 0; i < header_count; i++) {
                cytadel_plugin_header_free(&headers[i]);
            }
            free(headers);
            return -1;
        }
        for (size_t i = 0; i < header_count; i++) {
            nodes[i].script_id = headers[i].script_id;
            nodes[i].deps = headers[i].dependencies;
            nodes[i].dep_count = headers[i].dependency_count;
        }
    }

    size_t bad_index = 0;
    int64_t bad_dep = 0;
    cytadel_depgraph_status_t topo_status =
        cytadel_depgraph_toposort(nodes, header_count, order, &bad_index, &bad_dep, in_cycle);
    free(nodes);

    if (topo_status == CYTADEL_DEPGRAPH_MISSING_DEPENDENCY) {
        cytadel_log_error(
            "plugin registry: plugin script_id %lld (%s) declares a dependency on script_id "
            "%lld, which no loaded plugin registered -- refusing to start",
            (long long)headers[bad_index].script_id, headers[bad_index].script_name,
            (long long)bad_dep);
        free(order);
        free(in_cycle);
        for (size_t i = 0; i < header_count; i++) {
            cytadel_plugin_header_free(&headers[i]);
        }
        free(headers);
        return -1;
    }
    if (topo_status == CYTADEL_DEPGRAPH_CYCLE) {
        cytadel_plugin_log_cycle(headers, header_count, in_cycle);
        free(order);
        free(in_cycle);
        for (size_t i = 0; i < header_count; i++) {
            cytadel_plugin_header_free(&headers[i]);
        }
        free(headers);
        return -1;
    }
    free(in_cycle);

    /* Reorder headers[] into topo order in place, via a freshly built
     * array (simplest correct approach for a one-time, small-N startup
     * step -- no need for an in-place permutation cycle-walk). */
    cytadel_plugin_header_t *ordered = NULL;
    if (header_count > 0) {
        ordered = calloc(header_count, sizeof(*ordered));
        if (ordered == NULL) {
            cytadel_log_error("plugin registry: out of memory reordering %zu header(s)",
                               header_count);
            free(order);
            for (size_t i = 0; i < header_count; i++) {
                cytadel_plugin_header_free(&headers[i]);
            }
            free(headers);
            return -1;
        }
        for (size_t i = 0; i < header_count; i++) {
            ordered[i] = headers[order[i]];
        }
    }
    free(order);
    free(headers); /* shallow free only -- ownership of every entry moved into `ordered` above */

    cytadel_plugin_registry_t *registry = malloc(sizeof(*registry));
    if (registry == NULL) {
        cytadel_log_error("plugin registry: out of memory allocating the registry");
        for (size_t i = 0; i < header_count; i++) {
            cytadel_plugin_header_free(&ordered[i]);
        }
        free(ordered);
        return -1;
    }
    registry->headers = ordered;
    registry->count = header_count;

    cytadel_log_info("plugin registry: loaded %zu plugin(s) from '%s'", header_count, plugins_dir);

    *out_registry = registry;
    return 0;
}

void cytadel_plugin_registry_free(cytadel_plugin_registry_t *registry) {
    if (registry == NULL) {
        return;
    }
    for (size_t i = 0; i < registry->count; i++) {
        cytadel_plugin_header_free(&registry->headers[i]);
    }
    free(registry->headers);
    free(registry);
}

size_t cytadel_plugin_registry_count(const cytadel_plugin_registry_t *registry) {
    return (registry != NULL) ? registry->count : 0;
}
