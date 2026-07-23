#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "invoke.h"
#include "log.h"
#include "plugin_header.h"
#include "registry_internal.h"

/* Scheduler: required_keys gating + service-wildcard per-port dispatch
 * (docs/contracts/plugin-api.md §4.2, §4.6 -- FROZEN CONTRACT). Drives
 * invoke.c's per-invocation runner in the registry's fixed topological
 * order (registry.c / depgraph.c). */

static bool cytadel_scheduler_exact_key_present(const cytadel_kb_t *kb, const char *key) {
    cytadel_kb_value_t value;
    return cytadel_kb_get(kb, key, &value) == CYTADEL_KB_GET_FOUND;
}

/* True iff every required_keys entry OTHER than `skip_index` (the
 * wildcard's own index, or (size_t)-1 for an exact-key plugin with no
 * wildcard at all) is an exact key present in `kb`. Per §4.6: "Any
 * additional entries alongside [the wildcard] must be exact keys and act
 * as extra presence gates evaluated per dispatched port" -- these extra
 * gates are literal KB keys (no {port} templating exists in this
 * contract), so they are checked identically for every dispatched port. */
static bool cytadel_scheduler_extra_gates_satisfied(const cytadel_plugin_header_t *hdr,
                                                      const cytadel_kb_t *kb, size_t skip_index) {
    for (size_t i = 0; i < hdr->required_key_count; i++) {
        if (i == skip_index) {
            continue;
        }
        if (!cytadel_scheduler_exact_key_present(kb, hdr->required_keys[i])) {
            return false;
        }
    }
    return true;
}

typedef struct {
    const char *svc;
    size_t svc_len;
    int *ports;
    size_t count;
    size_t capacity;
} cytadel_scheduler_port_collect_t;

/* cytadel_kb_foreach() callback: collects the port number out of every KB
 * key matching exactly "Services/<svc>/<port>" (kb-schema.md §7.3) --
 * `<port>` must be the entire remainder after "Services/<svc>/" (no
 * further '/'), matching the frozen grammar's single trailing wildcard
 * segment. Malformed/unparseable port suffixes are silently skipped (a
 * defensive no-op, not a scan-ending error -- this only ever inspects KB
 * keys this same engine wrote, per kb-schema.md's writer roles). */
static void cytadel_scheduler_collect_port(const char *key, const cytadel_kb_value_t *value,
                                            void *user_data) {
    (void)value;
    cytadel_scheduler_port_collect_t *ctx = user_data;

    static const char prefix[] = "Services/";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t key_len = strlen(key);

    if (key_len <= prefix_len + ctx->svc_len + 1) {
        return;
    }
    if (strncmp(key, prefix, prefix_len) != 0) {
        return;
    }
    if (strncmp(key + prefix_len, ctx->svc, ctx->svc_len) != 0) {
        return;
    }
    if (key[prefix_len + ctx->svc_len] != '/') {
        return;
    }

    const char *port_str = key + prefix_len + ctx->svc_len + 1;
    if (port_str[0] == '\0' || strchr(port_str, '/') != NULL) {
        return; /* empty, or a deeper path than Services/<svc>/<port> */
    }

    long port = 0;
    for (const char *p = port_str; *p != '\0'; p++) {
        if (*p < '0' || *p > '9') {
            return; /* not a pure decimal port suffix */
        }
        port = port * 10 + (*p - '0');
        if (port > 65535) {
            return;
        }
    }
    if (port < 1) {
        return;
    }

    if (ctx->count == ctx->capacity) {
        size_t new_capacity = (ctx->capacity == 0) ? 8 : ctx->capacity * 2;
        int *grown = realloc(ctx->ports, new_capacity * sizeof(*grown));
        if (grown == NULL) {
            return; /* best-effort -- an OOM here just means fewer ports dispatched */
        }
        ctx->ports = grown;
        ctx->capacity = new_capacity;
    }
    ctx->ports[ctx->count++] = (int)port;
}

static int cytadel_scheduler_port_cmp(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

/* Extracts the "<svc>" token out of required_keys[wildcard_index]
 * ("Services/<svc>/" + "*", validated at registration time by
 * register.c) into a borrowed pointer + length -- no allocation needed. */
static void cytadel_scheduler_wildcard_service(const cytadel_plugin_header_t *hdr,
                                                const char **out_svc, size_t *out_svc_len) {
    const char *key = hdr->required_keys[hdr->wildcard_index];
    static const char prefix[] = "Services/";
    size_t prefix_len = sizeof(prefix) - 1;
    size_t key_len = strlen(key);
    *out_svc = key + prefix_len;
    *out_svc_len = key_len - prefix_len - 2; /* exclude the trailing slash and asterisk */
}

static void cytadel_scheduler_report(cytadel_plugin_result_fn on_result, void *user_data,
                                      int64_t script_id, const char *script_name, int bound_port,
                                      cytadel_plugin_result_status_t status) {
    if (on_result != NULL) {
        on_result(script_id, script_name, bound_port, status, user_data);
    }
}

static void cytadel_scheduler_run_exact_key_plugin(const cytadel_plugin_header_t *hdr,
                                                     const char *ip, cytadel_kb_t *kb,
                                                     cytadel_finding_list_t *out_findings,
                                                     cytadel_plugin_result_fn on_result,
                                                     void *user_data) {
    if (!cytadel_scheduler_extra_gates_satisfied(hdr, kb, (size_t)-1)) {
        cytadel_log_debug("plugin %lld %s: required_keys not satisfied, skipping",
                           (long long)hdr->script_id, hdr->script_name);
        cytadel_scheduler_report(on_result, user_data, hdr->script_id, hdr->script_name, -1,
                                  CYTADEL_PLUGIN_RESULT_SKIPPED);
        return;
    }

    cytadel_plugin_result_status_t status =
        cytadel_plugin_invoke_one(hdr, ip, kb, -1, out_findings);
    cytadel_scheduler_report(on_result, user_data, hdr->script_id, hdr->script_name, -1, status);
}

static void cytadel_scheduler_run_wildcard_plugin(const cytadel_plugin_header_t *hdr,
                                                    const char *ip, cytadel_kb_t *kb,
                                                    cytadel_finding_list_t *out_findings,
                                                    cytadel_plugin_result_fn on_result,
                                                    void *user_data) {
    const char *svc = NULL;
    size_t svc_len = 0;
    cytadel_scheduler_wildcard_service(hdr, &svc, &svc_len);

    cytadel_scheduler_port_collect_t collect;
    memset(&collect, 0, sizeof(collect));
    collect.svc = svc;
    collect.svc_len = svc_len;
    cytadel_kb_foreach(kb, cytadel_scheduler_collect_port, &collect);

    if (collect.count == 0) {
        cytadel_log_debug("plugin %lld %s: no Services/%.*s/<port> match, skipping",
                           (long long)hdr->script_id, hdr->script_name, (int)svc_len, svc);
        cytadel_scheduler_report(on_result, user_data, hdr->script_id, hdr->script_name, -1,
                                  CYTADEL_PLUGIN_RESULT_SKIPPED);
        free(collect.ports);
        return;
    }

    qsort(collect.ports, collect.count, sizeof(*collect.ports), cytadel_scheduler_port_cmp);

    for (size_t i = 0; i < collect.count; i++) {
        int port = collect.ports[i];
        if (!cytadel_scheduler_extra_gates_satisfied(hdr, kb, hdr->wildcard_index)) {
            cytadel_log_debug("plugin %lld %s: extra required_keys not satisfied for port %d, "
                               "skipping that dispatch",
                               (long long)hdr->script_id, hdr->script_name, port);
            cytadel_scheduler_report(on_result, user_data, hdr->script_id, hdr->script_name, port,
                                      CYTADEL_PLUGIN_RESULT_SKIPPED);
            continue;
        }
        cytadel_plugin_result_status_t status =
            cytadel_plugin_invoke_one(hdr, ip, kb, port, out_findings);
        cytadel_scheduler_report(on_result, user_data, hdr->script_id, hdr->script_name, port,
                                  status);
    }

    free(collect.ports);
}

void cytadel_plugin_run_all_for_host(const cytadel_plugin_registry_t *registry, const char *ip,
                                      cytadel_kb_t *kb, cytadel_finding_list_t *out_findings,
                                      cytadel_plugin_result_fn on_result, void *user_data) {
    if (registry == NULL || ip == NULL || kb == NULL || out_findings == NULL) {
        return;
    }

    for (size_t i = 0; i < registry->count; i++) {
        const cytadel_plugin_header_t *hdr = &registry->headers[i];
        if (hdr->wildcard_index == (size_t)-1) {
            cytadel_scheduler_run_exact_key_plugin(hdr, ip, kb, out_findings, on_result,
                                                    user_data);
        } else {
            cytadel_scheduler_run_wildcard_plugin(hdr, ip, kb, out_findings, on_result, user_data);
        }
    }
}
