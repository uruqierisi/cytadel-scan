#ifndef CYTADEL_PLUGIN_FINDING_INTERNAL_H
#define CYTADEL_PLUGIN_FINDING_INTERNAL_H

#include "cytadel/plugin/plugin.h"

/* Private (src/plugin-internal) counterpart to cytadel_finding_list_free()
 * (public, plugin.h) -- only api_report.c (report_vuln{}/security_report{})
 * ever appends to a findings list, so the append primitive itself stays
 * out of the public header. */

#ifdef __cplusplus
extern "C" {
#endif

/* Appends *finding to *list (growing list->items as needed, simple
 * geometric growth), taking ownership of every owned pointer field in
 * *finding (title/description/evidence/solution/cve[]/cpe/cvss_vector/
 * script_name) -- the caller must not free them itself afterward, and must
 * not reuse *finding's contents (only overwrite/discard the struct).
 * Returns 0 on success. On allocation failure, logs an error, frees every
 * owned pointer in *finding itself (so the caller never needs its own
 * cleanup path either way), and returns -1 -- the finding is silently
 * dropped from the plugin's perspective (an engine-side OOM is not turned
 * into a Lua error back at the plugin; report_vuln{}'s own §2.9
 * luaL_error() cases are reserved for schema violations, not engine
 * resource exhaustion). */
int cytadel_finding_list_append(cytadel_finding_list_t *list, cytadel_finding_t *finding);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_FINDING_INTERNAL_H */
