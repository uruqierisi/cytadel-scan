#ifndef CYTADEL_PLUGIN_INVOKE_H
#define CYTADEL_PLUGIN_INVOKE_H

#include "cytadel/kb/kb.h"
#include "cytadel/plugin/plugin.h"
#include "plugin_header.h"

/* Run phase for exactly one (plugin, target[, port]) invocation
 * (docs/contracts/plugin-api.md §4.2 steps 2-6, §4.5's runtime limit).
 * Private to src/plugin; scheduler.c drives this once per invocation that
 * passes required_keys gating (§4.6). */

#ifdef __cplusplus
extern "C" {
#endif

/* `bound_port` is the service-wildcard-dispatched port (§2.2a), or -1 for
 * an ordinary exact-key plugin. Appends any reported findings to
 * *findings. Returns CYTADEL_PLUGIN_RESULT_OK or
 * CYTADEL_PLUGIN_RESULT_FAILED (never CYTADEL_PLUGIN_RESULT_SKIPPED --
 * gating happens in the caller, before this is even invoked, per §4.2 step
 * 1's "cheap short-circuit": no lua_State exists yet at that point). Every
 * lua_State this function creates is closed unconditionally before
 * returning, on every path (§4.2 step 6). */
cytadel_plugin_result_status_t cytadel_plugin_invoke_one(const cytadel_plugin_header_t *header,
                                                           const char *ip, cytadel_kb_t *kb,
                                                           int bound_port,
                                                           cytadel_finding_list_t *findings);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_INVOKE_H */
