#ifndef CYTADEL_PLUGIN_REGISTRY_INTERNAL_H
#define CYTADEL_PLUGIN_REGISTRY_INTERNAL_H

#include "cytadel/plugin/plugin.h"
#include "plugin_header.h"

/* Private definition of the opaque cytadel_plugin_registry_t (declared in
 * the public include/cytadel/plugin/plugin.h). Shared between registry.c
 * (which builds/frees this) and scheduler.c (which walks headers[] in
 * order) -- same private-header-shared-within-module convention as
 * src/kb's kb_validate.h. */

#ifdef __cplusplus
extern "C" {
#endif

struct cytadel_plugin_registry {
    cytadel_plugin_header_t *headers; /* owned array, count entries, in fixed topo order (§4.1) */
    size_t count;
};

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_REGISTRY_INTERNAL_H */
