#ifndef CYTADEL_CORE_VERSION_H
#define CYTADEL_CORE_VERSION_H

/* Public version constants for the Cytadel Scan engine. This is one of the
 * few Milestone 1 headers that genuinely has a cross-module public surface
 * (docs/build-plan.md §1), so it lives under include/cytadel/core/ rather
 * than as a private per-module header.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define CYTADEL_VERSION_MAJOR 0
#define CYTADEL_VERSION_MINOR 1
#define CYTADEL_VERSION_PATCH 0
#define CYTADEL_VERSION_STRING "0.1.0"

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CORE_VERSION_H */
