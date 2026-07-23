#ifndef CYTADEL_PLUGIN_HEADER_H
#define CYTADEL_PLUGIN_HEADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Plugin metadata header (docs/contracts/plugin-api.md §1 -- FROZEN
 * CONTRACT) captured by register{...} at registration time (§4.1). Kept
 * private to src/plugin (not under include/cytadel/plugin/), matching this
 * codebase's existing private-header convention (e.g. src/net's
 * banner_grab.h/svc_token.h) -- only this module's own translation units
 * need the full field layout; the public surface (include/cytadel/plugin/
 * plugin.h) exposes just enough (script_id/script_name/severity/port/...)
 * through cytadel_finding_t and the run-callback signature for a caller to
 * report/log results, never this struct itself. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_PLUGIN_CATEGORY_ACT_SETTINGS = 0,
    CYTADEL_PLUGIN_CATEGORY_ACT_GATHER_INFO = 1
} cytadel_plugin_category_t;

/* Every owned pointer below is heap-allocated (strdup'd out of the Lua
 * table register{...} received -- Lua's own string/table memory is freed
 * when this registration's lua_State is closed, so nothing here may borrow
 * a Lua-owned pointer) and outlives the lua_State that captured it, per
 * plugin-api.md §4.1 step 4 ("captured into a C-side struct -- table
 * field, not Lua value, so it outlives this lua_State"). */
typedef struct {
    int64_t script_id;
    char *script_name;      /* owned, non-empty */
    char *script_version;   /* owned, non-empty */
    char *family;            /* owned, non-empty */
    cytadel_plugin_category_t category;

    int64_t *dependencies;      /* owned array of script_ids, may be NULL if dependency_count == 0 */
    size_t dependency_count;

    char **required_keys;       /* owned array of owned strings, may be NULL if required_key_count == 0 */
    size_t required_key_count;
    /* Index into required_keys of the single Services/<svc>/ wildcard
     * entry (plugin-api.md §4.6), or (size_t)-1 if this plugin has none
     * (an ordinary exact-key plugin). Registration-time validation
     * (plugin_header.c) already guarantees at most one such entry exists,
     * so the scheduler (scheduler.c) never has to re-scan for it. */
    size_t wildcard_index;

    char **cve;                 /* owned array of owned strings (header catalog CVEs), may be NULL if cve_count == 0 */
    size_t cve_count;

    char *cvss_vector;           /* owned, nullable */
    int risk_factor;              /* 0-4 canon severity (plugin-api.md §0), mapped from the risk_factor string */
    char *description;            /* owned, non-empty */
    char *solution;                /* owned, non-empty -- report_vuln's default when a finding omits its own solution */

    char *source_path;             /* owned -- the plugins/ *.lua file this header came from, for logging/luaL_loadfile */

    /* Set true only once every required field has been successfully
     * captured by cytadel_plugin_register_capture() (register.c). A
     * plugin file whose top level never actually calls register{...} (or
     * errors before completing it) leaves this false, which the loader
     * (loader.c) treats as a registration failure distinct from a
     * validation luaL_error (both are logged and the file is skipped, but
     * this catches the "never called register at all" case that no
     * luaL_error would otherwise flag). */
    bool captured;
} cytadel_plugin_header_t;

/* Frees every owned field of *hdr and zeroes it (idempotent, safe on an
 * already-zeroed/freed header and on hdr == NULL -- matches
 * cytadel_kb_free()/cytadel_host_result_free()'s free-function idiom
 * elsewhere in this codebase). Does not free hdr itself (hdr is always
 * embedded by value in an owning array in this module, never individually
 * heap-allocated). */
void cytadel_plugin_header_free(cytadel_plugin_header_t *hdr);

/* Maps a plugin-api.md §0 canon severity name ("Info"/"Low"/"Medium"/
 * "High"/"Critical", case-sensitive) to its 0-4 integer. Returns true and
 * writes *out on a recognized name, false (leaving *out untouched)
 * otherwise. */
bool cytadel_plugin_severity_from_name(const char *name, int *out);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_HEADER_H */
