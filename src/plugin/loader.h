#ifndef CYTADEL_PLUGIN_LOADER_H
#define CYTADEL_PLUGIN_LOADER_H

#include <stdbool.h>

#include "plugin_header.h"

/* Registration phase for exactly one plugin file (docs/contracts/
 * plugin-api.md §4.1 steps 1-6). Private to src/plugin; registry.c drives
 * this once per *.lua file found under plugins_dir. */

#ifdef __cplusplus
extern "C" {
#endif

/* On success, returns true and fills *out_hdr (caller owns it -- release
 * via cytadel_plugin_header_free()). On any failure (compile error, a
 * register{} validation luaL_error, register{} never called at all, or no
 * global `run` function defined), logs the error at ERROR level naming
 * `path` and returns false; *out_hdr is always left safe to pass to
 * cytadel_plugin_header_free() regardless (either still zeroed, or
 * partially captured and already freed internally before this returns --
 * either way the caller's own cytadel_plugin_header_free() call is a
 * correct, harmless no-op/idempotent cleanup). Never aborts the caller's
 * scan (§4.1 step 7: "a broken plugin never aborts the scan") -- this
 * function itself never longjmps/exits, only returns false. */
bool cytadel_plugin_register_one_file(const char *path, cytadel_plugin_header_t *out_hdr);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_LOADER_H */
