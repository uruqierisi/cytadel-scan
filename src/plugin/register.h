#ifndef CYTADEL_PLUGIN_REGISTER_H
#define CYTADEL_PLUGIN_REGISTER_H

#include <lua.h>

/* The engine-provided `register{...}` function (docs/contracts/
 * plugin-api.md §1) in its two forms:
 *
 *   - cytadel_plugin_register_capture: installed in the METADATA-phase
 *     sandbox (§4.1) with one upvalue -- a light userdata pointing at the
 *     cytadel_plugin_header_t the calling loader owns on its C stack.
 *     Validates every §1.2 field with luaL_error-on-violation and fills
 *     that struct.
 *   - cytadel_plugin_register_noop: installed in the RUN-phase sandbox
 *     (§4.2 step 3) with zero upvalues -- "a harmless no-op register so
 *     the chunk's top-level register{...} call doesn't error out the
 *     second time it's executed." Ignores its argument entirely.
 *
 * Both are private to src/plugin (registered directly by sandbox.c, never
 * exposed to any other module). */

#ifdef __cplusplus
extern "C" {
#endif

int cytadel_plugin_register_capture(lua_State *L);
int cytadel_plugin_register_noop(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_REGISTER_H */
