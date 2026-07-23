#include "api_functions.h"

#include <stdbool.h>
#include <stdio.h>

#include <lauxlib.h>

#include "plugin_ctx.h"

/* §2.1 get_kb_item(key) -> string|integer|boolean|nil. Net stack effect:
 * consumes 1 arg, returns 1 result. */
int cytadel_plugin_api_get_kb_item(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    const char *key = luaL_checkstring(L, 1);

    cytadel_kb_value_t value;
    cytadel_kb_get_status_t status = cytadel_kb_get(ctx->kb, key, &value);
    if (status != CYTADEL_KB_GET_FOUND) {
        /* §4: absent (and invalid-key, per kb-schema.md §4) both read as a
         * normal, expected nil -- never an error. */
        lua_pushnil(L);
        return 1;
    }

    switch (value.type) {
        case CYTADEL_KB_TYPE_STRING:
            /* lua_pushstring() copies the bytes into a fresh Lua string;
             * value.v.str's borrowed-pointer validity window (kb.h) does
             * not need to outlive this call. */
            lua_pushstring(L, value.v.str);
            break;
        case CYTADEL_KB_TYPE_INT:
            lua_pushinteger(L, (lua_Integer)value.v.i64);
            break;
        case CYTADEL_KB_TYPE_BOOL:
            lua_pushboolean(L, value.v.b);
            break;
        default:
            lua_pushnil(L);
            break;
    }
    return 1;
}

/* §2.2 set_kb_item(key, value) -> (nothing). Fail-loud (luaL_error) on any
 * validation failure -- delegates the actual validation to the KB's own
 * cytadel_kb_set_*() calls (kb-schema.md §2/§3), which already log a WARN
 * and reject (return -1, store nothing) on an invalid/over-length key, an
 * over-length string value, or invalid UTF-8; this wrapper just turns that
 * -1 into a Lua error, per §2.2's "reject, never truncate" / "raises a Lua
 * error" contract. Net stack effect: consumes 2 args, returns 0 results
 * (or raises). */
int cytadel_plugin_api_set_kb_item(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    const char *key = luaL_checkstring(L, 1);
    int value_type = lua_type(L, 2);

    int rc;
    switch (value_type) {
        case LUA_TSTRING: {
            size_t len = 0;
            const char *s = lua_tolstring(L, 2, &len);
            rc = cytadel_kb_set_str_n(ctx->kb, key, s, len);
            break;
        }
        case LUA_TNUMBER: {
            int is_int = 0;
            lua_Integer v = lua_tointegerx(L, 2, &is_int);
            if (!is_int) {
                return luaL_error(L,
                                   "set_kb_item: numeric value for key '%s' must be an integer, "
                                   "not a non-integer float",
                                   key);
            }
            rc = cytadel_kb_set_int(ctx->kb, key, (int64_t)v);
            break;
        }
        case LUA_TBOOLEAN:
            rc = cytadel_kb_set_bool(ctx->kb, key, lua_toboolean(L, 2) != 0);
            break;
        default:
            return luaL_error(L,
                               "set_kb_item: unsupported value type '%s' for key '%s' (expected "
                               "string, integer, or boolean)",
                               lua_typename(L, value_type), key);
    }

    if (rc != 0) {
        return luaL_error(L,
                           "set_kb_item: rejected key '%s' (invalid/over-length key, "
                           "over-length value, or invalid content -- see the engine log)",
                           key);
    }
    return 0;
}

/* §2.3 get_port_state(port) -> boolean, always. Reads Ports/tcp/<port>
 * (kb-schema.md §7.2: int, 0=closed/1=open/2=filtered) and answers "is
 * this port open" as a plain boolean -- the contract's own prose
 * ("equivalent to get_kb_item(...) == true") is reconciled against
 * kb-schema.md's authoritative int type for this key: comparing an int
 * against Lua `true` is always false, which would make this function
 * always return false (breaking even the contract's own §3 example
 * plugin's `if not get_port_state(21) then return end` guard) -- the
 * intended, non-degenerate reading is "true iff the stored state equals
 * CYTADEL_PORT_OPEN (1)". Net stack effect: consumes 1 arg, returns 1
 * result. */
int cytadel_plugin_api_get_port_state(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    lua_Integer port = luaL_checkinteger(L, 1);

    char key[32];
    snprintf(key, sizeof(key), "Ports/tcp/%lld", (long long)port);

    cytadel_kb_value_t value;
    cytadel_kb_get_status_t status = cytadel_kb_get(ctx->kb, key, &value);
    bool is_open = (status == CYTADEL_KB_GET_FOUND && value.type == CYTADEL_KB_TYPE_INT &&
                    value.v.i64 == 1 /* CYTADEL_PORT_OPEN */);
    lua_pushboolean(L, is_open);
    return 1;
}

/* §2.2a get_scan_port() -> integer | nil. Net stack effect: consumes 0
 * args, returns 1 result. */
int cytadel_plugin_api_get_scan_port(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    if (ctx->bound_port < 0) {
        lua_pushnil(L);
    } else {
        lua_pushinteger(L, ctx->bound_port);
    }
    return 1;
}
