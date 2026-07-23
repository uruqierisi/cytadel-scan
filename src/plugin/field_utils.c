#include "field_utils.h"

#include <stdlib.h>
#include <string.h>

#include <lauxlib.h>

/* See field_utils.h's own comment. */
void cytadel_plugin_raw_getfield(lua_State *L, int tbl_idx, const char *field) {
    lua_pushstring(L, field);
    lua_rawget(L, tbl_idx);
}

static char *cytadel_plugin_strdup(lua_State *L, const char *s, const char *what) {
    size_t len = strlen(s);
    char *copy = malloc(len + 1);
    if (copy == NULL) {
        luaL_error(L, "%s: out of memory copying a string field", what);
        return NULL; /* unreachable -- luaL_error longjmps */
    }
    memcpy(copy, s, len + 1);
    return copy;
}

static char *cytadel_plugin_required_string_impl(lua_State *L, int tbl_idx, const char *field,
                                                   const char *what, bool allow_empty) {
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "%s: field '%s' is required and must be a string", what, field);
    }
    size_t len = 0;
    const char *s = lua_tolstring(L, -1, &len);
    if (!allow_empty && len == 0) {
        luaL_error(L, "%s: field '%s' must be non-empty", what, field);
    }
    char *copy = cytadel_plugin_strdup(L, s, what);
    lua_pop(L, 1);
    return copy;
}

char *cytadel_plugin_field_required_string(lua_State *L, int tbl_idx, const char *field,
                                            const char *what) {
    return cytadel_plugin_required_string_impl(L, tbl_idx, field, what, false);
}

char *cytadel_plugin_field_required_string_allow_empty(lua_State *L, int tbl_idx,
                                                         const char *field, const char *what) {
    return cytadel_plugin_required_string_impl(L, tbl_idx, field, what, true);
}

char *cytadel_plugin_field_optional_string(lua_State *L, int tbl_idx, const char *field,
                                            const char *what) {
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return NULL;
    }
    if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "%s: field '%s' must be a string or nil", what, field);
    }
    const char *s = lua_tostring(L, -1);
    char *copy = cytadel_plugin_strdup(L, s, what);
    lua_pop(L, 1);
    return copy;
}

lua_Integer cytadel_plugin_field_required_integer(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what) {
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    /* lua_tointegerx() with its `isnum` out-param accepts both the Lua
     * integer subtype and an integer-valued float (e.g. 21.0), exactly
     * like luaL_checkinteger()'s own internal conversion rule -- and
     * correctly rejects a non-integer-valued float (21.5) or any
     * non-number, unlike a bare lua_isinteger() check (which would reject
     * 21.0 too, stricter than this contract's field types need). */
    int isnum = 0;
    lua_Integer v = lua_tointegerx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "%s: field '%s' is required and must be an integer", what, field);
    }
    lua_pop(L, 1);
    return v;
}

lua_Integer cytadel_plugin_field_optional_integer(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what, lua_Integer default_value) {
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return default_value;
    }
    int isnum = 0;
    lua_Integer v = lua_tointegerx(L, -1, &isnum);
    if (!isnum) {
        luaL_error(L, "%s: field '%s' must be an integer", what, field);
    }
    lua_pop(L, 1);
    return v;
}

char **cytadel_plugin_field_optional_string_array(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what, size_t *out_count) {
    *out_count = 0;
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return NULL;
    }
    if (lua_type(L, -1) != LUA_TTABLE) {
        luaL_error(L, "%s: field '%s' must be an array of strings", what, field);
    }

    int arr_idx = lua_gettop(L);
    lua_Integer n = (lua_Integer)lua_rawlen(L, arr_idx);
    if (n < 0) {
        n = 0;
    }

    char **arr = NULL;
    if (n > 0) {
        arr = calloc((size_t)n, sizeof(*arr));
        if (arr == NULL) {
            /* %I (lua_Integer), not libc's %lld -- lua_pushvfstring()'s
             * format-spec set is not printf's. */
            luaL_error(L, "%s: out of memory allocating %I-entry '%s' array", what, n, field);
        }
    }

    for (lua_Integer i = 1; i <= n; i++) {
        lua_rawgeti(L, arr_idx, i);
        if (lua_type(L, -1) != LUA_TSTRING) {
            cytadel_plugin_free_string_array(arr, (size_t)(i - 1));
            luaL_error(L, "%s: field '%s'[%I] must be a string", what, field, i);
            return NULL; /* unreachable -- luaL_error() longjmps, same idiom as
                          * cytadel_plugin_strdup() above. Makes that fact visible
                          * to the compiler's flow analysis instead of relying on
                          * it to infer noreturn through an opaque library call --
                          * without this, `arr` below is read after the free()
                          * just above on this path. GCC's -Wuse-after-free
                          * (part of this project's -Wall -Wextra -Werror gate)
                          * only flags this at higher optimization levels
                          * (-O2/-O3, i.e. a Release build) where its dataflow
                          * pass actually runs -- a -O0 Debug build (this
                          * project's documented dev-loop default) never
                          * exercises the check at all, which is how this went
                          * unnoticed. Found via M9 Phase 2's Docker scanner
                          * image, the first Release-mode build of this tree. */
        }
        const char *s = lua_tostring(L, -1);
        arr[i - 1] = cytadel_plugin_strdup(L, s, what);
        lua_pop(L, 1);
    }

    lua_pop(L, 1); /* the array table itself */
    *out_count = (size_t)n;
    return arr;
}

int64_t *cytadel_plugin_field_optional_integer_array(lua_State *L, int tbl_idx, const char *field,
                                                       const char *what, size_t *out_count) {
    *out_count = 0;
    cytadel_plugin_raw_getfield(L, tbl_idx, field); /* FIX 3: raw, not lua_getfield -- see field_utils.h */
    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        return NULL;
    }
    if (lua_type(L, -1) != LUA_TTABLE) {
        luaL_error(L, "%s: field '%s' must be an array of integers", what, field);
    }

    int arr_idx = lua_gettop(L);
    lua_Integer n = (lua_Integer)lua_rawlen(L, arr_idx);
    if (n < 0) {
        n = 0;
    }

    int64_t *arr = NULL;
    if (n > 0) {
        arr = calloc((size_t)n, sizeof(*arr));
        if (arr == NULL) {
            /* %I (lua_Integer), not libc's %lld -- lua_pushvfstring()'s
             * format-spec set is not printf's. */
            luaL_error(L, "%s: out of memory allocating %I-entry '%s' array", what, n, field);
        }
    }

    for (lua_Integer i = 1; i <= n; i++) {
        lua_rawgeti(L, arr_idx, i);
        int isnum = 0;
        lua_Integer v = lua_tointegerx(L, -1, &isnum);
        if (!isnum) {
            free(arr);
            luaL_error(L, "%s: field '%s'[%I] must be an integer", what, field, i);
            return NULL; /* unreachable -- see the identical fix + comment in
                          * cytadel_plugin_field_optional_string_array() above
                          * (the actual GCC -Wuse-after-free hit under -O3 /
                          * Release; the string-array twin has the same latent
                          * defect but wasn't flagged there because it frees via
                          * a wrapper call, not a direct free()). */
        }
        arr[i - 1] = (int64_t)v;
        lua_pop(L, 1);
    }

    lua_pop(L, 1); /* the array table itself */
    *out_count = (size_t)n;
    return arr;
}

void cytadel_plugin_free_string_array(char **arr, size_t count) {
    if (arr == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(arr[i]);
    }
    free(arr);
}
