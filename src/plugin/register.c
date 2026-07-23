#include "register.h"

#include <stdlib.h>
#include <string.h>

#include <lauxlib.h>

#include "field_utils.h"
#include "plugin_header.h"

/* required_keys grammar validation (docs/contracts/plugin-api.md §4.6,
 * FROZEN): "Wildcards are valid only in the Services/ namespace and only
 * as a whole trailing segment / then *. No mid-path wildcard, no suffix
 * wildcard, no wildcard outside Services/. Any other * usage is a
 * registration error." Returns true and writes the byte length of the
 * "<svc>" token (via *out_svc_len, pointing at key + 9, right after
 * "Services/") iff `key` is EXACTLY "Services/<svc>/" + "*" with a non-empty
 * <svc> token made up only of kb-schema.md §2's segment charset
 * ([A-Za-z0-9_.-]+). Any other string containing a '*' returns false via
 * *out_malformed = true (a hard error, not "just an exact key"); a string
 * containing no '*' at all returns false via *out_malformed = false (an
 * ordinary exact key, valid as far as this function is concerned). */
static bool cytadel_plugin_match_service_wildcard(const char *key, size_t *out_svc_len,
                                                    bool *out_malformed) {
    *out_svc_len = 0;
    *out_malformed = false;

    if (strchr(key, '*') == NULL) {
        return false; /* ordinary exact key -- no wildcard at all */
    }

    static const char prefix[] = "Services/";
    static const size_t prefix_len = sizeof(prefix) - 1;
    size_t key_len = strlen(key);

    if (key_len <= prefix_len || strncmp(key, prefix, prefix_len) != 0) {
        *out_malformed = true; /* '*' present but not under Services/ */
        return false;
    }
    if (key[key_len - 1] != '*' || key_len < prefix_len + 3 || key[key_len - 2] != '/') {
        *out_malformed = true; /* not a whole trailing slash-asterisk segment */
        return false;
    }

    const char *svc = key + prefix_len;
    size_t svc_len = key_len - prefix_len - 2; /* exclude the trailing slash-asterisk */
    for (size_t i = 0; i < svc_len; i++) {
        unsigned char c = (unsigned char)svc[i];
        bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '-';
        if (!ok) {
            *out_malformed = true; /* bad <svc> token charset, or a second '*' inside it */
            return false;
        }
    }
    if (svc_len == 0) {
        *out_malformed = true; /* "Services//" + "*" -- empty <svc> */
        return false;
    }

    *out_svc_len = svc_len;
    return true;
}

/* Validates every required_keys entry already captured into hdr (called
 * after cytadel_plugin_field_optional_string_array() has populated
 * hdr->required_keys/required_key_count) and sets hdr->wildcard_index.
 * Raises via luaL_error on any grammar violation (§4.6) or a second
 * wildcard entry ("at most one Services/<svc>/ wildcard"). */
static void cytadel_plugin_validate_required_keys(lua_State *L, cytadel_plugin_header_t *hdr) {
    hdr->wildcard_index = (size_t)-1;

    for (size_t i = 0; i < hdr->required_key_count; i++) {
        const char *key = hdr->required_keys[i];
        if (key[0] == '\0') {
            /* %I (lua_Integer), not libc's %zu -- lua_pushvfstring()'s
             * format-spec set is not printf's. */
            luaL_error(L, "register: required_keys[%I] must not be empty", (lua_Integer)(i + 1));
        }

        size_t svc_len = 0;
        bool malformed = false;
        bool is_wildcard = cytadel_plugin_match_service_wildcard(key, &svc_len, &malformed);
        (void)svc_len;

        if (malformed) {
            luaL_error(L,
                       "register: required_keys[%I] ('%s') is not a valid pattern -- '*' is "
                       "only legal as a whole trailing \"Services/<svc>/*\" wildcard",
                       (lua_Integer)(i + 1), key);
        }

        if (is_wildcard) {
            if (hdr->wildcard_index != (size_t)-1) {
                luaL_error(L,
                           "register: required_keys may contain at most one "
                           "\"Services/<svc>/*\" wildcard (found a second at index %I)",
                           (lua_Integer)(i + 1));
            }
            hdr->wildcard_index = i;
        }
    }
}

int cytadel_plugin_register_capture(lua_State *L) {
    cytadel_plugin_header_t *hdr =
        (cytadel_plugin_header_t *)lua_touserdata(L, lua_upvalueindex(1));
    luaL_checktype(L, 1, LUA_TTABLE);

    if (hdr->captured) {
        luaL_error(L, "register: called more than once in a single plugin file");
    }

    hdr->script_id = cytadel_plugin_field_required_integer(L, 1, "script_id", "register");
    hdr->script_name = cytadel_plugin_field_required_string(L, 1, "script_name", "register");
    hdr->script_version = cytadel_plugin_field_required_string(L, 1, "script_version", "register");
    hdr->family = cytadel_plugin_field_required_string(L, 1, "family", "register");

    /* category/risk_factor are checked against a fixed enum and never
     * stored as owned strings on hdr (only hdr->category/hdr->risk_factor,
     * both plain ints), so these are read directly off the Lua stack
     * (borrowed pointer, valid only while the value stays on the stack)
     * rather than via cytadel_plugin_field_required_string()'s strdup --
     * that avoids an allocation whose only purpose would be to immediately
     * free it again on every path, including an easy-to-get-wrong leak on
     * the luaL_error (longjmp, never returns) path. */
    /* FIX 3 (security-review round 2): raw, not lua_getfield -- see
     * field_utils.h's cytadel_plugin_raw_getfield() comment. */
    cytadel_plugin_raw_getfield(L, 1, "category");
    if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "register: field 'category' is required and must be a string");
    }
    const char *category = lua_tostring(L, -1);
    if (strcmp(category, "ACT_SETTINGS") == 0) {
        hdr->category = CYTADEL_PLUGIN_CATEGORY_ACT_SETTINGS;
    } else if (strcmp(category, "ACT_GATHER_INFO") == 0) {
        hdr->category = CYTADEL_PLUGIN_CATEGORY_ACT_GATHER_INFO;
    } else {
        luaL_error(L,
                   "register: field 'category' must be \"ACT_SETTINGS\" or "
                   "\"ACT_GATHER_INFO\" (got \"%s\")",
                   category);
    }
    lua_pop(L, 1);

    hdr->dependencies = cytadel_plugin_field_optional_integer_array(L, 1, "dependencies",
                                                                      "register",
                                                                      &hdr->dependency_count);

    hdr->required_keys = cytadel_plugin_field_optional_string_array(L, 1, "required_keys",
                                                                       "register",
                                                                       &hdr->required_key_count);
    cytadel_plugin_validate_required_keys(L, hdr);

    hdr->cve = cytadel_plugin_field_optional_string_array(L, 1, "cve", "register", &hdr->cve_count);
    hdr->cvss_vector = cytadel_plugin_field_optional_string(L, 1, "cvss_vector", "register");

    /* FIX 3 (security-review round 2): raw, not lua_getfield -- see
     * field_utils.h's cytadel_plugin_raw_getfield() comment. */
    cytadel_plugin_raw_getfield(L, 1, "risk_factor");
    if (lua_type(L, -1) != LUA_TSTRING) {
        luaL_error(L, "register: field 'risk_factor' is required and must be a string");
    }
    const char *risk_factor = lua_tostring(L, -1);
    int severity = 0;
    if (!cytadel_plugin_severity_from_name(risk_factor, &severity)) {
        luaL_error(L,
                   "register: field 'risk_factor' must be one of "
                   "\"Info\"/\"Low\"/\"Medium\"/\"High\"/\"Critical\" (got \"%s\")",
                   risk_factor);
    }
    hdr->risk_factor = severity;
    lua_pop(L, 1);

    hdr->description = cytadel_plugin_field_required_string(L, 1, "description", "register");
    hdr->solution = cytadel_plugin_field_required_string(L, 1, "solution", "register");

    hdr->captured = true;
    return 0;
}

int cytadel_plugin_register_noop(lua_State *L) {
    /* Run-phase stub (plugin-api.md §4.2 step 3): the chunk's top-level
     * register{...} call is executed again every run invocation (loading
     * a plugin file always re-runs its whole top level), but the header
     * was already captured once, at registration time -- this silently
     * discards the argument instead of re-validating/re-capturing it. */
    (void)L;
    return 0;
}
