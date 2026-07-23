#include "api_functions.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <lauxlib.h>

#include "field_utils.h"
#include "finding_internal.h"
#include "plugin_ctx.h"

/* Milestone 5 security-audit finding W3: validates the TYPE/shape of
 * every report_vuln{} field -- exactly mirroring the rules
 * cytadel_plugin_field_required_string()/_optional_string()/
 * _optional_string_array() (field_utils.c) and the inline severity/port
 * checks below enforce -- WITHOUT allocating anything. Called before any
 * of those allocating calls run. Without this pre-pass, e.g. an
 * evidence/description/solution/... field with a wrong type would raise
 * (luaL_error, longjmp) from partway through the sequence of allocating
 * field_utils calls below, past the free() of every field successfully
 * allocated for an earlier field in that same call -- directly
 * plugin-triggerable (any pcall-wrapped report_vuln{} call with one
 * wrong-typed optional field, repeated in a loop) heap growth. Validating
 * every field up front means no allocation below is ever reached while a
 * still-to-be-validated field remains unchecked, so once extraction
 * begins none of it can raise for a *validation* reason (an
 * allocation-failure/OOM raise from strdup() itself is a separate,
 * unavoidable, non-plugin-triggerable corner case, not what this fix
 * targets). Raises (luaL_error) and does not return on the first
 * violation found, in the same field order/wording report_vuln{} has
 * always validated in. Net stack effect: 0 (every cytadel_plugin_raw_getfield()/
 * lua_rawgeti() push is popped again before returning or before raising). */
static void cytadel_report_vuln_validate_fields(lua_State *L, const char *what) {
    /* FIX 3 (security-review round 2): raw, not lua_getfield, everywhere
     * this validate pass and the extraction pass below it read the
     * plugin-supplied finding table -- see field_utils.h's
     * cytadel_plugin_raw_getfield() comment for why (setmetatable() is
     * reachable from the sandbox; an ordinary lua_getfield() honours a
     * plugin-installed __index, which could otherwise present a different
     * value to this validation pass than to the extraction pass moments
     * later). */
    cytadel_plugin_raw_getfield(L, 1, "severity");
    int is_int = 0;
    lua_Integer severity = lua_tointegerx(L, -1, &is_int);
    lua_pop(L, 1);
    if (!is_int) {
        luaL_error(L, "%s: field 'severity' is required and must be an integer", what);
    }
    if (severity < 0 || severity > 4) {
        /* %I (lua_Integer), not libc's %lld -- lua_pushvfstring()'s
         * format-spec set is not printf's. */
        luaL_error(L, "%s: field 'severity' must be 0-4 (got %I)", what, severity);
    }

    static const char *const required_str_fields[] = {"title", "evidence"};
    for (size_t i = 0; i < sizeof(required_str_fields) / sizeof(required_str_fields[0]); i++) {
        cytadel_plugin_raw_getfield(L, 1, required_str_fields[i]);
        bool is_str = lua_type(L, -1) == LUA_TSTRING;
        size_t len = 0;
        if (is_str) {
            lua_tolstring(L, -1, &len);
        }
        lua_pop(L, 1);
        if (!is_str) {
            luaL_error(L, "%s: field '%s' is required and must be a string", what,
                       required_str_fields[i]);
        }
        if (len == 0) {
            luaL_error(L, "%s: field '%s' must be non-empty", what, required_str_fields[i]);
        }
    }

    cytadel_plugin_raw_getfield(L, 1, "port");
    is_int = 0;
    lua_tointegerx(L, -1, &is_int);
    lua_pop(L, 1);
    if (!is_int) {
        luaL_error(L, "%s: field 'port' is required and must be an integer", what);
    }

    static const char *const optional_str_fields[] = {"description", "solution", "cpe",
                                                        "cvss_vector"};
    for (size_t i = 0; i < sizeof(optional_str_fields) / sizeof(optional_str_fields[0]); i++) {
        cytadel_plugin_raw_getfield(L, 1, optional_str_fields[i]);
        bool is_nil = lua_isnil(L, -1);
        bool ok = is_nil || lua_type(L, -1) == LUA_TSTRING;
        lua_pop(L, 1);
        if (!ok) {
            luaL_error(L, "%s: field '%s' must be a string or nil", what, optional_str_fields[i]);
        }
    }

    cytadel_plugin_raw_getfield(L, 1, "cve");
    if (!lua_isnil(L, -1)) {
        if (lua_type(L, -1) != LUA_TTABLE) {
            luaL_error(L, "%s: field 'cve' must be an array of strings", what);
        }
        int arr_idx = lua_gettop(L);
        lua_Integer n = (lua_Integer)lua_rawlen(L, arr_idx);
        for (lua_Integer i = 1; i <= n; i++) {
            lua_rawgeti(L, arr_idx, i);
            bool ok = lua_type(L, -1) == LUA_TSTRING;
            lua_pop(L, 1);
            if (!ok) {
                /* %I (lua_Integer), not libc's %lld. */
                luaL_error(L, "%s: field 'cve'[%I] must be a string", what, i);
            }
        }
    }
    lua_pop(L, 1); /* cve (table or nil) */
}

/* §2.9 report_vuln(finding) / security_report(finding) -- the SAME C
 * function registered under both Lua global names by sandbox.c (an exact
 * alias, per the contract: "There is no separate positional-argument ...
 * form"). Validates every field, raising (luaL_error) on any schema
 * violation, then appends the finding to this invocation's findings sink.
 * Net stack effect: consumes 1 arg (the finding table), returns 0 results
 * (or raises). */
int cytadel_plugin_api_report_vuln(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    luaL_checktype(L, 1, LUA_TTABLE);
    static const char *const what = "report_vuln";

    /* W3 security-audit fix: see cytadel_report_vuln_validate_fields()'s
     * own comment -- guarantees nothing below can raise for a validation
     * reason once extraction (and allocation) begins. */
    cytadel_report_vuln_validate_fields(L, what);

    cytadel_plugin_raw_getfield(L, 1, "severity");
    int is_int = 0;
    lua_Integer severity = lua_tointegerx(L, -1, &is_int);
    lua_pop(L, 1);
    /* is_int is guaranteed true here -- already validated above. FIX 3
     * (security-review round 2): re-check the 0-4 bounds here too, at the
     * extraction site, not just in the validate pass above -- both reads
     * now use cytadel_plugin_raw_getfield() (immune to __index), but this
     * second check is defense-in-depth against the two validation paths
     * ever drifting apart (matching the existing "port" re-check pattern
     * just below), which is exactly the class of bug (validate one thing,
     * extract another) W3/FIX 3 close off. */
    if (severity < 0 || severity > 4) {
        /* %I (lua_Integer), not libc's %lld -- lua_pushvfstring()'s
         * format-spec set is not printf's. */
        return luaL_error(L, "%s: field 'severity' must be 0-4 (got %I)", what, severity);
    }

    char *title = cytadel_plugin_field_required_string(L, 1, "title", what);
    char *evidence = cytadel_plugin_field_required_string(L, 1, "evidence", what);

    cytadel_plugin_raw_getfield(L, 1, "port");
    is_int = 0;
    lua_Integer port = lua_tointegerx(L, -1, &is_int);
    lua_pop(L, 1);
    if (!is_int) {
        /* Unreachable given cytadel_report_vuln_validate_fields() above --
         * kept as a defense-in-depth safety net (still frees everything
         * allocated so far before raising) rather than an assert(), in
         * case the two validation paths ever drift apart. */
        free(title);
        free(evidence);
        return luaL_error(L, "%s: field 'port' is required and must be an integer", what);
    }

    char *description = cytadel_plugin_field_optional_string(L, 1, "description", what);
    char *solution = cytadel_plugin_field_optional_string(L, 1, "solution", what);
    size_t cve_count = 0;
    char **cve = cytadel_plugin_field_optional_string_array(L, 1, "cve", what, &cve_count);
    char *cpe = cytadel_plugin_field_optional_string(L, 1, "cpe", what);
    char *cvss_vector = cytadel_plugin_field_optional_string(L, 1, "cvss_vector", what);

    /* §2.9: "if omitted, the engine falls back to the plugin header's
     * solution" (explicit for `solution`); `cvss_vector`'s "Overrides the
     * header's default for this finding" is the same fallback pattern
     * applied consistently (see this project's own interpretation notes --
     * the contract text for cvss_vector implies the same default-exists
     * relationship it states explicitly for solution). */
    if (solution == NULL && ctx->header->solution != NULL) {
        size_t len = strlen(ctx->header->solution);
        solution = malloc(len + 1);
        if (solution != NULL) {
            memcpy(solution, ctx->header->solution, len + 1);
        }
    }
    if (cvss_vector == NULL && ctx->header->cvss_vector != NULL) {
        size_t len = strlen(ctx->header->cvss_vector);
        cvss_vector = malloc(len + 1);
        if (cvss_vector != NULL) {
            memcpy(cvss_vector, ctx->header->cvss_vector, len + 1);
        }
    }

    char *script_name_copy = NULL;
    if (ctx->header->script_name != NULL) {
        size_t len = strlen(ctx->header->script_name);
        script_name_copy = malloc(len + 1);
        if (script_name_copy != NULL) {
            memcpy(script_name_copy, ctx->header->script_name, len + 1);
        }
    }

    cytadel_finding_t finding;
    memset(&finding, 0, sizeof(finding));
    finding.severity = (int)severity;
    finding.title = title;
    finding.description = description;
    finding.evidence = evidence;
    finding.port = (int64_t)port;
    finding.solution = solution;
    finding.cve = cve;
    finding.cve_count = cve_count;
    finding.cpe = cpe;
    finding.cvss_vector = cvss_vector;
    finding.script_id = ctx->header->script_id;
    finding.script_name = script_name_copy;

    /* cytadel_finding_list_append() takes ownership of every owned pointer
     * above (or frees them itself on an OOM failure path) -- nothing left
     * for this function to free either way. */
    cytadel_finding_list_append(ctx->findings, &finding);
    return 0;
}
