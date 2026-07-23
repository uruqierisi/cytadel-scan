#ifndef CYTADEL_PLUGIN_FIELD_UTILS_H
#define CYTADEL_PLUGIN_FIELD_UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lua.h>

/* Small, shared helpers for pulling typed fields out of a Lua table
 * argument with luaL_error-on-violation semantics -- used by both
 * register.c (plugin-api.md §1.2's header-field validation) and
 * api_report.c (§2.9's report_vuln{...} finding-table validation), which
 * both need the same "required/optional string|integer|array-of-X field"
 * shape checking. Every function here that raises does so via luaL_error,
 * which unwinds via Lua's normal error mechanism back to the enclosing
 * lua_pcall -- callers must be running inside a protected call (register()
 * and report_vuln() always are: both are only ever invoked as C functions
 * from within Lua bytecode that is itself running under lua_pcall, per
 * plugin-api.md §4.1/§4.2). Net stack effect of every function below is
 * zero relative to entry (each pushes exactly one value with
 * lua_getfield() and pops it again before returning). Private to
 * src/plugin (same-directory quote-include convention). */

#ifdef __cplusplus
extern "C" {
#endif

/* Security-review round-2 FIX 3 (WARNING): raw (non-metamethod) equivalent
 * of lua_getfield(L, tbl_idx, field). Looks up tbl_idx[field] via
 * lua_rawget() (which NEVER triggers a __index metamethod) and pushes the
 * result exactly as lua_getfield() would -- net stack effect +1. Every
 * function below reads a PLUGIN-SUPPLIED table (register()'s header
 * literal, report_vuln()'s finding table), and setmetatable() is reachable
 * from the run-phase sandbox (plugin-api.md §5.1's base library) -- so an
 * ordinary lua_getfield() on such a table can be intercepted by a
 * plugin-installed __index. Without this, a plugin could present one
 * value to a validation pass and a different one to the extraction pass
 * that reads the "same" field moments later (a double-read / TOCTOU at the
 * Lua level), e.g. presenting `severity = 2` to whichever read happens
 * first and `severity = 99` to a later one, defeating the 0-4 bounds
 * check. `tbl_idx` MUST be an absolute (positive) stack index -- every
 * real caller in this codebase always passes the fixed argument-1 table
 * index, never a relative/negative one, so pushing the field-name string
 * (which lua_rawget() requires) never shifts what `tbl_idx` refers to. */
void cytadel_plugin_raw_getfield(lua_State *L, int tbl_idx, const char *field);

/* Reads tbl[field] (tbl_idx is the table's stack index), requires it to be
 * a non-empty Lua string, and returns a freshly strdup'd, NUL-terminated
 * copy (caller owns it -- free() it). Raises (luaL_error, does not return)
 * if the field is absent, not a string, or empty, or on allocation
 * failure. `what` names the calling C function in the error message (e.g.
 * "register" or "report_vuln"), for a clearer plugin-author-facing error. */
char *cytadel_plugin_field_required_string(lua_State *L, int tbl_idx, const char *field,
                                            const char *what);

/* Same as cytadel_plugin_field_required_string(), but empty strings are
 * accepted are not rejected (used for fields the contract does not
 * document a "non-empty" rule for -- e.g. report_vuln's optional
 * description). */
char *cytadel_plugin_field_required_string_allow_empty(lua_State *L, int tbl_idx,
                                                         const char *field, const char *what);

/* Reads tbl[field]. If absent or nil, returns NULL. If present, requires a
 * Lua string (raises otherwise) and returns a freshly strdup'd copy
 * (caller owns it). */
char *cytadel_plugin_field_optional_string(lua_State *L, int tbl_idx, const char *field,
                                            const char *what);

/* Reads tbl[field], requires an integer-valued Lua number, and returns it.
 * Raises if the field is absent or not integer-valued. */
lua_Integer cytadel_plugin_field_required_integer(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what);

/* Reads tbl[field]. If absent or nil, returns `default_value`. If present,
 * requires an integer-valued Lua number and returns it (raises otherwise). */
lua_Integer cytadel_plugin_field_optional_integer(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what, lua_Integer default_value);

/* Reads tbl[field]. If absent or nil, *out_count is set to 0 and NULL is
 * returned (a valid, empty array). If present, requires a Lua table (a
 * sequence, 1..#t) of strings, and returns a freshly malloc'd array of
 * freshly strdup'd strings (*out_count entries; caller owns both the array
 * and every string in it). Raises if the field is present but not a
 * table, or if any element is not a string. */
char **cytadel_plugin_field_optional_string_array(lua_State *L, int tbl_idx, const char *field,
                                                    const char *what, size_t *out_count);

/* Same shape as cytadel_plugin_field_optional_string_array(), but for an
 * array of integers (used for `dependencies`, an array of script_ids). */
int64_t *cytadel_plugin_field_optional_integer_array(lua_State *L, int tbl_idx, const char *field,
                                                       const char *what, size_t *out_count);

/* Frees an array returned by cytadel_plugin_field_optional_string_array()
 * (frees every element, then the array itself). Safe to call with
 * arr == NULL / count == 0 (no-op). */
void cytadel_plugin_free_string_array(char **arr, size_t count);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_FIELD_UTILS_H */
