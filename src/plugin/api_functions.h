#ifndef CYTADEL_PLUGIN_API_FUNCTIONS_H
#define CYTADEL_PLUGIN_API_FUNCTIONS_H

#include <lua.h>

/* Declarations for every C-backed API function docs/contracts/
 * plugin-api.md §2 specifies, implemented across api_kb.c/api_socket.c/
 * api_http.c/api_report.c/api_log.c. Registered into the run-phase sandbox
 * table by sandbox.c's cytadel_plugin_push_run_sandbox(); nowhere else
 * calls these directly. Each function's own doc comment (in its .c file)
 * cites the exact plugin-api.md subsection it implements. */

#ifdef __cplusplus
extern "C" {
#endif

/* api_kb.c -- §2.1, §2.2, §2.2a, §2.3 */
int cytadel_plugin_api_get_kb_item(lua_State *L);
int cytadel_plugin_api_set_kb_item(lua_State *L);
int cytadel_plugin_api_get_port_state(lua_State *L);
int cytadel_plugin_api_get_scan_port(lua_State *L);

/* api_socket.c -- §2.4-§2.7 */
int cytadel_plugin_api_open_sock_tcp(lua_State *L);
int cytadel_plugin_api_send(lua_State *L);
int cytadel_plugin_api_recv(lua_State *L);
int cytadel_plugin_api_close_sock(lua_State *L);
/* Registers the "cytadel.socket" metatable (§2.4's __gc + __close) into
 * this lua_State's registry, idempotent per-state (called once by
 * cytadel_plugin_push_run_sandbox() before any socket can be created). */
void cytadel_plugin_api_socket_register_metatable(lua_State *L);

/* api_http.c -- §2.8 */
int cytadel_plugin_api_http_get(lua_State *L);

/* api_report.c -- §2.9 (report_vuln and its exact alias security_report
 * are the SAME C function, per the contract -- registered under both
 * names by sandbox.c) */
int cytadel_plugin_api_report_vuln(lua_State *L);

/* api_log.c -- §2.10 */
int cytadel_plugin_api_log(lua_State *L);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_PLUGIN_API_FUNCTIONS_H */
