#include "api_functions.h"

#include <string.h>

#include <lauxlib.h>

#include "log.h"
#include "plugin_ctx.h"

/* §2.10 log(level, message) -> (nothing). Raises on an unrecognized level
 * (fail loud on a plugin-author typo). Net stack effect: consumes 2 args,
 * returns 0 results (or raises). */
int cytadel_plugin_api_log(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    const char *level = luaL_checkstring(L, 1);
    const char *msg = luaL_checkstring(L, 2);

    cytadel_log_level_t lvl;
    if (strcmp(level, "debug") == 0) {
        lvl = CYTADEL_LOG_DEBUG;
    } else if (strcmp(level, "info") == 0) {
        lvl = CYTADEL_LOG_INFO;
    } else if (strcmp(level, "warn") == 0) {
        lvl = CYTADEL_LOG_WARN;
    } else if (strcmp(level, "error") == 0) {
        lvl = CYTADEL_LOG_ERROR;
    } else {
        return luaL_error(L, "log: unrecognized level '%s' (expected debug|info|warn|error)",
                           level);
    }

    long long script_id = (ctx != NULL && ctx->header != NULL) ? (long long)ctx->header->script_id : -1;
    const char *script_name = (ctx != NULL && ctx->header != NULL) ? ctx->header->script_name : "?";

    /* `msg` is passed as a %s argument, never folded into the format
     * string itself, so an untrusted/attacker-influenced message (e.g.
     * built from a banner the plugin read) can never be a format-string
     * injection; cytadel_log()'s own sanitization (log.h's W2 hardening)
     * still escapes embedded control characters before this reaches
     * stderr/the log file. */
    cytadel_log(lvl, "plugin[%lld %s]: %s", script_id, script_name, msg);
    return 0;
}
