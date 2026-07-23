#define _POSIX_C_SOURCE 200809L

#include "api_functions.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/ssl.h>

#include <lauxlib.h>
#include <lua.h>

#include "api_socket.h"
#include "field_utils.h"
#include "plugin_ctx.h"
#include "timeout_clamp.h"
#include "tls_session.h"

/* §2.8 http_get(port, path [, opts]) -- built directly on this module's
 * own raw-TCP connect helper (api_socket.c, shared with open_sock_tcp())
 * and src/net's existing tls_session.h (cytadel_net_tls_connect(), the
 * same TLS-handshake primitive service_detect.c/http_probe.c already use)
 * -- deliberately NOT libcurl, per this milestone's scope. This is a
 * general-purpose GET/HEAD client (arbitrary path/headers/method, full
 * lowercased header map, 1 MiB body cap), distinct from http_probe.c's
 * fixed "GET / HTTP/1.0" baseline-detection probe used by
 * service_detect.c -- the two have different jobs and different response
 * shapes, so this does not reuse http_probe.c's parser. */

/* §2.8: "bodies larger than that are truncated to the cap ... 1,048,576
 * bytes (1 MiB)." */
#define CYTADEL_HTTP_BODY_CAP (1024 * 1024)
/* Generous cap on the status-line + header section alone, before giving up
 * and treating it as a protocol error -- real responses' headers are a
 * tiny fraction of this. Total read cap is this plus the body cap. */
#define CYTADEL_HTTP_HEADER_CAP (65536)
#define CYTADEL_HTTP_TOTAL_CAP (CYTADEL_HTTP_HEADER_CAP + CYTADEL_HTTP_BODY_CAP)

typedef struct {
    int fd;
    SSL *ssl; /* NULL for plain TCP */
} cytadel_http_conn_t;

static ssize_t cytadel_http_conn_read(cytadel_http_conn_t *conn, char *buf, size_t len) {
    if (conn->ssl != NULL) {
        int n = SSL_read(conn->ssl, buf, (int)len);
        return (n > 0) ? (ssize_t)n : -1;
    }
    return recv(conn->fd, buf, len, 0);
}

static bool cytadel_http_conn_write_all(cytadel_http_conn_t *conn, const char *data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        if (conn->ssl != NULL) {
            int n = SSL_write(conn->ssl, data + sent, (int)(len - sent));
            if (n <= 0) {
                return false;
            }
            sent += (size_t)n;
        } else {
            ssize_t n = send(conn->fd, data + sent, len - sent, 0);
            if (n <= 0) {
                return false;
            }
            sent += (size_t)n;
        }
    }
    return true;
}

/* Reads until EOF or CYTADEL_HTTP_TOTAL_CAP bytes accumulated (whichever
 * first), growing *out_buf geometrically. Returns 0 on success (even a
 * zero-byte response is "success" -- an empty response body is a valid,
 * if unusual, outcome for the parser to report on), -1 on allocation
 * failure. */
static int cytadel_http_read_all(cytadel_http_conn_t *conn, char **out_buf, size_t *out_len) {
    size_t capacity = 8192;
    char *buf = malloc(capacity);
    if (buf == NULL) {
        return -1;
    }
    size_t len = 0;

    for (;;) {
        if (len >= CYTADEL_HTTP_TOTAL_CAP) {
            break;
        }
        if (len == capacity) {
            size_t new_capacity = capacity * 2;
            if (new_capacity > CYTADEL_HTTP_TOTAL_CAP + 1) {
                new_capacity = CYTADEL_HTTP_TOTAL_CAP + 1;
            }
            char *grown = realloc(buf, new_capacity);
            if (grown == NULL) {
                free(buf);
                return -1;
            }
            buf = grown;
            capacity = new_capacity;
        }
        ssize_t n = cytadel_http_conn_read(conn, buf + len, capacity - len);
        if (n <= 0) {
            break; /* EOF, timeout, or error -- whatever was read so far is what we parse */
        }
        len += (size_t)n;
    }

    *out_buf = buf;
    *out_len = len;
    return 0;
}

typedef struct {
    const char *name_start;
    size_t name_len;
    const char *value_start;
    size_t value_len;
} cytadel_http_header_pair_t;

/* Bounded, index-checked response parser -- same "never read past `len`"
 * discipline as http_probe.c's cytadel_http_parse_response(), generalized
 * to a full header map instead of just Server/title. Writes *out_status
 * (-1 if not parsed), fills `pairs` (caller-provided, `pairs_cap` entries)
 * with up to that many raw header name/value spans into `buf` (borrowed,
 * not copied), *out_pair_count, and *out_body_start (byte offset into buf
 * where the body begins, or `len` if no blank-line terminator was ever
 * found). */
static void cytadel_http_parse(const char *buf, size_t len, int *out_status,
                                cytadel_http_header_pair_t *pairs, size_t pairs_cap,
                                size_t *out_pair_count, size_t *out_body_start) {
    *out_status = -1;
    *out_pair_count = 0;
    *out_body_start = len;

    if (len >= 5 && memcmp(buf, "HTTP/", 5) == 0) {
        size_t i = 5;
        while (i < len && buf[i] != ' ' && buf[i] != '\n') {
            i++;
        }
        if (i < len && buf[i] == ' ') {
            i++;
            if (i + 3 <= len && buf[i] >= '0' && buf[i] <= '9' && buf[i + 1] >= '0' &&
                buf[i + 1] <= '9' && buf[i + 2] >= '0' && buf[i + 2] <= '9') {
                *out_status = (buf[i] - '0') * 100 + (buf[i + 1] - '0') * 10 + (buf[i + 2] - '0');
            }
        }
    }

    size_t pos = 0;
    while (pos < len && buf[pos] != '\n') {
        pos++;
    }
    if (pos < len) {
        pos++;
    }

    size_t line_start = pos;
    while (line_start < len) {
        size_t line_end = line_start;
        while (line_end < len && buf[line_end] != '\n') {
            line_end++;
        }
        size_t content_end = line_end;
        if (content_end > line_start && buf[content_end - 1] == '\r') {
            content_end--;
        }

        if (content_end == line_start) {
            *out_body_start = (line_end < len) ? line_end + 1 : line_end;
            return;
        }

        size_t colon = line_start;
        while (colon < content_end && buf[colon] != ':') {
            colon++;
        }
        if (colon < content_end && *out_pair_count < pairs_cap) {
            size_t value_start = colon + 1;
            while (value_start < content_end && (buf[value_start] == ' ' || buf[value_start] == '\t')) {
                value_start++;
            }
            pairs[*out_pair_count].name_start = buf + line_start;
            pairs[*out_pair_count].name_len = colon - line_start;
            pairs[*out_pair_count].value_start = buf + value_start;
            pairs[*out_pair_count].value_len = content_end - value_start;
            (*out_pair_count)++;
        }

        line_start = (line_end < len) ? line_end + 1 : line_end;
    }
}

static void cytadel_http_lowercase_into(char *dst, const char *src, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (char)((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c);
    }
    dst[len] = '\0';
}

/* Pushes the `headers` result table (lowercased names, repeated headers
 * joined with ", " per RFC 7230 field-line folding semantics -- §2.8).
 * Net stack effect: +1 (the new table left on top). */
static void cytadel_http_push_headers_table(lua_State *L, const cytadel_http_header_pair_t *pairs,
                                             size_t pair_count) {
    lua_newtable(L);
    int tbl_idx = lua_gettop(L);

    char name_buf[256];
    for (size_t i = 0; i < pair_count; i++) {
        size_t name_len = pairs[i].name_len;
        if (name_len >= sizeof(name_buf)) {
            name_len = sizeof(name_buf) - 1;
        }
        cytadel_http_lowercase_into(name_buf, pairs[i].name_start, name_len);

        /* Security-review round-4 suggestion 1: raw, not lua_getfield --
         * this table is engine-created (lua_newtable() above, never handed
         * to plugin code, never given a metatable) so an ordinary
         * lua_getfield() is not a live bug here today. But
         * cytadel_plugin_api_http_get()'s own W-3 fix comment (below) states
         * this codebase's policy as "every read of a plugin-supplied table
         * in this codebase now uses the raw accessor uniformly" -- switching
         * this remaining table-field read on a table built during the same
         * request's processing to cytadel_plugin_raw_getfield() too keeps
         * that invariant enforceable by inspection of src/plugin's
         * table-field reads generally, rather than requiring a reader to
         * first re-derive (as this comment does) that lua_getfield() is
         * still safe here specifically because of this table's provenance.
         * (After this change, the only two literal lua_getfield() CALLS
         * left under src/plugin are debug_support.c's own attack-harness
         * sanity check, which deliberately needs an ordinary
         * metamethod-honouring lookup to prove its hostile __index fixture
         * actually works, and plugin_ctx.h's LUA_REGISTRYINDEX lookup,
         * which is never a plugin-reachable table at all.) */
        cytadel_plugin_raw_getfield(L, tbl_idx, name_buf);
        if (lua_isstring(L, -1)) {
            lua_pushliteral(L, ", ");
            lua_pushlstring(L, pairs[i].value_start, pairs[i].value_len);
            lua_concat(L, 3); /* existing value .. ", " .. new value */
        } else {
            lua_pop(L, 1);
            lua_pushlstring(L, pairs[i].value_start, pairs[i].value_len);
        }
        lua_setfield(L, tbl_idx, name_buf);
    }
}

/* §2.8/§5.3, Milestone 5 security-audit finding C1: `path` must be a
 * well-formed origin-form HTTP request target -- no CR/LF/other control
 * chars and no bare space. Without this, a plugin could pass e.g.
 * "/ HTTP/1.1\r\nHost: x\r\n\r\nDELETE /admin HTTP/1.1\r\n..." as `path`
 * and smuggle a second, state-changing request onto the wire after the
 * intended GET/HEAD -- a direct violation of §0/§5.3's detection-only
 * guarantee that must be enforced at this API surface itself, not by
 * plugin-author convention. Also requires `path` to start with '/' (a
 * minimally well-formed origin-form target per RFC 7230 §5.3.1) so a
 * plugin cannot pass an absolute-form/authority-form target or an empty
 * string that would otherwise slip through the CR/LF/space check. Called
 * BEFORE any request bytes are built. Raises (luaL_error) and does not
 * return on violation. Net stack effect: 0. */
static void cytadel_http_validate_path(lua_State *L, const char *path, size_t path_len) {
    if (path_len == 0 || path[0] != '/') {
        luaL_error(L, "http_get: path must start with '/' (an origin-form request target)");
    }
    for (size_t i = 0; i < path_len; i++) {
        unsigned char c = (unsigned char)path[i];
        /* c <= 0x20 catches every C0 control char (including CR/LF/NUL)
         * AND the space character (0x20) in one comparison; 0x7f is DEL,
         * the one control char above the printable ASCII range. */
        if (c <= 0x20 || c == 0x7f) {
            /* lua_pushvfstring() (what luaL_error() formats with) only
             * understands its own small format-spec set -- %d/%I/%s/%c/
             * %f/%p/%U/%% -- never libc's %x/%02x/%zu, so the byte value
             * and offset are reported in decimal via %d/%I, not hex. */
            luaL_error(L,
                       "http_get: path contains an invalid control/space byte (decimal %d) at "
                       "offset %I -- CR/LF/space are never permitted (request smuggling)",
                       (int)c, (lua_Integer)i);
        }
    }
}

/* Security-review round-2 FIX 5 (optional hardening): true iff `c` is a
 * valid RFC 7230 §3.2.6 "tchar" -- the only bytes a syntactically valid
 * HTTP header field-name may contain. This is strictly TIGHTER than the
 * documented contract (§2.8's opts.headers is `table<string,string>` with
 * no charset carve-out), never looser, and closes off header-name bytes
 * (colons, whitespace, other separators/control chars) that the CR/LF-only
 * check below never rejected. */
static bool cytadel_http_is_header_token_char(unsigned char c) {
    if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
        return true;
    }
    switch (c) {
        case '!':
        case '#':
        case '$':
        case '%':
        case '&':
        case '\'':
        case '*':
        case '+':
        case '-':
        case '.':
        case '^':
        case '_':
        case '`':
        case '|':
        case '~':
            return true;
        default:
            return false;
    }
}

/* Case-insensitive ASCII equality of a (name, name_len) span (as returned
 * by lua_tolstring(), NOT NUL-terminated by that length alone but always
 * followed by a real NUL byte -- a Lua string internal invariant) against
 * a NUL-terminated lowercase literal. */
static bool cytadel_http_header_name_equals_ci(const char *name, size_t name_len,
                                                const char *lower_literal) {
    size_t lit_len = strlen(lower_literal);
    if (name_len != lit_len) {
        return false;
    }
    for (size_t i = 0; i < lit_len; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c - 'A' + 'a');
        }
        if (c != (unsigned char)lower_literal[i]) {
            return false;
        }
    }
    return true;
}

/* Security-review round-2 FIX 5 (optional hardening): true iff `name` is
 * one of the framing-sensitive header names this client must own itself --
 * Host (already sent automatically from ctx->ip, §2.8/§5.3) or
 * Content-Length/Transfer-Encoding (never valid for the bodyless GET/HEAD
 * requests this client sends; letting a plugin set either invites
 * request-smuggling-adjacent confusion in whatever sits between this
 * scanner and the target). */
static bool cytadel_http_header_is_framing(const char *name, size_t name_len) {
    return cytadel_http_header_name_equals_ci(name, name_len, "content-length") ||
           cytadel_http_header_name_equals_ci(name, name_len, "transfer-encoding") ||
           cytadel_http_header_name_equals_ci(name, name_len, "host");
}

/* Validates every entry in the opts.headers table (arg index
 * `headers_tbl_idx`) is a string -> string pair with no CR/LF, a
 * syntactically valid (RFC 7230 token) header name, and not a
 * framing-sensitive header name this client must own itself -- WITHOUT
 * allocating anything. Milestone 5 security-audit finding W4: called
 * BEFORE the request buffer (`req` in cytadel_plugin_api_http_get()) is
 * malloc'd, so a validation failure here can never leak it. Raises
 * (luaL_error) and does not return on violation. Net stack effect: 0. */
static void cytadel_http_validate_headers_table(lua_State *L, int headers_tbl_idx) {
    lua_pushnil(L);
    while (lua_next(L, headers_tbl_idx) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING || lua_type(L, -1) != LUA_TSTRING) {
            luaL_error(L, "http_get: opts.headers must be a table of string -> string");
        }
        size_t name_len = 0, value_len = 0;
        const char *name = lua_tolstring(L, -2, &name_len);
        const char *value = lua_tolstring(L, -1, &value_len);
        if (name_len == 0) {
            luaL_error(L, "http_get: opts.headers has an entry with an empty header name");
        }
        for (size_t i = 0; i < name_len; i++) {
            if (!cytadel_http_is_header_token_char((unsigned char)name[i])) {
                luaL_error(L,
                           "http_get: opts.headers entry '%s' has an invalid header-name byte -- "
                           "header names must be an RFC 7230 token",
                           name);
            }
        }
        if (memchr(value, '\r', value_len) || memchr(value, '\n', value_len)) {
            luaL_error(L, "http_get: opts.headers entry '%s' contains a CR/LF", name);
        }
        if (cytadel_http_header_is_framing(name, name_len)) {
            luaL_error(L,
                       "http_get: opts.headers must not set the framing header '%s' -- Host is "
                       "sent automatically and Content-Length/Transfer-Encoding are never valid "
                       "for the GET/HEAD requests this client sends",
                       name);
        }
        lua_pop(L, 1); /* keep key for lua_next() */
    }
    /* Net stack effect: 0 -- the headers table itself (headers_tbl_idx) is
     * left on the stack, owned/popped by the caller. */
}

/* Appends "Name: value\r\n" lines for every entry in the opts.headers
 * table (arg index `headers_tbl_idx`) into a dynamically growing request
 * buffer. By the time this runs, cytadel_http_validate_headers_table()
 * above has already confirmed every entry is a valid string -> string,
 * CR/LF-free pair, so the checks here are a defense-in-depth repeat (the
 * table cannot have been mutated in between -- no Lua code runs between
 * the two passes, see cytadel_plugin_api_http_get()) rather than the
 * primary defense; they still raise the same way if reached. Also frees
 * *buf before raising on its own realloc() OOM path (Milestone 5
 * security-audit finding W4) -- unlike a validation failure, this really
 * can be reached the first time this function is called (allocation
 * failure has no earlier pre-check), so it must not leak *buf. */
static void cytadel_http_append_extra_headers(lua_State *L, int headers_tbl_idx, char **buf,
                                               size_t *len, size_t *cap) {
    lua_pushnil(L);
    while (lua_next(L, headers_tbl_idx) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING || lua_type(L, -1) != LUA_TSTRING) {
            free(*buf);
            *buf = NULL;
            luaL_error(L, "http_get: opts.headers must be a table of string -> string");
        }
        size_t name_len = 0, value_len = 0;
        const char *name = lua_tolstring(L, -2, &name_len);
        const char *value = lua_tolstring(L, -1, &value_len);
        if (memchr(name, '\r', name_len) || memchr(name, '\n', name_len) ||
            memchr(value, '\r', value_len) || memchr(value, '\n', value_len)) {
            free(*buf);
            *buf = NULL;
            luaL_error(L, "http_get: opts.headers entry '%s' contains a CR/LF", name);
        }

        size_t needed = name_len + 2 + value_len + 2;
        if (*len + needed + 1 > *cap) {
            size_t new_cap = (*cap + needed + 1) * 2;
            char *grown = realloc(*buf, new_cap);
            if (grown == NULL) {
                free(*buf);
                *buf = NULL;
                luaL_error(L, "http_get: out of memory building request headers");
            }
            *buf = grown;
            *cap = new_cap;
        }
        memcpy(*buf + *len, name, name_len);
        *len += name_len;
        memcpy(*buf + *len, ": ", 2);
        *len += 2;
        memcpy(*buf + *len, value, value_len);
        *len += value_len;
        memcpy(*buf + *len, "\r\n", 2);
        *len += 2;

        lua_pop(L, 1); /* keep key for lua_next() */
    }
}

int cytadel_plugin_api_http_get(lua_State *L) {
    cytadel_plugin_ctx_t *ctx = cytadel_plugin_ctx_get(L);
    lua_Integer port = luaL_checkinteger(L, 1);
    size_t path_len = 0;
    const char *path = luaL_checklstring(L, 2, &path_len);
    /* C1 security-audit fix: reject a CRLF/control-char/space `path`
     * BEFORE building any request bytes -- see
     * cytadel_http_validate_path()'s own comment. Enforced at this API
     * surface itself, per §5.3. */
    cytadel_http_validate_path(L, path, path_len);

    const char *method = "GET";
    lua_Integer timeout_ms = 5000;
    bool use_tls = false;
    int headers_tbl_idx = 0;

    if (!lua_isnoneornil(L, 3)) {
        luaL_checktype(L, 3, LUA_TTABLE);

        /* Security-review round-3 finding W-3 (WARNING, latent): raw, not
         * lua_getfield -- arg 3 (`opts`) is plugin-supplied, and
         * setmetatable() is reachable from the run-phase sandbox
         * (plugin-api.md §5.1), so an ordinary lua_getfield() on it could be
         * intercepted by a plugin-installed __index (the same class of
         * issue field_utils.h's cytadel_plugin_raw_getfield() already
         * documents for report_vuln{}'s/register{}'s own table arguments --
         * see field_utils.c's FIX 3 comment). Not currently reachable as a
         * live bug here (each field is read exactly once, copied straight
         * into a C local, and nothing is malloc'd before the request buffer
         * further down), but every read of a plugin-supplied table in this
         * codebase now uses the raw accessor uniformly, so a future
         * reordering here can never silently reopen it. */
        cytadel_plugin_raw_getfield(L, 3, "method");
        if (!lua_isnil(L, -1)) {
            const char *m = luaL_checkstring(L, -1);
            if (strcmp(m, "GET") == 0) {
                method = "GET";
            } else if (strcmp(m, "HEAD") == 0) {
                method = "HEAD";
            } else {
                return luaL_error(L,
                                   "http_get: opts.method must be \"GET\" or \"HEAD\" (got \"%s\") "
                                   "-- detection-only, no state-changing verbs",
                                   m);
            }
        }
        lua_pop(L, 1);

        cytadel_plugin_raw_getfield(L, 3, "timeout_ms");
        if (!lua_isnil(L, -1)) {
            timeout_ms = luaL_checkinteger(L, -1);
        }
        lua_pop(L, 1);

        cytadel_plugin_raw_getfield(L, 3, "tls");
        if (!lua_isnil(L, -1)) {
            use_tls = lua_toboolean(L, -1) != 0;
        }
        lua_pop(L, 1);

        cytadel_plugin_raw_getfield(L, 3, "headers");
        if (lua_isnil(L, -1)) {
            lua_pop(L, 1);
        } else {
            luaL_checktype(L, -1, LUA_TTABLE);
            headers_tbl_idx = lua_gettop(L); /* keep on stack, referenced below */
        }
    }

    if (port < 1 || port > 65535) {
        /* %I (lua_Integer), not libc's %lld -- see api_report.c's comment
         * on lua_pushvfstring()'s restricted format-spec set. */
        return luaL_error(L, "http_get: port %I out of range 1-65535", port);
    }
    /* W1 security-audit fix, floor single-sourced by FIX 2 (security-review
     * round 2) -- see timeout_clamp.h's cytadel_plugin_clamp_timeout_ms()
     * for the full rationale. This used to be preceded by its own local
     * `if (timeout_ms < 0) timeout_ms = 0;` pre-clamp; that is now
     * redundant (and was itself insufficient -- it never floored an
     * explicit 0, e.g. http_get{timeout_ms = 0}) since
     * cytadel_plugin_clamp_timeout_ms() floors to 1 up front
     * unconditionally. Applied once, here, before either the TLS or
     * plain-TCP connect path below -- both read this same `timeout_ms`,
     * and the plain-TCP path also carries it into the connection's own
     * SO_RCVTIMEO/SO_SNDTIMEO (see cytadel_plugin_raw_tcp_connect()), so
     * this single clamp covers connect AND the subsequent response read. */
    timeout_ms = cytadel_plugin_clamp_timeout_ms(L, timeout_ms);

    /* W4 security-audit fix: validate opts.headers (type + CR/LF) BEFORE
     * `req` is allocated below, so a validation failure here can never
     * leak it -- see cytadel_http_validate_headers_table()'s own comment. */
    if (headers_tbl_idx != 0) {
        cytadel_http_validate_headers_table(L, headers_tbl_idx);
    }

    /* Build the request. */
    size_t cap = 512;
    char *req = malloc(cap);
    if (req == NULL) {
        return luaL_error(L, "http_get: out of memory building the request");
    }
    int written = snprintf(req, cap, "%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n", method,
                            path, ctx->ip);
    if (written < 0) {
        free(req);
        return luaL_error(L, "http_get: failed to build the request line");
    }
    size_t len = (size_t)written;
    if (len >= cap) {
        /* path was longer than the initial buffer -- grow and rebuild. */
        cap = len + 1;
        char *grown = realloc(req, cap);
        if (grown == NULL) {
            free(req);
            return luaL_error(L, "http_get: out of memory building the request");
        }
        req = grown;
        written = snprintf(req, cap, "%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n", method,
                            path, ctx->ip);
        len = (size_t)written;
    }

    if (headers_tbl_idx != 0) {
        cytadel_http_append_extra_headers(L, headers_tbl_idx, &req, &len, &cap);
    }
    if (len + 3 > cap) {
        char *grown = realloc(req, len + 3);
        if (grown == NULL) {
            free(req);
            return luaL_error(L, "http_get: out of memory finishing the request");
        }
        req = grown;
        cap = len + 3;
    }
    memcpy(req + len, "\r\n", 2);
    len += 2;

    /* Connect (plain or TLS) and send. */
    cytadel_http_conn_t conn;
    conn.fd = -1;
    conn.ssl = NULL;
    cytadel_tls_session_t tls_session;
    memset(&tls_session, 0, sizeof(tls_session));
    tls_session.fd = -1;

    if (use_tls) {
        if (cytadel_net_tls_connect(ctx->ip, (uint16_t)port, (int)timeout_ms, &tls_session) != 0) {
            free(req);
            lua_pushnil(L);
            lua_pushstring(L, "tls_error");
            return 2;
        }
        conn.fd = tls_session.fd;
        conn.ssl = tls_session.ssl;
    } else {
        char err_buf[64];
        if (cytadel_plugin_raw_tcp_connect(ctx->ip, (uint16_t)port, (int)timeout_ms, &conn.fd,
                                            err_buf, sizeof(err_buf)) != 0) {
            free(req);
            lua_pushnil(L);
            lua_pushstring(L, err_buf);
            return 2;
        }
    }

    bool sent_ok = cytadel_http_conn_write_all(&conn, req, len);
    free(req);
    if (!sent_ok) {
        if (use_tls) {
            cytadel_net_tls_session_close(&tls_session);
        } else {
            close(conn.fd);
        }
        lua_pushnil(L);
        lua_pushstring(L, use_tls ? "tls_error" : "closed");
        return 2;
    }

    char *resp_buf = NULL;
    size_t resp_len = 0;
    int read_rc = cytadel_http_read_all(&conn, &resp_buf, &resp_len);

    if (use_tls) {
        cytadel_net_tls_session_close(&tls_session);
    } else {
        close(conn.fd);
    }

    if (read_rc != 0) {
        return luaL_error(L, "http_get: out of memory reading the response");
    }

    int status = -1;
    cytadel_http_header_pair_t pairs[128];
    size_t pair_count = 0;
    size_t body_start = resp_len;
    cytadel_http_parse(resp_buf, resp_len, &status, pairs, sizeof(pairs) / sizeof(pairs[0]),
                        &pair_count, &body_start);

    size_t body_len = (body_start < resp_len) ? resp_len - body_start : 0;
    if (body_len > CYTADEL_HTTP_BODY_CAP) {
        body_len = CYTADEL_HTTP_BODY_CAP; /* §2.8: truncate, don't reject */
    }

    /* Security-review round-2 FIX 5 (cheap robustness): copy everything
     * this function still needs out of resp_buf -- the body (a Lua-owned
     * lua_pushlstring() copy) and the header table (cytadel_http_push_headers_table()
     * copies each name/value pair into a fresh Lua table; `pairs` only
     * holds spans INTO resp_buf, so this must still run before resp_buf is
     * freed) -- BEFORE building the result table below, then free resp_buf
     * immediately. Previously resp_buf was held alive (freed only once,
     * right at the very end) across the ENTIRE result-table assembly
     * (lua_newtable() + 3 lua_setfield() calls); any one of those raising
     * on Lua-side OOM would skip the free() and leak resp_buf. This
     * shrinks that exposure window to just the two calls below that
     * actually still need resp_buf's backing memory. */
    lua_pushlstring(L, resp_buf + body_start, body_len);
    int body_idx = lua_gettop(L);
    cytadel_http_push_headers_table(L, pairs, pair_count);
    int headers_idx = lua_gettop(L);
    free(resp_buf);
    resp_buf = NULL;

    lua_newtable(L);
    int result_idx = lua_gettop(L);

    lua_pushinteger(L, status);
    lua_setfield(L, result_idx, "status");

    lua_pushvalue(L, headers_idx);
    lua_setfield(L, result_idx, "headers");

    lua_pushvalue(L, body_idx);
    lua_setfield(L, result_idx, "body");

    return 1;
}
