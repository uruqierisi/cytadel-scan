#include "cytadel/report/escape.h"

#include <stdlib.h>
#include <string.h>

/* Milestone 8 slice 1: the report-output escaper module. See
 * include/cytadel/report/escape.h for the full threat model and the exact
 * contract of every public function -- this file is purely the
 * implementation of that contract, and every comment below assumes the
 * reader has already read that header.
 */

/* ------------------------------------------------------------------- */
/* cytadel_report_buf_t: growable, overflow-checked, NUL-terminated sink. */
/* ------------------------------------------------------------------- */

void cytadel_report_buf_init(cytadel_report_buf_t *buf) {
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

void cytadel_report_buf_free(cytadel_report_buf_t *buf) {
    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
    buf->cap = 0;
}

/* Ensures buf->cap >= buf->len + extra + 1 (the "+1" reserves room for the
 * trailing NUL this module always maintains at data[len]), growing by
 * doubling. Returns false on allocation failure OR on size_t overflow --
 * in both cases *buf is left completely unchanged (no partial state). This
 * is the single choke point that makes every escaper's "never emit a
 * half-written entity at a truncation boundary" guarantee hold: callers
 * always reserve space for a whole escape sequence before writing any byte
 * of it, so a failure here happens strictly BEFORE any of that sequence's
 * bytes are written. */
static bool buf_reserve(cytadel_report_buf_t *buf, size_t extra) {
    if (buf->len > (size_t)-1 - 1) {
        return false; /* buf->len + 1 would already overflow. */
    }
    size_t base = buf->len + 1;
    if (extra > (size_t)-1 - base) {
        return false; /* base + extra would overflow. */
    }
    size_t need = base + extra;
    if (need <= buf->cap) {
        return true;
    }

    size_t new_cap = (buf->cap == 0) ? 64 : buf->cap;
    while (new_cap < need) {
        if (new_cap > (size_t)-1 / 2) {
            new_cap = need;
            break;
        }
        new_cap *= 2;
    }

    char *grown = realloc(buf->data, new_cap);
    if (grown == NULL) {
        return false;
    }
    buf->data = grown;
    buf->cap = new_cap;
    return true;
}

/* Appends exactly n raw bytes from src, reserving first. All-or-nothing:
 * on false, zero of these n bytes were written. Keeps data[len] NUL. */
static bool buf_append(cytadel_report_buf_t *buf, const char *src, size_t n) {
    if (!buf_reserve(buf, n)) {
        return false;
    }
    if (n > 0) {
        memcpy(buf->data + buf->len, src, n);
    }
    buf->len += n;
    buf->data[buf->len] = '\0';
    return true;
}

static bool buf_append_byte(cytadel_report_buf_t *buf, unsigned char c) {
    return buf_append(buf, (const char *)&c, 1);
}

bool cytadel_report_buf_append_lit(cytadel_report_buf_t *out, const char *lit) {
    return buf_append(out, lit, strlen(lit));
}

/* ------------------------------------------------------------------- */
/* Shared small helpers.                                                */
/* ------------------------------------------------------------------- */

static char hex_digit_upper(unsigned nibble) {
    return (char)((nibble < 10) ? ('0' + nibble) : ('A' + (nibble - 10)));
}

static char hex_digit_lower(unsigned nibble) {
    return (char)((nibble < 10) ? ('0' + nibble) : ('a' + (nibble - 10)));
}

static bool is_alpha_ascii(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

static bool is_scheme_char(unsigned char c) {
    return is_alpha_ascii(c) || (c >= '0' && c <= '9') || c == '+' || c == '-' || c == '.';
}

/* ------------------------------------------------------------------- */
/* Context 1 / 2: HTML body text / double-quoted HTML attribute value.  */
/* ------------------------------------------------------------------- */

static bool html_escape_one(cytadel_report_buf_t *out, unsigned char c, bool escape_quotes) {
    switch (c) {
        case '&':
            return buf_append(out, "&amp;", 5);
        case '<':
            return buf_append(out, "&lt;", 4);
        case '>':
            return buf_append(out, "&gt;", 4);
        case '"':
            if (escape_quotes) {
                return buf_append(out, "&quot;", 6);
            }
            return buf_append_byte(out, c);
        case '\'':
            if (escape_quotes) {
                return buf_append(out, "&#39;", 5);
            }
            return buf_append_byte(out, c);
        default:
            return buf_append_byte(out, c);
    }
}

bool cytadel_escape_html_body(cytadel_report_buf_t *out, const char *in, size_t in_len) {
    for (size_t i = 0; i < in_len; i++) {
        if (!html_escape_one(out, (unsigned char)in[i], false)) {
            return false;
        }
    }
    return true;
}

bool cytadel_escape_html_attr(cytadel_report_buf_t *out, const char *in, size_t in_len) {
    for (size_t i = 0; i < in_len; i++) {
        if (!html_escape_one(out, (unsigned char)in[i], true)) {
            return false;
        }
    }
    return true;
}

/* ------------------------------------------------------------------- */
/* Context 3: href/src URL -- scheme allowlist, then percent-encoding.   */
/* ------------------------------------------------------------------- */

/* Anything < 0x20 other than TAB/LF/CR, or 0x7F (DEL), anywhere in the raw
 * input. TAB/LF/CR are handled separately (stripped, not rejected) to
 * mirror how real URL parsers tolerate -- and therefore how attackers have
 * historically abused -- exactly that whitespace to sneak a `javascript:`
 * scheme past a naive check. Every OTHER control byte (most notably an
 * embedded NUL, which could otherwise let a naive strlen()-based scheme
 * check see only a harmless-looking prefix while a different downstream
 * consumer reads past it) causes outright rejection of the whole value. */
static bool url_has_disallowed_control(const char *in, size_t in_len) {
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        if (c < 0x20 || c == 0x7F) {
            return true;
        }
    }
    return false;
}

static bool url_is_safe_char(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) {
        return true;
    }
    switch (c) {
        /* RFC 3986 unreserved, minus nothing. */
        case '-':
        case '_':
        case '.':
        case '~':
        /* URL-structural reserved characters, deliberately WITHOUT the
         * quote-adjacent sub-delims (' is excluded on purpose -- percent-
         * encoding it too is defense-in-depth in case this value is ever
         * placed somewhere that skips the html_attr layer that would
         * otherwise neutralize an attribute break-out). */
        case ':':
        case '/':
        case '?':
        case '#':
        case '[':
        case ']':
        case '@':
        case '!':
        case '$':
        /* '&' is deliberately NOT here: it is the one HTML-significant byte a
         * URL may legitimately contain (query separator), and letting it pass
         * raw made url() output non-attribute-safe -- a value like
         * "&#106;avascript:alert(1)" survived url() as a "relative" URL and,
         * once placed in href="..." and HTML-parsed, the browser decoded the
         * numeric char reference back into "javascript:" (W1 from the XSS
         * audit). Percent-encoding it to %26 makes url() output self-contained
         * and safe in an href even if a caller forgets the html_attr pass. Our
         * emitted URLs are NVD detail links with no multi-param query, so
         * encoding '&' costs nothing here. */
        case '(':
        case ')':
        case '*':
        case '+':
        case ',':
        case ';':
        case '=':
        case '%':
            return true;
        default:
            return false;
    }
}

static bool url_percent_encode_append(cytadel_report_buf_t *out, const char *in, size_t in_len) {
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (url_is_safe_char(c)) {
            if (!buf_append_byte(out, c)) {
                return false;
            }
            continue;
        }
        char enc[3];
        enc[0] = '%';
        enc[1] = hex_digit_upper((unsigned)(c >> 4));
        enc[2] = hex_digit_upper((unsigned)(c & 0x0F));
        if (!buf_append(out, enc, 3)) {
            return false;
        }
    }
    return true;
}

static bool scheme_equals_ci(const char *s, size_t len, const char *lowercase_lit) {
    size_t lit_len = strlen(lowercase_lit);
    if (len != lit_len) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char a = (unsigned char)s[i];
        if (a >= 'A' && a <= 'Z') {
            a = (unsigned char)(a + 32);
        }
        if (a != (unsigned char)lowercase_lit[i]) {
            return false;
        }
    }
    return true;
}

bool cytadel_escape_url(cytadel_report_buf_t *out, const char *in, size_t in_len) {
    if (in_len == 0) {
        return true; /* Nothing to append; an empty href is not dangerous. */
    }

    if (url_has_disallowed_control(in, in_len)) {
        return cytadel_report_buf_append_lit(out, "#");
    }

    /* Build the "cleaned" value used for BOTH the scheme decision and the
     * value actually emitted: strip TAB/LF/CR from anywhere in the string
     * (not just the ends), then trim leading/trailing ASCII spaces. Both
     * steps mirror real URL-parser tolerance for that exact whitespace,
     * which is what makes "  javascript:alert(1)" and similar
     * whitespace-obfuscated schemes dangerous if not accounted for here --
     * they must be neutralized in the value that is actually emitted, not
     * just in a throwaway copy used only to decide. */
    char *clean_buf = malloc(in_len);
    if (clean_buf == NULL) {
        return false;
    }
    size_t clean_len = 0;
    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '\t' || c == '\n' || c == '\r') {
            continue;
        }
        clean_buf[clean_len++] = c;
    }

    size_t start = 0;
    size_t end = clean_len;
    while (start < end && clean_buf[start] == ' ') {
        start++;
    }
    while (end > start && clean_buf[end - 1] == ' ') {
        end--;
    }
    const char *clean = clean_buf + start;
    size_t effective_len = end - start;

    bool has_scheme = false;
    size_t scheme_len = 0;
    if (effective_len > 0 && is_alpha_ascii((unsigned char)clean[0])) {
        size_t i = 1;
        while (i < effective_len && is_scheme_char((unsigned char)clean[i])) {
            i++;
        }
        if (i < effective_len && clean[i] == ':') {
            has_scheme = true;
            scheme_len = i;
        }
    }

    bool allowed;
    if (has_scheme) {
        allowed = scheme_equals_ci(clean, scheme_len, "http") ||
                  scheme_equals_ci(clean, scheme_len, "https");
    } else if (effective_len >= 2 && clean[0] == '/' && (clean[1] == '/' || clean[1] == '\\')) {
        /* S1: a scheme-less value beginning "//" (or "/\") is a
         * PROTOCOL-RELATIVE URL -- the browser inherits the page scheme and
         * navigates to //host cross-origin. In a client-facing report that is
         * an off-site/open-redirect/phishing vector, so it is not "clearly
         * relative"; require an explicit allowlisted scheme instead. */
        allowed = false;
    } else {
        allowed = true; /* No scheme colon at all: a clearly-relative URL. */
    }

    bool ok;
    if (!allowed) {
        ok = cytadel_report_buf_append_lit(out, "#");
    } else {
        ok = url_percent_encode_append(out, clean, effective_len);
    }

    free(clean_buf);
    return ok;
}

/* ------------------------------------------------------------------- */
/* Context 4: JSON string value (RFC 8259), NOT HTML escaping.          */
/* ------------------------------------------------------------------- */

bool cytadel_escape_json(cytadel_report_buf_t *out, const char *in, size_t in_len) {
    for (size_t i = 0; i < in_len; i++) {
        unsigned char c = (unsigned char)in[i];
        switch (c) {
            case '"':
                if (!buf_append(out, "\\\"", 2)) return false;
                continue;
            case '\\':
                if (!buf_append(out, "\\\\", 2)) return false;
                continue;
            case '\b':
                if (!buf_append(out, "\\b", 2)) return false;
                continue;
            case '\f':
                if (!buf_append(out, "\\f", 2)) return false;
                continue;
            case '\n':
                if (!buf_append(out, "\\n", 2)) return false;
                continue;
            case '\r':
                if (!buf_append(out, "\\r", 2)) return false;
                continue;
            case '\t':
                if (!buf_append(out, "\\t", 2)) return false;
                continue;
            default:
                break;
        }
        if (c < 0x20) {
            char enc[6];
            enc[0] = '\\';
            enc[1] = 'u';
            enc[2] = '0';
            enc[3] = '0';
            enc[4] = hex_digit_lower((unsigned)(c >> 4));
            enc[5] = hex_digit_lower((unsigned)(c & 0x0F));
            if (!buf_append(out, enc, 6)) {
                return false;
            }
            continue;
        }
        /* >= 0x20, including 0x7F and non-ASCII bytes: RFC 8259 does not
         * require escaping these; they pass through as-is (JSON strings
         * are UTF-8 text, and this module does not re-validate UTF-8 --
         * that is a separate concern from output escaping). */
        if (!buf_append_byte(out, c)) {
            return false;
        }
    }
    return true;
}
