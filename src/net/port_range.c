#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/port_range.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* One bit per possible port number 0..65535 (index 0 is never set --
 * CYTADEL_PORT_MIN is 1). A stack-resident bitmap keeps de-duplication
 * O(spec length) with no intermediate heap allocation, and its size is
 * fixed regardless of how large/adversarial the input spec is. */
#define CYTADEL_PORT_BITMAP_BITS (CYTADEL_PORT_MAX + 1)
#define CYTADEL_PORT_BITMAP_BYTES ((CYTADEL_PORT_BITMAP_BITS + 7) / 8)

/* Longest legal token is "65535-65535" (11 bytes); a generous 16-byte cap
 * rejects anything longer as malformed before it is even parsed. */
#define CYTADEL_PORT_TOKEN_MAX_LEN 16

static void cytadel_port_set_err(char *err_buf, size_t err_buf_len, const char *fmt, ...) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_buf_len, fmt, ap);
    va_end(ap);
}

/* Parses an unsigned decimal integer from tok[0..len) (no sign, no
 * whitespace, digits only). Rejects empty input and caps accumulation so a
 * long digit run can never overflow `long` -- the caller still separately
 * range-checks the result against CYTADEL_PORT_MIN/MAX. */
static bool cytadel_port_parse_uint(const char *tok, size_t len, long *out) {
    if (len == 0 || len > 6) {
        return false;
    }
    long val = 0;
    for (size_t i = 0; i < len; i++) {
        char c = tok[i];
        if (c < '0' || c > '9') {
            return false;
        }
        val = (val * 10) + (c - '0');
        if (val > 1000000L) {
            val = 1000000L; /* clamp -- definitely out of range either way */
        }
    }
    *out = val;
    return true;
}

static void cytadel_port_bitmap_set(uint8_t *bitmap, long port) {
    size_t idx = (size_t)port;
    bitmap[idx / 8] |= (uint8_t)(1u << (idx % 8));
}

cytadel_port_range_status_t cytadel_port_range_parse(const char *spec,
                                                       cytadel_port_list_t *out_list,
                                                       char *err_buf, size_t err_buf_len) {
    if (out_list == NULL) {
        cytadel_port_set_err(err_buf, err_buf_len, "internal error: out_list is NULL");
        return CYTADEL_PORT_RANGE_ERR_MALFORMED;
    }
    if (spec == NULL || spec[0] == '\0') {
        cytadel_port_set_err(err_buf, err_buf_len, "empty port specification");
        return CYTADEL_PORT_RANGE_ERR_MALFORMED;
    }

    size_t spec_len = strnlen(spec, CYTADEL_PORT_SPEC_MAX_LEN);
    if (spec_len >= CYTADEL_PORT_SPEC_MAX_LEN) {
        cytadel_port_set_err(err_buf, err_buf_len,
                              "port specification too long (max %d bytes)",
                              CYTADEL_PORT_SPEC_MAX_LEN - 1);
        return CYTADEL_PORT_RANGE_ERR_MALFORMED;
    }

    uint8_t bitmap[CYTADEL_PORT_BITMAP_BYTES];
    memset(bitmap, 0, sizeof(bitmap));

    size_t i = 0;
    size_t token_count = 0;
    for (;;) {
        size_t tok_start = i;
        while (i < spec_len && spec[i] != ',') {
            i++;
        }
        size_t tok_len = i - tok_start;
        const char *tok = spec + tok_start;

        token_count++;
        if (token_count > CYTADEL_PORT_SPEC_MAX_TOKENS) {
            cytadel_port_set_err(err_buf, err_buf_len,
                                  "too many comma-separated tokens in port spec (max %d)",
                                  CYTADEL_PORT_SPEC_MAX_TOKENS);
            return CYTADEL_PORT_RANGE_ERR_TOO_MANY;
        }
        if (tok_len == 0 || tok_len > CYTADEL_PORT_TOKEN_MAX_LEN) {
            cytadel_port_set_err(err_buf, err_buf_len,
                                  "malformed port token (empty or too long) in '%s'", spec);
            return CYTADEL_PORT_RANGE_ERR_MALFORMED;
        }

        size_t dash_pos = 0;
        size_t dash_count = 0;
        for (size_t k = 0; k < tok_len; k++) {
            if (tok[k] == '-') {
                if (dash_count == 0) {
                    dash_pos = k;
                }
                dash_count++;
            }
        }
        if (dash_count > 1) {
            cytadel_port_set_err(err_buf, err_buf_len,
                                  "malformed port range token '%.*s'", (int)tok_len, tok);
            return CYTADEL_PORT_RANGE_ERR_MALFORMED;
        }

        long start_v;
        long end_v;
        if (dash_count == 1) {
            size_t left_len = dash_pos;
            size_t right_len = tok_len - dash_pos - 1;
            if (left_len == 0 || right_len == 0 ||
                !cytadel_port_parse_uint(tok, left_len, &start_v) ||
                !cytadel_port_parse_uint(tok + dash_pos + 1, right_len, &end_v)) {
                cytadel_port_set_err(err_buf, err_buf_len,
                                      "malformed port range token '%.*s'", (int)tok_len, tok);
                return CYTADEL_PORT_RANGE_ERR_MALFORMED;
            }
        } else {
            if (!cytadel_port_parse_uint(tok, tok_len, &start_v)) {
                cytadel_port_set_err(err_buf, err_buf_len,
                                      "malformed port token '%.*s'", (int)tok_len, tok);
                return CYTADEL_PORT_RANGE_ERR_MALFORMED;
            }
            end_v = start_v;
        }

        if (start_v < CYTADEL_PORT_MIN || start_v > CYTADEL_PORT_MAX ||
            end_v < CYTADEL_PORT_MIN || end_v > CYTADEL_PORT_MAX) {
            cytadel_port_set_err(err_buf, err_buf_len,
                                  "port value out of range 1-65535 in token '%.*s'",
                                  (int)tok_len, tok);
            return CYTADEL_PORT_RANGE_ERR_OUT_OF_BOUNDS;
        }
        if (start_v > end_v) {
            cytadel_port_set_err(err_buf, err_buf_len,
                                  "invalid range (start > end) in token '%.*s'",
                                  (int)tok_len, tok);
            return CYTADEL_PORT_RANGE_ERR_MALFORMED;
        }

        for (long v = start_v; v <= end_v; v++) {
            cytadel_port_bitmap_set(bitmap, v);
        }

        if (i >= spec_len) {
            break;
        }
        i++; /* skip the ',' */
    }

    size_t count = 0;
    for (long v = CYTADEL_PORT_MIN; v <= CYTADEL_PORT_MAX; v++) {
        size_t idx = (size_t)v;
        if (bitmap[idx / 8] & (uint8_t)(1u << (idx % 8))) {
            count++;
        }
    }
    if (count == 0) {
        cytadel_port_set_err(err_buf, err_buf_len, "port specification selected zero ports");
        return CYTADEL_PORT_RANGE_ERR_EMPTY;
    }

    uint16_t *ports = malloc(count * sizeof(uint16_t));
    if (ports == NULL) {
        cytadel_port_set_err(err_buf, err_buf_len, "out of memory allocating port list");
        return CYTADEL_PORT_RANGE_ERR_ALLOC;
    }

    size_t w = 0;
    for (long v = CYTADEL_PORT_MIN; v <= CYTADEL_PORT_MAX; v++) {
        size_t idx = (size_t)v;
        if (bitmap[idx / 8] & (uint8_t)(1u << (idx % 8))) {
            ports[w++] = (uint16_t)v;
        }
    }

    out_list->ports = ports;
    out_list->count = count;
    return CYTADEL_PORT_RANGE_OK;
}

void cytadel_port_list_free(cytadel_port_list_t *list) {
    if (list == NULL) {
        return;
    }
    free(list->ports);
    list->ports = NULL;
    list->count = 0;
}
