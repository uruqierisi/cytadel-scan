#include "kb_validate.h"

#include "cytadel/kb/kb.h"

bool cytadel_kb_validate_key(const char *key) {
    if (key == NULL) {
        return false;
    }

    /* Bounded length probe: strnlen() never reads past
     * CYTADEL_KB_KEY_MAX_LEN + 1 bytes, so an unterminated or
     * pathologically long buffer can never cause an out-of-bounds read
     * here regardless of what the caller passed. */
    size_t len = 0;
    while (len <= CYTADEL_KB_KEY_MAX_LEN && key[len] != '\0') {
        len++;
    }
    if (len == 0 || len > CYTADEL_KB_KEY_MAX_LEN) {
        return false; /* empty key, or no NUL within the length budget */
    }

    if (key[0] == '/' || key[len - 1] == '/') {
        return false; /* no leading/trailing slash (kb-schema.md SS2) */
    }

    size_t seg_len = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)key[i];
        if (c == '/') {
            if (seg_len == 0) {
                return false; /* empty segment ("//") */
            }
            seg_len = 0;
            continue;
        }

        bool ok_char = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
        if (!ok_char) {
            return false;
        }
        seg_len++;
    }

    /* Redundant with the trailing-slash check above (if the last char
     * isn't '/', the final segment is non-empty by construction), kept as
     * an explicit belt-and-braces check rather than relying on that
     * inference holding forever if this function is refactored later. */
    return seg_len > 0;
}

bool cytadel_kb_validate_no_embedded_nul(const char *buf, size_t len) {
    if (buf == NULL) {
        return len == 0;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '\0') {
            return false;
        }
    }
    return true;
}

/* Strict UTF-8 validator. Rejects overlong encodings, encoded surrogates
 * (U+D800-U+DFFF), and code points beyond U+10FFFF. Every array access
 * below is guarded by an explicit `i < len` bounds check before it is
 * performed -- this function never reads buf[len] or beyond, even for a
 * truncated/malformed multi-byte sequence at the end of the buffer. */
bool cytadel_kb_validate_utf8(const char *buf, size_t len) {
    if (buf == NULL) {
        return len == 0;
    }

    size_t i = 0;
    while (i < len) {
        unsigned char b0 = (unsigned char)buf[i];

        if (b0 < 0x80) {
            i += 1;
            continue;
        }

        size_t extra;      /* number of continuation bytes expected */
        unsigned char lo;  /* inclusive low bound for the first continuation byte */
        unsigned char hi;  /* inclusive high bound for the first continuation byte */

        if (b0 >= 0xC2 && b0 <= 0xDF) {
            extra = 1;
            lo = 0x80;
            hi = 0xBF;
        } else if (b0 == 0xE0) {
            extra = 2;
            lo = 0xA0; /* excludes overlong 3-byte encodings */
            hi = 0xBF;
        } else if (b0 >= 0xE1 && b0 <= 0xEC) {
            extra = 2;
            lo = 0x80;
            hi = 0xBF;
        } else if (b0 == 0xED) {
            extra = 2;
            lo = 0x80;
            hi = 0x9F; /* excludes encoded surrogates U+D800-U+DFFF */
        } else if (b0 >= 0xEE && b0 <= 0xEF) {
            extra = 2;
            lo = 0x80;
            hi = 0xBF;
        } else if (b0 == 0xF0) {
            extra = 3;
            lo = 0x90; /* excludes overlong 4-byte encodings */
            hi = 0xBF;
        } else if (b0 >= 0xF1 && b0 <= 0xF3) {
            extra = 3;
            lo = 0x80;
            hi = 0xBF;
        } else if (b0 == 0xF4) {
            extra = 3;
            lo = 0x80;
            hi = 0x8F; /* excludes code points beyond U+10FFFF */
        } else {
            return false; /* 0x80-0xC1 (stray continuation / overlong 2-byte
                            * lead) or 0xF5-0xFF (beyond Unicode range) */
        }

        if (i + extra >= len) {
            return false; /* truncated multi-byte sequence */
        }

        unsigned char c1 = (unsigned char)buf[i + 1];
        if (c1 < lo || c1 > hi) {
            return false;
        }
        for (size_t k = 2; k <= extra; k++) {
            unsigned char ck = (unsigned char)buf[i + k];
            if (ck < 0x80 || ck > 0xBF) {
                return false;
            }
        }

        i += extra + 1;
    }

    return true;
}
