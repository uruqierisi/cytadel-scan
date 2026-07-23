#include "cpe_map.h"

#include <stdio.h>
#include <string.h>

#include "log.h"

/* Longest version token this module will ever extract. Generous for any
 * real-world "MAJOR.MINOR.PATCHp1-suffix" style version string while still
 * bounding the CPE string build below to a fixed-size stack buffer. */
#define CYTADEL_CPE_VERSION_MAX_LEN 63

typedef struct {
    const char *marker;  /* substring that, if found, identifies the product */
    const char *vendor;  /* CPE 2.3 vendor component (already lowercase) */
    const char *product; /* CPE 2.3 product component (already lowercase) */
} cytadel_cpe_rule_t;

/* Starter map (see cpe_map.h's header comment for the M7 validation
 * caveat). Order matters only in that the first matching marker wins --
 * a banner is expected to identify at most one product. */
static const cytadel_cpe_rule_t g_cpe_rules[] = {
    {"OpenSSH_",       "openbsd",        "openssh"},
    {"Apache/",        "apache",         "http_server"},
    {"nginx/",         "nginx",          "nginx"},
    {"vsFTPd ",        "vsftpd_project", "vsftpd"},
    {"ProFTPD ",       "proftpd",        "proftpd"},
    {"Microsoft-IIS/", "microsoft",      "iis"},
    {"lighttpd/",      "lighttpd",       "lighttpd"},
};

/* Bounded substring search over exactly `haystack_len` bytes (never reads
 * haystack[haystack_len] or beyond, regardless of whether haystack is
 * NUL-terminated). Returns the byte offset of the first match, or
 * SIZE_MAX if `needle` does not occur. */
static size_t cytadel_cpe_find(const char *haystack, size_t haystack_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > haystack_len) {
        return (size_t)-1;
    }
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return i;
        }
    }
    return (size_t)-1;
}

static bool cytadel_cpe_version_char_ok(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

/* Extracts a version token starting at text[start] (bounded to
 * text_len), lowercased, into out (a buffer of at least
 * CYTADEL_CPE_VERSION_MAX_LEN + 1 bytes). Stops at the first character
 * outside cytadel_cpe_version_char_ok(), at `text_len`, or at
 * CYTADEL_CPE_VERSION_MAX_LEN bytes, whichever comes first. Returns the
 * number of bytes written (0 if the very first character is not a valid
 * version character -- "no usable version"). */
static size_t cytadel_cpe_extract_version(const char *text, size_t text_len, size_t start,
                                            char *out) {
    size_t out_len = 0;
    for (size_t i = start; i < text_len && out_len < CYTADEL_CPE_VERSION_MAX_LEN; i++) {
        unsigned char c = (unsigned char)text[i];
        if (!cytadel_cpe_version_char_ok(c)) {
            break;
        }
        if (c >= 'A' && c <= 'Z') {
            c = (unsigned char)(c - 'A' + 'a');
        }
        out[out_len++] = (char)c;
    }
    out[out_len] = '\0';
    return out_len;
}

bool cytadel_cpe_map_and_write(cytadel_kb_t *kb, uint16_t port, const char *text, size_t text_len) {
    if (kb == NULL || text == NULL || text_len == 0) {
        return false;
    }

    size_t rule_count = sizeof(g_cpe_rules) / sizeof(g_cpe_rules[0]);
    for (size_t r = 0; r < rule_count; r++) {
        const cytadel_cpe_rule_t *rule = &g_cpe_rules[r];
        size_t marker_at = cytadel_cpe_find(text, text_len, rule->marker);
        if (marker_at == (size_t)-1) {
            continue;
        }

        size_t version_start = marker_at + strlen(rule->marker);
        char version[CYTADEL_CPE_VERSION_MAX_LEN + 1];
        size_t version_len = cytadel_cpe_extract_version(text, text_len, version_start, version);
        if (version_len == 0) {
            /* Marker present but no usable version followed -- do not
             * guess a CPE (kb-schema.md §7.7). Nothing else in this
             * banner is going to identify a different product more
             * confidently, so stop here rather than trying later rules. */
            cytadel_log_debug("cpe_map: marker '%s' found on port %u but no version followed; "
                               "not writing a CPE",
                               rule->marker, (unsigned)port);
            return false;
        }

        char cpe[16 + 32 + 32 + CYTADEL_CPE_VERSION_MAX_LEN + 32];
        int written = snprintf(cpe, sizeof(cpe), "cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", rule->vendor,
                                rule->product, version);
        if (written < 0 || (size_t)written >= sizeof(cpe)) {
            cytadel_log_warn("cpe_map: CPE string too long for vendor='%s' product='%s' "
                              "version='%s' on port %u",
                              rule->vendor, rule->product, version, (unsigned)port);
            return false;
        }

        char key[32];
        int key_written = snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
        if (key_written < 0 || (size_t)key_written >= sizeof(key)) {
            return false;
        }

        return cytadel_kb_set_str(kb, key, cpe) == 0;
    }

    return false;
}
