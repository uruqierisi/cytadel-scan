#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/cidr.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "cytadel/net/scan_types.h"

static void cytadel_cidr_set_err(char *err_buf, size_t err_buf_len, const char *fmt, ...) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_buf_len, fmt, ap);
    va_end(ap);
}

cytadel_cidr_status_t cytadel_cidr_parse(const char *spec, cytadel_cidr_t *out,
                                          char *err_buf, size_t err_buf_len) {
    if (out == NULL || spec == NULL) {
        cytadel_cidr_set_err(err_buf, err_buf_len, "internal error: NULL argument to CIDR parser");
        return CYTADEL_CIDR_ERR_MALFORMED;
    }

    const char *slash = strchr(spec, '/');
    if (slash == NULL) {
        cytadel_cidr_set_err(err_buf, err_buf_len, "'%s' is not a CIDR block (missing '/')", spec);
        return CYTADEL_CIDR_ERR_MALFORMED;
    }
    if (strchr(slash + 1, '/') != NULL) {
        cytadel_cidr_set_err(err_buf, err_buf_len, "'%s' has more than one '/'", spec);
        return CYTADEL_CIDR_ERR_MALFORMED;
    }

    size_t addr_len = (size_t)(slash - spec);
    if (addr_len == 0 || addr_len >= CYTADEL_NET_IP_STR_MAX) {
        cytadel_cidr_set_err(err_buf, err_buf_len,
                              "'%s' has an invalid address part before '/'", spec);
        return CYTADEL_CIDR_ERR_BAD_ADDRESS;
    }
    char addr_buf[CYTADEL_NET_IP_STR_MAX];
    memcpy(addr_buf, spec, addr_len);
    addr_buf[addr_len] = '\0';

    struct in_addr addr4;
    if (inet_pton(AF_INET, addr_buf, &addr4) != 1) {
        cytadel_cidr_set_err(err_buf, err_buf_len,
                              "'%s' is not a valid IPv4 CIDR address", addr_buf);
        return CYTADEL_CIDR_ERR_BAD_ADDRESS;
    }

    const char *prefix_str = slash + 1;
    size_t prefix_len = strlen(prefix_str);
    /* Reject empty, over-long, non-digit (this also rejects a leading '-',
     * i.e. "/-1" -- there is no digit-only representation of a negative
     * number) prefixes up front so the accumulation loop below never has
     * to special-case a sign. */
    if (prefix_len == 0 || prefix_len > 2) {
        cytadel_cidr_set_err(err_buf, err_buf_len,
                              "'%s' has an invalid prefix length (expected 0-32)", spec);
        return CYTADEL_CIDR_ERR_BAD_PREFIX;
    }
    long prefix_val = 0;
    for (size_t i = 0; i < prefix_len; i++) {
        char c = prefix_str[i];
        if (c < '0' || c > '9') {
            cytadel_cidr_set_err(err_buf, err_buf_len,
                                  "'%s' has a non-numeric prefix length", spec);
            return CYTADEL_CIDR_ERR_BAD_PREFIX;
        }
        prefix_val = (prefix_val * 10) + (c - '0');
    }
    if (prefix_val > 32) {
        cytadel_cidr_set_err(err_buf, err_buf_len,
                              "'%s' has an out-of-range prefix length (expected 0-32)", spec);
        return CYTADEL_CIDR_ERR_BAD_PREFIX;
    }

    uint32_t addr_be;
    memcpy(&addr_be, &addr4, sizeof(addr_be));
    uint32_t addr_host = ntohl(addr_be);

    /* Guarded shift: for prefix == 0, "32 - prefix" == 32, and shifting a
     * 32-bit unsigned value left by its full bit width is undefined
     * behavior in C. The prefix == 0 case (mask is all-zero -- every
     * address matches) is special-cased explicitly rather than relying on
     * the shift to "do the right thing". */
    uint32_t mask = (prefix_val == 0) ? 0u : (uint32_t)(0xFFFFFFFFu << (32 - prefix_val));

    out->network = addr_host & mask;
    out->prefix = (int)prefix_val;
    return CYTADEL_CIDR_OK;
}

uint64_t cytadel_cidr_host_count(const cytadel_cidr_t *cidr) {
    if (cidr == NULL || cidr->prefix < 0 || cidr->prefix > 32) {
        return 0;
    }
    /* 1ULL (>=64 bits) shifted by up to 32 is always well-defined,
     * unlike shifting a 32-bit value by 32 -- this is the "guard the
     * shift" the milestone brief calls for; a /0 (32 - 0 == 32) yields
     * 4294967296 correctly instead of undefined behavior or a truncated
     * wraparound to 0. */
    return 1ULL << (32 - cidr->prefix);
}

int cytadel_cidr_nth_address(const cytadel_cidr_t *cidr, uint64_t n, char *buf, size_t buf_len) {
    if (cidr == NULL || buf == NULL || buf_len < CYTADEL_NET_IP_STR_MAX) {
        return -1;
    }
    uint64_t count = cytadel_cidr_host_count(cidr);
    if (count == 0 || n >= count) {
        return -1;
    }

    /* n < count <= 2^32, so the truncating cast to uint32_t below never
     * loses information, and `n`'s bits never overlap `cidr->network`'s
     * set bits (network is already masked to the top `prefix` bits by
     * cytadel_cidr_parse()), so a plain OR is the correct combine. */
    uint32_t addr_host = cidr->network | (uint32_t)n;
    uint32_t addr_be = htonl(addr_host);

    struct in_addr addr4;
    memcpy(&addr4, &addr_be, sizeof(addr_be));
    if (inet_ntop(AF_INET, &addr4, buf, (socklen_t)buf_len) == NULL) {
        return -1;
    }
    return 0;
}
