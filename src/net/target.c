#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/target.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

static void cytadel_target_set_err(char *err_buf, size_t err_buf_len, const char *fmt, ...) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_buf_len, fmt, ap);
    va_end(ap);
}

/* Any '/' (CIDR), ',' or whitespace (host list) means "more than one
 * target" -- reject with a clear Milestone-3 message rather than silently
 * scanning only a substring of spec. */
static bool cytadel_target_looks_like_multi(const char *spec) {
    for (size_t i = 0; spec[i] != '\0'; i++) {
        unsigned char c = (unsigned char)spec[i];
        if (c == '/' || c == ',' || isspace(c)) {
            return true;
        }
    }
    return false;
}

cytadel_target_status_t cytadel_target_parse(const char *spec, cytadel_target_t *out_target,
                                              char *err_buf, size_t err_buf_len) {
    if (out_target == NULL) {
        cytadel_target_set_err(err_buf, err_buf_len, "internal error: out_target is NULL");
        return CYTADEL_TARGET_ERR_INVALID;
    }

    if (spec == NULL || spec[0] == '\0') {
        cytadel_target_set_err(err_buf, err_buf_len, "empty target specification");
        return CYTADEL_TARGET_ERR_INVALID;
    }

    size_t spec_len = strnlen(spec, CYTADEL_NET_HOST_STR_MAX);
    if (spec_len >= CYTADEL_NET_HOST_STR_MAX) {
        cytadel_target_set_err(err_buf, err_buf_len,
                                "target specification too long (max %d bytes)",
                                CYTADEL_NET_HOST_STR_MAX - 1);
        return CYTADEL_TARGET_ERR_INVALID;
    }

    if (cytadel_target_looks_like_multi(spec)) {
        cytadel_target_set_err(err_buf, err_buf_len,
                                "multiple targets: '%s' looks like a CIDR range or a host "
                                "list, which is not supported yet -- Milestone 3", spec);
        return CYTADEL_TARGET_ERR_MULTI;
    }

    cytadel_target_t result;
    memset(&result, 0, sizeof(result));
    memcpy(result.host, spec, spec_len);
    result.host[spec_len] = '\0';

    /* Fast path: spec is already an IPv4 literal -- no DNS round trip. */
    struct in_addr addr4;
    if (inet_pton(AF_INET, spec, &addr4) == 1) {
        if (inet_ntop(AF_INET, &addr4, result.ip, sizeof(result.ip)) == NULL) {
            cytadel_target_set_err(err_buf, err_buf_len,
                                    "internal error: could not format IPv4 literal '%s'", spec);
            return CYTADEL_TARGET_ERR_INVALID;
        }
        *out_target = result;
        return CYTADEL_TARGET_OK;
    }

    /* Not a literal -- resolve as a hostname. AF_UNSPEC (see target.h's
     * header comment) so a future milestone can extend address selection
     * to include IPv6 without changing this call; Milestone 2 only picks
     * the first AF_INET result and reports clearly if none exists. */
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo *res = NULL;
    int gai_rc = getaddrinfo(spec, NULL, &hints, &res);
    if (gai_rc != 0) {
        cytadel_target_set_err(err_buf, err_buf_len, "could not resolve host '%s': %s",
                                spec, gai_strerror(gai_rc));
        return CYTADEL_TARGET_ERR_RESOLVE;
    }

    bool found_ipv4 = false;
    bool found_ipv6_only = false;
    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            const struct sockaddr_in *sin = (const struct sockaddr_in *)(const void *)p->ai_addr;
            if (inet_ntop(AF_INET, &sin->sin_addr, result.ip, sizeof(result.ip)) != NULL) {
                found_ipv4 = true;
                break;
            }
        } else if (p->ai_family == AF_INET6) {
            found_ipv6_only = true;
        }
    }

    /* Single owner of `res`: freed here on every path from this point on,
     * whether resolution ultimately succeeds or fails below. */
    freeaddrinfo(res);
    res = NULL;

    if (!found_ipv4) {
        if (found_ipv6_only) {
            cytadel_target_set_err(err_buf, err_buf_len,
                                    "host '%s' only resolved to IPv6 address(es); IPv6 "
                                    "targets are not supported yet", spec);
        } else {
            cytadel_target_set_err(err_buf, err_buf_len,
                                    "host '%s' resolved to no usable address", spec);
        }
        return CYTADEL_TARGET_ERR_RESOLVE;
    }

    *out_target = result;
    return CYTADEL_TARGET_OK;
}

bool cytadel_target_is_ipv4_literal(const char *spec) {
    if (spec == NULL) {
        return false;
    }
    struct in_addr addr4;
    return inet_pton(AF_INET, spec, &addr4) == 1;
}
