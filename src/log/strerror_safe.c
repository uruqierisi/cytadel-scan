#define _POSIX_C_SOURCE 200809L

#include "strerror_safe.h"

#include <string.h>
#include <stdio.h>

/* strerror_r() has two mutually incompatible signatures depending on which
 * feature-test macros are visible when <string.h> is included:
 *
 *   - XSI-compliant (POSIX.1-2001/2008): `int strerror_r(int, char *, size_t)`
 *     -- returns 0 on success (the message is written into buf), a
 *     positive errno-style code on failure.
 *   - GNU-specific: `char *strerror_r(int, char *, size_t)` -- returns a
 *     pointer to the message, which may or may not be `buf` itself (glibc
 *     sometimes returns a pointer into an internal, immutable, per-errnum
 *     string table instead of writing into buf at all).
 *
 * Which one a given translation unit gets depends on _POSIX_C_SOURCE /
 * _DEFAULT_SOURCE / _GNU_SOURCE, and this codebase does not define the
 * same feature-test macros in every file (e.g. icmp_probe.c additionally
 * needs _DEFAULT_SOURCE for <netinet/ip.h>/<netinet/ip_icmp.h> -- see its
 * own top-of-file comment), so a single #ifdef guess here would be fragile
 * and silently wrong wherever it disagrees with the libc's actual choice.
 *
 * Instead, the two tiny helpers below are dispatched via _Generic on the
 * *actual* return type the compiler resolved for the strerror_r() call in
 * this file -- correct by construction, regardless of which variant is in
 * scope. The controlling expression of a _Generic selection is never
 * evaluated (C11 6.5.1.1p3, same rule as sizeof/typeof), so writing
 * strerror_r(...) a second time as that controlling expression does not
 * actually invoke it twice at runtime -- only the chosen branch's call
 * (the second, real argument below) runs. */
static char *cytadel_strerror_r_xsi_result(char *buf, int rc) {
    return (rc == 0) ? buf : NULL;
}

static char *cytadel_strerror_r_gnu_result(char *buf, char *result) {
    (void)buf;
    return result;
}

#define CYTADEL_STRERROR_R(errnum, buf, buflen)                                     \
    _Generic((strerror_r((errnum), (buf), (buflen))),                              \
             int: cytadel_strerror_r_xsi_result,                                    \
             char *: cytadel_strerror_r_gnu_result)((buf), strerror_r((errnum), (buf), (buflen)))

const char *cytadel_strerror_safe(int errnum, char *buf, size_t buflen) {
    if (buf == NULL || buflen == 0) {
        return buf;
    }
    buf[0] = '\0';

    char *msg = CYTADEL_STRERROR_R(errnum, buf, buflen);
    if (msg == NULL) {
        /* XSI strerror_r() reported failure (unrecognized errnum on this
         * libc, or buflen too small) -- never leave buf empty/stale, an
         * empty "%s" in a log line is worse than a generic fallback. */
        snprintf(buf, buflen, "Unknown error %d", errnum);
        return buf;
    }
    if (msg != buf) {
        /* GNU strerror_r() returned a message living outside buf -- copy
         * it in so every caller gets one uniform "the message is always
         * in buf" contract, regardless of which variant actually ran. */
        strncpy(buf, msg, buflen - 1);
    }
    /* Defensive NUL-termination on every path, including the case where
     * strerror_r() itself already wrote a full, unterminated buflen bytes. */
    buf[buflen - 1] = '\0';
    return buf;
}
