#ifndef CYTADEL_LOG_STRERROR_SAFE_H
#define CYTADEL_LOG_STRERROR_SAFE_H

#include <stddef.h>

/* Thread-safe strerror() replacement (Milestone 3 security fix).
 *
 * strerror() is not required to be thread-safe, and on glibc it is not: on
 * an out-of-range/unrecognized errnum it formats "Unknown error %d" into a
 * process-wide static buffer and returns a pointer to it. Once src/core's
 * worker pool started calling into src/net's probe functions from multiple
 * pthreads concurrently (Milestone 3), every strerror(errno) on one of
 * those threads' failure paths became a potential data race against every
 * other thread doing the same -- two threads racing to (re)write that one
 * shared buffer, with either thread possibly observing a torn or the
 * *other* thread's message.
 *
 * This header lives under src/log/ (not src/net/ or src/core/) for the
 * same reason log.h does: it is a small, dependency-free helper needed by
 * both modules, and src/log/CMakeLists.txt already adds this directory to
 * `cytadel`'s PUBLIC include path, so "strerror_safe.h" is reachable from
 * any target linking against `cytadel` exactly the way "log.h" already is
 * -- no new include directory to wire up. */

#ifdef __cplusplus
extern "C" {
#endif

/* Buffer size (bytes) callers should use for `buf` below -- generous for
 * any strerror() message this platform is likely to produce (matches the
 * sizing glibc itself recommends for strerror_r()). */
#define CYTADEL_STRERROR_BUF_LEN 128

/* Writes a human-readable message for `errnum` into `buf` (thread-safe:
 * built on strerror_r(), never strerror()'s shared static buffer) and
 * returns `buf`. Always leaves buf NUL-terminated within buflen bytes --
 * including on an unrecognized errnum or a strerror_r() failure, where a
 * generic-but-non-empty fallback ("Unknown error %d") is written instead
 * of leaving buf blank or stale, so a caller's "%s" log argument is never
 * garbage.
 *
 * buf/buflen must describe a real buffer of at least 1 byte; if buf is
 * NULL or buflen is 0 this is a no-op that returns buf unchanged (every
 * caller in this codebase passes a fixed-size stack buffer, so this is a
 * defensive guard, not an expected path). */
const char *cytadel_strerror_safe(int errnum, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_LOG_STRERROR_SAFE_H */
