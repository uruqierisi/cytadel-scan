#define _POSIX_C_SOURCE 200809L

#include "log.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "strerror_safe.h"

/* Milestone 3: src/core's worker pool means multiple threads can call
 * cytadel_log*() concurrently for the first time, so the write to stderr /
 * the log file (cytadel_log_vwrite()'s critical section) must be
 * serialized -- otherwise two threads' lines can interleave mid-write
 * ("torn" lines) in the shared output. A single, statically-initialized
 * non-recursive mutex is enough: no code path between lock and unlock
 * below ever calls back into cytadel_log_lock()/cytadel_log_unlock()
 * itself, so recursive-mutex semantics are not needed.
 *
 * PTHREAD_MUTEX_INITIALIZER is used instead of an explicit
 * pthread_mutex_init() call: it is a compile-time constant, so the mutex
 * is valid before main() (and therefore before any thread, including the
 * very first one) ever runs -- there is no init-vs-first-use race window
 * to reason about, and no matching pthread_mutex_destroy() is required
 * either (POSIX allows a statically-initialized mutex to simply outlive
 * the process; PTHREAD_MUTEX_INITIALIZER never allocates any resource that
 * would otherwise leak). This keeps "init/close of the mutex is race-free"
 * true by construction rather than by careful ordering of init/close
 * calls. */
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static void cytadel_log_lock(void) {
    int rc = pthread_mutex_lock(&g_log_mutex);
    if (rc != 0) {
        /* Only possible here if the mutex were used incorrectly (e.g.
         * re-locked by the same thread, which this module never does) --
         * fall back to writing directly to stderr (bypassing the lock)
         * rather than silently dropping the log line, since
         * cytadel_log_vwrite() itself is what would normally report this
         * kind of failure.
         *
         * This path can run concurrently on any worker-pool thread (every
         * thread that logs reaches cytadel_log_lock()), so strerror() --
         * not guaranteed thread-safe -- must not be used here; the
         * thread-safe helper is. */
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        fprintf(stderr, "cytadel-scan: warning: log mutex lock failed: %s\n",
                cytadel_strerror_safe(rc, errbuf, sizeof(errbuf)));
    }
}

static void cytadel_log_unlock(void) {
    int rc = pthread_mutex_unlock(&g_log_mutex);
    if (rc != 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        fprintf(stderr, "cytadel-scan: warning: log mutex unlock failed: %s\n",
                cytadel_strerror_safe(rc, errbuf, sizeof(errbuf)));
    }
}

static cytadel_log_level_t g_min_level = CYTADEL_LOG_INFO;
static FILE *g_log_file = NULL;

#define CYTADEL_LOG_MSG_MAX 4096

/* Worst case every byte of the formatted message is a control byte and
 * expands to a 4-byte "\xNN" escape (W2 hardening); sizing the sanitized
 * buffer for that worst case means cytadel_log_sanitize() never has to
 * truncate a real audit line just because it contains a handful of escaped
 * bytes mixed with ordinary text. */
#define CYTADEL_LOG_SANITIZED_MAX ((CYTADEL_LOG_MSG_MAX * 4) + 1)

int cytadel_log_format_timestamp_utc(char *buf, size_t buf_len) {
    if (buf == NULL || buf_len < CYTADEL_ISO8601_BUF_LEN) {
        return -1;
    }

    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        return -1;
    }

    struct tm tm_utc;
    if (gmtime_r(&ts.tv_sec, &tm_utc) == NULL) {
        return -1;
    }

    long msec = ts.tv_nsec / 1000000L;
    int written = snprintf(buf, buf_len,
                            "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                            tm_utc.tm_year + 1900, tm_utc.tm_mon + 1, tm_utc.tm_mday,
                            tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec, msec);
    if (written < 0 || (size_t)written >= buf_len) {
        return -1;
    }

    return 0;
}

/* strerror(errno) below (not the thread-safe helper) is intentional and
 * safe: per log.h's header comment, cytadel_log_init() is only ever called
 * from main() before the worker pool starts or after it has been joined,
 * never concurrently with a running pool or with any other thread that
 * could itself be calling strerror() -- there is no second caller for it
 * to race against. */
int cytadel_log_init(cytadel_log_level_t min_level, const char *log_file_path) {
    g_min_level = min_level;

    if (g_log_file != NULL) {
        fclose(g_log_file);
        g_log_file = NULL;
    }

    if (log_file_path != NULL && log_file_path[0] != '\0') {
        /* S1 hardening: O_NOFOLLOW refuses to open log_file_path if it is
         * a symlink, so an attacker who can plant a symlink at the
         * requested path cannot redirect our writes at an arbitrary file.
         * O_CLOEXEC keeps the fd from leaking into child processes (none
         * exist yet in Milestone 1, but this is cheap and correct
         * regardless). 0600: the log may contain operator identity and
         * target information, no reason to make it world-readable. */
        int fd = open(log_file_path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            fprintf(stderr,
                    "cytadel-scan: warning: could not open log file '%s' (%s); "
                    "continuing with stderr-only logging\n",
                    log_file_path, strerror(errno));
        } else {
            FILE *f = fdopen(fd, "a");
            if (f == NULL) {
                fprintf(stderr,
                        "cytadel-scan: warning: could not open log file '%s' (%s); "
                        "continuing with stderr-only logging\n",
                        log_file_path, strerror(errno));
                close(fd);
            } else {
                g_log_file = f;
            }
        }
        /* A log file that could not be safely opened must never abort the
         * whole program -- the mandatory authorization audit trail (W1)
         * still has to reach stderr either way. */
    }

    return 0;
}

void cytadel_log_set_level(cytadel_log_level_t min_level) {
    g_min_level = min_level;
}

int cytadel_log_level_from_string(const char *name, cytadel_log_level_t *out_level) {
    if (name == NULL || out_level == NULL) {
        return -1;
    }
    if (strcasecmp(name, "debug") == 0) { *out_level = CYTADEL_LOG_DEBUG; return 0; }
    if (strcasecmp(name, "info")  == 0) { *out_level = CYTADEL_LOG_INFO;  return 0; }
    if (strcasecmp(name, "warn")  == 0) { *out_level = CYTADEL_LOG_WARN;  return 0; }
    if (strcasecmp(name, "error") == 0) { *out_level = CYTADEL_LOG_ERROR; return 0; }
    return -1;
}

const char *cytadel_log_level_to_string(cytadel_log_level_t level) {
    switch (level) {
        case CYTADEL_LOG_DEBUG: return "DEBUG";
        case CYTADEL_LOG_INFO:  return "INFO";
        case CYTADEL_LOG_WARN:  return "WARN";
        case CYTADEL_LOG_ERROR: return "ERROR";
        case CYTADEL_LOG_AUDIT: return "AUDIT";
        default:                return "UNKNOWN";
    }
}

/* Writes a sanitized copy of the NUL-terminated `in` into `out` (always
 * NUL-terminated within out_len bytes; never overflows). Any byte < 0x20
 * (control characters, including '\n', '\r', and tab) or 0x7f (DEL) is
 * replaced with a "\xNN" escape instead of being copied raw -- W2
 * hardening. Log calls routinely embed untrusted values (CLI argv,
 * environment variables) via %s; without this, an embedded newline could
 * forge an extra, unattributed log/audit line that never went through
 * cytadel_log(). CYTADEL_LOG_SANITIZED_MAX already sizes `out` for the
 * worst case (every input byte escaped), but this still bounds-checks
 * every write and truncates safely rather than trusting that sizing --
 * same truncation policy as the rest of this module: acceptable for a log
 * line, never used for anything correctness- or security-critical. */
static void cytadel_log_sanitize(const char *in, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }

    size_t o = 0;
    for (size_t i = 0; in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c < 0x20 || c == 0x7f) {
            char esc[5]; /* "\xNN" + NUL */
            snprintf(esc, sizeof(esc), "\\x%02x", c);
            size_t esc_len = strlen(esc);
            if (o + esc_len >= out_len) {
                break;
            }
            memcpy(out + o, esc, esc_len);
            o += esc_len;
        } else {
            if (o + 1 >= out_len) {
                break;
            }
            out[o++] = (char)c;
        }
    }
    out[o] = '\0';
}

static void cytadel_log_vwrite(cytadel_log_level_t level, const char *fmt, va_list ap) {
    /* CYTADEL_LOG_AUDIT is a standing exception to the level filter (W1
     * hardening): the mandatory authorization audit trail must never be
     * suppressible by --log-level. */
    if (level != CYTADEL_LOG_AUDIT && level < g_min_level) {
        return;
    }

    char timestamp[CYTADEL_ISO8601_BUF_LEN];
    if (cytadel_log_format_timestamp_utc(timestamp, sizeof(timestamp)) != 0) {
        /* Never lose a log line just because the clock read failed; fall
         * back to a fixed, obviously-sentinel timestamp instead. */
        strncpy(timestamp, "0000-00-00T00:00:00.000Z", sizeof(timestamp) - 1);
        timestamp[sizeof(timestamp) - 1] = '\0';
    }

    char message[CYTADEL_LOG_MSG_MAX];
    int written = vsnprintf(message, sizeof(message), fmt, ap);
    if (written < 0) {
        strncpy(message, "<log message formatting error>", sizeof(message) - 1);
        message[sizeof(message) - 1] = '\0';
    }
    /* A message longer than the buffer is silently truncated by vsnprintf
     * (still NUL-terminated) -- acceptable for a log line, never used for
     * anything correctness- or security-critical. */

    char sanitized[CYTADEL_LOG_SANITIZED_MAX];
    cytadel_log_sanitize(message, sanitized, sizeof(sanitized));

    cytadel_log_lock();
    fprintf(stderr, "%s [%s] %s\n", timestamp, cytadel_log_level_to_string(level), sanitized);
    if (g_log_file != NULL) {
        fprintf(g_log_file, "%s [%s] %s\n", timestamp, cytadel_log_level_to_string(level), sanitized);
        fflush(g_log_file);
    }
    cytadel_log_unlock();
}

void cytadel_log(cytadel_log_level_t level, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(level, fmt, ap);
    va_end(ap);
}

void cytadel_log_debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(CYTADEL_LOG_DEBUG, fmt, ap);
    va_end(ap);
}

void cytadel_log_info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(CYTADEL_LOG_INFO, fmt, ap);
    va_end(ap);
}

void cytadel_log_warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(CYTADEL_LOG_WARN, fmt, ap);
    va_end(ap);
}

void cytadel_log_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(CYTADEL_LOG_ERROR, fmt, ap);
    va_end(ap);
}

void cytadel_log_audit(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    cytadel_log_vwrite(CYTADEL_LOG_AUDIT, fmt, ap);
    va_end(ap);
}

void cytadel_log_close(void) {
    cytadel_log_lock();
    if (g_log_file != NULL) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    cytadel_log_unlock();
}
