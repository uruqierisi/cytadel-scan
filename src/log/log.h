#ifndef CYTADEL_LOG_H
#define CYTADEL_LOG_H

#include <stddef.h>

/* Internal-only logging module for the Cytadel Scan engine.
 *
 * This header intentionally lives under src/log/, not include/cytadel/log/:
 * logging is an engine-internal concern (docs/build-plan.md §1 option (b)),
 * not part of the public library surface. It is still reachable from other
 * in-repo targets (e.g. src/cli, tests/unit) because the `cytadel` static
 * library target publicly exposes src/log/ as an include directory (see
 * src/log/CMakeLists.txt) -- anything that links against `cytadel` picks up
 * this path transitively without log.h being installed or exported.
 *
 * Leveled, timestamped (ISO-8601 UTC, millisecond precision, matching
 * docs/contracts/db-schema.md's binding timestamp convention), writes to
 * stderr and optionally a log file. This is what the Lua log() binding
 * (Milestone 5/6) and the startup authorization gate call through.
 *
 * Thread-safe as of Milestone 3: the src/core worker pool's threads all
 * call cytadel_log*() concurrently while scanning different hosts, so the
 * write in cytadel_log_vwrite() (log.c) is serialized by a static
 * pthread_mutex_t -- see the comment above cytadel_log_lock() in log.c for
 * why a statically-initialized mutex needs no separate init/destroy call.
 * cytadel_log_init()/cytadel_log_set_level()/cytadel_log_close() are not
 * part of that locked section -- they are only ever called from main()
 * before the worker pool starts or after it has been joined, never
 * concurrently with a running pool.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_LOG_DEBUG = 0,
    CYTADEL_LOG_INFO  = 1,
    CYTADEL_LOG_WARN  = 2,
    CYTADEL_LOG_ERROR = 3,
    /* Not a selectable --log-level threshold (cytadel_log_level_from_string()
     * intentionally does not accept "audit") -- it is a distinct severity
     * that cytadel_log_vwrite() always emits regardless of g_min_level. See
     * cytadel_log_audit() below. */
    CYTADEL_LOG_AUDIT = 4
} cytadel_log_level_t;

/* Buffer size (bytes) required to hold a formatted "YYYY-MM-DDTHH:MM:SS.sssZ"
 * timestamp (24 characters) plus the NUL terminator, rounded up. */
#define CYTADEL_ISO8601_BUF_LEN 32

/* Initializes/resets the logger: sets the minimum level that will be
 * emitted and (re)opens an optional log file in append mode. Passing NULL
 * or an empty string for log_file_path disables file output (stderr-only).
 * Safe to call more than once (e.g. after re-parsing CLI flags); any
 * previously open log file is closed first.
 *
 * The log file is opened with O_NOFOLLOW (S1 hardening): if log_file_path
 * refers to a symlink -- planted by an attacker to redirect our writes at
 * an unintended file -- the open is refused rather than followed. A log
 * file that cannot be safely opened (symlink, permission denied, etc.)
 * must never prevent the mandatory authorization audit trail (W1,
 * cytadel_log_audit()) from being recorded, so this is never treated as a
 * fatal error: a warning is printed to stderr and logging falls back to
 * stderr-only.
 *
 * Always returns 0. The return type is kept `int` (rather than `void`) so
 * a genuine fatal initialization failure can be added later (e.g. once
 * cytadel_log_init() also initializes a mutex in Milestone 3) without an
 * API break. */
int cytadel_log_init(cytadel_log_level_t min_level, const char *log_file_path);

/* Changes the minimum level filter at runtime without touching the log
 * file. */
void cytadel_log_set_level(cytadel_log_level_t min_level);

/* Parses a level name ("debug"/"info"/"warn"/"error", case-insensitive).
 * Returns 0 and writes *out_level on success, -1 if name is NULL,
 * out_level is NULL, or the name is not recognized. */
int cytadel_log_level_from_string(const char *name, cytadel_log_level_t *out_level);

/* Returns a static, upper-case string for level ("DEBUG"/"INFO"/"WARN"/
 * "ERROR"/"AUDIT"/"UNKNOWN"). Never returns NULL. */
const char *cytadel_log_level_to_string(cytadel_log_level_t level);

/* Formats and emits a log line if level >= the configured minimum level
 * (CYTADEL_LOG_AUDIT is a standing exception -- see cytadel_log_audit()
 * below). printf-style; the formatted message is bounds-checked internally
 * against a fixed buffer and silently truncated if it would overflow (a
 * truncated log line is never a correctness/security issue, unlike
 * truncating detection data).
 *
 * Before being written, the formatted message is sanitized (W2 hardening):
 * every byte < 0x20 (e.g. '\n', '\r', tab) or 0x7f is replaced with a
 * "\xNN" escape. Log calls routinely embed untrusted values (CLI argv,
 * environment variables) via %s; without this, an embedded newline could
 * forge an extra, unattributed log/audit line. This applies to every log
 * function below -- callers never need to sanitize their own arguments. */
void cytadel_log(cytadel_log_level_t level, const char *fmt, ...);

void cytadel_log_debug(const char *fmt, ...);
void cytadel_log_info(const char *fmt, ...);
void cytadel_log_warn(const char *fmt, ...);
void cytadel_log_error(const char *fmt, ...);

/* Emits a log line unconditionally, ignoring the configured minimum level
 * filter (g_min_level / --log-level) -- W1 hardening. Reserved for the
 * mandatory startup authorization-confirmation / refusal record (the project policy
 * rule #2; docs/contracts/db-schema.md §6/§9's future `scans` row). That
 * record must never be silently dropped just because the operator raised
 * --log-level to warn/error; every other log function above is filterable
 * by design, this one deliberately is not. Same destinations, timestamp
 * format, and message sanitization as every other log function; tagged
 * "[AUDIT]" in the emitted line. */
void cytadel_log_audit(const char *fmt, ...);

/* Flushes and closes the log file, if one is open. Idempotent -- safe to
 * call multiple times or without a prior successful cytadel_log_init(). */
void cytadel_log_close(void);

/* Writes the current wall-clock time, formatted as strict ISO-8601 UTC with
 * millisecond precision and an explicit 'Z' suffix
 * ("YYYY-MM-DDTHH:MM:SS.sssZ"), into buf. buf_len must be at least
 * CYTADEL_ISO8601_BUF_LEN. Returns 0 on success, -1 on any failure (buffer
 * too small, clock read failure) -- buf is left unspecified in that case.
 * Exposed here (not just used internally by cytadel_log()) because this is
 * also the format every DB timestamp writer must use per
 * docs/contracts/db-schema.md's binding timestamp convention, and it is
 * independently unit-tested. */
int cytadel_log_format_timestamp_utc(char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_LOG_H */
