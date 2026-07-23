#ifndef CYTADEL_NET_TARGETS_FILE_H
#define CYTADEL_NET_TARGETS_FILE_H

#include <stddef.h>

/* Reads a --targets-file: one target spec per line (a literal IPv4
 * address, a hostname, or a CIDR block -- the same tokens accepted by
 * target_list.h's comma-separated spec grammar, just one per line instead
 * of comma-joined). '#' starts a comment that runs to the end of the line
 * (whether the whole line is a comment or it trails real content); blank
 * lines (empty after stripping the comment and surrounding whitespace) are
 * skipped. This module only knows about file I/O and line framing -- it
 * has no idea what a valid target spec looks like; target_list.c feeds
 * each returned line through the same per-token expansion it uses for the
 * comma-separated --targets spec. */

#ifdef __cplusplus
extern "C" {
#endif

/* Longest line this reader accepts (including any trailing comment before
 * it is stripped). Generous for any legitimate hostname/CIDR/comment;
 * a line that does not fit is a hard error (CYTADEL_TARGETS_FILE_ERR_LINE_TOO_LONG),
 * never silently truncated -- silently truncating a target spec could
 * cause a scan to silently target something the operator did not intend. */
#define CYTADEL_TARGETS_FILE_LINE_MAX 512

/* Hard cap on the number of non-comment/non-blank lines read from one
 * file -- independent of, and deliberately smaller than the reasoning
 * behind, CYTADEL_MAX_TARGETS (target_list.h): a single line can expand to
 * many hosts (a CIDR block), so this is a separate DoS guard against a
 * pathological file with an enormous number of *lines*, checked while
 * still just reading text, before any address expansion happens. */
#define CYTADEL_TARGETS_FILE_MAX_LINES 100000

typedef enum {
    CYTADEL_TARGETS_FILE_OK = 0,
    CYTADEL_TARGETS_FILE_ERR_OPEN,           /* could not open the file (missing, permission, symlink) */
    CYTADEL_TARGETS_FILE_ERR_LINE_TOO_LONG,  /* a line exceeded CYTADEL_TARGETS_FILE_LINE_MAX */
    CYTADEL_TARGETS_FILE_ERR_TOO_MANY_LINES, /* more than CYTADEL_TARGETS_FILE_MAX_LINES content lines */
    CYTADEL_TARGETS_FILE_ERR_ALLOC
} cytadel_targets_file_status_t;

typedef struct {
    char **lines;  /* heap array of heap-allocated, NUL-terminated, trimmed lines */
    size_t count;
} cytadel_targets_file_lines_t;

/* Opens and reads `path` (S1 hardening, matching src/log's log-file
 * opening: O_RDONLY | O_NOFOLLOW | O_CLOEXEC -- refuses to follow a
 * symlink an attacker may have planted at the requested path), returning
 * every non-comment, non-blank, trimmed content line via *out. On any
 * non-OK status, a human-readable message is written into err_buf
 * (bounds-checked, always NUL-terminated; err_buf/err_buf_len == 0 is safe
 * to skip the message) and *out is left unmodified.
 *
 * On CYTADEL_TARGETS_FILE_OK, the caller owns *out and must release it via
 * cytadel_targets_file_lines_free() exactly once (even if out->count == 0
 * -- an empty file is not itself an error at this layer; target_list.c
 * decides whether "zero targets total" is an error once every source
 * (--targets spec and/or --targets-file) has been combined). */
cytadel_targets_file_status_t cytadel_targets_file_read(const char *path,
                                                          cytadel_targets_file_lines_t *out,
                                                          char *err_buf, size_t err_buf_len);

/* Frees every line and the array itself, then zeroes the struct. Safe to
 * call on an already-freed/zeroed value (idempotent) and on a NULL
 * pointer (no-op). */
void cytadel_targets_file_lines_free(cytadel_targets_file_lines_t *lines);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TARGETS_FILE_H */
