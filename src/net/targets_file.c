#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/targets_file.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void cytadel_targets_file_set_err(char *err_buf, size_t err_buf_len, const char *fmt, ...) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_buf_len, fmt, ap);
    va_end(ap);
}

/* Frees every already-allocated line plus the array itself. Used both by
 * the public free function and internally to unwind a partially-built
 * accumulation on an error path -- single cleanup path, no duplicated
 * free logic. */
static void cytadel_targets_file_lines_release(char **lines, size_t count) {
    if (lines == NULL) {
        return;
    }
    for (size_t i = 0; i < count; i++) {
        free(lines[i]);
    }
    free(lines);
}

void cytadel_targets_file_lines_free(cytadel_targets_file_lines_t *lines) {
    if (lines == NULL) {
        return;
    }
    cytadel_targets_file_lines_release(lines->lines, lines->count);
    lines->lines = NULL;
    lines->count = 0;
}

/* Strips a trailing '\n'/'\r', truncates at the first '#' (comment marker,
 * anywhere in the line), then trims leading/trailing whitespace in place.
 * Returns the trimmed length. */
static size_t cytadel_targets_file_trim_line(char *line) {
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
        line[--len] = '\0';
    }

    char *hash = strchr(line, '#');
    if (hash != NULL) {
        *hash = '\0';
        len = (size_t)(hash - line);
    }

    size_t start = 0;
    while (start < len && isspace((unsigned char)line[start])) {
        start++;
    }
    size_t end = len;
    while (end > start && isspace((unsigned char)line[end - 1])) {
        end--;
    }

    size_t trimmed_len = end - start;
    if (start > 0 && trimmed_len > 0) {
        memmove(line, line + start, trimmed_len);
    }
    line[trimmed_len] = '\0';
    return trimmed_len;
}

/* strerror(errno) below (not the thread-safe helper in src/log/strerror_safe.h)
 * is intentional and safe: this function is only ever called from
 * target_list.c's target-expansion pass, which main() runs to completion
 * before cytadel_worker_pool_run() starts any worker thread (see
 * src/cli/main.c) -- there is no concurrent caller for it to race
 * against. */
cytadel_targets_file_status_t cytadel_targets_file_read(const char *path,
                                                          cytadel_targets_file_lines_t *out,
                                                          char *err_buf, size_t err_buf_len) {
    if (out == NULL || path == NULL || path[0] == '\0') {
        cytadel_targets_file_set_err(err_buf, err_buf_len,
                                      "internal error: invalid arguments to targets-file reader");
        return CYTADEL_TARGETS_FILE_ERR_OPEN;
    }

    /* S1 hardening, matching src/log's log-file opening: refuse to follow
     * a symlink an attacker may have planted at `path`. O_CLOEXEC keeps
     * the fd from leaking into any future child process. */
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        cytadel_targets_file_set_err(err_buf, err_buf_len,
                                      "could not open targets file '%s': %s", path, strerror(errno));
        return CYTADEL_TARGETS_FILE_ERR_OPEN;
    }

    FILE *f = fdopen(fd, "r");
    if (f == NULL) {
        cytadel_targets_file_set_err(err_buf, err_buf_len,
                                      "could not open targets file '%s': %s", path, strerror(errno));
        close(fd);
        return CYTADEL_TARGETS_FILE_ERR_OPEN;
    }

    char **lines = NULL;
    size_t count = 0;
    size_t capacity = 0;
    cytadel_targets_file_status_t status = CYTADEL_TARGETS_FILE_OK;

    /* +1 spare byte beyond the documented CYTADEL_TARGETS_FILE_LINE_MAX
     * (targets_file.h's public "longest line accepted" contract, still
     * CYTADEL_TARGETS_FILE_LINE_MAX - 1 content bytes below): fgets()
     * itself needs room for up to CYTADEL_TARGETS_FILE_LINE_MAX - 1
     * content bytes *plus* the trailing '\n' *plus* the NUL terminator it
     * appends. Sizing raw at exactly CYTADEL_TARGETS_FILE_LINE_MAX left no
     * room for the '\n' on a line of exactly the documented max length --
     * fgets() would fill the buffer with content only, never see the '\n'
     * or EOF on that read, and the has_newline/!feof(f) check below would
     * misclassify a legal max-length line as "too long" and reject it.
     * The too-long detection itself (a full read with no trailing '\n' and
     * not at EOF) still works exactly as before -- it just needed a big
     * enough buffer to not misfire on the boundary case. */
    char raw[CYTADEL_TARGETS_FILE_LINE_MAX + 1];
    while (fgets(raw, sizeof(raw), f) != NULL) {
        size_t raw_len = strlen(raw);
        int has_newline = (raw_len > 0 && raw[raw_len - 1] == '\n');
        if (!has_newline && !feof(f)) {
            cytadel_targets_file_set_err(err_buf, err_buf_len,
                                          "targets file '%s' has a line longer than %d bytes",
                                          path, CYTADEL_TARGETS_FILE_LINE_MAX - 1);
            status = CYTADEL_TARGETS_FILE_ERR_LINE_TOO_LONG;
            break;
        }

        size_t trimmed_len = cytadel_targets_file_trim_line(raw);
        if (trimmed_len == 0) {
            continue; /* blank line or comment-only line */
        }

        if (count >= CYTADEL_TARGETS_FILE_MAX_LINES) {
            cytadel_targets_file_set_err(err_buf, err_buf_len,
                                          "targets file '%s' has more than %d target lines",
                                          path, CYTADEL_TARGETS_FILE_MAX_LINES);
            status = CYTADEL_TARGETS_FILE_ERR_TOO_MANY_LINES;
            break;
        }

        if (count == capacity) {
            size_t new_capacity = (capacity == 0) ? 16 : (capacity * 2);
            char **grown = realloc(lines, new_capacity * sizeof(char *));
            if (grown == NULL) {
                cytadel_targets_file_set_err(err_buf, err_buf_len,
                                              "out of memory reading targets file '%s'", path);
                status = CYTADEL_TARGETS_FILE_ERR_ALLOC;
                break;
            }
            lines = grown;
            capacity = new_capacity;
        }

        char *copy = malloc(trimmed_len + 1);
        if (copy == NULL) {
            cytadel_targets_file_set_err(err_buf, err_buf_len,
                                          "out of memory reading targets file '%s'", path);
            status = CYTADEL_TARGETS_FILE_ERR_ALLOC;
            break;
        }
        memcpy(copy, raw, trimmed_len + 1);
        lines[count++] = copy;
    }

    fclose(f); /* also closes fd -- single owner, closed exactly once */

    if (status != CYTADEL_TARGETS_FILE_OK) {
        cytadel_targets_file_lines_release(lines, count);
        return status;
    }

    out->lines = lines;
    out->count = count;
    return CYTADEL_TARGETS_FILE_OK;
}
