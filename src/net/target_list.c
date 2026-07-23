#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/target_list.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cytadel/net/cidr.h"
#include "cytadel/net/scan_types.h"
#include "cytadel/net/targets_file.h"

/* A single list/file entry, after trimming, must fit the same budget
 * target.h's single-spec parser enforces (CYTADEL_NET_HOST_STR_MAX) --
 * a CIDR's "/NN" suffix fits comfortably inside that same budget, so one
 * constant covers every token shape. */
#define CYTADEL_TARGET_LIST_TOKEN_MAX_LEN CYTADEL_NET_HOST_STR_MAX

/* Guards against a pathological --targets spec string, mirroring
 * port_range.c's equivalent guards. */
#define CYTADEL_TARGET_LIST_SPEC_MAX_LEN 65536
#define CYTADEL_TARGET_LIST_SPEC_MAX_TOKENS 8192

static void cytadel_target_list_set_err(char *err_buf, size_t err_buf_len, const char *fmt, ...) {
    if (err_buf == NULL || err_buf_len == 0) {
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(err_buf, err_buf_len, fmt, ap);
    va_end(ap);
}

/* Growable array of cytadel_target_t -- the accumulation buffer every
 * token (list entry, CIDR-expanded address, or targets-file line) is
 * pushed into before the final de-duplication pass. */
typedef struct {
    cytadel_target_t *items;
    size_t count;
    size_t capacity;
} cytadel_target_dynarray_t;

static int cytadel_target_dynarray_push(cytadel_target_dynarray_t *arr, const cytadel_target_t *t) {
    if (arr->count == arr->capacity) {
        size_t new_capacity = (arr->capacity == 0) ? 64 : (arr->capacity * 2);
        cytadel_target_t *grown = realloc(arr->items, new_capacity * sizeof(*grown));
        if (grown == NULL) {
            return -1;
        }
        arr->items = grown;
        arr->capacity = new_capacity;
    }
    arr->items[arr->count++] = *t;
    return 0;
}

static void cytadel_target_dynarray_free(cytadel_target_dynarray_t *arr) {
    free(arr->items);
    arr->items = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

/* Expands one already-isolated token (one comma-separated list entry, or
 * one targets-file line) into `arr`, updating `*total` (the running count
 * across every token processed so far, from every source) as it goes.
 * Enforces CYTADEL_MAX_TARGETS *before* looping over a CIDR block's
 * addresses -- see cidr.h's host-count comment -- so an oversized block is
 * rejected in O(1), never partially expanded. */
static cytadel_target_list_status_t cytadel_target_list_expand_token(
    const char *tok, size_t tok_len, cytadel_target_dynarray_t *arr, size_t *total,
    char *err_buf, size_t err_buf_len) {
    while (tok_len > 0 && isspace((unsigned char)tok[0])) {
        tok++;
        tok_len--;
    }
    while (tok_len > 0 && isspace((unsigned char)tok[tok_len - 1])) {
        tok_len--;
    }

    if (tok_len == 0) {
        cytadel_target_list_set_err(err_buf, err_buf_len, "empty target token");
        return CYTADEL_TARGET_LIST_ERR_INVALID;
    }
    if (tok_len >= CYTADEL_TARGET_LIST_TOKEN_MAX_LEN) {
        cytadel_target_list_set_err(err_buf, err_buf_len,
                                     "target token too long (max %d bytes): '%.*s'",
                                     CYTADEL_TARGET_LIST_TOKEN_MAX_LEN - 1, (int)tok_len, tok);
        return CYTADEL_TARGET_LIST_ERR_INVALID;
    }

    char buf[CYTADEL_TARGET_LIST_TOKEN_MAX_LEN];
    memcpy(buf, tok, tok_len);
    buf[tok_len] = '\0';

    if (strchr(buf, '/') != NULL) {
        cytadel_cidr_t cidr;
        char cidr_err[192];
        cytadel_cidr_status_t cidr_status = cytadel_cidr_parse(buf, &cidr, cidr_err, sizeof(cidr_err));
        if (cidr_status != CYTADEL_CIDR_OK) {
            cytadel_target_list_set_err(err_buf, err_buf_len, "%s", cidr_err);
            return CYTADEL_TARGET_LIST_ERR_INVALID;
        }

        uint64_t host_count = cytadel_cidr_host_count(&cidr);
        if (host_count == 0 || (uint64_t)*total + host_count > (uint64_t)CYTADEL_MAX_TARGETS) {
            cytadel_target_list_set_err(
                err_buf, err_buf_len,
                "'%s' expands to %llu host(s), which would exceed the %d-target cap "
                "(CYTADEL_MAX_TARGETS) -- narrow the block or split it across multiple runs",
                buf, (unsigned long long)host_count, CYTADEL_MAX_TARGETS);
            return CYTADEL_TARGET_LIST_ERR_TOO_MANY;
        }

        for (uint64_t n = 0; n < host_count; n++) {
            cytadel_target_t t;
            memset(&t, 0, sizeof(t));
            if (cytadel_cidr_nth_address(&cidr, n, t.ip, sizeof(t.ip)) != 0) {
                cytadel_target_list_set_err(err_buf, err_buf_len,
                                             "internal error expanding CIDR block '%s'", buf);
                return CYTADEL_TARGET_LIST_ERR_INVALID;
            }
            /* CIDR-expanded entries have no distinct hostname -- host and
             * ip are the same dotted-quad literal, matching how
             * target.h's parser leaves both set to the same value for an
             * IPv4-literal spec. */
            memcpy(t.host, t.ip, strlen(t.ip) + 1);
            if (cytadel_target_dynarray_push(arr, &t) != 0) {
                cytadel_target_list_set_err(err_buf, err_buf_len, "out of memory expanding target list");
                return CYTADEL_TARGET_LIST_ERR_ALLOC;
            }
        }
        *total += (size_t)host_count;
        return CYTADEL_TARGET_LIST_OK;
    }

    if (*total + 1 > (size_t)CYTADEL_MAX_TARGETS) {
        cytadel_target_list_set_err(err_buf, err_buf_len,
                                     "target list exceeds the %d-target cap (CYTADEL_MAX_TARGETS)",
                                     CYTADEL_MAX_TARGETS);
        return CYTADEL_TARGET_LIST_ERR_TOO_MANY;
    }

    cytadel_target_t t;
    char target_err[192];
    cytadel_target_status_t target_status = cytadel_target_parse(buf, &t, target_err, sizeof(target_err));
    if (target_status != CYTADEL_TARGET_OK) {
        cytadel_target_list_set_err(err_buf, err_buf_len, "%s", target_err);
        return (target_status == CYTADEL_TARGET_ERR_RESOLVE) ? CYTADEL_TARGET_LIST_ERR_RESOLVE
                                                                : CYTADEL_TARGET_LIST_ERR_INVALID;
    }
    if (cytadel_target_dynarray_push(arr, &t) != 0) {
        cytadel_target_list_set_err(err_buf, err_buf_len, "out of memory expanding target list");
        return CYTADEL_TARGET_LIST_ERR_ALLOC;
    }
    *total += 1;
    return CYTADEL_TARGET_LIST_OK;
}

/* Splits `spec` on top-level commas and expands each token in turn --
 * same tokenizer shape as port_range.c's comma splitter. */
static cytadel_target_list_status_t cytadel_target_list_expand_spec(
    const char *spec, cytadel_target_dynarray_t *arr, size_t *total, char *err_buf,
    size_t err_buf_len) {
    size_t spec_len = strnlen(spec, CYTADEL_TARGET_LIST_SPEC_MAX_LEN);
    if (spec_len >= CYTADEL_TARGET_LIST_SPEC_MAX_LEN) {
        cytadel_target_list_set_err(err_buf, err_buf_len,
                                     "target specification too long (max %d bytes)",
                                     CYTADEL_TARGET_LIST_SPEC_MAX_LEN - 1);
        return CYTADEL_TARGET_LIST_ERR_INVALID;
    }

    size_t i = 0;
    size_t token_count = 0;
    for (;;) {
        size_t tok_start = i;
        while (i < spec_len && spec[i] != ',') {
            i++;
        }
        size_t tok_len = i - tok_start;

        token_count++;
        if (token_count > CYTADEL_TARGET_LIST_SPEC_MAX_TOKENS) {
            cytadel_target_list_set_err(err_buf, err_buf_len,
                                         "too many comma-separated tokens in target spec (max %d)",
                                         CYTADEL_TARGET_LIST_SPEC_MAX_TOKENS);
            return CYTADEL_TARGET_LIST_ERR_INVALID;
        }

        cytadel_target_list_status_t status =
            cytadel_target_list_expand_token(spec + tok_start, tok_len, arr, total, err_buf, err_buf_len);
        if (status != CYTADEL_TARGET_LIST_OK) {
            return status;
        }

        if (i >= spec_len) {
            break;
        }
        i++; /* skip the ',' */
    }
    return CYTADEL_TARGET_LIST_OK;
}

/* Sort key used only for the de-duplication pass below -- deliberately a
 * self-contained value type (ip string + original index) rather than a
 * comparator closing over external state, so qsort()'s plain
 * int(*)(const void*, const void*) signature is enough (no qsort_r /
 * global needed, so this stays reentrant). */
typedef struct {
    char ip[CYTADEL_NET_IP_STR_MAX];
    size_t idx;
} cytadel_target_dedup_key_t;

static int cytadel_target_dedup_key_cmp(const void *a, const void *b) {
    const cytadel_target_dedup_key_t *ka = (const cytadel_target_dedup_key_t *)a;
    const cytadel_target_dedup_key_t *kb = (const cytadel_target_dedup_key_t *)b;
    int c = strcmp(ka->ip, kb->ip);
    if (c != 0) {
        return c;
    }
    if (ka->idx < kb->idx) {
        return -1;
    }
    if (ka->idx > kb->idx) {
        return 1;
    }
    return 0;
}

/* De-duplicates arr in place by resolved IPv4 address, keeping the
 * earliest (by original insertion order) entry for each address and
 * preserving the original relative order of the survivors -- so
 * "127.0.0.1,localhost" keeps the "127.0.0.1" entry (index 0), not
 * "localhost" (index 1), even though a lexicographic string sort of
 * "127.0.0.1" vs "127.0.0.1" (both resolve to the same ip) doesn't itself
 * carry that ordering; the (ip, idx) sort key does. O(n log n) via qsort,
 * not O(n^2), so this stays fast even close to CYTADEL_MAX_TARGETS. */
static cytadel_target_list_status_t cytadel_target_list_dedup(cytadel_target_dynarray_t *arr,
                                                                 char *err_buf, size_t err_buf_len) {
    size_t n = arr->count;
    if (n <= 1) {
        return CYTADEL_TARGET_LIST_OK;
    }

    cytadel_target_dedup_key_t *keys = malloc(n * sizeof(cytadel_target_dedup_key_t));
    if (keys == NULL) {
        cytadel_target_list_set_err(err_buf, err_buf_len, "out of memory de-duplicating target list");
        return CYTADEL_TARGET_LIST_ERR_ALLOC;
    }
    for (size_t i = 0; i < n; i++) {
        memcpy(keys[i].ip, arr->items[i].ip, sizeof(keys[i].ip));
        keys[i].idx = i;
    }
    qsort(keys, n, sizeof(cytadel_target_dedup_key_t), cytadel_target_dedup_key_cmp);

    unsigned char *keep = calloc(n, sizeof(unsigned char));
    if (keep == NULL) {
        free(keys);
        cytadel_target_list_set_err(err_buf, err_buf_len, "out of memory de-duplicating target list");
        return CYTADEL_TARGET_LIST_ERR_ALLOC;
    }
    for (size_t i = 0; i < n; i++) {
        if (i == 0 || strcmp(keys[i].ip, keys[i - 1].ip) != 0) {
            keep[keys[i].idx] = 1;
        }
    }
    free(keys);

    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (keep[i]) {
            if (w != i) {
                arr->items[w] = arr->items[i];
            }
            w++;
        }
    }
    free(keep);
    arr->count = w;
    return CYTADEL_TARGET_LIST_OK;
}

cytadel_target_list_status_t cytadel_target_list_parse(const char *spec,
                                                          const char *targets_file_path,
                                                          cytadel_target_list_t *out_list,
                                                          char *err_buf, size_t err_buf_len) {
    if (out_list == NULL) {
        cytadel_target_list_set_err(err_buf, err_buf_len, "internal error: out_list is NULL");
        return CYTADEL_TARGET_LIST_ERR_INVALID;
    }

    bool has_spec = (spec != NULL && spec[0] != '\0');
    bool has_file = (targets_file_path != NULL && targets_file_path[0] != '\0');
    if (!has_spec && !has_file) {
        cytadel_target_list_set_err(err_buf, err_buf_len,
                                     "no targets given (need a target spec and/or --targets-file)");
        return CYTADEL_TARGET_LIST_ERR_EMPTY;
    }

    cytadel_target_dynarray_t arr = { NULL, 0, 0 };
    size_t total = 0;
    cytadel_target_list_status_t status = CYTADEL_TARGET_LIST_OK;

    if (has_spec) {
        status = cytadel_target_list_expand_spec(spec, &arr, &total, err_buf, err_buf_len);
    }

    if (status == CYTADEL_TARGET_LIST_OK && has_file) {
        cytadel_targets_file_lines_t file_lines = { NULL, 0 };
        char file_err[224];
        cytadel_targets_file_status_t file_status =
            cytadel_targets_file_read(targets_file_path, &file_lines, file_err, sizeof(file_err));
        if (file_status != CYTADEL_TARGETS_FILE_OK) {
            cytadel_target_list_set_err(err_buf, err_buf_len, "%s", file_err);
            status = CYTADEL_TARGET_LIST_ERR_FILE;
        } else {
            for (size_t i = 0; i < file_lines.count; i++) {
                const char *line = file_lines.lines[i];
                status = cytadel_target_list_expand_token(line, strlen(line), &arr, &total, err_buf,
                                                            err_buf_len);
                if (status != CYTADEL_TARGET_LIST_OK) {
                    break;
                }
            }
            cytadel_targets_file_lines_free(&file_lines);
        }
    }

    if (status != CYTADEL_TARGET_LIST_OK) {
        cytadel_target_dynarray_free(&arr);
        return status;
    }

    if (total == 0) {
        cytadel_target_dynarray_free(&arr);
        cytadel_target_list_set_err(err_buf, err_buf_len,
                                     "target spec / targets-file produced zero targets");
        return CYTADEL_TARGET_LIST_ERR_EMPTY;
    }

    status = cytadel_target_list_dedup(&arr, err_buf, err_buf_len);
    if (status != CYTADEL_TARGET_LIST_OK) {
        cytadel_target_dynarray_free(&arr);
        return status;
    }

    /* Shrink the backing allocation to the deduplicated size. Shrinking
     * realloc() is not expected to fail, but if it somehow does, the
     * original (larger) block is still valid per the C standard -- fall
     * back to using it as-is rather than leaking or erroring out. */
    if (arr.count > 0 && arr.count < arr.capacity) {
        cytadel_target_t *shrunk = realloc(arr.items, arr.count * sizeof(cytadel_target_t));
        if (shrunk != NULL) {
            arr.items = shrunk;
        }
    }

    out_list->targets = arr.items;
    out_list->count = arr.count;
    return CYTADEL_TARGET_LIST_OK;
}

void cytadel_target_list_free(cytadel_target_list_t *list) {
    if (list == NULL) {
        return;
    }
    free(list->targets);
    list->targets = NULL;
    list->count = 0;
}
