#include "cytadel/kb/kb.h"

#include <stdlib.h>
#include <string.h>

#include "kb_validate.h"
#include "log.h"

/* See include/cytadel/kb/kb.h's top-of-file comment for the concurrency
 * model this implementation relies on: exactly one thread touches a given
 * cytadel_kb_t at a time in Milestone 4, so this file has NO internal
 * locking. Do not add cross-host sharing of a single cytadel_kb_t without
 * revisiting that assumption first. */

/* Chained hash table. Grows (doubles) when the load factor would exceed
 * 3/4 on the next insert -- simple and correct; a single host's KB holds
 * at most a few hundred entries (ports/services/banners/TLS facts for one
 * target), so neither the initial size nor the growth policy needs to be
 * clever. */
#define CYTADEL_KB_INITIAL_BUCKETS 64

typedef struct cytadel_kb_entry {
    char *key; /* owned, NUL-terminated, already validated (SS2) */
    cytadel_kb_type_t type;
    union {
        char *str; /* owned, NUL-terminated, already validated (SS3) */
        int64_t i64;
        bool b;
    } v;
    struct cytadel_kb_entry *next;
} cytadel_kb_entry_t;

struct cytadel_kb {
    cytadel_kb_entry_t **buckets;
    size_t bucket_count;
    size_t entry_count;
};

/* FNV-1a, 64-bit. Simple, fast, dependency-free, and more than adequate
 * for a per-host in-memory table with at most a few hundred entries --
 * this is not a security boundary (kb-schema.md keys are engine/plugin
 * generated, not attacker-supplied hash-flooding input). */
static uint64_t cytadel_kb_hash(const char *s, size_t len) {
    uint64_t h = 1469598103934665603ULL; /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        h ^= (unsigned char)s[i];
        h *= 1099511628211ULL; /* FNV prime */
    }
    return h;
}

static cytadel_kb_entry_t *cytadel_kb_find(const cytadel_kb_t *kb, const char *key) {
    size_t key_len = strlen(key);
    size_t idx = (size_t)(cytadel_kb_hash(key, key_len) % kb->bucket_count);
    for (cytadel_kb_entry_t *e = kb->buckets[idx]; e != NULL; e = e->next) {
        if (strcmp(e->key, key) == 0) {
            return e;
        }
    }
    return NULL;
}

/* Best-effort: doubles bucket_count when the next insert would push the
 * load factor above 3/4. On allocation failure the table is left exactly
 * as it was (still fully valid, just not grown) and this returns false --
 * callers treat that as "proceed with the insert anyway, just at a worse
 * load factor," never as a set failure. Growing the table is a
 * performance concern, not a correctness one. */
static bool cytadel_kb_grow_if_needed(cytadel_kb_t *kb) {
    if ((kb->entry_count + 1) * 4 <= kb->bucket_count * 3) {
        return true; /* still under 75% load after the pending insert */
    }

    size_t new_count = kb->bucket_count * 2;
    if (new_count <= kb->bucket_count) {
        return false; /* overflow guard; effectively unreachable in practice */
    }

    cytadel_kb_entry_t **new_buckets = calloc(new_count, sizeof(*new_buckets));
    if (new_buckets == NULL) {
        cytadel_log_warn("kb: out of memory growing hash table past %zu bucket(s); "
                          "continuing at current size",
                          kb->bucket_count);
        return false;
    }

    for (size_t i = 0; i < kb->bucket_count; i++) {
        cytadel_kb_entry_t *e = kb->buckets[i];
        while (e != NULL) {
            cytadel_kb_entry_t *next = e->next;
            size_t idx = (size_t)(cytadel_kb_hash(e->key, strlen(e->key)) % new_count);
            e->next = new_buckets[idx];
            new_buckets[idx] = e;
            e = next;
        }
    }

    free(kb->buckets);
    kb->buckets = new_buckets;
    kb->bucket_count = new_count;
    return true;
}

/* Allocates and inserts a brand-new entry for `key` (caller guarantees no
 * entry for this key already exists). The entry's type/value are left
 * zeroed (CYTADEL_KB_TYPE_STRING / NULL str) -- the caller overwrites both
 * immediately after this returns. Returns NULL (logging the failure) on
 * any allocation failure; the table is left consistent either way (no
 * partially-linked entry on a failure path). */
static cytadel_kb_entry_t *cytadel_kb_insert_new(cytadel_kb_t *kb, const char *key) {
    size_t key_len = strlen(key);

    cytadel_kb_entry_t *e = calloc(1, sizeof(*e));
    if (e == NULL) {
        cytadel_log_error("kb: out of memory allocating entry for key '%s'", key);
        return NULL;
    }

    e->key = malloc(key_len + 1);
    if (e->key == NULL) {
        cytadel_log_error("kb: out of memory copying key '%s'", key);
        free(e);
        return NULL;
    }
    memcpy(e->key, key, key_len);
    e->key[key_len] = '\0';

    /* Best-effort growth before linking the new entry in -- growing after
     * would require re-finding this entry's bucket anyway, so do it first
     * and compute the final bucket index once. */
    (void)cytadel_kb_grow_if_needed(kb);

    size_t idx = (size_t)(cytadel_kb_hash(e->key, key_len) % kb->bucket_count);
    e->next = kb->buckets[idx];
    kb->buckets[idx] = e;
    kb->entry_count++;
    return e;
}

cytadel_kb_t *cytadel_kb_create(void) {
    cytadel_kb_t *kb = malloc(sizeof(*kb));
    if (kb == NULL) {
        cytadel_log_error("kb: out of memory allocating KB");
        return NULL;
    }

    kb->bucket_count = CYTADEL_KB_INITIAL_BUCKETS;
    kb->buckets = calloc(kb->bucket_count, sizeof(*kb->buckets));
    if (kb->buckets == NULL) {
        cytadel_log_error("kb: out of memory allocating %zu initial bucket(s)", kb->bucket_count);
        free(kb);
        return NULL;
    }
    kb->entry_count = 0;
    return kb;
}

void cytadel_kb_free(cytadel_kb_t *kb) {
    if (kb == NULL) {
        return;
    }

    for (size_t i = 0; i < kb->bucket_count; i++) {
        cytadel_kb_entry_t *e = kb->buckets[i];
        while (e != NULL) {
            cytadel_kb_entry_t *next = e->next;
            if (e->type == CYTADEL_KB_TYPE_STRING) {
                free(e->v.str);
            }
            free(e->key);
            free(e);
            e = next;
        }
        kb->buckets[i] = NULL;
    }

    free(kb->buckets);
    kb->buckets = NULL;
    free(kb);
}

bool cytadel_kb_key_is_valid(const char *key) {
    return cytadel_kb_validate_key(key);
}

int cytadel_kb_set_str_n(cytadel_kb_t *kb, const char *key, const char *value, size_t value_len) {
    if (kb == NULL) {
        cytadel_log_warn("kb: rejected set on key '%s': KB is NULL", key ? key : "(null)");
        return -1;
    }
    if (!cytadel_kb_validate_key(key)) {
        cytadel_log_warn("kb: rejected set: invalid key '%s'", key ? key : "(null)");
        return -1;
    }
    if (value == NULL) {
        cytadel_log_warn("kb: rejected set on key '%s': value is NULL", key);
        return -1;
    }
    if (value_len > CYTADEL_KB_VALUE_MAX_LEN) {
        cytadel_log_warn("kb: rejected set on key '%s': value is %zu bytes (max %d)", key,
                          value_len, CYTADEL_KB_VALUE_MAX_LEN);
        return -1;
    }
    if (!cytadel_kb_validate_no_embedded_nul(value, value_len)) {
        cytadel_log_warn("kb: rejected set on key '%s': value contains an embedded NUL", key);
        return -1;
    }
    if (!cytadel_kb_validate_utf8(value, value_len)) {
        cytadel_log_warn("kb: rejected set on key '%s': value is not valid UTF-8", key);
        return -1;
    }

    /* Build the new value fully before touching the table: if this
     * allocation fails, the table (and any pre-existing value for `key`)
     * is left completely untouched -- no partial mutation on an OOM
     * path. */
    char *copy = malloc(value_len + 1);
    if (copy == NULL) {
        cytadel_log_error("kb: out of memory copying %zu-byte value for key '%s'", value_len, key);
        return -1;
    }
    memcpy(copy, value, value_len);
    copy[value_len] = '\0';

    cytadel_kb_entry_t *entry = cytadel_kb_find(kb, key);
    if (entry == NULL) {
        entry = cytadel_kb_insert_new(kb, key);
        if (entry == NULL) {
            free(copy);
            return -1;
        }
    } else if (entry->type == CYTADEL_KB_TYPE_STRING) {
        free(entry->v.str);
    }

    entry->type = CYTADEL_KB_TYPE_STRING;
    entry->v.str = copy;
    return 0;
}

int cytadel_kb_set_str(cytadel_kb_t *kb, const char *key, const char *value) {
    if (value == NULL) {
        cytadel_log_warn("kb: rejected set on key '%s': value is NULL", key ? key : "(null)");
        return -1;
    }
    return cytadel_kb_set_str_n(kb, key, value, strlen(value));
}

int cytadel_kb_set_int(cytadel_kb_t *kb, const char *key, int64_t value) {
    if (kb == NULL) {
        cytadel_log_warn("kb: rejected set on key '%s': KB is NULL", key ? key : "(null)");
        return -1;
    }
    if (!cytadel_kb_validate_key(key)) {
        cytadel_log_warn("kb: rejected set: invalid key '%s'", key ? key : "(null)");
        return -1;
    }

    cytadel_kb_entry_t *entry = cytadel_kb_find(kb, key);
    if (entry == NULL) {
        entry = cytadel_kb_insert_new(kb, key);
        if (entry == NULL) {
            return -1;
        }
    } else if (entry->type == CYTADEL_KB_TYPE_STRING) {
        free(entry->v.str);
        entry->v.str = NULL;
    }

    entry->type = CYTADEL_KB_TYPE_INT;
    entry->v.i64 = value;
    return 0;
}

int cytadel_kb_set_bool(cytadel_kb_t *kb, const char *key, bool value) {
    if (kb == NULL) {
        cytadel_log_warn("kb: rejected set on key '%s': KB is NULL", key ? key : "(null)");
        return -1;
    }
    if (!cytadel_kb_validate_key(key)) {
        cytadel_log_warn("kb: rejected set: invalid key '%s'", key ? key : "(null)");
        return -1;
    }

    cytadel_kb_entry_t *entry = cytadel_kb_find(kb, key);
    if (entry == NULL) {
        entry = cytadel_kb_insert_new(kb, key);
        if (entry == NULL) {
            return -1;
        }
    } else if (entry->type == CYTADEL_KB_TYPE_STRING) {
        free(entry->v.str);
        entry->v.str = NULL;
    }

    entry->type = CYTADEL_KB_TYPE_BOOL;
    entry->v.b = value;
    return 0;
}

cytadel_kb_get_status_t cytadel_kb_get(const cytadel_kb_t *kb, const char *key,
                                        cytadel_kb_value_t *out_value) {
    if (out_value != NULL) {
        memset(out_value, 0, sizeof(*out_value));
    }
    if (kb == NULL || key == NULL || out_value == NULL) {
        cytadel_log_error("kb: get() called with a NULL kb, key, or out_value");
        return CYTADEL_KB_GET_INVALID_KEY;
    }
    if (!cytadel_kb_validate_key(key)) {
        cytadel_log_error("kb: get() on invalid key '%s'", key);
        return CYTADEL_KB_GET_INVALID_KEY;
    }

    cytadel_kb_entry_t *entry = cytadel_kb_find(kb, key);
    if (entry == NULL) {
        return CYTADEL_KB_GET_NOT_FOUND;
    }

    out_value->type = entry->type;
    switch (entry->type) {
        case CYTADEL_KB_TYPE_STRING: out_value->v.str = entry->v.str; break;
        case CYTADEL_KB_TYPE_INT:    out_value->v.i64 = entry->v.i64; break;
        case CYTADEL_KB_TYPE_BOOL:   out_value->v.b   = entry->v.b;   break;
    }
    return CYTADEL_KB_GET_FOUND;
}

const char *cytadel_kb_get_str(const cytadel_kb_t *kb, const char *key) {
    cytadel_kb_value_t value;
    if (cytadel_kb_get(kb, key, &value) != CYTADEL_KB_GET_FOUND) {
        return NULL;
    }
    if (value.type != CYTADEL_KB_TYPE_STRING) {
        return NULL;
    }
    return value.v.str;
}

void cytadel_kb_foreach(const cytadel_kb_t *kb, cytadel_kb_iter_fn fn, void *user_data) {
    if (kb == NULL || fn == NULL) {
        return;
    }

    for (size_t i = 0; i < kb->bucket_count; i++) {
        for (cytadel_kb_entry_t *e = kb->buckets[i]; e != NULL; e = e->next) {
            cytadel_kb_value_t value;
            value.type = e->type;
            switch (e->type) {
                case CYTADEL_KB_TYPE_STRING: value.v.str = e->v.str; break;
                case CYTADEL_KB_TYPE_INT:    value.v.i64 = e->v.i64; break;
                case CYTADEL_KB_TYPE_BOOL:   value.v.b   = e->v.b;   break;
            }
            fn(e->key, &value, user_data);
        }
    }
}

size_t cytadel_kb_count(const cytadel_kb_t *kb) {
    return (kb != NULL) ? kb->entry_count : 0;
}
