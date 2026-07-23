#ifndef CYTADEL_KB_KB_H
#define CYTADEL_KB_KB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* In-memory, per-host knowledge-base (KB) store (Milestone 4).
 *
 * This is the first code realization of docs/contracts/kb-schema.md (FROZEN
 * CONTRACT) -- every constant, validation rule, and semantic below is taken
 * directly from that document; where this header has a comment citing a
 * section number ("kb-schema.md SS4"), that section is the authoritative
 * source and this is just the C encoding of it.
 *
 * Design canon (kb-schema.md SS1):
 *   - One KB instance per scanned host.
 *   - Three value types only: string | int64 | bool. No composite types --
 *     lists are flattened into multiple keys or a single comma-joined
 *     string (kb-schema.md SS3).
 *   - The KB stores facts, never findings/severity -- that is the plugin
 *     API's report_vuln()/security_report() concern (Milestone 5+), not
 *     this store's.
 *
 * Concurrency / ownership model (kb-schema.md SS6, restated here so future
 * milestones do not have to re-derive it from the contract):
 *   - Exactly one worker thread owns exactly one host's KB for the
 *     duration of that host's scan (docs/build-plan.md's fixed-size worker
 *     pool, src/core/worker_pool.c). Hosts never share a KB, so there is
 *     no cross-host contention.
 *   - Milestone 4 schedules all writers for one host's KB (host-discovery,
 *     port-scanner, service-detection, tls-inspector, "engine") purely
 *     sequentially on that host's single worker thread -- no plugin
 *     scheduler exists yet to run anything concurrently against the same
 *     KB. The engine's future report generator also only reads a host's KB
 *     strictly after that host's scan/plugin schedule has completed.
 *   - THEREFORE: this implementation deliberately carries NO internal
 *     mutex/lock. This is safe today only because of the single-writer-
 *     thread invariant above. kb-schema.md SS6 is explicit that "If a
 *     future milestone introduces intra-host plugin parallelism, the KB
 *     store implementation must add a mutex around its hash table at that
 *     point." Whoever adds Milestone 5+ intra-host plugin concurrency MUST
 *     revisit this file and add locking before relaxing the "one thread
 *     touches this KB at a time" assumption -- do not assume thread-safety
 *     from the type name alone.
 *
 * Ownership model (kb-schema.md SS3): the KB is the sole owner of every
 * key and value it stores. cytadel_kb_set_*() copies the key and value in;
 * callers retain ownership of (and may free/reuse) whatever buffer they
 * passed in immediately after the call returns. cytadel_kb_get() copies
 * scalar values (int64/bool) out by value; for strings it hands back a
 * borrowed `const char *` pointer into KB-owned storage -- see
 * cytadel_kb_value_t's field comment below for that pointer's exact
 * validity window. Callers must never free it.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* kb-schema.md SS2: "Maximum key length: 255 bytes total." Does not
 * include the NUL terminator -- a caller's key buffer must be at least
 * CYTADEL_KB_KEY_MAX_LEN + 1 bytes to safely hold the longest legal key. */
#define CYTADEL_KB_KEY_MAX_LEN 255

/* kb-schema.md SS3: "Max length 4096 bytes (CYTADEL_KB_VALUE_MAX_LEN)."
 * Does not include the NUL terminator. */
#define CYTADEL_KB_VALUE_MAX_LEN 4096

typedef struct cytadel_kb cytadel_kb_t;

/* kb-schema.md SS3's three-way value type system. Never conflate
 * CYTADEL_KB_TYPE_BOOL with CYTADEL_KB_TYPE_INT -- a reader asking for a
 * bool must get a real bool, not a 0/1 int (mirrors the Lua-side
 * true/false vs. integer distinction the contract requires). */
typedef enum {
    CYTADEL_KB_TYPE_STRING = 0,
    CYTADEL_KB_TYPE_INT    = 1,
    CYTADEL_KB_TYPE_BOOL   = 2
} cytadel_kb_type_t;

/* Tagged union returned by cytadel_kb_get(). Only the union member
 * matching `type` is meaningful. */
typedef struct {
    cytadel_kb_type_t type;
    union {
        /* Borrowed pointer into KB-owned storage for this key. Valid until
         * the next cytadel_kb_set_*() call that overwrites THIS SAME key,
         * or until cytadel_kb_free() is called on this KB -- whichever
         * comes first (kb-schema.md SS4: "last-write-wins"). Never free
         * this pointer; never retain it past either of those events. If
         * the caller needs the string to outlive that window, it must
         * copy it out immediately. */
        const char *str;
        int64_t i64;
        bool b;
    } v;
} cytadel_kb_value_t;

/* Result of a cytadel_kb_get() lookup. Mirrors kb-schema.md SS4's
 * absent-key semantics: an unwritten key is a normal, expected outcome
 * (the C analogue of Lua nil) -- not an error. */
typedef enum {
    CYTADEL_KB_GET_FOUND       = 0,
    CYTADEL_KB_GET_NOT_FOUND   = 1,
    /* kb-schema.md SS4: "get_kb_item(key) on a syntactically invalid key
     * ... is a plugin bug; the engine logs an error and returns nil rather
     * than aborting the whole scan." CYTADEL_KB_GET_INVALID_KEY is the C
     * signal for that same case; callers should treat it like NOT_FOUND
     * (a WARN/ERROR is already logged internally -- callers do not need to
     * log again). */
    CYTADEL_KB_GET_INVALID_KEY = 2
} cytadel_kb_get_status_t;

/* Allocates a new, empty KB. Returns NULL on allocation failure (the
 * caller must check this -- every allocation in this codebase is
 * checked). The returned KB must be released exactly once via
 * cytadel_kb_free(). */
cytadel_kb_t *cytadel_kb_create(void);

/* Frees every key/value this KB owns, then the KB itself. Safe to call
 * with kb == NULL (no-op), matching the free-function idiom used
 * elsewhere in this codebase (e.g. cytadel_host_result_free()). Not safe
 * to call twice on the same non-NULL pointer (ordinary free() semantics;
 * callers set their pointer to NULL after calling this, same discipline
 * as the rest of the codebase). */
void cytadel_kb_free(cytadel_kb_t *kb);

/* kb-schema.md SS2's key-naming rules, exposed publicly so callers (and
 * tests) can pre-validate a key without attempting a set. A key is one or
 * more '/'-delimited segments; each segment's charset is
 * [A-Za-z0-9_.-]+; no leading/trailing/empty segment ("//" is invalid, as
 * is a leading or trailing '/'); case-sensitive; at most
 * CYTADEL_KB_KEY_MAX_LEN bytes total. Returns true iff `key` is non-NULL
 * and satisfies every rule above. */
bool cytadel_kb_key_is_valid(const char *key);

/* Stores a NUL-terminated string value under `key`, overwriting any prior
 * value for that key (kb-schema.md SS4: last-write-wins). `value` is
 * copied in full (cytadel_kb_set_str_n() below with strlen(value)) -- the
 * caller retains ownership of `value` and may free/reuse it immediately
 * after this call returns.
 *
 * Rejected, not truncated (kb-schema.md SS3/SS4), on any of: `kb` is
 * NULL, `key` fails cytadel_kb_key_is_valid(), `value` is NULL,
 * strlen(value) > CYTADEL_KB_VALUE_MAX_LEN, or `value` is not valid UTF-8.
 * A rejection logs a WARN (per SS3/SS4's "set_kb_item ... logs a warning
 * via the engine logger") and stores nothing.
 *
 * Returns 0 on success, -1 on rejection or allocation failure. */
int cytadel_kb_set_str(cytadel_kb_t *kb, const char *key, const char *value);

/* Same as cytadel_kb_set_str(), but takes an explicit byte length instead
 * of relying on strlen(). This is the primitive cytadel_kb_set_str() is
 * built on, and is also the entry point any future length-prefixed caller
 * (e.g. a Lua binding, where Lua strings are length-prefixed and may
 * legally contain embedded NUL bytes) must use to get kb-schema.md SS3's
 * "no embedded NUL" rule enforced -- a plain NUL-terminated `const char *`
 * cannot represent an embedded NUL for cytadel_kb_set_str() to reject in
 * the first place. Rejects (returns -1, logs WARN, stores nothing) if any
 * byte in value[0..value_len) is 0x00, in addition to every rejection
 * reason cytadel_kb_set_str() documents. */
int cytadel_kb_set_str_n(cytadel_kb_t *kb, const char *key, const char *value, size_t value_len);

/* Stores an int64 value under `key`. Same rejection/overwrite/WARN
 * semantics as cytadel_kb_set_str() (minus any value-content validation --
 * every int64_t value is representable). Returns 0 on success, -1 on
 * rejection (invalid key) or allocation failure. */
int cytadel_kb_set_int(cytadel_kb_t *kb, const char *key, int64_t value);

/* Stores a bool value under `key`. Same rejection/overwrite/WARN semantics
 * as cytadel_kb_set_str(). Returns 0 on success, -1 on rejection (invalid
 * key) or allocation failure. */
int cytadel_kb_set_bool(cytadel_kb_t *kb, const char *key, bool value);

/* Looks up `key`. On CYTADEL_KB_GET_FOUND, *out_value is populated (see
 * cytadel_kb_value_t's field comments for the string-pointer validity
 * window); on CYTADEL_KB_GET_NOT_FOUND or CYTADEL_KB_GET_INVALID_KEY,
 * *out_value is zeroed and must not be read. `kb`/`key`/`out_value` must
 * all be non-NULL; passing NULL for any of them is treated the same as an
 * invalid key (CYTADEL_KB_GET_INVALID_KEY) -- it is always a caller bug,
 * never a valid "absent" query. */
cytadel_kb_get_status_t cytadel_kb_get(const cytadel_kb_t *kb, const char *key,
                                        cytadel_kb_value_t *out_value);

/* Convenience wrapper over cytadel_kb_get() for the extremely common
 * "read a string I expect to be there, or treat it as absent" pattern
 * used throughout src/net's service-detection/TLS-inspection code and by
 * tests. Returns the same borrowed pointer cytadel_kb_get() would via
 * out_value->v.str (same validity window -- see cytadel_kb_value_t), or
 * NULL if the key is absent, invalid, or stores a non-string type. */
const char *cytadel_kb_get_str(const cytadel_kb_t *kb, const char *key);

/* Callback invoked once per stored entry by cytadel_kb_foreach() below.
 * `key` and `value` are borrowed for the duration of this call only (same
 * validity rules as cytadel_kb_get()'s out_value) -- do not retain either
 * pointer past the callback returning. */
typedef void (*cytadel_kb_iter_fn)(const char *key, const cytadel_kb_value_t *value,
                                    void *user_data);

/* Enumerates every key/value currently stored in `kb`, calling `fn` once
 * per entry with `user_data` forwarded unchanged. Iteration order is
 * unspecified (this is a hash table, not an insertion-ordered structure)
 * -- callers that need a specific order (e.g. the future M8 report layer)
 * must sort after collecting, not rely on this call's order. Read-only:
 * never mutates `kb`, safe to call from multiple threads only if no
 * writer thread is concurrently touching this same `kb` (see this
 * header's top-of-file concurrency note -- the whole KB has no internal
 * locking in Milestone 4). No-op if kb or fn is NULL. */
void cytadel_kb_foreach(const cytadel_kb_t *kb, cytadel_kb_iter_fn fn, void *user_data);

/* Number of entries currently stored in `kb`. Returns 0 if kb is NULL. */
size_t cytadel_kb_count(const cytadel_kb_t *kb);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_KB_KB_H */
