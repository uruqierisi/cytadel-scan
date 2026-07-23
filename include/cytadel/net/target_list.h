#ifndef CYTADEL_NET_TARGET_LIST_H
#define CYTADEL_NET_TARGET_LIST_H

#include <stddef.h>

#include "cytadel/net/target.h"

/* Multi-target expansion (Milestone 3) -- builds on top of target.h's
 * single-spec parser rather than replacing it. Accepts:
 *
 *   - a single literal/hostname, exactly what target.h already parses
 *     ("10.0.0.1", "example.com")
 *   - an IPv4 CIDR block ("10.0.0.0/24") -- expanded via cidr.h. Every
 *     address in the block is scanned, network/broadcast addresses
 *     included, for every prefix (see cidr.h's header comment for the
 *     full rationale); /32 (one host) and /31 (RFC 3021, two hosts) fall
 *     out of the same rule with no special-casing.
 *   - a comma-separated list mixing any of the above
 *     ("10.0.0.1,10.0.0.0/30,example.com")
 *   - a --targets-file (one spec per line, '#' comments, blank lines
 *     skipped -- see targets_file.h), combined with the comma-separated
 *     spec if both are given
 *
 * The combined result is de-duplicated by resolved IPv4 address (so
 * "127.0.0.1,localhost" -- two different spellings of the same host --
 * yields exactly one target) and hard-capped at CYTADEL_MAX_TARGETS total
 * hosts. The cap is enforced *before* an oversized block is expanded
 * (using cidr.h's uint64_t host-count math), so a spec like "10.0.0.0/8"
 * is rejected immediately rather than ever materializing 16 million
 * addresses. */

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on the total number of hosts one invocation will expand to,
 * across every spec + targets-file entry combined. Overridable at build
 * time (-DCYTADEL_MAX_TARGETS=...) for anyone who deliberately wants a
 * different ceiling; 65536 (a /16) is a generous default for a single
 * scan run without ever accidentally trying to scan, say, a /8. */
#ifndef CYTADEL_MAX_TARGETS
#define CYTADEL_MAX_TARGETS 65536
#endif

typedef enum {
    CYTADEL_TARGET_LIST_OK = 0,
    CYTADEL_TARGET_LIST_ERR_INVALID,   /* malformed token (bad IPv4/CIDR/hostname syntax) */
    CYTADEL_TARGET_LIST_ERR_RESOLVE,   /* a hostname token failed DNS resolution */
    CYTADEL_TARGET_LIST_ERR_TOO_MANY,  /* would exceed CYTADEL_MAX_TARGETS */
    CYTADEL_TARGET_LIST_ERR_EMPTY,     /* spec + targets-file together produced zero targets */
    CYTADEL_TARGET_LIST_ERR_FILE,      /* --targets-file could not be opened/read */
    CYTADEL_TARGET_LIST_ERR_ALLOC
} cytadel_target_list_status_t;

typedef struct {
    cytadel_target_t *targets; /* heap array, owned by this struct */
    size_t count;
} cytadel_target_list_t;

/* Parses and expands `spec` (may be NULL/empty if targets_file_path
 * supplies at least one target) and/or `targets_file_path` (may be
 * NULL/empty if spec supplies at least one target) into *out_list. At
 * least one of the two must be given and must together yield at least one
 * target, or CYTADEL_TARGET_LIST_ERR_EMPTY is returned.
 *
 * On any non-OK status, a human-readable message is written into err_buf
 * (bounds-checked, always NUL-terminated; err_buf/err_buf_len == 0 is safe
 * to skip the message) and *out_list is left unmodified.
 *
 * On CYTADEL_TARGET_LIST_OK, the caller owns *out_list and must release it
 * via cytadel_target_list_free() exactly once. */
cytadel_target_list_status_t cytadel_target_list_parse(const char *spec,
                                                          const char *targets_file_path,
                                                          cytadel_target_list_t *out_list,
                                                          char *err_buf, size_t err_buf_len);

/* Frees list->targets (if any) and zeroes the struct. Safe to call on an
 * already-freed/zeroed list (idempotent) and on a NULL pointer (no-op). */
void cytadel_target_list_free(cytadel_target_list_t *list);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TARGET_LIST_H */
