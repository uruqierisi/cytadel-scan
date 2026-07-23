#ifndef CYTADEL_NET_CIDR_H
#define CYTADEL_NET_CIDR_H

#include <stddef.h>
#include <stdint.h>

/* IPv4 CIDR block parsing + address math (Milestone 3). One token of the
 * multi-target grammar owned by target_list.h -- this module only knows
 * about "A.B.C.D/N" syntax and integer address arithmetic; it has no idea
 * about hostnames, comma lists, or files.
 *
 * Policy (documented here, in target_list.h, and in --help): a CIDR block
 * expands to *every* address in the block, for every prefix 0-32 --
 * network and broadcast addresses (for prefixes <= 30, which have a
 * distinct network/broadcast address) are included, not skipped. This
 * matches common scanner behavior (e.g. nmap's default) and keeps the
 * expansion rule uniform across every prefix length, including the /31
 * (RFC 3021 point-to-point, 2 usable addresses, no network/broadcast
 * concept) and /32 (single host) edge cases -- both fall out of the same
 * "host_count = 2^(32-prefix), scan every one of them" rule without any
 * special-casing. */

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CYTADEL_CIDR_OK = 0,
    CYTADEL_CIDR_ERR_MALFORMED,    /* not "A.B.C.D/N" syntax (missing/extra '/') */
    CYTADEL_CIDR_ERR_BAD_ADDRESS,  /* the "A.B.C.D" part is not a valid IPv4 literal */
    CYTADEL_CIDR_ERR_BAD_PREFIX    /* the "N" part is not a decimal integer in 0-32 */
} cytadel_cidr_status_t;

typedef struct {
    uint32_t network; /* base address, host byte order, masked to `prefix` bits */
    int prefix;        /* 0-32 */
} cytadel_cidr_t;

/* Parses `spec` (a NUL-terminated "A.B.C.D/N" string) into *out. On any
 * non-OK status, a human-readable message is written into err_buf
 * (bounds-checked, always NUL-terminated; err_buf/err_buf_len == 0 is safe
 * to skip the message) and *out is left unmodified. Never allocates. */
cytadel_cidr_status_t cytadel_cidr_parse(const char *spec, cytadel_cidr_t *out,
                                          char *err_buf, size_t err_buf_len);

/* Number of addresses in the block: 2^(32-prefix). Computed in a 64-bit
 * type specifically so a /0 (2^32 addresses) is representable without
 * overflow and so the caller can compare it against a target-count cap
 * *before* looping/allocating -- this is what lets target_list.c reject an
 * oversized block (e.g. a /8) immediately instead of ever materializing
 * millions of addresses. Returns 0 if cidr is NULL or cidr->prefix is
 * outside 0-32 (defensive; cytadel_cidr_parse() never produces such a
 * value). */
uint64_t cytadel_cidr_host_count(const cytadel_cidr_t *cidr);

/* Writes the dotted-quad IPv4 literal for the n-th address (0-indexed) in
 * the block into buf (must be at least CYTADEL_NET_IP_STR_MAX bytes;
 * see scan_types.h). n must be < cytadel_cidr_host_count(cidr) -- address
 * 0 is the block's base/network address, address (host_count - 1) is its
 * last/broadcast address (both included -- see the policy note above).
 * Returns 0 on success, -1 on any invalid argument (cidr/buf NULL, buf_len
 * too small, n out of range). */
int cytadel_cidr_nth_address(const cytadel_cidr_t *cidr, uint64_t n, char *buf, size_t buf_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_CIDR_H */
