#ifndef CYTADEL_NET_PORT_RANGE_H
#define CYTADEL_NET_PORT_RANGE_H

#include <stddef.h>
#include <stdint.h>

/* Parses the `--ports` CLI flag's grammar:
 *   "22"              a single port
 *   "1-1024"          an inclusive range
 *   "22,80,443"       a comma-separated list of ports and/or ranges
 *   "1-100,8080"      a mix of both
 *
 * Milestone 2 default (documented in cli_args.h's usage text and here):
 * CYTADEL_DEFAULT_PORT_SPEC, the well-known/system port range 1-1024. */

#ifdef __cplusplus
extern "C" {
#endif

#define CYTADEL_PORT_MIN 1
#define CYTADEL_PORT_MAX 65535

#define CYTADEL_DEFAULT_PORT_SPEC "1-1024"

/* Hard cap on the raw spec string length, independent of how many distinct
 * ports it ultimately de-duplicates to -- guards against a pathological
 * spec (e.g. thousands of repeated comma-separated tokens) burning parse
 * time before de-duplication ever runs. Generous for any legitimate spec:
 * every one of the 65535 possible ports fits in "1,2,3,...,65535" many
 * times over within this budget is not required since ranges are used for
 * bulk selection; a spec this long is definitionally malformed/abusive. */
#define CYTADEL_PORT_SPEC_MAX_LEN 8192

/* Cap on the number of comma-separated tokens in one spec. */
#define CYTADEL_PORT_SPEC_MAX_TOKENS 4096

typedef enum {
    CYTADEL_PORT_RANGE_OK = 0,
    CYTADEL_PORT_RANGE_ERR_MALFORMED,     /* syntax error, or spec/token too long */
    CYTADEL_PORT_RANGE_ERR_OUT_OF_BOUNDS, /* a port or range endpoint outside 1-65535 */
    CYTADEL_PORT_RANGE_ERR_EMPTY,         /* spec parsed but selected zero ports */
    CYTADEL_PORT_RANGE_ERR_TOO_MANY,      /* more than CYTADEL_PORT_SPEC_MAX_TOKENS tokens */
    CYTADEL_PORT_RANGE_ERR_ALLOC          /* out of memory while building the result */
} cytadel_port_range_status_t;

typedef struct {
    uint16_t *ports; /* heap array, owned by this struct, ascending, de-duplicated */
    size_t count;
} cytadel_port_list_t;

/* Parses `spec` into *out_list (ascending, de-duplicated port numbers).
 * On any non-OK status, a human-readable message is written into err_buf
 * (bounds-checked, always NUL-terminated; err_buf/err_buf_len == 0 is
 * safe to skip the message) and *out_list is left unmodified.
 *
 * On CYTADEL_PORT_RANGE_OK, the caller owns *out_list and must release it
 * via cytadel_port_list_free() exactly once. */
cytadel_port_range_status_t cytadel_port_range_parse(const char *spec,
                                                       cytadel_port_list_t *out_list,
                                                       char *err_buf, size_t err_buf_len);

/* Frees list->ports (if any) and zeroes the struct. Safe to call on an
 * already-freed/zeroed list (idempotent) and on a NULL pointer (no-op). */
void cytadel_port_list_free(cytadel_port_list_t *list);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_PORT_RANGE_H */
