#ifndef CYTADEL_NET_SVC_SSH_H
#define CYTADEL_NET_SVC_SSH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* SSH banner parser (Milestone 4, kb-schema.md §7.4). RFC 4253 §4.2 format:
 * "SSH-" <protoversion> "-" <softwareversion> [SP <comments>] CR LF. Kept
 * private to src/net (same-directory quote-include). */

#ifdef __cplusplus
extern "C" {
#endif

/* If `banner` (exactly `banner_len` bytes, need not be NUL-terminated)
 * begins with "SSH-" and parses as a well-formed SSH identification
 * string, writes SSH/<port>/version (the full identification string, sans
 * trailing CR/LF) and SSH/<port>/protocol (just the protoversion field,
 * e.g. "2.0"), writes Services/ssh/<port>, and attempts a CPE mapping
 * (cpe_map.c) from the software-version/comments portion. Every scan below
 * is bounds-checked against banner_len; a truncated/malformed banner (e.g.
 * a fake "SSH-" prefix with no second '-') is handled by returning false
 * without writing anything, never by reading past banner_len. Returns
 * true iff this was recognized as an SSH banner (regardless of whether the
 * CPE mapping succeeded). */
bool cytadel_svc_ssh_detect(cytadel_kb_t *kb, uint16_t port, const char *banner, size_t banner_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SVC_SSH_H */
