#ifndef CYTADEL_NET_SVC_FTP_H
#define CYTADEL_NET_SVC_FTP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* FTP greeting parser (Milestone 4, kb-schema.md §7.4). Kept private to
 * src/net (same-directory quote-include). */

#ifdef __cplusplus
extern "C" {
#endif

/* Writes FTP/<port>/banner (the first line of `banner`, sans trailing
 * CR/LF) and Services/ftp/<port>, and attempts a CPE mapping (cpe_map.c)
 * from that same line. Every scan below is bounds-checked against
 * banner_len; never reads past it. Returns false (writes nothing) if
 * banner_len is 0 or the first line is empty -- an empty/garbage
 * connection response is not evidence of an FTP service. Returns true
 * otherwise. Callers decide WHEN to call this (port == 21 is the
 * authoritative signal this milestone uses; see service_detect.c) --
 * this function itself does not inspect `port` beyond using it to build
 * key names. */
bool cytadel_svc_ftp_detect(cytadel_kb_t *kb, uint16_t port, const char *banner, size_t banner_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_SVC_FTP_H */
