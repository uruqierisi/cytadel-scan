#ifndef CYTADEL_NET_BANNER_GRAB_H
#define CYTADEL_NET_BANNER_GRAB_H

#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* Generic banner grab primitive (Milestone 4, kb-schema.md §7.4): connect
 * to ip:port, then passively read whatever the server sends first (an SSH/
 * FTP/SMTP-style greeting), bounded to CYTADEL_KB_VALUE_MAX_LEN bytes.
 * Detection-only: this NEVER writes a single byte to the socket -- see
 * host_scan.h's "detection only" header comment and the detection-only rule.
 * Kept private to src/net (same-directory quote-include, matching
 * icmp_probe.h/tcp_ping.h's convention) -- only service_detect.c and its
 * sibling svc_*.c files need this. */

#ifdef __cplusplus
extern "C" {
#endif

/* Capped at the KB's own string value limit (kb-schema.md §7.4: "longer
 * banners are truncated at the banner-grab layer before the set_kb_item
 * call"). +1 for the NUL terminator this module always writes. */
#define CYTADEL_BANNER_MAX_LEN CYTADEL_KB_VALUE_MAX_LEN

typedef struct {
    char data[CYTADEL_BANNER_MAX_LEN + 1]; /* always NUL-terminated within this buffer */
    size_t len;                            /* strlen(data); never > CYTADEL_BANNER_MAX_LEN */
} cytadel_banner_t;

/* Connects to ip:port (non-blocking connect, bounded by connect_timeout_ms)
 * then reads whatever the peer sends within read_timeout_ms, bounded to
 * CYTADEL_BANNER_MAX_LEN bytes total. Every byte actually read is copied
 * into out_banner->data with an explicit running length check before each
 * write -- this can never overflow out_banner->data regardless of how much
 * or how fast a malicious/misbehaving peer sends.
 *
 * A server that never sends anything (e.g. HTTP, which waits for a
 * request first) is not an error: this returns 0 with out_banner->len ==
 * 0 in that case, same as any other "nothing arrived in time" outcome.
 * Returns -1 only if the connection itself could not be established
 * (socket()/connect() failure or refused/filtered within
 * connect_timeout_ms) -- out_banner is zeroed in that case. The socket is
 * closed on every return path. */
int cytadel_net_banner_grab(const char *ip, uint16_t port, int connect_timeout_ms,
                             int read_timeout_ms, cytadel_banner_t *out_banner);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_BANNER_GRAB_H */
