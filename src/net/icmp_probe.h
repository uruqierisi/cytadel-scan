#ifndef CYTADEL_NET_ICMP_PROBE_H
#define CYTADEL_NET_ICMP_PROBE_H

/* Private to src/net -- only discovery.c calls this. Not part of the
 * public cytadel/net/ surface: a raw ICMP echo probe needs a raw socket,
 * which is an implementation detail of the ICMP discovery method, not
 * something other modules should reach for directly. */

typedef enum {
    CYTADEL_ICMP_REPLY_UP,   /* echo reply received within the timeout */
    CYTADEL_ICMP_NO_REPLY,   /* raw socket opened fine, but no reply arrived */
    CYTADEL_ICMP_UNAVAILABLE /* could not even open a raw ICMP socket (no privilege) */
} cytadel_icmp_result_t;

/* Sends one ICMP echo request to `ip` and waits up to timeout_ms for a
 * matching echo reply (same id/sequence, same source address). Opens and
 * closes its own raw socket on every path; if opening it fails
 * (EPERM/EACCES -- no CAP_NET_RAW/root), returns
 * CYTADEL_ICMP_UNAVAILABLE without attempting to send anything, so the
 * caller can fall back to a different discovery method rather than
 * requiring root. */
cytadel_icmp_result_t cytadel_icmp_echo_probe(const char *ip, int timeout_ms);

#endif /* CYTADEL_NET_ICMP_PROBE_H */
