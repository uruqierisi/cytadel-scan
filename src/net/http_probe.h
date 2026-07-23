#ifndef CYTADEL_NET_HTTP_PROBE_H
#define CYTADEL_NET_HTTP_PROBE_H

#include <stddef.h>
#include <stdint.h>

#include <openssl/ssl.h>

/* Minimal HTTP baseline probe (Milestone 4, kb-schema.md §7.4:
 * `HTTP/<port>/server`, `HTTP/<port>/status`, `HTTP/<port>/title`).
 * Detection-only: exactly one request ("GET / HTTP/1.0"), read-only,
 * never any other verb, matching the detection-only rule and host_scan.h's
 * "detection only" header comment. Kept private to src/net
 * (same-directory quote-include). */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int status;        /* parsed HTTP status code (e.g. 200), -1 if not parsed */
    char server[256];  /* raw Server: header value, "" if absent/not parsed */
    size_t server_len; /* strlen(server) -- tracked explicitly (see below) */
    char title[256];   /* parsed <title>, "" if absent/not HTML/not parsed */
    size_t title_len;  /* strlen(title) -- tracked explicitly (see below) */
} cytadel_http_probe_result_t;

/* server_len/title_len exist alongside the NUL-terminated buffers above so
 * a caller writing these into the KB can use cytadel_kb_set_str_n()
 * instead of a strlen()-based cytadel_kb_set_str() call: `server`/`title`
 * are copied from untrusted, attacker-controlled response bytes (a header
 * value or HTML title can legally contain an embedded NUL), and
 * strlen() would silently stop at that NUL rather than letting the KB's
 * own embedded-NUL rejection (kb-schema.md §3) see -- and correctly
 * reject -- the whole value. */

/* Connects to ip:port over plain TCP, sends a single "GET / HTTP/1.0"
 * request, and parses the response (bounded read/parse -- see
 * http_probe.c). Returns 0 if the connection was established (regardless
 * of whether a response was successfully parsed -- *out is always fully
 * populated, with status == -1 / empty strings for anything not
 * determined), -1 if the connection itself could not be established. */
int cytadel_net_http_probe_plain(const char *ip, uint16_t port, int connect_timeout_ms,
                                  int read_timeout_ms, cytadel_http_probe_result_t *out);

/* Same as cytadel_net_http_probe_plain(), but sends the request over an
 * already-handshaked TLS session (see tls_session.h) instead of opening a
 * new plaintext connection -- this is how service_detect.c layers the
 * HTTP baseline probe on top of a TLS-inspected port (443/8443) without a
 * second handshake. `ssl` must already have completed
 * SSL_connect() successfully; this function does not touch the
 * connection's lifecycle (no SSL_shutdown/SSL_free/close here -- the
 * caller, via tls_session.h, owns that). `host` is used for the request's
 * `Host:` header only. Returns 0 on success (same "*out always populated"
 * contract as the plain variant), -1 if `ssl`/`out` is NULL or the
 * request could not be sent at all. */
int cytadel_net_http_probe_tls(SSL *ssl, const char *host, int read_timeout_ms,
                                cytadel_http_probe_result_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_HTTP_PROBE_H */
