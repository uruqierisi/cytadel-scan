#ifndef CYTADEL_NET_TLS_INSPECT_H
#define CYTADEL_NET_TLS_INSPECT_H

#include <stdbool.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"
#include "tls_session.h"

/* Certificate/session fact extraction (Milestone 4, Part C,
 * kb-schema.md §7.5). Kept private to src/net (same-directory
 * quote-include).
 *
 * Ownership split with the caller (service_detect.c): this module does
 * NOT write TLS/<port>/enabled -- that fact is "did a handshake happen at
 * all," which the caller already knows the instant cytadel_net_tls_
 * connect() returns (before this module is ever invoked), and the caller
 * needs to write `enabled = false` on a failed handshake too, which this
 * module (only ever called on a successfully handshaked session) cannot
 * do. Every OTHER TLS/<port>/(...) key is this module's responsibility. */

#ifdef __cplusplus
extern "C" {
#endif

/* Populates every TLS/<port>/(...) key (kb-schema.md §7.5) except `enabled`
 * from an already-handshaked `session` (cytadel_net_tls_connect() must
 * have returned 0 for this session). Writes `version` and `cipher`
 * unconditionally (session-level facts, always available after a
 * completed handshake); writes the certificate-derived facts (cert_
 * expired, cert_not_yet_valid, self_signed, cn, san, not_before,
 * not_after, issuer, serial, sig_alg, key_bits) only if the peer actually
 * presented a certificate (SSL_get1_peer_certificate() succeeding) --
 * omitting them (never guessing/zero-filling) if it did not, which is an
 * unusual but valid TLS outcome (anonymous cipher suites).
 *
 * Every OpenSSL object this function allocates (X509, EVP_PKEY, BIGNUM,
 * GENERAL_NAMES, OPENSSL_malloc'd strings) is freed on every return path.
 * Every string extracted from the certificate is bounds-checked against a
 * fixed-size local buffer before being handed to cytadel_kb_set_str() --
 * a malicious/malformed certificate can never overflow anything here.
 *
 * Returns true if the session/kb were usable at all (regardless of
 * whether a certificate was present -- that is a valid, non-error
 * outcome, see above); false only if `session` is NULL/not handshaked
 * (session->ssl == NULL) or `kb` is NULL. */
bool cytadel_net_tls_populate_kb(const cytadel_tls_session_t *session, uint16_t port,
                                  cytadel_kb_t *kb);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_TLS_INSPECT_H */
