#include "tls_inspect.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "log.h"

/* "TLS/" + up to 5-digit port + longest sub-key ("/cert_not_yet_valid",
 * 19 bytes) + NUL, rounded up generously. */
#define CYTADEL_TLS_KEY_BUF_LEN 48

static void cytadel_tls_build_key(char *out, size_t out_len, uint16_t port, const char *sub) {
    snprintf(out, out_len, "TLS/%u/%s", (unsigned)port, sub);
}

static bool cytadel_tls_format_iso8601(const struct tm *tm, char *out, size_t out_len) {
    int written = snprintf(out, out_len, "%04d-%02d-%02dT%02d:%02d:%02dZ", tm->tm_year + 1900,
                            tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, tm->tm_sec);
    return written > 0 && (size_t)written < out_len;
}

/* Extracts and writes every cert-derived TLS/<port>/(...) key. Called only
 * when `cert` is non-NULL. Every OpenSSL object allocated in here
 * (pkey/serial_bn/serial_hex/san_names) is freed before returning, on
 * every path. */
static void cytadel_tls_populate_cert_facts(X509 *cert, uint16_t port, cytadel_kb_t *kb) {
    char key[CYTADEL_TLS_KEY_BUF_LEN];

    X509_NAME *subject = X509_get_subject_name(cert);
    X509_NAME *issuer = X509_get_issuer_name(cert);

    /* self_signed: structural DN comparison (kb-schema.md §7.5: "issuer DN
     * == subject DN"), not a string comparison of two independently
     * rendered buffers. */
    if (subject != NULL && issuer != NULL) {
        cytadel_tls_build_key(key, sizeof(key), port, "self_signed");
        cytadel_kb_set_bool(kb, key, X509_NAME_cmp(subject, issuer) == 0);
    }

    /* Issuer DN, "as rendered by OpenSSL's oneline format" (kb-schema.md
     * §7.5's Notes column names this specific, well-known OpenSSL API
     * literally) -- bounded: X509_NAME_oneline() truncates to fit within
     * `sizeof(issuer_buf)` and always NUL-terminates within it. */
    if (issuer != NULL) {
        char issuer_buf[512];
        if (X509_NAME_oneline(issuer, issuer_buf, sizeof(issuer_buf)) != NULL) {
            cytadel_tls_build_key(key, sizeof(key), port, "issuer");
            cytadel_kb_set_str(kb, key, issuer_buf);
        }
    }

    /* Common Name: X509_NAME_get_text_by_NID() bounds its write to
     * sizeof(cn_buf) and NUL-terminates within it, but -- unlike the
     * issuer oneline rendering above -- the underlying ASN.1 string is
     * raw, attacker-controlled certificate data that can legally contain
     * an embedded NUL byte (the classic CN NUL-byte-injection technique,
     * e.g. "good.example.com\0.evil.example.com"). Using the explicit
     * returned length with cytadel_kb_set_str_n() (rather than strlen() on
     * cn_buf, which would silently stop at the first embedded NUL and
     * store only "good.example.com" as if that were the whole, real CN)
     * means the KB's own embedded-NUL rejection (kb-schema.md §3) actually
     * sees the full byte range and correctly REJECTS a CN like that
     * instead of silently accepting a truncated, misleading value. */
    char cn_buf[256];
    int cn_len = X509_NAME_get_text_by_NID(subject, NID_commonName, cn_buf, (int)sizeof(cn_buf));
    if (cn_len > 0) {
        size_t len = (size_t)cn_len;
        if (len >= sizeof(cn_buf)) {
            len = sizeof(cn_buf) - 1; /* defensive clamp; API already bounds this internally */
        }
        cytadel_tls_build_key(key, sizeof(key), port, "cn");
        cytadel_kb_set_str_n(kb, key, cn_buf, len);
    }

    /* Subject Alternative Names: comma-joined per kb-schema.md §3's
     * "flattened list" convention. Same embedded-NUL concern as the CN
     * above applies per-entry (each dNSName is raw ASN.1 string data), so
     * this tracks an explicit running length (san_len) and uses
     * cytadel_kb_set_str_n() rather than relying on the joined buffer
     * being a clean C string. The join is capped at CYTADEL_KB_VALUE_MAX_LEN
     * bytes -- if the full SAN list would not fit, later entries are
     * simply not appended (a partial, still-valid, KB-acceptable list)
     * rather than either overflowing the buffer or losing the entire SAN
     * fact to a single oversized-value rejection. */
    GENERAL_NAMES *san_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);
    if (san_names != NULL) {
        char san_buf[CYTADEL_KB_VALUE_MAX_LEN + 1];
        size_t san_len = 0;
        int san_count = sk_GENERAL_NAME_num(san_names);
        for (int i = 0; i < san_count; i++) {
            const GENERAL_NAME *gen = sk_GENERAL_NAME_value(san_names, i);
            if (gen == NULL || gen->type != GEN_DNS) {
                continue;
            }
            const unsigned char *data = ASN1_STRING_get0_data(gen->d.dNSName);
            int dlen = ASN1_STRING_length(gen->d.dNSName);
            if (data == NULL || dlen <= 0) {
                continue;
            }
            size_t entry_len = (size_t)dlen;
            size_t needed = entry_len + (san_len > 0 ? 1 : 0);
            if (san_len + needed > CYTADEL_KB_VALUE_MAX_LEN) {
                break; /* would overflow the KB's own value cap -- stop, keep what fit so far */
            }
            if (san_len > 0) {
                san_buf[san_len++] = ',';
            }
            memcpy(san_buf + san_len, data, entry_len);
            san_len += entry_len;
        }
        if (san_len > 0) {
            cytadel_tls_build_key(key, sizeof(key), port, "san");
            cytadel_kb_set_str_n(kb, key, san_buf, san_len);
        }
        GENERAL_NAMES_free(san_names);
    }

    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);

    if (not_after != NULL) {
        int cmp = X509_cmp_current_time(not_after);
        if (cmp != 0) { /* 0 == "error/could not determine" -- don't overclaim */
            cytadel_tls_build_key(key, sizeof(key), port, "cert_expired");
            cytadel_kb_set_bool(kb, key, cmp < 0);
        }
        struct tm tm_after;
        char iso[CYTADEL_ISO8601_BUF_LEN];
        if (ASN1_TIME_to_tm(not_after, &tm_after) == 1 &&
            cytadel_tls_format_iso8601(&tm_after, iso, sizeof(iso))) {
            cytadel_tls_build_key(key, sizeof(key), port, "not_after");
            cytadel_kb_set_str(kb, key, iso);
        }
    }
    if (not_before != NULL) {
        int cmp = X509_cmp_current_time(not_before);
        if (cmp != 0) {
            cytadel_tls_build_key(key, sizeof(key), port, "cert_not_yet_valid");
            cytadel_kb_set_bool(kb, key, cmp > 0);
        }
        struct tm tm_before;
        char iso[CYTADEL_ISO8601_BUF_LEN];
        if (ASN1_TIME_to_tm(not_before, &tm_before) == 1 &&
            cytadel_tls_format_iso8601(&tm_before, iso, sizeof(iso))) {
            cytadel_tls_build_key(key, sizeof(key), port, "not_before");
            cytadel_kb_set_str(kb, key, iso);
        }
    }

    /* Signature algorithm (the algorithm used to SIGN the certificate --
     * X509_get0_signature(), not the tbsCertificate's own declared
     * algorithm, which is conventionally what tools like `openssl x509
     * -text` label "Signature Algorithm"). */
    const ASN1_BIT_STRING *sig = NULL;
    const X509_ALGOR *sig_alg = NULL;
    X509_get0_signature(&sig, &sig_alg, cert);
    if (sig_alg != NULL) {
        const ASN1_OBJECT *sig_obj = NULL;
        X509_ALGOR_get0(&sig_obj, NULL, NULL, sig_alg);
        if (sig_obj != NULL) {
            char sig_buf[128];
            int n = OBJ_obj2txt(sig_buf, (int)sizeof(sig_buf), sig_obj, 0);
            if (n > 0) {
                size_t len = (size_t)n;
                if (len >= sizeof(sig_buf)) {
                    len = sizeof(sig_buf) - 1;
                }
                cytadel_tls_build_key(key, sizeof(key), port, "sig_alg");
                cytadel_kb_set_str_n(kb, key, sig_buf, len);
            }
        }
    }

    /* Serial number: uppercase hex, no "0x" prefix, no colons
     * (kb-schema.md §7.5) -- BN_bn2hex() already produces exactly that
     * format for a non-negative serial (a negative serial, technically
     * invalid per RFC 5280 but not impossible to encounter from a
     * malformed/hostile cert, gets a leading '-' from BN_bn2hex(), which
     * is still a safe, bounded, non-crashing string -- just not a value a
     * plugin should expect to see). */
    const ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    if (serial != NULL) {
        BIGNUM *serial_bn = ASN1_INTEGER_to_BN(serial, NULL);
        if (serial_bn != NULL) {
            char *serial_hex = BN_bn2hex(serial_bn);
            if (serial_hex != NULL) {
                cytadel_tls_build_key(key, sizeof(key), port, "serial");
                cytadel_kb_set_str(kb, key, serial_hex);
                OPENSSL_free(serial_hex);
            }
            BN_free(serial_bn);
        }
    }

    /* Public key size in bits (RSA modulus bit-length, or EC curve order
     * bit-length -- EVP_PKEY_bits() handles both uniformly). */
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if (pkey != NULL) {
        int bits = EVP_PKEY_bits(pkey);
        if (bits > 0) {
            cytadel_tls_build_key(key, sizeof(key), port, "key_bits");
            cytadel_kb_set_int(kb, key, bits);
        }
        EVP_PKEY_free(pkey);
    }
}

bool cytadel_net_tls_populate_kb(const cytadel_tls_session_t *session, uint16_t port,
                                  cytadel_kb_t *kb) {
    if (session == NULL || session->ssl == NULL || kb == NULL) {
        return false;
    }

    char key[CYTADEL_TLS_KEY_BUF_LEN];

    const char *version = SSL_get_version(session->ssl);
    if (version != NULL) {
        cytadel_tls_build_key(key, sizeof(key), port, "version");
        cytadel_kb_set_str(kb, key, version);
    }

    const char *cipher = SSL_get_cipher(session->ssl);
    if (cipher != NULL) {
        cytadel_tls_build_key(key, sizeof(key), port, "cipher");
        cytadel_kb_set_str(kb, key, cipher);
    }

    /* SSL_get1_peer_certificate() (the OpenSSL 3.0+ non-deprecated name;
     * increments the cert's refcount) -- the caller of THIS function owns
     * the returned reference and must free it, which the single X509_free()
     * below does on every path. A NULL return (no certificate presented,
     * e.g. an anonymous cipher suite) is a valid, non-error outcome -- the
     * session-level facts above are still written either way. */
    X509 *cert = SSL_get1_peer_certificate(session->ssl);
    if (cert != NULL) {
        cytadel_tls_populate_cert_facts(cert, port, kb);
        X509_free(cert);
    } else {
        cytadel_log_debug("tls: handshake completed on port %u but peer presented no certificate",
                           (unsigned)port);
    }

    return true;
}
