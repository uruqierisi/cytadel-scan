#define _POSIX_C_SOURCE 200809L

#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "cytadel/kb/kb.h"
#include "cytadel/net/service_detect.h"

/* Binds to the first of `candidates` that succeeds. Used here (rather than
 * an OS-assigned ephemeral port) because TLS inspection is dispatched by
 * well-known port number (cytadel_svc_is_tls_candidate_port(), src/net's
 * svc_token.c) -- the public cytadel_service_detect_port() entry point
 * only attempts a TLS handshake at all on one of those ports. Every port
 * in that list except 8443 is a privileged (< 1024) well-known port
 * (443/465/636/990/992/993/995), which this non-root test process cannot
 * bind -- so 8443 is the only usable candidate. 8443 is also in the
 * HTTP-port list (cytadel_svc_is_http_port()), meaning
 * cytadel_service_detect_port() will additionally attempt an HTTP GET over
 * the TLS session after this fixture's handshake completes; the fixture
 * below does not answer that request (it closes right after the
 * handshake), which is fine -- the TLS/<port>/(...) facts this test
 * asserts are all populated by tls_inspect.c immediately after the handshake,
 * before that HTTP attempt is even made, and http_probe_tls() failing to
 * get a response is a normal, non-fatal outcome (see http_probe.c). */
static int cytadel_test_bind_fixed(const uint16_t *candidates, size_t count, uint16_t *out_port) {
    for (size_t i = 0; i < count; i++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        CYTADEL_ASSERT(fd >= 0);

        int reuse = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(candidates[i]);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0 && listen(fd, 1) == 0) {
            *out_port = candidates[i];
            return fd;
        }
        close(fd);
    }
    CYTADEL_ASSERT(0 && "no candidate TLS test port was available");
    return -1;
}

/* Generates an ephemeral, self-signed 2048-bit RSA certificate in memory
 * (no disk I/O, no external `openssl` process). Subject == Issuer, so
 * this is exactly the "self-signed" case TLS/<port>/self_signed exists to
 * detect. `out_cert`/`out_pkey` are owned by the caller (X509_free()/
 * EVP_PKEY_free()) -- returns true on success, false on any OpenSSL
 * failure (nothing partially allocated is leaked either way: on failure,
 * whatever this function itself allocated is freed before returning). */
static bool cytadel_test_make_self_signed_cert(X509 **out_cert, EVP_PKEY **out_pkey) {
    *out_cert = NULL;
    *out_pkey = NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL) {
        return false;
    }
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    X509 *cert = X509_new();
    if (cert == NULL) {
        EVP_PKEY_free(pkey);
        return false;
    }

    bool ok = true;
    ok = ok && (X509_set_version(cert, 2) == 1); /* X.509 v3 */
    ok = ok && (ASN1_INTEGER_set(X509_get_serialNumber(cert), 0x1234) == 1);
    ok = ok && (X509_gmtime_adj(X509_getm_notBefore(cert), -3600) != NULL);       /* valid from 1h ago */
    ok = ok && (X509_gmtime_adj(X509_getm_notAfter(cert), 365L * 24 * 3600) != NULL); /* 1 year validity */
    ok = ok && (X509_set_pubkey(cert, pkey) == 1);

    if (ok) {
        X509_NAME *name = X509_get_subject_name(cert);
        ok = ok && (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                                (const unsigned char *)"test.cytadel.local", -1, -1,
                                                0) == 1);
        ok = ok && (X509_set_issuer_name(cert, name) == 1); /* self-signed: issuer == subject */
    }

    ok = ok && (X509_sign(cert, pkey, EVP_sha256()) > 0);

    if (!ok) {
        X509_free(cert);
        EVP_PKEY_free(pkey);
        return false;
    }

    *out_cert = cert;
    *out_pkey = pkey;
    return true;
}

typedef struct {
    int listen_fd;
    X509 *cert;
    EVP_PKEY *pkey;
} cytadel_tls_fixture_args_t;

static void *cytadel_tls_fixture_server_main(void *arg) {
    cytadel_tls_fixture_args_t *args = (cytadel_tls_fixture_args_t *)arg;

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        return NULL;
    }
    if (SSL_CTX_use_certificate(ctx, args->cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, args->pkey) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    int fd = accept(args->listen_fd, NULL, NULL);
    if (fd < 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL *ssl = SSL_new(ctx);
    if (ssl != NULL) {
        if (SSL_set_fd(ssl, fd) == 1) {
            SSL_accept(ssl); /* best-effort; the client-side assertions are what matter */
        }
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }

    close(fd);
    SSL_CTX_free(ctx);
    return NULL;
}

static void test_tls_inspection_self_signed_cert(void) {
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    CYTADEL_ASSERT(cytadel_test_make_self_signed_cert(&cert, &pkey));

    static const uint16_t candidates[] = {8443};
    uint16_t port;
    int listen_fd =
        cytadel_test_bind_fixed(candidates, sizeof(candidates) / sizeof(candidates[0]), &port);

    cytadel_tls_fixture_args_t args;
    args.listen_fd = listen_fd;
    args.cert = cert;
    args.pkey = pkey;

    pthread_t thread;
    CYTADEL_ASSERT(pthread_create(&thread, NULL, cytadel_tls_fixture_server_main, &args) == 0);

    cytadel_kb_t *kb = cytadel_kb_create();
    CYTADEL_ASSERT(kb != NULL);

    cytadel_service_detect_opts_t opts;
    opts.connect_timeout_ms = 2000;
    opts.read_timeout_ms = 2000;
    cytadel_service_detect_port("127.0.0.1", port, &opts, kb, NULL);

    pthread_join(thread, NULL);

    char key[64];

    snprintf(key, sizeof(key), "TLS/%u/enabled", (unsigned)port);
    cytadel_kb_value_t enabled;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &enabled), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(enabled.type, CYTADEL_KB_TYPE_BOOL);
    CYTADEL_ASSERT_EQ(enabled.v.b, true);

    snprintf(key, sizeof(key), "TLS/%u/self_signed", (unsigned)port);
    cytadel_kb_value_t self_signed;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &self_signed), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(self_signed.type, CYTADEL_KB_TYPE_BOOL);
    CYTADEL_ASSERT_EQ(self_signed.v.b, true);

    snprintf(key, sizeof(key), "TLS/%u/cn", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "test.cytadel.local");

    snprintf(key, sizeof(key), "TLS/%u/not_after", (unsigned)port);
    const char *not_after = cytadel_kb_get_str(kb, key);
    CYTADEL_ASSERT(not_after != NULL);
    /* ISO-8601 UTC, no fractional seconds (kb-schema.md §7.5's own
     * example: "2026-01-01T00:00:00Z"): exactly
     * "YYYY-MM-DDTHH:MM:SSZ" == 20 characters, 'T' at [10], 'Z' at [19]. */
    CYTADEL_ASSERT_EQ(strlen(not_after), (size_t)20);
    CYTADEL_ASSERT_EQ(not_after[10], 'T');
    CYTADEL_ASSERT_EQ(not_after[19], 'Z');

    snprintf(key, sizeof(key), "TLS/%u/not_before", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) != NULL);

    /* A cert valid from 1h ago to 1y from now must be neither expired nor
     * not-yet-valid. */
    snprintf(key, sizeof(key), "TLS/%u/cert_expired", (unsigned)port);
    cytadel_kb_value_t expired;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &expired), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(expired.v.b, false);

    snprintf(key, sizeof(key), "TLS/%u/cert_not_yet_valid", (unsigned)port);
    cytadel_kb_value_t not_yet_valid;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &not_yet_valid), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(not_yet_valid.v.b, false);

    snprintf(key, sizeof(key), "TLS/%u/key_bits", (unsigned)port);
    cytadel_kb_value_t key_bits;
    CYTADEL_ASSERT_EQ(cytadel_kb_get(kb, key, &key_bits), CYTADEL_KB_GET_FOUND);
    CYTADEL_ASSERT_EQ(key_bits.type, CYTADEL_KB_TYPE_INT);
    CYTADEL_ASSERT_EQ(key_bits.v.i64, 2048);

    snprintf(key, sizeof(key), "TLS/%u/version", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) != NULL);

    snprintf(key, sizeof(key), "TLS/%u/cipher", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) != NULL);

    snprintf(key, sizeof(key), "TLS/%u/serial", (unsigned)port);
    CYTADEL_ASSERT_STREQ(cytadel_kb_get_str(kb, key), "1234");

    snprintf(key, sizeof(key), "TLS/%u/sig_alg", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) != NULL);

    snprintf(key, sizeof(key), "TLS/%u/issuer", (unsigned)port);
    CYTADEL_ASSERT(cytadel_kb_get_str(kb, key) != NULL);

    close(listen_fd);
    cytadel_kb_free(kb);
    X509_free(cert);
    EVP_PKEY_free(pkey);
}

int main(void) {
    /* This test drives cytadel_service_detect_port() directly against a
     * fixture that closes the connection right after the TLS handshake
     * (see the comment above cytadel_test_bind_fixed()) -- src/net's HTTP-
     * over-TLS probe (http_probe.c's cytadel_net_http_probe_tls()) may
     * then SSL_write() to that already-closed peer. As of this milestone,
     * SIGPIPE is ignored exactly once at process startup (src/cli/main.c),
     * not per-call inside service_detect.c (see that file's header
     * comment) -- this test binary is its own process and never runs
     * main.c's startup path, so it must install the same ignore itself,
     * for the same reason. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    test_tls_inspection_self_signed_cert();
    CYTADEL_TEST_PASS();
}
