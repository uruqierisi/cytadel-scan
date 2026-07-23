#include "cytadel/net/service_detect.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "banner_grab.h"
#include "cpe_map.h"
#include "http_probe.h"
#include "log.h"
#include "svc_ftp.h"
#include "svc_ssh.h"
#include "svc_token.h"
#include "tls_inspect.h"
#include "tls_session.h"

/* Bounded, case-insensitive substring search over exactly `haystack_len`
 * bytes (never reads haystack[haystack_len] or beyond, regardless of
 * whether haystack is NUL-terminated) -- used below as a conservative FTP
 * banner-signature fallback. Returns true iff `needle` occurs anywhere in
 * the first `haystack_len` bytes of `haystack`. */
static bool cytadel_service_detect_contains_ci(const char *haystack, size_t haystack_len,
                                                const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > haystack_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        size_t j = 0;
        for (; j < needle_len; j++) {
            unsigned char a = (unsigned char)haystack[i + j];
            unsigned char b = (unsigned char)needle[j];
            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
        }
        if (j == needle_len) {
            return true;
        }
    }
    return false;
}

/* Built-in defaults used when the caller passes opts == NULL, or when a
 * caller-supplied field is out of range. Deliberately small/generous
 * enough for loopback/LAN detection probes without making a full scan of
 * many hosts unreasonably slow -- not user-configurable this milestone
 * (see service_detect.h's header comment: this is the one thing Part D's
 * wiring hard-codes rather than threading a new CLI flag through). */
#define CYTADEL_SERVICE_DETECT_DEFAULT_CONNECT_MS 3000
#define CYTADEL_SERVICE_DETECT_DEFAULT_READ_MS 2000

static void cytadel_service_detect_write_http_facts(cytadel_kb_t *kb, uint16_t port,
                                                      const cytadel_http_probe_result_t *http) {
    char key[48];

    if (http->status >= 0) {
        snprintf(key, sizeof(key), "HTTP/%u/status", (unsigned)port);
        cytadel_kb_set_int(kb, key, http->status);
    }
    if (http->server[0] != '\0') {
        /* set_str_n() with the tracked http->server_len, not strlen(): see
         * http_probe.h's header comment -- the Server: header value is
         * untrusted response data that may contain an embedded NUL. */
        snprintf(key, sizeof(key), "HTTP/%u/server", (unsigned)port);
        cytadel_kb_set_str_n(kb, key, http->server, http->server_len);
        cytadel_cpe_map_and_write(kb, port, http->server, http->server_len);
    }
    if (http->title[0] != '\0') {
        snprintf(key, sizeof(key), "HTTP/%u/title", (unsigned)port);
        cytadel_kb_set_str_n(kb, key, http->title, http->title_len);
    }

    /* kb-schema.md §7.3: Services/www/<port>. The paired
     * Services/https/<port> write for a TLS-confirmed port is the TLS
     * handshake path's responsibility (cytadel_service_detect_try_tls()
     * below writes it unconditionally the moment the handshake succeeds,
     * before this function is ever reached for that port), not this
     * function's -- this function runs for both the plaintext-HTTP path
     * (no TLS at all) and the HTTP-over-TLS path (TLS already confirmed by
     * the caller), and only the former should ever produce www without
     * https. */
    cytadel_svc_token_write(kb, "www", port);
}

/* TLS-candidate ports (kb-schema.md §7.5): attempt the handshake first.
 * On success, TLS/<port>/enabled=true plus every other TLS/<port>/(...)
 * fact is written (tls_inspect.c), Services/https/<port> is written
 * unconditionally (see the comment on that write below -- security-review
 * finding C4(a)), and -- for the well-known HTTP-over-TLS ports -- an HTTP
 * GET is additionally layered on the same session to also populate
 * HTTP/<port>/(...) and Services/www/<port>. On failure,
 * TLS/<port>/enabled=false is written and the caller falls back to the
 * plaintext detection path (the port may simply not speak TLS at all).
 * Returns true iff the handshake succeeded (i.e. the plaintext fallback
 * below must NOT also run).
 *
 * `sni_hostname`: forwarded verbatim to cytadel_net_tls_connect_sni() --
 * NULL (IP-literal target) omits SNI, non-NULL (name-based target) sends
 * that hostname. See service_detect.h's doc comment on the public
 * cytadel_service_detect_port() entry point. */
static bool cytadel_service_detect_try_tls(const char *ip, uint16_t port,
                                            const cytadel_service_detect_opts_t *opts,
                                            cytadel_kb_t *kb, const char *sni_hostname) {
    char enabled_key[32];
    snprintf(enabled_key, sizeof(enabled_key), "TLS/%u/enabled", (unsigned)port);

    cytadel_tls_session_t session;
    if (cytadel_net_tls_connect_sni(ip, sni_hostname, port, opts->connect_timeout_ms, &session) !=
        0) {
        cytadel_kb_set_bool(kb, enabled_key, false);
        cytadel_net_tls_session_close(&session); /* safe no-op on a failed connect */
        return false;
    }

    cytadel_kb_set_bool(kb, enabled_key, true);
    cytadel_net_tls_populate_kb(&session, port, kb);

    /* kb-schema.md §7.3's Services/https/<port> row: written here for
     * EVERY port a TLS handshake was just confirmed on, not only the
     * well-known HTTP-over-TLS ports (security-review finding C4(a)) --
     * the 8 stock TLS-inspection plugins (plugins/tls_*.lua) all gate on
     * the `Services/https/<port>` required_keys wildcard, so a TLS-confirmed
     * port that never got this key (e.g. IMAPS/993, POP3S/995, FTPS/990,
     * LDAPS/636) silently got zero TLS-plugin coverage even though the
     * handshake -- and every TLS/<port>/(...) fact above -- succeeded.
     * cytadel_svc_token_write() is last-write-wins and idempotent, so the
     * HTTP-over-TLS branch below writing Services/www/<port> in addition
     * to this is not a conflict. */
    cytadel_svc_token_write(kb, "https", port);

    if (cytadel_svc_is_http_port(port)) {
        cytadel_http_probe_result_t http;
        if (cytadel_net_http_probe_tls(session.ssl, ip, opts->read_timeout_ms, &http) == 0) {
            cytadel_service_detect_write_http_facts(kb, port, &http);
        }
    } else {
        const char *token = cytadel_svc_token_for_well_known_port(port);
        if (token != NULL) {
            cytadel_svc_token_write(kb, token, port);
        }
    }

    cytadel_net_tls_session_close(&session);
    return true;
}

static void cytadel_service_detect_plaintext(const char *ip, uint16_t port,
                                              const cytadel_service_detect_opts_t *opts,
                                              cytadel_kb_t *kb) {
    if (cytadel_svc_is_http_port(port)) {
        cytadel_http_probe_result_t http;
        if (cytadel_net_http_probe_plain(ip, port, opts->connect_timeout_ms,
                                          opts->read_timeout_ms, &http) == 0) {
            cytadel_service_detect_write_http_facts(kb, port, &http);
        }
        return;
    }

    cytadel_banner_t banner;
    if (cytadel_net_banner_grab(ip, port, opts->connect_timeout_ms, opts->read_timeout_ms,
                                 &banner) != 0 ||
        banner.len == 0) {
        /* No greeting arrived (or the connection failed outright) -- still
         * map a well-known port to its frozen token if one applies
         * (kb-schema.md §7.3: "Map by well-known port AND/OR banner
         * signature"), matching common scanner convention of trusting a
         * conventional port even without confirming via banner. */
        const char *token = cytadel_svc_token_for_well_known_port(port);
        if (token != NULL) {
            cytadel_svc_token_write(kb, token, port);
        }
        return;
    }

    /* kb-schema.md §7.4: Banner/<port> is "service-detection (generic
     * FIRST-LINE banner grab on connect)" -- cytadel_net_banner_grab()
     * itself may have captured more than one line within its read window
     * (some servers send pre-banner lines), so trim to the first line
     * (up to CR/LF, or the whole capture if there is none) before writing,
     * matching the contract's own example value ("SSH-2.0-OpenSSH_9.6",
     * no trailing CR/LF). */
    size_t banner_line_len = 0;
    while (banner_line_len < banner.len && banner.data[banner_line_len] != '\r' &&
           banner.data[banner_line_len] != '\n') {
        banner_line_len++;
    }

    /* A banner grab that captured only a bare CR/LF (or nothing before the
     * first CR/LF) has no actual first-line content to record -- skip the
     * write entirely rather than storing an empty-but-present
     * Banner/<port> key. An absent key is kb-schema.md's correct
     * "unknown"/"not observed" representation (§4); a present-but-empty
     * string is not a distinct state anything reads for, so it would only
     * be misleading (e.g. a reporting/plugin reader treating presence
     * alone as "a banner was seen"). */
    if (banner_line_len > 0) {
        char banner_key[32];
        snprintf(banner_key, sizeof(banner_key), "Banner/%u", (unsigned)port);
        /* Length-aware write (cytadel_kb_set_str_n(), not cytadel_kb_set_str()):
         * `banner.data` is untrusted, attacker-controlled network data that
         * can legally contain an embedded NUL byte. A plain strlen()-based
         * cytadel_kb_set_str() call would silently stop at that NUL and
         * store only the prefix as if it were the whole banner; using the
         * actual tracked length instead lets the KB's own embedded-NUL
         * rejection (kb-schema.md §3) correctly reject the whole value
         * instead of silently truncating/misrepresenting it. */
        cytadel_kb_set_str_n(kb, banner_key, banner.data, banner_line_len);
    }

    if (cytadel_svc_ssh_detect(kb, port, banner.data, banner.len)) {
        return;
    }
    /* FTP is dispatched by well-known port (21) OR a bounded,
     * case-insensitive "FTP" banner signature: unlike SSH's "SSH-" prefix
     * (an unambiguous, protocol-defined signature), a bare "220 ..."
     * greeting alone is shared by several unrelated protocols (e.g.
     * SMTP), so a generic "220" prefix is not used as the signature.
     * Real-world FTP daemons near-universally advertise "FTP" literally in
     * their greeting (e.g. "220 (vsFTPd 3.0.5)", "220 ProFTPD ... FTP
     * Server ready"), which SMTP/other 220-greeting protocols do not, so
     * this remains a conservative, low-false-positive signature. */
    bool looks_like_ftp =
        (port == 21) || cytadel_service_detect_contains_ci(banner.data, banner.len, "ftp");
    if (looks_like_ftp && cytadel_svc_ftp_detect(kb, port, banner.data, banner.len)) {
        return;
    }

    const char *token = cytadel_svc_token_for_well_known_port(port);
    if (token != NULL) {
        cytadel_svc_token_write(kb, token, port);
    }
}

void cytadel_service_detect_port(const char *ip, uint16_t port,
                                  const cytadel_service_detect_opts_t *opts, cytadel_kb_t *kb,
                                  const char *sni_hostname) {
    if (ip == NULL || port == 0 || kb == NULL) {
        return;
    }

    /* This is the one place in the engine that writes to a peer-controlled
     * socket (http_probe.c's GET request, both plain and over TLS) -- a
     * slow/misbehaving/actively hostile service on an open port that
     * closes its end early would otherwise raise SIGPIPE on the next
     * send()/SSL_write() and kill the entire process. SIGPIPE is ignored
     * ONCE, process-wide, at startup (src/cli/main.c, via sigaction) --
     * not here per-call: this function runs on worker-pool threads
     * (src/core/worker_pool.c), and signal()/sigaction() disposition is
     * process-wide state, so calling signal() from multiple concurrently
     * running worker threads is undefined behavior (a data race on the
     * process's signal disposition table), not merely redundant. Every
     * write path in this module already checks `n <= 0` -> treat as
     * failure, never a fatal scan error, so a broken connection still
     * surfaces as an ordinary EPIPE/SSL error return once SIGPIPE itself
     * is ignored process-wide. */

    cytadel_service_detect_opts_t resolved;
    resolved.connect_timeout_ms =
        (opts != NULL && opts->connect_timeout_ms > 0) ? opts->connect_timeout_ms
                                                          : CYTADEL_SERVICE_DETECT_DEFAULT_CONNECT_MS;
    resolved.read_timeout_ms = (opts != NULL && opts->read_timeout_ms > 0)
                                    ? opts->read_timeout_ms
                                    : CYTADEL_SERVICE_DETECT_DEFAULT_READ_MS;

    if (cytadel_svc_is_tls_candidate_port(port)) {
        if (cytadel_service_detect_try_tls(ip, port, &resolved, kb, sni_hostname)) {
            return;
        }
        /* Handshake failed -- fall through and try plaintext detection,
         * since a TLS-candidate port (e.g. 8443) may simply be running a
         * plain, non-TLS service instead. */
    }

    cytadel_service_detect_plaintext(ip, port, &resolved, kb);
}
