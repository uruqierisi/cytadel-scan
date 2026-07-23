#include "svc_token.h"

#include <stddef.h>
#include <stdio.h>

#include "log.h"

int cytadel_svc_token_write(cytadel_kb_t *kb, const char *token, uint16_t port) {
    /* kb-schema.md §7.3: key is "Services/<service>/<port>", <port> is the
     * decimal ASCII port number (no zero-padding). Longest possible key:
     * "Services/" (9) + longest token ("postgresql", 10) + "/" (1) +
     * "65535" (5) + NUL = 26 bytes -- 64 bytes is generous headroom. */
    char key[64];
    int written = snprintf(key, sizeof(key), "Services/%s/%u", token, (unsigned)port);
    if (written < 0 || (size_t)written >= sizeof(key)) {
        cytadel_log_warn("svc_token: could not format Services key for token '%s' port %u",
                          token, (unsigned)port);
        return -1;
    }
    return cytadel_kb_set_int(kb, key, (int64_t)port);
}

typedef struct {
    uint16_t port;
    const char *token;
} cytadel_well_known_port_t;

/* kb-schema.md §2's frozen vocabulary, mapped from the ports this
 * milestone's detection layer recognizes. Only ports whose underlying
 * protocol token is actually in the frozen list are mapped here -- e.g.
 * IMAPS (993) and POP3S (995) map to the base "imap"/"pop3" tokens (there
 * is no separate "imaps"/"pop3s" token in the frozen vocabulary), and
 * ports whose conventional service (e.g. LDAP/LDAPS) has no frozen token
 * at all are deliberately left unmapped rather than inventing one. */
static const cytadel_well_known_port_t g_well_known_ports[] = {
    {21, "ftp"},
    {22, "ssh"},
    {23, "telnet"},
    {25, "smtp"},
    {53, "dns"},
    {80, "www"},
    {110, "pop3"},
    {143, "imap"},
    {161, "snmp"},
    {443, "https"},
    {445, "smb"},
    {465, "smtp"},   /* SMTPS (implicit TLS) */
    {587, "smtp"},   /* SMTP submission (usually STARTTLS) */
    {993, "imap"},   /* IMAPS (implicit TLS) */
    {995, "pop3"},   /* POP3S (implicit TLS) */
    {3306, "mysql"},
    {3389, "rdp"},
    {5432, "postgresql"},
    {6379, "redis"},
    {8000, "www"},
    {8080, "www"},
    {8443, "https"},
    {8888, "www"},
};

const char *cytadel_svc_token_for_well_known_port(uint16_t port) {
    size_t count = sizeof(g_well_known_ports) / sizeof(g_well_known_ports[0]);
    for (size_t i = 0; i < count; i++) {
        if (g_well_known_ports[i].port == port) {
            return g_well_known_ports[i].token;
        }
    }
    return NULL;
}

bool cytadel_svc_is_tls_candidate_port(uint16_t port) {
    switch (port) {
        case 443:  /* HTTPS */
        case 8443: /* HTTPS (alt) */
        case 465:  /* SMTPS */
        case 636:  /* LDAPS */
        case 990:  /* FTPS (control) */
        case 992:  /* Telnet over TLS */
        case 993:  /* IMAPS */
        case 995:  /* POP3S */
            return true;
        default:
            return false;
    }
}

bool cytadel_svc_is_http_port(uint16_t port) {
    switch (port) {
        case 80:
        case 81:
        case 443:
        case 8000:
        case 8080:
        case 8443:
        case 8888:
            return true;
        default:
            return false;
    }
}
