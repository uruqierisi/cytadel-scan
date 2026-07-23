#include "svc_ssh.h"

#include <stdio.h>
#include <string.h>

#include "cpe_map.h"
#include "svc_token.h"

bool cytadel_svc_ssh_detect(cytadel_kb_t *kb, uint16_t port, const char *banner, size_t banner_len) {
    if (kb == NULL || banner == NULL || banner_len < 4) {
        return false;
    }
    if (memcmp(banner, "SSH-", 4) != 0) {
        return false;
    }

    /* protoversion runs from index 4 up to (but not including) the next
     * '-'; bail safely (no writes) if the banner ends or hits CR/LF before
     * that '-' is found -- a malformed/truncated peer-supplied banner must
     * never be treated as well-formed. */
    size_t i = 4;
    while (i < banner_len && banner[i] != '-' && banner[i] != '\r' && banner[i] != '\n') {
        i++;
    }
    if (i >= banner_len || banner[i] != '-') {
        return false;
    }
    size_t proto_start = 4;
    size_t proto_len = i - proto_start;
    if (proto_len == 0 || proto_len > 15) {
        return false; /* not a plausible protoversion (e.g. "2.0") */
    }

    size_t sw_start = i + 1;

    /* The identification string ends at CR, LF, or the banner's end. */
    size_t line_end = sw_start;
    while (line_end < banner_len && banner[line_end] != '\r' && banner[line_end] != '\n') {
        line_end++;
    }
    if (line_end == sw_start) {
        return false; /* "SSH-2.0-" with nothing after it */
    }

    char protocol[16];
    memcpy(protocol, banner + proto_start, proto_len);
    protocol[proto_len] = '\0';

    /* line_end <= banner_len <= CYTADEL_BANNER_MAX_LEN ==
     * CYTADEL_KB_VALUE_MAX_LEN (banner_grab.h), so this always fits. */
    char version[CYTADEL_KB_VALUE_MAX_LEN + 1];
    memcpy(version, banner, line_end);
    version[line_end] = '\0';

    /* set_str_n() with the explicitly tracked lengths (line_end/proto_len),
     * not strlen()-based set_str(): `banner` is untrusted network data and
     * neither scan above stops early at a NUL byte (only at '-'/CR/LF), so
     * an attacker-crafted banner could contain one -- using the real
     * length lets the KB correctly reject that instead of a strlen() call
     * silently truncating it into a shorter, misleading value. */
    char key[32];
    snprintf(key, sizeof(key), "SSH/%u/version", (unsigned)port);
    cytadel_kb_set_str_n(kb, key, version, line_end);
    snprintf(key, sizeof(key), "SSH/%u/protocol", (unsigned)port);
    cytadel_kb_set_str_n(kb, key, protocol, proto_len);

    cytadel_svc_token_write(kb, "ssh", port);
    cytadel_cpe_map_and_write(kb, port, banner + sw_start, line_end - sw_start);

    return true;
}
