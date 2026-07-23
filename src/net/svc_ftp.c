#include "svc_ftp.h"

#include <stdio.h>
#include <string.h>

#include "cpe_map.h"
#include "svc_token.h"

bool cytadel_svc_ftp_detect(cytadel_kb_t *kb, uint16_t port, const char *banner, size_t banner_len) {
    if (kb == NULL || banner == NULL || banner_len == 0) {
        return false;
    }

    size_t line_end = 0;
    while (line_end < banner_len && banner[line_end] != '\r' && banner[line_end] != '\n') {
        line_end++;
    }
    if (line_end == 0) {
        return false;
    }

    /* line_end <= banner_len <= CYTADEL_KB_VALUE_MAX_LEN (banner_grab.h). */
    char line[CYTADEL_KB_VALUE_MAX_LEN + 1];
    memcpy(line, banner, line_end);
    line[line_end] = '\0';

    /* set_str_n() with the explicitly tracked `line_end`, not strlen()-based
     * set_str(): see svc_ssh.c's identical comment -- `banner` is
     * untrusted network data that may contain an embedded NUL the CR/LF
     * scan above would not have stopped at. */
    char key[32];
    snprintf(key, sizeof(key), "FTP/%u/banner", (unsigned)port);
    cytadel_kb_set_str_n(kb, key, line, line_end);

    cytadel_svc_token_write(kb, "ftp", port);
    cytadel_cpe_map_and_write(kb, port, line, line_end);

    return true;
}
