#ifndef CYTADEL_DB_CVE_ID_VALID_H
#define CYTADEL_DB_CVE_ID_VALID_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

/* Private to src/db/ -- not under include/cytadel/db/ -- matching the
 * db_migrations.h / icmp_probe.h (src/net) / kb_validate.h (src/kb)
 * convention: only translation units inside this directory include it.
 *
 * ONE shared definition of the NVD CVE-ID grammar check, promoted here out
 * of nvd_ingest.c (where it started life as a file-static helper during the
 * Milestone 7 slice 2 security review, W3 fix) so that nvd_ingest.c,
 * kev_ingest.c, and epss_ingest.c cannot independently drift into two
 * subtly different grammar checks. Every one of those three modules stores
 * a cve_id value that becomes either the cves table's PRIMARY KEY (NVD) or
 * a hard FOREIGN KEY into it (KEV/EPSS, via the placeholder-row dance --
 * db-schema.md SS9/SS10 assumption 5) -- a bad key must never reach either
 * role, so all three call this single implementation before ever binding a
 * cve_id into a prepared statement.
 *
 * Security-review W3 (Milestone 7 slice 2, nvd_ingest.c): cJSON faithfully
 * decodes a JSON string's null-character escape sequence (the standard JSON
 * encoding of code point U+0000) into a genuine embedded NUL byte inside its
 * valuestring, but cJSON's public struct carries no length field alongside
 * valuestring -- there is no way for a caller to "see past" that embedded
 * NUL to compare a true byte-length against strlen(). This function
 * implements the INTENT of "reject an embedded-NUL-truncated id" instead,
 * which is actually stronger: it requires the entire VISIBLE
 * (NUL-terminated) string to fully match the NVD/CISA/first.org CVE-ID
 * grammar, CVE-YYYY-NNNN... (four digit year, a literal hyphen, then four
 * or more digits, and nothing else). A NUL-truncated id like "CVE-X" plus a
 * hidden suffix has a visible portion "CVE-X", which fails that grammar
 * outright (no four-digit year), so it is rejected before it ever reaches
 * sqlite3_bind_text() -- two differently-suffixed crafted ids (identical
 * visible prefix, different bytes hidden after their own embedded NULs) can
 * therefore never collide on a PK/FK keyed by this value, because neither
 * one is ever stored.
 *
 * `id` must be non-NULL (callers only ever reach this after their own
 * json_get_string()-style helper has already confirmed a non-NULL
 * valuestring). Evaluated over strlen(id) -- the VISIBLE, NUL-terminated
 * string the JSON library exposes -- deliberately, not a separately-tracked
 * byte length (see above for why the latter is not implementable against
 * cJSON's public API, and why the former is the correct closure anyway). */
static inline bool cytadel_is_valid_cve_id(const char *id) {
    size_t len = strlen(id);
    /* Shortest legal id: "CVE-" (4) + 4 digits + '-' (1) + 4 digits = 13. */
    if (len < 13) {
        return false;
    }
    if (memcmp(id, "CVE-", 4) != 0) {
        return false;
    }
    size_t i = 4;
    for (int d = 0; d < 4; d++) {
        if (id[i] < '0' || id[i] > '9') {
            return false;
        }
        i++;
    }
    if (id[i] != '-') {
        return false;
    }
    i++;
    size_t digit_count = 0;
    for (; i < len; i++) {
        if (id[i] < '0' || id[i] > '9') {
            return false; /* any non-digit anywhere in the sequence -- reject */
        }
        digit_count++;
    }
    return digit_count >= 4;
}

#endif /* CYTADEL_DB_CVE_ID_VALID_H */
