#ifndef CYTADEL_NET_CPE_MAP_H
#define CYTADEL_NET_CPE_MAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cytadel/kb/kb.h"

/* CPE bridge (Milestone 4, kb-schema.md §7.7): a small, deliberately
 * extensible starter banner -> (vendor, product, version) map, used to
 * write CPE/<port> once a product+version is confidently parsed out of a
 * banner or HTTP `Server:` header.
 *
 * IMPORTANT (flagged for M7/the schema work): the vendor/product tokens in
 * cpe_map.c's rule table are a best-effort starting point for Milestone 4
 * detection, not a validated extract from the authoritative NVD CPE
 * dictionary -- db-schema.md §10.1 explicitly calls this "the
 * detection-rules mapping db-schema §10.1 expects the engine to own" and
 * assigns validating/correcting it against the real dictionary to the M7
 * DB/CVE ingestion work. Nothing here queries a CVE database or performs
 * any matching -- this file only ever WRITES a CPE/<port> KB fact; the
 * CVE-matching consumer of that fact is engine-side C in a future
 * milestone (kb-schema.md §7.7's "This is the join key the schema work's schema
 * must index on").
 *
 * Kept private to src/net (same-directory quote-include). */

#ifdef __cplusplus
extern "C" {
#endif

/* Scans exactly `text_len` bytes at `text` (need not be NUL-terminated;
 * this never reads text[text_len] or beyond) for a recognized product
 * marker (e.g. "OpenSSH_", "nginx/"). If found AND a version token of at
 * least one valid character (alphanumeric, '.', '_', '-') immediately
 * follows the marker, builds a CPE 2.3 formatted string
 * ("cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*") and writes it
 * to CPE/<port>. Deliberately conservative: if a marker is found but no
 * usable version token follows it, NO CPE is written (kb-schema.md §7.7:
 * "absent if the version could not be determined precisely enough for a
 * safe CPE (avoid false CPEs from a bare banner guess)").
 *
 * Returns true iff a CPE was written, false otherwise (no matching
 * marker, or a marker matched but no usable version followed, or the KB
 * write itself failed). Never crashes or reads out of bounds on
 * malformed/oversized/garbage `text` -- every scan below is index-bounded
 * against `text_len`. */
bool cytadel_cpe_map_and_write(cytadel_kb_t *kb, uint16_t port, const char *text, size_t text_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_NET_CPE_MAP_H */
