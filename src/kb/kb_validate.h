#ifndef CYTADEL_KB_VALIDATE_H
#define CYTADEL_KB_VALIDATE_H

#include <stdbool.h>
#include <stddef.h>

/* Private (src/kb-internal) validation helpers backing kb.c's
 * cytadel_kb_set_*()/cytadel_kb_key_is_valid() public entry points. Split
 * out of kb.c so the bounds-checked string-scanning logic (key charset,
 * UTF-8, embedded-NUL) is easy to unit-reason about and test in isolation
 * from the hash table itself. Not installed under include/cytadel/kb/ --
 * only kb.c in this directory includes this, via the same-directory
 * quote-include convention already used by src/net's private headers (see
 * src/net/CMakeLists.txt's header comment). */

#ifdef __cplusplus
extern "C" {
#endif

/* Implements cytadel_kb_key_is_valid() from include/cytadel/kb/kb.h --
 * kb-schema.md SS2. Declared here (not just defined in kb.c) so kb.c can
 * call it and tests can exercise it indirectly through the public
 * wrapper; kept in this file for cohesion with the other validators
 * below. */
bool cytadel_kb_validate_key(const char *key);

/* Bounds-checked UTF-8 validity check over exactly `len` bytes starting at
 * `buf` (buf need not be NUL-terminated; this never reads buf[len] or
 * beyond). Rejects overlong encodings, encoded surrogate code points
 * (U+D800-U+DFFF), and code points beyond U+10FFFF -- i.e. this is strict
 * UTF-8 validation, not merely "every byte is < 0x80 or in a continuation
 * shape". Returns true iff every byte in range is part of a valid UTF-8
 * sequence. An empty range (len == 0) is valid UTF-8 (the empty string). */
bool cytadel_kb_validate_utf8(const char *buf, size_t len);

/* Scans exactly `len` bytes starting at `buf` for an embedded NUL
 * (kb-schema.md SS3: "No embedded NUL"). Returns true iff no byte in
 * range is 0x00. */
bool cytadel_kb_validate_no_embedded_nul(const char *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_KB_VALIDATE_H */
