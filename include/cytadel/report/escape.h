#ifndef CYTADEL_REPORT_ESCAPE_H
#define CYTADEL_REPORT_ESCAPE_H

#include <stdbool.h>
#include <stddef.h>

/* Context-correct output escaping for Cytadel's branded HTML/JSON reports
 * (Milestone 8, report-output escaper slice).
 *
 * THREAT MODEL (read this before calling anything in this header): every
 * value a report renders -- banners, HTTP response headers, TLS
 * certificate CN/SAN fields, CVE descriptions pulled from NVD -- is stored
 * RAW in the KB/DB by design (docs/contracts/kb-schema.md, db-schema.md)
 * and is either fully attacker-controlled (the scan target can put
 * anything it wants in a banner or a response header) or untrusted
 * third-party data (NVD). NONE of it is safe to place into an HTML
 * document, an HTML attribute, an href/src URL, or a JSON string value
 * without going through exactly ONE of the four functions below -- chosen
 * to match the exact output context the value is about to be placed into.
 *
 * WHY FOUR FUNCTIONS, NOT ONE "STRIP TAGS" ESCAPER: a value that is safe in
 * one context can be actively dangerous in another. `<` is dangerous in
 * `html_body` (opens a tag) but is not even meaningful in a JSON string
 * (`json` deliberately does NOT touch it, per RFC 8259 -- that is not a
 * bug). A `"` is only dangerous inside a double-quoted attribute value
 * (`html_attr`); `html_body` does not need to escape it at all. A
 * `javascript:` URI is not neutralized by ANY amount of character escaping
 * -- it is a semantically dangerous *value*, not a syntactically unsafe
 * one, which is why `url` is the only escaper here that can refuse to
 * return the caller's input at all. Picking the wrong one of these four
 * for a given call site is itself a vulnerability; see each function's own
 * comment for exactly which context it is for.
 *
 * The report renderer (a later M8 slice) MUST:
 *   - always use double-quoted (never single-quoted, never unquoted) HTML
 *     attribute values, and escape every dynamic one with `html_attr`;
 *   - never build an href/src by string concatenation without routing the
 *     dynamic part through `url` first;
 *   - never take a shortcut and reuse `html_body` output inside an
 *     attribute, or vice versa -- they are not interchangeable.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Growable, always-NUL-terminated output sink every escaper below appends
 * to. Callers own it: initialize with cytadel_report_buf_init(), pass its
 * address to as many escape calls (and/or cytadel_report_buf_append_lit()
 * literal-text appends) as needed to assemble a whole document, then
 * release it with cytadel_report_buf_free(). Never reset automatically by
 * an escape call -- that is what lets a caller interleave escaped dynamic
 * values with static template text in one buffer. */
typedef struct {
    char *data;   /* Heap-owned. NULL iff cap == 0 (freshly initialized, or
                     freed). Always NUL-terminated at data[len] once cap >
                     0 -- safe to treat as a C string as long as the
                     escaped value itself is known not to contain an
                     embedded NUL (html_body/html_attr/url copy raw input
                     bytes through unescaped for anything outside the
                     characters/scheme they explicitly cover, so an input
                     NUL byte passes through as a real NUL in `data`, which
                     WILL confuse strlen()/strcmp() on the result -- read
                     `len` bytes if the input's byte cleanliness is not
                     already known). */
    size_t len;   /* Bytes written so far, NOT counting the trailing NUL. */
    size_t cap;   /* Allocated size of `data` in bytes (0 iff data == NULL). */
} cytadel_report_buf_t;

/* Zero-initializes *buf. Safe to call on stack/heap storage of any prior
 * content -- does not free anything (never call this on a buffer that
 * still owns a live allocation without freeing it first). */
void cytadel_report_buf_init(cytadel_report_buf_t *buf);

/* Frees buf->data (if any) and resets *buf to the same state
 * cytadel_report_buf_init() would produce. Safe to call more than once on
 * the same buffer (second and later calls are no-ops) and safe to call on
 * a buffer that was only ever init()'d and never appended to. buf itself
 * must be non-NULL. */
void cytadel_report_buf_free(cytadel_report_buf_t *buf);

/* Appends a trusted, NUL-terminated C-string literal (template text the
 * report renderer itself wrote, e.g. "<td>") to *out verbatim, with no
 * escaping. NEVER pass attacker-controlled or third-party bytes to this --
 * it exists solely so a caller can interleave static template fragments
 * with escaped dynamic values in the same buffer. Returns false only on
 * allocation failure (OOM); *out is left in its last valid state either
 * way (see the escape functions' own comment for the same guarantee). */
bool cytadel_report_buf_append_lit(cytadel_report_buf_t *out, const char *lit);

/* Every escape function below shares this contract:
 *   - Appends the escaped rendering of in[0..in_len) onto *out. `out` must
 *     already be initialized (cytadel_report_buf_init()) and is never
 *     cleared first.
 *   - `in` is read for EXACTLY in_len bytes. It is never assumed to be
 *     NUL-terminated and is never run through strlen() -- an embedded NUL,
 *     control byte, or non-ASCII byte anywhere in in[0..in_len) is
 *     ordinary input, not a terminator or an error.
 *   - `in_len` may be 0 (in may be NULL in that case).
 *   - Returns false ONLY on allocation failure (OOM). On false, *out is
 *     left exactly as it was after the last fully-completed append --
 *     never a half-written HTML entity, percent-escape, or \u-escape.
 *     Every reservation the escaper needs for one input byte's *entire*
 *     escaped output is made before any byte of that output is written,
 *     so a truncation boundary can never land inside a multi-character
 *     escape sequence.
 *   - On true, exactly one escaped rendering of the whole input has been
 *     appended; the caller is responsible for freeing *out eventually via
 *     cytadel_report_buf_free().
 */

/* Context 1: plain text between HTML tags (e.g. a <td>...</td> body).
 * Escapes only `&` -> `&amp;`, `<` -> `&lt;`, `>` -> `&gt;`. That is
 * sufficient to neutralize this context completely: with no literal `<` or
 * `>` possible in the output, the input can never open a new tag, close an
 * enclosing one (</td>, </tr>, ...), or close an HTML comment (-->) --
 * every one of those requires a literal `<` or `>` that this function
 * makes impossible to produce. Does NOT escape `"`/`'` (meaningless
 * outside an attribute) and must NEVER be used to escape an attribute
 * value -- use cytadel_escape_html_attr for that. */
bool cytadel_escape_html_body(cytadel_report_buf_t *out, const char *in, size_t in_len);

/* Context 2: inside a DOUBLE-QUOTED HTML attribute value, e.g.
 * title="...here...". Escapes everything cytadel_escape_html_body does,
 * PLUS `"` -> `&quot;` and `'` -> `&#39;`. Escaping `"` is what makes it
 * impossible for the value to end the attribute early (the classic
 * `" onmouseover=x` break-out); `'` is escaped too so the same output is
 * also safe if a template is ever mistakenly single-quoted. The report
 * renderer must always use double-quoted attributes with this escaper --
 * never reuse cytadel_escape_html_body's output inside an attribute. */
bool cytadel_escape_html_attr(cytadel_report_buf_t *out, const char *in, size_t in_len);

/* Context 3: a value used as an href/src URL. Character escaping ALONE
 * cannot make an arbitrary string safe here -- `javascript:alert(1)` is a
 * perfectly well-formed URL that no amount of entity/percent-escaping
 * changes into something inert, because the danger is the *scheme*, not
 * any individual character. This function therefore enforces a strict
 * scheme ALLOWLIST before doing any character-level work:
 *   - Bytes are scanned for disallowed raw control bytes first (anything
 *     < 0x20 other than TAB/LF/CR, or 0x7F, anywhere in the input --
 *     including an embedded NUL used to try to smuggle a second URL past a
 *     naive strlen()-based scheme check). Any such byte -> the whole
 *     input is rejected.
 *   - TAB/LF/CR are stripped from anywhere in the string, and leading/
 *     trailing ASCII spaces are trimmed, mirroring how real URL parsers
 *     (WHATWG URL spec) tolerate the exact same whitespace/control tricks
 *     historically used to sneak a `javascript:` URI past naive scheme
 *     checks (e.g. "  javascript:alert(1)").
 *   - What remains is checked for a leading `scheme:` (ALPHA, then
 *     ALPHA/DIGIT/+/-/. , then `:`). If a scheme is present, it is
 *     accepted ONLY if it case-insensitively equals "http" or "https".
 *     ANY other scheme (javascript:, data:, vbscript:, file:, mailto:,
 *     etc.) is rejected. A value with no scheme colon at all (a relative
 *     path/query/fragment, e.g. "/report.html", "?id=1", "#frag") is
 *     treated as a clearly-relative URL and accepted -- EXCEPT a
 *     protocol-relative value beginning "//" or "/\", which is rejected to
 *     "#" (it would navigate cross-origin; S1 from the XSS audit).
 *   - On rejection, this function appends the fixed inert placeholder "#"
 *     -- NEVER any prefix/transformation of the caller's original input --
 *     and returns true (rejection is not an allocation failure).
 *   - On acceptance, the cleaned value is percent-encoded (RFC 3986:
 *     ALPHA/DIGIT/`-._~` and the URL-structural reserved characters pass
 *     through; anything else, including space/control/`"`/`'`/`<`/`>`/
 *     backtick/non-ASCII/`&`, becomes %XX) and appended. NOTE `&` is
 *     percent-encoded to %26 (W1 from the XSS audit): a raw `&` would let a
 *     numeric HTML char-reference like "&#106;avascript:" survive url() and
 *     be decoded back to "javascript:" by the browser once dropped in an
 *     href, so url() output is self-contained and attribute-safe on its own.
 *     Belt-and-suspenders is still the rule for the renderer: place a URL as
 *     html_attr(url(v)) inside a double-quoted href="...".
 */
bool cytadel_escape_url(cytadel_report_buf_t *out, const char *in, size_t in_len);

/* Context 4: a JSON string value (the --format json report path). Escapes
 * strictly per RFC 8259 -- `"`, `\`, and the named short escapes
 * (\b \f \n \r \t), plus every other control byte < 0x20 as \u00XX. This is
 * JSON's own escaping rule, which is DELIBERATELY NOT the same as HTML
 * escaping: `<script>` passes through as the literal 8 characters
 * `<script>` (a `<` is not special in a JSON string) -- only the
 * characters RFC 8259 actually requires escaping are touched. Bytes >=
 * 0x20 (including 0x7F and non-ASCII bytes) pass through unescaped. Never
 * use this to produce HTML output, and never use an HTML escaper to
 * produce a JSON string value -- the two rule sets are not compatible.
 *   RENDERER OBLIGATION (W2 from the XSS audit): because `<` is NOT escaped
 *   here, json() output is safe ONLY as a standalone JSON response/file
 *   (which is the only way `--format json` delivers it). It MUST NOT be
 *   inlined into an HTML <script> block -- a "</script>" hidden in a CVE
 *   description/banner would close the element. If HTML-inlined JSON is ever
 *   needed, that caller must additionally escape `<` as < (valid JSON,
 *   same decoded value) -- do not change this function's standalone contract.
 *
 * ---------------------------------------------------------------------------
 * RENDERER CONTRACT -- what each escaper does NOT defend against (S2 from the
 * XSS audit; picking the wrong escaper for a context is itself the vuln):
 *   html_body : safe ONLY between tags. Does NOT escape " ' (attribute
 *               breakout), or : / (so "javascript:" survives -> unsafe as an
 *               href). Never reuse its output in an attribute or a URL.
 *   html_attr : safe ONLY inside a DOUBLE-QUOTED attribute. Does NOT escape
 *               space or = (so unsafe in an UNQUOTED attribute). Not a URL
 *               validator: "javascript:" passes through -> run url() first.
 *   url       : enforces the http/https/relative scheme allowlist + percent-
 *               encodes (incl. & -> %26). Not an HTML escaper for any other
 *               context; only meaningful as an href/src value.
 *   json      : RFC 8259 only; not an HTML escaper (see the W2 obligation
 *               above). 0x7F and non-ASCII pass through by design.
 * ------------------------------------------------------------------------- */
bool cytadel_escape_json(cytadel_report_buf_t *out, const char *in, size_t in_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_REPORT_ESCAPE_H */
