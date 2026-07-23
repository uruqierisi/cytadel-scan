#include "cytadel/report/escape.h"

#include <string.h>

#include "cytadel_test.h"

/* Milestone 8 slice 1: hostile, context-breaking fixtures for the four
 * report-output escapers (see include/cytadel/report/escape.h for the
 * threat model). Written BEFORE the implementation, per this project's
 * TDD/anti-"green-but-false" method -- each test asserts neutralization in
 * the SPECIFIC context the payload attacks (not generic tag-stripping),
 * and the three tests marked REVERT-PROOF below were each independently
 * confirmed to FAIL when the specific protection they check was removed
 * from escape.c (see this milestone's write-up for the exact diff/output).
 */

/* True iff needle (a trusted, NUL-terminated literal) occurs anywhere in
 * hay[0..hay_len) as a raw byte sequence. Bounded by hay_len, never by a
 * NUL byte in hay -- hay may itself contain embedded NULs. */
static bool contains_bytes(const char *hay, size_t hay_len, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || needle_len > hay_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= hay_len; i++) {
        if (memcmp(hay + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------- */
/* Context 1: html_body                                                 */
/* ------------------------------------------------------------------- */

static void test_html_body_amp_lt_gt_basic(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "a & b < c > d";
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "a &amp; b &lt; c &gt; d");

    cytadel_report_buf_free(&out);
}

/* Gate-1 fixture: </td></tr> through html_body -> no literal </td> or
 * </tr> survives; a live table structure cannot be broken. */
static void test_html_body_table_close_neutralized(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "</td></tr>";
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, strlen(in)));

    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "</td>"));
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "</tr>"));
    CYTADEL_ASSERT_STREQ(out.data, "&lt;/td&gt;&lt;/tr&gt;");

    cytadel_report_buf_free(&out);
}

/* Gate-1 fixture: --> through html_body -> no literal --> survives; an
 * HTML comment cannot be closed/escaped by attacker-controlled evidence. */
static void test_html_body_comment_close_neutralized(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "<!-- comment -->";
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, strlen(in)));

    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "-->"));
    CYTADEL_ASSERT_STREQ(out.data, "&lt;!-- comment --&gt;");

    cytadel_report_buf_free(&out);
}

/* Gate-1 fixture: <script>...</script> through html_body -> fully escaped. */
static void test_html_body_script_tag_fully_escaped(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "<script>alert(1)</script>";
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, strlen(in)));

    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "<script>"));
    CYTADEL_ASSERT_STREQ(out.data, "&lt;script&gt;alert(1)&lt;/script&gt;");

    cytadel_report_buf_free(&out);
}

/* html_body does NOT need to touch quotes -- meaningless outside an
 * attribute. Documents the boundary against cytadel_escape_html_attr. */
static void test_html_body_does_not_escape_quotes(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "he said \"hi\" and 'bye'";
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, in);

    cytadel_report_buf_free(&out);
}

/* ------------------------------------------------------------------- */
/* Context 2: html_attr                                                 */
/* ------------------------------------------------------------------- */

/* Gate-1 fixture (REVERT-PROOF a): " onmouseover=x through html_attr -> no
 * un-escaped " survives; placed inside title="...esc..." the attribute
 * cannot be broken out of.
 *
 * Revert-proof: with the `case '"': if (escape_quotes) ...` branch in
 * html_escape_one() temporarily replaced by a fall-through to the literal
 * default (i.e. html_attr stops escaping '"' and behaves like html_body),
 * this test FAILS -- rebuilt and re-ran under that mutation, out.data
 * became `" onmouseover=x` (the raw '"' byte, 0x22, present at offset 0),
 * tripping the `!contains_bytes(..., "\"")` assertion below. Reverted
 * immediately after confirming the failure; see this milestone's
 * write-up for the exact captured assertion-failure line. */
static void test_html_attr_quote_breakout_neutralized(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "\" onmouseover=x";
    CYTADEL_ASSERT(cytadel_escape_html_attr(&out, in, strlen(in)));

    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "\""));
    CYTADEL_ASSERT_STREQ(out.data, "&quot; onmouseover=x");

    cytadel_report_buf_free(&out);
}

static void test_html_attr_single_quote_escaped(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "' onmouseover='x";
    CYTADEL_ASSERT(cytadel_escape_html_attr(&out, in, strlen(in)));

    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "'"));
    CYTADEL_ASSERT_STREQ(out.data, "&#39; onmouseover=&#39;x");

    cytadel_report_buf_free(&out);
}

/* html_attr is a strict superset of html_body's escaping -- &/</> are
 * still escaped too. */
static void test_html_attr_also_escapes_angle_brackets(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "<b>&\"'";
    CYTADEL_ASSERT(cytadel_escape_html_attr(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "&lt;b&gt;&amp;&quot;&#39;");

    cytadel_report_buf_free(&out);
}

/* ------------------------------------------------------------------- */
/* Context 3: url                                                       */
/* ------------------------------------------------------------------- */

/* Gate-1 fixture (REVERT-PROOF b): javascript:alert(1) through url -> the
 * inert placeholder "#", never a string beginning "javascript".
 *
 * Revert-proof: with the scheme-allowlist check in cytadel_escape_url()
 * temporarily replaced by `bool allowed = true;` unconditionally (bypassing
 * the http/https allowlist entirely), this test FAILS -- rebuilt and
 * re-ran under that mutation, out.data became `javascript:alert(1)`
 * (percent-encoded, but still a live javascript: URI, starting with
 * "javascript"), tripping the CYTADEL_ASSERT_STREQ(out.data, "#") below.
 * Reverted immediately after confirming the failure. */
static void test_url_javascript_scheme_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "javascript:alert(1)";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));

    CYTADEL_ASSERT_STREQ(out.data, "#");
    CYTADEL_ASSERT(out.data[0] != 'j');

    cytadel_report_buf_free(&out);
}

static void test_url_javascript_scheme_case_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "JavaScript:alert(1)";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

static void test_url_javascript_leading_space_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "  javascript:alert(1)";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

/* Leading/embedded TAB and CR/LF around a dangerous scheme (the same
 * whitespace class real URL parsers strip) must also be rejected, not
 * merely bare spaces. */
static void test_url_javascript_leading_control_whitespace_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = "\t\n javascript:alert(1)";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, sizeof(in) - 1));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

static void test_url_data_scheme_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "data:text/html,<script>alert(1)</script>";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

static void test_url_vbscript_scheme_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "vbscript:msgbox(1)";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

static void test_url_file_scheme_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "file:///etc/passwd";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

/* NUL-obfuscated variant: an embedded NUL byte sits between "java" and
 * "script:alert(1)". A naive strlen()-based scheme check could see only
 * the harmless-looking "java" prefix; this module takes (ptr, len) and
 * must reject the WHOLE value outright because of the embedded control
 * byte, never silently truncate at it and call the prefix safe. */
static void test_url_nul_obfuscated_scheme_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = "java\0script:alert(1)";
    size_t in_len = sizeof(in) - 1; /* keep the embedded NUL, drop only the trailing one */
    CYTADEL_ASSERT_EQ(in_len, (size_t)20);

    CYTADEL_ASSERT(cytadel_escape_url(&out, in, in_len));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

/* Legit https URL (a real NVD CVE reference link) must be preserved
 * working, proving the allowlist does not break real links. */
static void test_url_legit_https_preserved(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, in);

    cytadel_report_buf_free(&out);
}

static void test_url_legit_http_preserved(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "http://example.com/advisory?id=1";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, in);

    cytadel_report_buf_free(&out);
}

/* A clearly-relative URL (no scheme colon at all) is preserved. */
static void test_url_relative_preserved(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "/report.html?id=42#frag";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, in);

    cytadel_report_buf_free(&out);
}

/* Dangerous characters inside an otherwise-relative URL are still
 * percent-encoded -- the allowlist check does not exempt a relative URL
 * from character-level neutralization. */
static void test_url_relative_percent_encodes_dangerous_chars(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    /* W1: '&' is now percent-encoded to %26 too (self-contained url output). */
    const char *in = "/search?q=<script>&name=\"x\"";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "/search?q=%3Cscript%3E%26name=%22x%22");

    cytadel_report_buf_free(&out);
}

static void test_url_empty_is_harmless(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    CYTADEL_ASSERT(cytadel_escape_url(&out, "", 0));
    CYTADEL_ASSERT_EQ(out.len, (size_t)0);

    cytadel_report_buf_free(&out);
}

/* ------------------------------------------------------------------- */
/* Context 4: json                                                      */
/* ------------------------------------------------------------------- */

/* Gate-1 fixture (REVERT-PROOF c): the SAME <script>...</script> payload
 * through json -> JSON-escaped only (quotes/backslash/control escaped);
 * the literal characters <script> are PRESENT (proving JSON != HTML
 * escaping).
 *
 * Revert-proof: with cytadel_escape_json() temporarily made to also
 * html-escape '<'/'>' (i.e. reusing html_escape_one() instead of passing
 * them through), this test FAILS -- rebuilt and re-ran under that
 * mutation, out.data became `&lt;script&gt;alert(1)&lt;/script&gt;`
 * instead of the literal `<script>alert(1)</script>`, tripping both the
 * `contains_bytes(..., "<script>")` assertion and the exact-match
 * assertion below. Reverted immediately after confirming the failure. */
static void test_json_script_tag_json_escaped_not_html_escaped(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "<script>alert(1)</script>";
    CYTADEL_ASSERT(cytadel_escape_json(&out, in, strlen(in)));

    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "<script>"));
    CYTADEL_ASSERT_STREQ(out.data, in); /* no HTML entity introduced at all */

    cytadel_report_buf_free(&out);
}

static void test_json_quote_backslash_newline_escaped(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char *in = "He said \"hi\"\nback\\slash";
    CYTADEL_ASSERT(cytadel_escape_json(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "He said \\\"hi\\\"\\nback\\\\slash");

    cytadel_report_buf_free(&out);
}

static void test_json_control_chars_escaped_as_u_sequences(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = {(char)0x01, (char)0x1F, (char)0x00, '\b', '\f', '\r', '\t'};
    CYTADEL_ASSERT(cytadel_escape_json(&out, in, sizeof(in)));
    CYTADEL_ASSERT_STREQ(out.data, "\\u0001\\u001f\\u0000\\b\\f\\r\\t");

    cytadel_report_buf_free(&out);
}

/* Bytes >= 0x20 (including 0x7F and non-ASCII) pass through unescaped --
 * RFC 8259 does not require escaping them. */
static void test_json_high_bytes_pass_through(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = {(char)0x7F, (char)0x80, (char)0xFF, 'z'};
    CYTADEL_ASSERT(cytadel_escape_json(&out, in, sizeof(in)));
    CYTADEL_ASSERT_EQ(out.len, sizeof(in));
    CYTADEL_ASSERT(memcmp(out.data, in, sizeof(in)) == 0);

    cytadel_report_buf_free(&out);
}

/* ------------------------------------------------------------------- */
/* Cross-cutting hostile-byte robustness (run under ASan/UBSan).        */
/* ------------------------------------------------------------------- */

static void test_hostile_bytes_html_body_no_crash(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = {0x00, 0x01, 0x1F, (char)0x7F, (char)0x80, (char)0xFF};
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, sizeof(in)));
    CYTADEL_ASSERT_EQ(out.len, sizeof(in));
    CYTADEL_ASSERT(memcmp(out.data, in, sizeof(in)) == 0);

    cytadel_report_buf_free(&out);
}

static void test_hostile_bytes_html_attr_no_crash(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = {0x00, 0x01, 0x1F, (char)0x7F, (char)0x80, (char)0xFF};
    CYTADEL_ASSERT(cytadel_escape_html_attr(&out, in, sizeof(in)));
    CYTADEL_ASSERT_EQ(out.len, sizeof(in));
    CYTADEL_ASSERT(memcmp(out.data, in, sizeof(in)) == 0);

    cytadel_report_buf_free(&out);
}

static void test_hostile_bytes_url_no_crash(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    /* Contains an embedded NUL -> must reject to "#", not crash. */
    const char in[] = {0x00, 0x01, 0x1F, (char)0x7F, (char)0x80, (char)0xFF};
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, sizeof(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");

    cytadel_report_buf_free(&out);
}

static void test_hostile_bytes_json_no_crash(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    const char in[] = {0x00, 0x01, 0x1F, (char)0x7F, (char)0x80, (char)0xFF};
    CYTADEL_ASSERT(cytadel_escape_json(&out, in, sizeof(in)));
    CYTADEL_ASSERT_STREQ(out.data, "\\u0000\\u0001\\u001f\x7F\x80\xFF");

    cytadel_report_buf_free(&out);
}

static void test_hostile_bytes_empty_input_all_contexts(void) {
    cytadel_report_buf_t out;

    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, "", 0));
    CYTADEL_ASSERT_EQ(out.len, (size_t)0);
    cytadel_report_buf_free(&out);

    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_html_attr(&out, "", 0));
    CYTADEL_ASSERT_EQ(out.len, (size_t)0);
    cytadel_report_buf_free(&out);

    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_url(&out, "", 0));
    CYTADEL_ASSERT_EQ(out.len, (size_t)0);
    cytadel_report_buf_free(&out);

    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_json(&out, "", 0));
    CYTADEL_ASSERT_EQ(out.len, (size_t)0);
    cytadel_report_buf_free(&out);
}

/* Very long input: forces multiple buffer-growth doublings and exercises
 * the "reserve whole entity before writing any of it" invariant at many
 * successive capacity boundaries. Every single '&' becomes "&amp;". */
static void test_hostile_bytes_very_long_input_html_body(void) {
    enum { N = 50000 };
    char *in = malloc(N);
    CYTADEL_ASSERT(in != NULL);
    memset(in, '&', N);

    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, in, N));
    CYTADEL_ASSERT_EQ(out.len, (size_t)N * 5);
    CYTADEL_ASSERT(out.cap >= out.len + 1);

    /* Spot-check the whole thing is really N repetitions of "&amp;", not
     * just the right total length. */
    for (size_t i = 0; i < (size_t)N; i++) {
        CYTADEL_ASSERT(memcmp(out.data + i * 5, "&amp;", 5) == 0);
    }

    cytadel_report_buf_free(&out);
    free(in);
}

/* ------------------------------------------------------------------- */
/* cytadel_report_buf_t plumbing: literal-append interleaving, double-free. */
/* ------------------------------------------------------------------- */

static void test_buf_interleaves_literals_and_escapes(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);

    CYTADEL_ASSERT(cytadel_report_buf_append_lit(&out, "<td>"));
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, "<b>", 3));
    CYTADEL_ASSERT(cytadel_report_buf_append_lit(&out, "</td>"));

    CYTADEL_ASSERT_STREQ(out.data, "<td>&lt;b&gt;</td>");

    cytadel_report_buf_free(&out);
}

static void test_buf_free_is_idempotent_and_free_of_fresh_init_is_safe(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    cytadel_report_buf_free(&out); /* never appended to -- must not crash */
    cytadel_report_buf_free(&out); /* second free -- must not double-free */

    cytadel_report_buf_init(&out);
    CYTADEL_ASSERT(cytadel_escape_html_body(&out, "x", 1));
    cytadel_report_buf_free(&out);
    cytadel_report_buf_free(&out); /* second free after real use -- must not double-free */
}

/* W1 (XSS audit): url() must percent-encode '&' to %26 so a numeric HTML
 * char-reference cannot survive url() and be browser-decoded back into a
 * javascript: scheme once placed in an href. Revert-proof: re-add `case '&':`
 * to url_is_safe_char and this fails (the literal "&#106;" survives). */
static void test_url_ampersand_percent_encoded(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    const char *in = "&#106;avascript:alert(1)"; /* no scheme colon -> "relative" */
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    /* The raw entity introducer must be gone; '&' must be %26. */
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "&#106;"));
    CYTADEL_ASSERT(!contains_bytes(out.data, out.len, "&"));
    CYTADEL_ASSERT(contains_bytes(out.data, out.len, "%26"));
    cytadel_report_buf_free(&out);
}

/* S1 (XSS audit): a scheme-less protocol-relative "//host" (and "/\\host")
 * navigates cross-origin -> rejected to "#". Revert-proof: remove the "//"
 * branch and this fails ("//evil.com/x" is emitted as a live relative URL). */
static void test_url_protocol_relative_rejected(void) {
    cytadel_report_buf_t out;
    cytadel_report_buf_init(&out);
    const char *in = "//evil.com/x";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in, strlen(in)));
    CYTADEL_ASSERT_STREQ(out.data, "#");
    cytadel_report_buf_free(&out);

    cytadel_report_buf_init(&out);
    const char *in2 = "/\\evil.com/x";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in2, strlen(in2)));
    CYTADEL_ASSERT_STREQ(out.data, "#");
    cytadel_report_buf_free(&out);

    /* A genuine single-slash relative path is still accepted. */
    cytadel_report_buf_init(&out);
    const char *in3 = "/report.html";
    CYTADEL_ASSERT(cytadel_escape_url(&out, in3, strlen(in3)));
    CYTADEL_ASSERT_STREQ(out.data, "/report.html");
    cytadel_report_buf_free(&out);
}

/* W3 (XSS audit): the buffer's "reserve room for the trailing NUL" invariant
 * (base = len + 1) must hold at a growth boundary. Emit output whose cumulative
 * length lands exactly on a power-of-two capacity (64, 4096) of PLAIN bytes
 * (no expansion), which is where an under-reservation-by-one would write one
 * past the allocation. Must be ASan-clean. Revert-proof: drop the +1 in
 * buf reserve and this trips a heap-buffer-overflow under ASan. */
static void test_buf_nul_reservation_at_growth_boundary(void) {
    const size_t sizes[] = {63, 64, 65, 127, 128, 255, 256, 4095, 4096, 4097};
    for (size_t s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
        char *plain = malloc(sizes[s]);
        CYTADEL_ASSERT(plain != NULL);
        memset(plain, 'a', sizes[s]); /* 'a' is not escaped in any context */
        cytadel_report_buf_t out;
        cytadel_report_buf_init(&out);
        CYTADEL_ASSERT(cytadel_escape_html_body(&out, plain, sizes[s]));
        CYTADEL_ASSERT_EQ(out.len, sizes[s]);
        CYTADEL_ASSERT(out.data[out.len] == '\0'); /* NUL slot present */
        cytadel_report_buf_free(&out);
        free(plain);
    }
}

int main(void) {
    test_html_body_amp_lt_gt_basic();
    test_html_body_table_close_neutralized();
    test_html_body_comment_close_neutralized();
    test_html_body_script_tag_fully_escaped();
    test_html_body_does_not_escape_quotes();

    test_html_attr_quote_breakout_neutralized();
    test_html_attr_single_quote_escaped();
    test_html_attr_also_escapes_angle_brackets();

    test_url_javascript_scheme_rejected();
    test_url_javascript_scheme_case_rejected();
    test_url_javascript_leading_space_rejected();
    test_url_javascript_leading_control_whitespace_rejected();
    test_url_data_scheme_rejected();
    test_url_vbscript_scheme_rejected();
    test_url_file_scheme_rejected();
    test_url_nul_obfuscated_scheme_rejected();
    test_url_legit_https_preserved();
    test_url_legit_http_preserved();
    test_url_relative_preserved();
    test_url_relative_percent_encodes_dangerous_chars();
    test_url_empty_is_harmless();
    test_url_ampersand_percent_encoded();
    test_url_protocol_relative_rejected();
    test_buf_nul_reservation_at_growth_boundary();

    test_json_script_tag_json_escaped_not_html_escaped();
    test_json_quote_backslash_newline_escaped();
    test_json_control_chars_escaped_as_u_sequences();
    test_json_high_bytes_pass_through();

    test_hostile_bytes_html_body_no_crash();
    test_hostile_bytes_html_attr_no_crash();
    test_hostile_bytes_url_no_crash();
    test_hostile_bytes_json_no_crash();
    test_hostile_bytes_empty_input_all_contexts();
    test_hostile_bytes_very_long_input_html_body();

    test_buf_interleaves_literals_and_escapes();
    test_buf_free_is_idempotent_and_free_of_fresh_init_is_safe();

    CYTADEL_TEST_PASS();
}
