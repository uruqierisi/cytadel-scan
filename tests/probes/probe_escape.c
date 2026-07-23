/* Independent probe of the report escapers — my own payloads, not the suite's.
 * Focus: context-breaking attacks proven neutralized in their OWN context. */
#include <stdio.h>
#include <string.h>
#include "cytadel/report/escape.h"

static int fails = 0;

/* returns the escaped output as a NUL-terminated C string (payloads have no NUL) */
static const char *esc(int ctx, const char *in, char *dst, size_t dstsz) {
    cytadel_report_buf_t b;
    cytadel_report_buf_init(&b);
    bool ok = false;
    switch (ctx) {
    case 0: ok = cytadel_escape_html_body(&b, in, strlen(in)); break;
    case 1: ok = cytadel_escape_html_attr(&b, in, strlen(in)); break;
    case 2: ok = cytadel_escape_url(&b, in, strlen(in)); break;
    case 3: ok = cytadel_escape_json(&b, in, strlen(in)); break;
    }
    if (!ok || b.data == NULL) { cytadel_report_buf_free(&b); return "<ALLOC-FAIL>"; }
    size_t n = b.len < dstsz - 1 ? b.len : dstsz - 1;
    memcpy(dst, b.data, n); dst[n] = 0;
    cytadel_report_buf_free(&b);
    return dst;
}

/* assert the escaped output does NOT contain `needle` (a live break) */
static void deny(int ctx, const char *in, const char *needle, const char *why) {
    char out[4096];
    const char *e = esc(ctx, in, out, sizeof out);
    int bad = (strstr(e, needle) != NULL);
    if (bad) fails++;
    printf("%-8s ctx=%d in=%-28s -> %-30s [deny '%s': %s]\n",
           bad ? "LEAK!!" : "ok", ctx, in, e, needle, why);
}
/* assert the escaped output DOES contain `needle` (preserved / correct form) */
static void want(int ctx, const char *in, const char *needle, const char *why) {
    char out[4096];
    const char *e = esc(ctx, in, out, sizeof out);
    int bad = (strstr(e, needle) == NULL);
    if (bad) fails++;
    printf("%-8s ctx=%d in=%-28s -> %-30s [want '%s': %s]\n",
           bad ? "MISS!!" : "ok", ctx, in, e, needle, why);
}

int main(void) {
    puts("=== html_body: structure + comment breaks (ctx 0) ===");
    deny(0, "</td></tr>", "</td>", "table structure break");
    deny(0, "x-->y", "-->", "comment close");
    deny(0, "<script>alert(1)</script>", "<script>", "tag inject");
    deny(0, "a<svg/onload=1>", "<svg", "svg tag");

    puts("\n=== html_attr: quote breakout (ctx 1) ===");
    deny(1, "\" onmouseover=x", "\"", "double-quote breakout");
    deny(1, "' onfocus=x", "'", "single-quote breakout");
    deny(1, "\"><script>", "\">", "quote+tag breakout");

    puts("\n=== url: scheme allowlist (ctx 2) ===");
    deny(2, "javascript:alert(1)", "javascript:", "js scheme");
    deny(2, "JaVaScRiPt:alert(1)", "avaScript:", "js scheme mixed case");
    deny(2, "\tjavascript:alert(1)", "javascript:", "TAB-obfuscated js");
    deny(2, "java\nscript:alert(1)", "javascript:", "newline-split js");
    deny(2, "data:text/html,<script>", "data:", "data uri");
    deny(2, "vbscript:msgbox(1)", "vbscript:", "vbscript");
    deny(2, "&#106;avascript:alert(1)", "&", "W1: raw & (entity) must be %26");
    want(2, "&#106;avascript:alert(1)", "%26", "W1: & -> %26");
    deny(2, "//evil.com/x", "//evil.com", "S1: protocol-relative rejected");
    want(2, "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "https://nvd.nist.gov", "real link preserved");
    want(2, "/report.html", "/report.html", "single-slash relative kept");

    puts("\n=== json: JSON rules not HTML (ctx 3) ===");
    want(3, "<script>alert(1)</script>", "<script>", "literal < kept (not &lt;)");
    deny(3, "a\"b", "a\"b", "raw quote must be escaped");
    want(3, "a\"b", "a\\\"b", "quote -> backslash-quote");

    printf("\nLEAKS/MISSES: %d\n", fails);
    return fails != 0;
}
