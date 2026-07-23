/* Independent probe of cytadel_cpe_match_evaluate — my cases, not the agent's table.
 * Focus: advisory truth, off-by-one on every bound, UNDECIDABLE propagation +
 * short-circuit order-independence, malformed guard, and the slice-A carryover
 * (pre-release UNDECIDABLE must surface, not silently become NO_MATCH). */
#include <stdio.h>
#include <string.h>
#include "cytadel/match/cpe_match.h"

#define S(x) (x), ((x) ? strlen(x) : 0)

static const char *N(cytadel_cpe_match_t v) {
    switch (v) {
    case CYTADEL_CPE_NO_MATCH: return "NO_MATCH";
    case CYTADEL_CPE_MATCH: return "MATCH";
    case CYTADEL_CPE_UNDECIDABLE: return "UNDECIDABLE";
    default: return "MALFORMED";
    }
}

static int fails = 0;

/* build a row from strings; NULL -> empty/unbounded */
static cytadel_cpe_match_row_t R(const char *ver, const char *si, const char *se, const char *ei,
                                  const char *ee, int vuln) {
    cytadel_cpe_match_row_t r;
    memset(&r, 0, sizeof r);
    r.version = ver ? ver : ""; r.version_len = ver ? strlen(ver) : 0;
    r.version_start_including = si ? si : ""; r.version_start_including_len = si ? strlen(si) : 0;
    r.version_start_excluding = se ? se : ""; r.version_start_excluding_len = se ? strlen(se) : 0;
    r.version_end_including = ei ? ei : ""; r.version_end_including_len = ei ? strlen(ei) : 0;
    r.version_end_excluding = ee ? ee : ""; r.version_end_excluding_len = ee ? strlen(ee) : 0;
    r.vulnerable = vuln;
    return r;
}

static void chk(cytadel_cpe_match_row_t row, const char *det, cytadel_cpe_match_t want,
                const char *why) {
    cytadel_cpe_match_t got = cytadel_cpe_match_evaluate(&row, det, det ? strlen(det) : 0);
    int bad = (got != want);
    if (bad) fails++;
    printf("%-8s det=%-16s -> %-12s (want %-12s) [%s]\n", bad ? "MISMATCH" : "ok",
           det ? det : "(null)", N(got), N(want), why);
}

int main(void) {
    puts("=== REAL ADVISORY: Heartbleed CVE-2014-0160 (1.0.1 .. 1.0.1f affected, 1.0.1g fixed) ===");
    /* modeled as versionStartIncluding=1.0.1, versionEndIncluding=1.0.1f */
    cytadel_cpe_match_row_t hb = R("*", "1.0.1", NULL, "1.0.1f", NULL, 1);
    chk(hb, "1.0.1", CYTADEL_CPE_MATCH, "lower bound inclusive");
    chk(hb, "1.0.1c", CYTADEL_CPE_MATCH, "mid-range");
    chk(hb, "1.0.1f", CYTADEL_CPE_MATCH, "upper bound inclusive");
    chk(hb, "1.0.1g", CYTADEL_CPE_NO_MATCH, "FIXED VERSION - off-by-one killer");
    chk(hb, "1.0.0", CYTADEL_CPE_NO_MATCH, "below lower bound");

    puts("\n=== REAL ADVISORY: regreSSHion CVE-2024-6387 (8.5p1 <= v < 9.8p1) ===");
    cytadel_cpe_match_row_t rs = R("*", "8.5p1", NULL, NULL, "9.8p1", 1);
    chk(rs, "8.5p1", CYTADEL_CPE_MATCH, "lower inclusive");
    chk(rs, "9.7", CYTADEL_CPE_MATCH, "inside");
    chk(rs, "9.8p1", CYTADEL_CPE_NO_MATCH, "upper EXCLUSIVE - off-by-one killer");
    chk(rs, "8.4p1", CYTADEL_CPE_NO_MATCH, "just below lower");
    /* second band: v < 4.4p1 */
    cytadel_cpe_match_row_t rs2 = R("*", NULL, NULL, NULL, "4.4p1", 1);
    chk(rs2, "4.3", CYTADEL_CPE_MATCH, "second band inside");
    chk(rs2, "4.4p1", CYTADEL_CPE_NO_MATCH, "second band exclusive upper");

    puts("\n=== OFF-BY-ONE ON EACH SINGLE BOUND ===");
    chk(R("*", "2.0", NULL, NULL, NULL, 1), "2.0", CYTADEL_CPE_MATCH, "startIncluding: equal IS in");
    chk(R("*", "2.0", NULL, NULL, NULL, 1), "1.9", CYTADEL_CPE_NO_MATCH, "startIncluding: below out");
    chk(R("*", NULL, "2.0", NULL, NULL, 1), "2.0", CYTADEL_CPE_NO_MATCH, "startExcluding: equal OUT");
    chk(R("*", NULL, "2.0", NULL, NULL, 1), "2.1", CYTADEL_CPE_MATCH, "startExcluding: above in");
    chk(R("*", NULL, NULL, "2.0", NULL, 1), "2.0", CYTADEL_CPE_MATCH, "endIncluding: equal IS in");
    chk(R("*", NULL, NULL, "2.0", NULL, 1), "2.1", CYTADEL_CPE_NO_MATCH, "endIncluding: above out");
    chk(R("*", NULL, NULL, NULL, "2.0", 1), "2.0", CYTADEL_CPE_NO_MATCH, "endExcluding: equal OUT");
    chk(R("*", NULL, NULL, NULL, "2.0", 1), "1.9", CYTADEL_CPE_MATCH, "endExcluding: below in");

    puts("\n=== BOUND COMBINATIONS (must AND; stricter wins) ===");
    chk(R("*", "1.0", "1.5", NULL, NULL, 1), "1.2", CYTADEL_CPE_NO_MATCH, "both starts: 1.2 fails >1.5");
    chk(R("*", "1.0", "1.5", NULL, NULL, 1), "1.6", CYTADEL_CPE_MATCH, "both starts: 1.6 passes both");
    chk(R("*", NULL, NULL, "3.0", "2.0", 1), "2.5", CYTADEL_CPE_NO_MATCH, "both ends: 2.5 fails <2.0");
    chk(R("*", NULL, NULL, "3.0", "2.0", 1), "1.9", CYTADEL_CPE_MATCH, "both ends: 1.9 passes both");
    chk(R("*", "1.0", NULL, NULL, "2.0", 1), "1.5", CYTADEL_CPE_MATCH, "all-four style range");

    puts("\n=== MALFORMED / vulnerable=0 / EXACT ===");
    chk(R("*", NULL, NULL, NULL, NULL, 1), "9.9.9", CYTADEL_CPE_MALFORMED_ROW, "all bounds empty");
    chk(R("*", "1.0", NULL, NULL, NULL, 0), "2.0", CYTADEL_CPE_NO_MATCH, "vulnerable=0");
    chk(R("1.2.3", NULL, NULL, NULL, NULL, 1), "1.2.3", CYTADEL_CPE_MATCH, "exact row equal");
    chk(R("1.2.3", NULL, NULL, NULL, NULL, 1), "1.2.4", CYTADEL_CPE_NO_MATCH, "exact row differ");
    chk(R("1.2.3", NULL, NULL, NULL, NULL, 0), "1.2.3", CYTADEL_CPE_NO_MATCH, "exact row vuln=0");
    /* zero-pad-equal carried from slice A */
    chk(R("2.4", NULL, NULL, NULL, NULL, 1), "2.4.0", CYTADEL_CPE_MATCH, "exact 2.4 vs 2.4.0");

    puts("\n=== SLICE-A CARRYOVER: pre-release UNDECIDABLE MUST SURFACE ===");
    puts("    (if these say NO_MATCH the false negative is back through the back door)");
    chk(R("*", NULL, NULL, NULL, "1.0.0", 1), "1.0.0-cr1", CYTADEL_CPE_UNDECIDABLE, "unknown prerelease vs endExcluding");
    chk(R("*", NULL, NULL, NULL, "1.0.0", 1), "1.0.0-M1", CYTADEL_CPE_UNDECIDABLE, "maven milestone");
    chk(R("*", NULL, NULL, NULL, "1.0.0", 1), "1.0.0-alpha", CYTADEL_CPE_MATCH, "KNOWN prerelease is decidable, < 1.0.0");
    chk(R("*", NULL, NULL, NULL, "1.0.0", 1), "1.0.0-ga", CYTADEL_CPE_NO_MATCH, "ga == release, not < 1.0.0");

    puts("\n=== SHORT-CIRCUIT ORDER INDEPENDENCE ===");
    puts("    definite-fail + undecidable => NO_MATCH (the definite failure settles it)");
    /* detected 0.5 definitely fails startIncluding 1.0; endExcluding is garbage => undecidable */
    chk(R("*", "1.0", NULL, NULL, "@@@", 1), "0.5", CYTADEL_CPE_NO_MATCH, "fail-first then undecidable");
    /* same row content, bounds swapped in position: undecidable start, definite-fail end */
    chk(R("*", "@@@", NULL, NULL, "1.0", 1), "5.0", CYTADEL_CPE_NO_MATCH, "undecidable-first then fail");
    puts("    all decidable bounds PASS + one undecidable => UNDECIDABLE");
    chk(R("*", "1.0", NULL, NULL, "@@@", 1), "2.0", CYTADEL_CPE_UNDECIDABLE, "pass + undecidable");
    chk(R("*", "@@@", NULL, NULL, "9.0", 1), "2.0", CYTADEL_CPE_UNDECIDABLE, "undecidable + pass");

    puts("\n=== CPE SPECIAL TOKENS / HOSTILE ===");
    chk(R("-", NULL, NULL, NULL, NULL, 1), "1.0", CYTADEL_CPE_UNDECIDABLE, "version = NA '-'");
    chk(R("*", "1.0", NULL, NULL, NULL, 1), "", CYTADEL_CPE_UNDECIDABLE, "empty detected");
    chk(R("*", "1.0", NULL, NULL, NULL, 1), NULL, CYTADEL_CPE_UNDECIDABLE, "NULL detected");
    {   /* NULL row must not crash */
        cytadel_cpe_match_t g = cytadel_cpe_match_evaluate(NULL, S("1.0"));
        printf("%-8s NULL row -> %s\n", g == CYTADEL_CPE_UNDECIDABLE ? "ok" : "CHECK", N(g));
    }
    {   /* embedded NUL in detected version */
        const char nul[] = "1.0\0evil";
        cytadel_cpe_match_row_t r = R("*", "1.0", NULL, NULL, NULL, 1);
        cytadel_cpe_match_t g = cytadel_cpe_match_evaluate(&r, nul, 8);
        printf("%-8s embedded-NUL detected -> %s\n", g == CYTADEL_CPE_UNDECIDABLE ? "ok" : "CHECK", N(g));
    }

    printf("\nMISMATCHES vs my expectations: %d\n", fails);
    return fails != 0;
}
