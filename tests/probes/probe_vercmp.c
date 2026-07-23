/* Independent probe of cytadel_version_compare — my own cases, not the agent's table.
 * Focus: the residual-walk keyword heuristic, real advisory boundaries, antisymmetry. */
#include <stdio.h>
#include <string.h>
#include "cytadel/match/version_compare.h"

static const char *N(cytadel_vercmp_t v) {
    switch (v) {
    case CYTADEL_VERCMP_LESS: return "LESS";
    case CYTADEL_VERCMP_EQUAL: return "EQUAL";
    case CYTADEL_VERCMP_GREATER: return "GREATER";
    default: return "UNDECIDABLE";
    }
}

static int fails = 0;
static int undec = 0;

static void chk(const char *a, const char *b, cytadel_vercmp_t want, const char *why) {
    cytadel_vercmp_t got = cytadel_version_compare(a, strlen(a), b, strlen(b));
    cytadel_vercmp_t rev = cytadel_version_compare(b, strlen(b), a, strlen(a));
    /* antisymmetry check */
    cytadel_vercmp_t mirror = (got == CYTADEL_VERCMP_LESS)      ? CYTADEL_VERCMP_GREATER
                              : (got == CYTADEL_VERCMP_GREATER) ? CYTADEL_VERCMP_LESS
                                                                : got;
    int asym = (rev != mirror);
    if (got == CYTADEL_VERCMP_UNDECIDABLE) undec++;
    int bad = (want != CYTADEL_VERCMP_UNDECIDABLE && got != want);
    if (bad) fails++;
    printf("%-8s %-22s vs %-22s -> %-12s%s  [%s]\n", bad ? "MISMATCH" : (got == CYTADEL_VERCMP_UNDECIDABLE ? "undec" : "ok"),
           a, b, N(got), asym ? "  !!ANTISYM-BROKEN!!" : "", why);
}

int main(void) {
    puts("=== REAL ADVISORY BOUNDARIES (report-trust critical) ===");
    /* Heartbleed CVE-2014-0160: 1.0.1 through 1.0.1f affected, 1.0.1g fixed. */
    chk("1.0.1f", "1.0.1g", CYTADEL_VERCMP_LESS, "heartbleed: last-affected < first-fixed");
    chk("1.0.1", "1.0.1f", CYTADEL_VERCMP_LESS, "heartbleed: base < letter suffix");
    chk("1.0.1g", "1.0.1", CYTADEL_VERCMP_GREATER, "heartbleed: fixed > base");
    /* regreSSHion CVE-2024-6387: 8.5p1 <= v < 9.8p1 */
    chk("8.5p1", "9.8p1", CYTADEL_VERCMP_LESS, "regreSSHion band lower < upper");
    chk("9.8p1", "9.8p1", CYTADEL_VERCMP_EQUAL, "regreSSHion upper bound exact");
    chk("4.4p1", "8.5p1", CYTADEL_VERCMP_LESS, "regreSSHion second band");
    chk("9.7", "9.8p1", CYTADEL_VERCMP_LESS, "9.7 inside band");

    puts("\n=== LETTER SUFFIX (must be GREATER) ===");
    chk("1.0.2k", "1.0.2", CYTADEL_VERCMP_GREATER, "openssl letter > base");
    chk("1.0.2k", "1.0.2l", CYTADEL_VERCMP_LESS, "openssl k < l");
    chk("7.2p2", "7.2", CYTADEL_VERCMP_GREATER, "openssh p2 > base");
    chk("7.2p2", "7.2p3", CYTADEL_VERCMP_LESS, "openssh p2 < p3");

    puts("\n=== PRE-RELEASE (must be LESS) ===");
    chk("1.0.0-alpha", "1.0.0", CYTADEL_VERCMP_LESS, "alpha < release");
    chk("1.0.0-rc1", "1.0.0", CYTADEL_VERCMP_LESS, "rc < release");
    chk("1.0.0-alpha", "1.0.0-beta", CYTADEL_VERCMP_LESS, "alpha < beta");
    chk("1.0.0-beta", "1.0.0-rc", CYTADEL_VERCMP_LESS, "beta < rc");

    puts("\n=== KEYWORD-TABLE HEURISTIC: UNLISTED PRE-RELEASE SPELLINGS ===");
    puts("    (unlisted spelling => treated as GREATER => version looks NEWER than");
    puts("     its release => a fixed-version bound can be missed = FALSE NEGATIVE)");
    /* Unknown DETACHED spellings are UNDECIDABLE by design: the comparator
     * refuses to guess a direction it cannot justify, rather than silently
     * dropping a finding. A human adds the spelling to the keyword table. */
    chk("1.0.0-a1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE, "a1 unknown detached spelling");
    chk("1.0.0-b2", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE, "b2 unknown detached spelling");
    chk("1.0.0-M1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE, "M1 maven milestone, unknown");
    chk("1.0.0-cr1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE, "cr jboss candidate, unknown");
    chk("1.0.0-ga", "1.0.0", CYTADEL_VERCMP_EQUAL, "ga = general availability = release");

    puts("\n=== CASE INSENSITIVITY (claimed) ===");
    chk("1.0.0-ALPHA", "1.0.0", CYTADEL_VERCMP_LESS, "uppercase ALPHA");
    chk("1.0.0-RC1", "1.0.0", CYTADEL_VERCMP_LESS, "uppercase RC1");

    puts("\n=== EPOCH / DISTRO / PARTIAL ===");
    chk("1:2.4.6", "2.4.6", CYTADEL_VERCMP_GREATER, "epoch dominates");
    chk("2.4", "2.4.0", CYTADEL_VERCMP_EQUAL, "zero-pad-equal");
    chk("2.4.6-2ubuntu2.2", "2.4.6", CYTADEL_VERCMP_GREATER, "distro rev > base");

    puts("\n=== HOSTILE ===");
    chk("", "1.0", CYTADEL_VERCMP_UNDECIDABLE, "empty");
    chk("1.0", "v1.0", CYTADEL_VERCMP_UNDECIDABLE, "v-prefix (known limitation)");
    chk("99999999999999999999999", "1.0", CYTADEL_VERCMP_UNDECIDABLE, "numeric overflow");
    chk("....", "1.0", CYTADEL_VERCMP_UNDECIDABLE, "all delimiters");
    /* embedded NUL: length-bounded API must see past it */
    {
        const char nul[] = "1.0\0evil";
        cytadel_vercmp_t g = cytadel_version_compare(nul, 8, "1.0", 3);
        printf("%-8s embedded-NUL(len 8) vs 1.0 -> %s\n", g == CYTADEL_VERCMP_UNDECIDABLE ? "ok" : "CHECK", N(g));
    }

    printf("\nMISMATCHES vs my expectations: %d   UNDECIDABLE count: %d\n", fails, undec);
    return 0;
}
