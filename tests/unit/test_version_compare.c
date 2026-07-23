#include "cytadel/match/version_compare.h"

#include <string.h>

#include "cytadel_test.h"

/* Mirror of test_cpe_match.c's outcome-distinctness guard, for the
 * comparator's own result enum. cpe-matching.md §1 freezes cytadel_vercmp_t
 * at exactly four values; these static asserts turn a refactor that aliases
 * two of them (e.g. UNDECIDABLE onto EQUAL, which would silently start
 * guessing a direction for unorderable inputs) into a build failure rather
 * than a green-but-wrong suite. */
_Static_assert(CYTADEL_VERCMP_LESS != CYTADEL_VERCMP_EQUAL, "vercmp values must be distinct");
_Static_assert(CYTADEL_VERCMP_LESS != CYTADEL_VERCMP_GREATER, "vercmp values must be distinct");
_Static_assert(CYTADEL_VERCMP_LESS != CYTADEL_VERCMP_UNDECIDABLE, "vercmp values must be distinct");
_Static_assert(CYTADEL_VERCMP_EQUAL != CYTADEL_VERCMP_GREATER, "vercmp values must be distinct");
_Static_assert(CYTADEL_VERCMP_EQUAL != CYTADEL_VERCMP_UNDECIDABLE, "vercmp values must be distinct");
_Static_assert(CYTADEL_VERCMP_GREATER != CYTADEL_VERCMP_UNDECIDABLE,
               "vercmp values must be distinct");

/* Table-driven truth table for cytadel_version_compare() (see
 * include/cytadel/match/version_compare.h for the full design writeup this
 * table exercises). Each row's `a_len`/`b_len` is computed via sizeof(...)-1
 * on a string literal rather than strlen() -- this also correctly counts
 * through an explicitly embedded '\0' escape inside a literal (e.g.
 * "1.0\0zz"), which is exactly what the embedded-NUL hostile-input rows
 * below need: sizeof() is a compile-time array size, not a runtime scan that
 * would stop at the first NUL the way strlen() does.
 *
 * Every row is marked REAL (a genuine OpenSSL/OpenSSH release version
 * string, as handed to this task directly -- 1.0.1/1.0.1f/1.0.1g,
 * 4.4p1/8.5p1/9.8p1) or SYNTHETIC (hand-constructed to exercise one specific
 * rule; never presented as a real advisory version-range bound). No row
 * asserts a CVE-applicability claim -- every assertion here is a version-
 * STRING-ordering fact about the comparator, independent of any specific
 * vulnerability's actual affected range. */

typedef struct {
    const char *desc;
    const char *a;
    size_t a_len;
    const char *b;
    size_t b_len;
    cytadel_vercmp_t expected;
} vercmp_case_t;

#define CASE(desc_, a_, b_, exp_) \
    { (desc_), (a_), sizeof(a_) - 1, (b_), sizeof(b_) - 1, (exp_) }

static const vercmp_case_t CASES[] = {
    /* ---- Base algorithm (db-schema.md SS3), no refinement needed ---- */
    CASE("SYNTHETIC base: equal", "1.2.3", "1.2.3", CYTADEL_VERCMP_EQUAL),
    CASE("SYNTHETIC base: patch less", "1.2.3", "1.2.4", CYTADEL_VERCMP_LESS),
    CASE("SYNTHETIC base: patch greater", "1.2.4", "1.2.3", CYTADEL_VERCMP_GREATER),
    CASE("SYNTHETIC base: major greater", "2.0.0", "1.9.9", CYTADEL_VERCMP_GREATER),
    CASE("SYNTHETIC base: underscore delimiter", "1_2_3", "1.2.3", CYTADEL_VERCMP_EQUAL),
    CASE("SYNTHETIC base: mixed delimiters", "1-2_3", "1.2.3", CYTADEL_VERCMP_EQUAL),
    CASE("SYNTHETIC base: leading zero numeric equal", "1.01", "1.1", CYTADEL_VERCMP_EQUAL),

    /* ---- Refinement 1: OpenSSL letter suffixes ---- */
    CASE("REFINEMENT-1 SYNTHETIC: 1.0.2k > 1.0.2", "1.0.2k", "1.0.2", CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-1 SYNTHETIC: 1.0.2 < 1.0.2k", "1.0.2", "1.0.2k", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-1 SYNTHETIC: 1.0.2k < 1.0.2l", "1.0.2k", "1.0.2l", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-1 SYNTHETIC: 1.0.2l > 1.0.2k", "1.0.2l", "1.0.2k", CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-1 REAL (OpenSSL, Heartbleed CVE-2014-0160 era): "
         "1.0.1 < 1.0.1f",
         "1.0.1", "1.0.1f", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-1 REAL (OpenSSL): 1.0.1f < 1.0.1g", "1.0.1f", "1.0.1g", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-1 REAL (OpenSSL): 1.0.1 < 1.0.1g", "1.0.1", "1.0.1g", CYTADEL_VERCMP_LESS),

    /* ---- Refinement 2: OpenSSH patch letters ---- */
    CASE("REFINEMENT-2 SYNTHETIC: 7.2p2 > 7.2", "7.2p2", "7.2", CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-2 SYNTHETIC: 7.2p2 < 7.2p3", "7.2p2", "7.2p3", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-2 REAL (OpenSSH release versions): 4.4p1 < 8.5p1", "4.4p1", "8.5p1",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-2 REAL (OpenSSH release versions): 8.5p1 < 9.8p1", "8.5p1", "9.8p1",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-2 REAL (OpenSSH release versions): 4.4p1 < 9.8p1", "4.4p1", "9.8p1",
         CYTADEL_VERCMP_LESS),

    /* ---- Refinement 3: Debian epochs ---- */
    CASE("REFINEMENT-3 SYNTHETIC: epoch 1 > absent epoch", "1:2.4.6", "2.4.6",
         CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-3 SYNTHETIC: explicit epoch 0 == absent epoch", "0:2.4.6", "2.4.6",
         CYTADEL_VERCMP_EQUAL),
    CASE("REFINEMENT-3 SYNTHETIC: epoch dominates rest-of-string", "2:1.0", "1:9.9",
         CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-3 SYNTHETIC: equal epoch falls through to rest", "1:2.4.6", "1:2.4.7",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-3 SYNTHETIC: leading zero epoch equals no epoch", "00:1.0", "1.0",
         CYTADEL_VERCMP_EQUAL),

    /* ---- C-1: ATTACHED pre-release must order BELOW its release ----
     * (real strings: CPython 3.11.0rc1/3.9.0b2, PHP 7.4.0RC1). These escaped
     * the original suite AND the first probe because both tested only the
     * DETACHED spelling (-rc1). The keyword check now runs before the
     * attached-alpha GREATER shortcut. */
    CASE("C-1 REAL CPython: 3.11.0rc1 < 3.11.0", "3.11.0rc1", "3.11.0",
         CYTADEL_VERCMP_LESS),
    /* 3.9.0b2 -> b+2; single letter 'b' is ambiguous (beta vs OpenSSL letter
     * release like 1.0.2b), same net as a1 -> UNDECIDABLE, not a guess. */
    CASE("C-1 REAL CPython: 3.9.0b2 ambiguous single-letter -> UNDECIDABLE", "3.9.0b2", "3.9.0",
         CYTADEL_VERCMP_UNDECIDABLE),
    CASE("C-1 REAL PHP: 7.4.0RC1 < 7.4.0 (case-insensitive)", "7.4.0RC1", "7.4.0",
         CYTADEL_VERCMP_LESS),
    CASE("C-1 SYNTHETIC: attached beta1 < release", "1.0.0beta1", "1.0.0",
         CYTADEL_VERCMP_LESS),
    CASE("C-1 SYNTHETIC: attached dev < release", "2.0.0dev", "2.0.0",
         CYTADEL_VERCMP_LESS),
    /* Ambiguous single-letter attached alpha in [a,b,c]+digits: could be a
     * pre-release (3.9.0a1) OR an OpenSSL-style letter release (1.0.2a). Genuinely
     * indistinguishable -> UNDECIDABLE, never a guessed direction. */
    CASE("C-1 SYNTHETIC: ambiguous single-letter attached alpha 3.9.0a1 vs 3.9.0",
         "3.9.0a1", "3.9.0", CYTADEL_VERCMP_UNDECIDABLE),
    /* Regression guard: attached letter suffix WITHOUT a keyword still GREATER. */
    CASE("C-1 REGRESSION: OpenSSL 1.0.2k > 1.0.2 (not a keyword)", "1.0.2k", "1.0.2",
         CYTADEL_VERCMP_GREATER),

    /* ---- C-2: same-position keyword rank (release-equivalent > pre-release) ----
     * These fell through to plain lexical before, ordering 21/52 pairs backwards
     * and creating 597 transitivity cycles. */
    CASE("C-2 SYNTHETIC: ga > rc (GA names the release)", "1.0.0-ga", "1.0.0-rc",
         CYTADEL_VERCMP_GREATER),
    CASE("C-2 SYNTHETIC: final > rc", "1.0.0-final", "1.0.0-rc",
         CYTADEL_VERCMP_GREATER),
    CASE("C-2 SYNTHETIC: release > snapshot", "1.0.0-release", "1.0.0-snapshot",
         CYTADEL_VERCMP_GREATER),
    CASE("C-2 SYNTHETIC: recognized keyword vs unrecognized -> UNDECIDABLE",
         "1.0.0-rc", "1.0.0-zzq", CYTADEL_VERCMP_UNDECIDABLE),

    /* ---- C-3: bare epoch has no comparable body -> UNDECIDABLE (was GREATER,
     * a 2-byte scan-evasion string since "1:" beat every epoch-0 version). ---- */
    CASE("C-3 SYNTHETIC: bare epoch 1: vs real version", "1:", "2.4.6",
         CYTADEL_VERCMP_UNDECIDABLE),
    CASE("C-3 SYNTHETIC: bare epoch 1: vs high version", "1:", "999.999",
         CYTADEL_VERCMP_UNDECIDABLE),
    CASE("C-3 SYNTHETIC: epoch with all-delimiter body", "1:...", "2.4.6",
         CYTADEL_VERCMP_UNDECIDABLE),

    /* ---- W-2: SemVer build metadata ignored in precedence ---- */
    CASE("W-2 SYNTHETIC: +build metadata ignored", "1.0.0+build5", "1.0.0",
         CYTADEL_VERCMP_EQUAL),
    CASE("W-2 SYNTHETIC: +build metadata ignored (numeric)", "1.0.0+20130313", "1.0.0",
         CYTADEL_VERCMP_EQUAL),

    /* ---- Refinement 4: distro revisions ---- */
    CASE("REFINEMENT-4 SYNTHETIC: revision suffix > pristine upstream", "2.4.6-2ubuntu2.2",
         "2.4.6", CYTADEL_VERCMP_GREATER),
    CASE("REFINEMENT-4 SYNTHETIC: revision number decides when upstream equal",
         "2.4.6-2ubuntu2.2", "2.4.6-3ubuntu1", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-4 SYNTHETIC: differing upstream patch decided before revision",
         "2.4.6-2ubuntu2.2", "2.4.7", CYTADEL_VERCMP_LESS),

    /* ---- Refinement 5: pre-release below release ---- */
    CASE("REFINEMENT-5 SYNTHETIC: 1.0.0-alpha < 1.0.0", "1.0.0-alpha", "1.0.0",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: 1.0.0-rc1 < 1.0.0", "1.0.0-rc1", "1.0.0", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: -alpha < -beta", "1.0.0-alpha", "1.0.0-beta",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: -beta < -rc", "1.0.0-beta", "1.0.0-rc", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: -alpha < -rc", "1.0.0-alpha", "1.0.0-rc", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: rc1 < rc2 (same keyword, numeric tiebreak)", "1.0.0-rc1",
         "1.0.0-rc2", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: case-insensitive keyword match", "1.0.0-ALPHA", "1.0.0",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: alpha-with-trailing-digits still a keyword residual",
         "1.0.0-alpha1", "1.0.0", CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-5 SYNTHETIC: pre-release below a zero-padded release too",
         "1.0.0-alpha", "1.0", CYTADEL_VERCMP_LESS),

    /* ---- Round-2 fix: an independent reviewer's out-of-tree probe found
     * that an unrecognized DETACHED alpha residual was being guessed as
     * GREATER (the same rule as attachment 1/2/4's letter suffixes),
     * which is WRONG for common pre-release spellings this project's fixed
     * keyword table does not (and never can, exhaustively) enumerate --
     * concretely, this made "1.0.0-cr1" compare GREATER than "1.0.0", so a
     * host actually running a pre-release candidate build would fall
     * OUTSIDE an NVD versionEndExcluding="1.0.0" bound and the finding
     * would be silently dropped: a false negative in a security scanner,
     * exactly the failure class this comparator exists to prevent. All 5
     * of these are the reviewer's own reported cases, verbatim. */
    CASE("ROUND-2 SYNTHETIC: unrecognized detached alpha 'a1' (common alpha spelling) "
         "is UNDECIDABLE, not guessed GREATER",
         "1.0.0-a1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("ROUND-2 SYNTHETIC: unrecognized detached alpha 'b2' (common beta spelling) "
         "is UNDECIDABLE, not guessed GREATER",
         "1.0.0-b2", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("ROUND-2 SYNTHETIC: unrecognized detached alpha 'M1' (Maven milestone) "
         "is UNDECIDABLE, not guessed GREATER",
         "1.0.0-M1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("ROUND-2 SYNTHETIC: unrecognized detached alpha 'cr1' (JBoss candidate release) "
         "is UNDECIDABLE, not guessed GREATER",
         "1.0.0-cr1", "1.0.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("ROUND-2 SYNTHETIC: 'ga' (General Availability) IS the release -> EQUAL, "
         "not GREATER and not LESS",
         "1.0.0-ga", "1.0.0", CYTADEL_VERCMP_EQUAL),
    /* Same detached-vs-attached discriminator, a couple more angles: */
    CASE("ROUND-2 SYNTHETIC: case-insensitive release-equivalent keyword", "1.0.0-GA", "1.0.0",
         CYTADEL_VERCMP_EQUAL),
    CASE("ROUND-2 SYNTHETIC: release-equivalent keyword with real trailing content "
         "still resumes the walk",
         "1.0.0-ga.1", "1.0.0", CYTADEL_VERCMP_GREATER),
    CASE("ROUND-2 SYNTHETIC: 'final' is also a recognized release-equivalent keyword",
         "1.0.0-final", "1.0.0", CYTADEL_VERCMP_EQUAL),
    CASE("ROUND-2 SYNTHETIC: attachment (no delimiter) still wins over word content -- "
         "'k' is not a keyword in any table but is ATTACHED, so still GREATER",
         "1.0.2k", "1.0.2", CYTADEL_VERCMP_GREATER),

    /* ---- The explicit 1/2-vs-5 tension, both directions side by side ---- */
    CASE("TENSION SYNTHETIC: non-keyword trailing alpha (k) is GREATER", "1.0.2k", "1.0.2",
         CYTADEL_VERCMP_GREATER),
    CASE("TENSION SYNTHETIC: keyword trailing alpha (alpha) is LESS", "1.0.2-alpha", "1.0.2",
         CYTADEL_VERCMP_LESS),
    CASE("TENSION SYNTHETIC: non-keyword trailing alpha (p2) is GREATER", "7.2p2", "7.2",
         CYTADEL_VERCMP_GREATER),
    CASE("TENSION SYNTHETIC: keyword trailing alpha (rc2) is LESS", "7.2-rc2", "7.2",
         CYTADEL_VERCMP_LESS),

    /* ---- Refinement 6: partial versions (zero-pad-equal, chosen rule) ---- */
    CASE("REFINEMENT-6 SYNTHETIC: 2.4 == 2.4.0 (zero-pad-equal)", "2.4", "2.4.0",
         CYTADEL_VERCMP_EQUAL),
    CASE("REFINEMENT-6 SYNTHETIC: 2.4 == 2.4.0.0", "2.4", "2.4.0.0", CYTADEL_VERCMP_EQUAL),
    CASE("REFINEMENT-6 SYNTHETIC: 2 == 2.0.0.0.0", "2", "2.0.0.0.0", CYTADEL_VERCMP_EQUAL),
    CASE("REFINEMENT-6 SYNTHETIC: 2.4 < 2.4.1 (non-zero residual)", "2.4", "2.4.1",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-6 SYNTHETIC: 2.4.1 > 2.4", "2.4.1", "2.4", CYTADEL_VERCMP_GREATER),

    /* ---- Refinement 7: UNDECIDABLE, never guessed ---- */
    CASE("REFINEMENT-7 SYNTHETIC: both empty", "", "", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: empty vs real version", "", "1.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: all-delimiters vs real version", "...", "1.0",
         CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: all-delimiters vs all-delimiters (different chars)", "---",
         "___", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: numeric vs alpha type mismatch", "1.0", "1.a",
         CYTADEL_VERCMP_UNDECIDABLE),
    /* W-3 fix: a single leading 'v'/'V' glued to a digit is stripped before
     * tokenizing, so a 'v'-prefixed tag equals its bare-numeric form. */
    CASE("W-3: leading 'v' prefix stripped, equals bare numeric", "v1.0", "1.0",
         CYTADEL_VERCMP_EQUAL),
    CASE("W-3: leading 'V' prefix stripped, equals bare numeric", "V2.1.0", "2.1.0",
         CYTADEL_VERCMP_EQUAL),
    CASE("W-3: 'v'-prefixed with pre-release suffix orders below release", "v2.1.0-rc1", "2.1.0",
         CYTADEL_VERCMP_LESS),
    CASE("REFINEMENT-7 SYNTHETIC: embedded NUL is a control byte, not a terminator",
         "1.0\0zz", "1.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: tab control byte", "1.0\t", "1.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: DEL byte", "1.0\x7f", "1.0", CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: high-bit non-ASCII byte", "1.0\xff", "1.0",
         CYTADEL_VERCMP_UNDECIDABLE),
    CASE("REFINEMENT-7 SYNTHETIC: invalid-UTF-8 overlong-NUL sequence", "1.0\xc0\x80", "1.0",
         CYTADEL_VERCMP_UNDECIDABLE),
    /* Epochs must be EQUAL here (both "5") so the epoch-dominance check
     * passes through and the comparator actually has to inspect the
     * (empty) rest-of-string on the "5:" side -- if the epochs differed,
     * refinement 3 says the epoch alone decides the whole comparison
     * (correctly) without ever needing to notice the rest is empty. */
    CASE("REFINEMENT-7 SYNTHETIC: epoch with nothing after it (equal epochs)", "5:", "5:1.0",
         CYTADEL_VERCMP_UNDECIDABLE),
    /* Documented finding (see test_chain_transitivity()'s header comment
     * for the full story): a pre-release marker and a distro-revision
     * marker are two differently-shaped qualifiers with no rule for
     * comparing one directly against the other once neither is a prefix
     * of the other -- shared position 3 is ALPHA "alpha" on one side and
     * NUMERIC "2" on the other, which is exactly the numeric-vs-alpha
     * UNDECIDABLE bullet, correctly applied rather than guessed. */
    CASE("REFINEMENT-7 SYNTHETIC: pre-release marker vs distro-revision marker "
         "at the same shared position is genuinely undecidable",
         "1.0.0-alpha", "1.0.0-2ubuntu1", CYTADEL_VERCMP_UNDECIDABLE),

    /* ---- Decidable-but-nonobvious: alpha-vs-alpha lexical per SS3 (NOT
     * UNDECIDABLE -- two distinct plain alpha strings are still ordered by
     * the base algorithm's literal "alpha components lexically" rule). */
    /* Two genuinely non-keyword alpha strings still fall through to lexical
     * (SS3's literal rule). NB: 'dev' is now a pre-release keyword, so it can
     * no longer be used here -- pairing a keyword with a non-keyword is
     * UNDECIDABLE under the C-2 rank rule, tested separately. */
    CASE("SS3-literal SYNTHETIC: two non-keyword alpha-only strings, lexical", "foo", "unknown",
         CYTADEL_VERCMP_LESS),
    CASE("SS3-literal SYNTHETIC: identical alpha-only strings", "unknown", "unknown",
         CYTADEL_VERCMP_EQUAL),
};

#define CASES_COUNT (sizeof(CASES) / sizeof(CASES[0]))

static void test_table_and_antisymmetry(void) {
    for (size_t i = 0; i < CASES_COUNT; i++) {
        const vercmp_case_t *c = &CASES[i];
        cytadel_vercmp_t actual =
            cytadel_version_compare(c->a, c->a_len, c->b, c->b_len);
        if (actual != c->expected) {
            fprintf(stderr, "case %zu FAILED: %s (a=%.*s, b=%.*s): expected %d got %d\n", i,
                    c->desc, (int)c->a_len, c->a, (int)c->b_len, c->b, (int)c->expected,
                    (int)actual);
        }
        CYTADEL_ASSERT_EQ(actual, c->expected);

        /* Antisymmetry: compare(b, a) must be the exact mirror. */
        cytadel_vercmp_t mirror =
            cytadel_version_compare(c->b, c->b_len, c->a, c->a_len);
        cytadel_vercmp_t expected_mirror;
        switch (c->expected) {
            case CYTADEL_VERCMP_LESS: expected_mirror = CYTADEL_VERCMP_GREATER; break;
            case CYTADEL_VERCMP_GREATER: expected_mirror = CYTADEL_VERCMP_LESS; break;
            case CYTADEL_VERCMP_EQUAL: expected_mirror = CYTADEL_VERCMP_EQUAL; break;
            default: expected_mirror = CYTADEL_VERCMP_UNDECIDABLE; break;
        }
        if (mirror != expected_mirror) {
            fprintf(stderr, "case %zu ANTISYMMETRY FAILED: %s: mirror expected %d got %d\n", i,
                    c->desc, (int)expected_mirror, (int)mirror);
        }
        CYTADEL_ASSERT_EQ(mirror, expected_mirror);
    }
}

/* ---- Transitivity / total-order consistency over hand-verified, strictly
 * monotonically increasing chains. Every ADJACENT pair below was
 * hand-derived against the documented algorithm (see the design writeup in
 * include/cytadel/match/version_compare.h); test_chain_transitivity() then
 * checks EVERY pair in a chain (not just adjacent ones) is consistent with
 * a strict total order, which is a real transitivity check, not just an
 * adjacent-hop sanity check.
 *
 * DELIBERATELY TWO SEPARATE CHAINS, NOT ONE -- documented finding: an
 * earlier single combined chain (interleaving the "1.0.0-{alpha,beta,rc1,
 * rc2}" pre-release family with "1.0.0-2ubuntu1") FAILED this exact test
 * during development: cytadel_version_compare("1.0.0-alpha", ...,
 * "1.0.0-2ubuntu1", ...) returns CYTADEL_VERCMP_UNDECIDABLE, not LESS as a
 * hand-wavy "pre-release < release <= revision" chain would assume. Once
 * both sides' shared "1.0.0" prefix is exhausted, "-alpha"'s next
 * component is an ALPHA token and "-2ubuntu1"'s next component is a
 * NUMERIC token at that SAME shared position -- exactly
 * version_compare.h's third UNDECIDABLE bullet (numeric vs. alpha
 * component at a shared position), correctly applied. This is NOT a bug:
 * per this comparator's rules, a pre-release marker and a distro-revision
 * marker are simply two differently-shaped qualifiers with no documented
 * rule for comparing one directly against the other once neither is a
 * prefix of the other, so UNDECIDABLE is the honest answer, not a defect
 * to "fix" by inventing a guess. The two chains below are therefore kept
 * internally consistent but deliberately never cross-compared against each
 * other. */
static const char *const CHAIN_PRERELEASE[] = {
    "1.0.0-alpha", /* 0 */
    "1.0.0-beta",  /* 1 */
    "1.0.0-rc1",   /* 2 */
    "1.0.0-rc2",   /* 3 */
    "1.0.0",       /* 4 */
    "1.0.1",       /* 5 */
    "1.0.1f",      /* 6 */
    "1.0.1g",      /* 7 */
    "1.0.2",       /* 8 */
    "1.0.2k",      /* 9 */
    "1.0.2l",      /* 10 */
    "7.2",         /* 11 */
    "7.2p2",       /* 12 */
    "7.2p3",       /* 13 */
    "8.5p1",       /* 14 -- REAL (OpenSSH) */
    "9.8p1",       /* 15 -- REAL (OpenSSH) */
};

/* Distro-revision family (refinement 4): kept separate from
 * CHAIN_PRERELEASE above for exactly the reason explained there. Every
 * post-hyphen component here starts with a digit on both sides being
 * compared, so no numeric-vs-alpha shared-position clash is possible
 * within this chain. */
static const char *const CHAIN_DISTRO_REVISION[] = {
    "2.4.6",             /* 0 */
    "2.4.6-2ubuntu2.2",  /* 1 */
    "2.4.6-3ubuntu1",    /* 2 */
    "2.4.7",             /* 3 */
};

static void assert_chain_is_strict_total_order(const char *const *chain, size_t chain_len) {
    for (size_t i = 0; i < chain_len; i++) {
        for (size_t j = 0; j < chain_len; j++) {
            const char *ai = chain[i];
            const char *aj = chain[j];
            cytadel_vercmp_t r = cytadel_version_compare(ai, strlen(ai), aj, strlen(aj));
            cytadel_vercmp_t expected;
            if (i < j) {
                expected = CYTADEL_VERCMP_LESS;
            } else if (i > j) {
                expected = CYTADEL_VERCMP_GREATER;
            } else {
                expected = CYTADEL_VERCMP_EQUAL;
            }
            if (r != expected) {
                fprintf(stderr,
                        "chain[%zu]=%s vs chain[%zu]=%s FAILED: expected %d got %d\n", i, ai, j,
                        aj, (int)expected, (int)r);
            }
            CYTADEL_ASSERT_EQ(r, expected);
        }
    }
}

static void test_chain_transitivity(void) {
    assert_chain_is_strict_total_order(
        CHAIN_PRERELEASE, sizeof(CHAIN_PRERELEASE) / sizeof(CHAIN_PRERELEASE[0]));
    assert_chain_is_strict_total_order(
        CHAIN_DISTRO_REVISION, sizeof(CHAIN_DISTRO_REVISION) / sizeof(CHAIN_DISTRO_REVISION[0]));
}

/* ---- Hostile-input: NULL pointer handling. Cannot go through the CASES
 * table (its rows are all string literals), so this is its own function. */
static void test_null_pointer_handling(void) {
    /* NULL paired with length 0 is a legitimate empty string -- still
     * UNDECIDABLE (refinement 7's "empty" bullet), but must not crash. */
    CYTADEL_ASSERT_EQ(cytadel_version_compare(NULL, 0, "1.0", 3), CYTADEL_VERCMP_UNDECIDABLE);
    CYTADEL_ASSERT_EQ(cytadel_version_compare("1.0", 3, NULL, 0), CYTADEL_VERCMP_UNDECIDABLE);
    CYTADEL_ASSERT_EQ(cytadel_version_compare(NULL, 0, NULL, 0), CYTADEL_VERCMP_UNDECIDABLE);

    /* NULL paired with a NON-zero length is a caller bug -- must not
     * dereference the NULL pointer, must return UNDECIDABLE defensively. */
    CYTADEL_ASSERT_EQ(cytadel_version_compare(NULL, 5, "1.0", 3), CYTADEL_VERCMP_UNDECIDABLE);
    CYTADEL_ASSERT_EQ(cytadel_version_compare("1.0", 3, NULL, 5), CYTADEL_VERCMP_UNDECIDABLE);
}

/* ---- Hostile-input: over-long numeric components / thousands of
 * components. Uses fixed-size automatic arrays (no VLA -- the array size
 * is a compile-time constant; only the CONTENT is filled at runtime), and
 * proves the comparator's iterative (non-recursive) design does not
 * overflow the stack even for very long inputs. */

#define HOSTILE_BUF_LEN 8192

static void fill_repeated(char *buf, size_t n, char c) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = c;
    }
}

static void test_overlong_numeric_component(void) {
    static char a_buf[HOSTILE_BUF_LEN];
    static char b_buf[HOSTILE_BUF_LEN];

    /* 5000 '9' digits vs a short "1": the huge nonzero digit run must
     * still be recognized as GREATER, via length-after-leading-zero-strip
     * comparison only -- never via strtol()/atoi() conversion (which would
     * overflow any integer type long before 5000 digits). */
    size_t huge_len = 5000;
    fill_repeated(a_buf, huge_len, '9');
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare(a_buf, huge_len, "1", 1), CYTADEL_VERCMP_GREATER);
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare("1", 1, a_buf, huge_len), CYTADEL_VERCMP_LESS);

    /* Two equal-length, equal-content huge digit runs must compare EQUAL. */
    fill_repeated(b_buf, huge_len, '9');
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare(a_buf, huge_len, b_buf, huge_len), CYTADEL_VERCMP_EQUAL);

    /* One more digit at 30/31 digits -- well beyond even a 64-bit integer's
     * ~19-20 decimal digit range -- still decided purely by length, no
     * overflow. */
    const char *thirty_nines = "999999999999999999999999999999"; /* 30 digits (well past int64) */
    const char *one_then_zeros = "1000000000000000000000000000000"; /* 31 digits */
    CYTADEL_ASSERT_EQ(cytadel_version_compare(thirty_nines, strlen(thirty_nines), one_then_zeros,
                                               strlen(one_then_zeros)),
                      CYTADEL_VERCMP_LESS);
}

static void test_thousands_of_components(void) {
    static char a_buf[HOSTILE_BUF_LEN];
    static char b_buf[HOSTILE_BUF_LEN];
    static char c_buf[HOSTILE_BUF_LEN];

    /* "1.1.1. ... .1" with 2000 components, twice, must compare EQUAL --
     * and must not crash/stack-overflow (this comparator is iterative, not
     * recursive, so component count is bounded only by input length). */
    size_t n_components = 2000;
    size_t pos = 0;
    for (size_t i = 0; i < n_components; i++) {
        if (i > 0) {
            a_buf[pos++] = '.';
        }
        a_buf[pos++] = '1';
    }
    size_t a_total = pos;
    memcpy(b_buf, a_buf, a_total);
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare(a_buf, a_total, b_buf, a_total), CYTADEL_VERCMP_EQUAL);

    /* Change the LAST component of b from "1" to "2": must be decided
     * correctly all the way at the far end of a long stream. */
    b_buf[a_total - 1] = '2';
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare(a_buf, a_total, b_buf, a_total), CYTADEL_VERCMP_LESS);

    /* A trailing all-delimiter run ("...." with nothing between the last
     * real component and the end) must not be misread as extra components
     * -- delimiters alone never manufacture a token, so this must still
     * compare EQUAL to the un-suffixed original. */
    memcpy(c_buf, a_buf, a_total);
    c_buf[a_total] = '.';
    c_buf[a_total + 1] = '.';
    c_buf[a_total + 2] = '.';
    size_t c_total = a_total + 3;
    CYTADEL_ASSERT_EQ(
        cytadel_version_compare(a_buf, a_total, c_buf, c_total), CYTADEL_VERCMP_EQUAL);
}

/* ---- Revert-prove (a): flip refinement 5's pre-release rule so a
 * pre-release token would rank ABOVE its release (the opposite of what
 * this comparator implements) and confirm the antisymmetry/table test
 * above fails. This is not run automatically (it would require patching
 * the implementation); it is documented, executed, and reported by hand --
 * see this task's final summary for the observed `ctest`/binary failure
 * output when CYTADEL_VERCMP_GREATER was substituted for
 * CYTADEL_VERCMP_LESS at the "keyword residual" branch of
 * cytadel_residual_verdict() in src/match/version_compare.c. */

/* ---- Revert-prove (b): collapse CYTADEL_VERCMP_UNDECIDABLE into
 * CYTADEL_VERCMP_EQUAL and confirm test_table_and_antisymmetry() (every
 * REFINEMENT-7 row) fails. Same reporting approach as (a) above. */

int main(void) {
    test_table_and_antisymmetry();
    test_chain_transitivity();
    test_null_pointer_handling();
    test_overlong_numeric_component();
    test_thousands_of_components();

    CYTADEL_TEST_PASS();
}
