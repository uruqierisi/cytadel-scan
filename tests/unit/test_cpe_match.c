#include "cytadel/match/cpe_match.h"

#include <stdbool.h>
#include <string.h>

#include "cytadel/match/version_compare.h"
#include "cytadel_test.h"

/* ------------------------------------------------------------------------
 * docs/contracts/cpe-matching.md §7 compile-time guards. These need no
 * caller and no runtime; they catch a refactor that would let a future
 * caller silently collapse a can't-decide / data-quality outcome into an
 * affected/not-affected answer.
 *
 * Guard 1: every pair of cytadel_cpe_match_t enumerators is distinct. A
 * "simplifying" refactor that aliases UNDECIDABLE onto NO_MATCH, or folds
 * MALFORMED_ROW into UNDECIDABLE, would compile green with the runtime truth
 * table still passing (the table asserts on enum NAMES, not distinctness) --
 * these static asserts turn that into a build failure instead. A test that
 * merely reads the enum back could not catch it. */
_Static_assert(CYTADEL_CPE_MATCH != CYTADEL_CPE_NO_MATCH, "cpe outcomes must be distinct");
_Static_assert(CYTADEL_CPE_MATCH != CYTADEL_CPE_UNDECIDABLE, "cpe outcomes must be distinct");
_Static_assert(CYTADEL_CPE_MATCH != CYTADEL_CPE_MALFORMED_ROW, "cpe outcomes must be distinct");
_Static_assert(CYTADEL_CPE_NO_MATCH != CYTADEL_CPE_UNDECIDABLE, "cpe outcomes must be distinct");
_Static_assert(CYTADEL_CPE_NO_MATCH != CYTADEL_CPE_MALFORMED_ROW, "cpe outcomes must be distinct");
_Static_assert(CYTADEL_CPE_UNDECIDABLE != CYTADEL_CPE_MALFORMED_ROW,
               "cpe outcomes must be distinct");

/* Guard 2: an exhaustive switch with NO default: over cytadel_cpe_match_t.
 * Under -Wall -Werror (this project's default) a no-default: switch that
 * omits a value is a -Wswitch error, so adding a fifth
 * outcome under contract §5 makes THIS a compile error, forcing a deliberate
 * decision here rather than a silent absorption into a default: label. The
 * function is never called; it exists only to be compiled. */
static const char *cytadel_cpe_outcome_name_exhaustive(cytadel_cpe_match_t v) {
    switch (v) {
    case CYTADEL_CPE_MATCH:
        return "MATCH";
    case CYTADEL_CPE_NO_MATCH:
        return "NO_MATCH";
    case CYTADEL_CPE_UNDECIDABLE:
        return "UNDECIDABLE";
    case CYTADEL_CPE_MALFORMED_ROW:
        return "MALFORMED_ROW";
    }
    return "?";
}

/* Table-driven truth table for cytadel_cpe_match_evaluate() (see
 * include/cytadel/match/cpe_match.h for the full design writeup this table
 * exercises: SS3's base algorithm, the four-state result, the three-valued
 * AND with short-circuit-safe UNDECIDABLE propagation, CPE special-token
 * handling, both-bounds-set combinations, vulnerable=0 rows).
 *
 * Every row is marked REAL (a genuine advisory, with the advisory + its
 * exact bounds cited right next to the row so a human can audit against the
 * source) or SYNTHETIC (hand-constructed to exercise one specific rule).
 * This slice does NOT reimplement or duplicate slice A's comparator logic
 * -- every MATCH/NO_MATCH verdict below is a direct consequence of
 * cytadel_version_compare()'s own already-verified truth table
 * (tests/unit/test_version_compare.c); this file only proves the range/
 * bound COMBINATION logic layered on top of it. */

#define LIT(s) (s), (sizeof(s) - 1)
#define EMPTY NULL, (size_t)0
/* W-4: a non-NULL pointer to a zero-length string. This is exactly what
 * sqlite3_column_text() returns for an empty TEXT column, so the real DB
 * layer hands the evaluator EMPTY_STR, not EMPTY (NULL). The skip condition
 * must key off len==0, not ptr==NULL; rows using this pin that. */
#define EMPTY_STR "", (size_t)0

typedef struct {
    const char *desc;
    cytadel_cpe_match_row_t row;
    const char *detected;
    size_t detected_len;
    cytadel_cpe_match_t expected;
} cpe_case_t;

static const cpe_case_t CASES[] = {
    /* ===================================================================
     * REAL ADVISORY: OpenSSL CVE-2014-0160 (Heartbleed).
     * Affected: 1.0.1 through 1.0.1f inclusive. Fixed: 1.0.1g.
     * Modeled as versionStartIncluding="1.0.1", versionEndIncluding="1.0.1f".
     * =================================================================== */
    {"REAL CVE-2014-0160 Heartbleed: 1.0.1 (lower bound) MATCHES",
     {LIT("*"), LIT("1.0.1"), EMPTY, LIT("1.0.1f"), EMPTY, 1},
     LIT("1.0.1"), CYTADEL_CPE_MATCH},
    {"REAL CVE-2014-0160 Heartbleed: 1.0.1f (upper bound, inclusive) MATCHES",
     {LIT("*"), LIT("1.0.1"), EMPTY, LIT("1.0.1f"), EMPTY, 1},
     LIT("1.0.1f"), CYTADEL_CPE_MATCH},
    {"REAL CVE-2014-0160 Heartbleed: 1.0.1g (the fix) does NOT match -- "
     "the off-by-one killer",
     {LIT("*"), LIT("1.0.1"), EMPTY, LIT("1.0.1f"), EMPTY, 1},
     LIT("1.0.1g"), CYTADEL_CPE_NO_MATCH},
    {"REAL CVE-2014-0160 Heartbleed: 1.0.0 (below lower bound) does NOT match",
     {LIT("*"), LIT("1.0.1"), EMPTY, LIT("1.0.1f"), EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_NO_MATCH},

    /* ===================================================================
     * REAL ADVISORY: OpenSSH CVE-2024-6387 (regreSSHion).
     * Band 1: 8.5p1 <= v < 9.8p1 (versionStartIncluding="8.5p1",
     *         versionEndExcluding="9.8p1").
     * Band 2 (separate configuration node): v < 4.4p1
     *         (versionEndExcluding="4.4p1" only).
     * =================================================================== */
    {"REAL CVE-2024-6387 regreSSHion band 1: 8.5p1 (inclusive lower) MATCHES",
     {LIT("*"), LIT("8.5p1"), EMPTY, EMPTY, LIT("9.8p1"), 1},
     LIT("8.5p1"), CYTADEL_CPE_MATCH},
    {"REAL CVE-2024-6387 regreSSHion band 1: 9.7 MATCHES",
     {LIT("*"), LIT("8.5p1"), EMPTY, EMPTY, LIT("9.8p1"), 1},
     LIT("9.7"), CYTADEL_CPE_MATCH},
    {"REAL CVE-2024-6387 regreSSHion band 1: 9.8p1 does NOT match -- "
     "exclusive upper bound",
     {LIT("*"), LIT("8.5p1"), EMPTY, EMPTY, LIT("9.8p1"), 1},
     LIT("9.8p1"), CYTADEL_CPE_NO_MATCH},
    {"REAL CVE-2024-6387 regreSSHion band 1: 8.4p1 does NOT match -- "
     "below inclusive lower bound",
     {LIT("*"), LIT("8.5p1"), EMPTY, EMPTY, LIT("9.8p1"), 1},
     LIT("8.4p1"), CYTADEL_CPE_NO_MATCH},
    {"REAL CVE-2024-6387 regreSSHion band 2: 4.3 MATCHES the < 4.4p1 band",
     {LIT("*"), EMPTY, EMPTY, EMPTY, LIT("4.4p1"), 1},
     LIT("4.3"), CYTADEL_CPE_MATCH},
    {"REAL CVE-2024-6387 regreSSHion band 2: 4.4p1 itself does NOT match "
     "(exclusive)",
     {LIT("*"), EMPTY, EMPTY, EMPTY, LIT("4.4p1"), 1},
     LIT("4.4p1"), CYTADEL_CPE_NO_MATCH},

    /* ===================================================================
     * SYNTHETIC: exact-match row (SS3 rule 1).
     * =================================================================== */
    {"SYNTHETIC exact-match row: equal version, vulnerable=1 -> MATCH",
     {LIT("2.4.6"), EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("2.4.6"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC exact-match row: different version -> NO_MATCH",
     {LIT("2.4.6"), EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("2.4.7"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC exact-match row: equal version but vulnerable=0 -> NO_MATCH",
     {LIT("2.4.6"), EMPTY, EMPTY, EMPTY, EMPTY, 0},
     LIT("2.4.6"), CYTADEL_CPE_NO_MATCH},

    /* ===================================================================
     * SYNTHETIC: one version JUST outside EACH of the four bounds
     * individually (off-by-one is where the real bugs live).
     * =================================================================== */
    {"SYNTHETIC start_including: exactly at bound -> PASS/MATCH",
     {LIT("*"), LIT("2.0.0"), EMPTY, EMPTY, EMPTY, 1},
     LIT("2.0.0"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC start_including: one below bound -> FAIL/NO_MATCH",
     {LIT("*"), LIT("2.0.0"), EMPTY, EMPTY, EMPTY, 1},
     LIT("1.9.9"), CYTADEL_CPE_NO_MATCH},

    {"SYNTHETIC start_excluding: exactly at bound -> FAIL/NO_MATCH (exclusive)",
     {LIT("*"), EMPTY, LIT("2.0.0"), EMPTY, EMPTY, 1},
     LIT("2.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC start_excluding: one above bound -> PASS/MATCH",
     {LIT("*"), EMPTY, LIT("2.0.0"), EMPTY, EMPTY, 1},
     LIT("2.0.1"), CYTADEL_CPE_MATCH},

    {"SYNTHETIC end_including: exactly at bound -> PASS/MATCH",
     {LIT("*"), EMPTY, EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("2.0.0"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC end_including: one above bound -> FAIL/NO_MATCH",
     {LIT("*"), EMPTY, EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("2.0.1"), CYTADEL_CPE_NO_MATCH},

    {"SYNTHETIC end_excluding: exactly at bound -> FAIL/NO_MATCH (exclusive)",
     {LIT("*"), EMPTY, EMPTY, EMPTY, LIT("2.0.0"), 1},
     LIT("2.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC end_excluding: one below bound -> PASS/MATCH",
     {LIT("*"), EMPTY, EMPTY, EMPTY, LIT("2.0.0"), 1},
     LIT("1.9.9"), CYTADEL_CPE_MATCH},

    /* ===================================================================
     * SYNTHETIC: every bound COMBINATION (start+end pairs; both-starts;
     * both-ends; all four).
     * =================================================================== */
    {"SYNTHETIC start_including + end_including pair: inside range -> MATCH",
     {LIT("*"), LIT("1.0.0"), EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("1.5.0"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC start_including + end_including pair: below range -> NO_MATCH",
     {LIT("*"), LIT("1.0.0"), EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("0.9.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC start_including + end_including pair: above range -> NO_MATCH",
     {LIT("*"), LIT("1.0.0"), EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("2.0.1"), CYTADEL_CPE_NO_MATCH},

    {"SYNTHETIC start_excluding + end_excluding pair: inside range -> MATCH",
     {LIT("*"), EMPTY, LIT("1.0.0"), EMPTY, LIT("2.0.0"), 1},
     LIT("1.5.0"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC start_excluding + end_excluding pair: at excluded lower "
     "edge -> NO_MATCH",
     {LIT("*"), EMPTY, LIT("1.0.0"), EMPTY, LIT("2.0.0"), 1},
     LIT("1.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC start_excluding + end_excluding pair: at excluded upper "
     "edge -> NO_MATCH",
     {LIT("*"), EMPTY, LIT("1.0.0"), EMPTY, LIT("2.0.0"), 1},
     LIT("2.0.0"), CYTADEL_CPE_NO_MATCH},

    /* Both start bounds set simultaneously -- the stricter must win
     * (header comment refinement 4). start_including=1.0.0 (permits
     * >=1.0.0), start_excluding=1.0.0 (permits >1.0.0, strictly stricter).
     * Detected exactly 1.0.0 passes the including bound but fails the
     * excluding bound -> overall NO_MATCH, proving both are actually
     * evaluated (a bug that only checked one of the two would wrongly
     * MATCH here). */
    {"SYNTHETIC both start bounds set, detected at the stricter edge -> "
     "NO_MATCH (both bounds are actually enforced)",
     {LIT("*"), LIT("1.0.0"), LIT("1.0.0"), EMPTY, EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC both start bounds set, detected past both -> MATCH",
     {LIT("*"), LIT("1.0.0"), LIT("1.0.0"), EMPTY, EMPTY, 1},
     LIT("1.0.1"), CYTADEL_CPE_MATCH},

    /* Both end bounds set simultaneously, same reasoning. */
    {"SYNTHETIC both end bounds set, detected at the stricter edge -> "
     "NO_MATCH (both bounds are actually enforced)",
     {LIT("*"), EMPTY, EMPTY, LIT("2.0.0"), LIT("2.0.0"), 1},
     LIT("2.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC both end bounds set, detected before both -> MATCH",
     {LIT("*"), EMPTY, EMPTY, LIT("2.0.0"), LIT("2.0.0"), 1},
     LIT("1.9.9"), CYTADEL_CPE_MATCH},

    /* All four bounds set at once. */
    {"SYNTHETIC all four bounds set, detected inside every one -> MATCH",
     {LIT("*"), LIT("1.0.0"), LIT("0.9.0"), LIT("3.0.0"), LIT("3.0.1"), 1},
     LIT("2.0.0"), CYTADEL_CPE_MATCH},
    {"SYNTHETIC all four bounds set, detected fails only the tightest "
     "(start_including) -> NO_MATCH",
     {LIT("*"), LIT("1.0.0"), LIT("0.9.0"), LIT("3.0.0"), LIT("3.0.1"), 1},
     LIT("0.9.5"), CYTADEL_CPE_NO_MATCH},

    /* ===================================================================
     * SYNTHETIC: the malformed all-four-empty range row.
     * =================================================================== */
    {"SYNTHETIC malformed row: version='*', all four bounds empty -> "
     "MALFORMED_ROW, never MATCH",
     {LIT("*"), EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("9.9.9"), CYTADEL_CPE_MALFORMED_ROW},
    {"SYNTHETIC malformed row via empty-string version (also range-row "
     "per SS3's exact-match exclusion), all bounds empty -> MALFORMED_ROW",
     {EMPTY, EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("9.9.9"), CYTADEL_CPE_MALFORMED_ROW},

    /* ===================================================================
     * SYNTHETIC: '*' / '-' / NA handling on `version` and defensively on
     * bounds (header comment refinement 3).
     * =================================================================== */
    {"SYNTHETIC version='-' (CPE NA) treated as unparseable exact-match "
     "text, never a literal match or a wildcard -> UNDECIDABLE",
     {LIT("-"), EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_UNDECIDABLE},
    {"SYNTHETIC version='-' vs detected also '-' -- still UNDECIDABLE, "
     "'-' is never compared as literal text even against itself",
     {LIT("-"), EMPTY, EMPTY, EMPTY, EMPTY, 1},
     LIT("-"), CYTADEL_CPE_UNDECIDABLE},
    {"W-1 defensive: a bound field hostilely set to '*' instead of '' is a "
     "structurally bad row (MALFORMED_ROW), never skipped and never a literal "
     "text compare",
     {LIT("*"), LIT("*"), EMPTY, EMPTY, EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_MALFORMED_ROW},
    {"W-1 defensive: a bound field hostilely set to '-' instead of '' is a "
     "structurally bad row (MALFORMED_ROW), not compared as pure-delimiter text",
     {LIT("*"), EMPTY, EMPTY, LIT("-"), EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_MALFORMED_ROW},

    /* ===================================================================
     * SYNTHETIC: vulnerable=0 rows (header comment refinement 5) --
     * exercised on both row kinds, including one with bounds that would
     * otherwise MATCH and one with a malformed shape, to prove vulnerable=0
     * is checked before anything else and always wins with NO_MATCH.
     * =================================================================== */
    {"SYNTHETIC vulnerable=0 range row that would otherwise MATCH -> "
     "NO_MATCH regardless",
     {LIT("*"), LIT("1.0.0"), EMPTY, LIT("2.0.0"), EMPTY, 0},
     LIT("1.5.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC vulnerable=0 malformed-shaped row (all bounds empty) -> "
     "still NO_MATCH, not MALFORMED_ROW (vulnerable=0 short-circuits "
     "before the malformed check ever runs)",
     {LIT("*"), EMPTY, EMPTY, EMPTY, EMPTY, 0},
     LIT("9.9.9"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC vulnerable=0 exact-match row with equal version -> "
     "NO_MATCH regardless",
     {LIT("2.4.6"), EMPTY, EMPTY, EMPTY, EMPTY, 0},
     LIT("2.4.6"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC vulnerable field is a hostile nonzero-but-not-1 value "
     "(defensive 'nonzero means true' convention) -- treated as "
     "vulnerable=1, normal MATCH",
     {LIT("2.4.6"), EMPTY, EMPTY, EMPTY, EMPTY, 42},
     LIT("2.4.6"), CYTADEL_CPE_MATCH},

    /* ===================================================================
     * SYNTHETIC: UNDECIDABLE propagation, including the short-circuit
     * subtlety (header comment refinement 2), tested with the
     * decidable-FAIL and the UNDECIDABLE bound placed in DIFFERENT struct
     * fields (a proxy for "different evaluation order") -- both must land
     * on NO_MATCH, and the "no FAIL, one UNDECIDABLE" case must land on
     * UNDECIDABLE regardless of which field carries it.
     *
     * "1.0.0-cr1" vs "1.0.0" is UNDECIDABLE per slice A's own truth table
     * (tests/unit/test_version_compare.c: unrecognized detached alpha
     * residual "cr1", round-2 fix) -- reused here verbatim, not
     * reinvented.
     * =================================================================== */
    {"SYNTHETIC short-circuit A: start_including decidably FAILS, "
     "end_excluding is UNDECIDABLE -> overall NO_MATCH (the definite "
     "failure settles it)",
     {LIT("*"), LIT("5.0.0"), EMPTY, EMPTY, LIT("1.0.0-cr1"), 1},
     LIT("1.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC short-circuit B: same verdicts, FAIL and UNDECIDABLE "
     "swapped into the OTHER pair of fields -> still NO_MATCH (order-"
     "independent)",
     {LIT("*"), LIT("1.0.0-cr1"), EMPTY, EMPTY, LIT("0.5.0"), 1},
     LIT("1.0.0"), CYTADEL_CPE_NO_MATCH},
    {"SYNTHETIC genuine UNDECIDABLE A: start_including is UNDECIDABLE, "
     "end_including decidably PASSES (no FAIL anywhere) -> overall "
     "UNDECIDABLE",
     {LIT("*"), LIT("1.0.0-cr1"), EMPTY, LIT("5.0.0"), EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_UNDECIDABLE},
    {"SYNTHETIC genuine UNDECIDABLE B: same verdicts, PASS and "
     "UNDECIDABLE swapped into the OTHER pair of fields -> still "
     "UNDECIDABLE",
     {LIT("*"), LIT("0.0.0"), EMPTY, LIT("1.0.0-cr1"), EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_UNDECIDABLE},

    /* ===================================================================
     * SYNTHETIC: hostile input -- control bytes / non-ASCII / embedded NUL
     * in the detected version and in a bound, both routed straight through
     * to slice A (never crashes, always a clean UNDECIDABLE/NO_MATCH per
     * slice A's own hostile-input rules).
     * =================================================================== */
    {"SYNTHETIC hostile: detected_version contains embedded NUL -> "
     "UNDECIDABLE (control byte), not a crash",
     {LIT("*"), LIT("1.0.0"), EMPTY, EMPTY, EMPTY, 1},
     "1.0\0zz", sizeof("1.0\0zz") - 1, CYTADEL_CPE_UNDECIDABLE},
    {"SYNTHETIC hostile: detected_version contains a high-bit non-ASCII "
     "byte -> UNDECIDABLE, not a crash",
     {LIT("*"), LIT("1.0.0"), EMPTY, EMPTY, EMPTY, 1},
     "1.0\xff", 4, CYTADEL_CPE_UNDECIDABLE},
    {"SYNTHETIC hostile: a bound field itself contains a control byte -- "
     "still UNDECIDABLE for that bound, no crash",
     {LIT("*"), "1.0\t.0", 6, EMPTY, EMPTY, EMPTY, 1},
     LIT("2.0.0"), CYTADEL_CPE_UNDECIDABLE},

    /* ---- W-1: sentinel-only bound must never compare as text ---- */
    {"W-1: bound of solely '*' is a bad row (MALFORMED_ROW), never a lexical "
     "MATCH against a non-numeric detected version",
     {LIT("*"), LIT("*"), EMPTY, EMPTY, EMPTY, 1},
     LIT("unknown"), CYTADEL_CPE_MALFORMED_ROW},
    {"W-1: bound of solely '-' (NA) is a bad row, not compared as text",
     {LIT("*"), EMPTY, EMPTY, LIT("-"), EMPTY, 1},
     LIT("1.0.0"), CYTADEL_CPE_MALFORMED_ROW},

    /* ---- W-4: non-NULL empty bound (what SQLite hands us) is skipped, same
     * as a NULL empty bound. Keys off len==0, not ptr==NULL. ---- */
    {"W-4: non-NULL empty start bound is skipped -> in-range MATCH",
     {LIT("*"), EMPTY_STR, EMPTY, LIT("2.0.0"), EMPTY, 1},
     LIT("1.5.0"), CYTADEL_CPE_MATCH},
    {"W-4: all four bounds non-NULL empty -> MALFORMED_ROW (still 'no bound set')",
     {LIT("*"), EMPTY_STR, EMPTY_STR, EMPTY_STR, EMPTY_STR, 1},
     LIT("1.5.0"), CYTADEL_CPE_MALFORMED_ROW},
};

#define CASES_COUNT (sizeof(CASES) / sizeof(CASES[0]))

static void test_table(void) {
    /* Reference the §7 exhaustiveness canary so it is genuinely compiled and
     * cannot be dropped as dead code -- its whole purpose is to be a
     * -Wswitch (no-default:) tripwire when the outcome set grows. */
    CYTADEL_ASSERT(cytadel_cpe_outcome_name_exhaustive(CYTADEL_CPE_MATCH) != NULL);

    for (size_t i = 0; i < CASES_COUNT; i++) {
        const cpe_case_t *c = &CASES[i];
        cytadel_cpe_match_t actual =
            cytadel_cpe_match_evaluate(&c->row, c->detected, c->detected_len);
        if (actual != c->expected) {
            fprintf(stderr, "case %zu FAILED: %s: expected %d got %d\n", i, c->desc,
                    (int)c->expected, (int)actual);
        }
        CYTADEL_ASSERT_EQ(actual, c->expected);
    }
}

/* ---------------------------------------------------------------------- *
 * Independent reversed-evaluation-order reference oracle (per this task's
 * explicit instruction: "Do not let evaluation order change the answer.
 * Test both orderings."). This is a SEPARATE, independently written
 * implementation of SS3's range-row three-valued AND that walks the four
 * bounds in the OPPOSITE order from cytadel_cpe_evaluate_range_row() in
 * src/match/cpe_match.c (end_excluding, end_including, start_excluding,
 * start_including instead of the production start-to-end order). It calls
 * cytadel_version_compare() directly (slice A's public API) rather than any
 * private production helper, so it is a genuinely independent check, not a
 * call-through to the same code path. Run across every range-row case in
 * CASES above, it must agree with cytadel_cpe_match_evaluate() on every
 * single row -- any disagreement would mean the production result secretly
 * depends on which order the bounds happen to be visited in, exactly the
 * defect this task warns against.
 * ---------------------------------------------------------------------- */
static cytadel_cpe_match_t reference_evaluate_range_reversed(const cytadel_cpe_match_row_t *row,
                                                              const char *detected,
                                                              size_t detected_len) {
    if (row->vulnerable == 0) {
        return CYTADEL_CPE_NO_MATCH;
    }

    /* W-1: independently mirror the sentinel-only-bound rejection. A set bound
     * that is solely '*'/'-' bytes is a structurally bad row. Checked up front
     * here (order-independent by definition) rather than interleaved. */
    struct {
        const char *p;
        size_t n;
    } rb[4] = {{row->version_end_excluding, row->version_end_excluding_len},
               {row->version_end_including, row->version_end_including_len},
               {row->version_start_excluding, row->version_start_excluding_len},
               {row->version_start_including, row->version_start_including_len}};
    for (size_t i = 0; i < 4; i++) {
        if (rb[i].n == 0) {
            continue;
        }
        bool sentinel_only = true;
        for (size_t j = 0; j < rb[i].n; j++) {
            if (rb[i].p[j] != '*' && rb[i].p[j] != '-') {
                sentinel_only = false;
                break;
            }
        }
        if (sentinel_only) {
            return CYTADEL_CPE_MALFORMED_ROW;
        }
    }

    bool any_set = false;
    bool any_fail = false;
    bool any_undecidable = false;

    /* end_excluding first */
    if (row->version_end_excluding_len > 0) {
        any_set = true;
        cytadel_vercmp_t cmp = cytadel_version_compare(
            detected, detected_len, row->version_end_excluding, row->version_end_excluding_len);
        if (cmp == CYTADEL_VERCMP_UNDECIDABLE) {
            any_undecidable = true;
        } else if (cmp != CYTADEL_VERCMP_LESS) {
            any_fail = true;
        }
    }
    /* end_including second */
    if (row->version_end_including_len > 0) {
        any_set = true;
        cytadel_vercmp_t cmp = cytadel_version_compare(
            detected, detected_len, row->version_end_including, row->version_end_including_len);
        if (cmp == CYTADEL_VERCMP_UNDECIDABLE) {
            any_undecidable = true;
        } else if (cmp == CYTADEL_VERCMP_GREATER) {
            any_fail = true;
        }
    }
    /* start_excluding third */
    if (row->version_start_excluding_len > 0) {
        any_set = true;
        cytadel_vercmp_t cmp =
            cytadel_version_compare(detected, detected_len, row->version_start_excluding,
                                     row->version_start_excluding_len);
        if (cmp == CYTADEL_VERCMP_UNDECIDABLE) {
            any_undecidable = true;
        } else if (cmp != CYTADEL_VERCMP_GREATER) {
            any_fail = true;
        }
    }
    /* start_including last */
    if (row->version_start_including_len > 0) {
        any_set = true;
        cytadel_vercmp_t cmp =
            cytadel_version_compare(detected, detected_len, row->version_start_including,
                                     row->version_start_including_len);
        if (cmp == CYTADEL_VERCMP_UNDECIDABLE) {
            any_undecidable = true;
        } else if (cmp == CYTADEL_VERCMP_LESS) {
            any_fail = true;
        }
    }

    if (!any_set) {
        return CYTADEL_CPE_MALFORMED_ROW;
    }
    if (any_fail) {
        return CYTADEL_CPE_NO_MATCH;
    }
    if (any_undecidable) {
        return CYTADEL_CPE_UNDECIDABLE;
    }
    return CYTADEL_CPE_MATCH;
}

static bool cpe_case_is_range_row(const cpe_case_t *c) {
    return (c->row.version_len == 1 && c->row.version[0] == '*') || c->row.version_len == 0;
}

static void test_reversed_evaluation_order_agrees(void) {
    for (size_t i = 0; i < CASES_COUNT; i++) {
        const cpe_case_t *c = &CASES[i];
        if (!cpe_case_is_range_row(c)) {
            continue; /* the reference oracle only re-implements the
                         range-row bound scan, not the exact-match path */
        }
        cytadel_cpe_match_t forward = cytadel_cpe_match_evaluate(&c->row, c->detected, c->detected_len);
        cytadel_cpe_match_t reversed =
            reference_evaluate_range_reversed(&c->row, c->detected, c->detected_len);
        if (forward != reversed) {
            fprintf(stderr,
                    "case %zu ORDER-DEPENDENCE DETECTED: %s: forward=%d reversed=%d\n", i,
                    c->desc, (int)forward, (int)reversed);
        }
        CYTADEL_ASSERT_EQ(forward, reversed);
    }
}

/* ---------------------------------------------------------------------- *
 * Hostile input: NULL row pointer. Cannot go through the CASES table (its
 * rows are all real structs), so this is its own function.
 * ---------------------------------------------------------------------- */
static void test_null_row_handling(void) {
    CYTADEL_ASSERT_EQ(cytadel_cpe_match_evaluate(NULL, "1.0.0", 5), CYTADEL_CPE_UNDECIDABLE);
}

/* ---------------------------------------------------------------------- *
 * Hostile input: NULL detected_version paired with a NONZERO length (a
 * caller bug) must not crash -- must propagate to UNDECIDABLE via slice A's
 * own NULL-with-nonzero-length guard.
 * ---------------------------------------------------------------------- */
static void test_null_detected_version_with_nonzero_length(void) {
    cytadel_cpe_match_row_t row = {LIT("1.0.0"), EMPTY, EMPTY, EMPTY, EMPTY, 1};
    CYTADEL_ASSERT_EQ(cytadel_cpe_match_evaluate(&row, NULL, 5), CYTADEL_CPE_UNDECIDABLE);

    cytadel_cpe_match_row_t range_row = {LIT("*"), LIT("1.0.0"), EMPTY, EMPTY, EMPTY, 1};
    CYTADEL_ASSERT_EQ(cytadel_cpe_match_evaluate(&range_row, NULL, 5), CYTADEL_CPE_UNDECIDABLE);
}

/* ---------------------------------------------------------------------- *
 * Hostile input: an absurdly long detected_version (thousands of bytes)
 * must not crash, hang, or overflow any stack buffer -- this evaluator
 * itself allocates nothing and recurses nowhere, and relies on slice A's
 * own already-proven O(n) iterative, non-recursive design
 * (test_version_compare.c's test_thousands_of_components()/
 * test_overlong_numeric_component()).
 * ---------------------------------------------------------------------- */
static void test_overlong_detected_version(void) {
    static char huge[8192];
    for (size_t i = 0; i < sizeof(huge); i++) {
        huge[i] = '9';
    }
    cytadel_cpe_match_row_t row = {LIT("*"), LIT("1.0.0"), EMPTY, EMPTY, EMPTY, 1};
    cytadel_cpe_match_t result = cytadel_cpe_match_evaluate(&row, huge, sizeof(huge));
    /* A 8192-digit numeric run is GREATER than "1.0.0"'s first component by
     * length alone (slice A never converts to an integer) -- start_including
     * PASSes, no other bound set -> MATCH. The real assertion here is "did
     * not crash/hang"; the exact verdict is a bonus sanity check. */
    CYTADEL_ASSERT_EQ(result, CYTADEL_CPE_MATCH);
}

int main(void) {
    test_table();
    test_reversed_evaluation_order_agrees();
    test_null_row_handling();
    test_null_detected_version_with_nonzero_length();
    test_overlong_detected_version();

    CYTADEL_TEST_PASS();
}
