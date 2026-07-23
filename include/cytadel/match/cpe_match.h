#ifndef CYTADEL_MATCH_CPE_MATCH_H
#define CYTADEL_MATCH_CPE_MATCH_H

#include <stddef.h>

/* CPE range/bound *evaluation* layer (slice B of the version-range matching
 * feature). Slice A (include/cytadel/match/version_compare.h,
 * cytadel_version_compare()) is the shared string comparator this slice
 * consumes; this file does NOT reimplement or duplicate any of its
 * component-splitting/numeric/pre-release logic -- every bound comparison
 * below is a single call to cytadel_version_compare(), never a direct
 * strcmp()/memcmp() on version text.
 *
 * This is the application-code evaluator required by
 * docs/contracts/db-schema.md (FROZEN CONTRACT) SS3 "Version-range matching
 * approach" and SS10 assumption 3: "SQLite must never be asked to compare
 * version strings directly ... All range/equality evaluation happens in
 * application code." It takes one candidate row already fetched from
 * `cve_cpe_matches` (SS3's `(vendor, product)` pre-filter query, SS9) plus
 * the detector's `detected_version`, and decides whether that row is a
 * match.
 *
 * ---------------------------------------------------------------------------
 * SS3 algorithm, restated verbatim in spirit (frozen, not reproduced here to
 * avoid drift -- see db-schema.md SS3 for the authoritative text):
 *
 *   1. Exact-match row (`version` NOT IN ('*','')): vulnerable iff
 *      compare(detected, row.version) == 0 AND row.vulnerable = 1.
 *   2. Range row (`version = '*'`): vulnerable iff row.vulnerable = 1 AND
 *      every SET bound holds (an empty-string bound is SKIPPED, not treated
 *      as 0):
 *        version_start_including = '' OR compare(detected, b) >= 0
 *        version_start_excluding = '' OR compare(detected, b) >  0
 *        version_end_including   = '' OR compare(detected, b) <= 0
 *        version_end_excluding   = '' OR compare(detected, b) <  0
 *      AND at least one of the four bounds is non-empty -- a range row with
 *      `version = '*'` and all four bounds empty is malformed and must NOT
 *      match every version ever detected.
 *
 * ---------------------------------------------------------------------------
 * Refinements/extensions of SS3 (this project's explicit direction for this
 * slice; SS3 does not spell any of these out, each documented here as a
 * deliberate extension, not a silent reinterpretation):
 *
 *   1. FOUR-STATE RESULT (cytadel_cpe_match_t), never a bool, never folded
 *      down to a tri-state:
 *        - CYTADEL_CPE_MATCH:      row applies to detected_version.
 *        - CYTADEL_CPE_NO_MATCH:   row definitely does not apply -- either a
 *          decidable bound/exact-compare failed, or row.vulnerable = 0.
 *        - CYTADEL_CPE_UNDECIDABLE: at least one bound comparison this
 *          result's outcome depends on returned CYTADEL_VERCMP_UNDECIDABLE
 *          (slice A could not order detected_version against that bound),
 *          and no OTHER, independent bound already produced a definite
 *          NO_MATCH that settles the row regardless (see the short-circuit
 *          rule below). UNDECIDABLE is a first-class outcome the caller
 *          (e.g. report generation) must surface distinctly -- collapsing
 *          it to NO_MATCH risks a false negative (a real vulnerability
 *          silently dropped); collapsing it to MATCH risks a false
 *          positive. Both break report trust, which is the entire reason
 *          this slice exists.
 *        - CYTADEL_CPE_MALFORMED_ROW: the row itself is structurally
 *          invalid per SS3 -- currently only "range row (`version = '*'`)
 *          with all four bounds empty". A SEPARATE enum value rather than
 *          folded into UNDECIDABLE, because the two causes are diagnostically
 *          different (an ingest-time DB defect vs. an unparseable version
 *          string) and a caller may reasonably want to alert on one but not
 *          the other -- see cytadel_cpe_match_t's own comment for exactly
 *          this rationale.
 *
 *   2. UNDECIDABLE PROPAGATION WITH SHORT-CIRCUIT, exactly per this task's
 *      instructions: SS3's range-row rule is a logical AND across up to four
 *      bound checks, each individually LESS/EQUAL/GREATER/UNDECIDABLE via
 *      slice A. Standard three-valued (Kleene) AND semantics apply:
 *        - ANY bound is a decidable FAIL (the comparison is decidable and
 *          the required inequality does not hold) -> the whole row is
 *          CYTADEL_CPE_NO_MATCH immediately, REGARDLESS of what any other
 *          bound (even an UNDECIDABLE one) would have said. A definite
 *          failure settles a logical AND; nothing else can rescue it.
 *        - No bound is a decidable FAIL, but AT LEAST ONE bound is
 *          UNDECIDABLE -> CYTADEL_CPE_UNDECIDABLE.
 *        - Every set bound is a decidable PASS (and at least one bound is
 *          set, per SS3's malformed-row rule) -> CYTADEL_CPE_MATCH.
 *      This is evaluation-order-independent by construction: all four
 *      bounds are always evaluated (never stopped early at the first
 *      UNDECIDABLE), and the three-valued AND above is applied to the
 *      complete set of four per-bound verdicts, so re-ordering which bound
 *      is checked first/last cannot change the final answer. Tested in both
 *      literal source-order and a reversed evaluation order in
 *      tests/unit/test_cpe_match.c to prove this independence empirically,
 *      not just by inspection.
 *
 *   3. CPE SPECIAL TOKENS -- '*', '-', and (defensively) any other
 *      non-version sentinel are NEVER compared as literal version text:
 *        - `version` field: '*' or empty string means "range row" (SS3's
 *          own rule, restated in cytadel_cpe_match_row_t's own comment
 *          below). '-' (CPE 2.3's "not applicable" logical value, "NA") on
 *          `version` is treated as "this CPE attribute is not applicable to
 *          this product at all" -- concretely, this evaluator treats a row
 *          whose `version` is exactly "-" the SAME as an exact-match row
 *          whose target text is the (unparseable) string "-": since
 *          cytadel_version_compare() cannot parse a bare hyphen as a real
 *          version (it is pure delimiter content, refinement 7's
 *          "all-delimiters" UNDECIDABLE bullet in version_compare.h) this
 *          naturally surfaces as CYTADEL_CPE_UNDECIDABLE rather than ever
 *          being silently treated as a wildcard match or a hard non-match --
 *          "not applicable" is not something this evaluator can respond to
 *          without more context. Documented explicitly rather than special-
 *          cased into a fifth enum value, because slice A's existing
 *          UNDECIDABLE-for-unparseable-text behavior already produces the
 *          right conservative answer with zero extra code.
 *        - Bound fields (`version_start_including` etc.): SS3 only defines
 *          '' as the "unbounded/skip" sentinel. Defensively, if a bound
 *          field ever arrives as '*' or '-' instead of '' (NVD should never
 *          emit this, but the row is hostile-JSON-derived per this task's
 *          brief), it is NOT treated as an empty/skip sentinel (only an
 *          exact, zero-length '' string is) and is NOT compared as literal
 *          text either -- it is handed to cytadel_version_compare() exactly
 *          like any other bound value. '*'/'-' are not parseable version
 *          strings by slice A's own rules (both are pure delimiter/single-
 *          alpha-run content that fails the epoch/first-token check or
 *          becomes an unparseable single alpha component), so this
 *          correctly surfaces as UNDECIDABLE for that one bound rather than
 *          silently matching or excluding every detected version.
 *
 *   4. MULTIPLE START/END BOUNDS SET SIMULTANEOUSLY: SS3 says "every SET
 *      bound holds" -- this is a logical AND across all four independently,
 *      so if both version_start_including AND version_start_excluding are
 *      set (or both end bounds), each is checked independently and ALL must
 *      pass; the stricter one effectively wins since failing either fails
 *      the row. No special-casing is needed or done for this combination --
 *      it falls directly out of treating the four bounds as four
 *      independent AND-ed conditions, but it is called out here and tested
 *      explicitly (tests/unit/test_cpe_match.c) since it is easy to
 *      mis-implement as "only check the tightest bound" by accident.
 *
 *   5. `vulnerable = 0`: per SS3 both row kinds require `vulnerable = 1` to
 *      ever produce a match. A `vulnerable = 0` row is NVD's own explicit
 *      "this configuration is NOT vulnerable" declaration (used to carve out
 *      an exception within a broader vulnerable range in some NVD
 *      configurations) -- this evaluator returns CYTADEL_CPE_NO_MATCH
 *      immediately for such a row WITHOUT evaluating any bound/exact-match
 *      comparison at all (vulnerable = 0 is checked first, unconditionally).
 *      This is a deliberate short-circuit: since the row can never produce
 *      MATCH or UNDECIDABLE-that-matters when vulnerable = 0 (the final
 *      answer is NO_MATCH no matter what the bounds say), skipping the bound
 *      evaluation avoids reporting a spurious CYTADEL_CPE_UNDECIDABLE for a
 *      row that could never have mattered anyway (e.g. a garbage bound
 *      string on a vulnerable=0 row must not surface as "undecidable" to a
 *      caller -- the row is settled NO_MATCH regardless of that garbage).
 *
 * ---------------------------------------------------------------------------
 * Hostile input: `row` fields originate from NVD JSON (already passed
 * through the ingest layer, but this evaluator makes NO trust assumption
 * beyond "each field is some byte buffer with an explicit length");
 * `detected_version` originates from an attacker-controlled network banner.
 * Every string here is passed as an explicit (pointer, length) pair --
 * NEVER strlen()'d -- straight through to cytadel_version_compare(), which
 * is itself embedded-NUL-safe and control/non-ASCII-byte-safe (see
 * version_compare.h). This evaluator itself performs no parsing of its own
 * beyond the trivial "is this field exactly the sentinel '*' / '' / '-'"
 * checks (plain length + memcmp against a 1-byte literal), allocates
 * nothing, recurses nowhere, and uses no VLA or unbounded stack buffer --
 * it is a small, fixed number of length-bounded comparisons and branches.
 * NULL pointers paired with a non-zero length are a caller bug; NULL is
 * tolerated only when the paired length is 0 (mirrors slice A's own
 * contract) -- see cytadel_cpe_match_row_t's field comments.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Result of evaluating one cve_cpe_matches candidate row against a detected
 * version string. Four-state by design -- see the module header comment's
 * refinement 1 for why UNDECIDABLE and MALFORMED_ROW are both distinct,
 * first-class outcomes rather than being folded into NO_MATCH or into each
 * other. Never treat a non-MATCH result as a uniform "not vulnerable" --
 * callers that care about false negatives (this whole project's stated
 * purpose) must branch on all four values explicitly. */
typedef enum {
    CYTADEL_CPE_NO_MATCH = 0,
    CYTADEL_CPE_MATCH,
    CYTADEL_CPE_UNDECIDABLE,
    CYTADEL_CPE_MALFORMED_ROW
} cytadel_cpe_match_t;

/* One candidate row from `cve_cpe_matches` (db-schema.md SS3), field-for-
 * field. Every `*_len` is the exact byte length of the corresponding
 * pointer's buffer -- none of these need be NUL-terminated, and none are
 * strlen()'d anywhere in this module. A field pointer may be NULL only when
 * its paired length is 0 (an empty string, e.g. an unset bound) -- NULL with
 * a non-zero length is a caller bug, handled defensively (see
 * cytadel_cpe_match_evaluate()'s own comment) rather than dereferenced.
 *
 * `vulnerable` is the row's raw `vulnerable` column value (0 or 1 per the
 * frozen schema's CHECK constraint); this struct does not validate it is
 * exactly 0 or 1 -- any nonzero value is treated as "1" (true), matching the
 * project-wide boolean convention (db-schema.md's binding "Booleans" note:
 * 0 = false, 1 = true) applied defensively to a hostile/corrupt caller-
 * supplied value rather than trusting it is exactly 1. */
typedef struct {
    const char *version;
    size_t version_len;

    const char *version_start_including;
    size_t version_start_including_len;

    const char *version_start_excluding;
    size_t version_start_excluding_len;

    const char *version_end_including;
    size_t version_end_including_len;

    const char *version_end_excluding;
    size_t version_end_excluding_len;

    int vulnerable;
} cytadel_cpe_match_row_t;

/* Evaluates `row` against `detected_version` (detected_version_len bytes,
 * need not be NUL-terminated, may contain embedded NUL/control/non-ASCII
 * bytes -- all handled safely by the underlying cytadel_version_compare()
 * calls) per the algorithm in this header's own top comment.
 *
 * `detected_version` may be NULL only when detected_version_len is 0
 * (mirrors cytadel_version_compare()'s own NULL/length-0 contract) --
 * pairing NULL with a nonzero length is a caller bug and is handled
 * defensively (every comparison against it becomes UNDECIDABLE via
 * cytadel_version_compare()'s own NULL-with-nonzero-length guard, rather
 * than dereferencing) instead of crashing.
 *
 * `row` itself must not be NULL; passing NULL is a caller bug and is
 * treated defensively (returns CYTADEL_CPE_UNDECIDABLE without
 * dereferencing `row`) rather than crashing, but callers should never rely
 * on this -- always pass a real row. */
cytadel_cpe_match_t cytadel_cpe_match_evaluate(const cytadel_cpe_match_row_t *row,
                                                const char *detected_version,
                                                size_t detected_version_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_MATCH_CPE_MATCH_H */
