#include "cytadel/match/cpe_match.h"

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/match/version_compare.h"

/* See include/cytadel/match/cpe_match.h for the full design writeup (SS3's
 * base algorithm, every refinement 1-5 and their rationale, the four-state
 * result, the short-circuit-safe three-valued AND, CPE special-token
 * handling). This file is the mechanical implementation of that writeup;
 * comments here are deliberately short and point back to the header instead
 * of re-deriving the reasoning. Every bound/exact-version comparison below
 * is a single call to cytadel_version_compare() (slice A) -- this file never
 * inspects version bytes itself beyond the trivial "is this field exactly
 * the one-byte '*' sentinel, or exactly empty" checks below. */

/* True iff `s` (s_len bytes) is exactly the one-byte CPE wildcard "*".
 * Never treats '*' as literal version text -- see header comment refinement
 * 3. */
static bool cytadel_cpe_is_star(const char *s, size_t s_len) {
    return s != NULL && s_len == 1 && s[0] == '*';
}

/* Which of SS3's four range-row inequalities a bound field represents. Used
 * only to select the correct verdict-from-comparison rule below; carries no
 * other behavior. */
typedef enum {
    CYTADEL_BOUND_START_INCLUDING,
    CYTADEL_BOUND_START_EXCLUDING,
    CYTADEL_BOUND_END_INCLUDING,
    CYTADEL_BOUND_END_EXCLUDING
} cytadel_bound_kind_t;

typedef enum {
    CYTADEL_BOUND_PASS,
    CYTADEL_BOUND_FAIL,
    CYTADEL_BOUND_UNDECIDABLE
} cytadel_bound_verdict_t;

/* Translates one bound's cytadel_version_compare(detected, bound) result
 * into PASS/FAIL/UNDECIDABLE per SS3's exact inequality for that bound kind
 * (header comment, base algorithm section). UNDECIDABLE always propagates
 * regardless of bound kind -- this is never guessed into PASS or FAIL. */
static cytadel_bound_verdict_t cytadel_cpe_bound_verdict(cytadel_bound_kind_t kind,
                                                          cytadel_vercmp_t cmp) {
    if (cmp == CYTADEL_VERCMP_UNDECIDABLE) {
        return CYTADEL_BOUND_UNDECIDABLE;
    }
    switch (kind) {
        case CYTADEL_BOUND_START_INCLUDING:
            /* compare(detected, bound) >= 0 */
            return (cmp == CYTADEL_VERCMP_GREATER || cmp == CYTADEL_VERCMP_EQUAL)
                       ? CYTADEL_BOUND_PASS
                       : CYTADEL_BOUND_FAIL;
        case CYTADEL_BOUND_START_EXCLUDING:
            /* compare(detected, bound) > 0 */
            return (cmp == CYTADEL_VERCMP_GREATER) ? CYTADEL_BOUND_PASS : CYTADEL_BOUND_FAIL;
        case CYTADEL_BOUND_END_INCLUDING:
            /* compare(detected, bound) <= 0 */
            return (cmp == CYTADEL_VERCMP_LESS || cmp == CYTADEL_VERCMP_EQUAL)
                       ? CYTADEL_BOUND_PASS
                       : CYTADEL_BOUND_FAIL;
        case CYTADEL_BOUND_END_EXCLUDING:
        default:
            /* compare(detected, bound) < 0 */
            return (cmp == CYTADEL_VERCMP_LESS) ? CYTADEL_BOUND_PASS : CYTADEL_BOUND_FAIL;
    }
}

/* One (pointer, length, kind) triple for the generic bound-scan loop below. */
typedef struct {
    const char *ptr;
    size_t len;
    cytadel_bound_kind_t kind;
} cytadel_bound_field_t;

/* Range-row evaluator (header comment refinement 2): scans all four bounds
 * unconditionally -- never stops early at the first UNDECIDABLE or the
 * first FAIL -- then combines the four per-bound verdicts with a standard
 * three-valued (Kleene) AND:
 *   - any bound is a decidable FAIL  -> CYTADEL_CPE_NO_MATCH (a definite
 *     failure settles the AND regardless of any other bound's verdict,
 *     including another bound's UNDECIDABLE);
 *   - else any bound is UNDECIDABLE  -> CYTADEL_CPE_UNDECIDABLE;
 *   - else (every set bound PASSES, and at least one bound is set)
 *                                     -> CYTADEL_CPE_MATCH.
 * Because the combination only depends on the aggregate booleans
 * "any bound set" / "any FAIL" / "any UNDECIDABLE" -- never on which
 * specific bound produced which verdict, or the order they were visited in
 * -- the result is provably independent of the array order below. This is
 * exercised from both directions in tests/unit/test_cpe_match.c (rows that
 * place the decidable FAIL and the UNDECIDABLE bound in different struct
 * fields, plus an independent reversed-order reference evaluator). */
/* W-1: true iff `s` is non-empty and every byte is a CPE sentinel ('*' or
 * '-'). Such a string carries no version information and must never be
 * compared as text. */
static bool cytadel_cpe_bound_is_sentinel_only(const char *s, size_t len) {
    if (len == 0) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (s[i] != '*' && s[i] != '-') {
            return false;
        }
    }
    return true;
}

static cytadel_cpe_match_t cytadel_cpe_evaluate_range_row(const cytadel_cpe_match_row_t *row,
                                                           const char *detected,
                                                           size_t detected_len) {
    const cytadel_bound_field_t bounds[4] = {
        {row->version_start_including, row->version_start_including_len,
         CYTADEL_BOUND_START_INCLUDING},
        {row->version_start_excluding, row->version_start_excluding_len,
         CYTADEL_BOUND_START_EXCLUDING},
        {row->version_end_including, row->version_end_including_len,
         CYTADEL_BOUND_END_INCLUDING},
        {row->version_end_excluding, row->version_end_excluding_len, CYTADEL_BOUND_END_EXCLUDING},
    };

    bool any_set = false;
    bool any_fail = false;
    bool any_undecidable = false;

    for (size_t i = 0; i < 4; i++) {
        if (bounds[i].len == 0) {
            /* Empty-string sentinel: unbounded on this side, SKIPPED (SS3),
             * never treated as "0" and never counted toward "any bound
             * set". */
            continue;
        }
        any_set = true;
        /* W-1 fix: a bound field consisting solely of CPE sentinel bytes
         * ('*' = ANY, '-' = NA) is not a version -- '*' (0x2A) and '-' (0x2D)
         * are neither digit nor delimiter, so the comparator would tokenize
         * them as an alpha run and lexically compare them against a real
         * version, which can fabricate a MATCH (e.g. detected "unknown" vs a
         * bound of "*"). A sentinel-only bound is a structurally invalid NVD
         * row (bounds are meant to be empty-string when unset), so classify it
         * on the row axis as MALFORMED_ROW rather than ever comparing it. */
        if (cytadel_cpe_bound_is_sentinel_only(bounds[i].ptr, bounds[i].len)) {
            return CYTADEL_CPE_MALFORMED_ROW;
        }
        cytadel_vercmp_t cmp =
            cytadel_version_compare(detected, detected_len, bounds[i].ptr, bounds[i].len);
        cytadel_bound_verdict_t v = cytadel_cpe_bound_verdict(bounds[i].kind, cmp);
        if (v == CYTADEL_BOUND_FAIL) {
            any_fail = true;
        } else if (v == CYTADEL_BOUND_UNDECIDABLE) {
            any_undecidable = true;
        }
    }

    if (!any_set) {
        /* SS3: a range row (`version = '*'`) with all four bounds empty is
         * malformed -- must never silently match every version. */
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

cytadel_cpe_match_t cytadel_cpe_match_evaluate(const cytadel_cpe_match_row_t *row,
                                                const char *detected_version,
                                                size_t detected_version_len) {
    /* Defensive: a NULL row is a caller bug. Never dereference it. */
    if (row == NULL) {
        return CYTADEL_CPE_UNDECIDABLE;
    }

    /* Refinement 5 (header comment): vulnerable=0 rows are NO_MATCH
     * unconditionally, checked FIRST, before determining exact-vs-range,
     * before the malformed-row check, and before any bound/exact-version
     * comparison. A vulnerable=0 row can never produce MATCH or a
     * meaningful UNDECIDABLE regardless of its bounds, so evaluating them
     * at all would only risk surfacing a spurious UNDECIDABLE from garbage
     * bound text on a row whose answer is already settled. */
    if (row->vulnerable == 0) {
        return CYTADEL_CPE_NO_MATCH;
    }

    /* SS3: range row iff version IN ('*', ''). '*' is CPE's own wildcard
     * token and is never compared as literal version text (header comment
     * refinement 3); an empty version is the same "no pinned version, use
     * the bounds" case per SS3's literal "NOT IN ('*','')" exact-match
     * rule. */
    bool is_range_row = cytadel_cpe_is_star(row->version, row->version_len) ||
                         row->version_len == 0;

    if (is_range_row) {
        return cytadel_cpe_evaluate_range_row(row, detected_version, detected_version_len);
    }

    /* Exact-match row (SS3): vulnerable iff compare(detected, row.version)
     * == EQUAL. `vulnerable == 1` was already established above. Any CPE
     * '-' (NA) or other non-'*' sentinel arriving in `version` is NOT
     * special-cased here -- it is handed straight to
     * cytadel_version_compare() like any other exact-match target, which
     * (per its own documented UNDECIDABLE rules) naturally answers
     * UNDECIDABLE for unparseable sentinel text such as a bare "-" rather
     * than ever being silently treated as a wildcard or a hard non-match
     * (header comment refinement 3). */
    cytadel_vercmp_t cmp = cytadel_version_compare(detected_version, detected_version_len,
                                                    row->version, row->version_len);
    switch (cmp) {
        case CYTADEL_VERCMP_EQUAL:
            return CYTADEL_CPE_MATCH;
        case CYTADEL_VERCMP_UNDECIDABLE:
            return CYTADEL_CPE_UNDECIDABLE;
        case CYTADEL_VERCMP_LESS:
        case CYTADEL_VERCMP_GREATER:
        default:
            return CYTADEL_CPE_NO_MATCH;
    }
}
