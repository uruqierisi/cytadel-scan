#ifndef CYTADEL_MATCH_VERSION_COMPARE_H
#define CYTADEL_MATCH_VERSION_COMPARE_H

#include <stddef.h>

/* Version-string comparator (slice A of the version-range matching feature --
 * range/bound *evaluation* against cve_cpe_matches rows is a separate, later
 * slice and is NOT implemented here).
 *
 * This is the "single shared CPE-2.3-spec version comparator" required by
 * docs/contracts/db-schema.md (FROZEN CONTRACT) SS3 "Version-range matching
 * approach" and SS10 assumption 3: "Version comparison is never done in SQL
 * ... This must be one implementation, exposed to Lua via the plugin API, not
 * duplicated." This file is that one implementation. It is deliberately a
 * pure, length-bounded, allocation-free, reentrant C function with no global
 * state, so a future Lua binding (NOT built in this slice -- see db-schema.md
 * SS10 assumption 3's "exposed to Lua via the plugin API") can wrap it
 * directly without any additional synchronization or lifetime concerns.
 *
 * ---------------------------------------------------------------------------
 * Base algorithm (db-schema.md SS3, frozen, restated here verbatim in spirit):
 *   Split each version string on '.', '-', '_' into components; compare
 *   numeric components numerically; compare alpha components lexically.
 *
 * ---------------------------------------------------------------------------
 * Refinements/extensions of SS3 (this project's explicit direction; SS3 does
 * not spell any of these out, so each is documented here as a deliberate
 * extension a future maintainer must not silently "correct" back to a naive
 * reading of SS3):
 *
 *   1. Letter suffixes (OpenSSL point releases), e.g. "1.0.2k": a dot-
 *      delimited component may itself mix a digit run and a following letter
 *      run with NO delimiter between them ("2k" = digit-run "2" + alpha-run
 *      "k"). Such a component is further decomposed into its digit/alpha
 *      sub-runs, in order, and each sub-run participates in the comparison
 *      exactly like a top-level component. A trailing alpha sub-run that one
 *      side has and the other does not (e.g. "2k" vs "2") ranks the side that
 *      HAS it higher, UNLESS that alpha text is a recognized pre-release
 *      keyword (see refinement 5) -- "k" is not, so "1.0.2k" > "1.0.2", and
 *      "1.0.2k" < "1.0.2l" (both have the trailing alpha sub-run "k"/"l";
 *      compared lexically once both sides have one).
 *   2. OpenSSH-style patch letters, e.g. "7.2p2" vs "7.2": identical
 *      mechanism to refinement 1 ("2p2" = digit "2" + alpha "p" + digit "2").
 *      "7.2p2" > "7.2" (extra non-pre-release alpha sub-run); "7.2p2" <
 *      "7.2p3" (both have the "p" sub-run, differ only in the trailing
 *      digit).
 *   3. Debian epochs, e.g. "1:2.4.6": an optional `^[0-9]+:` prefix at the
 *      very start of the string is the epoch. An absent epoch is treated as
 *      epoch 0 (Debian semantics). Epochs are compared FIRST and dominate
 *      everything else -- if the epochs differ, the rest of the string is
 *      never even inspected. A ':' that is not preceded by digits starting
 *      at offset 0 is NOT treated as an epoch delimiter at all (this
 *      comparator does not invent an "epoch syntax error" UNDECIDABLE case
 *      for a stray, non-leading ':' -- it is simply ordinary alpha-run
 *      content at that point, per the base algorithm).
 *
 *      ****************************************************************
 *      * C-3 FIX (execution+mutation audit, this round): "epoch        *
 *      * dominates" does NOT mean "epoch alone can ever settle a       *
 *      * comparison against a side with no comparable content at all". *
 *      ****************************************************************
 *      An earlier version of this comparator computed the epoch comparison
 *      and returned it immediately whenever the epochs differed, BEFORE the
 *      "does this side have any real component at all after epoch-
 *      stripping" check (refinement 7's empty/all-delimiter bullet) ever
 *      ran. That made a bare epoch with nothing after it, e.g. "1:" (epoch
 *      "1", empty rest), compare as a definite GREATER than every epoch-0
 *      version in existence -- "1:" > "999.999", "1:" > "2.4.6", regardless
 *      of what either actually names -- a two-byte string that could
 *      out-rank any real version and fail every versionEnd* bound in a
 *      database, verified by execution. The empty/all-delimiter first-token
 *      check on each side's post-epoch remainder now runs BEFORE the epoch
 *      comparison is ever trusted (not after), so a version that is nothing
 *      but an epoch is UNDECIDABLE regardless of what the epoch digits
 *      themselves say -- "1:" vs "2.4.6" and "1:" vs "999.999" are both now
 *      CYTADEL_VERCMP_UNDECIDABLE, matching what this header already
 *      (correctly) documented for the case of EQUAL epochs (e.g. "5:" vs
 *      "5:1.0") but previously failed to apply when the epochs differed --
 *      the guard only worked "when the epoch is zero", which is exactly why
 *      it went uncaught. Pinned by tests/unit/test_version_compare.c's "C-3"
 *      rows.
 *   4. Distro revisions, e.g. "2.4.6-2ubuntu2.2" vs "2.4.6": after the
 *      shared prefix ("2","4","6") is exhausted on the shorter side, the
 *      longer side has residual components ("2", "ubuntu", "2", "2"). The
 *      first residual component is numeric and non-zero, so (by the same
 *      rule as refinements 1/2, generalized across a '-' delimiter boundary
 *      instead of only within one dot-component) the side WITH the revision
 *      is ranked higher: "2.4.6-2ubuntu2.2" > "2.4.6". Rationale: a distro
 *      rebuild/revision is additional, real version information layered on
 *      top of the pristine upstream release, not a "lesser" pre-release --
 *      the opposite of refinement 5's pre-release tokens.
 *   5. Pre-release-below-release, e.g. "1.0.0-alpha" < "1.0.0"; "1.0.0-rc1" <
 *      "1.0.0"; "-alpha" < "-beta" < "-rc" (case-insensitive keyword
 *      comparison, see the resolution note below).
 *
 *      ****************************************************************
 *      * CONFLICT WITH A NAIVE READING OF SS3, DOCUMENTED HERE:        *
 *      ****************************************************************
 *      SS3 says only "alpha components lexically" -- read completely
 *      naively/uniformly, an extra trailing alpha component would ALWAYS
 *      rank the side that has it higher (exactly refinements 1/2/4's rule).
 *      That reading is *correct* for "1.0.2k" (refinement 1), "7.2p2"
 *      (refinement 2), and "-2ubuntu2.2" (refinement 4), but is *wrong* for
 *      "-alpha"/"-rc1" (refinement 5): a pre-release must rank BELOW the
 *      release it precedes, not above it. A single uniform rule cannot get
 *      both right. This comparator resolves the conflict with a targeted,
 *      documented distinction instead of a uniform rule:
 *
 *        When one side has a residual component the other side lacks (after
 *        their shared prefix matches), walk the residual components in
 *        order:
 *          - a residual NUMERIC component equal to zero is skipped (zero-pad
 *            semantics, refinement 6) and the walk continues into the next
 *            residual component;
 *          - a residual NUMERIC component that is NON-zero immediately
 *            settles the comparison: the side with the residual is GREATER
 *            (refinements 1/2/4's rule);
 *          - a residual ALPHA component's verdict depends on the structural
 *            signal of WHERE it sits, not just what it spells (round-2
 *            fix, see "ATTACHED VS. DETACHED" below):
 *              - ATTACHED (no delimiter between it and the numeric run
 *                immediately before it, e.g. the "k" in "2k", the "p" in
 *                "2p2", the "ubuntu" in "2ubuntu2") -- always GREATER,
 *                regardless of what the letters spell. Attachment alone is
 *                the vendor-letter/patch-suffix signal (refinements 1/2/4);
 *              - DETACHED (its own '.'/'-'/'_' -delimited segment, e.g. the
 *                "alpha" in "-alpha", the "cr1"'s "cr" in "-cr1") -- checked
 *                against two small, fixed, case-insensitive keyword tables:
 *                  * CYTADEL_PRERELEASE_KEYWORDS ("alpha", "beta", "rc",
 *                    "pre", "preview", "dev", "devel", "snapshot",
 *                    "nightly", "test", "unstable", "alfa", "milestone"):
 *                    exact match -> LESS (refinement 5's pre-release rule);
 *                  * CYTADEL_RELEASE_EQUIVALENT_KEYWORDS ("ga", "final",
 *                    "release", "stable" -- these name the release itself,
 *                    e.g. Maven/JBoss's "GA" = General Availability): exact
 *                    match -> contributes nothing, walk continues exactly
 *                    like a zero-numeric residual (so a bare "-ga" with
 *                    nothing else following resolves EQUAL against the
 *                    bare release -- "GA *is* the release", not above or
 *                    below it);
 *                  * anything else detached -> CYTADEL_VERCMP_UNDECIDABLE.
 *                    A closed keyword table can never enumerate every
 *                    vendor's spelling ("a1", "b2", "M1" [Maven milestone],
 *                    "cr1" [JBoss candidate release], and endless others);
 *                    guessing GREATER for "unrecognized" was a real defect
 *                    an independent reviewer's out-of-tree probe found in
 *                    an earlier version of this comparator (it read
 *                    "1.0.0-cr1" as newer than "1.0.0", when a
 *                    candidate-release build is a pre-release of it -- the
 *                    exact false-negative failure mode, a genuinely
 *                    vulnerable host's version comparing outside an NVD
 *                    versionEndExcluding bound and the finding being
 *                    silently dropped, this comparator exists to prevent).
 *                    Detachment alone identifies "this is a pre-release
 *                    POSITION"; it is not enough signal to guess a
 *                    DIRECTION for an unrecognized spelling, so refinement
 *                    7 applies: UNDECIDABLE, not a guess.
 *
 *      ATTACHED VS. DETACHED: "attached" means zero delimiter bytes were
 *      skipped immediately before this alpha component began -- it directly
 *      continues the SAME '.'/'-'/'_' -delimited segment as the numeric run
 *      before it (by construction, alpha/digit runs are maximal, so an
 *      attached alpha component always immediately follows a numeric one).
 *      "Detached" means at least one delimiter byte was skipped immediately
 *      before it -- it starts its OWN segment. This is a purely structural,
 *      never-guessed signal read directly off the input, not an inference
 *      about word meaning.
 *
 *      This structural distinction is what makes every one of refinements
 *      1/2/4/5/6 correct simultaneously: "1.0.2k"/"7.2p2"/"-2ubuntu2.2" are
 *      all ATTACHED (or, for refinement 4, decided by a non-zero NUMERIC
 *      residual before the attached alpha is even reached) -> GREATER;
 *      "-alpha"/"-rc1" are DETACHED and keyword-recognized -> LESS; "-ga" is
 *      DETACHED and release-equivalent -> EQUAL; "-a1"/"-b2"/"-M1"/"-cr1"
 *      are DETACHED and unrecognized -> UNDECIDABLE, not a guess.
 *      --- C-2 FIX (was a false comment + real defect; see
 *      src/match/version_compare.c's same-position alpha branch and
 *      cytadel_alpha_keyword_rank): when both sides HAVE an alpha component
 *      at the exact same shared position (not a residual -- e.g. "ga" vs
 *      "rc" at the same slot), the keyword tables ARE consulted, via a
 *      keyword RANK: release-equivalent ("ga"/"final"/"release"/"stable")
 *      outranks any unrecognized-but-decidable alpha, which outranks a
 *      pre-release keyword ("alpha"/"beta"/"rc"/...). A recognized keyword
 *      against an UNRECOGNIZED alpha is UNDECIDABLE, not a lexical guess.
 *      Only when BOTH sides are in the same rank (both pre-release, both
 *      release-equivalent, or both unrecognized) does it fall through to a
 *      case-insensitive lexical compare (SS3's literal rule). The earlier
 *      "plain lexical, no keyword table" behavior described here was WRONG:
 *      it ordered 21/52 release-equivalent x pre-release pairs backwards
 *      (e.g. "ga" < "rc") and produced 597 transitivity-cycle violations,
 *      which broke range coherence. Do NOT revert to plain lexical.
 *   6. Partial versions, e.g. "2.4" vs "2.4.0": this comparator chooses
 *      ZERO-PAD-EQUAL, not shorter-is-less. Rationale: in the vulnerability-
 *      matching domain this comparator exists for, "2.4" and "2.4.0"
 *      virtually always name the identical upstream release (elided
 *      trailing ".0" is extremely common banner/NVD-version-string
 *      variance, not a real distinction), and NVD versionStart/End bounds
 *      routinely mix full and short forms. Choosing shorter-is-less would
 *      make "2.4" < "2.4.0" even when they denote the same release, risking
 *      both false positives and false negatives against range bounds
 *      expressed in the other form. Zero-pad-equal is exactly the terminal
 *      case of refinement 5's residual walk: an all-zero residual (e.g. "2.4"
 *      vs "2.4.0.0") is EQUAL; the walk only stops early at a non-zero
 *      numeric or an alpha residual component.
 *   7. UNDECIDABLE is returned, never guessed, for a small, fixed, documented
 *      set of conditions -- see CYTADEL_VERCMP_UNDECIDABLE's own comment
 *      below for the exact list. Deliberately NOT included in that list:
 *      two distinct plain alpha-only strings (e.g. "unknown" vs "dev") are
 *      still compared lexically per SS3's literal rule and are NOT
 *      UNDECIDABLE -- SS3 already defines that outcome, so returning it is
 *      applying the contract, not guessing.
 *
 * Case sensitivity: every alpha-vs-alpha comparison in this comparator
 * (lexical ordering AND pre-release-keyword matching) is ASCII
 * case-insensitive. SS3 does not specify case handling; case-insensitive was
 * chosen because real banners/NVD strings mix case ("RC1" vs "rc1") and a
 * scanner that silently mis-orders on case alone would be a correctness bug
 * in the domain this comparator serves. This is an explicit extension of SS3,
 * not a literal reading of it.
 *
 * Hostile input handling: `a`/`b` need not be NUL-terminated and MAY contain
 * embedded NUL bytes -- this comparator never calls strlen() on them and
 * never reads past a_len/b_len or b_len bytes respectively. Numeric
 * components of arbitrary length (thousands of digits) are compared by
 * stripping leading zeros and then comparing remaining length, then a bounded
 * memcmp() -- never by converting to an integer, so there is no
 * strtol()-into-overflow undefined behavior or truncation regardless of
 * digit-run length. The whole comparison is a single linear (O(a_len +
 * b_len)) iterative scan with no recursion and no heap allocation, so
 * "thousands of components" or very long strings cannot cause a stack
 * overflow or unbounded memory use.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Three-state (plus UNDECIDABLE) result of cytadel_version_compare(). This is
 * deliberately NOT a bool and NOT a bare int -- see that function's own
 * comment for why UNDECIDABLE must be a first-class, never-guessed outcome
 * distinct from LESS/EQUAL/GREATER, and callers (e.g. the future range-
 * evaluation slice B) must handle all four cases explicitly rather than
 * treating a non-zero return as "not equal" the way a plain int comparator
 * result often would be. */
typedef enum {
    CYTADEL_VERCMP_LESS = 0,
    CYTADEL_VERCMP_EQUAL,
    CYTADEL_VERCMP_GREATER,
    CYTADEL_VERCMP_UNDECIDABLE
} cytadel_vercmp_t;

/* Compares version string `a` (a_len bytes, need not be NUL-terminated)
 * against version string `b` (b_len bytes, same). Neither buffer is mutated
 * or retained past this call; this function performs no allocation and is
 * fully reentrant (no global/static mutable state), so it is safe to call
 * concurrently from any number of threads with no external locking.
 *
 * `a`/`b` may be NULL only when the corresponding length is 0 (an empty
 * version string); passing NULL together with a non-zero length is a caller
 * bug and is treated defensively as CYTADEL_VERCMP_UNDECIDABLE rather than
 * dereferencing the NULL pointer.
 *
 * Returns CYTADEL_VERCMP_UNDECIDABLE (never guessing LESS/EQUAL/GREATER
 * instead) when any of the following hold -- this is the complete, fixed set
 * this comparator recognizes as "genuinely unorderable/garbage/unparseable"
 * (module header comment, refinement 7):
 *   - `a` or `b` contains any byte < 0x20 (control, including an embedded
 *     NUL), the DEL byte 0x7F, or any byte >= 0x80 (non-ASCII -- this also
 *     subsumes every invalid-UTF-8 byte sequence, since UTF-8 invalidity can
 *     only arise from bytes >= 0x80);
 *   - `a` or `b`, after stripping an optional leading Debian epoch prefix,
 *     contains no numeric or alpha component at all -- i.e. it is empty, or
 *     consists entirely of '.'/'-'/'_' delimiter bytes with nothing between
 *     them (e.g. "", "...", "---", "1:" with nothing after the epoch's ':');
 *   - at some component position both `a` and `b` still have a component,
 *     but one is numeric and the other is alpha (e.g. "1.0" vs "1.a") -- SS3
 *     gives no rule for comparing a numeric component against an alpha one,
 *     so this is genuinely undefined rather than a guessable case;
 *   - one side has a residual (refinement 5/6) whose first alpha component
 *     is DETACHED (its own '.'/'-'/'_' -delimited segment -- a pre-release
 *     position) but is neither a recognized CYTADEL_PRERELEASE_KEYWORDS
 *     entry nor a recognized CYTADEL_RELEASE_EQUIVALENT_KEYWORDS entry
 *     (e.g. "1.0.0-cr1", "1.0.0-M1", "1.0.0-a1" against "1.0.0") -- a closed
 *     keyword table can never enumerate every vendor's pre-release spelling,
 *     so an unrecognized detached alpha residual is UNDECIDABLE, never
 *     guessed as GREATER (see the module header comment's refinement 5 for
 *     the real defect this fixes and why).
 *
 * Antisymmetry: for every pair, cytadel_version_compare(a,...,b,...) and
 * cytadel_version_compare(b,...,a,...) are exact mirror images of each other
 * (LESS<->GREATER swap, EQUAL stays EQUAL, UNDECIDABLE stays UNDECIDABLE) --
 * verified for every decidable row (and the UNDECIDABLE rows) in
 * tests/unit/test_version_compare.c. */
cytadel_vercmp_t cytadel_version_compare(const char *a, size_t a_len, const char *b, size_t b_len);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_MATCH_VERSION_COMPARE_H */
