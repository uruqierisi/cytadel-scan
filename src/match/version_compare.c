#include "cytadel/match/version_compare.h"

#include <stdbool.h>
#include <string.h>

/* See include/cytadel/match/version_compare.h for the full design writeup
 * (base algorithm, every refinement 1-7 and their rationale, the SS3
 * pre-release-vs-letter-suffix conflict and its resolution, hostile-input
 * handling). This file is the mechanical implementation of that writeup;
 * comments here are deliberately short and point back to the header instead
 * of re-deriving the reasoning. */

/* --------------------------------------------------------------------- *
 * Byte classification. Every byte is handled as `unsigned char` so plain
 * `char` signedness never produces undefined/implementation-defined
 * behavior (the classic <ctype.h> isdigit()-on-a-negative-char pitfall) --
 * these are hand-written comparisons, not ctype.h calls, specifically to
 * avoid that.
 * --------------------------------------------------------------------- */

static bool cytadel_is_digit_byte(unsigned char c) {
    return c >= (unsigned char)'0' && c <= (unsigned char)'9';
}

static bool cytadel_is_delim_byte(unsigned char c) {
    return c == (unsigned char)'.' || c == (unsigned char)'-' || c == (unsigned char)'_';
}

static unsigned char cytadel_to_lower_ascii(unsigned char c) {
    if (c >= (unsigned char)'A' && c <= (unsigned char)'Z') {
        return (unsigned char)(c + ('a' - 'A'));
    }
    return c;
}

/* W-3 fix: strip a single leading 'v'/'V' when it is IMMEDIATELY followed by
 * a digit (e.g. "v2.1.0", "V2.1.0") before any tokenizing happens. This is
 * the single most common real-world spelling variance in this domain (Go
 * modules, GitHub release tags, etc. routinely prefix a bare "v" onto an
 * otherwise ordinary version) and is unambiguous: no real version scheme
 * means anything else by a leading "v" directly glued to a digit. Only ONE
 * leading byte is ever stripped, and only under this exact condition -- an
 * alpha string that merely starts with the letter v (e.g. "vfoo", or a bare
 * "v" with nothing after it) is left completely alone and continues to be
 * ordinary alpha-run content per the base algorithm. Applied once, up front,
 * to the RAW input (before epoch-splitting), and independently to each of
 * `a`/`b` -- see cytadel_version_compare()'s call sites. Pinned by
 * tests/unit/test_version_compare.c's "W-3 SYNTHETIC" rows (revert-proved:
 * see version_compare.h's own comment on this fix and its test name). */
static void cytadel_strip_v_prefix(const char **s, size_t *len) {
    if (*len >= 2 && ((unsigned char)(*s)[0] == (unsigned char)'v' ||
                       (unsigned char)(*s)[0] == (unsigned char)'V') &&
        cytadel_is_digit_byte((unsigned char)(*s)[1])) {
        *s += 1;
        *len -= 1;
    }
}

/* Header comment's first UNDECIDABLE bullet: any control byte (< 0x20),
 * DEL (0x7F), or non-ASCII byte (>= 0x80) anywhere in s[0..len). Bounded by
 * `len` only -- never calls strlen(), so an embedded NUL is inspected (and
 * rejected, since 0x00 < 0x20) rather than silently truncating the scan. */
static bool cytadel_has_disallowed_byte(const char *s, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c < 0x20 || c == 0x7F || c >= 0x80) {
            return true;
        }
    }
    return false;
}

/* --------------------------------------------------------------------- *
 * Tokenizer: streaming, O(1)-extra-space extraction of the next digit-run
 * or alpha-run component from buf[0..len), starting at *pos, skipping any
 * run of delimiter bytes first. Never allocates; never looks past `len`.
 * --------------------------------------------------------------------- */

typedef enum {
    CYTADEL_TOK_NONE = 0,
    CYTADEL_TOK_NUM,
    CYTADEL_TOK_ALPHA
} cytadel_tok_type_t;

/* `*out_delim_skipped` reports whether at least one delimiter byte was
 * skipped immediately before this token began -- i.e. whether the token
 * starts its OWN '.'/'-'/'_' -delimited segment ("detached") rather than
 * directly continuing the previous token with no separator at all
 * ("attached", e.g. the "k" in "2k" or the "p" in "2p2"). This is the
 * structural signal refinement 5's residual walk (cytadel_residual_verdict()
 * below) uses to distinguish a vendor letter/patch suffix from a
 * pre-release marker -- see that function's header comment. Callers that
 * do not need it (the main lockstep loop's "both sides present" branch)
 * may pass a throwaway bool. */
static cytadel_tok_type_t cytadel_next_token(const char *buf, size_t len, size_t *pos,
                                              size_t *out_start, size_t *out_len,
                                              bool *out_delim_skipped) {
    size_t p = *pos;
    while (p < len && cytadel_is_delim_byte((unsigned char)buf[p])) {
        p++;
    }
    *out_delim_skipped = (p != *pos);
    if (p >= len) {
        *pos = p;
        *out_start = p;
        *out_len = 0;
        return CYTADEL_TOK_NONE;
    }

    size_t start = p;
    bool numeric = cytadel_is_digit_byte((unsigned char)buf[p]);
    if (numeric) {
        while (p < len && cytadel_is_digit_byte((unsigned char)buf[p])) {
            p++;
        }
    } else {
        while (p < len && !cytadel_is_digit_byte((unsigned char)buf[p]) &&
               !cytadel_is_delim_byte((unsigned char)buf[p])) {
            p++;
        }
    }

    *out_start = start;
    *out_len = p - start;
    *pos = p;
    return numeric ? CYTADEL_TOK_NUM : CYTADEL_TOK_ALPHA;
}

/* --------------------------------------------------------------------- *
 * Component comparators.
 * --------------------------------------------------------------------- */

/* Digit-run comparison with NO integer conversion (header comment: no
 * strtol()-into-overflow UB, arbitrary-length digit runs supported).
 * Strips leading zeros from both runs, then the longer remaining length
 * wins; equal remaining length falls back to a bounded memcmp() (safe
 * because equal-length, all-digit byte strings compare identically
 * lexically and numerically). Never returns UNDECIDABLE -- two digit runs
 * are always comparable. */
static cytadel_vercmp_t cytadel_cmp_digit_runs(const char *a, size_t alen, const char *b,
                                                size_t blen) {
    size_t sa = 0, sb = 0;
    while (sa < alen && a[sa] == '0') {
        sa++;
    }
    while (sb < blen && b[sb] == '0') {
        sb++;
    }
    size_t ea = alen - sa;
    size_t eb = blen - sb;
    if (ea != eb) {
        return (ea < eb) ? CYTADEL_VERCMP_LESS : CYTADEL_VERCMP_GREATER;
    }
    if (ea == 0) {
        /* Both runs are all-zero (or, degenerately, both empty). */
        return CYTADEL_VERCMP_EQUAL;
    }
    int c = memcmp(a + sa, b + sb, ea);
    if (c < 0) {
        return CYTADEL_VERCMP_LESS;
    }
    if (c > 0) {
        return CYTADEL_VERCMP_GREATER;
    }
    return CYTADEL_VERCMP_EQUAL;
}

/* Case-insensitive alpha-run comparison, strncmp()-with-length-tiebreak
 * shape: returns <0, 0, >0 like strcmp(). Used both for "both sides have an
 * alpha component at this shared position" (plain lexical order) and, via
 * exact-match callers, for pre-release-keyword detection. */
static int cytadel_alpha_cmp_ci(const char *a, size_t alen, const char *b, size_t blen) {
    size_t n = (alen < blen) ? alen : blen;
    for (size_t i = 0; i < n; i++) {
        unsigned char ca = cytadel_to_lower_ascii((unsigned char)a[i]);
        unsigned char cb = cytadel_to_lower_ascii((unsigned char)b[i]);
        if (ca != cb) {
            return (ca < cb) ? -1 : 1;
        }
    }
    if (alen == blen) {
        return 0;
    }
    return (alen < blen) ? -1 : 1;
}

/* Header comment refinement 5's fixed pre-release keyword table. Exact
 * (whole-token) case-insensitive match only -- "rc" matches "RC" but not
 * "recover" or "rcx". Deliberately small and named in the header comment;
 * extend only with a matching header-comment update. */
static const struct {
    const char *word;
    size_t len;
} CYTADEL_PRERELEASE_KEYWORDS[] = {
    {"alpha", 5},  {"beta", 4},     {"rc", 2},      {"pre", 3},    {"preview", 7},
    {"dev", 3},    {"devel", 5},    {"snapshot", 8}, {"nightly", 7}, {"test", 4},
    {"unstable", 8}, {"alfa", 4},   {"milestone", 9},
};

static bool cytadel_is_prerelease_keyword(const char *s, size_t len) {
    size_t n = sizeof(CYTADEL_PRERELEASE_KEYWORDS) / sizeof(CYTADEL_PRERELEASE_KEYWORDS[0]);
    for (size_t i = 0; i < n; i++) {
        if (len == CYTADEL_PRERELEASE_KEYWORDS[i].len &&
            cytadel_alpha_cmp_ci(s, len, CYTADEL_PRERELEASE_KEYWORDS[i].word,
                                  CYTADEL_PRERELEASE_KEYWORDS[i].len) == 0) {
            return true;
        }
    }
    return false;
}

/* Round-2 addition (coordinator-reviewed): a small, fixed table of
 * "release-equivalent" detached-alpha markers -- tags that name the
 * release itself rather than a pre-release of it. "ga" (General
 * Availability), "final", "release", and "stable" are all conventional
 * ways of spelling "this build IS the real release", so a detached residual
 * matching one of these contributes NO ordering information beyond that --
 * it is treated exactly like an all-zero numeric residual (skipped, walk
 * continues), which makes a bare "-ga"/"-final"/"-release"/"-stable" with
 * nothing else following resolve to EQUAL against the bare release (see
 * cytadel_residual_verdict()'s header comment for why EQUAL, not LESS or
 * GREATER, is the chosen answer here). Same exact-match, case-insensitive
 * matching discipline as CYTADEL_PRERELEASE_KEYWORDS above. */
static const struct {
    const char *word;
    size_t len;
} CYTADEL_RELEASE_EQUIVALENT_KEYWORDS[] = {
    {"ga", 2},
    {"final", 5},
    {"release", 7},
    {"stable", 6},
};

static bool cytadel_is_release_equivalent_keyword(const char *s, size_t len) {
    size_t n = sizeof(CYTADEL_RELEASE_EQUIVALENT_KEYWORDS) /
               sizeof(CYTADEL_RELEASE_EQUIVALENT_KEYWORDS[0]);
    for (size_t i = 0; i < n; i++) {
        if (len == CYTADEL_RELEASE_EQUIVALENT_KEYWORDS[i].len &&
            cytadel_alpha_cmp_ci(s, len, CYTADEL_RELEASE_EQUIVALENT_KEYWORDS[i].word,
                                  CYTADEL_RELEASE_EQUIVALENT_KEYWORDS[i].len) == 0) {
            return true;
        }
    }
    return false;
}

/* C-2 fix. Classifies an alpha token's KEYWORD RANK for the "both sides have
 * an alpha component at the exact same shared position" branch of the main
 * loop below -- see that branch's own comment for why a plain lexical
 * compare alone is wrong here (it silently ignores both keyword tables and
 * produces a non-transitive, backwards-ordered result for 21 of the 52
 * release-equivalent x pre-release keyword pairs, e.g. "-ga" < "-rc"
 * lexically even though "ga" NAMES the release and must outrank any
 * pre-release spelling of the same release). Three ranks, worst to best:
 *   0 = CYTADEL_PRERELEASE_KEYWORDS match (a pre-release marker)
 *   1 = CYTADEL_RELEASE_EQUIVALENT_KEYWORDS match (names the release itself)
 *   2 = neither table recognizes it (unrecognized alpha text)
 * Deliberately NOT an ordered numeric scale beyond "compare directly" --
 * see the call site for why a same-rank-2 (both unrecognized) pair still
 * falls through to plain lexical (SS3's literal rule), while a rank
 * mismatch that includes an UNRECOGNIZED side is UNDECIDABLE rather than a
 * lexical guess. */
static int cytadel_alpha_keyword_rank(const char *s, size_t len) {
    if (cytadel_is_prerelease_keyword(s, len)) {
        return 0;
    }
    if (cytadel_is_release_equivalent_keyword(s, len)) {
        return 1;
    }
    return 2;
}

static bool cytadel_is_all_zero_digits(const char *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (p[i] != '0') {
            return false;
        }
    }
    return true;
}

/* C-1 fix's residual ambiguity guard. `s`/`l` is an ATTACHED alpha token
 * that neither keyword table recognizes; `buf`/`len`/`pos_after` is the
 * residual stream with `pos_after` positioned immediately past that token
 * (i.e. where cytadel_next_token() left it). Returns true iff this token is
 * a single letter 'a'/'b'/'c' (case-insensitive) immediately followed by a
 * digit with NO delimiter in between (e.g. the "a" in "a1", as in
 * "3.9.0a1") -- the exact CPython/PEP-440-style collision this project
 * cannot resolve: "a" is simultaneously a plausible abbreviation for an
 * "alpha" pre-release AND a legitimate attached OpenSSL-style letter release
 * (vs. "1.0.2a", where nothing follows the letter and there is no
 * ambiguity at all -- see the false branch below). Guessing either
 * direction here is a guess, not a derivation, so the caller returns
 * UNDECIDABLE instead. Pinned by tests/unit/test_version_compare.c's "C-1
 * ambiguity" rows. */
static bool cytadel_is_ambiguous_attached_letter(const char *s, size_t l, const char *buf,
                                                  size_t len, size_t pos_after) {
    if (l != 1) {
        return false;
    }
    unsigned char c = cytadel_to_lower_ascii((unsigned char)s[0]);
    if (c != (unsigned char)'a' && c != (unsigned char)'b' && c != (unsigned char)'c') {
        return false;
    }
    return pos_after < len && cytadel_is_digit_byte((unsigned char)buf[pos_after]);
}

/* Header comment refinement 5's residual walk (REVISED by the C-1 fix --
 * see version_compare.h's own comment for the full before/after story).
 * `buf`/`len` is the SIDE that has extra content beyond the other side's
 * exhausted stream; `pos` is the position at which that residual content
 * starts (i.e. where the shared prefix stopped matching -- ALWAYS strictly
 * past the start of `buf`, since this is only ever invoked after at least
 * one earlier component matched; see this file's only two call sites).
 * Returns, from the point of view of "this side's residual vs. nothing":
 *
 *   For each ALPHA component encountered (checked in THIS order, REGARDLESS
 *   of attached/detached -- this is the C-1 fix; the old code checked
 *   attachment FIRST, so an ATTACHED spelling of a real keyword, e.g. the
 *   "rc" in "3.11.0rc1" with no delimiter before it, never even reached the
 *   keyword tables and was misread as a vendor letter suffix):
 *     1. CYTADEL_PRERELEASE_KEYWORDS exact match -> CYTADEL_VERCMP_LESS,
 *        regardless of attachment.
 *     2. CYTADEL_RELEASE_EQUIVALENT_KEYWORDS exact match -> contributes
 *        nothing, walk continues exactly like a zero-numeric residual,
 *        regardless of attachment.
 *     3. Neither table recognizes it:
 *          - ATTACHED (no delimiter immediately before this alpha run --
 *            the vendor letter/patch-suffix structural signal, e.g. the
 *            "k" in "2k", the "p" in "2p2", the "ubuntu" in "2ubuntu2"):
 *            normally CYTADEL_VERCMP_GREATER, UNLESS
 *            cytadel_is_ambiguous_attached_letter() flags it as the
 *            genuinely irresolvable single-letter-immediately-followed-by-
 *            digit collision (e.g. "3.9.0a1"'s "a1" -- "a" reads equally
 *            plausibly as an abbreviated "alpha" pre-release or an attached
 *            OpenSSL-style letter release), in which case
 *            CYTADEL_VERCMP_UNDECIDABLE, not a guess.
 *          - DETACHED (its own '.'/'-'/'_' -delimited segment, a pre-release
 *            POSITION) -> CYTADEL_VERCMP_UNDECIDABLE: a closed keyword table
 *            can never enumerate every vendor's spelling ("a1", "b2", "M1"
 *            [Maven milestone], "cr1" [JBoss candidate release], ...), so
 *            guessing a direction for "unrecognized" here would repeat the
 *            exact false-negative failure mode (a genuinely vulnerable
 *            host's version compares outside an NVD versionEndExcluding
 *            bound and the finding is silently dropped) this comparator
 *            exists to prevent.
 *   A NUMERIC residual component equal to zero is skipped (zero-pad
 *   semantics, refinement 6); non-zero settles CYTADEL_VERCMP_GREATER.
 *   Running out of residual components (all skipped/all zero) settles
 *   CYTADEL_VERCMP_EQUAL.
 * The caller is responsible for translating this verdict back into a
 * LESS/EQUAL/GREATER/UNDECIDABLE result for the original (a, b) pair
 * depending on which side `buf` actually was -- UNDECIDABLE passes straight
 * through unchanged regardless of which side it came from. */
static cytadel_vercmp_t cytadel_residual_verdict(const char *buf, size_t len, size_t pos) {
    for (;;) {
        size_t s, l;
        bool delim_skipped;
        cytadel_tok_type_t t = cytadel_next_token(buf, len, &pos, &s, &l, &delim_skipped);
        if (t == CYTADEL_TOK_NONE) {
            return CYTADEL_VERCMP_EQUAL;
        }
        if (t == CYTADEL_TOK_NUM) {
            if (!cytadel_is_all_zero_digits(buf + s, l)) {
                return CYTADEL_VERCMP_GREATER;
            }
            /* All-zero: keep walking into the next residual component. */
            continue;
        }
        /* CYTADEL_TOK_ALPHA -- C-1 fix: keyword tables checked FIRST,
         * before attached/detached is even consulted. */
        if (cytadel_is_prerelease_keyword(buf + s, l)) {
            return CYTADEL_VERCMP_LESS;
        }
        if (cytadel_is_release_equivalent_keyword(buf + s, l)) {
            /* Contributes nothing beyond "this is the real release" --
             * treat like a zero-numeric residual and keep walking. */
            continue;
        }
        /* Unrecognized by either table. */
        if (!delim_skipped) {
            /* Attached: vendor letter/patch suffix signal -- UNLESS this is
             * the genuinely ambiguous single-letter-then-digit collision
             * (C-1's documented residual ambiguity), which is UNDECIDABLE
             * rather than guessed. */
            if (cytadel_is_ambiguous_attached_letter(buf + s, l, buf, len, pos)) {
                return CYTADEL_VERCMP_UNDECIDABLE;
            }
            return CYTADEL_VERCMP_GREATER;
        }
        /* Detached and unrecognized: a pre-release position with no known
         * spelling -- UNDECIDABLE, not a guess. */
        return CYTADEL_VERCMP_UNDECIDABLE;
    }
}

/* --------------------------------------------------------------------- *
 * Debian epoch (refinement 3): an optional `^[0-9]+:` prefix. Absent ==
 * epoch "0". A ':' not preceded by at least one leading digit at offset 0
 * is NOT an epoch delimiter -- see header comment for why that is a
 * deliberate non-case, not an omission.
 * --------------------------------------------------------------------- */

static void cytadel_split_epoch(const char *s, size_t len, const char **epoch_ptr,
                                 size_t *epoch_len, const char **rest_ptr, size_t *rest_len) {
    size_t p = 0;
    while (p < len && cytadel_is_digit_byte((unsigned char)s[p])) {
        p++;
    }
    if (p > 0 && p < len && s[p] == ':') {
        *epoch_ptr = s;
        *epoch_len = p;
        *rest_ptr = s + p + 1;
        *rest_len = len - p - 1;
    } else {
        static const char zero_epoch[] = "0";
        *epoch_ptr = zero_epoch;
        *epoch_len = 1;
        *rest_ptr = s;
        *rest_len = len;
    }
}

/* --------------------------------------------------------------------- *
 * Public entry point.
 * --------------------------------------------------------------------- */

cytadel_vercmp_t cytadel_version_compare(const char *a, size_t a_len, const char *b,
                                          size_t b_len) {
    /* NULL is only tolerated paired with length 0 (an empty string); NULL
     * with a non-zero length is a caller bug, handled defensively instead
     * of dereferencing. */
    if ((a == NULL && a_len > 0) || (b == NULL && b_len > 0)) {
        return CYTADEL_VERCMP_UNDECIDABLE;
    }

    if (cytadel_has_disallowed_byte(a, a_len) || cytadel_has_disallowed_byte(b, b_len)) {
        return CYTADEL_VERCMP_UNDECIDABLE;
    }

    /* W-3 fix: strip a single leading "v"/"V" glued directly to a digit
     * (e.g. "v2.1.0") on each side independently, before anything else is
     * inspected -- including epoch splitting, since a "v" prefix is never
     * itself part of a Debian epoch. See cytadel_strip_v_prefix()'s own
     * comment. */
    cytadel_strip_v_prefix(&a, &a_len);
    cytadel_strip_v_prefix(&b, &b_len);

    const char *epoch_a, *rest_a;
    const char *epoch_b, *rest_b;
    size_t epoch_a_len, rest_a_len;
    size_t epoch_b_len, rest_b_len;
    cytadel_split_epoch(a, a_len, &epoch_a, &epoch_a_len, &rest_a, &rest_a_len);
    cytadel_split_epoch(b, b_len, &epoch_b, &epoch_b_len, &rest_b, &rest_b_len);

    /* W-2 fix: SemVer build metadata (an optional "+..." suffix, SemVer
     * §10) carries NO precedence information at all -- not even as a
     * tiebreaker -- so it is truncated off `rest_a`/`rest_b` before any
     * tokenizing happens, independently on each side. Only the FIRST '+'
     * matters (build metadata runs to the end of the string by
     * definition); anything at or after it is simply dropped from
     * comparison. Bounded by memchr()'s own explicit length argument --
     * never strlen()'d. */
    {
        /* rest_a/rest_b may be NULL when their paired length is 0 (an
         * empty input) -- memchr() on a NULL pointer is only reliably safe
         * with `n == 0`, but guard explicitly rather than lean on that. */
        if (rest_a_len > 0) {
            const char *plus_a = memchr(rest_a, '+', rest_a_len);
            if (plus_a != NULL) {
                rest_a_len = (size_t)(plus_a - rest_a);
            }
        }
        if (rest_b_len > 0) {
            const char *plus_b = memchr(rest_b, '+', rest_b_len);
            if (plus_b != NULL) {
                rest_b_len = (size_t)(plus_b - rest_b);
            }
        }
    }

    /* Header comment's second UNDECIDABLE bullet: either side has NO real
     * component at all after epoch-stripping and build-metadata-truncation
     * (empty, or pure delimiters). Checked once, up front, on the very
     * first token only -- this must NOT be confused with one side simply
     * running out AFTER matching a shared prefix (that is refinement 6's
     * legitimate zero-pad residual case, handled later in the main loop
     * below).
     *
     * C-3 fix: this check now runs BEFORE the epoch comparison is ever
     * trusted (it used to run after, so a differing-epoch bare epoch like
     * "1:" with nothing following it short-circuited straight to a
     * definite GREATER/LESS without this guard ever running -- see
     * version_compare.h's own comment on this fix). A version that is
     * nothing but an epoch has no comparable content and must be
     * UNDECIDABLE regardless of what the epoch digits themselves say. */
    {
        size_t probe_a = 0, sa, la;
        size_t probe_b = 0, sb, lb;
        bool discard_a, discard_b;
        cytadel_tok_type_t first_a =
            cytadel_next_token(rest_a, rest_a_len, &probe_a, &sa, &la, &discard_a);
        cytadel_tok_type_t first_b =
            cytadel_next_token(rest_b, rest_b_len, &probe_b, &sb, &lb, &discard_b);
        if (first_a == CYTADEL_TOK_NONE || first_b == CYTADEL_TOK_NONE) {
            return CYTADEL_VERCMP_UNDECIDABLE;
        }
    }

    cytadel_vercmp_t epoch_cmp = cytadel_cmp_digit_runs(epoch_a, epoch_a_len, epoch_b, epoch_b_len);
    if (epoch_cmp != CYTADEL_VERCMP_EQUAL) {
        return epoch_cmp;
    }

    size_t pos_a = 0, pos_b = 0;
    for (;;) {
        size_t pos_a_before = pos_a, pos_b_before = pos_b;
        size_t sa, la, sb, lb;
        bool discard_a, discard_b;
        cytadel_tok_type_t ta =
            cytadel_next_token(rest_a, rest_a_len, &pos_a, &sa, &la, &discard_a);
        cytadel_tok_type_t tb =
            cytadel_next_token(rest_b, rest_b_len, &pos_b, &sb, &lb, &discard_b);

        if (ta == CYTADEL_TOK_NONE && tb == CYTADEL_TOK_NONE) {
            return CYTADEL_VERCMP_EQUAL;
        }
        if (ta == CYTADEL_TOK_NONE) {
            /* b has residual content starting at pos_b_before. */
            cytadel_vercmp_t v = cytadel_residual_verdict(rest_b, rest_b_len, pos_b_before);
            if (v == CYTADEL_VERCMP_UNDECIDABLE) {
                return CYTADEL_VERCMP_UNDECIDABLE;
            }
            if (v == CYTADEL_VERCMP_GREATER) {
                return CYTADEL_VERCMP_LESS; /* b > nothing => b > a => a < b */
            }
            if (v == CYTADEL_VERCMP_LESS) {
                return CYTADEL_VERCMP_GREATER; /* b < nothing => b < a => a > b */
            }
            return CYTADEL_VERCMP_EQUAL;
        }
        if (tb == CYTADEL_TOK_NONE) {
            cytadel_vercmp_t v = cytadel_residual_verdict(rest_a, rest_a_len, pos_a_before);
            if (v == CYTADEL_VERCMP_UNDECIDABLE) {
                return CYTADEL_VERCMP_UNDECIDABLE;
            }
            if (v == CYTADEL_VERCMP_GREATER) {
                return CYTADEL_VERCMP_GREATER;
            }
            if (v == CYTADEL_VERCMP_LESS) {
                return CYTADEL_VERCMP_LESS;
            }
            return CYTADEL_VERCMP_EQUAL;
        }

        if (ta != tb) {
            /* Header comment's third UNDECIDABLE bullet: numeric component
             * vs. alpha component at the same shared position. */
            return CYTADEL_VERCMP_UNDECIDABLE;
        }

        if (ta == CYTADEL_TOK_NUM) {
            cytadel_vercmp_t r = cytadel_cmp_digit_runs(rest_a + sa, la, rest_b + sb, lb);
            if (r != CYTADEL_VERCMP_EQUAL) {
                return r;
            }
        } else {
            /* C-2 fix: both sides have an ALPHA component at this exact
             * shared position (NOT a residual -- both are present). Rank
             * each side via the keyword tables BEFORE falling back to
             * plain lexical order -- see cytadel_alpha_keyword_rank()'s own
             * comment for why the old "always lexical" rule silently
             * inverted 21 of 52 release-equivalent-vs-pre-release keyword
             * pairs and broke transitivity/EQUAL-as-congruence project-
             * wide. */
            int rank_a = cytadel_alpha_keyword_rank(rest_a + sa, la);
            int rank_b = cytadel_alpha_keyword_rank(rest_b + sb, lb);
            if (rank_a != rank_b) {
                if (rank_a == 2 || rank_b == 2) {
                    /* One side is a recognized keyword (either table), the
                     * other is unrecognized -- no rule relates a known
                     * marker to an arbitrary unknown spelling; guessing a
                     * lexical order here is exactly the kind of guess
                     * refinement 7 forbids. */
                    return CYTADEL_VERCMP_UNDECIDABLE;
                }
                /* Both recognized, different tables: release-equivalent
                 * (rank 1) outranks pre-release (rank 0) -- this is the
                 * one directly decidable cross-table case. */
                return (rank_a > rank_b) ? CYTADEL_VERCMP_GREATER : CYTADEL_VERCMP_LESS;
            }
            if (rank_a == 1) {
                /* Both sides are release-equivalent keywords (e.g. "ga" vs
                 * "final"): these are different SPELLINGS of the exact
                 * same fact ("this IS the release"), not different
                 * releases -- treating them as lexically ordered would
                 * make "-ga" < "-final" < "-release" an arbitrary,
                 * meaningless total order between synonyms and reintroduce
                 * the same EQUAL-is-not-a-congruence transitivity breakage
                 * this fix exists to close (see version_compare.h). No
                 * ordering information here -- equal at this position,
                 * walk continues into the next component exactly like an
                 * identical-text alpha match would. */
            } else {
                /* Same rank 0 (both pre-release) or rank 2 (both
                 * unrecognized) -- SS3's literal "alpha components
                 * lexically" rule applies cleanly within a single
                 * table/category: rank 0 gives the real, intentional
                 * "alpha" < "beta" < "rc" pre-release ordering; rank 2 is
                 * two genuinely unrecognized alpha strings with no
                 * keyword-table information either way. */
                int c = cytadel_alpha_cmp_ci(rest_a + sa, la, rest_b + sb, lb);
                if (c < 0) {
                    return CYTADEL_VERCMP_LESS;
                }
                if (c > 0) {
                    return CYTADEL_VERCMP_GREATER;
                }
            }
        }
        /* Equal at this position -- continue to the next component. */
    }
}
