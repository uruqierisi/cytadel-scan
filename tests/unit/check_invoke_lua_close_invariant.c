#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Security-review round-6 item 3 (closing the W-A residual structurally).
 *
 * invoke.c's own comments assert "every lua_close(L) call in this file
 * MUST go through cytadel_plugin_close_state(), never call lua_close(L)
 * directly" (see that function's top-of-file comment) -- but until this
 * tool existed that was enforced by nothing but the comment itself, i.e. a
 * documented CONVENTION. Round 6's own reviewer demonstrated a 2-line
 * "hollow" mutation that defeats it while every runtime test stays green:
 * replace the `lua_close(L);` statement INSIDE cytadel_plugin_close_state()
 * with `(void)L;`, and add a free-standing `lua_close(L);` call directly in
 * cytadel_plugin_invoke_one() right after its final
 * cytadel_plugin_invoke_cleanup() call. That reinstates the exact
 * round-2 FIX 1 double-close ordering bug (the force-close sweep now runs
 * BEFORE the real lua_close(L)), because
 * tests/unit/test_plugin_r4w2_order_invariant.c's
 * CYTADEL_PLUGIN_INVOKE_ORDER_HOOK()-based instrumentation only observes
 * that cytadel_plugin_close_state() itself finished running -- it has no
 * way to observe whether lua_close(L) was the call that actually happened
 * inside it.
 *
 * This program closes that gap the only way that is actually robust
 * against that exact mutation: by reading invoke.c's own SOURCE TEXT
 * (never running it, and independent of any test instrumentation compiled
 * into it) and mechanically proving the invariant:
 *
 *   the identifier `lua_close`, as a WHOLE TOKEN (not merely a
 *   `lua_close(` call), appears EXACTLY ONCE in invoke.c, and that one
 *   occurrence lies textually INSIDE cytadel_plugin_close_state()'s own
 *   function body -- nowhere else.
 *
 * Round-7 item W-1: an earlier version of this tool required the
 * occurrence to be immediately followed by '(' (i.e. it only looked for
 * `lua_close(`, not any reference to `lua_close`). That is defeated by
 * any real reference to lua_close that is not textually adjacent to its
 * own call parenthesis -- `lua_close (L);` (a space before the paren),
 * `#define ALIAS lua_close` plus `ALIAS(L);` (an object-like macro
 * alias), `void (*p)(lua_State *) = lua_close; p(L);` (a function-pointer
 * indirection), and `lua_close\n(L);` (split across lines) all name
 * lua_close without the name being immediately followed by '(' anywhere
 * in the text. Matching on the whole token instead, regardless of what
 * (if anything) follows it, closes all four at once -- see
 * cytadel_find_token_occurrences()'s own comment below for the exact
 * matching rule and for the residual holes even this broader match
 * cannot see.
 *
 * Comments and string/char literals are stripped (blanked to spaces, same
 * length as the original so byte offsets and line numbers stay aligned)
 * before searching, so a `lua_close` appearing only inside a comment or a
 * string literal (e.g. this file's own doc comments, if it ever needed to
 * quote invoke.c) is correctly ignored rather than miscounted -- see
 * cytadel_strip_comments_and_strings() below. Round-7 item W-3: a
 * backslash-continued `//` line comment (the comment text ends with `\`
 * immediately before the newline, so the comment continues onto the next
 * physical line exactly as it does for the compiler) is now handled
 * correctly too -- see that function's LINE_COMMENT case.
 *
 * Registered as its own CTest entry (tests/unit/CMakeLists.txt) so it runs
 * as part of the normal `ctest` invocation alongside every other regression
 * test, not as a separate manual step -- and specifically NOT gated behind
 * the "plugin" or "security" CTest labels alone, so a plain `ctest` run
 * (with no -L filter) always exercises it.
 *
 * This tool was verified, on a throwaway copy of the tree, to FAIL under
 * the original "hollow" mutation described above, under all four of the
 * round-7 W-1 bypass spellings layered on top of it (each keeping a dead,
 * never-executed `if (0) { lua_close(L); }` inside
 * cytadel_plugin_close_state()'s own body so the naive "still exactly one
 * occurrence" count alone would not have caught it), and to PASS again
 * once every mutation is reverted -- see the round-6 and round-7 reports
 * for the transcripts.
 *
 * Usage: check_invoke_lua_close_invariant <path-to-invoke.c>
 * Exit 0 (prints "PASS: ...") if the invariant holds. Exit 1 (prints a
 * message naming the invariant, plus file:line for every violation found)
 * if it does not, or if this tool cannot confirm the invariant at all
 * (e.g. cytadel_plugin_close_state() was renamed or duplicated, which this
 * tool treats as "unverifiable", not as a silent pass).
 *
 * What this tool deliberately does NOT do, even after the round-7
 * broadening (see cytadel_find_token_occurrences()'s comment for the full
 * reasoning): it does not evaluate C control flow, so a `lua_close`
 * reference that is dead/unreachable code but textually sits inside
 * cytadel_plugin_close_state()'s body is still counted as "inside" (a
 * pure text-position check, not a reachability proof); it does not look
 * across translation units, so a wrapper defined in a different .c file
 * that itself calls lua_close(L) is invisible to it; and it does not
 * evaluate preprocessor conditionals, so a `lua_close` sitting inside a
 * `#if 0` ... `#endif` block (never compiled) is still reported as a
 * violation rather than silently ignored -- see
 * cytadel_find_if0_blocks()'s comment for why that last one is a
 * deliberate, documented choice rather than an oversight. */

typedef struct {
    char *text; /* original file contents, NUL-terminated */
    char *code; /* same length; comments/string-and-char literals blanked to spaces */
    size_t len;
} cytadel_source_t;

static int cytadel_read_file(const char *path, cytadel_source_t *out) {
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "check_invoke_lua_close_invariant: cannot open %s\n", path);
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "check_invoke_lua_close_invariant: fseek(SEEK_END) failed on %s\n", path);
        fclose(f);
        return -1;
    }
    long size = ftell(f);
    if (size < 0) {
        fprintf(stderr, "check_invoke_lua_close_invariant: ftell() failed on %s\n", path);
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "check_invoke_lua_close_invariant: fseek(SEEK_SET) failed on %s\n", path);
        fclose(f);
        return -1;
    }

    char *buf = malloc((size_t)size + 1);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    size_t n = fread(buf, 1, (size_t)size, f);
    fclose(f);
    buf[n] = '\0';

    char *code = malloc(n + 1);
    if (code == NULL) {
        free(buf);
        return -1;
    }
    memcpy(code, buf, n + 1);

    out->text = buf;
    out->code = code;
    out->len = n;
    return 0;
}

static void cytadel_source_free(cytadel_source_t *src) {
    free(src->text);
    free(src->code);
}

/* Blanks (replaces with ' ') every character in src->code that is part of
 * a line comment (two slashes to end of line), a block comment (slash-star
 * to star-slash), or a "string"/'char' literal -- leaving every other byte,
 * including
 * newlines, untouched, so line numbers computed from either buffer still
 * agree and later brace/paren matching on src->code cannot be thrown off
 * by a stray delimiter inside a comment or literal. Escape sequences
 * inside string/char literals are skipped over correctly (an escaped quote
 * does not end the literal). */
static void cytadel_strip_comments_and_strings(cytadel_source_t *src) {
    enum { NORMAL, LINE_COMMENT, BLOCK_COMMENT, IN_STRING, IN_CHAR } state = NORMAL;
    char *c = src->code;
    size_t i = 0;

    while (i < src->len) {
        char ch = c[i];
        switch (state) {
        case NORMAL:
            if (ch == '/' && i + 1 < src->len && c[i + 1] == '/') {
                c[i] = ' ';
                c[i + 1] = ' ';
                i += 2;
                state = LINE_COMMENT;
                continue;
            }
            if (ch == '/' && i + 1 < src->len && c[i + 1] == '*') {
                c[i] = ' ';
                c[i + 1] = ' ';
                i += 2;
                state = BLOCK_COMMENT;
                continue;
            }
            if (ch == '"') {
                c[i] = ' ';
                i += 1;
                state = IN_STRING;
                continue;
            }
            if (ch == '\'') {
                c[i] = ' ';
                i += 1;
                state = IN_CHAR;
                continue;
            }
            i += 1;
            continue;

        case LINE_COMMENT:
            /* Round-7 item W-3: a backslash immediately before the newline
             * splices the next physical line onto this one (C11 5.1.1.2
             * phase 2, which runs BEFORE phase 3 comment stripping), so the
             * `//` comment continues onto that next line too, exactly as
             * it does for the compiler. Without this, a `lua_close(L)`
             * hidden behind such a continuation is invisible to the
             * compiler but NOT to this tool's own (until now, naive)
             * line-comment handling -- a false positive: real, dead
             * comment text incorrectly treated as live code. Blank the
             * backslash but leave the newline byte itself untouched (byte
             * offsets/line numbers must stay aligned with src->text) and
             * stay in LINE_COMMENT instead of returning to NORMAL. */
            if (ch == '\\' && i + 1 < src->len && c[i + 1] == '\n') {
                c[i] = ' ';
                i += 2;
                continue;
            }
            if (ch == '\n') {
                state = NORMAL;
                i += 1;
                continue;
            }
            c[i] = ' ';
            i += 1;
            continue;

        case BLOCK_COMMENT:
            if (ch == '*' && i + 1 < src->len && c[i + 1] == '/') {
                c[i] = ' ';
                c[i + 1] = ' ';
                i += 2;
                state = NORMAL;
                continue;
            }
            if (ch != '\n') {
                c[i] = ' ';
            }
            i += 1;
            continue;

        case IN_STRING:
            if (ch == '\\' && i + 1 < src->len) {
                c[i] = ' ';
                c[i + 1] = ' ';
                i += 2;
                continue;
            }
            if (ch == '"') {
                c[i] = ' ';
                i += 1;
                state = NORMAL;
                continue;
            }
            c[i] = ' ';
            i += 1;
            continue;

        case IN_CHAR:
            if (ch == '\\' && i + 1 < src->len) {
                c[i] = ' ';
                c[i + 1] = ' ';
                i += 2;
                continue;
            }
            if (ch == '\'') {
                c[i] = ' ';
                i += 1;
                state = NORMAL;
                continue;
            }
            c[i] = ' ';
            i += 1;
            continue;
        }
    }
}

static int cytadel_is_ident_char(char ch) {
    return isalnum((unsigned char)ch) || ch == '_';
}

static size_t cytadel_line_of(const cytadel_source_t *src, size_t offset) {
    size_t line = 1;
    for (size_t i = 0; i < offset && i < src->len; i++) {
        if (src->text[i] == '\n') {
            line++;
        }
    }
    return line;
}

/* Appends the offset of every whole-token occurrence of `needle` in
 * src->code to out_offsets[], and returns how many were found. A "whole
 * token" occurrence is bounded on both sides by a non-identifier
 * character (or start/end of file) -- so `lua_close` does NOT match
 * inside `lua_close_all` or `cytadel_plugin_close_state`, on either side,
 * regardless of what character (if any) immediately follows it.
 *
 * When `require_call_paren` is nonzero, an occurrence is additionally
 * required to be immediately followed by '(' -- i.e. it must be a call
 * to, or definition of, something named exactly `needle`, with no
 * whitespace, macro, or pointer indirection between the name and the
 * parenthesis. This mode is used ONLY for locating
 * cytadel_plugin_close_state()'s own definition (step 1 in main() below),
 * where the immediate '(' is exactly what lets a definition/call be told
 * apart from the function's name appearing elsewhere (e.g. in a comment,
 * already stripped, or -- not applicable to this identifier today, but in
 * principle -- as a bare reference with no call).
 *
 * When `require_call_paren` is zero, ANY whole-token occurrence counts,
 * whether or not '(' follows -- this is deliberately broader than "is a
 * call", and is what this tool uses to search for `lua_close` (round-7
 * item W-1). The previous version of this function always required an
 * immediate '(', which a `lua_close (L);` (space before the paren), a
 * `#define ALIAS lua_close` object-like macro, a
 * `void (*p)(lua_State *) = lua_close;` function-pointer assignment, or a
 * `lua_close\n(L);` split across lines could each defeat -- every one of
 * those is a real reference to `lua_close` that is not textually followed
 * by '(', so the old, narrower search silently missed all four. Matching
 * on the whole token regardless of what follows closes that hole -- at
 * the cost of also (correctly, by this invariant's own wording: "every
 * lua_close(L) call in this file MUST go through
 * cytadel_plugin_close_state(), never call lua_close(L) directly")
 * flagging non-call references such as the `#define` and function-pointer
 * forms above as themselves being "a `lua_close` outside
 * cytadel_plugin_close_state()'s body": nothing outside that one helper
 * should even NAME lua_close, whether or not it goes on to call it.
 *
 * Returns -1 if more than max_offsets were found (a hard error, not
 * silent truncation -- this tool's counts are always small and known in
 * advance).
 *
 * Residual holes this text-based, single-file parser cannot see even
 * after this broadening (round-7 item W-2, restating what round-6's
 * comment here overclaimed): (1) a `lua_close` reference that is
 * genuine, compiled C code but happens to sit inside
 * cytadel_plugin_close_state()'s own body is correctly counted as
 * "inside" even if it is unreachable DEAD code within that body (e.g. an
 * `if (0) { lua_close(L); }` sitting alongside a real, differently
 * spelled close elsewhere in the same body) -- this tool proves textual
 * position, not control-flow reachability, so "inside the body" means
 * "between the body's braces", not "on the path that actually runs"; and
 * (2) a wrapper function DEFINED IN A DIFFERENT TRANSLATION UNIT that
 * itself calls lua_close(L) and is then called from invoke.c is invisible
 * to this tool, because it only ever reads invoke.c's own source text.
 * Neither is an oversight in this broadening -- both are inherent limits
 * of a single-file text parser that this tool does not attempt to work
 * around. */
static int cytadel_find_token_occurrences(const cytadel_source_t *src, const char *needle,
                                           int require_call_paren, size_t *out_offsets,
                                           int max_offsets) {
    size_t needle_len = strlen(needle);
    int count = 0;

    for (size_t i = 0; i + needle_len <= src->len; i++) {
        if (strncmp(src->code + i, needle, needle_len) != 0) {
            continue;
        }
        if (i > 0 && cytadel_is_ident_char(src->code[i - 1])) {
            continue; /* part of a longer identifier, not a whole-token match */
        }
        size_t after = i + needle_len;
        if (after < src->len && cytadel_is_ident_char(src->code[after])) {
            continue; /* part of a longer identifier, not a whole-token match */
        }
        if (require_call_paren && (after >= src->len || src->code[after] != '(')) {
            continue; /* not immediately called/defined */
        }
        if (count >= max_offsets) {
            return -1;
        }
        out_offsets[count++] = i;
    }
    return count;
}

/* `open_paren_offset` must be the offset of a '(' character. Returns the
 * offset of its matching ')' via depth counting over src->code (already
 * comment/string-stripped, so no delimiter inside either can throw this
 * off), or (size_t)-1 if the parens never balance before EOF. */
static size_t cytadel_match_paren(const cytadel_source_t *src, size_t open_paren_offset) {
    int depth = 0;
    for (size_t i = open_paren_offset; i < src->len; i++) {
        if (src->code[i] == '(') {
            depth++;
        } else if (src->code[i] == ')') {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }
    return (size_t)-1;
}

static size_t cytadel_match_brace(const cytadel_source_t *src, size_t open_brace_offset) {
    int depth = 0;
    for (size_t i = open_brace_offset; i < src->len; i++) {
        if (src->code[i] == '{') {
            depth++;
        } else if (src->code[i] == '}') {
            depth--;
            if (depth == 0) {
                return i;
            }
        }
    }
    return (size_t)-1;
}

/* Returns the offset of the next non-whitespace character at or after
 * `from` in src->code (comments were already blanked to spaces above, so
 * this also skips over former comments), or src->len if none remains. */
static size_t cytadel_skip_ws(const cytadel_source_t *src, size_t from) {
    size_t i = from;
    while (i < src->len && isspace((unsigned char)src->code[i])) {
        i++;
    }
    return i;
}

typedef struct {
    size_t start; /* offset of the '#' starting the `#if 0` line itself */
    size_t end;   /* offset of the '#' starting the matching `#endif` line */
} cytadel_range_t;

/* Round-7 item W-3: `lua_close(L);` sitting inside a `#if 0 ... #endif`
 * block never gets compiled and has no runtime effect -- so flagging it
 * as a live invariant violation, with no explanation of why, is a false
 * positive that would make a future "keep the old call around inside
 * #if 0 for reference" edit look like a hard failure of this checker
 * instead of what it is (dead, disabled code).
 *
 * DESIGN DECISION, made explicitly rather than silently: this function
 * does NOT make cytadel_find_if0_blocks()'s callers treat a `lua_close`
 * inside such a block as absent. It still counts as a violation. Only
 * the diagnostic text changes, to name the actual cause. Two reasons,
 * weighed against each other:
 *
 *   1. Correctly SKIPPING disabled code in general requires evaluating
 *      arbitrary preprocessor conditionals -- #ifdef/#ifndef/#elif,
 *      `defined(...)`, macro-expanded conditions, and conditions that
 *      depend on compiler command-line -D flags this tool has no access
 *      to. A text parser that tries to approximate that (as this one
 *      would have to) is exactly the kind of surface that round-7's own
 *      W-1 bypasses exploited: a bypass author could hide a real,
 *      compiled `lua_close(L)` behind `#ifdef CYTADEL_ALWAYS_DEFINED` (a
 *      macro that IS always defined but whose name superficially looks
 *      conditional) or any condition this tool fails to recognize as
 *      "always true", and a parser that skips "probably disabled" code
 *      too eagerly would silently wave it through -- a false NEGATIVE,
 *      which is strictly worse for a security invariant than the false
 *      positive being fixed here.
 *   2. This tool only ever needs to recognize the single, unambiguous,
 *      always-false literal spelling `#if 0` (with optional whitespace)
 *      to give a correct, helpful diagnostic for the one genuinely
 *      common case (dead code kept "for reference"). It does not need to
 *      handle every conditional to do that.
 *
 * So: broadening W-1's match (find every whole-token `lua_close`, not
 * just `lua_close(`) necessarily also broadens what can be found INSIDE
 * a `#if 0` block, and this function's only job is to let the caller
 * explain that occurrence clearly instead of leaving a developer to
 * wonder why disabled code tripped a "structural" checker -- it does not
 * try to shrink the set of what counts as a violation.
 *
 * Recognizes only the literal `#if 0` directive (whitespace tolerated
 * around `#`, `if`, and `0`; nothing else may follow `0` on that line
 * once trailing whitespace/blanked-comment spaces are skipped). Tracks
 * `#if`/`#ifdef`/`#ifndef` vs `#endif` nesting depth so a `#if 0` block
 * that itself contains further (unrelated) conditionals is still bounded
 * at its own matching `#endif`, but does NOT evaluate #ifdef/#ifndef/
 * #elif conditions at all -- by design (see above), a `lua_close`
 * hidden behind any condition other than the literal `#if 0` is NOT
 * recognized as disabled and gets the plain, unqualified diagnostic
 * instead. `#else`/`#elif` branches inside a `#if 0` block are not
 * distinguished from the `#if 0` branch itself -- an acceptable
 * imprecision for a diagnostic-only aid that never changes pass/fail. */
static int cytadel_find_if0_blocks(const cytadel_source_t *src, cytadel_range_t *out,
                                    int max_out) {
    int count = 0;
    int depth = 0;
    int disabled_at_depth = -1;
    size_t region_start = 0;
    size_t i = 0;

    while (i < src->len) {
        size_t line_start = i;
        size_t j = line_start;
        while (j < src->len && src->code[j] != '\n' && isspace((unsigned char)src->code[j])) {
            j++;
        }
        if (j < src->len && src->code[j] == '#') {
            size_t k = j + 1;
            while (k < src->len && src->code[k] != '\n' && isspace((unsigned char)src->code[k])) {
                k++;
            }
            if (strncmp(src->code + k, "if", 2) == 0 && !cytadel_is_ident_char(src->code[k + 2])) {
                depth++;
                if (disabled_at_depth < 0) {
                    size_t cond = k + 2;
                    while (cond < src->len && src->code[cond] != '\n' &&
                           isspace((unsigned char)src->code[cond])) {
                        cond++;
                    }
                    if (cond < src->len && src->code[cond] == '0' &&
                        !cytadel_is_ident_char(src->code[cond + 1])) {
                        size_t rest = cond + 1;
                        while (rest < src->len && src->code[rest] != '\n' &&
                               isspace((unsigned char)src->code[rest])) {
                            rest++;
                        }
                        if (rest >= src->len || src->code[rest] == '\n') {
                            disabled_at_depth = depth;
                            region_start = line_start;
                        }
                    }
                }
            } else if (strncmp(src->code + k, "endif", 5) == 0 &&
                       !cytadel_is_ident_char(src->code[k + 5])) {
                if (disabled_at_depth == depth) {
                    if (count >= max_out) {
                        return -1;
                    }
                    out[count].start = region_start;
                    out[count].end = line_start;
                    count++;
                    disabled_at_depth = -1;
                }
                if (depth > 0) {
                    depth--;
                }
            }
        }
        while (i < src->len && src->code[i] != '\n') {
            i++;
        }
        if (i < src->len) {
            i++;
        }
    }
    return count;
}

static int cytadel_offset_in_ranges(const cytadel_range_t *ranges, int count, size_t offset) {
    for (int i = 0; i < count; i++) {
        if (offset >= ranges[i].start && offset < ranges[i].end) {
            return 1;
        }
    }
    return 0;
}

#define CYTADEL_CLOSE_STATE_FN "cytadel_plugin_close_state"
#define CYTADEL_LUA_CLOSE_FN "lua_close"

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s <path-to-invoke.c>\n", argv[0]);
        return 1;
    }
    const char *path = argv[1];

    cytadel_source_t src;
    if (cytadel_read_file(path, &src) != 0) {
        return 1;
    }
    cytadel_strip_comments_and_strings(&src);

    /* Step 1: locate cytadel_plugin_close_state()'s own DEFINITION (never
     * one of its call sites) and its body's [open_brace, close_brace]
     * span. Every whole-token occurrence of the name immediately followed
     * by '(' is a candidate; it is a definition, not a call, iff the first
     * non-whitespace character after its matching ')' is '{' (a call site
     * is followed by ';' instead, e.g. `cytadel_plugin_close_state(L,
     * "final");`). */
    size_t fn_offsets[16];
    int fn_count = cytadel_find_token_occurrences(&src, CYTADEL_CLOSE_STATE_FN, /*require_call_paren=*/1,
                                                   fn_offsets, 16);
    if (fn_count < 0) {
        fprintf(stderr,
                "check_invoke_lua_close_invariant: more than 16 occurrences of "
                CYTADEL_CLOSE_STATE_FN "( in %s -- update this tool's internal limit\n",
                path);
        cytadel_source_free(&src);
        return 1;
    }

    size_t body_open = (size_t)-1;
    size_t body_close = (size_t)-1;
    int def_count = 0;
    size_t name_len = strlen(CYTADEL_CLOSE_STATE_FN);

    for (int i = 0; i < fn_count; i++) {
        size_t open_paren = fn_offsets[i] + name_len;
        size_t close_paren = cytadel_match_paren(&src, open_paren);
        if (close_paren == (size_t)-1) {
            continue;
        }
        size_t next = cytadel_skip_ws(&src, close_paren + 1);
        if (next < src.len && src.code[next] == '{') {
            size_t close_brace = cytadel_match_brace(&src, next);
            if (close_brace != (size_t)-1) {
                body_open = next;
                body_close = close_brace;
                def_count++;
            }
        }
    }

    if (def_count != 1) {
        fprintf(stderr,
                "check_invoke_lua_close_invariant: INVARIANT UNVERIFIABLE -- expected "
                "exactly one definition of " CYTADEL_CLOSE_STATE_FN "() in %s, found %d. "
                "Cannot confirm the round-5 W-A / round-6 item 3 "
                "\"lua_close(L) only inside " CYTADEL_CLOSE_STATE_FN "()\" invariant "
                "without exactly one definition to check against.\n",
                path, def_count);
        cytadel_source_free(&src);
        return 1;
    }

    /* Step 2 (round-7 item W-1): every whole-token occurrence of
     * `lua_close` anywhere in the whole file -- not just `lua_close(`
     * call sites, see cytadel_find_token_occurrences()'s own comment --
     * must lie strictly inside [body_open, body_close], and there must be
     * exactly one such occurrence in the entire file. */
    size_t close_offsets[16];
    int close_count = cytadel_find_token_occurrences(&src, CYTADEL_LUA_CLOSE_FN,
                                                       /*require_call_paren=*/0, close_offsets, 16);
    if (close_count < 0) {
        fprintf(stderr,
                "check_invoke_lua_close_invariant: more than 16 occurrences of "
                CYTADEL_LUA_CLOSE_FN " in %s -- update this tool's internal limit\n",
                path);
        cytadel_source_free(&src);
        return 1;
    }

    /* Round-7 item W-3: diagnostic-only -- see cytadel_find_if0_blocks()'s
     * own comment for why a `lua_close` found inside one of these ranges
     * still counts as a violation below; this only lets the message name
     * the actual cause instead of leaving dead, disabled code looking
     * like a baffling false positive. */
    cytadel_range_t if0_ranges[16];
    int if0_count = cytadel_find_if0_blocks(&src, if0_ranges, 16);
    if (if0_count < 0) {
        fprintf(stderr,
                "check_invoke_lua_close_invariant: more than 16 `#if 0` blocks in %s -- "
                "update this tool's internal limit\n",
                path);
        cytadel_source_free(&src);
        return 1;
    }

    int violations = 0;
    for (int i = 0; i < close_count; i++) {
        size_t off = close_offsets[i];
        int inside = (off > body_open && off < body_close);
        if (!inside) {
            int in_if0 = cytadel_offset_in_ranges(if0_ranges, if0_count, off);
            fprintf(stderr,
                    "check_invoke_lua_close_invariant: %s:%zu: " CYTADEL_LUA_CLOSE_FN
                    " OUTSIDE " CYTADEL_CLOSE_STATE_FN "()'s body -- this reinstates "
                    "the round-2 FIX 1 double-close ordering bug (see that function's own "
                    "top-of-file comment in invoke.c). Every " CYTADEL_LUA_CLOSE_FN
                    "(L) call in this file MUST go through " CYTADEL_CLOSE_STATE_FN
                    "(), never be named or called directly.%s\n",
                    path, cytadel_line_of(&src, off),
                    in_if0 ? " (found inside a preprocessor-disabled `#if 0` block; this tool "
                             "deliberately still fails on it rather than silently ignoring "
                             "disabled code -- move or delete it, don't just wrap it in `#if 0`.)"
                           : "");
            violations++;
        }
    }

    if (close_count != 1) {
        fprintf(stderr,
                "check_invoke_lua_close_invariant: INVARIANT VIOLATION -- expected exactly "
                "one " CYTADEL_LUA_CLOSE_FN " reference in %s (inside " CYTADEL_CLOSE_STATE_FN
                "()'s body), found %d.\n",
                path, close_count);
        violations++;
    }

    cytadel_source_free(&src);

    if (violations > 0) {
        return 1;
    }

    printf("PASS: %s -- " CYTADEL_LUA_CLOSE_FN " appears exactly once, only inside "
           CYTADEL_CLOSE_STATE_FN "()'s body\n",
           path);
    return 0;
}
