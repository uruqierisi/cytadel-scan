# Cytadel Scan — CPE Version-Range Matching Contract (FROZEN)

**Status:** FROZEN at the M7 CPE-matching slice. This is a design/contract document, not an
implementation. Any change after this point requires an explicit stop-and-ask per the project's engineering policy.

**Relationship to other contracts.** This document extends, and does not replace,
`db-schema.md` §3 ("Version-range matching approach", the frozen matching algorithm) and
`db-schema.md` §10 assumption 3 (one single shared version comparator, engine C now, exposed
to Lua later). §3 defines **how a match verdict is computed**. This document defines **what a
caller must do with that verdict** — the caller-side obligations that keep an UNDECIDABLE or
malformed result from silently becoming a wrong answer in a delivered security report.

The functions this contract governs live in `include/cytadel/match/`:
`cytadel_version_compare()` (the comparator, slice A) and `cytadel_cpe_match_evaluate()` (the
range/bound evaluator, slice B).

---

## 1. The comparator is origin-neutral, and must stay that way

`cytadel_version_compare(a, a_len, b, b_len)` compares two version strings and knows **nothing**
about where either string came from — a scan banner, an NVD row, a test fixture. It returns an
origin-neutral fact:

| result | meaning |
|--------|---------|
| `CYTADEL_VERCMP_LESS` / `EQUAL` / `GREATER` | `a` orders below / equal to / above `b` |
| `CYTADEL_VERCMP_UNDECIDABLE` | the comparator cannot honestly order these two strings |

**Binding rule (do not violate):** the comparator MUST NOT be made origin-aware, and its API
(the `cytadel_version_compare` signature and the `cytadel_vercmp_t` result set) MUST NOT be
changed to carry origin. Its value as a verification target depends on that isolation — the
mutation and out-of-tree probe suites (`tests/probes/`) exercise it as a pure two-argument
oracle. Classification that depends on *where an input came from* is the **caller's** job (§3),
never the comparator's. If a caller lacks the context to classify, the fix is to give the
caller more context at the call site — never to push origin-awareness down into the comparator.

`CYTADEL_VERCMP_UNDECIDABLE` deliberately covers two distinct real-world situations that the
comparator, knowing only the bytes, cannot itself tell apart:

- **Unsupported scheme** — a well-formed version in a scheme the comparator does not rank
  (e.g. Cisco IOS `15.2(4)S5`, a date-based `2023.10.1`, an unrecognized detached pre-release
  spelling such as `-cr1`/`-M1`, or a numeric-vs-alpha type mismatch at a shared position). A
  human *could* extend the comparator to support it.
- **Malformed input** — bytes that are not a version at all (control bytes, embedded NUL, DEL,
  non-ASCII / invalid UTF-8, empty, all-delimiter). No amount of scheme support helps.

Distinguishing these two is a §3 caller obligation, done by inspecting the strings' bytes and
their origin — **not** by extending the comparator's result set.

---

## 2. The evaluator's four outcomes

`cytadel_cpe_match_evaluate(row, detected, detected_len)` returns `cytadel_cpe_match_t`:

| outcome | meaning | axis |
|---------|---------|------|
| `CYTADEL_CPE_MATCH` | the row applies to `detected` | verdict |
| `CYTADEL_CPE_NO_MATCH` | the row definitely does not apply (a decidable bound/exact-compare failed, or `row.vulnerable = 0`) | verdict |
| `CYTADEL_CPE_UNDECIDABLE` | at least one comparison this verdict depends on was `CYTADEL_VERCMP_UNDECIDABLE`, and no other bound already settled the row as a definite `NO_MATCH` | can't-decide |
| `CYTADEL_CPE_MALFORMED_ROW` | the **NVD row** is structurally invalid — all four bounds empty on a range row, or a bound field that is solely CPE sentinel bytes (`*`/`-`) | data-quality |

`MATCH`/`NO_MATCH` answer "is this host affected". `UNDECIDABLE` and `MALFORMED_ROW` are **not**
answers to that question — they are the honest "I could not answer, and here is which kind of
problem stopped me". They live on two different triage axes (see §4) and MUST be surfaced
distinctly (§3).

---

## 3. Caller obligations (the frozen core)

These bind **every** caller of `cytadel_cpe_match_evaluate()` — report generation, CLI output,
exit-code logic, any aggregation layer. There is no production caller today; this section is
written now, before one exists, precisely so the first caller is built against it.

### 3.1 Required disposition of each outcome

| outcome | the caller MUST |
|---------|-----------------|
| `CYTADEL_CPE_MATCH` | report it as an affected finding |
| `CYTADEL_CPE_NO_MATCH` | omit it from findings; no operator notice required |
| `CYTADEL_CPE_UNDECIDABLE` | emit a distinct, operator-visible **unable-to-determine** record carrying the CVE id, the detected version verbatim, and the bound(s) that could not be ordered |
| `CYTADEL_CPE_MALFORMED_ROW` | emit a distinct, operator-visible **data-quality** record carrying the row's CVE id and CPE identity |

### 3.2 Prohibitions

A caller is FORBIDDEN from:

1. Coercing `UNDECIDABLE` or `MALFORMED_ROW` to either affected or not-affected — by any
   mechanism, including a `default:` label, an `else`, a `!= CYTADEL_CPE_MATCH` test, a
   truthiness/boolean cast of the enum, or a comparison against the raw integer values.
2. Consuming the result with anything other than an **exhaustive `switch` over every enumerator
   with no `default:` label**. Under this project's `-Wall -Werror`, a `switch` over an enum
   with no `default:` that omits a value is a `-Wswitch` error — so adding a fifth outcome (§5)
   becomes a compile error at every such call site rather than a silent behavior change. (The
   no-`default:` rule is load-bearing: `-Wswitch` only fires when there is no `default:`.
   Enabling `-Wswitch-enum` project-wide would additionally catch a missing case even with a
   `default:`, but it is not currently in `cmake/CompilerWarnings.cmake`; the guard here relies
   on `-Wswitch` plus the mandated no-`default:` rule, which §7 proves bites.)
3. Aggregating outcomes across the candidate rows for one `(vendor, product)` in a way that lets
   a `NO_MATCH` on one row suppress an `UNDECIDABLE` or `MATCH` on another. Per-CVE aggregation
   is itself three-valued and order-independent: **any** row `MATCH` ⇒ affected; else **any**
   row `UNDECIDABLE` ⇒ unable-to-determine; else not-affected. A fold in which `NO_MATCH` can
   overwrite a previously-seen `UNDECIDABLE` is a defect.
4. Suppressing an `UNDECIDABLE`/`MALFORMED_ROW` record on the grounds that another CVE for the
   same host already produced a `MATCH`. They are independent findings.
5. Rendering `UNDECIDABLE` or `MALFORMED_ROW` only in a verbose/debug mode, or as a log line
   only. They MUST appear in the default report output.

### 3.3 Report obligation

A report containing at least one `UNDECIDABLE` result MUST NOT describe the host as "no
vulnerabilities found" (or equivalent), and MUST state the count of undetermined checks in its
summary. **A clean report is clean only if the undecidable set is empty.**

### 3.4 Classifying malformed input by origin (Ruling 1)

The comparator surfaces malformed input as `CYTADEL_VERCMP_UNDECIDABLE` (§1) — origin-neutral,
because it does not know the origin. When a caller needs to separate "unsupported scheme"
(operator action: *ask an engineer to add scheme support*) from "malformed input" (operator
action: *fix the bad data*), it does so **at the call site, by origin**, because only the caller
knows which string came from where:

- Malformed bytes originating in a `row->*` bound field ⇒ classify as **data-quality**
  (`CYTADEL_CPE_MALFORMED_ROW`). The evaluator already does this for the structural cases it can
  see (all-bounds-empty, sentinel-only bound).
- Malformed bytes originating in `detected` (the scan banner / CPE input) ⇒ classify as a
  **scan-input data-quality** problem, distinct from an unsupported scheme.
- Well-formed-but-unrankable input (no malformed bytes; the comparator simply does not support
  the scheme) ⇒ remains `CYTADEL_CPE_UNDECIDABLE` (unable-to-determine).

The test that decides the bucket: **if a human could add support for this version scheme, it is
UNDECIDABLE; if no scheme support would help because the input itself is garbage, it is
malformed.** Realizing a distinct scan-input-malformed outcome MAY require adding a new value to
the **`cytadel_cpe_match_t`** enum (§5) when the caller is built — that is permitted; it is the
evaluator's API, not the comparator's. Achieving the same split by making
`cytadel_version_compare()` origin-aware, or by widening its result set to carry origin, is
**forbidden** (§1).

---

## 4. Two triage axes, kept separate

`UNDECIDABLE` and `MALFORMED_ROW` are not two grades of the same thing:

- **can't-decide (UNDECIDABLE)** → routes to *engineering*: extend the comparator to support a
  scheme. Volume here should be tracked per **distinct version string**, not per row — one
  unparseable banner fans out across every candidate row for a `(vendor, product)` and would
  otherwise look like dozens of problems when it is one input needing one fix.
- **data-quality (MALFORMED_ROW)** → routes to *ingest / data owners*: an NVD row that should
  never have been stored in that shape.

A caller MUST NOT merge these queues.

---

## 5. Adding a fifth outcome later

If a future caller needs to distinguish scan-input-malformed from row-malformed and from
unsupported-scheme as three separate operator queues (§3.4), the correct change is a **new
`cytadel_cpe_match_t` enumerator** plus updating every `switch` that consumes the result — the
compiler, via the no-`default:` rule in §3.2.2 and `-Wswitch` (from `-Wall -Werror`), will
point at every site that must decide how to handle it. This is the sanctioned way to grow the outcome set without a
silent behavior change. The comparator's result set (§1) is **not** part of this and stays
fixed at four values.

---

## 6. the security review checklist for any future caller

**CPE-MATCH-CALLER-1 (Critical if violated).** For every call site of
`cytadel_cpe_match_evaluate()`:

1. The result is consumed by a `switch` covering all enumerators with **no `default:`**. An
   `if`/`else`, a `!= CYTADEL_CPE_MATCH` test, a `== CYTADEL_CPE_NO_MATCH` test used to mean
   "safe", a ternary, a boolean cast, or a `switch` with `default:` is an automatic Critical —
   regardless of whether the current code paths happen to be correct — because it silently
   absorbs any outcome added under §5.
2. `CYTADEL_CPE_UNDECIDABLE` and `CYTADEL_CPE_MALFORMED_ROW` each reach a distinct
   operator-visible output path. Trace each to the actual rendered artifact (HTML report, CLI
   output, exit code). A `log_debug()`, a counter, a comment, or a TODO does **not** count as
   surfaced — that is a Critical.
3. Any per-CVE / per-host aggregation over multiple rows is three-valued and order-independent
   per §3.2.3. A fold where `NO_MATCH` can overwrite a previously-seen `UNDECIDABLE` is a
   Critical. Verify by constructing a candidate set containing both and evaluating in both
   orders.
4. The report's "clean host" / summary logic accounts for undetermined results per §3.3 — a
   host with a non-empty undecidable set never renders as "no vulnerabilities found".
5. Verify 1–4 by **executing** the caller against a crafted row set (e.g. a bound of
   `versionEndExcluding = "1.0.0-cr1"`, and a range row with all four bounds empty) and
   inspecting the produced artifact. A source-reading-only review does not satisfy this item.

**Collapsing `UNDECIDABLE` to affected or not-affected is a CRITICAL finding.**

---

## 7. Compile-time guards that exist now (no caller required)

`tests/unit/test_cpe_match.c` carries, independent of any caller:

- `_Static_assert`s pinning every pair of `cytadel_cpe_match_t` enumerators as distinct, so a
  refactor that aliases `UNDECIDABLE` onto `NO_MATCH` (or folds `MALFORMED_ROW` into
  `UNDECIDABLE`) fails the build rather than compiling green. A test that merely *reads* the
  enum back cannot catch this; the static assertion can.
- A no-`default:` exhaustiveness `switch` canary over `cytadel_cpe_match_t`. Under `-Wall
  -Werror` (this project's default), a no-`default:` switch that omits an enumerator is a
  `-Wswitch` error, so adding an enumerator under §5 forces a deliberate decision at that site.
