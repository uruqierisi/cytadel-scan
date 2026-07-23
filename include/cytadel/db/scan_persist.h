#ifndef CYTADEL_DB_SCAN_PERSIST_H
#define CYTADEL_DB_SCAN_PERSIST_H

#include <stdbool.h>
#include <stddef.h>

#include "cytadel/db/db.h"
#include "cytadel/match/cpe_match.h"

/* Milestone 7 (CPE-matching-caller slice): the `scans` / `scan_results`
 * persistence layer, and the FIRST PRODUCTION CALLER of
 * cytadel_cpe_match_evaluate() (include/cytadel/match/cpe_match.h). Built
 * strictly against docs/contracts/cpe-matching.md (FROZEN CONTRACT,
 * especially SS3 "caller obligations" and the CPE-MATCH-CALLER-1 checklist
 * in SS6) and docs/contracts/db-schema.md SS6/SS7/SS9/SS10 (also FROZEN,
 * except for the SS7 `match_status` column amendment this slice was
 * explicitly authorized to make on 2026-07-22 -- see db_migrations.c's
 * migration 2 and db-schema.md SS7/SS9's own "added migration v2" notes).
 *
 * ---------------------------------------------------------------------
 * THE CRUX: per-CVE three-valued aggregation (cpe-matching.md SS3.2.3).
 * ---------------------------------------------------------------------
 * A detected service resolves to a `(vendor, product, detected_version)`
 * triple. The SS9 candidate lookup (`SELECT ... FROM cve_cpe_matches WHERE
 * vendor = ? AND product = ?`) can return MULTIPLE rows for the SAME
 * cve_id (separate NVD configuration nodes/bands for one advisory -- see
 * tests/unit/test_cpe_match.c's regreSSHion two-band example). Each row is
 * independently evaluated via cytadel_cpe_match_evaluate(); the outcomes
 * for one cve_id are folded into exactly one of three `scan_results.
 * match_status` values via a Kleene (three-valued logic) OR, applied
 * order-independently:
 *
 *   any row MATCH               -> 'confirmed'
 *   else any row UNDECIDABLE    -> 'undetermined'
 *   else (>=1 row NO_MATCH)     -> 'not_affected'
 *
 * A `NO_MATCH` NEVER overwrites a previously-seen `UNDECIDABLE` or `MATCH`
 * -- this fold accumulates order-free booleans (any_match/any_undecidable/
 * any_no_match) across every row for the CVE and decides only once every
 * row has been seen, so re-ordering the candidate rows cannot change the
 * answer (cytadel_scan_aggregate_cve_verdict() below is unit-testable in
 * exactly this way, independent of any DB).
 *
 * `CYTADEL_CPE_MALFORMED_ROW` is NEVER one of the three match_status
 * values (cpe-matching.md SS2/SS3.1: it is a data-quality event, not a
 * verdict about the host). Every occurrence is:
 *   (a) counted in cytadel_scan_persist_counts_t.malformed_events, and
 *   (b) logged as a distinct, cve_id-naming data-quality line
 * -- regardless of what any OTHER row for that same cve_id decided. A
 * cve_id whose candidate rows are ALL malformed produces zero
 * `scan_results` rows (there is no verdict to persist), never a
 * fabricated 'confirmed'/'not_affected' row.
 *
 * The consuming switch over `cytadel_cpe_match_t` (src/db/scan_persist.c's
 * accumulate_outcome()) is EXHAUSTIVE with NO `default:` label per
 * CPE-MATCH-CALLER-1 SS3.2.2 -- adding a 5th outcome to that enum is a
 * `-Wswitch` build error at that one call site, by design.
 *
 * ---------------------------------------------------------------------
 * Audit-trail row model (cpe-matching.md SS3.1/SS3.2.4, this project's
 * explicit choice for this slice).
 * ---------------------------------------------------------------------
 * ONE `scan_results` row is written per DISTINCT candidate cve_id
 * evaluated for a detected service, regardless of verdict -- including
 * 'not_affected' rows. Row count multiplies by the number of distinct
 * CVEs candidate for a (vendor, product) pair; that is intended (an
 * operator can see exactly which CVEs were checked and ruled out, not
 * only the ones that hit).
 *
 * ---------------------------------------------------------------------
 * Ownership / concurrency.
 * ---------------------------------------------------------------------
 * Every function here takes a `cytadel_db_t *` already opened+migrated by
 * the caller (db.h) and performs its own bounded prepare/bind/step/
 * finalize sequence, wrapping cytadel_scan_detect_and_persist()'s multiple
 * inserts in one BEGIN..COMMIT transaction (mirrors src/db/kev_ingest.c /
 * epss_ingest.c's own transactional shape) -- either every `scan_results`
 * row this call would produce is committed together, or none of it is.
 * This module opens no connection of its own and spawns no threads.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* Hard cap on the byte length of the `vendor`/`product` strings
 * cytadel_scan_detect_and_persist() will accept -- generous headroom for
 * any real CPE-dictionary vendor/product token (mirrors kev_ingest.h's
 * CYTADEL_KEV_VENDOR_PRODUCT_MAX_LEN convention). Exposed here so tests can
 * assert against it by name. */
#define CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN 256

typedef enum {
    CYTADEL_SCAN_PERSIST_OK = 0,
    /* NULL/empty required argument, an out-of-range port, or a NULL
     * detected_version paired with a nonzero length -- caller bug, no DB
     * access was attempted. */
    CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG = 1,
    /* A fatal (non-recoverable) sqlite3 error occurred. Any transaction
     * this call had open was rolled back -- no partial write. */
    CYTADEL_SCAN_PERSIST_ERR_DB = 2,
    /* M9 Gap #3 fix: cytadel_scan_persist_finding() ONLY. A genuine per-row
     * data/constraint problem was rejected by SQLite itself (SQLITE_CONSTRAINT
     * on the cves placeholder upsert or on the scan_results insert) -- NOT a
     * broken/unavailable connection. Any transaction this call had open was
     * rolled back (this one row is skipped in its entirety: never a partial
     * cves-placeholder-without-its-scan_results-row, or vice versa), but the
     * connection itself is expected to still be perfectly usable for the very
     * next call. Callers (src/cli/scan_wiring.c) MUST count this and continue
     * -- it must NEVER be treated the same as CYTADEL_SCAN_PERSIST_ERR_DB
     * (which means "stop persisting to this connection at all"). See
     * cytadel_scan_persist_finding()'s own doc comment for the exact sqlite3
     * rc classification (which rc's are fatal vs. per-row). */
    CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED = 3
} cytadel_scan_persist_status_t;

/* Returns a static, human-readable name for `status`. Never returns NULL. */
const char *cytadel_scan_persist_status_to_string(cytadel_scan_persist_status_t status);

/* The three real, persisted `scan_results.match_status` values
 * (db-schema.md SS7, migration v2). Deliberately NOT the same type as
 * `cytadel_cpe_match_t` (cpe_match.h) -- that four-value evaluator result
 * is a per-ROW outcome including the two data-quality/can't-decide axes
 * (UNDECIDABLE, MALFORMED_ROW); this is the three-value, per-CVE,
 * ALREADY-AGGREGATED verdict that is actually safe to store as one
 * persisted column. Never conflate the two enums. */
typedef enum {
    CYTADEL_SCAN_MATCH_CONFIRMED = 0,    /* db: 'confirmed' */
    CYTADEL_SCAN_MATCH_UNDETERMINED = 1, /* db: 'undetermined' */
    CYTADEL_SCAN_MATCH_NOT_AFFECTED = 2  /* db: 'not_affected' */
} cytadel_scan_match_status_t;

/* Returns the exact, lower-case, DB-stored string for `status`
 * ("confirmed"/"undetermined"/"not_affected"). Never returns NULL. */
const char *cytadel_scan_match_status_to_string(cytadel_scan_match_status_t status);

/* Result of aggregating every cve_cpe_matches candidate row for ONE cve_id
 * against one detected_version, per cpe-matching.md SS3.2.3. */
typedef struct {
    /* false iff every row passed in was CYTADEL_CPE_MALFORMED_ROW (no
     * decidable outcome at all for this cve_id) -- `status` is unspecified
     * and MUST NOT be persisted/read when this is false; no scan_results
     * row should be written for this cve_id in that case. */
    bool has_verdict;
    cytadel_scan_match_status_t status; /* only meaningful when has_verdict */
    /* Count of CYTADEL_CPE_MALFORMED_ROW outcomes among the rows passed in
     * -- ALWAYS meaningful (independent of has_verdict): every one of these
     * is its own distinct data-quality event that a caller must still
     * surface even when has_verdict is also true (a CVE can have both a
     * decidable row and a separately malformed row). */
    size_t malformed_count;
} cytadel_scan_cve_verdict_t;

/* PURE function: no DB access, no allocation, no global state. Evaluates
 * every element of `rows` (all belonging to the SAME cve_id -- grouping
 * candidate rows by cve_id is the caller's job; this function makes no
 * attempt to detect or reject a mixed-cve_id `rows` array, since it never
 * looks at cve_id at all) against `detected_version` via
 * cytadel_cpe_match_evaluate(), and folds the per-row cytadel_cpe_match_t
 * outcomes into one cytadel_scan_cve_verdict_t via the order-independent
 * Kleene accumulator described in this header's own top comment. Evaluating
 * `rows` in any order (including fully reversed) is guaranteed to produce
 * an identical result -- this is the single piece of logic
 * CPE-MATCH-CALLER-1 SS3.2.3 (per-CVE aggregation must be three-valued and
 * order-independent) exists to prove, and it is exercised directly (no DB,
 * no cytadel_db_t) by tests/unit/test_scan_persist.c so the property can be
 * proven and reverted-proven independent of any SQL machinery.
 *
 * `rows` may be NULL only when row_count is 0 (returns has_verdict=false,
 * malformed_count=0 -- "no candidate rows" is not a data-quality event and
 * produces nothing to persist). `detected_version` may be NULL only when
 * detected_version_len is 0, mirroring cytadel_cpe_match_evaluate()'s own
 * contract. */
cytadel_scan_cve_verdict_t cytadel_scan_aggregate_cve_verdict(const cytadel_cpe_match_row_t *rows,
                                                                size_t row_count,
                                                                const char *detected_version,
                                                                size_t detected_version_len);

/* Creates the durable `scans` row (db-schema.md SS6/SS9 "Scan authorization
 * + creation") -- this row IS the durable record of the mandatory
 * startup-authorization-gate confirmation (the mandatory authorization-gate rule: "Log the
 * confirmation."). Every argument is bound as a `?` parameter (SS9); none
 * are ever string-concatenated into SQL text.
 *
 * `authorization_method` must be exactly "interactive" or "flag" (the
 * schema's own CHECK constraint, db-schema.md SS6) -- this function does
 * NOT independently re-validate the value; an invalid string is rejected
 * by SQLite itself via SQLITE_CONSTRAINT, surfaced here as
 * CYTADEL_SCAN_PERSIST_ERR_DB (no row is left half-written).
 *
 * On success, writes the new scan_id (sqlite3_last_insert_rowid()) into
 * *out_scan_id. `db`, `target_spec`, `authorized_by`,
 * `authorization_method`, and `out_scan_id` must all be non-NULL. */
cytadel_scan_persist_status_t cytadel_scan_create(cytadel_db_t *db, const char *target_spec,
                                                    const char *authorized_by,
                                                    const char *authorization_method,
                                                    long long *out_scan_id);

/* Everything cytadel_scan_detect_and_persist() needs to build one (or,
 * across candidate CVEs, several) `scan_results` row(s) besides the
 * per-CVE match_status/cve_id/kev_flag/epss_score/severity it computes
 * itself. Every pointer field is bound as a `?` parameter -- never
 * string-concatenated. `evidence` is stored RAW: this module never
 * escapes it (escaping is the reporter's job, a later milestone's
 * concern) -- db-schema.md SS7's own `evidence` column comment. */
typedef struct {
    const char *host;      /* NOT NULL in the schema; must be non-NULL, non-empty here */
    int port;               /* must be in [0, 65535] (db-schema.md SS7 CHECK) */
    const char *service;    /* nullable */
    const char *plugin_id;  /* NOT NULL in the schema; must be non-NULL, non-empty here */
    const char *evidence;   /* NOT NULL in the schema; must be non-NULL here; never escaped */
    const char *remediation; /* nullable */
    /* The detected version string every candidate cve_cpe_matches row is
     * evaluated against (cpe-matching.md's `detected_version`). May
     * contain embedded NUL/control/non-ASCII bytes -- passed through
     * verbatim, exactly `detected_version_len` bytes, never strlen()'d.
     * May be NULL only when detected_version_len is 0. */
    const char *detected_version;
    size_t detected_version_len;
} cytadel_scan_detection_t;

/* Per-call outcome counters. `rows_inserted` counts exactly one row per
 * distinct candidate cve_id that had at least one decidable
 * (MATCH/NO_MATCH/UNDECIDABLE) outcome; `malformed_events` counts every
 * individual CYTADEL_CPE_MALFORMED_ROW outcome seen across every
 * candidate row for this detection (independent of, and not a substitute
 * for, rows_inserted -- see cytadel_scan_cve_verdict_t's own comment). */
typedef struct {
    size_t rows_inserted;
    size_t malformed_events;
} cytadel_scan_persist_counts_t;

/* Runs db-schema.md SS9's candidate lookup (`SELECT cve_id, version,
 * version_start_including, version_start_excluding, version_end_including,
 * version_end_excluding, vulnerable FROM cve_cpe_matches WHERE vendor = ?
 * AND product = ?`, augmented with `ORDER BY cve_id, id` purely so this
 * function can group each cve_id's candidate rows by simple adjacency
 * while streaming the result set -- the WHERE clause and returned columns
 * are unchanged from SS9's illustrative text) against `db`, evaluates
 * every returned row via cytadel_cpe_match_evaluate(), aggregates the
 * outcomes per distinct cve_id exactly as cytadel_scan_aggregate_cve_verdict()
 * does (both share the same underlying accumulator -- see
 * src/db/scan_persist.c), and persists one `scan_results` row per cve_id
 * that reached a decidable verdict (SS9's new scan_results insert pattern),
 * including a point-in-time snapshot lookup of severity (`cves.severity`),
 * kev_flag (`SELECT 1 FROM kev WHERE cve_id = ?`), and epss_score (`SELECT
 * epss_score FROM epss WHERE cve_id = ?`) for each such row
 * (db-schema.md SS10 assumption 6).
 *
 * `vendor`/`product` are lowercased internally before binding (db-schema.md
 * SS10 assumption 2: cve_cpe_matches stores both lowercase, and the index
 * is a case-sensitive equality lookup) -- callers may pass mixed-case
 * values. Both must be non-empty and no longer than 256 bytes (rejected as
 * CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG otherwise, no DB access attempted).
 *
 * A cve_id whose only candidate rows are CYTADEL_CPE_MALFORMED_ROW produces
 * NO scan_results row (out_counts->malformed_events is still incremented
 * and a data-quality line is still logged for it) -- never a fabricated
 * verdict. See this header's own top comment for the full per-CVE
 * aggregation rule this function implements.
 *
 * Beyond the ephemeral, per-call out_counts->malformed_events, every
 * CYTADEL_CPE_MALFORMED_ROW event this call sees is also folded DURABLY into
 * `scans.malformed_data_count` (db-schema.md SS6, migration v3, M8 report
 * slice 2) via `UPDATE scans SET malformed_data_count = malformed_data_count
 * + ? WHERE scan_id = ?` -- this is what lets a report generated from a
 * later process (which never sees this call's in-memory out_counts) still
 * show "N records had malformed data" for the scan. See this header's
 * "whole call ... one BEGIN..COMMIT transaction" note directly below: that
 * UPDATE is part of the SAME transaction as every scan_results row this call
 * produces, so the durable count and the rows it describes always commit or
 * roll back together.
 *
 * The whole call (every scan_results insert this detection produces, plus
 * the scans.malformed_data_count update above) is wrapped in one
 * BEGIN..COMMIT transaction: either all of it is durably committed
 * (CYTADEL_SCAN_PERSIST_OK) or none of it is (CYTADEL_SCAN_PERSIST_ERR_DB,
 * full ROLLBACK).
 *
 * `*out_counts` is always reset to all-zero at entry (even on an early
 * INVALID_ARG return). `db`, `vendor`, `product`, `detection`, and
 * `out_counts` must all be non-NULL; `scan_id` must be > 0 (the value
 * cytadel_scan_create() wrote into *out_scan_id). */
cytadel_scan_persist_status_t cytadel_scan_detect_and_persist(cytadel_db_t *db, long long scan_id,
                                                                const char *vendor, const char *product,
                                                                const cytadel_scan_detection_t *detection,
                                                                cytadel_scan_persist_counts_t *out_counts);

/* ---------------------------------------------------------------------
 * M9 Phase 0: cytadel_scan_persist_finding() -- direct plugin findings.
 * ---------------------------------------------------------------------
 * Everything cytadel_scan_persist_finding() needs to persist ONE
 * cytadel_finding_t (plugin-api.md SS2.9's report_vuln{}/security_report{},
 * already collected into a cytadel_host_result_t.findings by
 * cytadel_host_scan()) as its own `scan_results` row, independent of any
 * CPE/version match. Every pointer field is bound as a `?` parameter --
 * never string-concatenated. `evidence` is stored RAW, exactly like
 * cytadel_scan_detection_t.evidence (escaping is the reporter's job). */
typedef struct {
    const char *host;        /* NOT NULL in the schema; must be non-NULL, non-empty here */
    int port;                 /* must be in [0, 65535] (db-schema.md SS7 CHECK); 0 = host-level */
    const char *service;      /* nullable -- the KB service token for this port, if known */
    const char *plugin_id;    /* NOT NULL in the schema; must be non-NULL, non-empty here */
    const char *evidence;     /* NOT NULL in the schema; must be non-NULL here; never escaped */
    const char *remediation;  /* nullable */
    const char *cve_id;       /* nullable -- the finding's own CVE hint, if any */
    int severity;              /* must be in [0, 4] (db-schema.md SS7 CHECK) */
} cytadel_scan_finding_persist_t;

/* Persists exactly ONE `scan_results` row for `finding`, always with
 * match_status = 'confirmed' (a direct plugin observation is not a
 * candidate-CVE-range verdict -- cpe-matching.md's three-valued aggregation
 * does not apply here at all; there is nothing UNDECIDABLE or MALFORMED
 * about a plugin directly reporting what it observed).
 *
 * If `finding->cve_id` is non-NULL, this looks up a point-in-time
 * kev_flag/epss_score snapshot for it (db-schema.md SS9's "Is this CVE in
 * KEV / what's its EPSS?" query pattern -- the same query text
 * cytadel_scan_detect_and_persist() uses). If `finding->cve_id` is NULL,
 * kev_flag is stored as 0 and epss_score as NULL -- never a lookup against
 * a NULL key. `finding->severity` is stored verbatim (the plugin's own
 * severity, not a `cves.severity` snapshot -- a non-CVE-backed finding has
 * no `cves` row to snapshot from).
 *
 * ---------------------------------------------------------------------
 * M9 Gap #3 fix -- `finding->cve_id` is UNTRUSTED plugin input.
 * ---------------------------------------------------------------------
 * `scan_results.cve_id` is a hard FOREIGN KEY into `cves(cve_id)`
 * (db-schema.md SS7). A Lua plugin's report_vuln()/security_report() may
 * name a real-looking CVE this local `cves` table has never ingested (NVD
 * sync lag is NORMAL, not an error condition) -- inserting that cve_id
 * verbatim would previously fail the whole row with SQLITE_CONSTRAINT, which
 * a naive caller could (and did) treat as fatal. This function now applies
 * TWO defenses before ever binding `finding->cve_id` as that FK:
 *
 *   1. Grammar validation: `finding->cve_id` is checked against the SAME
 *      shared CVE-ID grammar src/db/nvd_ingest.c / kev_ingest.c / epss_ingest.c
 *      already enforce (src/db/cve_id_valid.h's cytadel_is_valid_cve_id()).
 *      A cve_id that does not fully match is NEVER used as a PK/FK -- this
 *      finding is instead persisted with cve_id=NULL (kev_flag=0,
 *      epss_score=NULL), and a WARN is logged naming the malformed value.
 *      This is still CYTADEL_SCAN_PERSIST_OK: a malformed cve_id hint does
 *      not mean the finding itself is invalid.
 *   2. Placeholder-FK dance: for a well-formed cve_id NOT yet present in
 *      `cves`, this runs the SAME placeholder-row upsert db-schema.md
 *      SS9/SS10 assumption 5 already documents for KEV/EPSS (`INSERT INTO
 *      cves (...) VALUES (...) ON CONFLICT (cve_id) DO NOTHING`, source =
 *      'placeholder') BEFORE the scan_results insert, both wrapped in ONE
 *      BEGIN..COMMIT transaction -- either both the placeholder cves row and
 *      the scan_results row land together, or neither does. A later NVD sync
 *      that reaches this cve_id promotes the placeholder to source='nvd'
 *      exactly like the KEV/EPSS placeholder rows do (nvd_ingest.c's own
 *      upsert, unmodified).
 *
 * sqlite3 rc classification (this function's own fatal-vs-per-row rule):
 *   - SQLITE_CONSTRAINT on the cves placeholder upsert or the scan_results
 *     insert itself -> per-row, NOT fatal: this one finding is skipped in
 *     its entirety (the whole transaction rolls back, so a rejected
 *     scan_results insert can never leave an orphaned placeholder cves row
 *     behind either), CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED is returned, and
 *     the connection remains fully usable for the next call.
 *   - Every other non-SQLITE_DONE sqlite3_step() outcome, every
 *     sqlite3_prepare_v2()/sqlite3_bind_*() failure, and every failed
 *     BEGIN/COMMIT/ROLLBACK -> fatal: indicates a broken connection or a
 *     genuine programming/environment bug, not a per-row data issue;
 *     CYTADEL_SCAN_PERSIST_ERR_DB is returned.
 *
 * ---------------------------------------------------------------------
 * KNOWN v1 LIMITATION -- deferred dedup (disclosed, not silently shipped).
 * ---------------------------------------------------------------------
 * A plugin finding persisted here and a `cytadel_scan_detect_and_persist()`
 * CPE/version-range verdict for the SAME underlying issue on the SAME
 * host/port can both produce a `scan_results` row describing (from an
 * operator's point of view) the same problem twice -- e.g. a plugin that
 * both calls report_vuln() with a CVE hint AND whose service is
 * independently resolved to a `(vendor, product, version)` triple that also
 * matches that CVE in `cve_cpe_matches`. This module does NOT attempt to
 * detect or collapse that overlap in this slice -- doing so correctly would
 * require either a stable natural key across both write paths or a
 * reconciliation pass this milestone does not build. The report may
 * therefore show two rows for what is really one vulnerability; severity/
 * KEV/finding COUNTS in a rendered report can read slightly high until a
 * future milestone adds real dedup. This is a disclosed limitation, not a
 * silently-shipped defect -- do not "fix" it with an ad hoc heuristic here
 * without updating this comment and docs/contracts accordingly.
 *
 * `db`, `finding`, `finding->host`, `finding->plugin_id`, and
 * `finding->evidence` must all be non-NULL/non-empty; `scan_id` must be > 0.
 * Returns CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG (no DB access attempted) on
 * any violation of the above, CYTADEL_SCAN_PERSIST_ERR_DB on a fatal sqlite3
 * error, CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED on a per-row constraint
 * rejection (see this function's own "M9 Gap #3 fix" comment above for the
 * exact rc classification), CYTADEL_SCAN_PERSIST_OK once the row is durably
 * committed. */
cytadel_scan_persist_status_t cytadel_scan_persist_finding(cytadel_db_t *db, long long scan_id,
                                                             const cytadel_scan_finding_persist_t *finding);

/* ---------------------------------------------------------------------
 * M9 Phase 0: cytadel_scan_finalize() -- close out the `scans` row.
 * ---------------------------------------------------------------------
 * The three real, terminal `scans.status` values this module can transition
 * a scan INTO (db-schema.md SS6's CHECK constraint also allows 'running',
 * the value cytadel_scan_create() itself sets at INSERT time -- never a
 * value this finalize step writes back to). */
typedef enum {
    CYTADEL_SCAN_FINALIZE_COMPLETED = 0, /* db: 'completed' */
    CYTADEL_SCAN_FINALIZE_ABORTED = 1,   /* db: 'aborted' */
    CYTADEL_SCAN_FINALIZE_FAILED = 2     /* db: 'failed' */
} cytadel_scan_finalize_status_t;

/* Returns the exact, lower-case, DB-stored string for `status`
 * ("completed"/"aborted"/"failed"). Never returns NULL. */
const char *cytadel_scan_finalize_status_to_string(cytadel_scan_finalize_status_t status);

/* `UPDATE scans SET status = ?, finished_at = strftime(...) WHERE scan_id =
 * ?;` -- ?-bound, `status` is always one of this module's own three trusted
 * literal strings (cytadel_scan_finalize_status_to_string()), never a
 * caller-supplied/external string, so there is no path for an invalid value
 * to reach the schema's own CHECK constraint through this function. `db`
 * must be non-NULL and `scan_id` must be > 0 (CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG
 * otherwise, no DB access attempted). Returns CYTADEL_SCAN_PERSIST_ERR_DB on
 * a fatal sqlite3 error (including "no scans row exists for this scan_id" --
 * SQLite's own `UPDATE ... WHERE` affecting zero rows is not itself an
 * error, but this function treats a zero-row update as a caller-visible DB
 * error since it means the scan_id this whole call chain believes it is
 * finalizing does not actually exist). */
cytadel_scan_persist_status_t cytadel_scan_finalize(cytadel_db_t *db, long long scan_id,
                                                      cytadel_scan_finalize_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_SCAN_PERSIST_H */
