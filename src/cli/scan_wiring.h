#ifndef CYTADEL_CLI_SCAN_WIRING_H
#define CYTADEL_CLI_SCAN_WIRING_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "cytadel/db/db.h"
#include "cytadel/db/scan_persist.h"
#include "cytadel/kb/kb.h"
#include "cytadel/net/scan_types.h"

/* M9 Phase 0: the live scan pipeline's DB wiring, extracted out of
 * src/cli/main.c into small, independently unit-testable functions (this
 * milestone's own build-plan requirement -- main() itself is not a useful
 * unit-test surface). Every function here is pure orchestration over
 * already-frozen contracts: docs/contracts/db-schema.md SS6/SS7/SS9/SS10 and
 * docs/contracts/cpe-matching.md (both FROZEN) via src/db/scan_persist.c's
 * cytadel_scan_create()/cytadel_scan_detect_and_persist()/
 * cytadel_scan_persist_finding()/cytadel_scan_finalize(), and
 * docs/contracts/kb-schema.md SS7.7's CPE/<port> join-key fact via
 * src/net/cpe_map.c. No new SQL lives here -- every DB write funnels through
 * src/db/scan_persist.c's own prepared statements.
 *
 * Kept private to src/cli (this is CLI-orchestration glue, not a reusable
 * engine module), mirroring src/cli/report_cmd.h's own "logic split out of
 * main() for testability" precedent.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ *
 * Step 3/4: the mandatory-DB gate (the mandatory authorization-gate rule's durable half).
 * ------------------------------------------------------------------ */

typedef enum {
    CYTADEL_SCAN_GATE_OK = 0,
    /* db is NULL, target_spec/authorized_by/authorization_method is
     * NULL/empty, or out_db/out_scan_id is NULL -- caller bug, no DB access
     * was attempted. */
    CYTADEL_SCAN_GATE_ERR_INVALID_ARG = 1,
    /* cytadel_db_open() itself failed (missing parent directory, permission
     * denied, disk full, ...). *out_db is left NULL. */
    CYTADEL_SCAN_GATE_ERR_OPEN = 2,
    /* cytadel_db_migrate() failed against an otherwise-open connection.
     * *out_db has already been closed by this function -- never leaked. */
    CYTADEL_SCAN_GATE_ERR_MIGRATE = 3,
    /* cytadel_scan_create() itself failed (e.g. a schema-level rejection).
     * *out_db has already been closed by this function -- never leaked. */
    CYTADEL_SCAN_GATE_ERR_SCAN_CREATE = 4
} cytadel_scan_gate_status_t;

/* Returns a static, human-readable name for `status`. Never returns NULL. */
const char *cytadel_scan_gate_status_to_string(cytadel_scan_gate_status_t status);

/* Opens `db_path` (creating the file if it does not exist), migrates it to
 * the latest schema version, and creates the durable `scans` row (the
 * mandatory-authorization-gate confirmation record, the mandatory authorization-gate rule) --
 * db-schema.md SS6/SS9's "Scan authorization + creation", verbatim via
 * cytadel_scan_create(). This function takes no target list, port range, or
 * scan-options argument of any kind -- structurally, it cannot expand a
 * target or start a network probe, which is exactly the property
 * src/cli/main.c's ordering depends on: this call happens BEFORE
 * cytadel_target_list_parse() and the worker pool, so a refusal here is
 * observable as "no scan phase was ever reached" rather than merely
 * "some scan output was suppressed".
 *
 * On CYTADEL_SCAN_GATE_OK, *out_db is a live, migrated connection the
 * caller must release exactly once via cytadel_db_close(), and *out_scan_id
 * is the new scan_id (already > 0). On any other status, *out_db is NULL
 * (any connection this call opened along the way has already been closed --
 * never leaked) and *out_scan_id is left unset.
 *
 * `db_path`, `target_spec`, `authorized_by`, `authorization_method`,
 * `out_db`, and `out_scan_id` must all be non-NULL; `target_spec`,
 * `authorized_by`, and `authorization_method` must also be non-empty.
 * `authorization_method` must be exactly "interactive" or "flag"
 * (cytadel_scan_create()'s own contract; an invalid value is rejected at
 * the DB layer, surfaced here as CYTADEL_SCAN_GATE_ERR_SCAN_CREATE). */
cytadel_scan_gate_status_t cytadel_scan_wiring_open_gate(const char *db_path, const char *target_spec,
                                                           const char *authorized_by,
                                                           const char *authorization_method,
                                                           cytadel_db_t **out_db, long long *out_scan_id);

/* ------------------------------------------------------------------ *
 * The resolver: KB CPE/<port> fact -> (vendor, product, detected_version).
 * ------------------------------------------------------------------ */

typedef struct {
    /* NUL-terminated, bounded copies -- cytadel_scan_detect_and_persist()
     * takes plain `const char *` for these two (no length parameter), so
     * they cannot be borrowed substring pointers the way `version` below
     * is. */
    char vendor[CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN + 1];
    char product[CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN + 1];

    /* Borrowed pointer into the KB's own owned storage for this port's
     * CPE/<port> string (kb.h's cytadel_kb_get_str() validity window: valid
     * until that same key is next overwritten, or the KB is freed --
     * whichever comes first). Never NUL-terminated on its own (it is a
     * substring of the larger CPE string, delimited by ':'), so callers
     * must always pass `version`/`version_len` together, exactly like
     * cytadel_scan_detection_t.detected_version/detected_version_len. */
    const char *version;
    size_t version_len;
} cytadel_scan_resolved_service_t;

/* Reads `CPE/<port>` from `kb` (kb-schema.md SS7.7 -- written by
 * src/net/cpe_map.c during service detection, if and only if a marker AND a
 * usable version token were both confidently identified) and splits its
 * fixed "cpe:2.3:a:VENDOR:PRODUCT:VERSION:*:*:*:*:*:*:*" shape back into a
 * (vendor, product, detected_version) triple.
 *
 * Returns false ("unresolvable" -- kb-schema.md SS7.7's whole reason for
 * being conservative about writing a CPE at all) when: no CPE/<port> key
 * exists for this port; the stored string does not split into at least 6
 * ':'-delimited fields; the vendor or product field is empty or exceeds
 * CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN bytes; or the version field is empty.
 * Every one of these checks is bounded against the string's own byte length
 * (kb.h's own CYTADEL_KB_VALUE_MAX_LEN cap, and kb_set_str()'s existing
 * embedded-NUL/UTF-8 rejection at write time) -- this function never reads
 * past that length, never assumes any particular field width, and never
 * crashes or truncates-and-continues on a garbage/oversized/malformed
 * value; a value this function cannot cleanly parse is treated exactly like
 * an absent CPE fact, not like a valid-but-empty one. A caller that gets
 * `false` back MUST NOT record that as "no vulnerability" -- see
 * src/cli/scan_wiring.c's cytadel_scan_wiring_persist_host() for the
 * data-quality log line this drives.
 *
 * `kb` and `out` must both be non-NULL. */
bool cytadel_scan_wiring_resolve_port(const cytadel_kb_t *kb, uint16_t port,
                                       cytadel_scan_resolved_service_t *out);

/* ------------------------------------------------------------------ *
 * The persist phase: one host's already-scanned result -> DB rows.
 * ------------------------------------------------------------------ */

typedef struct {
    size_t findings_persisted;     /* cytadel_scan_persist_finding() rows written */
    /* M9 Gap #3 fix: a finding whose scan_results/cves-placeholder insert
     * was rejected by a genuine per-row SQLITE_CONSTRAINT
     * (CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED) -- counted here and logged by
     * cytadel_scan_persist_finding() itself, NEVER treated the same as
     * CYTADEL_SCAN_PERSIST_ERR_DB: this does not abort persistence for the
     * rest of this host, this scan, or flip scans.status to 'failed'. */
    size_t findings_skipped;
    size_t detections_attempted;   /* open ports whose service DID resolve, and were
                                     * handed to cytadel_scan_detect_and_persist() */
    size_t unresolvable_services;  /* open ports whose service could NOT be resolved
                                     * to (vendor, product, version) -- logged, never
                                     * silently treated as clean */
    size_t rows_inserted;          /* summed across every detect_and_persist() call */
    size_t malformed_events;       /* summed across every detect_and_persist() call */
} cytadel_scan_wiring_host_counts_t;

/* Runs the approved persistence procedure's step 7 ("PERSIST PHASE") for one
 * already-UP, already-scanned host:
 *
 *   (a) every cytadel_finding_t in result->findings -> one
 *       cytadel_scan_persist_finding() row each (match_status='confirmed');
 *   (b) every OPEN port whose service resolves (cytadel_scan_wiring_resolve_port()
 *       above) -> one cytadel_scan_detect_and_persist() call (the CVE-CPE
 *       version-match path, including the UNDECIDABLE outcome);
 *   (c) every OPEN port whose service does NOT resolve -> a data-quality
 *       WARN log line naming host:port/service, counted in
 *       out_counts->unresolvable_services -- never silently treated as "no
 *       CVE / clean" (this project's own binding rule).
 *
 * This function performs DB writes only -- it never re-probes the network,
 * never mutates `result` or its KB, and never changes which ports/services
 * were detected. `result` must already be fully populated by
 * cytadel_host_scan() (result->state == CYTADEL_HOST_UP; calling this
 * against a DOWN host is a caller bug -- there is nothing to persist and
 * this function returns CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG rather than
 * silently no-op'ing, so a caller cannot accidentally believe a down host
 * was persisted).
 *
 * `*out_counts` is always reset to all-zero at entry, even on an early
 * INVALID_ARG return. Returns CYTADEL_SCAN_PERSIST_ERR_DB on the FIRST
 * fatal DB error encountered (a broken DB connection is unlikely to recover
 * mid-host) -- the caller should treat this as "stop attempting further
 * persistence for this scan", not "this one finding/port was bad" (that
 * case is instead absorbed here: an CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG
 * from an individual cytadel_scan_persist_finding()/
 * cytadel_scan_detect_and_persist() call -- which should not happen given
 * well-formed input, but is handled defensively -- is logged and skipped,
 * never propagated as a whole-host failure). Likewise, M9 Gap #3 fix: a
 * CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED from cytadel_scan_persist_finding()
 * (a genuine per-row SQLITE_CONSTRAINT -- e.g. a plugin-supplied cve_id the
 * placeholder-FK dance itself could not reconcile) is counted in
 * `out_counts->findings_skipped` and this loop simply continues to the next
 * finding -- it is NEVER treated the same as CYTADEL_SCAN_PERSIST_ERR_DB and
 * never aborts the rest of this host/scan.
 *
 * `db`, `result`, and `out_counts` must all be non-NULL; `scan_id` must be
 * > 0. */
cytadel_scan_persist_status_t cytadel_scan_wiring_persist_host(cytadel_db_t *db, long long scan_id,
                                                                  const cytadel_host_result_t *result,
                                                                  cytadel_scan_wiring_host_counts_t *out_counts);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_CLI_SCAN_WIRING_H */
