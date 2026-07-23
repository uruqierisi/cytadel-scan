#ifndef CYTADEL_DB_NVD_CATCHUP_H
#define CYTADEL_DB_NVD_CATCHUP_H

#include <stddef.h>

#include "cytadel/db/db.h"
#include "cytadel/net/nvd_fetch.h"

/* Milestone 7 (live NVD fetch slice): the fetch-driver / multi-window
 * catch-up wrapper. cytadel_nvd_sync_window() (src/db/nvd_sync.c) drives
 * exactly ONE [start_date, end_date] window and is explicitly scoped to
 * leave "computing the window bounds themselves (reading the current
 * watermark, the min(now, watermark+120d) arithmetic, and the multi-window
 * catch-up loop of db-schema.md SS8 step 6) ... the caller's concern" (see
 * that header's own top-of-file comment). This module IS that caller: it
 * reads the durable watermark out of sync_state, computes the chronological
 * sequence of at-most-120-day windows needed to reach "now", and drives
 * cytadel_nvd_sync_window() once per window until caught up.
 *
 * WATERMARK-ADVANCE INVARIANT (inherited from nvd_sync.h/nvd_ingest.h, this
 * module adds nothing new here -- it just chains the invariant across
 * windows): each window's watermark advance is committed by the ingest layer
 * INSIDE that window's own call to cytadel_nvd_sync_window(), before that
 * call ever returns CYTADEL_NVD_SYNC_OK. This module never itself touches
 * sync_state -- it only decides whether to start the NEXT window, based on
 * the previous call's return status. The moment any window's call returns
 * anything other than OK, this module stops immediately and returns an
 * error: it never advances its own in-memory cursor past a window that did
 * not itself durably commit, and it never retries/skips a window. The next
 * time cytadel_nvd_catchup() is called (e.g. the next scheduled run), it
 * re-reads the (unchanged) watermark and resumes from exactly the same
 * point -- never skipping a day of CVE coverage, never re-downloading data
 * that already committed.
 *
 * DETERMINISTIC "now" (mandatory, not a convenience): `now_iso8601` is an
 * INJECTED caller-supplied timestamp, never read from the system clock
 * inside this module. This is what makes the multi-window loop -- including
 * the 120-day boundary arithmetic -- fully unit-testable without any
 * wall-clock dependence; see tests/unit/test_nvd_catchup.c. A production
 * caller (e.g. a future scheduled-sync entry point) is expected to format
 * the real current time (matching db-schema.md's binding
 * "YYYY-MM-DDTHH:MM:SS.sssZ" convention, e.g. via
 * cytadel_log_format_timestamp_utc()) and pass that string in here; this
 * module has no opinion on how that thin wrapper is built and does not
 * provide one itself.
 *
 * DATE ARITHMETIC (this module's own, timezone-trap-free implementation --
 * see nvd_catchup.c's top-of-file comment for the full rationale): every
 * ISO-8601 instant this module reads (the stored watermark, the injected
 * `now`) is parsed into a (days-since-epoch, milliseconds-of-day) pair using
 * a Howard-Hinnant-style days_from_civil()/civil_from_days() integer
 * algorithm -- NEVER mktime()/localtime()/gmtime(), which are timezone- and
 * DST-dependent and are not appropriate for pure calendar-date arithmetic on
 * an already-UTC-normalized value. Two such pairs compare correctly by
 * simple integer comparison; "add 120 days" is simple integer addition on
 * the days component, correctly crossing month/year/leap-year boundaries
 * for free because the underlying algorithm is exact proleptic-Gregorian
 * civil-calendar math, not calendar-table lookups.
 *
 * LIBERAL IN / STRICT OUT: the stored sync_state.last_mod_watermark this
 * module reads is treated as untrusted, format-wise -- it accepts either a
 * bare `YYYY-MM-DD` date or a full `YYYY-MM-DDTHH:MM:SS[.sss][Z]` instant
 * (optional fractional seconds of 1-9 digits, optional trailing Z/z). Any
 * window bound this module itself computes and hands to
 * cytadel_nvd_sync_window() (which also becomes the NEXT stored watermark,
 * via that call's own commit) is always emitted in the full canonical
 * `YYYY-MM-DDTHH:MM:SS.sssZ` shape db-schema.md's timestamp convention
 * requires. A watermark string that fails to parse at all (garbage,
 * embedded control bytes, an implausible/out-of-range date) is a clean
 * CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK -- never a crash, never an
 * unbounded loop.
 */

#ifdef __cplusplus
extern "C" {
#endif

/* NVD 2.0's own documented ceiling on a single lastModStartDate/
 * lastModEndDate window (db-schema.md SS8 step 2's "NVD API 2.0 caps each
 * window at 120 days"). */
#define CYTADEL_NVD_CATCHUP_WINDOW_DAYS 120

/* Hostile-input safety valve: an upper bound on how many 120-day windows a
 * single cytadel_nvd_catchup() call will ever drive. At 120 days/window this
 * covers roughly 328 years of catch-up (1000 * 120 / 365.25) -- NVD's own
 * CVE program did not exist before 1999, so a legitimate watermark, however
 * stale, never comes close to this. It exists purely so a hostile or
 * corrupted watermark (e.g. a stray "0001-01-01") cannot make this function
 * loop for an unbounded/impractically long time: once exceeded, the loop
 * aborts cleanly with CYTADEL_NVD_CATCHUP_ERR_TOO_MANY_WINDOWS instead of
 * either hanging or (worse) silently truncating the catch-up without
 * telling the caller. */
#define CYTADEL_NVD_CATCHUP_MAX_WINDOWS 1000

typedef enum {
    CYTADEL_NVD_CATCHUP_OK = 0,
    /* NULL db/cfg/out, an empty/NULL now_iso8601, or a now_iso8601 that does
     * not itself parse as a valid ISO-8601 date/instant -- caller bug, no DB
     * access or network I/O was attempted. */
    CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG = 1,
    /* Reading sync_state.last_mod_watermark failed at the SQL level (prepare/
     * bind/step error, or the seeded feed='nvd' row is unexpectedly absent --
     * db-schema.md SS8 requires it be seeded by the migration). A DB-layer
     * failure, not a data-shape problem. */
    CYTADEL_NVD_CATCHUP_ERR_DB = 2,
    /* sync_state.last_mod_watermark holds a non-NULL, non-empty value that
     * does not parse as either a bare YYYY-MM-DD date or a
     * YYYY-MM-DDTHH:MM:SS[.sss][Z] instant. Nothing was fetched; the
     * watermark is left exactly as stored (this module never writes to
     * sync_state itself). */
    CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK = 3,
    /* One window's cytadel_nvd_sync_window() call returned a non-OK status.
     * The catch-up loop stopped immediately -- *out->windows_completed
     * reports how many EARLIER windows in this same call already committed
     * (and therefore already advanced the durable watermark that far); the
     * failed window's own data was never committed (nvd_sync.h's own
     * invariant), so the watermark sits exactly at the end of the last
     * successful window, ready for the next catch-up call to resume from
     * there. */
    CYTADEL_NVD_CATCHUP_ERR_SYNC = 4,
    /* CYTADEL_NVD_CATCHUP_MAX_WINDOWS windows were driven (all successfully
     * -- see *out->windows_completed) and the cursor still had not reached
     * `now`. Every one of those windows' data is durably committed (each
     * one individually returned OK before the next was attempted), so this
     * is a "stopped early for safety", not a data-loss condition -- the next
     * cytadel_nvd_catchup() call resumes and will make further progress. */
    CYTADEL_NVD_CATCHUP_ERR_TOO_MANY_WINDOWS = 5
} cytadel_nvd_catchup_status_t;

typedef struct {
    size_t windows_completed; /* number of windows that returned CYTADEL_NVD_SYNC_OK */
    size_t pages_fetched;     /* summed across every completed window */
    size_t cve_ingested;      /* summed across every completed window */
    size_t cve_skipped;       /* summed across every completed window */
} cytadel_nvd_catchup_counts_t;

/* Never returns NULL. */
const char *cytadel_nvd_catchup_status_to_string(cytadel_nvd_catchup_status_t status);

/* Drives however many chronological, at-most-120-day windows are needed to
 * bring the NVD sync's watermark up to `now_iso8601`:
 *
 *   1. Reads sync_state.last_mod_watermark for feed='nvd' (parameterized
 *      read, never string-concatenated).
 *   2. NULL/empty watermark (no prior sync ever completed): drives exactly
 *      ONE window with start_date=NULL (the initial bulk load) and
 *      end_date=now_iso8601.
 *   3. Otherwise: start = watermark; loop while start < now: end =
 *      min(start + CYTADEL_NVD_CATCHUP_WINDOW_DAYS days, now); drive
 *      cytadel_nvd_sync_window(db, cfg, start, end, 0, ...); on OK, advance
 *      start = end (that window's own commit already made this the new
 *      durable watermark) and continue; on any non-OK status, stop
 *      immediately and return CYTADEL_NVD_CATCHUP_ERR_SYNC.
 *   4. If start already >= now (watermark is current or in the future),
 *      zero windows are driven and this returns CYTADEL_NVD_CATCHUP_OK
 *      immediately -- no fetch, no DB write.
 *
 * `db` must already be migrated. `cfg` is passed through unchanged to every
 * cytadel_nvd_sync_window() call (loopback-fixture-injectable in tests, same
 * as that function's own contract). `now_iso8601` must be non-NULL/non-empty
 * and must itself parse as a valid ISO-8601 date/instant (see this header's
 * top-of-file "DETERMINISTIC now" note for why this is never read from the
 * system clock in here). `*out` is zeroed on entry and always safe to read
 * after the call, regardless of status.
 *
 * Returns CYTADEL_NVD_CATCHUP_OK only when every window needed to reach
 * `now_iso8601` (possibly zero of them) completed successfully. */
cytadel_nvd_catchup_status_t cytadel_nvd_catchup(cytadel_db_t *db,
                                                 const cytadel_nvd_fetch_config_t *cfg,
                                                 const char *now_iso8601,
                                                 cytadel_nvd_catchup_counts_t *out);

#ifdef __cplusplus
}
#endif

#endif /* CYTADEL_DB_NVD_CATCHUP_H */
