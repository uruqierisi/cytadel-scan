#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/net/target.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

/* Milestone 7 (live NVD fetch slice): the fetch-driver / multi-window
 * catch-up wrapper. See include/cytadel/db/nvd_catchup.h for the module
 * contract and the watermark-advance invariant this file exists to uphold.
 *
 * DATE MATH IMPLEMENTATION NOTE: every ISO-8601 date/instant this file
 * touches is parsed into a (days-since-1970-01-01, milliseconds-of-day)
 * pair via days_from_civil()/civil_from_days() below -- Howard Hinnant's
 * well-known, widely-verified integer civil-calendar algorithm
 * (http://howardhinnant.github.io/date_algorithms.html). This is pure
 * integer arithmetic over the proleptic Gregorian calendar: it has NO
 * dependency on the process's TZ environment, NO call to mktime()/
 * localtime()/gmtime() (which are timezone/DST-sensitive and are the wrong
 * tool here -- these timestamps are already UTC-normalized text, not local
 * wall-clock values needing timezone interpretation), and it is exact
 * across every month/year/leap-year boundary because leap years fall out of
 * the era/century/four-year-cycle arithmetic itself rather than a
 * hand-maintained days-per-month table. Two instants compare correctly via
 * plain integer comparison on (days, ms_of_day); "add N days" is plain
 * integer addition on the days component alone.
 */

#include "cytadel/db/nvd_catchup.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sqlite3.h>

#include "cytadel/db/nvd_sync.h"
#include "log.h"

/* Bound on the raw watermark string read back from sync_state, and on the
 * `now_iso8601` string handed in by the caller. Real values are at most
 * "YYYY-MM-DDTHH:MM:SS.sssZ" (24 bytes); this is deliberately generous (an
 * order of magnitude over that) so a slightly-unusual-but-legitimate value
 * is never rejected purely for length, while a hostile/corrupt value of
 * effectively unbounded length is still capped before any parsing begins --
 * see parse_instant()'s use of strnlen() against this bound. */
#define CYTADEL_NVD_CATCHUP_TS_MAX_LEN 40

/* Buffer sizes: +1 for the TS bound's NUL; the canonical-output buffer only
 * ever needs to hold "YYYY-MM-DDTHH:MM:SS.sssZ" (24 bytes) + NUL, but is
 * sized generously to match CYTADEL_ISO8601_BUF_LEN's own rounding (see
 * src/log/log.h) for consistency across the codebase. */
#define CYTADEL_NVD_CATCHUP_TS_BUF_LEN 32
#define CYTADEL_NVD_CATCHUP_WATERMARK_BUF_LEN (CYTADEL_NVD_CATCHUP_TS_MAX_LEN + 1)

const char *cytadel_nvd_catchup_status_to_string(cytadel_nvd_catchup_status_t status) {
    switch (status) {
        case CYTADEL_NVD_CATCHUP_OK:                       return "OK";
        case CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG:          return "INVALID_ARG";
        case CYTADEL_NVD_CATCHUP_ERR_DB:                   return "DB";
        case CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK:  return "MALFORMED_WATERMARK";
        case CYTADEL_NVD_CATCHUP_ERR_SYNC:                 return "SYNC";
        case CYTADEL_NVD_CATCHUP_ERR_TOO_MANY_WINDOWS:     return "TOO_MANY_WINDOWS";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* Howard-Hinnant-style civil-calendar <-> day-count conversion.       */
/* ------------------------------------------------------------------ */

/* Returns the number of days since 1970-01-01 for the (proleptic Gregorian)
 * civil date y-m-d. `m` in [1,12], `d` in [1,31] (the caller -- is_valid_ymd()
 * below -- is responsible for range/validity checking; this function itself
 * has no invalid-input branch because it is a pure formula, well-defined for
 * any m in [1,12] and any d, valid or not -- validity is established purely
 * by the round-trip check in is_valid_ymd()). */
static long long days_from_civil(long long y, int m, int d) {
    y -= (m <= 2) ? 1 : 0;
    long long era = (y >= 0 ? y : y - 399) / 400;
    long long yoe = y - era * 400;                                          /* [0, 399] */
    long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;          /* [0, 365] */
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;                  /* [0, 146096] */
    return era * 146097 + doe - 719468;
}

/* Inverse of days_from_civil(). */
static void civil_from_days(long long z, long long *y, int *m, int *d) {
    z += 719468;
    long long era = (z >= 0 ? z : z - 146096) / 146097;
    long long doe = z - era * 146097;                                                     /* [0, 146096] */
    long long yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;                 /* [0, 399] */
    long long yy = yoe + era * 400;
    long long doy = doe - (365 * yoe + yoe / 4 - yoe / 100);                               /* [0, 365] */
    long long mp = (5 * doy + 2) / 153;                                                    /* [0, 11] */
    long long dd = doy - (153 * mp + 2) / 5 + 1;                                            /* [1, 31] */
    long long mm = mp + (mp < 10 ? 3 : -9);                                                 /* [1, 12] */
    *y = yy + (mm <= 2 ? 1 : 0);
    *m = (int)mm;
    *d = (int)dd;
}

/* True iff (y, m, d) is a genuine calendar date -- established by round-
 * tripping through days_from_civil()/civil_from_days() rather than a
 * hand-maintained days-per-month/leap-year table, so this is automatically
 * correct for leap years (a malformed "2023-02-29" round-trips to
 * "2023-03-01" and is rejected; a genuine "2024-02-29" round-trips to
 * itself and is accepted). */
static bool is_valid_ymd(long long y, int m, int d) {
    if (m < 1 || m > 12 || d < 1 || d > 31) {
        return false;
    }
    long long days = days_from_civil(y, m, d);
    long long y2;
    int m2, d2;
    civil_from_days(days, &y2, &m2, &d2);
    return y2 == y && m2 == m && d2 == d;
}

/* ------------------------------------------------------------------ */
/* ISO-8601 instant: (days-since-epoch, milliseconds-of-day).         */
/* ------------------------------------------------------------------ */

typedef struct {
    long long days;
    long ms_of_day; /* [0, 86399999] */
} cytadel_instant_t;

static int instant_compare(const cytadel_instant_t *a, const cytadel_instant_t *b) {
    if (a->days != b->days) {
        return (a->days < b->days) ? -1 : 1;
    }
    if (a->ms_of_day != b->ms_of_day) {
        return (a->ms_of_day < b->ms_of_day) ? -1 : 1;
    }
    return 0;
}

static cytadel_instant_t instant_add_days(cytadel_instant_t inst, long long n) {
    inst.days += n;
    return inst;
}

/* Reads exactly `n` ASCII digits from s[*pos, *pos+n) into *out, advancing
 * *pos. Fails (leaving *pos and *out untouched) if fewer than n bytes remain
 * or any of them is not a digit -- never reads past `len`. */
static bool read_digits(const char *s, size_t len, size_t *pos, int n, long *out) {
    if (*pos + (size_t)n > len) {
        return false;
    }
    long val = 0;
    for (int i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[*pos + (size_t)i];
        if (c < '0' || c > '9') {
            return false;
        }
        val = val * 10 + (long)(c - '0');
    }
    *pos += (size_t)n;
    *out = val;
    return true;
}

/* Parses `s` as either a bare "YYYY-MM-DD" date or a full
 * "YYYY-MM-DDTHH:MM:SS[.f+][Z]" instant (fractional seconds: 1-9 digits,
 * normalized to milliseconds by taking the leading 3 -- padded with
 * trailing zeros if fewer than 3 digits were given; trailing 'Z'/'z' is
 * optional and is the only accepted "offset" -- this codebase's own
 * timestamps are always UTC per db-schema.md's binding convention, so no
 * other offset form is supported). Bounded, hand-rolled (no sscanf) so a
 * hostile/garbage/embedded-control-byte `s` can never do anything worse than
 * fail this function -- every branch either advances `pos` by a fixed,
 * already-length-checked amount or returns false immediately. Returns false
 * (leaving *out unspecified) for: a NULL `s`, an empty string, a string
 * longer than CYTADEL_NVD_CATCHUP_TS_MAX_LEN, any missing/wrong separator,
 * an out-of-range field (month/day/hour/minute/second, or a (y,m,d) that is
 * not a genuine calendar date), or any trailing garbage after a
 * successfully parsed instant. */
static bool parse_instant(const char *s, cytadel_instant_t *out) {
    if (s == NULL) {
        return false;
    }
    size_t len = strnlen(s, CYTADEL_NVD_CATCHUP_TS_MAX_LEN + 1);
    if (len == 0 || len > CYTADEL_NVD_CATCHUP_TS_MAX_LEN) {
        return false;
    }

    size_t pos = 0;
    long year = 0, month = 0, day = 0;
    if (!read_digits(s, len, &pos, 4, &year)) {
        return false;
    }
    if (pos >= len || s[pos] != '-') {
        return false;
    }
    pos++;
    if (!read_digits(s, len, &pos, 2, &month)) {
        return false;
    }
    if (pos >= len || s[pos] != '-') {
        return false;
    }
    pos++;
    if (!read_digits(s, len, &pos, 2, &day)) {
        return false;
    }
    if (!is_valid_ymd(year, (int)month, (int)day)) {
        return false;
    }
    long long days = days_from_civil(year, (int)month, (int)day);

    if (pos == len) {
        /* Bare date -- treated as midnight UTC. */
        out->days = days;
        out->ms_of_day = 0;
        return true;
    }

    char sep = s[pos];
    if (sep != 'T' && sep != 't' && sep != ' ') {
        return false;
    }
    pos++;

    long hh = 0, mm = 0, ss = 0;
    if (!read_digits(s, len, &pos, 2, &hh) || hh > 23) {
        return false;
    }
    if (pos >= len || s[pos] != ':') {
        return false;
    }
    pos++;
    if (!read_digits(s, len, &pos, 2, &mm) || mm > 59) {
        return false;
    }
    if (pos >= len || s[pos] != ':') {
        return false;
    }
    pos++;
    if (!read_digits(s, len, &pos, 2, &ss) || ss > 59) {
        return false;
    }

    long millis = 0;
    if (pos < len && s[pos] == '.') {
        pos++;
        int frac_digits = 0;
        long frac_val = 0;
        /* Bounded loop: `len` itself is already capped at
         * CYTADEL_NVD_CATCHUP_TS_MAX_LEN, so this can never iterate more
         * than that many times regardless of input; frac_digits > 9 below
         * additionally rejects an implausible fractional-second field
         * outright rather than silently truncating it. */
        while (pos < len && s[pos] >= '0' && s[pos] <= '9') {
            if (frac_digits < 9) {
                frac_val = frac_val * 10 + (s[pos] - '0');
            }
            frac_digits++;
            pos++;
        }
        if (frac_digits == 0 || frac_digits > 9) {
            return false; /* bare '.' with no digits, or an absurd fraction */
        }
        if (frac_digits >= 3) {
            long divisor = 1;
            for (int i = 0; i < frac_digits - 3; i++) {
                divisor *= 10;
            }
            millis = frac_val / divisor;
        } else {
            long multiplier = 1;
            for (int i = 0; i < 3 - frac_digits; i++) {
                multiplier *= 10;
            }
            millis = frac_val * multiplier;
        }
    }

    if (pos < len && (s[pos] == 'Z' || s[pos] == 'z')) {
        pos++;
    }
    if (pos != len) {
        return false; /* trailing garbage after the parsed instant */
    }

    out->days = days;
    out->ms_of_day = (long)(((hh * 60 + mm) * 60 + ss) * 1000 + millis);
    return true;
}

/* Formats `inst` into the canonical "YYYY-MM-DDTHH:MM:SS.sssZ" shape
 * db-schema.md's timestamp convention requires. `out_cap` must be >=
 * CYTADEL_NVD_CATCHUP_TS_BUF_LEN. Returns false (never writing past
 * `out_cap`) if `inst` is somehow out of the 4-digit-year grammar this
 * module accepts on read, or ms_of_day is out of its valid range -- neither
 * should be reachable given this file's own callers, but this is checked
 * rather than assumed so a future internal bug fails closed instead of
 * emitting a malformed/overflowed timestamp. */
static bool format_instant(const cytadel_instant_t *inst, char *out, size_t out_cap) {
    long long y;
    int m, d;
    civil_from_days(inst->days, &y, &m, &d);
    if (y < 0 || y > 9999) {
        return false;
    }
    if (inst->ms_of_day < 0 || inst->ms_of_day >= 86400000L) {
        return false;
    }
    int hh = (int)(inst->ms_of_day / 3600000L);
    int mm = (int)((inst->ms_of_day / 60000L) % 60);
    int ss = (int)((inst->ms_of_day / 1000L) % 60);
    int ms = (int)(inst->ms_of_day % 1000L);
    int n = snprintf(out, out_cap, "%04lld-%02d-%02dT%02d:%02d:%02d.%03dZ", y, m, d, hh, mm, ss, ms);
    return n > 0 && (size_t)n < out_cap;
}

/* ------------------------------------------------------------------ */
/* sync_state watermark read.                                          */
/* ------------------------------------------------------------------ */

/* Not part of db-schema.md SS9's illustrative query list (that section has
 * no read-watermark example -- see this module's task brief) -- this
 * mirrors its parameterized style: `feed` is bound, never string-
 * concatenated, even though 'nvd' is the only value this module ever
 * passes. */
static const char *const CYTADEL_NVD_WATERMARK_SELECT_SQL =
    "SELECT last_mod_watermark FROM sync_state WHERE feed = ?;";

static void clip_into(char *dst, size_t dst_cap, const char *src) {
    size_t n = strnlen(src, dst_cap - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Reads sync_state.last_mod_watermark for feed='nvd' into `out` (bounded,
 * always NUL-terminated). *out_present is set to true iff the column was
 * non-NULL and non-empty. Returns CYTADEL_NVD_CATCHUP_ERR_DB on any SQL-level
 * failure (prepare/bind/step, or the seeded row being unexpectedly absent --
 * db-schema.md SS8 requires it to be seeded by the migration runner). */
static cytadel_nvd_catchup_status_t read_watermark(sqlite3 *handle, char *out, size_t out_cap,
                                                    bool *out_present) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(handle, CYTADEL_NVD_WATERMARK_SELECT_SQL, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_catchup: preparing watermark select failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return CYTADEL_NVD_CATCHUP_ERR_DB;
    }
    rc = sqlite3_bind_text(stmt, 1, "nvd", -1, SQLITE_STATIC);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_catchup: binding watermark select failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        sqlite3_finalize(stmt);
        return CYTADEL_NVD_CATCHUP_ERR_DB;
    }
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        cytadel_log_error(
            "nvd_catchup: sync_state has no row for feed='nvd' (sqlite rc=%d) -- has the schema been "
            "migrated?",
            rc);
        sqlite3_finalize(stmt);
        return CYTADEL_NVD_CATCHUP_ERR_DB;
    }

    if (sqlite3_column_type(stmt, 0) == SQLITE_NULL) {
        out[0] = '\0';
        *out_present = false;
    } else {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        clip_into(out, out_cap, text != NULL ? (const char *)text : "");
        *out_present = (out[0] != '\0');
    }

    sqlite3_finalize(stmt);
    return CYTADEL_NVD_CATCHUP_OK;
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

cytadel_nvd_catchup_status_t cytadel_nvd_catchup(cytadel_db_t *db,
                                                 const cytadel_nvd_fetch_config_t *cfg,
                                                 const char *now_iso8601,
                                                 cytadel_nvd_catchup_counts_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
    }
    if (db == NULL || cfg == NULL || now_iso8601 == NULL || now_iso8601[0] == '\0' || out == NULL) {
        cytadel_log_error(
            "nvd_catchup: catchup() called with a NULL db/cfg/out, or an empty now_iso8601");
        return CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG;
    }

    cytadel_instant_t now_instant;
    if (!parse_instant(now_iso8601, &now_instant)) {
        cytadel_log_error("nvd_catchup: now_iso8601 ('%s') is not a parseable ISO-8601 date/instant",
                          now_iso8601);
        return CYTADEL_NVD_CATCHUP_ERR_INVALID_ARG;
    }

    sqlite3 *handle = cytadel_db_handle(db);
    char watermark_raw[CYTADEL_NVD_CATCHUP_WATERMARK_BUF_LEN];
    bool have_watermark = false;
    cytadel_nvd_catchup_status_t rd_status =
        read_watermark(handle, watermark_raw, sizeof(watermark_raw), &have_watermark);
    if (rd_status != CYTADEL_NVD_CATCHUP_OK) {
        return rd_status;
    }

    /* One human-facing API-key status line per sync run (whether it is set and
     * whether it will be sent -- never the value). Replaces the fetch layer's
     * old once-per-page logging, which repeated an identical line for every
     * page of a multi-hour bulk load. */
    cytadel_nvd_fetch_log_api_key_status(cfg->base_url);

    /* Establish the starting cursor and the per-window length. Both the
     * initial bulk load (no prior watermark) and a routine incremental
     * catch-up (a watermark exists) run the SAME chronological window loop
     * below -- they differ only in where the cursor starts and how large each
     * window is. The bulk load starts at the CVE-program epoch and uses small
     * (CYTADEL_NVD_CATCHUP_BULK_WINDOW_DAYS) windows so a failure part way
     * through costs one small window, not the whole corpus; a routine
     * catch-up starts at the stored watermark and uses the full 120-day
     * ceiling. */
    cytadel_instant_t cursor;
    long window_days;
    if (have_watermark) {
        if (!parse_instant(watermark_raw, &cursor)) {
            cytadel_log_error(
                "nvd_catchup: stored sync_state.last_mod_watermark ('%s') does not parse as a valid "
                "YYYY-MM-DD date or YYYY-MM-DDTHH:MM:SS[.sss][Z] instant -- refusing to catch up",
                watermark_raw);
            return CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK;
        }
        window_days = CYTADEL_NVD_CATCHUP_WINDOW_DAYS;
    } else {
        /* CYTADEL_NVD_EPOCH_START is a compile-time constant this module owns,
         * so a parse failure here would be an internal bug, never untrusted
         * input -- fail closed rather than proceed from an undefined cursor. */
        if (!parse_instant(CYTADEL_NVD_EPOCH_START, &cursor)) {
            cytadel_log_error("nvd_catchup: internal error -- the built-in epoch '%s' did not parse",
                              CYTADEL_NVD_EPOCH_START);
            return CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK;
        }
        window_days = CYTADEL_NVD_CATCHUP_BULK_WINDOW_DAYS;
        cytadel_log_info(
            "nvd_catchup: no prior watermark -- initial bulk load from %s in %ld-day windows "
            "(each commits independently; a failure resumes from the last committed window)",
            CYTADEL_NVD_EPOCH_START, window_days);
    }

    /* db-schema.md SS8 step 6: repeat `window_days`-day windows,
     * chronologically, until caught up. `cursor < now_instant` is the loop
     * condition; each iteration only ever advances `cursor` to a window bound
     * that a prior cytadel_nvd_sync_window() call has ALREADY durably committed
     * (that call's own OK return is the only thing that lets this loop advance
     * past that point) -- see this file's own top-of-file/header
     * "WATERMARK-ADVANCE INVARIANT" note. */
    while (instant_compare(&cursor, &now_instant) < 0) {
        if (out->windows_completed >= CYTADEL_NVD_CATCHUP_MAX_WINDOWS) {
            cytadel_log_error(
                "nvd_catchup: exceeded the %d-window safety cap without reaching 'now' -- aborting "
                "(hostile/corrupt watermark?); %zu window(s) already committed successfully",
                CYTADEL_NVD_CATCHUP_MAX_WINDOWS, out->windows_completed);
            return CYTADEL_NVD_CATCHUP_ERR_TOO_MANY_WINDOWS;
        }

        char start_buf[CYTADEL_NVD_CATCHUP_TS_BUF_LEN];
        if (!format_instant(&cursor, start_buf, sizeof(start_buf))) {
            cytadel_log_error("nvd_catchup: internal error formatting the current window's start bound");
            return CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK;
        }

        cytadel_instant_t candidate_end = instant_add_days(cursor, window_days);
        cytadel_instant_t window_end =
            (instant_compare(&candidate_end, &now_instant) < 0) ? candidate_end : now_instant;

        char end_buf[CYTADEL_NVD_CATCHUP_TS_BUF_LEN];
        if (!format_instant(&window_end, end_buf, sizeof(end_buf))) {
            cytadel_log_error("nvd_catchup: internal error formatting the current window's end bound");
            return CYTADEL_NVD_CATCHUP_ERR_MALFORMED_WATERMARK;
        }

        cytadel_nvd_sync_counts_t window_counts;
        cytadel_nvd_sync_status_t st =
            cytadel_nvd_sync_window(db, cfg, start_buf, end_buf, 0, &window_counts);
        if (st != CYTADEL_NVD_SYNC_OK) {
            cytadel_log_warn(
                "nvd_catchup: window [%s, %s] failed (%s) -- stopping catch-up; the durable watermark "
                "remains at the last successfully committed window (%zu completed so far)",
                start_buf, end_buf, cytadel_nvd_sync_status_to_string(st), out->windows_completed);
            return CYTADEL_NVD_CATCHUP_ERR_SYNC;
        }

        out->windows_completed++;
        out->pages_fetched += window_counts.pages_fetched;
        out->cve_ingested += window_counts.cve_ingested;
        out->cve_skipped += window_counts.cve_skipped;

        /* Per-window rollup: the cross-window running totals a per-page line
         * (nvd_sync.c) cannot show, so an operator watching a long bulk load
         * sees overall progress advance window by window. */
        cytadel_log_info(
            "nvd_catchup: window %zu committed [%s..%s]: %zu ingested, %zu skipped "
            "(run totals: %zu ingested, %zu skipped across %zu window(s))",
            out->windows_completed, start_buf, end_buf, window_counts.cve_ingested,
            window_counts.cve_skipped, out->cve_ingested, out->cve_skipped, out->windows_completed);

        cursor = window_end;
    }

    return CYTADEL_NVD_CATCHUP_OK;
}
