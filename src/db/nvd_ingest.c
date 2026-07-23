#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/net/target.c
                                 * for the same project-wide convention. Must be defined before
                                 * any header is included. */

#include "cytadel/db/nvd_ingest.h"

#include <cJSON.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <string.h>

#include "cve_id_valid.h"
#include "log.h"

/* Milestone 7 slice 2: see include/cytadel/db/nvd_ingest.h for the full
 * design/contract this file implements. Summary of the hostile-input
 * defenses relied on throughout this file (spelled out once here instead
 * of repeating at every call site):
 *
 *   - Every cJSON_Is*() check happens BEFORE any deref of the value it
 *     guards, and cJSON's own cJSON_GetObjectItemCaseSensitive()/Is*()
 *     family is NULL-safe on both the container and the item (verified
 *     against third_party/cjson/cJSON.c's get_object_item(): a NULL
 *     `object`, or an `object` whose ->child is NULL -- true for every
 *     scalar/wrong-typed node, since cJSON only ever populates ->child for
 *     Array/Object types -- both safely fall through to "field not found"
 *     rather than crashing). This is what lets this file look up e.g.
 *     `cve.metrics.cvssMetricV31` without ever separately re-checking "is
 *     `cve` an object" / "is `metrics` an object" at every intermediate
 *     step: a wrong-typed ancestor anywhere in that chain just makes the
 *     leaf lookup fail closed, which every helper below already treats as
 *     "value absent" and degrades from there.
 *   - A CVE record's three columns that cannot be NULL in the frozen schema
 *     (cve_id, published, last_modified) are validated BEFORE any bind/step
 *     is attempted, with a specific log line per field, and the whole
 *     record is skipped (not just that field defaulted) if any of them is
 *     missing/empty/non-string/oversized -- there is no meaningful "CVE
 *     row" to store at all without them.
 *   - DESIGN CHOICE (flagged per this milestone's task brief -- the hostile-
 *     test brief's wording could be read as wanting a *whole-record* skip
 *     whenever "metrics" or "descriptions" is present-but-wrong-typed;
 *     this file instead treats that identically to the field being
 *     ABSENT: a wrong-typed/absent "descriptions" degrades to
 *     description = "" and a wrong-typed/absent "metrics" degrades to no
 *     CVSS data + severity 0, exactly the fallback behavior this
 *     milestone's own field-by-field spec already spells out ("descriptions
 *     ... else ''"; "metrics (cvssMetricV31[] preferred, else V30, else
 *     V2)"). Rationale: for a vulnerability-scanner's CVE database, silently
 *     discarding an otherwise-good CVE row (valid id/published/
 *     lastModified) over one malformed *optional* field is a worse outcome
 *     (a real coverage gap in the vuln DB) than storing it with a
 *     degraded/default value for that one field. A CVE record is only
 *     skipped outright when its REQUIRED fields (id/published/
 *     lastModified) cannot be recovered -- see the bullet above.
 *   - Every cpeMatch row is independently validated and skipped on its own
 *     (never the whole CVE) for a malformed `criteria` string, an invalid
 *     `part`, or a malformed range configuration (db-schema.md SS3: a
 *     `version = '*'` row with every bound empty).
 *   - CYTADEL_NVD_MAX_CPE_PER_CVE bounds the amount of work done per CVE
 *     regardless of how many cpeMatch entries a hostile page claims to
 *     have; CYTADEL_NVD_MAX_CVES_PER_PAGE below does the same across the
 *     whole page. Neither ever sizes an allocation off an untrusted count
 *     -- both are walked via cJSON's own already-parsed child/next chain,
 *     these are simply "stop doing more work" circuit breakers.
 *   - Every string bound into a TEXT column is clipped to a fixed cap
 *     (clip_into()/clip_into_n() below) rather than rejecting an oversized
 *     value outright, per this module's own header comment and this
 *     milestone's task brief.
 *   - Every sqlite3_step() outcome is classified into exactly one of three
 *     buckets: SQLITE_DONE (success, counted), SQLITE_CONSTRAINT (that one
 *     row is skipped-and-logged, never fatal), or anything else (treated
 *     as a genuinely fatal DB error -- aborts the whole page via ROLLBACK).
 *     This is the same three-way split db-schema.md SS9's writers are
 *     expected to make; it is what makes "one bad row never aborts the
 *     page" a property of the DB-interaction layer itself, not just the
 *     JSON-parsing layer above it.
 *
 * Post-slice-2 security review fixes (security-review round 1 -- 0 Critical,
 * 3 Warnings, applied here):
 *
 *   - W3 (treated as data-integrity CRITICAL): embedded-NUL PK collision on
 *     cve_id. cJSON 1.7.18 faithfully decodes a JSON string containing a
 *     literal null-character escape (Unicode code point U+0000) into a
 *     genuine embedded NUL byte inside valuestring -- e.g. an id field
 *     of "CVE-X" + (a NUL byte) + "A" decodes to the 8 bytes
 *     'C','V','E','-','X','\0','A','\0' with strlen()==5. cJSON's public
 *     cJSON struct carries NO length field
 *     alongside valuestring, so there is no way for this file to "see past"
 *     that embedded NUL to compare a true byte-length against strlen() --
 *     the review's literal phrasing ("reject where cJSON length !=
 *     strlen") is not implementable against this library's public API.
 *     cytadel_is_valid_cve_id() (shared cve_id_valid.h, also used by
 *     kev_ingest.c/epss_ingest.c) implements the INTENT instead, which is
 *     actually stronger: it requires the entire VISIBLE (NUL-terminated)
 *     string to fully match the NVD CVE-ID grammar, ^CVE-[0-9]{4}-[0-9]{4,}$.
 *     A NUL-truncated id like "CVE-X\0A" has a visible portion "CVE-X",
 *     which fails that grammar outright (no 4-digit year), so it is
 *     skipped-and-logged exactly like a missing id -- it never reaches
 *     sqlite3_bind_text() at all, so two differently-suffixed crafted ids
 *     (identical visible prefix, different bytes hidden after their own
 *     embedded NULs) can never collide on the cves.cve_id PRIMARY KEY,
 *     because neither one is ever stored. An id whose *entire* visible
 *     string legitimately matches the grammar is, definitionally, a
 *     complete valid CVE id with nothing hidden after it -- ON CONFLICT
 *     upserting against that id is correct dedup behavior, not a bug. The
 *     existing CYTADEL_NVD_CVE_ID_MAX_LEN oversize check composes correctly
 *     with this: it is still evaluated over the same bounded/visible
 *     strnlen() result (bind_text(-1) itself would only ever store up to
 *     the first NUL regardless), and the grammar additionally rejects any
 *     visually-valid-looking but pathologically long digit run.
 *   - W1: a missing OR present-but-non-array top-level "vulnerabilities"
 *     now returns CYTADEL_NVD_INGEST_ERR_PARSE (no transaction opened, no
 *     watermark change) instead of silently being treated as a valid empty
 *     page -- see nvd_ingest.h's ERR_PARSE doc comment. Only a *present*
 *     JSON array value (including an empty one, `[]`) is a valid page.
 *   - W2: `window_complete` parameter threads through to a conditional
 *     sync_state UPDATE -- see nvd_ingest.h's cytadel_nvd_ingest_page() doc
 *     comment for the full contract. This closes a trap for the future
 *     multi-page fetch-driver slice: without it, ANY successful page of a
 *     multi-page window (not just the last one) would have advanced the
 *     watermark past data the window hadn't finished delivering yet.
 *
 * Suggestions applied:
 *   - CYTADEL_NVD_PAGE_MAX_BYTES: a pre-parse sanity cap on `len` (checked
 *     BEFORE cJSON_ParseWithLength() ever runs) -- fails fast with
 *     ERR_PARSE instead of relying on the allocator's own back-pressure to
 *     eventually reject an absurdly large hostile `len`.
 *   - db_migrations.c's migration COMMIT failure path now issues a
 *     ROLLBACK before returning an error (parity with this file's own
 *     failed-COMMIT handling) -- see db_migrations.c's own comment at that
 *     call site.
 *
 * TODO (flagged for the later M-web report-generation slice, not
 * implemented here): clip_into()/clip_into_n() below clip at a fixed BYTE
 * count, which can split a multi-byte UTF-8 sequence in half (description/
 * vendor/product values are attacker-influenced NVD text). The report layer
 * MUST treat every TEXT column this module writes as untrusted on read --
 * validate/repair-or-drop a trailing partial UTF-8 sequence and HTML-escape
 * before ever rendering it -- rather than assuming DB content is safe to
 * embed verbatim.
 */

/* Security-review suggestion: a pre-parse sanity cap on the raw byte length
 * of a page, checked BEFORE cJSON_ParseWithLength() is ever called. NVD
 * pages at resultsPerPage<=2000 are far smaller than this in practice --
 * this exists purely to fail fast (CYTADEL_NVD_INGEST_ERR_PARSE, no
 * transaction opened) against a hostile/corrupted `len` instead of handing
 * cJSON an arbitrarily large buffer and relying on the allocator's own
 * back-pressure (OOM) to eventually reject it. */
#define CYTADEL_NVD_PAGE_MAX_BYTES (64 * 1024 * 1024)

/* Hard cap on the number of "vulnerabilities" array elements this module
 * will walk for a single page -- NVD's own API caps resultsPerPage at 2000,
 * so this is purely a generous hostile-input safety valve (a page claiming
 * far more than any real NVD response ever would). Kept as an internal
 * #define (unlike CYTADEL_NVD_MAX_CPE_PER_CVE) since no test needs to name
 * it -- the tests exercise the per-CVE CPE cap instead, which is the cap
 * this milestone's task brief explicitly calls out for a dedicated test. */
#define CYTADEL_NVD_MAX_CVES_PER_PAGE 20000

/* Descriptions arrays are per-CVE and per NVD's own schema carry one entry
 * per supported language (typically 1-2, "en" plus occasionally another) --
 * this bounds how many entries this module will scan looking for an "en"
 * entry before falling back to the first valid one seen, purely as a
 * hostile-input safety valve against a page claiming an absurdly long
 * descriptions array. */
#define CYTADEL_NVD_MAX_DESCRIPTIONS 256

#define CYTADEL_NVD_CVE_ID_MAX_LEN 64
/* Raw NVD timestamps look like "2021-12-10T10:15:09.143" (23 bytes); this
 * cap is deliberately generous (2x) so a slightly-longer-than-expected but
 * still plausible timestamp is clipped rather than rejected, while an
 * absurd (hostile) value is still bounded. +2 buffer: the appended 'Z' plus
 * the NUL terminator. */
#define CYTADEL_NVD_TS_MAX_LEN 48
#define CYTADEL_NVD_TS_BUF_LEN (CYTADEL_NVD_TS_MAX_LEN + 2)

#define CYTADEL_NVD_DESC_BUF_LEN (CYTADEL_NVD_DESC_MAX_LEN + 1)

/* Real CVSS vector strings ("CVSS:3.1/AV:N/AC:L/...") are well under 128
 * bytes; 256 leaves headroom without allowing an unbounded value through. */
#define CYTADEL_NVD_VECTOR_MAX_LEN 256
#define CYTADEL_NVD_VECTOR_BUF_LEN (CYTADEL_NVD_VECTOR_MAX_LEN + 1)

/* Longest legal value is "CRITICAL" (8 bytes); this is intentionally tiny
 * so an oversized hostile "baseSeverity" string can never even superficially
 * resemble a legal value -- is_valid_v3_severity()/is_valid_v2_severity()
 * below reject anything that doesn't match a fixed allowlist regardless,
 * this cap just keeps the working buffer itself bounded. */
#define CYTADEL_NVD_SEVERITY_BUF_LEN 16

/* A cpe:2.3 URI ("cpe:2.3:a:vendor:product:version:...") is normally well
 * under 200 bytes even for the longest real dictionary entries; 1024 is
 * generous headroom for a legitimate value while still bounding a hostile
 * one. */
#define CYTADEL_NVD_CPE_URI_MAX_LEN 1024
#define CYTADEL_NVD_CPE_URI_BUF_LEN (CYTADEL_NVD_CPE_URI_MAX_LEN + 1)

#define CYTADEL_NVD_VENDOR_PRODUCT_MAX_LEN 256
#define CYTADEL_NVD_VENDOR_PRODUCT_BUF_LEN (CYTADEL_NVD_VENDOR_PRODUCT_MAX_LEN + 1)

#define CYTADEL_NVD_VERSION_MAX_LEN 128
#define CYTADEL_NVD_VERSION_BUF_LEN (CYTADEL_NVD_VERSION_MAX_LEN + 1)

const char *cytadel_nvd_ingest_status_to_string(cytadel_nvd_ingest_status_t status) {
    switch (status) {
        case CYTADEL_NVD_INGEST_OK:              return "OK";
        case CYTADEL_NVD_INGEST_ERR_INVALID_ARG: return "INVALID_ARG";
        case CYTADEL_NVD_INGEST_ERR_PARSE:       return "PARSE";
        case CYTADEL_NVD_INGEST_ERR_DB:          return "DB";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* Small bounded-copy / cJSON-field-extraction helpers.                */
/* ------------------------------------------------------------------ */

/* Copies at most dst_cap-1 bytes of the NUL-terminated `src` into `dst`,
 * always NUL-terminating `dst`. `dst_cap` must be >= 1. This is a clip, not
 * a rejection -- an oversized `src` is silently truncated (never read past
 * dst_cap-1 bytes of it, via strnlen's own bound, so this is safe even if
 * `src` were somehow not actually NUL-terminated within that many bytes). */
static void clip_into(char *dst, size_t dst_cap, const char *src) {
    size_t n = strnlen(src, dst_cap - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Same as clip_into(), but for a `src` span that is NOT NUL-terminated at
 * `src_len` (e.g. a sub-span of a larger buffer) -- never reads past
 * src_len bytes of `src` regardless of dst_cap. */
static void clip_into_n(char *dst, size_t dst_cap, const char *src, size_t src_len) {
    size_t n = (src_len < dst_cap - 1) ? src_len : (dst_cap - 1);
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Same as clip_into_n(), lowercasing every byte as it copies (ASCII-only --
 * matches db-schema.md's "vendor/product stored lowercase" rule; CPE 2.3
 * component values are themselves ASCII by spec). */
static void clip_lower_into_n(char *dst, size_t dst_cap, const char *src, size_t src_len) {
    size_t n = (src_len < dst_cap - 1) ? src_len : (dst_cap - 1);
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)src[i];
        dst[i] = (char)((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c);
    }
    dst[n] = '\0';
}

/* Looks up obj[key]; true iff present, a JSON string, and its valuestring
 * is non-NULL (cJSON always NUL-terminates valuestring on a successful
 * parse, so callers may safely strlen()/strnlen() *out afterward). `obj`
 * may be NULL (cJSON_GetObjectItemCaseSensitive() is NULL-safe -- see this
 * file's top-of-file comment). */
static bool json_get_string(const cJSON *obj, const char *key, const char **out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return false;
    }
    *out = item->valuestring;
    return true;
}

/* Looks up obj[key]; true iff present and a JSON number. */
static bool json_get_number(const cJSON *obj, const char *key, double *out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsNumber(item)) {
        return false;
    }
    *out = item->valuedouble;
    return true;
}

/* Looks up obj[key]; true iff present and a JSON bool, in which case *out is
 * set to its value. If absent/wrong-typed, *out is left untouched -- callers
 * pre-set *out to the column's own DEFAULT before calling this. */
static bool json_get_bool(const cJSON *obj, const char *key, bool *out) {
    const cJSON *item = cJSON_GetObjectItemCaseSensitive(obj, key);
    if (!cJSON_IsBool(item)) {
        return false;
    }
    *out = cJSON_IsTrue(item) ? true : false;
    return true;
}

/* Normalizes an NVD timestamp: clips `raw` (bounded, never assumes it is
 * short) into `out` and appends a trailing 'Z' if one is not already
 * present -- db-schema.md's binding timestamp convention: "NVD's API
 * returns timestamps without a trailing Z ... the sync writer MUST append
 * Z (NVD timestamps are UTC) before storing." Returns false (leaving *out
 * unspecified) if `raw` is NULL or empty -- an empty string is not a
 * meaningful timestamp and must not silently become just "Z". `out_cap`
 * must be >= CYTADEL_NVD_TS_BUF_LEN. */
static bool normalize_nvd_timestamp(const char *raw, char *out, size_t out_cap) {
    if (raw == NULL) {
        return false;
    }
    size_t raw_len = strnlen(raw, CYTADEL_NVD_TS_MAX_LEN);
    if (raw_len == 0) {
        return false;
    }
    if (out_cap < raw_len + 2) {
        return false; /* caller bug: buffer too small for this file's own constants */
    }
    memcpy(out, raw, raw_len);
    bool has_z = (raw[raw_len - 1] == 'Z' || raw[raw_len - 1] == 'z');
    if (has_z) {
        out[raw_len] = '\0';
    } else {
        out[raw_len] = 'Z';
        out[raw_len + 1] = '\0';
    }
    return true;
}

/* Extracts a CVE's "descriptions" array (kb: [{lang, value}, ...]) into
 * `out`, per this milestone's spec: prefer lang=="en", else the first
 * entry with a valid string value, else "". `descriptions` may be NULL or
 * any wrong type (degrades to "" -- see this file's top-of-file DESIGN
 * CHOICE comment); each element is independently validated and a malformed
 * element is simply skipped (never aborts the scan of the rest of the
 * array). `out_cap` must be >= 1; the result is clipped to out_cap-1 bytes
 * (CYTADEL_NVD_DESC_MAX_LEN in practice), never rejected for being
 * oversized. */
/* TODO(later M-web report-generation slice): the clip_into() call below
 * truncates `value` at a fixed BYTE count (CYTADEL_NVD_DESC_MAX_LEN), which
 * can split a multi-byte UTF-8 sequence in half -- `value` is
 * attacker-influenced NVD text. Not fixed here (out of this slice's
 * scope); the report layer MUST treat this column as untrusted on read and
 * validate/repair-or-drop a trailing partial UTF-8 sequence plus
 * HTML-escape before ever rendering it. */
static void extract_description(const cJSON *cve, char *out, size_t out_cap) {
    out[0] = '\0';
    const cJSON *descriptions = cJSON_GetObjectItemCaseSensitive(cve, "descriptions");
    if (!cJSON_IsArray(descriptions)) {
        return;
    }

    const char *first_value = NULL;
    size_t count = 0;
    for (const cJSON *item = descriptions->child;
         item != NULL && count < CYTADEL_NVD_MAX_DESCRIPTIONS; item = item->next, count++) {
        const char *value = NULL;
        if (!json_get_string(item, "value", &value)) {
            continue; /* malformed entry -- skip it, keep scanning the rest */
        }
        if (first_value == NULL) {
            first_value = value;
        }
        const char *lang = NULL;
        if (json_get_string(item, "lang", &lang) && strcmp(lang, "en") == 0) {
            clip_into(out, out_cap, value);
            return;
        }
    }
    if (first_value != NULL) {
        clip_into(out, out_cap, first_value);
    }
}

typedef struct {
    char vector[CYTADEL_NVD_VECTOR_BUF_LEN];
    bool has_vector;
    double base_score;
    bool has_score;
    char severity[CYTADEL_NVD_SEVERITY_BUF_LEN];
    bool has_severity;
} cytadel_nvd_cvss_t;

/* Extracts cvssData.{vectorString,baseScore,baseSeverity} from the first
 * element of `metrics[metric_key]` (a CVE's "metrics.cvssMetricV31" etc.).
 * `metrics` may be NULL/wrong-typed, the named array may be absent/empty/
 * wrong-typed, its first element may be wrong-typed, "cvssData" may be
 * absent/wrong-typed -- every one of those degrades to "no data found"
 * (returns false, *out all-false/zeroed) rather than being treated as an
 * error; this is the exact "cve.metrics is a string" / "cve.metrics is an
 * object but cvssMetricV31 is missing" hostile-input class, handled purely
 * by cJSON's own NULL-safe lookups (see this file's top-of-file comment).
 * `baseScore` is only accepted in [0, 10] (matches the cves table's own
 * CHECK constraint) -- an out-of-range or non-finite hostile value (a
 * "1e400"-style JSON literal that overflows double parsing to +/-inf, or a
 * negative score) is treated as "no score", not stored, rather than
 * poisoning the whole CVE row via a CHECK-constraint failure at insert
 * time. Returns true iff at least one of vector/score/severity was found. */
static bool extract_first_cvss(const cJSON *metrics, const char *metric_key, cytadel_nvd_cvss_t *out) {
    memset(out, 0, sizeof(*out));

    const cJSON *arr = cJSON_GetObjectItemCaseSensitive(metrics, metric_key);
    if (!cJSON_IsArray(arr) || arr->child == NULL) {
        return false;
    }
    const cJSON *first = arr->child;
    const cJSON *cvss_data = cJSON_GetObjectItemCaseSensitive(first, "cvssData");

    const char *vector = NULL;
    if (json_get_string(cvss_data, "vectorString", &vector) && vector[0] != '\0') {
        clip_into(out->vector, sizeof(out->vector), vector);
        out->has_vector = true;
    }

    double score = 0.0;
    if (json_get_number(cvss_data, "baseScore", &score) && score >= 0.0 && score <= 10.0) {
        out->base_score = score;
        out->has_score = true;
    }

    const char *severity = NULL;
    if (json_get_string(cvss_data, "baseSeverity", &severity) && severity[0] != '\0') {
        clip_into(out->severity, sizeof(out->severity), severity);
        out->has_severity = true;
    }

    return out->has_vector || out->has_score || out->has_severity;
}

static bool is_valid_v3_severity(const char *s) {
    static const char *const allowed[] = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"};
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strcmp(s, allowed[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool is_valid_v2_severity(const char *s) {
    static const char *const allowed[] = {"LOW", "MEDIUM", "HIGH"};
    for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) {
        if (strcmp(s, allowed[i]) == 0) {
            return true;
        }
    }
    return false;
}

/* Security-review W3 fix: strictly validates `id` against the NVD CVE-ID
 * grammar, ^CVE-[0-9]{4}-[0-9]{4,}$ ("CVE-", exactly 4 digits, '-', then 4
 * or more digits, and NOTHING else) -- evaluated over strlen(id), i.e. the
 * VISIBLE, NUL-terminated string cJSON exposes. See this file's top-of-file
 * "W3" comment for why this (not a byte-length comparison, which cJSON's
 * public API cannot support at all) is what closes the embedded-NUL
 * cve_id PK-collision hole: an id with hidden bytes after an embedded NUL
 * has a visible prefix that will virtually never itself be a complete,
 * grammar-conforming CVE id, so it fails here and is never stored.
 *
 * This check itself now lives in the shared cve_id_valid.h
 * (cytadel_is_valid_cve_id()), not as a file-static function here -- the
 * KEV/EPSS ingest slice's own task brief required ONE shared definition
 * (not a second, independently-hand-rolled grammar check) since a bad KEV/
 * EPSS cve_id becomes an FK into the very same cves.cve_id PRIMARY KEY this
 * check protects. See that header's own comment for the full rationale;
 * this file, kev_ingest.c, and epss_ingest.c all call the one
 * implementation there. */

/* db-schema.md SS2's "Severity normalization rule" table, reproduced
 * verbatim as executable buckets -- this is a CONTRACT-specified mapping
 * (db-schema.md lines defining the 0-4 severity scale from the CVSS v3/v2
 * base score), not this module's own invention: it is applied to the
 * numeric baseScore, independent of (and more precise than) the separate
 * cvss_v3_severity/cvss_v2_severity TEXT columns' own "baseSeverity" string
 * (which is stored verbatim, when it validates against its own allowlist,
 * purely for display/audit -- the *ordinal* `severity` column below is
 * always derived from the score, per the contract). */
static int severity_from_v3_score(double score) {
    if (score <= 0.0) return 0;
    if (score < 4.0) return 1;
    if (score < 7.0) return 2;
    if (score < 9.0) return 3;
    return 4;
}

/* Same table's v2-only column ("CVSS v2 has no Critical tier"). */
static int severity_from_v2_score(double score) {
    if (score <= 0.0) return 0;
    if (score < 4.0) return 1;
    if (score < 7.0) return 2;
    return 3;
}

/* Returns the [start, start+len) span of the `field_index`'th (0-based)
 * colon-delimited field of `s[0, len)` -- used to split a cpe:2.3 URI
 * ("cpe:2.3:part:vendor:product:version:...") into its components without
 * ever allocating or requiring NUL-termination at any particular offset.
 * Returns false if `s` has fewer than field_index+1 colon-delimited fields
 * (a truncated/malformed criteria string) -- the caller must treat that as
 * "skip this cpe row", not a crash.
 *
 * Simplification (flagged): this does a plain split on ':' with no
 * backslash-escape handling for a literal colon inside a component value.
 * The CPE 2.3 formatted-string spec allows escaping special characters
 * (including ':') with a backslash inside vendor/product/etc, but NVD's
 * own generated criteria strings essentially never contain one in
 * practice, and this module's job is defensive parsing (never crash, never
 * misattribute a field), not full CPE-2.3-spec-compliant unescaping --
 * that concern already lives with the version-comparison code db-schema.md
 * SS3 describes as a separate shared component. A criteria string with a
 * genuinely escaped colon would simply split "early" here and most likely
 * fail the `part` validation below, causing that one cpe row to be
 * skipped-and-logged like any other malformed criteria -- never a crash,
 * never corruption of any other row. */
static bool cpe23_field(const char *s, size_t len, int field_index, size_t *out_start, size_t *out_len) {
    int current = 0;
    size_t start = 0;
    for (size_t i = 0; i <= len; i++) {
        if (i == len || s[i] == ':') {
            if (current == field_index) {
                *out_start = start;
                *out_len = i - start;
                return true;
            }
            current++;
            start = i + 1;
        }
    }
    return false;
}

/* ------------------------------------------------------------------ */
/* Prepared-statement plumbing.                                       */
/* ------------------------------------------------------------------ */

/* db-schema.md SS9's "CVE upsert (NVD sync, per page)" query, reproduced
 * verbatim (parameter order/count unchanged) -- FROZEN CONTRACT text, do
 * not edit without a stop-and-ask per project policy. */
static const char *const CYTADEL_NVD_CVE_UPSERT_SQL =
    "INSERT INTO cves (cve_id, published, last_modified, description, "
    "cvss_v3_vector, cvss_v3_base_score, cvss_v3_severity, "
    "cvss_v2_vector, cvss_v2_base_score, cvss_v2_severity, "
    "severity, source, ingested_at) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'nvd', strftime('%Y-%m-%dT%H:%M:%fZ','now')) "
    "ON CONFLICT (cve_id) DO UPDATE SET "
    "last_modified = excluded.last_modified, "
    "description = excluded.description, "
    "cvss_v3_vector = excluded.cvss_v3_vector, "
    "cvss_v3_base_score = excluded.cvss_v3_base_score, "
    "cvss_v3_severity = excluded.cvss_v3_severity, "
    "cvss_v2_vector = excluded.cvss_v2_vector, "
    "cvss_v2_base_score = excluded.cvss_v2_base_score, "
    "cvss_v2_severity = excluded.cvss_v2_severity, "
    "severity = excluded.severity, "
    "source = 'nvd', "
    "ingested_at = excluded.ingested_at;";

/* db-schema.md SS9's "CPE match row upsert", reproduced verbatim. */
static const char *const CYTADEL_NVD_CPE_UPSERT_SQL =
    "INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, version, "
    "version_start_including, version_start_excluding, "
    "version_end_including, version_end_excluding, vulnerable) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
    "ON CONFLICT (cve_id, cpe23_uri, version_start_including, version_start_excluding, "
    "version_end_including, version_end_excluding, vulnerable) DO NOTHING;";

/* Not part of db-schema.md SS9's illustrative query list (that section
 * documents the cves/cve_cpe_matches upserts verbatim; sync_state's own
 * update is only described procedurally, in SS8 step 5) -- these are this
 * module's own parameterized statements implementing that documented
 * procedure, only ever reached from inside the same transaction as the
 * page's own data (see cytadel_nvd_ingest_page()).
 *
 * Security-review W2 fix: TWO variants, selected by `window_complete`
 * (see nvd_ingest.h's cytadel_nvd_ingest_page() doc comment for the full
 * contract) -- exactly one of the two is ever prepared/used per call:
 *
 *   - "COMPLETE" (window_complete == true, the final page of a window):
 *     advances last_mod_watermark, marks status='success'. Two bound
 *     parameters: (1) lastmod_end_date, (2) this page's record count.
 *   - "PARTIAL" (window_complete == false, an earlier page of a
 *     multi-page window): deliberately does NOT touch last_mod_watermark
 *     at all (not even in the SET clause), and marks status='running'
 *     instead of 'success' -- so a crash after this page (but before the
 *     window's final page) leaves the watermark exactly where it was
 *     before the window started, and the next run safely re-fetches and
 *     re-ingests the WHOLE window (idempotent via the ON CONFLICT upserts
 *     above). One bound parameter: (1) this page's record count. */
static const char *const CYTADEL_NVD_SYNC_STATE_COMPLETE_SQL =
    "UPDATE sync_state SET "
    "last_mod_watermark = ?, "
    "last_sync_completed = strftime('%Y-%m-%dT%H:%M:%fZ','now'), "
    "total_records = total_records + ?, "
    "status = 'success', "
    "last_error = NULL "
    "WHERE feed = 'nvd';";

static const char *const CYTADEL_NVD_SYNC_STATE_PARTIAL_SQL =
    "UPDATE sync_state SET "
    "total_records = total_records + ?, "
    "status = 'running', "
    "last_error = NULL "
    "WHERE feed = 'nvd';";

/* Runs `sql` (fixed, non-parameterized -- BEGIN/ROLLBACK/COMMIT only) via
 * sqlite3_exec(), logging sqlite3's error text on failure. Mirrors
 * db_migrations.c's own (file-static, not exported) cytadel_db_exec()
 * helper -- kept as a separate static copy in this translation unit rather
 * than sharing one across the two .c files, since neither helper is part
 * of either module's public surface. */
static int cytadel_nvd_exec(sqlite3 *handle, const char *sql, const char *context) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(handle, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: %s failed (sqlite rc=%d): %s", context, rc,
                           errmsg ? errmsg : "(no message)");
        sqlite3_free(errmsg);
    }
    return rc;
}

static int prepare_statements(sqlite3 *handle, bool window_complete, sqlite3_stmt **cve_stmt,
                               sqlite3_stmt **cpe_stmt, sqlite3_stmt **sync_stmt) {
    int rc = sqlite3_prepare_v2(handle, CYTADEL_NVD_CVE_UPSERT_SQL, -1, cve_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: preparing cves upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    rc = sqlite3_prepare_v2(handle, CYTADEL_NVD_CPE_UPSERT_SQL, -1, cpe_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: preparing cve_cpe_matches upsert failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    const char *sync_sql =
        window_complete ? CYTADEL_NVD_SYNC_STATE_COMPLETE_SQL : CYTADEL_NVD_SYNC_STATE_PARTIAL_SQL;
    rc = sqlite3_prepare_v2(handle, sync_sql, -1, sync_stmt, NULL);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: preparing sync_state update failed (sqlite rc=%d): %s", rc,
                           sqlite3_errmsg(handle));
        return rc;
    }
    return SQLITE_OK;
}

/* sqlite3_finalize(NULL) is a documented no-op -- safe to call on any of
 * these even if an earlier prepare in the same call failed and left a
 * later one NULL. */
static void finalize_all(sqlite3_stmt *cve_stmt, sqlite3_stmt *cpe_stmt, sqlite3_stmt *sync_stmt) {
    sqlite3_finalize(cve_stmt);
    sqlite3_finalize(cpe_stmt);
    sqlite3_finalize(sync_stmt);
}

/* ------------------------------------------------------------------ */
/* Per-cpeMatch-row and per-CVE processing.                            */
/* ------------------------------------------------------------------ */

static void process_one_cpe_match(sqlite3_stmt *stmt, const char *cve_id, const cJSON *m,
                                   cytadel_nvd_ingest_counts_t *counts, bool *fatal_db_error) {
    const char *criteria = NULL;
    if (!json_get_string(m, "criteria", &criteria) || criteria[0] == '\0') {
        cytadel_log_debug("nvd_ingest: %s: cpeMatch missing/empty 'criteria' -- skipping this cpe row",
                           cve_id);
        counts->cpe_skipped++;
        return;
    }

    char cpe_buf[CYTADEL_NVD_CPE_URI_BUF_LEN];
    clip_into(cpe_buf, sizeof(cpe_buf), criteria);
    size_t cpe_len = strlen(cpe_buf);

    size_t part_start = 0, part_len = 0;
    size_t vendor_start = 0, vendor_len = 0;
    size_t product_start = 0, product_len = 0;
    size_t version_start = 0, version_len = 0;
    if (!cpe23_field(cpe_buf, cpe_len, 2, &part_start, &part_len) ||
        !cpe23_field(cpe_buf, cpe_len, 3, &vendor_start, &vendor_len) ||
        !cpe23_field(cpe_buf, cpe_len, 4, &product_start, &product_len) ||
        !cpe23_field(cpe_buf, cpe_len, 5, &version_start, &version_len)) {
        cytadel_log_debug("nvd_ingest: %s: malformed cpe23 criteria (too few colon-delimited fields): %s",
                           cve_id, cpe_buf);
        counts->cpe_skipped++;
        return;
    }

    char part_ch = (part_len == 1) ? cpe_buf[part_start] : '\0';
    if (part_ch != 'a' && part_ch != 'o' && part_ch != 'h') {
        cytadel_log_debug(
            "nvd_ingest: %s: malformed cpe23 'part' component (must be exactly one of a/o/h): %s", cve_id,
            cpe_buf);
        counts->cpe_skipped++;
        return;
    }
    if (vendor_len == 0 || product_len == 0) {
        cytadel_log_debug("nvd_ingest: %s: empty vendor/product component in cpe23 criteria: %s", cve_id,
                           cpe_buf);
        counts->cpe_skipped++;
        return;
    }

    char part_str[2] = {part_ch, '\0'};
    /* TODO(later M-web report-generation slice): same fixed-byte-clip
     * caveat as extract_description() above applies to vendor_buf/
     * product_buf -- a multi-byte UTF-8 sequence in an attacker-influenced
     * CPE vendor/product component can be split in half by
     * clip_lower_into_n()'s byte-count truncation. The report layer must
     * treat these columns as untrusted on read for the same reason. */
    char vendor_buf[CYTADEL_NVD_VENDOR_PRODUCT_BUF_LEN];
    clip_lower_into_n(vendor_buf, sizeof(vendor_buf), cpe_buf + vendor_start, vendor_len);
    char product_buf[CYTADEL_NVD_VENDOR_PRODUCT_BUF_LEN];
    clip_lower_into_n(product_buf, sizeof(product_buf), cpe_buf + product_start, product_len);
    char version_buf[CYTADEL_NVD_VERSION_BUF_LEN];
    clip_into_n(version_buf, sizeof(version_buf), cpe_buf + version_start, version_len);

    char vsi[CYTADEL_NVD_VERSION_BUF_LEN] = "";
    char vse[CYTADEL_NVD_VERSION_BUF_LEN] = "";
    char vei[CYTADEL_NVD_VERSION_BUF_LEN] = "";
    char vee[CYTADEL_NVD_VERSION_BUF_LEN] = "";
    const char *tmp = NULL;
    if (json_get_string(m, "versionStartIncluding", &tmp)) clip_into(vsi, sizeof(vsi), tmp);
    if (json_get_string(m, "versionStartExcluding", &tmp)) clip_into(vse, sizeof(vse), tmp);
    if (json_get_string(m, "versionEndIncluding", &tmp)) clip_into(vei, sizeof(vei), tmp);
    if (json_get_string(m, "versionEndExcluding", &tmp)) clip_into(vee, sizeof(vee), tmp);

    /* db-schema.md SS3's "Version-range matching approach": a range row
     * (version == '*') with every bound empty is malformed -- NVD always
     * supplies at least one bound for a genuine range match -- and "the
     * sync writer must reject/flag such a configuration node at ingest
     * time rather than let it silently match every version ever
     * detected." */
    bool is_wildcard_version = (strcmp(version_buf, "*") == 0);
    bool any_bound_set = (vsi[0] != '\0' || vse[0] != '\0' || vei[0] != '\0' || vee[0] != '\0');
    if (is_wildcard_version && !any_bound_set) {
        cytadel_log_debug(
            "nvd_ingest: %s: cpe23 range row has version='*' with no version bound set -- malformed "
            "configuration node (db-schema.md SS3), skipping this cpe row: %s",
            cve_id, cpe_buf);
        counts->cpe_skipped++;
        return;
    }

    bool vulnerable = true; /* matches the column's own DEFAULT 1 when absent/wrong-typed */
    (void)json_get_bool(m, "vulnerable", &vulnerable);

    sqlite3_reset(stmt);
    sqlite3_clear_bindings(stmt);
    int rc = sqlite3_bind_text(stmt, 1, cve_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 2, cpe_buf, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 3, part_str, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 4, vendor_buf, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 5, product_buf, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 6, version_buf, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 7, vsi, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 8, vse, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 9, vei, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(stmt, 10, vee, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(stmt, 11, vulnerable ? 1 : 0);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: %s: binding cve_cpe_matches upsert failed (sqlite rc=%d): %s", cve_id,
                           rc, sqlite3_errmsg(sqlite3_db_handle(stmt)));
        counts->cpe_skipped++;
        return;
    }

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_DONE) {
        counts->cpe_ingested++;
    } else if (rc == SQLITE_CONSTRAINT) {
        cytadel_log_debug(
            "nvd_ingest: %s: cpe row rejected by a CHECK/UNIQUE/FK constraint -- skipping this cpe row: %s",
            cve_id, cpe_buf);
        counts->cpe_skipped++;
    } else {
        cytadel_log_error("nvd_ingest: %s: fatal sqlite error inserting cpe row (sqlite rc=%d): %s", cve_id,
                           rc, sqlite3_errmsg(sqlite3_db_handle(stmt)));
        *fatal_db_error = true;
    }
}

/* Walks one "configurations[].nodes[]" entry's own "cpeMatch" array
 * (db-schema.md/this milestone's spec: "configurations (array).nodes[].
 * cpeMatch[]" -- each top-level "configurations" element is itself a
 * config object carrying a "nodes" array, and each node carries its own
 * "cpeMatch" array; see process_one_cve() below for the outer two levels
 * of that walk). `*remaining_budget` is shared across every node of the
 * same CVE (CYTADEL_NVD_MAX_CPE_PER_CVE total) and decremented for every
 * cpeMatch entry looked at, whether it is ultimately ingested or skipped --
 * this is what bounds the total *work* done per CVE regardless of how many
 * entries a hostile page claims. */
static void process_cpe_node(sqlite3_stmt *cpe_stmt, const char *cve_id, const cJSON *node,
                              size_t *remaining_budget, cytadel_nvd_ingest_counts_t *counts,
                              bool *fatal_db_error) {
    const cJSON *matches = cJSON_GetObjectItemCaseSensitive(node, "cpeMatch");
    if (!cJSON_IsArray(matches)) {
        return; /* no cpe rows contributed by this node -- not an error */
    }

    for (const cJSON *m = matches->child; m != NULL; m = m->next) {
        if (*remaining_budget == 0) {
            /* Cap already hit (logged once, below, at the exact moment it
             * was reached) -- every further entry, in this node or any
             * later node/config for the same CVE, is counted as skipped
             * without re-logging per row (a hostile page can claim
             * thousands of these; one log line is enough). */
            counts->cpe_skipped++;
            continue;
        }
        (*remaining_budget)--;
        if (*remaining_budget == 0) {
            cytadel_log_debug(
                "nvd_ingest: %s: cpeMatch cap (%d) reached -- remaining entries in this CVE's "
                "configurations are skipped",
                cve_id, CYTADEL_NVD_MAX_CPE_PER_CVE);
        }

        if (!cJSON_IsObject(m)) {
            counts->cpe_skipped++;
            continue;
        }
        process_one_cpe_match(cpe_stmt, cve_id, m, counts, fatal_db_error);
        if (*fatal_db_error) {
            return;
        }
    }
}

/* Processes one "vulnerabilities[]" element: validates/binds/steps the
 * cves upsert, then (only if that succeeded) walks its "configurations"
 * for cve_cpe_matches rows. Never lets a malformed element's absence of a
 * "cve" object, or a wrong-typed elem itself, crash -- every lookup below
 * cascades through cJSON's own NULL-safe accessors (see top-of-file
 * comment) down to the "cve.id missing" skip path. */
static void process_one_cve(sqlite3_stmt *cve_stmt, sqlite3_stmt *cpe_stmt, const cJSON *elem,
                             cytadel_nvd_ingest_counts_t *counts, bool *fatal_db_error) {
    const cJSON *cve = cJSON_GetObjectItemCaseSensitive(elem, "cve");

    const char *id = NULL;
    if (!json_get_string(cve, "id", &id) || id[0] == '\0' ||
        strnlen(id, CYTADEL_NVD_CVE_ID_MAX_LEN + 1) > CYTADEL_NVD_CVE_ID_MAX_LEN ||
        !cytadel_is_valid_cve_id(id)) {
        /* Security-review W3: cytadel_is_valid_cve_id() (shared
         * cve_id_valid.h) rejects anything whose VISIBLE (NUL-terminated)
         * content does not fully match ^CVE-[0-9]{4}-[0-9]{4,}$ -- this is
         * what catches an
         * embedded-NUL-truncated id (e.g. "CVE-X" + NUL + garbage, whose
         * visible prefix "CVE-X" is not a complete CVE id) before it ever
         * reaches sqlite3_bind_text(), closing the PK-collision hole two
         * such crafted ids would otherwise open. See this file's
         * top-of-file "W3" comment for the full explanation. */
        cytadel_log_warn(
            "nvd_ingest: <no id>: 'cve.id' is missing/empty/non-string/oversized/malformed (does not "
            "fully match ^CVE-[0-9]{4}-[0-9]{4,}$ over its visible length), or 'cve' itself is missing "
            "or not an object -- skipping this record");
        counts->cve_skipped++;
        return;
    }
    char cve_id[CYTADEL_NVD_CVE_ID_MAX_LEN + 1];
    clip_into(cve_id, sizeof(cve_id), id);

    const char *published_raw = NULL;
    char published[CYTADEL_NVD_TS_BUF_LEN];
    if (!json_get_string(cve, "published", &published_raw) ||
        !normalize_nvd_timestamp(published_raw, published, sizeof(published))) {
        cytadel_log_warn("nvd_ingest: %s: 'published' is missing/empty/non-string -- skipping this record",
                          cve_id);
        counts->cve_skipped++;
        return;
    }

    const char *last_modified_raw = NULL;
    char last_modified[CYTADEL_NVD_TS_BUF_LEN];
    if (!json_get_string(cve, "lastModified", &last_modified_raw) ||
        !normalize_nvd_timestamp(last_modified_raw, last_modified, sizeof(last_modified))) {
        cytadel_log_warn(
            "nvd_ingest: %s: 'lastModified' is missing/empty/non-string -- skipping this record", cve_id);
        counts->cve_skipped++;
        return;
    }

    char description[CYTADEL_NVD_DESC_BUF_LEN];
    extract_description(cve, description, sizeof(description));

    const cJSON *metrics = cJSON_GetObjectItemCaseSensitive(cve, "metrics");
    cytadel_nvd_cvss_t v3 = {0};
    bool have_v3 = extract_first_cvss(metrics, "cvssMetricV31", &v3);
    if (!have_v3) {
        have_v3 = extract_first_cvss(metrics, "cvssMetricV30", &v3);
    }
    cytadel_nvd_cvss_t v2 = {0};
    bool have_v2 = extract_first_cvss(metrics, "cvssMetricV2", &v2);

    int severity = 0;
    if (have_v3 && v3.has_score) {
        severity = severity_from_v3_score(v3.base_score);
    } else if (have_v2 && v2.has_score) {
        severity = severity_from_v2_score(v2.base_score);
    }

    sqlite3_reset(cve_stmt);
    sqlite3_clear_bindings(cve_stmt);
    int rc = sqlite3_bind_text(cve_stmt, 1, cve_id, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(cve_stmt, 2, published, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(cve_stmt, 3, last_modified, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) rc = sqlite3_bind_text(cve_stmt, 4, description, -1, SQLITE_TRANSIENT);
    if (rc == SQLITE_OK) {
        rc = (have_v3 && v3.has_vector) ? sqlite3_bind_text(cve_stmt, 5, v3.vector, -1, SQLITE_TRANSIENT)
                                         : sqlite3_bind_null(cve_stmt, 5);
    }
    if (rc == SQLITE_OK) {
        rc = (have_v3 && v3.has_score) ? sqlite3_bind_double(cve_stmt, 6, v3.base_score)
                                        : sqlite3_bind_null(cve_stmt, 6);
    }
    if (rc == SQLITE_OK) {
        rc = (have_v3 && v3.has_severity && is_valid_v3_severity(v3.severity))
                 ? sqlite3_bind_text(cve_stmt, 7, v3.severity, -1, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(cve_stmt, 7);
    }
    if (rc == SQLITE_OK) {
        rc = (have_v2 && v2.has_vector) ? sqlite3_bind_text(cve_stmt, 8, v2.vector, -1, SQLITE_TRANSIENT)
                                         : sqlite3_bind_null(cve_stmt, 8);
    }
    if (rc == SQLITE_OK) {
        rc = (have_v2 && v2.has_score) ? sqlite3_bind_double(cve_stmt, 9, v2.base_score)
                                        : sqlite3_bind_null(cve_stmt, 9);
    }
    if (rc == SQLITE_OK) {
        rc = (have_v2 && v2.has_severity && is_valid_v2_severity(v2.severity))
                 ? sqlite3_bind_text(cve_stmt, 10, v2.severity, -1, SQLITE_TRANSIENT)
                 : sqlite3_bind_null(cve_stmt, 10);
    }
    if (rc == SQLITE_OK) rc = sqlite3_bind_int(cve_stmt, 11, severity);
    if (rc != SQLITE_OK) {
        cytadel_log_error("nvd_ingest: %s: binding cves upsert failed (sqlite rc=%d): %s", cve_id, rc,
                           sqlite3_errmsg(sqlite3_db_handle(cve_stmt)));
        counts->cve_skipped++;
        return;
    }

    rc = sqlite3_step(cve_stmt);
    if (rc == SQLITE_CONSTRAINT) {
        cytadel_log_warn("nvd_ingest: %s: cves upsert rejected by a CHECK constraint -- skipping this record",
                          cve_id);
        counts->cve_skipped++;
        return;
    }
    if (rc != SQLITE_DONE) {
        cytadel_log_error("nvd_ingest: %s: fatal sqlite error upserting cves row (sqlite rc=%d): %s", cve_id,
                           rc, sqlite3_errmsg(sqlite3_db_handle(cve_stmt)));
        *fatal_db_error = true;
        return;
    }
    counts->cve_ingested++;

    const cJSON *configurations = cJSON_GetObjectItemCaseSensitive(cve, "configurations");
    if (!cJSON_IsArray(configurations)) {
        return; /* no cpe rows for this CVE -- not an error */
    }

    /* Two levels of nesting per this milestone's spec: "configurations
     * (array).nodes[].cpeMatch[]" -- each "configurations" element is a
     * config object carrying its own "nodes" array, and each node carries
     * the actual "cpeMatch" array process_cpe_node() walks. A malformed/
     * wrong-typed config or node is skipped on its own (cJSON_IsArray()/
     * cJSON_IsObject() below fail closed to "no cpe rows from this one"),
     * never aborting the scan of this CVE's other configs/nodes. */
    size_t remaining_budget = CYTADEL_NVD_MAX_CPE_PER_CVE;
    for (const cJSON *config = configurations->child; config != NULL; config = config->next) {
        const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(config, "nodes");
        if (!cJSON_IsArray(nodes)) {
            continue;
        }
        for (const cJSON *node = nodes->child; node != NULL; node = node->next) {
            if (!cJSON_IsObject(node)) {
                continue;
            }
            process_cpe_node(cpe_stmt, cve_id, node, &remaining_budget, counts, fatal_db_error);
            if (*fatal_db_error) {
                return;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* Public entry point.                                                 */
/* ------------------------------------------------------------------ */

cytadel_nvd_ingest_status_t cytadel_nvd_ingest_page(cytadel_db_t *db, const char *json_bytes, size_t len,
                                                     const char *lastmod_end_date, bool window_complete,
                                                     cytadel_nvd_ingest_counts_t *out_counts) {
    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
    }
    if (db == NULL || json_bytes == NULL || lastmod_end_date == NULL || lastmod_end_date[0] == '\0' ||
        out_counts == NULL) {
        cytadel_log_error(
            "nvd_ingest: ingest_page() called with a NULL db/json_bytes/out_counts, or an empty "
            "lastmod_end_date");
        return CYTADEL_NVD_INGEST_ERR_INVALID_ARG;
    }

    /* Security-review suggestion: fail fast against a hostile/corrupted
     * `len` BEFORE handing it to cJSON at all, rather than relying on the
     * allocator's own back-pressure (OOM) to eventually reject it. Checked
     * before any transaction is opened, same as every other ERR_PARSE path
     * below -- sync_state cannot be perturbed. */
    if (len > CYTADEL_NVD_PAGE_MAX_BYTES) {
        cytadel_log_error(
            "nvd_ingest: page length %zu exceeds the %d-byte sanity cap -- rejecting without parsing; no "
            "data was written and sync_state is unchanged",
            len, CYTADEL_NVD_PAGE_MAX_BYTES);
        return CYTADEL_NVD_INGEST_ERR_PARSE;
    }

    /* Parsed BEFORE any transaction is opened -- a truncated/malformed
     * document never touches the DB at all, so sync_state cannot possibly
     * be perturbed by this call in that case (project policy / this milestone's
     * "a crash mid-sync re-runs the same window instead of skipping it",
     * applied here to "a parse failure" rather than a crash). */
    cJSON *root = cJSON_ParseWithLength(json_bytes, len);
    if (root == NULL) {
        cytadel_log_error(
            "nvd_ingest: cJSON_ParseWithLength() failed to parse this page (truncated or invalid JSON) -- "
            "rejecting the whole page; no data was written and sync_state is unchanged");
        return CYTADEL_NVD_INGEST_ERR_PARSE;
    }
    if (!cJSON_IsObject(root)) {
        cytadel_log_error(
            "nvd_ingest: top-level NVD document is not a JSON object -- rejecting the whole page; no data "
            "was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_PARSE;
    }

    const char *format = NULL;
    if (json_get_string(root, "format", &format) && strcmp(format, "NVD_CVE") != 0) {
        cytadel_log_warn("nvd_ingest: unexpected top-level 'format' value (expected 'NVD_CVE') -- "
                          "continuing anyway, this is not fatal");
    }

    /* Security-review W1 fix: a missing OR present-but-wrong-typed
     * "vulnerabilities" key is now a rejected (ERR_PARSE) page, not a
     * silently-accepted empty one -- see nvd_ingest.h's ERR_PARSE doc
     * comment for the full rationale. Only a *present* JSON array value is
     * valid (an empty array, `[]`, is a legitimately empty page and still
     * CYTADEL_NVD_INGEST_OK -- the per-element loop below simply does
     * nothing for it). No transaction is opened for the rejected case. */
    const cJSON *vulnerabilities = cJSON_GetObjectItemCaseSensitive(root, "vulnerabilities");
    if (!cJSON_IsArray(vulnerabilities)) {
        cytadel_log_error(
            "nvd_ingest: top-level 'vulnerabilities' is missing or not an array -- rejecting the whole "
            "page; no data was written and sync_state is unchanged");
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_PARSE;
    }

    sqlite3 *handle = cytadel_db_handle(db);

    if (cytadel_nvd_exec(handle, "BEGIN;", "starting nvd_ingest transaction") != SQLITE_OK) {
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_DB;
    }

    sqlite3_stmt *cve_stmt = NULL;
    sqlite3_stmt *cpe_stmt = NULL;
    sqlite3_stmt *sync_stmt = NULL;
    if (prepare_statements(handle, window_complete, &cve_stmt, &cpe_stmt, &sync_stmt) != SQLITE_OK) {
        finalize_all(cve_stmt, cpe_stmt, sync_stmt);
        (void)cytadel_nvd_exec(handle, "ROLLBACK;", "rolling back after a prepare failure");
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_DB;
    }

    bool fatal_db_error = false;

    /* `vulnerabilities` is guaranteed to be a JSON array at this point (the
     * W1 check above already rejected the whole page with ERR_PARSE
     * otherwise) -- an empty array (`child == NULL`) is a legitimately
     * empty page and the loop below simply does nothing. */
    {
        size_t processed = 0;
        const cJSON *elem = vulnerabilities->child;
        for (; elem != NULL && processed < CYTADEL_NVD_MAX_CVES_PER_PAGE; elem = elem->next, processed++) {
            process_one_cve(cve_stmt, cpe_stmt, elem, out_counts, &fatal_db_error);
            if (fatal_db_error) {
                break;
            }
        }
        if (!fatal_db_error && processed >= CYTADEL_NVD_MAX_CVES_PER_PAGE && elem != NULL) {
            cytadel_log_warn(
                "nvd_ingest: page exceeds %d CVE entries -- remaining entries in this page were not "
                "processed (hostile/oversized page)",
                CYTADEL_NVD_MAX_CVES_PER_PAGE);
            /* Every remaining element is counted as skipped (a cheap
             * linked-list walk, not re-parsing) so cve_ingested+cve_skipped
             * always equals the number of elements actually present in
             * this page's "vulnerabilities" array -- consistent with the
             * per-CVE CPE cap's own accounting above. */
            for (; elem != NULL; elem = elem->next) {
                out_counts->cve_skipped++;
            }
        }
    }

    if (!fatal_db_error) {
        /* Security-review W2: which statement was prepared (see
         * prepare_statements() above) already matches `window_complete`;
         * only the bind-parameter *count* and positions differ between the
         * two SQL variants (CYTADEL_NVD_SYNC_STATE_COMPLETE_SQL has
         * lastmod_end_date at position 1 and the record-count delta at
         * position 2; CYTADEL_NVD_SYNC_STATE_PARTIAL_SQL has only the
         * record-count delta, at position 1 -- it deliberately has no
         * lastmod_end_date parameter at all, since it never touches
         * last_mod_watermark). */
        sqlite3_int64 records_seen =
            (sqlite3_int64)(out_counts->cve_ingested + out_counts->cve_skipped);
        int rc;
        if (window_complete) {
            rc = sqlite3_bind_text(sync_stmt, 1, lastmod_end_date, -1, SQLITE_TRANSIENT);
            if (rc == SQLITE_OK) {
                rc = sqlite3_bind_int64(sync_stmt, 2, records_seen);
            }
        } else {
            rc = sqlite3_bind_int64(sync_stmt, 1, records_seen);
        }
        if (rc == SQLITE_OK) {
            rc = sqlite3_step(sync_stmt);
        }
        if (rc != SQLITE_OK && rc != SQLITE_DONE) {
            cytadel_log_error("nvd_ingest: updating sync_state failed (sqlite rc=%d): %s", rc,
                               sqlite3_errmsg(handle));
            fatal_db_error = true;
        }
    }

    finalize_all(cve_stmt, cpe_stmt, sync_stmt);

    if (fatal_db_error) {
        (void)cytadel_nvd_exec(handle, "ROLLBACK;", "rolling back nvd_ingest page after a fatal DB error");
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_DB;
    }

    if (cytadel_nvd_exec(handle, "COMMIT;", "committing nvd_ingest page") != SQLITE_OK) {
        (void)cytadel_nvd_exec(handle, "ROLLBACK;", "rolling back after a failed COMMIT");
        cJSON_Delete(root);
        return CYTADEL_NVD_INGEST_ERR_DB;
    }

    cJSON_Delete(root);
    return CYTADEL_NVD_INGEST_OK;
}
