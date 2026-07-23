#define _POSIX_C_SOURCE 200809L /* strnlen() -- POSIX.1-2008, not ISO C11; see src/db/scan_persist.c
                                 * for the same project-wide convention. Must be defined before any
                                 * header is included. */

#include "scan_wiring.h"

#include <stdio.h>
#include <string.h>

#include "log.h"

/* See scan_wiring.h for the full design/contract this file implements. This
 * comment covers implementation details only. */

/* ------------------------------------------------------------------ */
/* Step 3/4: the mandatory-DB gate.                                    */
/* ------------------------------------------------------------------ */

const char *cytadel_scan_gate_status_to_string(cytadel_scan_gate_status_t status) {
    switch (status) {
        case CYTADEL_SCAN_GATE_OK:                return "OK";
        case CYTADEL_SCAN_GATE_ERR_INVALID_ARG:    return "INVALID_ARG";
        case CYTADEL_SCAN_GATE_ERR_OPEN:           return "OPEN";
        case CYTADEL_SCAN_GATE_ERR_MIGRATE:        return "MIGRATE";
        case CYTADEL_SCAN_GATE_ERR_SCAN_CREATE:    return "SCAN_CREATE";
    }
    return "UNKNOWN";
}

cytadel_scan_gate_status_t cytadel_scan_wiring_open_gate(const char *db_path, const char *target_spec,
                                                           const char *authorized_by,
                                                           const char *authorization_method,
                                                           cytadel_db_t **out_db, long long *out_scan_id) {
    if (out_db != NULL) {
        *out_db = NULL;
    }
    if (db_path == NULL || db_path[0] == '\0' || target_spec == NULL || target_spec[0] == '\0' ||
        authorized_by == NULL || authorized_by[0] == '\0' || authorization_method == NULL ||
        authorization_method[0] == '\0' || out_db == NULL || out_scan_id == NULL) {
        cytadel_log_error("scan_wiring: cytadel_scan_wiring_open_gate() called with a NULL/empty argument");
        return CYTADEL_SCAN_GATE_ERR_INVALID_ARG;
    }

    /* Mandatory-DB half of the authorization gate (the mandatory authorization-gate rule): a
     * database that cannot be opened/migrated means there is nowhere to
     * durably record the confirmation this function is about to make, so
     * this returns BEFORE any scans row (let alone any target expansion or
     * network probe) exists. This function takes no target-list/port/scan-
     * option argument at all -- structurally, it cannot reach a network
     * probe even if it wanted to. */
    cytadel_db_t *db = NULL;
    cytadel_db_status_t db_status = cytadel_db_open(db_path, &db);
    if (db_status != CYTADEL_DB_OK) {
        cytadel_log_error("scan_wiring: opening DB '%s' failed (%s)", db_path,
                           cytadel_db_status_to_string(db_status));
        return CYTADEL_SCAN_GATE_ERR_OPEN;
    }

    db_status = cytadel_db_migrate(db);
    if (db_status != CYTADEL_DB_OK) {
        cytadel_log_error("scan_wiring: migrating DB '%s' failed (%s)", db_path,
                           cytadel_db_status_to_string(db_status));
        cytadel_db_close(db);
        return CYTADEL_SCAN_GATE_ERR_MIGRATE;
    }

    long long scan_id = 0;
    cytadel_scan_persist_status_t persist_status =
        cytadel_scan_create(db, target_spec, authorized_by, authorization_method, &scan_id);
    if (persist_status != CYTADEL_SCAN_PERSIST_OK) {
        cytadel_log_error("scan_wiring: creating the durable scans row failed (%s)",
                           cytadel_scan_persist_status_to_string(persist_status));
        cytadel_db_close(db);
        return CYTADEL_SCAN_GATE_ERR_SCAN_CREATE;
    }

    *out_db = db;
    *out_scan_id = scan_id;
    return CYTADEL_SCAN_GATE_OK;
}

/* ------------------------------------------------------------------ */
/* The resolver.                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    const char *ptr;
    size_t len;
} cytadel_scan_wiring_field_t;

/* CPE 2.3 URI shape: "cpe:2.3:a:vendor:product:version:update:edition:
 * language:sw_edition:target_sw:target_hw:other" -- 13 ':'-delimited
 * fields. Bounded, index-based split: never reads text[text_len] or
 * beyond, and bails (returns (size_t)-1) rather than silently dropping the
 * tail if the input would produce more than max_fields -- a hostile or
 * corrupted value with an unexpectedly large field count is treated as
 * malformed, never partially parsed. */
#define CYTADEL_SCAN_WIRING_CPE_FIELD_COUNT 13

/* True iff `field` (ptr,len -- not NUL-terminated) exactly equals the
 * NUL-terminated ASCII literal `lit`. Length-bounded, no strlen on the
 * field bytes. */
static bool cytadel_scan_wiring_field_equals(const cytadel_scan_wiring_field_t *field,
                                              const char *lit) {
    size_t lit_len = strlen(lit);
    return field->len == lit_len && memcmp(field->ptr, lit, lit_len) == 0;
}

static size_t cytadel_scan_wiring_split_cpe(const char *text, size_t text_len,
                                              cytadel_scan_wiring_field_t *fields, size_t max_fields) {
    size_t count = 0;
    size_t start = 0;
    for (size_t i = 0; i <= text_len; i++) {
        if (i == text_len || text[i] == ':') {
            if (count >= max_fields) {
                return (size_t)-1;
            }
            fields[count].ptr = text + start;
            fields[count].len = i - start;
            count++;
            start = i + 1;
        }
    }
    return count;
}

bool cytadel_scan_wiring_resolve_port(const cytadel_kb_t *kb, uint16_t port,
                                       cytadel_scan_resolved_service_t *out) {
    if (kb == NULL || out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));

    char key[32];
    int key_written = snprintf(key, sizeof(key), "CPE/%u", (unsigned)port);
    if (key_written < 0 || (size_t)key_written >= sizeof(key)) {
        return false;
    }

    cytadel_kb_value_t value;
    memset(&value, 0, sizeof(value));
    if (cytadel_kb_get(kb, key, &value) != CYTADEL_KB_GET_FOUND || value.type != CYTADEL_KB_TYPE_STRING ||
        value.v.str == NULL) {
        /* No CPE fact for this port at all -- kb-schema.md SS7.7's
         * deliberately conservative "absent if the version could not be
         * determined precisely enough" outcome. Unresolvable, not an
         * error. */
        return false;
    }

    /* Bounded by kb.h's own CYTADEL_KB_VALUE_MAX_LEN cap -- cytadel_kb_set_str()
     * never stores a longer value in the first place, and this never reads
     * past that bound regardless of what a future writer might attempt. */
    size_t cpe_len = strnlen(value.v.str, CYTADEL_KB_VALUE_MAX_LEN);

    cytadel_scan_wiring_field_t fields[CYTADEL_SCAN_WIRING_CPE_FIELD_COUNT];
    size_t field_count =
        cytadel_scan_wiring_split_cpe(value.v.str, cpe_len, fields, CYTADEL_SCAN_WIRING_CPE_FIELD_COUNT);
    if (field_count == (size_t)-1 || field_count < 6) {
        cytadel_log_warn(
            "scan_wiring: CPE/%u does not split into a well-formed CPE 2.3 URI (expected at least "
            "6 ':'-delimited fields) -- treating port %u as unresolvable, not clean",
            (unsigned)port, (unsigned)port);
        return false;
    }

    /* Defense-in-depth (Phase-0 review S2): validate the CPE 2.3 URI prefix
     * before trusting fields [3]/[4]/[5] as vendor/product/version. Today the
     * only writer (cpe_map.c) always emits the fixed "cpe:2.3:a:" prefix and
     * its version charset excludes ':' so fields can't shift -- but if a
     * future writer ever stores an externally-derived CPE string, an
     * unvalidated prefix could let attacker-shaped text land in the
     * (vendor, product) lookup. A malformed prefix is unresolvable, not clean. */
    if (!cytadel_scan_wiring_field_equals(&fields[0], "cpe") ||
        !cytadel_scan_wiring_field_equals(&fields[1], "2.3")) {
        cytadel_log_warn(
            "scan_wiring: CPE/%u is not a 'cpe:2.3:' URI -- treating port %u as unresolvable, "
            "not clean",
            (unsigned)port, (unsigned)port);
        return false;
    }

    const cytadel_scan_wiring_field_t *vendor_field = &fields[3];
    const cytadel_scan_wiring_field_t *product_field = &fields[4];
    const cytadel_scan_wiring_field_t *version_field = &fields[5];

    /* Never truncate-and-continue on an oversized field -- a silently
     * truncated vendor/product/version could produce a WRONG match
     * (either a false MATCH against the wrong product, or a false
     * NOT_AFFECTED against a truncated version), which is worse than
     * honestly reporting "unresolvable". */
    if (vendor_field->len == 0 || vendor_field->len > CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN ||
        product_field->len == 0 || product_field->len > CYTADEL_SCAN_VENDOR_PRODUCT_MAX_LEN ||
        version_field->len == 0) {
        cytadel_log_warn(
            "scan_wiring: CPE/%u has an empty or oversized vendor/product/version field -- "
            "treating port %u as unresolvable, not clean",
            (unsigned)port, (unsigned)port);
        return false;
    }

    memcpy(out->vendor, vendor_field->ptr, vendor_field->len);
    out->vendor[vendor_field->len] = '\0';
    memcpy(out->product, product_field->ptr, product_field->len);
    out->product[product_field->len] = '\0';
    /* Borrowed, non-NUL-terminated substring -- passed through verbatim
     * (ptr, len), exactly like cytadel_scan_detection_t.detected_version.
     * Hostile bytes inside this substring (control bytes, an unsupported
     * version scheme, ...) are cytadel_cpe_match_evaluate()'s own concern
     * (cpe-matching.md SS1/SS3.4) -- this function's only job is to split
     * the CPE string safely, never to judge the version's content. */
    out->version = version_field->ptr;
    out->version_len = version_field->len;
    return true;
}

/* ------------------------------------------------------------------ */
/* Small KB-lookup helpers shared by the persist phase below.          */
/* ------------------------------------------------------------------ */

/* The frozen service-token vocabulary (docs/contracts/kb-schema.md §2),
 * duplicated here (as plain string literals, not shared code) purely so
 * this module can look up which Services/<token>/<port> key, if any, was
 * written for a given port -- the exact same duplication src/cli/main.c's
 * own cytadel_print_port_kb_details() already carries, and for the same
 * reason (kb-schema.md §7.3 keys `Services/<service>/<port>` by service
 * token first, port second, which is not a convenient per-port lookup
 * direction). */
static const char *const CYTADEL_SCAN_WIRING_SVC_TOKENS[] = {
    "www", "https", "ssh", "ftp", "smb", "rdp", "telnet", "smtp",
    "pop3", "imap", "dns", "snmp", "mysql", "postgresql", "redis",
};

static const char *cytadel_scan_wiring_lookup_service(const cytadel_kb_t *kb, uint16_t port) {
    if (kb == NULL || port == 0) {
        return NULL;
    }
    size_t token_count = sizeof(CYTADEL_SCAN_WIRING_SVC_TOKENS) / sizeof(CYTADEL_SCAN_WIRING_SVC_TOKENS[0]);
    for (size_t i = 0; i < token_count; i++) {
        char key[64];
        int written = snprintf(key, sizeof(key), "Services/%s/%u", CYTADEL_SCAN_WIRING_SVC_TOKENS[i],
                                 (unsigned)port);
        if (written < 0 || (size_t)written >= sizeof(key)) {
            continue;
        }
        cytadel_kb_value_t v;
        if (cytadel_kb_get(kb, key, &v) == CYTADEL_KB_GET_FOUND) {
            return CYTADEL_SCAN_WIRING_SVC_TOKENS[i];
        }
    }
    return NULL;
}

/* Best-effort "what raw text proves this detection" lookup: Banner/<port>,
 * then HTTP/<port>/server, then FTP/<port>/banner, falling back to
 * `fallback` (the CPE/<port> string itself, when this is for a CPE/version
 * detection) if none of those keys are present. Every returned pointer is
 * borrowed KB storage (kb.h's own validity-window rules) or `fallback`
 * (borrowed from the caller) -- never allocated, never freed here. */
static const char *cytadel_scan_wiring_lookup_evidence(const cytadel_kb_t *kb, uint16_t port,
                                                          const char *fallback) {
    if (kb == NULL) {
        return fallback;
    }
    char key[32];

    snprintf(key, sizeof(key), "Banner/%u", (unsigned)port);
    const char *banner = cytadel_kb_get_str(kb, key);
    if (banner != NULL) {
        return banner;
    }

    snprintf(key, sizeof(key), "HTTP/%u/server", (unsigned)port);
    const char *http_server = cytadel_kb_get_str(kb, key);
    if (http_server != NULL) {
        return http_server;
    }

    snprintf(key, sizeof(key), "FTP/%u/banner", (unsigned)port);
    const char *ftp_banner = cytadel_kb_get_str(kb, key);
    if (ftp_banner != NULL) {
        return ftp_banner;
    }

    return fallback;
}

/* ------------------------------------------------------------------ */
/* The persist phase.                                                  */
/* ------------------------------------------------------------------ */

cytadel_scan_persist_status_t cytadel_scan_wiring_persist_host(cytadel_db_t *db, long long scan_id,
                                                                  const cytadel_host_result_t *result,
                                                                  cytadel_scan_wiring_host_counts_t *out_counts) {
    if (out_counts != NULL) {
        memset(out_counts, 0, sizeof(*out_counts));
    }
    if (db == NULL || result == NULL || out_counts == NULL) {
        cytadel_log_error("scan_wiring: cytadel_scan_wiring_persist_host() called with a NULL argument");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (scan_id <= 0) {
        cytadel_log_error(
            "scan_wiring: cytadel_scan_wiring_persist_host() called with a non-positive scan_id %lld",
            scan_id);
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }
    if (result->state != CYTADEL_HOST_UP || result->host[0] == '\0') {
        cytadel_log_error(
            "scan_wiring: cytadel_scan_wiring_persist_host() called against a host that is not "
            "UP/populated -- caller bug (there is nothing to persist for a down host)");
        return CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG;
    }

    const char *host = result->host;

    /* (a) every direct plugin finding -> one scan_results row each. */
    for (size_t i = 0; i < result->findings.count; i++) {
        const cytadel_finding_t *f = &result->findings.items[i];
        const char *title = (f->title != NULL) ? f->title : "(untitled)";

        if (f->port < 0 || f->port > 65535) {
            cytadel_log_warn(
                "scan_wiring: host=%s: finding '%s' has an out-of-range port %lld -- skipping "
                "(not persisted, but not silently dropped from the log either)",
                host, title, (long long)f->port);
            continue;
        }
        if (f->severity < 0 || f->severity > 4) {
            cytadel_log_warn("scan_wiring: host=%s: finding '%s' has an out-of-range severity %d -- skipping",
                              host, title, f->severity);
            continue;
        }
        if (f->evidence == NULL) {
            cytadel_log_warn("scan_wiring: host=%s: finding '%s' has no evidence -- skipping", host, title);
            continue;
        }

        uint16_t port = (uint16_t)f->port;
        char plugin_id_buf[32];
        int written = snprintf(plugin_id_buf, sizeof(plugin_id_buf), "%lld", (long long)f->script_id);
        if (written < 0 || (size_t)written >= sizeof(plugin_id_buf)) {
            cytadel_log_warn("scan_wiring: host=%s: finding '%s' has an unrepresentable script_id -- skipping",
                              host, title);
            continue;
        }

        cytadel_scan_finding_persist_t persist_row;
        memset(&persist_row, 0, sizeof(persist_row));
        persist_row.host = host;
        persist_row.port = (int)port;
        persist_row.service = cytadel_scan_wiring_lookup_service(result->kb, port);
        persist_row.plugin_id = plugin_id_buf;
        persist_row.evidence = f->evidence;
        persist_row.remediation = f->solution;
        /* S1 (Phase-0 review): guard cve != NULL too. The invariant
         * (cve_count > 0 ⟹ cve != NULL) holds for the only current producer
         * (field_utils.c), but a future non-plugin producer of a
         * cytadel_finding_t must not fault here. */
        persist_row.cve_id = (f->cve_count > 0 && f->cve != NULL) ? f->cve[0] : NULL;
        persist_row.severity = f->severity;

        cytadel_scan_persist_status_t st = cytadel_scan_persist_finding(db, scan_id, &persist_row);
        if (st == CYTADEL_SCAN_PERSIST_ERR_DB) {
            /* Fatal -- a broken DB connection will not recover mid-host.
             * Stop attempting further persistence for this host/scan. */
            return st;
        }
        if (st == CYTADEL_SCAN_PERSIST_OK) {
            out_counts->findings_persisted++;
        } else if (st == CYTADEL_SCAN_PERSIST_ERR_ROW_SKIPPED) {
            /* M9 Gap #3 fix: a genuine per-row constraint rejection (already
             * logged by cytadel_scan_persist_finding() itself) -- count it
             * and move on to the next finding. This must NEVER be conflated
             * with CYTADEL_SCAN_PERSIST_ERR_DB above: one bad finding/CVE
             * must never poison the rest of this host, the rest of this
             * scan, or flip scans.status to 'failed' (main.c's db_ok latch
             * only ever sees ERR_DB from this whole call, never this
             * per-finding outcome). */
            out_counts->findings_skipped++;
        }
        /* CYTADEL_SCAN_PERSIST_ERR_INVALID_ARG here would mean this
         * module's own field-by-field validation above missed something --
         * already logged by cytadel_scan_persist_finding() itself; absorbed
         * (not propagated as a whole-host failure) so one bad finding can
         * never abort persistence for the rest of this host. */
    }

    /* (b)/(c): every OPEN port's service, resolved or not. */
    for (size_t p = 0; p < result->port_count; p++) {
        if (result->ports[p].state != CYTADEL_PORT_OPEN) {
            continue;
        }
        uint16_t port = result->ports[p].port;

        cytadel_scan_resolved_service_t resolved;
        bool resolvable = cytadel_scan_wiring_resolve_port(result->kb, port, &resolved);
        if (!resolvable) {
            const char *service = cytadel_scan_wiring_lookup_service(result->kb, port);
            /* The binding rule this whole item exists to satisfy: an
             * unresolvable service is a DATA-QUALITY event, surfaced by
             * name (host:port/service), and is NEVER recorded as, or
             * confused with, "no CVE / clean" -- no scan_results row is
             * written for this port at all, which is the honest
             * representation of "we could not check", not "we checked and
             * found nothing". */
            cytadel_log_warn(
                "scan_wiring: host=%s port=%u service=%s -- could not resolve a (vendor, product, "
                "version) triple for this open port; NO CVE check was performed here -- this is a "
                "data-quality gap, not a clean bill of health",
                host, (unsigned)port, (service != NULL) ? service : "(unknown)");
            out_counts->unresolvable_services++;
            continue;
        }

        char cpe_key[32];
        snprintf(cpe_key, sizeof(cpe_key), "CPE/%u", (unsigned)port);
        const char *cpe_str = cytadel_kb_get_str(result->kb, cpe_key);

        cytadel_scan_detection_t det;
        memset(&det, 0, sizeof(det));
        det.host = host;
        det.port = (int)port;
        det.service = cytadel_scan_wiring_lookup_service(result->kb, port);
        /* Not a Lua script_id -- this is the engine's own internal CPE/
         * version-match detector, distinct from any plugin_id a Lua plugin
         * might report (db-schema.md SS10 assumption 7: plugin_id has no
         * DB-level validation against a registry, so this fixed literal is
         * a valid, if non-Lua, plugin_id). */
        det.plugin_id = "cpe_version_match";
        det.evidence = cytadel_scan_wiring_lookup_evidence(
            result->kb, port, (cpe_str != NULL) ? cpe_str : "(no additional evidence captured)");
        det.remediation = NULL;
        det.detected_version = resolved.version;
        det.detected_version_len = resolved.version_len;

        cytadel_scan_persist_counts_t counts;
        cytadel_scan_persist_status_t st =
            cytadel_scan_detect_and_persist(db, scan_id, resolved.vendor, resolved.product, &det, &counts);
        if (st == CYTADEL_SCAN_PERSIST_ERR_DB) {
            return st;
        }
        if (st == CYTADEL_SCAN_PERSIST_OK) {
            out_counts->detections_attempted++;
            out_counts->rows_inserted += counts.rows_inserted;
            out_counts->malformed_events += counts.malformed_events;
        }
    }

    return CYTADEL_SCAN_PERSIST_OK;
}
