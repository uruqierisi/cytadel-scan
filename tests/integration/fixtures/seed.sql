-- tests/integration/fixtures/seed.sql -- M9 Phase 2 deterministic fixture
-- CVE DB. Applied via the sqlite3 CLI (inside the scanner container, so it
-- writes the exact same file CYTADEL_DB_PATH names) AFTER a bootstrap
-- invocation of cytadel-scan has already created+migrated the schema
-- (tests/integration/run_integration_test.sh does this in that order --
-- schema must exist first, and cve_cpe_matches/kev/epss all carry hard FKs
-- into cves that a bare `sqlite3 db < seed.sql` against a schema-less file
-- would violate).
--
-- (vendor, product) MUST exactly match what the scanner's resolver emits
-- for a service in the Phase-1 target -- see src/net/cpe_map.c's starter
-- map and docs/contracts/db-schema.md SS10 assumption 2 (lowercase,
-- CPE-dictionary form). The `web` container's nginx 1.18.0 Server header
-- ("nginx/1.18.0") is matched by cpe_map.c's `{"nginx/", "nginx", "nginx"}`
-- rule, so the resolver emits vendor='nginx' product='nginx'
-- version='1.18.0' -- every row below keys on exactly that pair. (The
-- `ftp` container now resolves to (vsftpd_project, vsftpd, 3.0.3) since M9
-- Gap #1 was fixed -- docker/ftp/banner.txt carries the literal "vsFTPd 3.0.3"
-- marker cpe_map.c keys on. We deliberately do NOT seed a vsftpd cve_cpe_matches
-- row here: FTP resolving a CPE is asserted directly from the scan output (the
-- "gap1-regression" gate), and leaving vsftpd un-seeded keeps this fixture
-- focused on the nginx confirmed/undetermined/malformed composition paths.)
--
-- Three CVEs, one per required outcome (docs/contracts/cpe-matching.md):
--   CVE-2026-10001 -- CONFIRMED: a real version-range hit
--                     (versionEndExcluding=1.20.0, detected 1.18.0 < 1.20.0).
--   CVE-2026-10002 -- UNDECIDABLE: versionEndExcluding uses an unrecognized
--                     detached pre-release spelling ("-cr1") the comparator
--                     cannot rank (src/match/version_compare.c's residual
--                     walk: "cr" is not in either keyword table, and it is
--                     DETACHED, so cytadel_version_compare("1.18.0",
--                     "1.18.0-cr1") == CYTADEL_VERCMP_UNDECIDABLE, verified
--                     against the real comparator, not asserted from
--                     reading the header comment alone).
--   CVE-2026-10003 -- MALFORMED_ROW: a range row (version='*') with all
--                     four bounds empty -- db-schema.md SS3's own example
--                     of a malformed configuration node.
--
-- KEV + EPSS rows are attached to CVE-2026-10001 only, to exercise the
-- scan_results.kev_flag / .epss_score snapshot columns end to end.

PRAGMA foreign_keys = ON;

BEGIN;

INSERT INTO cves (cve_id, published, last_modified, description,
                   cvss_v3_vector, cvss_v3_base_score, cvss_v3_severity,
                   severity, source, ingested_at)
VALUES ('CVE-2026-10001', '2026-01-05T00:00:00.000Z', '2026-01-05T00:00:00.000Z',
        'Cytadel M9 Phase 2 fixture (synthetic, detection-only test data, not a real CVE): nginx < 1.20.0 path traversal.',
        'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N', 7.5, 'HIGH',
        3, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, version,
                              version_start_including, version_start_excluding,
                              version_end_including, version_end_excluding, vulnerable)
VALUES ('CVE-2026-10001', 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'a', 'nginx', 'nginx', '*',
        '', '', '', '1.20.0', 1);

INSERT INTO kev (cve_id, date_added, vendor_project, product, vulnerability_name,
                  required_action, due_date, known_ransomware, notes, synced_at)
VALUES ('CVE-2026-10001', '2026-01-10', 'nginx', 'nginx',
        'Cytadel fixture: nginx path traversal (synthetic, not a real KEV entry)',
        'Upgrade nginx to >= 1.20.0', '2026-02-10', 0,
        'M9 Phase 2 integration-test fixture row.',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO epss (cve_id, epss_score, percentile, score_date, synced_at)
VALUES ('CVE-2026-10001', 0.42, 0.91, '2026-01-09', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at)
VALUES ('CVE-2026-10002', '2026-01-06T00:00:00.000Z', '2026-01-06T00:00:00.000Z',
        'Cytadel M9 Phase 2 fixture (synthetic): deliberately UNDECIDABLE version-range row (versionEndExcluding="1.18.0-cr1", an unrecognized detached pre-release spelling).',
        2, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, version,
                              version_start_including, version_start_excluding,
                              version_end_including, version_end_excluding, vulnerable)
VALUES ('CVE-2026-10002', 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'a', 'nginx', 'nginx', '*',
        '', '', '', '1.18.0-cr1', 1);

INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at)
VALUES ('CVE-2026-10003', '2026-01-07T00:00:00.000Z', '2026-01-07T00:00:00.000Z',
        'Cytadel M9 Phase 2 fixture (synthetic): deliberately MALFORMED cve_cpe_matches row (a range row with all four version bounds empty).',
        1, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, version,
                              version_start_including, version_start_excluding,
                              version_end_including, version_end_excluding, vulnerable)
VALUES ('CVE-2026-10003', 'cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*', 'a', 'nginx', 'nginx', '*',
        '', '', '', '', 1);

COMMIT;
