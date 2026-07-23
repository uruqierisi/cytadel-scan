# Cytadel Scan — DB Schema Contract (FROZEN)

**Status:** FROZEN at Milestone 0. This is a design/contract document, not an implementation.
Any change after this point requires an explicit stop-and-ask per the project's engineering policy. Downstream
consumers (the engine, the plugin layer, and the sync jobs) build
against this contract as-is.

**Engine:** SQLite 3.35.0+ (required for `UPSERT ... RETURNING`, used by the sync writer to
fetch inserted/updated row ids in one round trip; core `INSERT ... ON CONFLICT` has been
available since 3.24.0). Single-file DB at `CYTADEL_DB_PATH` (see `.env.example`).

**Severity scale (binding across the whole project):**

| int | label    |
|-----|----------|
| 0   | Info     |
| 1   | Low      |
| 2   | Medium   |
| 3   | High     |
| 4   | Critical |

**Timestamp convention (binding):** every timestamp column is `TEXT` in strict ISO-8601 UTC,
millisecond precision, explicit `Z` suffix: `YYYY-MM-DDTHH:MM:SS.sssZ`. SQLite has no native
datetime type — range filters and `ORDER BY` on these columns rely on **lexicographic string
comparison**, which is only correct if every writer normalizes to this exact zero-padded
format. NVD's API returns timestamps without a trailing `Z` (e.g.
`2021-12-10T10:15:09.143`) — the sync writer MUST append `Z` (NVD timestamps are UTC) before
storing. `date`-only fields (KEV `dateAdded`/`dueDate`, EPSS `score_date`) use `YYYY-MM-DD`
and still sort correctly against each other.

**Booleans:** SQLite has no boolean type. All boolean columns are `INTEGER NOT NULL CHECK (col
IN (0,1))`, `0` = false, `1` = true. Never store `'true'/'false'` text.

**Connection setup (every connection, not just the writer):**

```sql
PRAGMA foreign_keys = ON;      -- OFF by default per-connection; must be set every time a
                                -- connection is opened, it is NOT a persistent DB property.
PRAGMA journal_mode = WAL;     -- one-time, persists in the DB file; set on first open.
                                -- Lets the scan engine read while the sync job writes.
                                -- Requires the DB file to live on a local filesystem
                                -- (operational note: no CIFS/NFS-mounted DB path in the
                                -- Docker test target).
PRAGMA synchronous = NORMAL;   -- safe durability/perf tradeoff under WAL.
PRAGMA busy_timeout = 5000;    -- avoid SQLITE_BUSY races between the scan engine (reader)
                                -- and the sync job (writer) instead of ad-hoc retry loops.
```

`PRAGMA foreign_keys = ON` is mandatory — several tables rely on `ON DELETE CASCADE` / `ON
DELETE SET NULL` for integrity instead of manual cleanup code.

---

## 1. `schema_migrations`

Tracks which DDL revision is applied. Frozen at version 1 for the lifetime of this contract.

```sql
CREATE TABLE schema_migrations (
    version     INTEGER NOT NULL PRIMARY KEY,
    description TEXT    NOT NULL,
    applied_at  TEXT    NOT NULL   -- ISO-8601 UTC, see timestamp convention above
) WITHOUT ROWID;

INSERT INTO schema_migrations (version, description, applied_at)
VALUES (1, 'Initial frozen schema: cves, cve_cpe_matches, kev, epss, scans, scan_results, sync_state',
        strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));
```

`WITHOUT ROWID`: single-row-lookup-by-PK table, no secondary indexes, tiny row count — a
plain integer PK B-tree with no separate rowid alias is the right shape here.

---

## 2. `cves`

Canonical NVD CVE record. One row per CVE ID. Refreshed by the NVD delta sync
(`lastModStartDate`/`lastModEndDate` windows, `startIndex` pagination).

```sql
CREATE TABLE cves (
    cve_id               TEXT    NOT NULL PRIMARY KEY,   -- 'CVE-YYYY-NNNN...'
    published            TEXT    NOT NULL,                -- ISO-8601 UTC
    last_modified         TEXT    NOT NULL,                -- ISO-8601 UTC; NVD delta cursor field
    description           TEXT    NOT NULL DEFAULT '',

    cvss_v3_vector         TEXT,                            -- e.g. 'CVSS:3.1/AV:N/AC:L/...'
    cvss_v3_base_score     REAL    CHECK (cvss_v3_base_score IS NULL
                                          OR (cvss_v3_base_score >= 0.0 AND cvss_v3_base_score <= 10.0)),
    cvss_v3_severity       TEXT    CHECK (cvss_v3_severity IS NULL
                                          OR cvss_v3_severity IN ('NONE','LOW','MEDIUM','HIGH','CRITICAL')),

    cvss_v2_vector         TEXT,                            -- fallback for pre-2016 CVEs w/o v3 data
    cvss_v2_base_score     REAL    CHECK (cvss_v2_base_score IS NULL
                                          OR (cvss_v2_base_score >= 0.0 AND cvss_v2_base_score <= 10.0)),
    cvss_v2_severity       TEXT    CHECK (cvss_v2_severity IS NULL
                                          OR cvss_v2_severity IN ('LOW','MEDIUM','HIGH')),

    -- Normalized 0-4 severity per the project-wide scale, computed at ingest time from
    -- cvss_v3_base_score if present, else cvss_v2_base_score, else 0 (Info). See "Severity
    -- normalization rule" below for the exact score->int mapping. Stored (not computed on
    -- read) because it is the hot filter/sort column for every report and CLI listing.
    severity               INTEGER NOT NULL DEFAULT 0 CHECK (severity BETWEEN 0 AND 4),

    source                 TEXT    NOT NULL DEFAULT 'nvd',  -- 'nvd' | 'placeholder' (see sync_state
                                                             -- notes / KEV-EPSS reconciliation below)
    ingested_at             TEXT    NOT NULL                -- local write time, distinct from NVD's
                                                             -- own last_modified; debugging aid only
) ;

CREATE INDEX idx_cves_last_modified ON cves (last_modified);
CREATE INDEX idx_cves_severity      ON cves (severity);
```

Kept as an ordinary ROWID table (not `WITHOUT ROWID`): it carries two secondary indexes, and
its PK is a ~15-20 byte TEXT string. A `WITHOUT ROWID` table duplicates the full PK into every
secondary index leaf; a normal ROWID table stores the cheap 8-byte rowid there instead. With
two non-PK indexes this is a real space/perf win, unlike the small lookup-only metadata
tables below.

**Severity normalization rule (applied by the sync writer at ingest, not by the DB):**

| CVSS v3 base score | severity | CVSS v2-only base score | severity |
|---------------------|----------|--------------------------|----------|
| 0.0                  | 0 (Info) | 0.0                       | 0 (Info) |
| 0.1 – 3.9            | 1 (Low)  | 0.1 – 3.9                 | 1 (Low)  |
| 4.0 – 6.9            | 2 (Med)  | 4.0 – 6.9                 | 2 (Med)  |
| 7.0 – 8.9            | 3 (High) | 7.0 – 10.0                | 3 (High) |
| 9.0 – 10.0           | 4 (Crit) | (v2 has no Critical tier) | never 4  |

CVEs with neither score present get `severity = 0`.

---

## 3. `cve_cpe_matches`

CPE 2.3 applicability rows extracted from each CVE's NVD `configurations` block. This is the
table the scan engine queries when it has detected a `(vendor, product, version)` triple and
needs candidate CVEs.

```sql
CREATE TABLE cve_cpe_matches (
    id                          INTEGER NOT NULL PRIMARY KEY,   -- rowid alias
    cve_id                      TEXT    NOT NULL REFERENCES cves (cve_id) ON DELETE CASCADE,

    cpe23_uri                    TEXT    NOT NULL,   -- full 'cpe:2.3:a:vendor:product:version:...' string
                                                       -- as returned by NVD ("criteria"), kept verbatim
                                                       -- for audit/debug even though matching uses the
                                                       -- parsed columns below.
    part                         TEXT    NOT NULL DEFAULT 'a' CHECK (part IN ('a','o','h')),
    vendor                       TEXT    NOT NULL,     -- lowercase, CPE-dictionary form (component 4)
    product                      TEXT    NOT NULL,     -- lowercase, CPE-dictionary form (component 5)

    -- '*' means "not version-pinned here, use the range bounds below" (matches CPE 2.3's own
    -- wildcard convention). A concrete value means an exact-version match row with no range.
    version                      TEXT    NOT NULL DEFAULT '*',

    -- Range bounds. Deliberately NOT NULL DEFAULT '' (empty-string sentinel = "unbounded on
    -- this side") rather than nullable. Reason: SQLite UNIQUE indexes treat NULL as distinct
    -- from every other NULL, so a nullable-column UNIQUE constraint cannot dedupe identical
    -- range rows during upsert. Empty-string sentinels make the UNIQUE index below actually
    -- work, and application code treats '' as "no bound" uniformly.
    version_start_including       TEXT    NOT NULL DEFAULT '',
    version_start_excluding       TEXT    NOT NULL DEFAULT '',
    version_end_including         TEXT    NOT NULL DEFAULT '',
    version_end_excluding         TEXT    NOT NULL DEFAULT '',

    vulnerable                    INTEGER NOT NULL DEFAULT 1 CHECK (vulnerable IN (0,1)),

    UNIQUE (cve_id, cpe23_uri, version_start_including, version_start_excluding,
            version_end_including, version_end_excluding, vulnerable)
);

CREATE INDEX idx_cpe_vendor_product ON cve_cpe_matches (vendor, product);
CREATE INDEX idx_cpe_product        ON cve_cpe_matches (product);
CREATE INDEX idx_cpe_cve_id         ON cve_cpe_matches (cve_id);
```

Index rationale:

- `idx_cpe_vendor_product (vendor, product)` — the primary scan-time lookup: engine has
  parsed a banner into `(vendor, product, version)` and needs every candidate CVE for that
  exact pair. Leftmost-prefix also serves vendor-only queries.
- `idx_cpe_product (product)` — fallback when the detector is confident about the product
  ("openssh") but not the CPE-dictionary vendor spelling ("openbsd" vs a guessed vendor).
  Kept as a separate index rather than relying on `(vendor, product)`'s second column because
  SQLite cannot use a composite index to skip the leading `vendor` column.
- `idx_cpe_cve_id (cve_id)` — reverse lookup for "all CPE rows for CVE X" (report drill-down,
  CASCADE-delete efficiency, and upsert dedupe checks during sync).
- The `UNIQUE` constraint doubles as the upsert conflict target (`INSERT ... ON CONFLICT
  (...) DO UPDATE SET vulnerable = excluded.vulnerable`), making repeated NVD syncs
  idempotent instead of accumulating duplicate range rows.

Kept as a plain ROWID table: `id` is already a cheap integer PK and the table carries three
secondary indexes — `WITHOUT ROWID` would force every one of those to duplicate a wider key.

### Version-range matching approach

SQL only does the coarse pre-filter (`vendor`, `product` equality via `idx_cpe_vendor_product`)
and returns the small candidate set (typically tens, rarely low hundreds of rows even for
high-profile products). **SQLite must never be asked to compare version strings directly** —
its default TEXT/REAL affinities compare `'7.2p2'` and `'10.0'` lexicographically, which is
wrong (`'10.0' < '7.2p2'` as strings). All range/equality evaluation happens in application
code (engine C, shared with any Lua-side matching — see Assumptions) using a CPE-2.3-spec
version comparator that splits on `.`/`-`/`_`, compares numeric components numerically and
alpha components lexically, matching the algorithm NVD itself uses for `versionStartIncluding`
etc.

For each candidate row returned by the `(vendor, product)` query, given the detector's
`detected_version`:

1. **Exact-match row** (`version NOT IN ('*','')`): vulnerable iff
   `compare(detected_version, row.version) == 0 AND row.vulnerable = 1`.
2. **Range row** (`version = '*'`): vulnerable iff `row.vulnerable = 1` AND every *set* bound
   holds (an empty-string bound is skipped, not treated as `0`):
   - `version_start_including = '' OR compare(detected_version, version_start_including) >= 0`
   - `version_start_excluding = '' OR compare(detected_version, version_start_excluding) >  0`
   - `version_end_including   = '' OR compare(detected_version, version_end_including)   <= 0`
   - `version_end_excluding   = '' OR compare(detected_version, version_end_excluding)   <  0`
   - **and at least one of the four bounds is non-empty.** A range row ingested with `version
     = '*'` and all four bounds empty is malformed (NVD always supplies at least one bound for
     a genuine range match); the sync writer must reject/flag such a configuration node at
     ingest time rather than let it silently match every version ever detected.

---

## 4. `kev`

CISA Known Exploited Vulnerabilities catalog, refreshed daily (full-file re-pull, then
upsert — the feed has no delta mechanism of its own).

```sql
CREATE TABLE kev (
    cve_id                TEXT    NOT NULL PRIMARY KEY REFERENCES cves (cve_id) ON DELETE CASCADE,
    date_added             TEXT    NOT NULL,   -- 'YYYY-MM-DD'
    vendor_project          TEXT    NOT NULL,
    product                 TEXT    NOT NULL,
    vulnerability_name       TEXT    NOT NULL,
    required_action          TEXT,
    due_date                 TEXT,               -- 'YYYY-MM-DD', nullable (not all entries have one)
    known_ransomware         INTEGER NOT NULL DEFAULT 0 CHECK (known_ransomware IN (0,1)),
                                                 -- CISA field "knownRansomwareCampaignUse":
                                                 -- 'Known' -> 1, 'Unknown'/absent -> 0
    notes                    TEXT,
    synced_at                TEXT    NOT NULL     -- local ingestion timestamp
) WITHOUT ROWID;
```

`WITHOUT ROWID`: the only access pattern is `SELECT 1 FROM kev WHERE cve_id = ?` (or a JOIN on
`cve_id`) — no secondary indexes are needed, so clustering the whole row by its TEXT PK avoids
a redundant rowid index entirely. The PK itself answers "is this CVE in KEV?" in O(log n)
without any extra index.

---

## 5. `epss`

EPSS exploitation-probability scores, refreshed daily (full replace of all ~250k+ scored CVEs
via upsert).

```sql
CREATE TABLE epss (
    cve_id       TEXT    NOT NULL PRIMARY KEY REFERENCES cves (cve_id) ON DELETE CASCADE,
    epss_score    REAL    NOT NULL CHECK (epss_score  >= 0.0 AND epss_score  <= 1.0),
    percentile    REAL    NOT NULL CHECK (percentile  >= 0.0 AND percentile  <= 1.0),
    score_date    TEXT    NOT NULL,   -- 'YYYY-MM-DD', the date this score was published
    synced_at     TEXT    NOT NULL
) WITHOUT ROWID;
```

`WITHOUT ROWID` for the same reason as `kev`: PK-only access, no secondary indexes. The PK
directly serves "EPSS for these CVE ids" via `WHERE cve_id IN (?, ?, ...)` or a join from
`scan_results`/`cve_cpe_matches` results.

---

## 6. `scans`

One row per scan run. Created at the moment the mandatory authorization gate is confirmed —
this row *is* the durable record of that confirmation (project rule: "Log the confirmation.").

```sql
CREATE TABLE scans (
    scan_id                     INTEGER NOT NULL PRIMARY KEY,   -- engine obtains this via
                                                                 -- sqlite3_last_insert_rowid()
                                                                 -- immediately after the INSERT
                                                                 -- below, before any scanning starts
    started_at                   TEXT    NOT NULL,
    finished_at                  TEXT,                           -- NULL while the scan is in progress
    target_spec                  TEXT    NOT NULL,                -- CIDR/host list/spec as given on CLI
    authorized_by                 TEXT    NOT NULL,                -- operator identity string
    authorization_confirmed_at     TEXT    NOT NULL,                -- timestamp of the explicit gate
    authorization_method           TEXT    NOT NULL
                                   CHECK (authorization_method IN ('interactive','flag')),
                                                                 -- interactive prompt vs
                                                                 -- --i-am-authorized
    status                       TEXT    NOT NULL DEFAULT 'running'
                                   CHECK (status IN ('running','completed','aborted','failed')),
    notes                        TEXT,
    malformed_data_count          INTEGER NOT NULL DEFAULT 0
                                   -- added migration v3 (M8 report slice), authorized 2026-07-22.
                                   -- Durable running total of CYTADEL_CPE_MALFORMED_ROW
                                   -- data-quality events (docs/contracts/cpe-matching.md SS2/SS3.1)
                                   -- seen across every cytadel_scan_detect_and_persist() call for
                                   -- this scan_id -- see src/db/scan_persist.c's own
                                   -- scans.malformed_data_count UPDATE, committed atomically in the
                                   -- SAME transaction as the scan_results rows it describes. A
                                   -- COUNT column, so DEFAULT 0 is honest here (unlike
                                   -- match_status, which has none): zero genuinely means zero. This
                                   -- powers the M8 report's "N records had malformed data --
                                   -- results may be incomplete" banner (report Gate 2).
);

CREATE INDEX idx_scans_started_at ON scans (started_at DESC);
```

`idx_scans_started_at` — supports "most recent scan" / scan-history listing (`ORDER BY
started_at DESC LIMIT n`), the standard entry point for report generation (`cytadel-scan
report --latest`).

Per-record malformed detail (which record, why it was malformed) is deliberately NOT stored
here — `malformed_data_count` is only ever the durable running total. Per-record malformed
detail is a FUTURE additive `data_quality` table, NOT a reshape of this column — this count is
not a dead end.

---

## 7. `scan_results`

Persisted findings, one row per detection. The dominant write pattern during a scan; the
dominant read pattern during report generation.

```sql
CREATE TABLE scan_results (
    id             INTEGER NOT NULL PRIMARY KEY,
    scan_id         INTEGER NOT NULL REFERENCES scans (scan_id) ON DELETE CASCADE,
    host            TEXT    NOT NULL,                -- IP or hostname as detected
    port            INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
                                                     -- 0 reserved for host-level findings not
                                                     -- tied to a specific port (e.g. OS fingerprint)
    service         TEXT,                             -- banner-detected service name, nullable
    plugin_id       TEXT    NOT NULL,                 -- Lua plugin identifier (plugin-api contract);
                                                     -- intentionally no FK — plugins are file-based,
                                                     -- not DB-registered
    cve_id          TEXT    REFERENCES cves (cve_id) ON DELETE SET NULL,
                                                     -- nullable: not every finding is CVE-backed
                                                     -- (weak-cipher, self-signed cert, default-cred
                                                     -- checks have no CVE mapping)
    severity        INTEGER NOT NULL CHECK (severity BETWEEN 0 AND 4),
                                                     -- deliberately DENORMALIZED: a snapshot of
                                                     -- severity at detection time, not a live join
                                                     -- to cves.severity. A report must reflect what
                                                     -- was true when the scan ran, even if NVD later
                                                     -- revises the CVSS score.
    evidence        TEXT    NOT NULL,                 -- raw banner/version/cert string — the
                                                     -- detection proof; never exploitation output
    remediation     TEXT,
    kev_flag        INTEGER NOT NULL DEFAULT 0 CHECK (kev_flag IN (0,1)),
                                                     -- snapshot, same reasoning as severity
    epss_score      REAL    CHECK (epss_score IS NULL OR (epss_score >= 0.0 AND epss_score <= 1.0)),
                                                     -- snapshot, same reasoning as severity
    detected_at     TEXT    NOT NULL,                 -- ISO-8601 UTC, may differ from scans.started_at
    match_status    TEXT    NOT NULL DEFAULT 'confirmed'
                                   CHECK (match_status IN ('confirmed','undetermined','not_affected'))
                                                     -- added migration v2 (M7 CPE-caller slice),
                                                     -- authorized 2026-07-22. The three-valued,
                                                     -- order-independent per-CVE aggregation of
                                                     -- cytadel_cpe_match_evaluate() outcomes
                                                     -- (docs/contracts/cpe-matching.md SS3.2.3):
                                                     -- 'confirmed' (any candidate row MATCH),
                                                     -- 'undetermined' (no MATCH, any row
                                                     -- UNDECIDABLE), 'not_affected' (otherwise).
                                                     -- CYTADEL_CPE_MALFORMED_ROW never produces a
                                                     -- value here -- it is a data-quality event,
                                                     -- surfaced separately, never a match_status.
);

CREATE INDEX idx_scan_results_scan_id      ON scan_results (scan_id);
CREATE INDEX idx_scan_results_host_port    ON scan_results (scan_id, host, port);
CREATE INDEX idx_scan_results_severity     ON scan_results (scan_id, severity DESC);
CREATE INDEX idx_scan_results_cve_id       ON scan_results (cve_id) WHERE cve_id IS NOT NULL;
```

Index rationale:

- `idx_scan_results_scan_id` — the single most common query: "every finding for scan X"
  (report generation's outermost query).
- `idx_scan_results_host_port (scan_id, host, port)` — Nessus-style reports group findings by
  host then port within a scan; this composite index serves that grouping directly without a
  sort.
- `idx_scan_results_severity (scan_id, severity DESC)` — reports list findings
  Critical-first within a scan; this serves that ordering without a sort.
- `idx_scan_results_cve_id ... WHERE cve_id IS NOT NULL` — **partial** index for cross-scan
  "which hosts/scans were hit by CVE-2021-44228" queries. Partial because a meaningful share
  of findings are non-CVE config/cert checks; indexing their `NULL` cve_id would waste space
  for zero query benefit (`NULL` never satisfies an equality lookup anyway).

`plugin_id` has no index: no stated query pattern groups/filters by plugin today. Add one in a
future milestone if profiling shows it's needed — avoid a write-cost index nobody reads yet.

---

## 8. `sync_state`

The delta-sync watermark table. This is what prevents re-downloading the entire NVD dataset on
every run.

```sql
CREATE TABLE sync_state (
    feed                 TEXT    NOT NULL PRIMARY KEY CHECK (feed IN ('nvd','kev','epss')),
    last_sync_started      TEXT,
    last_sync_completed     TEXT,
    last_mod_watermark      TEXT,   -- NVD: the lastModEndDate cursor of the most recently
                                    -- *successfully completed* sync window (advance the
                                    -- watermark only after the window's data is durably
                                    -- committed, never before, so a crash mid-sync re-runs
                                    -- the same window instead of skipping it).
                                    -- KEV/EPSS: local ingestion date of the last successful pull
                                    -- (both feeds are always full-file pulls; there is no
                                    -- remote delta cursor to track, this column just records
                                    -- "we already have today's file").
    total_records          INTEGER NOT NULL DEFAULT 0,
    status                 TEXT    NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','running','success','error')),
    last_error             TEXT
) WITHOUT ROWID;

-- Seed the three known feeds so application code only ever UPDATEs, never branches on
-- INSERT-vs-UPDATE.
INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('nvd', 'idle', 0);
INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('kev', 'idle', 0);
INSERT OR IGNORE INTO sync_state (feed, status, total_records) VALUES ('epss', 'idle', 0);
```

`WITHOUT ROWID`: 3 rows total, PK-only access (`UPDATE sync_state SET ... WHERE feed = ?`), no
secondary indexes.

**NVD delta-sync procedure this table supports** (binding on the sync writer /
whichever component runs the scheduled sync):

1. Read `last_mod_watermark` for `feed = 'nvd'`. If `NULL`, this is the initial bulk load —
   start from the NVD dataset's earliest date and page through the full CVE corpus.
2. Otherwise, sync from `lastModStartDate = last_mod_watermark` to `lastModEndDate = min(now,
   last_mod_watermark + 120 days)` (NVD API 2.0 caps each window at 120 days).
3. Page with `startIndex`/`resultsPerPage` (up to 2000) until the window is exhausted.
4. Upsert every returned CVE (see §9) inside one transaction per page/window.
5. Only after a window's data is committed, `UPDATE sync_state SET last_mod_watermark =
   <that window's lastModEndDate>, last_sync_completed = now(), status = 'success'`.
6. If `now - last_mod_watermark > 120 days`, repeat from step 2 for the next window until
   caught up to the present — this is what makes the sync incremental instead of one giant
   window.

---

## 9. Query pattern reference (parameterized; illustrative for the engine and plugin layers)

All statements are prepared with `?` bound parameters. **Never string-concatenate a CVE ID,
host, version string, or any other external/detected value into SQL text.**

**CVE upsert (NVD sync, per page):**

```sql
INSERT INTO cves (cve_id, published, last_modified, description,
                   cvss_v3_vector, cvss_v3_base_score, cvss_v3_severity,
                   cvss_v2_vector, cvss_v2_base_score, cvss_v2_severity,
                   severity, source, ingested_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'nvd', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT (cve_id) DO UPDATE SET
    last_modified = excluded.last_modified,
    description = excluded.description,
    cvss_v3_vector = excluded.cvss_v3_vector,
    cvss_v3_base_score = excluded.cvss_v3_base_score,
    cvss_v3_severity = excluded.cvss_v3_severity,
    cvss_v2_vector = excluded.cvss_v2_vector,
    cvss_v2_base_score = excluded.cvss_v2_base_score,
    cvss_v2_severity = excluded.cvss_v2_severity,
    severity = excluded.severity,
    source = 'nvd',              -- an NVD sync always promotes a placeholder row to 'nvd'
    ingested_at = excluded.ingested_at;
```

**CPE match row upsert (per configuration node under a CVE):**

```sql
INSERT INTO cve_cpe_matches (cve_id, cpe23_uri, part, vendor, product, version,
                              version_start_including, version_start_excluding,
                              version_end_including, version_end_excluding, vulnerable)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (cve_id, cpe23_uri, version_start_including, version_start_excluding,
             version_end_including, version_end_excluding, vulnerable)
DO NOTHING;
```

**CPE candidate lookup (scan-time, per detected service):**

```sql
SELECT cve_id, version, version_start_including, version_start_excluding,
       version_end_including, version_end_excluding, vulnerable
FROM cve_cpe_matches
WHERE vendor = ? AND product = ?;
-- application code applies the version-range algorithm from §3 to this small candidate set
```

**KEV/EPSS reconciliation upsert** — required *before* inserting into `kev` or `epss` because
both tables carry a hard FK to `cves(cve_id)`, and either feed can reference a CVE ID the NVD
sync hasn't ingested yet (KEV/EPSS both update independently and sometimes faster than NVD):

```sql
INSERT INTO cves (cve_id, published, last_modified, description, severity, source, ingested_at)
VALUES (?, ?, ?, '', 0, 'placeholder', strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT (cve_id) DO NOTHING;   -- no-op if the CVE already exists (real or placeholder)

INSERT INTO kev (cve_id, date_added, vendor_project, product, vulnerability_name,
                  required_action, due_date, known_ransomware, notes, synced_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))
ON CONFLICT (cve_id) DO UPDATE SET
    date_added = excluded.date_added, due_date = excluded.due_date,
    required_action = excluded.required_action, known_ransomware = excluded.known_ransomware,
    notes = excluded.notes, synced_at = excluded.synced_at;
```

The placeholder row (`source = 'placeholder'`, `severity = 0`) is silently enriched the next
time the NVD sync's own upsert (above) runs against that `cve_id` — its `ON CONFLICT` branch
unconditionally sets `source = 'nvd'`, overwriting the placeholder. Report/CLI code that wants
to distinguish "we don't actually know anything about this CVE yet" from "confirmed severity
0" can check `source = 'placeholder'`.

**"Is this CVE in KEV / what's its EPSS?" (used while building a `scan_results` row):**

```sql
SELECT 1 FROM kev WHERE cve_id = ?;                          -- kev_flag
SELECT epss_score FROM epss WHERE cve_id = ?;                -- epss_score
```

**`scan_results` insert (per candidate `cve_id` evaluated against a detected service, one row per
CVE regardless of verdict — the M7 CPE-matching-caller slice, `src/db/scan_persist.c`; added
migration v2 (M7 CPE-caller slice), authorized 2026-07-22 for the `match_status` column):**

```sql
INSERT INTO scan_results (scan_id, host, port, service, plugin_id, cve_id, match_status,
                           severity, evidence, remediation, kev_flag, epss_score, detected_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'));
-- match_status is one of 'confirmed' | 'undetermined' | 'not_affected' -- the caller's
-- three-valued, order-independent aggregation of cytadel_cpe_match_evaluate() across every
-- cve_cpe_matches row for this cve_id (docs/contracts/cpe-matching.md SS3.2.3). A cve_id whose
-- only candidate rows are CYTADEL_CPE_MALFORMED_ROW never reaches this INSERT at all -- that is
-- a data-quality event (logged + counted), not a row.
-- severity/kev_flag/epss_score are bound from the "is this CVE in KEV / what's its EPSS?" query
-- above plus a `SELECT severity FROM cves WHERE cve_id = ?` lookup, all three point-in-time
-- snapshots per SS10 assumption 6.
```

**EPSS for a batch of CVE ids (report generation):**

```sql
SELECT cve_id, epss_score, percentile FROM epss WHERE cve_id IN (?, ?, ?, ...);
```

**Scan authorization + creation (the confirmation gate, must run before any packet leaves the
engine):**

```sql
INSERT INTO scans (started_at, target_spec, authorized_by, authorization_confirmed_at,
                    authorization_method, status)
VALUES (strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'), ?, 'running');
-- scan_id = sqlite3_last_insert_rowid(db)
-- malformed_data_count is omitted -- the column's own DEFAULT 0 (migration v3) applies; this
-- INSERT is unchanged by that migration.
```

**Durable malformed-data-count update (per `cytadel_scan_detect_and_persist()` call, M8 report
slice 2 -- `src/db/scan_persist.c`; added migration v3, authorized 2026-07-22):**

```sql
UPDATE scans SET malformed_data_count = malformed_data_count + ? WHERE scan_id = ?;
```

Run inside the SAME `BEGIN...COMMIT` transaction as every `scan_results` row that detection call
produces -- either both the rows and the incremented count are committed together, or neither is
(a fatal error anywhere in that call rolls back both).

**Report: findings for a scan, host-grouped, severity-sorted:**

```sql
SELECT host, port, service, plugin_id, cve_id, severity, evidence, remediation,
       kev_flag, epss_score, detected_at
FROM scan_results
WHERE scan_id = ?
ORDER BY host, port, severity DESC;
```

---

## 10. Assumptions other agents must honor

1. **CPE lookup key is `(vendor, product, version)`, not a full CPE URI.** The service
   detection code (engine C and/or Lua plugins) must resolve a parsed banner (e.g.
   `"OpenSSH_7.2p2"`) into this triple before querying `cve_cpe_matches` — that resolution
   (banner keyword → CPE-dictionary vendor/product) is a plugin-api/detection-rules concern,
   *not* something this schema provides. Flag for the plugin-API layer.
2. **`vendor` and `product` are stored lowercase**, matching the CPE 2.3 spec's own casing
   rule. Callers must lowercase their detected vendor/product before querying
   `idx_cpe_vendor_product` / `idx_cpe_product` — there are no functional `lower()` indexes,
   so a mismatched case silently returns zero rows rather than erroring.
3. **Version comparison is never done in SQL.** Any code that walks
   `cve_cpe_matches.version` / `version_start_*` / `version_end_*` must use a single shared
   CPE-2.3-spec version comparator (period/hyphen/underscore-delimited, numeric-vs-alpha
   component rules per §3). If the engine (C) and plugins (Lua) end up with two independently
   written comparators, they will disagree on edge cases (`"7.2p2"` vs `"7.2"`, `"1.1.1k"` vs
   `"1.1.1"`) and produce inconsistent CVE matches. This must be one implementation, exposed to
   Lua via the plugin API, not duplicated.
4. **Timestamp format is binding** (`YYYY-MM-DDTHH:MM:SS.sssZ`, UTC) for every writer touching
   this DB — sync jobs, the scan engine, report generation. Mixed formats break the
   lexicographic range queries this schema relies on (`idx_cves_last_modified`, the
   `sync_state` watermark comparison, `idx_scans_started_at`).
5. **`kev`/`epss` sync writers must run the placeholder-row upsert (§9) before their own
   insert**, because both tables carry a hard FK to `cves(cve_id)` and either feed can name a
   CVE the NVD sync hasn't reached yet. Skipping this step will hit `FOREIGN KEY constraint
   failed` and abort that sync transaction.
6. **`scan_results.severity`, `kev_flag`, and `epss_score` are point-in-time snapshots**, not
   live joins. Report code should read them directly from `scan_results`, not re-join
   `cves`/`kev`/`epss`, when the goal is "what did we find during this scan" — re-joining would
   silently show today's CVSS score/KEV status instead of what was true when the scan ran.
7. **`plugin_id` in `scan_results` has no DB-level validation** against a plugin registry —
   the plugin-api contract is the source of truth for valid plugin identifiers, this schema
   only stores whatever string the engine hands it.
8. **`PRAGMA foreign_keys = ON` must be set on every connection** (engine, sync writer, report
   generator, CLI tools) — it is not persisted in the database file and defaults to `OFF`.
   Forgetting it silently disables every `ON DELETE CASCADE`/`SET NULL` and FK integrity check
   in this schema.
9. **WAL mode requires a local filesystem** for the DB file — flagged for the sync/deployment layer when
   wiring the Docker test target / any future deployment.
