#!/usr/bin/env bash
# tests/integration/run_integration_test.sh -- M9 Phase 2: the full
# end-to-end integration test. See docs/build-plan.md's tests/integration/
# section and CYTADEL_ENABLE_INTEGRATION_TESTS (this script is what that
# CMake option/CTest label ultimately runs -- tests/integration/CMakeLists.txt
# registers it as a single CTest case labeled "integration").
#
# Orchestrates: compose build -> compose up (Phase-1 targets only) -> seed
# the fixture CVE DB -> run the REAL cytadel-scan binary (as its own
# container, on the SAME internal-only network as the targets) -> render
# the report (JSON + HTML) -> 5 composition assertions -> compose down -v.
#
# Requires Docker + the `docker compose` CLI plugin (v2+) and `jq` on the
# host running this script. Never runs as part of a plain `ctest -L unit`
# (see tests/integration/CMakeLists.txt's CYTADEL_ENABLE_INTEGRATION_TESTS
# gate, OFF by default).
#
# Every assertion below prints the REAL command output it is judging, not
# just a pass/fail line -- per this milestone's whole point: prove the
# pipeline composes, and if it does not, say exactly where with the real
# failing output (never fake data to force a green run).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"
FIXTURE_SQL="$SCRIPT_DIR/fixtures/seed.sql"

COMPOSE=(docker compose -f "$DOCKER_DIR/docker-compose.yml" -f "$DOCKER_DIR/docker-compose.scanner.yml")

# ssh-sshv1-stub and tls-legacy are deliberately excluded from this
# deterministic run: neither is needed by the 5 required composition
# assertions below (they exercise plugins this test does not assert on),
# and tls-legacy's whole point -- RC4/3DES/TLSv1-only -- is documented in
# docker/README.md as unreachable from essentially any currently-maintained
# OpenSSL client, including this scanner image's own libssl3, which would
# only add a slow/flaky TLS-handshake-failure path for zero assertion value.
#
# ssh-vulnerable IS built/started (needed for the dedicated composition-gap
# repro near the end of this script) but is DELIBERATELY NOT part of the
# PRIMARY scan's target spec below -- see that repro section for why:
# plugins/ssh_known_vulnerable_openssh.lua reports a real cve_id
# (CVE-2024-6387) that this fixture DB never seeds into `cves`, and
# src/db/scan_persist.c's cytadel_scan_persist_finding() inserts that cve_id
# straight into scan_results.cve_id, which carries a hard FK into cves(cve_id)
# -- with no local row for it, the INSERT hits a FOREIGN KEY constraint
# violation, which src/cli/scan_wiring.c treats as fatal and aborts
# persistence for EVERY SUBSEQUENT HOST in the run (main.c's `db_ok` latches
# false for the rest of the scan), which in turn flips the whole scan's
# `scans.status` to 'failed' -- breaking ASSERTION 5's status='completed'
# requirement for a reason that has nothing to do with assertion 5 itself.
# Keeping the 5 required, spec-mandated assertions on a scan that completes
# cleanly, and demonstrating this real, separate, high-value composition
# finding in its own clearly-labeled section further down (with real
# output, not asserted pass/fail), is more honest than either hiding the
# bug (excluding ssh-vulnerable entirely) or letting it silently break an
# unrelated required assertion.
BUILD_SERVICES=(ftp ssh-vulnerable telnet web)
UP_SERVICES=(ftp ssh-vulnerable telnet web db)
TARGET_SPEC="ftp,telnet,web,db"
PORT_SPEC="21,23,80,443,6379"

PASS_COUNT=0
FAIL_COUNT=0
FAILED_ASSERTIONS=()

pass() { PASS_COUNT=$((PASS_COUNT + 1)); echo "[PASS] $1"; }
fail() { FAIL_COUNT=$((FAIL_COUNT + 1)); FAILED_ASSERTIONS+=("$1"); echo "[FAIL] $1"; }
section() {
  echo
  echo "======================================================================"
  echo "== $1"
  echo "======================================================================"
}

cleanup() {
  section "TEARDOWN (compose down -v -- disposable, leaves nothing behind)"
  "${COMPOSE[@]}" down -v --remove-orphans || true
}
trap cleanup EXIT

section "BUILD: target images + the scanner image"
"${COMPOSE[@]}" build "${BUILD_SERVICES[@]}" scanner

section "COMPOSE UP: Phase-1 targets only (no scanner yet -- it runs as a one-off below)"
"${COMPOSE[@]}" up -d "${UP_SERVICES[@]}"
echo "Waiting for target daemons to finish starting..."
sleep 5
"${COMPOSE[@]}" ps

section "BOOTSTRAP: create+migrate CYTADEL_DB_PATH (this call is EXPECTED to fail -- no scans exist yet;"
echo "its only job is the side effect of cytadel_db_migrate() creating the schema before we seed it)"
set +e
"${COMPOSE[@]}" run --rm -T scanner report --latest --format json
BOOTSTRAP_RC=$?
set -e
echo "(bootstrap exit code: $BOOTSTRAP_RC)"

section "SEED: applying tests/integration/fixtures/seed.sql"
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner /data/cytadel-test.sqlite < "$FIXTURE_SQL"
echo "Real SQL -- fixture rows now in cve_cpe_matches:"
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner -header -column /data/cytadel-test.sqlite \
  "SELECT cve_id, vendor, product, version_end_excluding FROM cve_cpe_matches ORDER BY cve_id;"

section "SCAN: running the REAL cytadel-scan binary against the Phase-1 target"
SCAN_LOG="$(mktemp)"
"${COMPOSE[@]}" run --rm -T scanner \
  --i-am-authorized --authorized-by "m9-phase2-integration-test" --skip-discovery \
  --ports "$PORT_SPEC" "$TARGET_SPEC" 2>&1 | tee "$SCAN_LOG"
echo "--- end of real scan output (full log: $SCAN_LOG) ---"

section "REGRESSION GATE (M9 Gap #1, FIXED): the FTP banner must resolve a vsftpd CPE"
echo "History: docker/ftp/banner.txt used to REPLACE vsftpd's greeting with text lacking the 'vsFTPd '"
echo "marker src/net/cpe_map.c keys on, so FTP never resolved a CPE (counted unresolvable, never CVE-checked)."
echo "FIXED: banner.txt now carries the literal 'vsFTPd 3.0.3' (plus 'anonymous' for the anon plugin), so"
echo "cpe_map resolves port 21 to (vsftpd_project, vsftpd, 3.0.3). This asserts that end to end."
echo "Real grep of the scan output for the resolved vsftpd CPE (only FTP can produce this marker):"
grep -iE "cpe:2\.3:a:vsftpd_project:vsftpd" "$SCAN_LOG" || true
if grep -qiE "cpe:2\.3:a:vsftpd_project:vsftpd" "$SCAN_LOG"; then
  pass "gap1-regression: FTP resolves a vsftpd CPE (banner carries the 'vsFTPd <version>' marker cpe_map keys on)"
else
  fail "gap1-regression: FTP did NOT resolve a vsftpd CPE -- docker/ftp/banner.txt must contain 'vsFTPd <version>' (the cpe_map marker); the Gap #1 fix has regressed"
fi

section "REPORT: rendering JSON + HTML for the latest scan"
JSON1="$(mktemp)"
HTML1="$(mktemp)"
"${COMPOSE[@]}" run --rm -T scanner report --latest --format json > "$JSON1"
"${COMPOSE[@]}" run --rm -T scanner report --latest --format html > "$HTML1"
echo "--- report --latest --format json (first 4000 bytes) ---"
head -c 4000 "$JSON1"
echo
echo "--- end ---"

SCAN_ID="$(jq -r '.scan.scan_id' "$JSON1")"
echo "Resolved scan_id = $SCAN_ID"

# ---------------------------------------------------------------------------
# REGRESSION GATE (M9 Gap #2, FIXED): the tls_cert_hostname_mismatch plugin
# (100023) was structurally DEAD -- it reads KB fact Host/hostname, which
# src/net/host_scan.c never wrote, so it always returned early regardless of
# the cert. FIXED: host_scan.c now writes Host/hostname from the user-typed
# target spec for non-IP-literal targets. The `web` target is a hostname, and
# web:443 serves a cert whose CN is legacy-internal-app.example.invalid (does
# NOT cover "web"), so 100023 MUST now fire. This is the real-target gate on
# top of the deterministic unit gate (test_plugins_stock's engine-integration
# case): if the plugin ever goes dead again -- or host_scan stops writing
# Host/hostname -- this finding vanishes and this assertion fails.
# ---------------------------------------------------------------------------
section "REGRESSION GATE (Gap #2): tls_cert_hostname_mismatch (100023) fires against web:443's mismatched cert"
HOSTNAME_MISMATCH_COUNT="$(jq -r '[.findings[] | select(.plugin_id=="100023")] | length' "$JSON1")"
echo "Real jq: findings with plugin_id=100023 (hostname mismatch): $HOSTNAME_MISMATCH_COUNT"
jq -r '[.findings[] | select(.plugin_id=="100023") | {host, port, plugin_id, evidence}]' "$JSON1" || true
if [ "$HOSTNAME_MISMATCH_COUNT" -ge 1 ]; then
  pass "gap2-regression: plugin 100023 fired -- Host/hostname is written for name targets and the dead plugin is alive"
else
  fail "gap2-regression: plugin 100023 did NOT fire against web:443's mismatched cert -- either host_scan.c stopped writing Host/hostname or the plugin went dead again"
fi

# ---------------------------------------------------------------------------
# ASSERTION 1: expected direct plugin findings (non-CVE) reached the report,
# proving scan -> persist_finding -> report for direct findings, not only
# CVE matches.
# ---------------------------------------------------------------------------
section "ASSERTION 1: direct plugin findings reached the report"
# plugin_id -> what it proves (docker/README.md's services -> findings map).
# ssh-vulnerable's own plugin ids (100011, 100012) are intentionally NOT in
# this list -- ssh-vulnerable is not part of the primary scan's target spec
# (see the TARGET_SPEC comment above); they are exercised separately in the
# dedicated composition-gap repro near the end of this script instead.
#
# 100023 (tls_cert_hostname_mismatch) is ALSO intentionally not in this list
# -- see the dedicated composition-check paragraph right after this
# assertion for why it structurally cannot fire through the real pipeline
# at all, contrary to docker/README.md's and plugins/README.md's claims.
DIRECT_PLUGIN_IDS=(100001 100002 100036 100037 100032 100033 100034 100040 100041 100020 100022)
MISSING_DIRECT=()
for pid in "${DIRECT_PLUGIN_IDS[@]}"; do
  count=$(jq --arg pid "$pid" '[.findings[] | select(.plugin_id == $pid)] | length' "$JSON1")
  if [ "$count" -gt 0 ]; then
    echo "  plugin_id=$pid: $count row(s) -- present"
  else
    MISSING_DIRECT+=("$pid")
  fi
done
if [ "${#MISSING_DIRECT[@]}" -eq 0 ]; then
  pass "assertion1: every expected direct-finding plugin_id is present in the report"
else
  fail "assertion1: missing direct-finding plugin_id(s): ${MISSING_DIRECT[*]}"
fi
echo "Real jq output (a sample of direct findings -- host/port/plugin_id/evidence):"
jq '[.findings[] | select(.plugin_id | IN("100001","100002","100036","100037","100020","100022")) | {host, port, plugin_id, evidence}]' "$JSON1"

# (tls_cert_hostname_mismatch / 100023 is now gated by the "gap2-regression"
# assertion earlier in this script -- it fires against web:443's mismatched
# cert because host_scan.c writes Host/hostname for name targets. The former
# "CONFIRMED COMPOSITION GAP" block here is removed: it asserted the opposite,
# which is no longer true after the M9 Gap #2 fix.)

# ---------------------------------------------------------------------------
# ASSERTION 2: the seeded UNDECIDABLE reaches the report as 'undetermined'.
# ---------------------------------------------------------------------------
section "ASSERTION 2: the seeded UNDECIDABLE CVE renders as 'undetermined', never omitted/coerced"
UNDET_ROWS_JSON="$(jq '[.findings[] | select(.cve_id == "CVE-2026-10002")]' "$JSON1")"
echo "Real jq output for CVE-2026-10002:"
echo "$UNDET_ROWS_JSON"
UNDET_COUNT=$(echo "$UNDET_ROWS_JSON" | jq 'length')
UNDET_WRONG_STATUS=$(echo "$UNDET_ROWS_JSON" | jq '[.[] | select(.match_status != "undetermined")] | length')
if [ "$UNDET_COUNT" -gt 0 ] && [ "$UNDET_WRONG_STATUS" -eq 0 ]; then
  pass "assertion2(json): CVE-2026-10002 appears $UNDET_COUNT time(s), every occurrence match_status='undetermined'"
else
  fail "assertion2(json): CVE-2026-10002 did not render as undetermined (count=$UNDET_COUNT, wrong-status=$UNDET_WRONG_STATUS)"
fi
echo "Real grep against the rendered HTML report:"
grep -n "CVE-2026-10002" "$HTML1" || true
if grep -q "CVE-2026-10002" "$HTML1" && grep -q "Could not determine -- manual review needed" "$HTML1"; then
  pass "assertion2(html): CVE-2026-10002 and the undetermined-badge text both appear in the HTML report"
else
  fail "assertion2(html): CVE-2026-10002 / the undetermined-badge text was not found in the rendered HTML report"
fi

# ---------------------------------------------------------------------------
# ASSERTION 3: the MALFORMED row surfaces the data-quality banner and
# scans.malformed_data_count.
# ---------------------------------------------------------------------------
section "ASSERTION 3: the MALFORMED cve_cpe_matches row surfaces the data-quality banner"
MALFORMED_COUNT=$(jq '.scan.malformed_data_count' "$JSON1")
NOT_FOUND_1003=$(jq '[.findings[] | select(.cve_id == "CVE-2026-10003")] | length' "$JSON1")
echo "scan.malformed_data_count = $MALFORMED_COUNT"
echo "scan_results rows for CVE-2026-10003 (must be 0 -- a malformed row never produces a scan_results row): $NOT_FOUND_1003"
if [ "$MALFORMED_COUNT" -gt 0 ] && [ "$NOT_FOUND_1003" -eq 0 ]; then
  pass "assertion3(json): malformed_data_count=$MALFORMED_COUNT > 0, and CVE-2026-10003 produced zero scan_results rows"
else
  fail "assertion3(json): expected malformed_data_count > 0 and 0 rows for CVE-2026-10003; got malformed_data_count=$MALFORMED_COUNT rows=$NOT_FOUND_1003"
fi
echo "Real grep against the rendered HTML report:"
grep -n "record(s) had malformed data -- results may be incomplete" "$HTML1" || true
if grep -q "record(s) had malformed data -- results may be incomplete" "$HTML1"; then
  pass "assertion3(html): the data-quality banner text is present in the rendered HTML report"
else
  fail "assertion3(html): the data-quality banner text is NOT present in the rendered HTML report"
fi
echo "Real SQL: scans.malformed_data_count for this scan (durable total, same transaction as the rows):"
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner -header -column /data/cytadel-test.sqlite \
  "SELECT scan_id, malformed_data_count FROM scans WHERE scan_id = $SCAN_ID;"

# ---------------------------------------------------------------------------
# ASSERTION 4: snapshot holds through the real pipeline.
# ---------------------------------------------------------------------------
section "ASSERTION 4: scan_results.severity is a point-in-time snapshot, not a live join"
BEFORE_SEVERITY=$(jq '[.findings[] | select(.cve_id == "CVE-2026-10001" and .match_status == "confirmed")][0].severity' "$JSON1")
echo "Snapshot severity recorded at scan time for CVE-2026-10001: $BEFORE_SEVERITY (fixture seeded it as 3 == High)"

echo "Real SQL: mutating the LIVE cves.severity for CVE-2026-10001 to 0 (Info)..."
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner /data/cytadel-test.sqlite \
  "UPDATE cves SET severity = 0, cvss_v3_severity = 'NONE', cvss_v3_base_score = 0.0 WHERE cve_id = 'CVE-2026-10001';"
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner -header -column /data/cytadel-test.sqlite \
  "SELECT cve_id, severity, cvss_v3_severity FROM cves WHERE cve_id = 'CVE-2026-10001';"

JSON2="$(mktemp)"
"${COMPOSE[@]}" run --rm -T scanner report --latest --format json > "$JSON2"
AFTER_SEVERITY=$(jq '[.findings[] | select(.cve_id == "CVE-2026-10001" and .match_status == "confirmed")][0].severity' "$JSON2")
echo "Re-rendered report's severity for CVE-2026-10001 AFTER the live cves.severity mutation: $AFTER_SEVERITY"
if [ "$BEFORE_SEVERITY" = "3" ] && [ "$AFTER_SEVERITY" = "3" ]; then
  pass "assertion4: report still shows severity=3 (the scan-time snapshot) after cves.severity was live-mutated to 0"
else
  fail "assertion4: expected severity to read 3 both before and after the live mutation; got before=$BEFORE_SEVERITY after=$AFTER_SEVERITY"
fi

# ---------------------------------------------------------------------------
# ASSERTION 5: the scans row is the durable authorization record.
# ---------------------------------------------------------------------------
section "ASSERTION 5: the scans row is the durable authorization record"
echo "Real SQL: the scans row for scan_id=$SCAN_ID:"
"${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner -header -column /data/cytadel-test.sqlite \
  "SELECT scan_id, status, authorized_by, authorization_method, authorization_confirmed_at, target_spec FROM scans WHERE scan_id = $SCAN_ID;"
SCANS_COUNT=$("${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner /data/cytadel-test.sqlite \
  "SELECT COUNT(*) FROM scans WHERE scan_id = $SCAN_ID AND status = 'completed' AND authorization_method = 'flag' AND authorized_by = 'm9-phase2-integration-test';")
echo "matching-row count (status=completed, method=flag, authorized_by recorded) = $SCANS_COUNT"
if [ "$SCANS_COUNT" = "1" ]; then
  pass "assertion5: exactly one scans row for scan_id=$SCAN_ID with status=completed and the recorded authorization fields"
else
  fail "assertion5: expected exactly 1 matching scans row, got $SCANS_COUNT"
fi

# ---------------------------------------------------------------------------
# BONUS COMPOSITION FINDING (not one of the 5 required assertions, not
# gating pass/fail): a direct-plugin heuristic CVE that isn't in the local
# `cves` table poisons persistence for the REST OF THE SCAN. Reproduced here
# in isolation, against the REAL binary, with real output -- see the
# TARGET_SPEC comment above for why the primary scan excludes ssh-vulnerable.
# ---------------------------------------------------------------------------
section "REGRESSION GATE (M9 Gap #3, FIXED): an un-seeded plugin-reported CVE must NOT poison the scan"
echo "History: scanning ssh-vulnerable makes ssh_known_vulnerable_openssh heuristically report"
echo "cve_id=CVE-2024-6387, which this fixture DB never seeds into 'cves'. Before the fix, the hard FK"
echo "into cves(cve_id) made the INSERT hit SQLITE_CONSTRAINT, which was treated as fatally as a broken"
echo "DB connection -- aborting persistence for the rest of the host AND every subsequent host, and"
echo "flipping scans.status to 'failed'. FIXED (user-approved placeholder-FK dance + per-row resilience):"
echo "cytadel_scan_persist_finding() now grammar-validates the cve_id, INSERT-OR-IGNOREs a placeholder"
echo "cves row (source='placeholder', exactly as KEV/EPSS do), and a single-row SQLITE_CONSTRAINT is"
echo "per-row skip-and-log (ERR_ROW_SKIPPED), never a scan-wide fatal abort. This section now GUARDS that"
echo "fix: the scan must COMPLETE, the CVE finding must persist, and a placeholder cves row must exist."
BONUS_LOG="$(mktemp)"
set +e
"${COMPOSE[@]}" run --rm -T scanner \
  --i-am-authorized --authorized-by "m9-phase2-integration-test" --skip-discovery \
  --ports 22 ssh-vulnerable 2>&1 | tee "$BONUS_LOG"
BONUS_RC=$?
set -e
echo "--- end of real bonus-repro scan output (exit code: $BONUS_RC) ---"

echo
echo "Real grep for the FK-violation + cascade log lines:"
grep -n "FOREIGN KEY constraint failed\|no further hosts will be persisted" "$BONUS_LOG" || true

BONUS_JSON="$(mktemp)"
"${COMPOSE[@]}" run --rm -T scanner report --latest --format json > "$BONUS_JSON"
BONUS_SCAN_ID="$(jq -r '.scan.scan_id' "$BONUS_JSON")"
BONUS_STATUS="$(jq -r '.scan.status' "$BONUS_JSON")"
BONUS_FINDING_COUNT="$(jq '.findings | length' "$BONUS_JSON")"
echo
echo "scan_id=$BONUS_SCAN_ID status=$BONUS_STATUS findings_persisted=$BONUS_FINDING_COUNT"
echo "(ssh-vulnerable's plugin schedule reports 2 findings -- ssh_version_disclosure (100012, no CVE) and"
echo " ssh_known_vulnerable_openssh (100011, cve_id=CVE-2024-6387) -- see which of them actually made it"
echo " into scan_results below, real jq output:)"
jq '[.findings[] | {plugin_id, cve_id, evidence}]' "$BONUS_JSON"

# Gap #3 regression assertions (the fix must hold end-to-end):
#   (a) the scan COMPLETES -- one un-synced plugin CVE no longer poisons persistence.
#   (b) the plugin-reported CVE finding is actually persisted (not silently dropped).
#   (c) a placeholder cves row (source='placeholder') was created for it -- proving the
#       placeholder-FK dance ran rather than the finding being discarded.
BONUS_HAS_CVE="$(jq -r '[.findings[] | select(.cve_id=="CVE-2024-6387")] | length' "$BONUS_JSON")"
BONUS_PLACEHOLDER="$("${COMPOSE[@]}" run --rm -T --entrypoint sqlite3 scanner /data/cytadel-test.sqlite \
  "SELECT source FROM cves WHERE cve_id = 'CVE-2024-6387';" 2>/dev/null | tr -d '[:space:]')"
echo
echo "Real jq/SQL: status=$BONUS_STATUS  cve-2024-6387 findings=$BONUS_HAS_CVE  cves.source='$BONUS_PLACEHOLDER'"

if [ "$BONUS_STATUS" = "completed" ] && [ "$BONUS_HAS_CVE" -ge 1 ] && [ "$BONUS_PLACEHOLDER" = "placeholder" ]; then
  pass "gap3-regression: un-seeded plugin CVE did NOT poison the scan (status=completed, finding persisted, placeholder cves row created)"
else
  fail "gap3-regression: expected status=completed + CVE-2024-6387 persisted + a source='placeholder' cves row; got status=$BONUS_STATUS findings=$BONUS_HAS_CVE source='$BONUS_PLACEHOLDER' -- the Gap #3 poisoning fix has regressed"
fi

section "RESULT"
echo "PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "FAILED ASSERTIONS: ${FAILED_ASSERTIONS[*]}"
  exit 1
fi
echo "ALL ASSERTIONS PASSED"
exit 0
