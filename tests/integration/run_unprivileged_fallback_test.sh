#!/usr/bin/env bash
# tests/integration/run_unprivileged_fallback_test.sh -- M9 Phase 3.
#
# Proves, by OBSERVED behavior (never by assumption), that
# src/net/discovery.c's TCP-ping fallback fires when raw ICMP sockets are
# unavailable (the unprivileged-scanning position an operator depends on),
# AND that the SAME test would catch a regression where the fallback
# silently stopped working -- by also proving the fallback marker is ABSENT
# (real ICMP is used instead) in a contrast run where raw ICMP genuinely is
# available. See docker/docker-compose.scanner-unprivileged.yml's header
# comment for the full design rationale (why this needs two different
# scanner images, not one).
#
# Registered as its own CTest case (tests/integration/CMakeLists.txt),
# gated behind the SAME CYTADEL_ENABLE_INTEGRATION_TESTS option / "-L
# integration" label as run_integration_test.sh -- never runs as part of a
# plain `ctest -L unit`.
#
# Every assertion below prints the REAL log line it is judging, not just a
# pass/fail line.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DOCKER_DIR="$REPO_ROOT/docker"

COMPOSE=(docker compose -f "$DOCKER_DIR/docker-compose.yml" -f "$DOCKER_DIR/docker-compose.scanner-unprivileged.yml")

# `web` is the only target needed: it has ports 80 AND 443 open, both of
# which are also in src/net/tcp_ping.c's CYTADEL_TCP_PING_PORTS probe list
# (80, 443, 22) -- so the TCP-ping discovery fallback itself (not just the
# subsequent port scan) can actually succeed against it. Real, unmodified
# nginx 1.18.0 (EOL) also guarantees at least one direct-plugin finding
# (http_server_version_disclosure, 100036) so "the scan still worked" has
# something concrete to assert on.
BUILD_SERVICES=(web)
UP_SERVICES=(web)
TARGET_SPEC="web"
PORT_SPEC="80,443"

# Marker strings this test asserts on -- copied verbatim from the actual
# cytadel_log_debug()/cytadel_log_info() call sites (src/net/discovery.c,
# src/net/host_scan.c), never invented. If these ever stop matching the
# real source, this test must be updated to match the source, not the
# other way around.
MARKER_FALLBACK_DEBUG="used TCP ping (fallback)"
MARKER_ICMP_DEBUG="used ICMP echo"
MARKER_FALLBACK_INFO="method=tcp-ping"
MARKER_ICMP_INFO="method=icmp"

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

section "BUILD: target image + BOTH scanner variants (scanner-unprivileged, scanner-rawcapable)"
"${COMPOSE[@]}" build "${BUILD_SERVICES[@]}" scanner-unprivileged scanner-rawcapable

section "COMPOSE UP: Phase-1 'web' target only"
"${COMPOSE[@]}" up -d "${UP_SERVICES[@]}"
echo "Waiting for target daemon to finish starting..."
sleep 5
"${COMPOSE[@]}" ps

# ---------------------------------------------------------------------------
# RUN A: the real unprivileged scenario -- cap_drop:[ALL], non-root,
# UNMODIFIED scanner image. Real host discovery runs (no --skip-discovery:
# that is the entire point of this test). --log-level debug so the
# discovery-method marker (logged at debug level) is actually emitted.
# ---------------------------------------------------------------------------
section "RUN A (FALLBACK): scanner-unprivileged (cap_drop:[ALL], non-root) scanning 'web' with REAL discovery"
LOG_A="$(mktemp)"
set +e
"${COMPOSE[@]}" run --rm -T scanner-unprivileged \
  --i-am-authorized --authorized-by "m9-phase3-unprivileged-fallback" --log-level debug \
  --ports "$PORT_SPEC" "$TARGET_SPEC" 2>&1 | tee "$LOG_A"
RUN_A_RC=${PIPESTATUS[0]}
set -e
echo "--- end of RUN A output (exit code: $RUN_A_RC, full log: $LOG_A) ---"

# ---------------------------------------------------------------------------
# RUN B: the contrast / negative-control scenario -- file-capability
# (cap_net_raw+ep) scanner image, capability bounding set left intact (no
# cap_drop). Still non-root, still no --privileged. Real host discovery.
# ---------------------------------------------------------------------------
section "RUN B (CONTRAST): scanner-rawcapable (setcap cap_net_raw+ep, NET_RAW not dropped) scanning 'web' with REAL discovery"
LOG_B="$(mktemp)"
set +e
"${COMPOSE[@]}" run --rm -T scanner-rawcapable \
  --i-am-authorized --authorized-by "m9-phase3-rawcapable-contrast" --log-level debug \
  --ports "$PORT_SPEC" "$TARGET_SPEC" 2>&1 | tee "$LOG_B"
RUN_B_RC=${PIPESTATUS[0]}
set -e
echo "--- end of RUN B output (exit code: $RUN_B_RC, full log: $LOG_B) ---"

# ---------------------------------------------------------------------------
# ASSERTION 1: RUN A (cap-dropped, non-root, unmodified image) shows the
# TCP-ping fallback marker and does NOT show the raw-ICMP marker.
# ---------------------------------------------------------------------------
section "ASSERTION 1: RUN A used the TCP-ping fallback, never raw ICMP"
echo "Real grep of LOG_A for the debug-level fallback marker ('$MARKER_FALLBACK_DEBUG'):"
grep -n "$MARKER_FALLBACK_DEBUG" "$LOG_A" || true
echo "Real grep of LOG_A for the info-level per-host summary marker ('$MARKER_FALLBACK_INFO'):"
grep -n "$MARKER_FALLBACK_INFO" "$LOG_A" || true
FALLBACK_DEBUG_COUNT_A=$(grep -c "$MARKER_FALLBACK_DEBUG" "$LOG_A" || true)
FALLBACK_INFO_COUNT_A=$(grep -c "$MARKER_FALLBACK_INFO" "$LOG_A" || true)
ICMP_DEBUG_COUNT_A=$(grep -c "$MARKER_ICMP_DEBUG" "$LOG_A" || true)
ICMP_INFO_COUNT_A=$(grep -c "$MARKER_ICMP_INFO" "$LOG_A" || true)
echo "counts: fallback(debug)=$FALLBACK_DEBUG_COUNT_A fallback(info)=$FALLBACK_INFO_COUNT_A icmp(debug)=$ICMP_DEBUG_COUNT_A icmp(info)=$ICMP_INFO_COUNT_A"
if [ "$FALLBACK_DEBUG_COUNT_A" -gt 0 ] && [ "$FALLBACK_INFO_COUNT_A" -gt 0 ] && \
   [ "$ICMP_DEBUG_COUNT_A" -eq 0 ] && [ "$ICMP_INFO_COUNT_A" -eq 0 ]; then
  pass "assertion1: RUN A shows the TCP-ping fallback marker(s) and zero raw-ICMP marker(s)"
else
  fail "assertion1: expected fallback markers present and ICMP markers absent in RUN A; got fallback(debug)=$FALLBACK_DEBUG_COUNT_A fallback(info)=$FALLBACK_INFO_COUNT_A icmp(debug)=$ICMP_DEBUG_COUNT_A icmp(info)=$ICMP_INFO_COUNT_A"
fi

# ---------------------------------------------------------------------------
# ASSERTION 2 (NEGATIVE CONTROL): RUN B (raw-capable contrast image) shows
# the raw-ICMP marker and does NOT show the TCP-ping fallback marker --
# proves assertion 1 is not a tautology / would catch a real regression.
# ---------------------------------------------------------------------------
section "ASSERTION 2 (NEGATIVE CONTROL): RUN B used raw ICMP, never the TCP-ping fallback"
echo "Real grep of LOG_B for the debug-level raw-ICMP marker ('$MARKER_ICMP_DEBUG'):"
grep -n "$MARKER_ICMP_DEBUG" "$LOG_B" || true
echo "Real grep of LOG_B for the info-level per-host summary marker ('$MARKER_ICMP_INFO'):"
grep -n "$MARKER_ICMP_INFO" "$LOG_B" || true
FALLBACK_DEBUG_COUNT_B=$(grep -c "$MARKER_FALLBACK_DEBUG" "$LOG_B" || true)
FALLBACK_INFO_COUNT_B=$(grep -c "$MARKER_FALLBACK_INFO" "$LOG_B" || true)
ICMP_DEBUG_COUNT_B=$(grep -c "$MARKER_ICMP_DEBUG" "$LOG_B" || true)
ICMP_INFO_COUNT_B=$(grep -c "$MARKER_ICMP_INFO" "$LOG_B" || true)
echo "counts: fallback(debug)=$FALLBACK_DEBUG_COUNT_B fallback(info)=$FALLBACK_INFO_COUNT_B icmp(debug)=$ICMP_DEBUG_COUNT_B icmp(info)=$ICMP_INFO_COUNT_B"
if [ "$ICMP_DEBUG_COUNT_B" -gt 0 ] && [ "$ICMP_INFO_COUNT_B" -gt 0 ] && \
   [ "$FALLBACK_DEBUG_COUNT_B" -eq 0 ] && [ "$FALLBACK_INFO_COUNT_B" -eq 0 ]; then
  pass "assertion2(negative control): RUN B shows the raw-ICMP marker(s) and zero fallback marker(s) -- proves assertion 1 has teeth"
else
  fail "assertion2(negative control): expected ICMP markers present and fallback markers absent in RUN B; got fallback(debug)=$FALLBACK_DEBUG_COUNT_B fallback(info)=$FALLBACK_INFO_COUNT_B icmp(debug)=$ICMP_DEBUG_COUNT_B icmp(info)=$ICMP_INFO_COUNT_B"
fi

# ---------------------------------------------------------------------------
# ASSERTION 3: the unprivileged (fallback) scan STILL WORKED -- host
# detected up, ports open, at least one plugin finding reached the report.
# The fallback is worthless if it only logs a marker but the scan itself
# never actually completes.
# ---------------------------------------------------------------------------
section "ASSERTION 3: RUN A's unprivileged scan still detected the host/ports/service"
echo "Real grep of LOG_A for 'Host state: up':"
grep -n "Host state: up" "$LOG_A" || true
echo "Real grep of LOG_A for open ports 80 and 443:"
grep -n "80/tcp open\|443/tcp open" "$LOG_A" || true
HOST_UP_A=$(grep -c "Host state: up" "$LOG_A" || true)
PORT80_OPEN_A=$(grep -c "80/tcp open" "$LOG_A" || true)
PORT443_OPEN_A=$(grep -c "443/tcp open" "$LOG_A" || true)
if [ "$HOST_UP_A" -gt 0 ] && [ "$PORT80_OPEN_A" -gt 0 ] && [ "$PORT443_OPEN_A" -gt 0 ]; then
  pass "assertion3: RUN A's unprivileged scan still detected the host as up with both ports open"
else
  fail "assertion3: expected host-up + both ports open in RUN A; got host_up=$HOST_UP_A port80=$PORT80_OPEN_A port443=$PORT443_OPEN_A"
fi

section "ASSERTION 4: RUN A's report shows the scan completed with real findings persisted"
JSON_A="$(mktemp)"
"${COMPOSE[@]}" run --rm -T scanner-unprivileged report --latest --format json > "$JSON_A"
echo "--- report --latest --format json (first 2000 bytes) ---"
head -c 2000 "$JSON_A"
echo
echo "--- end ---"
SCAN_STATUS_A="$(jq -r '.scan.status' "$JSON_A")"
FINDINGS_COUNT_A="$(jq '.findings | length' "$JSON_A")"
VERSION_DISCLOSURE_COUNT_A="$(jq '[.findings[] | select(.plugin_id == "100036")] | length' "$JSON_A")"
echo "scan.status=$SCAN_STATUS_A findings_count=$FINDINGS_COUNT_A plugin_id=100036(http_server_version_disclosure) count=$VERSION_DISCLOSURE_COUNT_A"
if [ "$SCAN_STATUS_A" = "completed" ] && [ "$FINDINGS_COUNT_A" -gt 0 ] && [ "$VERSION_DISCLOSURE_COUNT_A" -gt 0 ]; then
  pass "assertion4: RUN A's scan completed and produced a report with real plugin findings"
else
  fail "assertion4: expected status=completed, findings>0, plugin_id=100036 present; got status=$SCAN_STATUS_A findings=$FINDINGS_COUNT_A v100036=$VERSION_DISCLOSURE_COUNT_A"
fi

section "RESULT"
echo "PASS=$PASS_COUNT FAIL=$FAIL_COUNT"
if [ "$FAIL_COUNT" -gt 0 ]; then
  echo "FAILED ASSERTIONS: ${FAILED_ASSERTIONS[*]}"
  exit 1
fi
echo "ALL ASSERTIONS PASSED"
exit 0
