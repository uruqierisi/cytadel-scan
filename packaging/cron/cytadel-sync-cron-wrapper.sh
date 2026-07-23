#!/usr/bin/env bash
# packaging/cron/cytadel-sync-cron-wrapper.sh -- M9 Phase 4b.
#
# The cron alternative to cytadel-sync.service/.timer (packaging/systemd/)
# for hosts with no systemd. Invoked by root from a cron entry (see
# packaging/cron/cytadel-sync.cron) -- root privilege here is used ONLY to
# (a) read the 0600 root-only EnvironmentFile and (b) drop to an
# unprivileged system user before ever executing cytadel-scan itself. The
# NVD API key never appears on the crontab line, never on this script's own
# command line, and is never echoed/logged by this script.
#
# Same non-overlap discipline as the systemd timer (which gets it for free
# from "a non-templated unit only ever has one active instance"): this
# script wraps the actual invocation in a non-blocking flock, so a run that
# is still in progress when cron fires again causes the SECOND invocation
# to exit immediately rather than run concurrently.

set -euo pipefail

ENV_FILE="/etc/cytadel/cytadel.env"
LOCK_FILE="/run/lock/cytadel-sync.lock"
RUN_AS_USER="cytadel-sync"
BINARY="/usr/local/bin/cytadel-scan"

log() {
    # Plain stderr -- cron's own MTA/redirect (see cytadel-sync.cron's own
    # comment) is this script's only logging destination; no attempt to
    # duplicate journald's log-rotation/retention behavior here.
    echo "cytadel-sync-cron-wrapper: $*" >&2
}

if [ "$(id -u)" -ne 0 ]; then
    log "must be run as root (the cron entry should invoke it as root, then it drops to '$RUN_AS_USER' itself)"
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    log "missing $ENV_FILE -- see packaging/README.md for the required setup"
    exit 1
fi

# Refuse to run against a loosely-permissioned secret file rather than
# silently trusting it -- fails loud, not silent-degrade.
env_file_mode="$(stat -c '%a' "$ENV_FILE")"
if [ "$env_file_mode" != "600" ]; then
    log "refusing to run -- $ENV_FILE must be mode 0600 (got $env_file_mode); run: sudo chmod 0600 $ENV_FILE"
    exit 1
fi
env_file_owner="$(stat -c '%U' "$ENV_FILE")"
if [ "$env_file_owner" != "root" ]; then
    log "refusing to run -- $ENV_FILE must be owned by root (got $env_file_owner)"
    exit 1
fi

if ! id "$RUN_AS_USER" >/dev/null 2>&1; then
    log "system user '$RUN_AS_USER' does not exist -- see packaging/README.md's cron setup steps"
    exit 1
fi

if [ ! -x "$BINARY" ]; then
    log "$BINARY not found or not executable -- see packaging/README.md ('there is no cmake --install target yet; the binary is copied into place by hand')"
    exit 1
fi

# `set -a` exports every name this sources (CYTADEL_NVD_API_KEY,
# CYTADEL_DB_PATH, and any optional overrides) so they ride through
# `runuser --preserve-environment` below into the unprivileged process's
# environment -- never written back out, never echoed, never passed as a
# CLI argument.
set -a
# shellcheck source=/dev/null
. "$ENV_FILE"
set +a

if [ -z "${CYTADEL_NVD_API_KEY:-}" ] || [ "$CYTADEL_NVD_API_KEY" = "REPLACE_ME_WITH_A_REAL_NVD_API_KEY" ]; then
    log "warning: CYTADEL_NVD_API_KEY is unset or still the placeholder from cytadel.env.example -- sync will run at the lower anonymous NVD rate limit"
fi
if [ -z "${CYTADEL_DB_PATH:-}" ]; then
    log "CYTADEL_DB_PATH is not set in $ENV_FILE -- refusing to run (cytadel-scan sync requires it)"
    exit 1
fi

# -n: non-blocking -- a still-running previous invocation makes this exit
# immediately (nonzero) instead of queuing up a second concurrent sync.
# --preserve-environment: forwards the env vars sourced above through to
# the unprivileged user; runuser drops root privileges for every subsequent
# instruction, including the exec of cytadel-scan itself.
exec flock -n "$LOCK_FILE" \
    runuser --preserve-environment -u "$RUN_AS_USER" -- "$BINARY" sync
