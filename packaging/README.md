# Cytadel Scan -- packaging (M9 Phase 4b)

This directory holds the operator-facing packaging for scheduling
`cytadel-scan sync` (M9 Phase 4a) -- the DETECTION-ONLY, target-free
subcommand that catches this host's local vulnerability database up to the
public NVD CVE feed. It never scans, probes, or contacts any
operator-specified target, so it never touches the mandatory startup
authorization gate (the mandatory authorization-gate rule) -- see `src/cli/sync_cmd.h`'s own
header comment.

```
packaging/
├── README.md                          -- this file
├── cytadel.env.example                -- template for /etc/cytadel/cytadel.env
├── systemd/
│   ├── cytadel-sync.service           -- the sync job itself
│   └── cytadel-sync.timer             -- the daily schedule
└── cron/
    ├── cytadel-sync.cron              -- /etc/cron.d/ drop-in (non-systemd hosts)
    └── cytadel-sync-cron-wrapper.sh   -- reads the env file, drops privileges, runs it
```

Prefer **systemd** (`packaging/systemd/`) on any host that has it; the
**cron** alternative (`packaging/cron/`) exists for hosts that don't.

## Key hygiene (read this before installing either path)

`CYTADEL_NVD_API_KEY` (src/net/nvd_fetch.h's `CYTADEL_NVD_API_KEY_ENV_VAR`)
and `CYTADEL_DB_PATH` must come from **one place only**: a root-only-readable
(`0600`) file at `/etc/cytadel/cytadel.env`. Neither value is ever:

- written inline into a systemd unit file or a crontab line,
- passed as a `cytadel-scan` command-line argument (arguments are visible
  to any local user via `ps`/`/proc/<pid>/cmdline` -- an environment
  variable of a process you don't have permission to `/proc/<pid>/environ`
  read is not), or
- printed to the journal/a log file: every `cytadel_log_*()` call in this
  codebase that mentions the key prints the **environment variable's name**
  only, never its value (verified during the M7 NVD-fetch security review),
  and `cytadel-scan sync`'s own stdout summary
  (`src/cli/sync_cmd.c::cytadel_sync_cmd_run()`) only ever prints
  window/page/CVE **counts**.

No real (or realistic-looking) key is committed anywhere in this
repository. `packaging/cytadel.env.example`'s placeholder is the literal
string `REPLACE_ME_WITH_A_REAL_NVD_API_KEY` -- deliberately not shaped like
a real key.

## Option A -- systemd (preferred)

### 1. Build and install the binary

This project does not (yet) ship a `cmake --install` target, so the binary
is copied into place by hand:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Release <your usual configure flags>
cmake --build build --target cytadel-scan -j"$(nproc)"
sudo install -o root -g root -m 0755 build/src/cli/cytadel-scan /usr/local/bin/cytadel-scan
```

(`packaging/systemd/cytadel-sync.service`'s `ExecStart=` points at
`/usr/local/bin/cytadel-scan` -- edit that line if you install elsewhere.)

### 2. Create the protected environment file

```sh
sudo mkdir -p /etc/cytadel
sudo install -o root -g root -m 0600 /dev/null /etc/cytadel/cytadel.env
sudo cp packaging/cytadel.env.example /etc/cytadel/cytadel.env
sudo chmod 0600 /etc/cytadel/cytadel.env   # cp above may reset the mode -- verify it stayed 0600
sudo -e /etc/cytadel/cytadel.env           # replace the placeholder with your real NVD API key
```

Verify the permissions before moving on -- the unit refuses to start
loudly if this file is missing, but nothing checks its mode for you at the
systemd layer (only the cron wrapper does that check itself):

```sh
stat -c '%a %U:%G %n' /etc/cytadel/cytadel.env   # expect: 600 root:root /etc/cytadel/cytadel.env
```

### 3. Install and enable the unit + timer

```sh
sudo install -m 0644 packaging/systemd/cytadel-sync.service /etc/systemd/system/
sudo install -m 0644 packaging/systemd/cytadel-sync.timer   /etc/systemd/system/
sudo systemctl daemon-reload
# Required for the unit's After=/Wants=network-online.target to mean
# anything -- enable whichever wait-online provider your distro ships:
sudo systemctl enable --now systemd-networkd-wait-online.service   # networkd hosts
# or: sudo systemctl enable --now NetworkManager-wait-online.service # NetworkManager hosts
sudo systemctl enable --now cytadel-sync.timer
```

Do **not** `systemctl enable` `cytadel-sync.service` itself -- only the
`.timer` has an `[Install]` section pointed at boot activation; the
`.service` is timer-triggered (or run once on demand, see below).

### 4. Verify

```sh
systemctl list-timers cytadel-sync.timer      # see next/last scheduled run
sudo systemctl start cytadel-sync.service     # run once immediately, don't wait for the schedule
systemctl status cytadel-sync.service
journalctl -u cytadel-sync.service -e         # confirm no key value ever appears here
```

### Disable / uninstall

```sh
sudo systemctl disable --now cytadel-sync.timer
sudo rm /etc/systemd/system/cytadel-sync.{service,timer}
sudo systemctl daemon-reload
```

`StateDirectory=cytadel` (in the `.service` file) means the vuln DB lives
at `/var/lib/cytadel/` -- remove that directory yourself if you want a full
uninstall (`systemctl disable` does not delete it, which is deliberate: it
is your scan-history data, not disposable state).

### Hardening summary (what's applied, and why)

| Directive | Why |
|---|---|
| `DynamicUser=yes` | No persistent system account to create/maintain; ephemeral non-root UID per run. |
| `StateDirectory=cytadel` | The ONLY writable path (`/var/lib/cytadel`) -- exactly where `CYTADEL_DB_PATH` lives. |
| `CapabilityBoundingSet=` (empty) | `sync` needs zero Linux capabilities -- no raw sockets, no privileged bind, unlike an actual scan. |
| `ProtectSystem=strict`, `ProtectHome=yes` | Whole filesystem read-only except the state directory + API/pseudo filesystems. |
| `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX` | Outbound HTTPS + local name resolution only -- no `AF_NETLINK`/`AF_PACKET`/raw sockets. |
| `NoNewPrivileges`, `RestrictSUIDSGID`, `LockPersonality`, `MemoryDenyWriteExecute`, `RemoveIPC`, `Protect{Kernel*,Clock,Hostname,ControlGroups}`, `RestrictNamespaces`, `RestrictRealtime` | Standard defense-in-depth for an unattended network client that needs none of these. |
| `SystemCallFilter=@system-service` | systemd's own curated syscall allow-list for ordinary userspace services. |

`sync` needs exactly: outbound HTTPS (NVD), read the `EnvironmentFile`
(done by systemd itself, not this process), and read+write the state
directory. Everything above is scoped to grant exactly that and nothing
else -- it does **not** need `CAP_NET_RAW` or any other capability a real
scan (raw ICMP discovery) might, because `sync` never scans a target.

## Option B -- cron (non-systemd hosts)

### 1. Build and install the binary

Same as systemd Option A step 1 above.

### 2. Create the dedicated unprivileged user + state directory

```sh
sudo useradd --system --no-create-home --shell /usr/sbin/nologin cytadel-sync
sudo mkdir -p /var/lib/cytadel
sudo chown cytadel-sync:cytadel-sync /var/lib/cytadel
sudo chmod 0750 /var/lib/cytadel
```

### 3. Create the protected environment file

Same as systemd Option A step 2 above -- `/etc/cytadel/cytadel.env`, owned
`root:root`, mode `0600`. The cron wrapper script (unlike the systemd path,
where systemd itself reads the file as root) is what reads this file while
briefly running as root, purely to export the two variables into the
environment of the unprivileged process it then execs -- see the wrapper
script's own header comment.

### 4. Install the wrapper + cron drop-in

```sh
sudo install -m 0755 packaging/cron/cytadel-sync-cron-wrapper.sh /usr/local/sbin/cytadel-sync-cron-wrapper.sh
sudo install -m 0644 packaging/cron/cytadel-sync.cron /etc/cron.d/cytadel-sync
sudo touch /var/log/cytadel-sync.log
sudo chown cytadel-sync:cytadel-sync /var/log/cytadel-sync.log
```

Cron itself reloads `/etc/cron.d/` drop-ins automatically (no daemon
restart needed on any mainstream cron implementation).

Optional: rotate the log file with logrotate --
`/etc/logrotate.d/cytadel-sync`:

```
/var/log/cytadel-sync.log {
    weekly
    rotate 8
    compress
    missingok
    notifempty
}
```

### 5. Verify

```sh
sudo /usr/local/sbin/cytadel-sync-cron-wrapper.sh   # run once immediately, as root (it drops privileges itself)
tail -f /var/log/cytadel-sync.log
```

### Non-overlap

The wrapper script wraps the real invocation in `flock -n` on
`/run/lock/cytadel-sync.lock` -- a run still in progress when cron fires
again causes the second invocation to exit immediately rather than run
concurrently (the systemd path gets the equivalent property for free,
since a non-templated unit only ever has one active instance at a time).

### Disable / uninstall

```sh
sudo rm /etc/cron.d/cytadel-sync
sudo rm /usr/local/sbin/cytadel-sync-cron-wrapper.sh
```

## Why daily, and why a missed run is fine either way

NVD updates continuously, but `cytadel-scan sync` drives
`cytadel_nvd_catchup()` (`src/db/nvd_catchup.c`), which walks
`[last watermark, now]` in bounded windows regardless of how large that gap
is. A once-a-day schedule (`OnCalendar=daily` / `17 3 * * *`) is therefore
a *convenience* cadence, not a correctness requirement -- if a run is
missed entirely (host was off, a prior run failed), the next run's window
is simply wider and self-heals in one invocation. `Persistent=true` on the
timer additionally means a missed **schedule** (not just a missed sync) is
made up shortly after the host is next up, rather than silently waiting for
the following day's `OnCalendar=` to roll around.

## CI (for context, not installed by this directory)

`.github/workflows/ci.yml`'s unit-test matrix and Docker-backed
integration job deliberately do **not** invoke a live sync at all -- see
that file's own header comment. The integration tests seed the local vuln
DB from `tests/integration/fixtures/seed.sql`, never from a live NVD pull,
so CI needs no `NVD_API_KEY`/`CYTADEL_NVD_API_KEY` secret whatsoever. The
scheduling in this directory is entirely about a real, unattended
deployment host -- it has no CI counterpart and should not be given one.
