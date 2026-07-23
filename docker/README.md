# Cytadel Scan -- Disposable Integration-Test Target (M9 Phase 1)

This directory defines a **disposable, detection-only, deliberately
misconfigured** Docker environment: the intended target for Cytadel's
Phase 2 end-to-end integration test. Every service here exists to be
**scanned**, never exploited, and every condition it presents was chosen
because it is the *exact* banner/certificate/header condition one of
Cytadel's stock plugins (`plugins/*.lua`, catalogued in
`plugins/README.md`) keys on -- not a generic "vulnerable box" grab-bag.

**This is test-only infrastructure.** Nothing here should ever be
reachable from anywhere but the internal Docker network defined below, and
nothing here should ever be deployed, exposed, or reused outside this
integration-test harness.

## Quick start

```sh
cd docker
docker compose build
docker compose up -d
docker compose exec sidecar sh    # run proof commands from here (see below)
docker compose down -v            # clean, disposable teardown -- leaves nothing
```

No `.env` file or secret is required: every "credential" in this
environment (Redis with no password, FTP anonymous access, SSH with no
valid accounts) is intentionally weak/absent by design, not a real secret.

## Services -> plugin findings

| Service (compose name) | Port(s) | Real or stub? | What it triggers |
|---|---|---|---|
| `ftp` | 21 | Real vsftpd 3.0.3 (Debian bookworm) | `ftp_anonymous_banner_hint` (100001, Info) -- banner text says "Anonymous FTP login is permitted"; `ftp_cleartext_protocol` (100002, Low) -- any FTP service. |
| `ssh-vulnerable` | 22 | Real, unmodified OpenSSH 8.9p1 (Ubuntu 22.04 jammy-updates) | `ssh_known_vulnerable_openssh` (100011, Medium) -- 8.9 falls in the 8.5-9.7 regreSSHion/CVE-2024-6387 band; `ssh_version_disclosure` (100012, Info). |
| `ssh-sshv1-stub` | 22 | **Synthetic stub** (not a real daemon -- see below) | `ssh_sshv1_supported` (100010, High) -- banner advertises protocol `1.99`. |
| `telnet` | 23 | Real BusyBox `telnetd` | `telnet_cleartext_protocol` (100040, Medium) -- any Telnet service present. |
| `web` | 80, 443 | Real nginx 1.18.0 (EOL) | See "web" breakdown below. |
| `tls-legacy` | 8443, 993 | Source-compiled OpenSSL 1.1.1w `s_server` (see below) | See "tls-legacy" breakdown below. |
| `db` | 6379 | Real Redis 7.2 (alpine), no `requirepass` | `db_exposed_cleartext` (100041, Low) -- Redis reachable on its conventional port. |
| `sidecar` | -- | Toolbox only, not part of the target | N/A -- this is the verification/scanner-position container, see below. |

### `web` (nginx 1.18.0, real, EOL -- `< 1.20`)

| Port | Condition | Plugin(s) |
|---|---|---|
| 80 | `Server: nginx/1.18.0` disclosed (`server_tokens on`, the default) | `http_server_version_disclosure` (100036, Info), `http_known_vulnerable_server` (100038, Low, nginx < 1.20) |
| 80 | No `index.html` in the docroot -> nginx `autoindex` serves its default "Index of /" listing | `http_directory_listing` (100037, Medium) |
| 80 | No CSP / X-Content-Type-Options / X-Frame-Options headers set (nginx default) | `http_missing_csp` (100032), `http_missing_xcto` (100033), `http_missing_xfo` (100034) -- all Low |
| 80 | `Set-Cookie` without `Secure`/`HttpOnly` | `http_insecure_cookie_flags` (100035, Low -- plaintext port, so only `HttpOnly` is "missing"; `Secure` is only evaluated over TLS) |
| 443 | Self-signed, expired (backdated via `libfaketime` to 2020), CN deliberately mismatched | `tls_cert_expired` (100020, High), `tls_cert_self_signed` (100022, Medium), `tls_cert_hostname_mismatch` (100023, Medium) |
| 443 | No HSTS header | `http_missing_hsts` (100031, Low) |

### `tls-legacy` (source-compiled OpenSSL 1.1.1w, see "What we could not pin" below)

| Port | Condition | Plugin(s) |
|---|---|---|
| 8443 | Self-signed, mismatched-CN, **MD5**-signed, **1024-bit RSA** key, restricted to **SSLv3/TLSv1** protocols and **RC4/3DES-only** ciphers | `tls_cert_self_signed` (100022), `tls_cert_hostname_mismatch` (100023), `tls_weak_sig_alg` (100024, High for MD5), `tls_weak_key_size` (100025, Medium), `tls_deprecated_protocol` (100026, Medium for TLSv1), `tls_weak_cipher` (100027, High for RC4/anon, Medium for 3DES) |
| 993 | Self-signed, mismatched-CN, **not-yet-valid** cert (backdated build clock puts `notBefore` in 2030) | `tls_cert_self_signed`, `tls_cert_hostname_mismatch`, `tls_cert_not_yet_valid` (100021, Medium) |

Port 993 is IMAPS's conventional port; it is used here *only* because it
is on the engine's fixed TLS-candidate port list
(`src/net/svc_token.c::cytadel_svc_is_tls_candidate_port`) -- nothing here
speaks real IMAP.

### `sidecar`

Not part of the vulnerable target. A small Alpine toolbox
(curl/openssl/netcat/bind-tools) on the same internal network, standing in
for the position the Phase 2 Cytadel scanner container will occupy: it
reaches every target by its Compose service (DNS) name, never by a
published host port (there are none).

## Deliberately omitted: SMBv1 and RDP

`plugins/README.md` documents that Cytadel ships **no detector** for
SMBv1 or RDP (no `Services/smb/*` or `Services/rdp/*` KB-reading plugin
exists in-tree). This test target intentionally runs **only** services
Cytadel has detectors for -- **SMBv1 and RDP are excluded on purpose**,
not by oversight. Standing up a real (or stub) SMB/RDP service here would
test nothing (there is no plugin to observe it) and would only add attack
surface and maintenance burden to a disposable test box for zero coverage
benefit. If SMB/RDP detection is ever added to Cytadel, this target should
grow a matching service at that point, not before.

## Isolation model (security posture, non-negotiable)

- **Every** vulnerable-target service sits on `cytadel-test-net`, declared
  `internal: true` in `docker-compose.yml`. Docker gives an `internal`
  network **no route out at all** -- not to the host, not to the LAN, not
  to the internet -- independent of anything else in this file.
- **No service publishes a host port.** There is no top-level `ports:` key
  anywhere in `docker-compose.yml` -- only `expose:`, which documents
  container-internal ports and does **not** publish them to the host.
- The **only** other thing on `cytadel-test-net` is `sidecar`, a
  verification toolbox container (see above) -- modeling exactly where the
  Phase 2 Cytadel scanner container will attach as a sidecar on this same
  internal network and reach every target by Compose service name.
- **No real secrets or credentials exist anywhere in this environment.**
  Redis runs with no password, FTP anonymous access has no real account
  behind it, and the SSH containers have no user accounts with passwords
  set at all (`PasswordAuthentication no` + no password-bearing accounts on
  `ssh-vulnerable`; the `ssh-sshv1-stub` container cannot authenticate
  anything -- see below). Weak/absent-by-design is the point; none of it is
  a real credential that could leak.
- Every image is pinned by tag **and digest** (`image@sha256:...` /
  `FROM ...@sha256:...`). Nothing here uses `:latest`. A fresh
  `docker compose build` on any machine with network access reproduces
  bit-identical base layers.

## What we could not pin / had to work around (read this before trusting the coverage table)

- **`ssh-sshv1-stub` is a synthetic banner stub, not a real SSH-1 daemon.**
  OpenSSH removed SSH protocol 1 support from its own source tree in the
  7.6 release (2017); no currently-maintained distro packages a build with
  it re-enabled. There is no reproducible way to `apt`/`apk` install a
  genuinely-functioning SSH-1 server today the way `ssh-vulnerable` pins a
  real OpenSSH 8.9p1. Standing up an actual historical SSH-1
  implementation would mean running genuinely ancient, exploitable
  third-party code inside the test harness for a protocol whose only fact
  Cytadel's engine ever reads is four bytes of plaintext banner
  (`src/net/svc_ssh.c` parses `SSH-<proto>-<software>` from the version-
  exchange line; it never performs a real key exchange for either SSH-1 or
  SSH-2 -- see `src/net/banner_grab.c`). So `ssh-sshv1-stub` is exactly
  that: a `busybox nc` listener that writes one line
  (`SSH-1.99-OpenSSH_stub_test_only\r\n`) and closes. It never reads
  input, never completes a handshake, and cannot be interacted with beyond
  that one line -- see its Dockerfile for the full rationale.

- **`tls-legacy` compiles OpenSSL 1.1.1w from source instead of using any
  apt/apk package.** We tried, in order: Debian bookworm (nginx's own
  bundled OpenSSL 1.1.1d), Alpine 3.20, and Alpine 3.9 (2019) -- **every
  one** ships an OpenSSL build with RC4/DES/EXPORT cipher suites compiled
  out entirely (`openssl ciphers -v ALL` returns zero RC4/DES entries on
  all three). This is standard practice for actively-maintained distro
  OpenSSL packages today, but it means `plugins/tls_weak_cipher.lua`
  cannot be triggered against *any* currently-installable openssl/nginx
  build. We also tried `debian:jessie` (2015, genuinely old) but its
  `deb.debian.org` mirror entries 404 -- reaching it would require pointing
  at `snapshot.debian.org`, trading one kind of fragility (a dead package
  mirror) for another (a slow, timestamp-pinned snapshot host) for no real
  reproducibility gain. Instead, `tls-legacy/Dockerfile` compiles
  **unmodified, upstream OpenSSL 1.1.1w** (the final 1.1.1 release) from
  source, with `enable-weak-ssl-ciphers enable-rc4 enable-ssl3
  enable-ssl3-method`, verified against its published SHA-256
  (`cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8`).
  This is a genuinely reproducible, checksum-pinned build (~30-40s on a
  cold cache), not a binary anyone else stopped maintaining -- confirmed
  locally to support `RC4-SHA`, `RC4-MD5`, and `DES-CBC3-SHA` once
  `@SECLEVEL=0` is set (modern OpenSSL's library-default security level
  rejects sub-112-bit ciphers and sub-2048-bit RSA keys otherwise -- this
  is *why* nginx's bundled 1.1.1d refused to even load the 1024-bit/MD5
  cert used here, `SSL_CTX_use_certificate ... ee key too small`, before
  this container existed).

- **`tls_weak_cipher.lua` is the only stock plugin this target does not
  exercise on the `web` (nginx) container** -- it is exercised instead on
  `tls-legacy`, for the reason above.

## Proving it works

All commands below are run **from `sidecar`**, on the internal network --
never from the host (there are no published ports to reach from the host
at all; see "Host-side isolation proof" further down).

```sh
docker compose up -d --build
docker compose exec sidecar sh
```

Then, inside the sidecar shell:

```sh
# --- FTP: banner advertises anonymous access, cleartext ---
nc -w2 ftp 21

# --- SSH: real OpenSSH 8.9p1 (regreSSHion band) ---
nc -w2 ssh-vulnerable 22

# --- SSH: synthetic SSH-1.99 stub banner ---
nc -w2 ssh-sshv1-stub 22

# --- Telnet: cleartext IAC negotiation ---
nc -w2 telnet 23 | xxd | head

# --- HTTP: missing security headers + version disclosure + directory listing ---
curl -sI http://web/
curl -s  http://web/ | head -5

# --- TLS: expired, self-signed, mismatched-CN cert ---
openssl s_client -connect web:443 </dev/null 2>&1 | grep -E "subject|issuer|verify"

# --- TLS: not-yet-valid, self-signed, mismatched-CN ---
openssl s_client -connect tls-legacy:993 -cipher "ALL:@SECLEVEL=0" </dev/null 2>&1 \
  | grep -E "subject|issuer|verify"
```

`tls-legacy:8443`'s whole point is RC4/3DES/TLSv1-only -- and, as the "what
we could not pin" section above explains, **every** actively-maintained
OpenSSL build (including `sidecar`'s own Alpine `openssl` package) has
those suites compiled out and cannot even attempt them, regardless of
`-cipher`/`@SECLEVEL`. Verify that port from a client that itself still
supports them instead: `tls-legacy`'s own bundled, source-compiled
OpenSSL 1.1.1w (the container connecting to itself over the loopback
interface, still entirely inside the isolated network -- this is a
client-capability limitation, not a host/LAN reachability check):

```sh
docker compose exec tls-legacy sh -c \
  'openssl s_client -connect 127.0.0.1:8443 -cipher "RC4-SHA:DES-CBC3-SHA:@SECLEVEL=0" -tls1 </dev/null 2>&1 \
   | grep -E "subject|issuer|verify|Protocol|Cipher"'
```

Finally, back in the `sidecar` shell:

```sh
# --- Exposed cleartext DB ---
printf 'PING\r\n' | nc -w2 db 6379
```

See this milestone's task output / commit message for a full real-run
transcript of every command above.

### Host-side isolation proof

From the **host** (outside any container -- e.g. a plain WSL shell, not
`docker compose exec`), none of these ports are reachable, because
`cytadel-test-net` is `internal: true` and no `ports:` mapping exists
anywhere in `docker-compose.yml`:

```sh
nc -zv -w2 127.0.0.1 21    # ftp        -> connection refused / no route
nc -zv -w2 127.0.0.1 22    # ssh        -> connection refused / no route
nc -zv -w2 127.0.0.1 80    # web        -> connection refused / no route
nc -zv -w2 127.0.0.1 8443  # tls-legacy -> connection refused / no route
nc -zv -w2 127.0.0.1 6379  # db         -> connection refused / no route
```

### Teardown

```sh
docker compose down -v
```

`-v` removes the (unnamed/anonymous) volumes Compose may have created;
this environment defines no named/persistent volumes, so a plain
`docker compose down` already leaves nothing behind -- `-v` is included
for completeness/habit.

## M9 Phase 3: unprivileged-scanning / TCP-ping-fallback scenario

`docker-compose.scanner-unprivileged.yml` (used together with the base
`docker-compose.yml`) proves -- by OBSERVED log output, never by
assumption -- that `src/net/discovery.c`'s TCP-ping fallback fires when
raw ICMP sockets are unavailable, which is the exact position an operator
scanning from an unprivileged host is in. Run it with:

```sh
docker compose -f docker-compose.yml -f docker-compose.scanner-unprivileged.yml build web scanner-unprivileged scanner-rawcapable
docker compose -f docker-compose.yml -f docker-compose.scanner-unprivileged.yml up -d web
```

Or simply run `tests/integration/run_unprivileged_fallback_test.sh` (also
registered as the CTest case `integration_e2e_unprivileged_fallback`,
gated behind `CYTADEL_ENABLE_INTEGRATION_TESTS` / `-L integration` exactly
like `integration_e2e_docker_scan`), which does all of the above plus the
assertions below and a full `compose down -v` teardown.

### Why this needs TWO scanner images, not one

A test that shows the fallback marker regardless of whether raw ICMP is
actually available proves nothing -- it needs a genuine contrast. This
overlay defines two scanner services, differing ONLY in one Docker build
arg and one capability setting:

| Service | Image | Capabilities | Expected discovery method |
|---|---|---|---|
| `scanner-unprivileged` | `docker/scanner/Dockerfile` (`CYTADEL_TEST_SETCAP_NET_RAW=0`, the default -- identical to Phase 2's `scanner` image) | `cap_drop: [ALL]`, non-root | TCP-ping fallback |
| `scanner-rawcapable` | same Dockerfile, `--build-arg CYTADEL_TEST_SETCAP_NET_RAW=1` | default caps (NET_RAW present, not dropped), still non-root | Real ICMP echo |

**Empirically verified fact worth knowing** (see `docker/scanner/Dockerfile`'s
own updated CAPABILITIES comment for the full writeup): Docker's *default*
capability bounding set already includes `CAP_NET_RAW` -- dropping it is
NOT what actually makes raw ICMP unavailable to `scanner-unprivileged`.
What makes it unavailable is that the image runs as the non-root
`cytadel` user with no file capability on the binary: Linux only grants a
non-root process capabilities from the executable's own capability xattr
(or root's legacy "permitted = bounding" exec rule, which only applies
when the process actually is UID 0) -- a non-root process gets `EPERM` on
`socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` even with an intact capability
bounding set. Confirmed with a minimal raw-socket probe binary run inside
this exact base image under four postures (non-root/default-caps,
root/default-caps, root/cap-drop, non-root/cap-drop) before writing any of
this. `cap_drop: [ALL]` on `scanner-unprivileged` is real defense-in-depth
(and what this milestone was asked to add), not what flips the behavior
for this particular image -- the `USER cytadel` line alone already does.
`scanner-rawcapable` exists ONLY to flip it back the other way (via
`setcap cap_net_raw+ep`, applied during its own image build) so the
fallback test has a genuine negative control. It is never a production
scenario -- see the Dockerfile's `CYTADEL_TEST_SETCAP_NET_RAW` ARG comment.

### What `run_unprivileged_fallback_test.sh` asserts

Both runs target `web` (the only Phase-1 target whose open ports, 80 and
443, are also in `src/net/tcp_ping.c`'s fixed probe-port list, so the
fallback itself -- not just the subsequent port scan -- can succeed), with
`--log-level debug` and **no** `--skip-discovery` (real discovery is the
entire point here):

1. **RUN A (`scanner-unprivileged`)** must log `used TCP ping (fallback)`
   and `(method=tcp-ping)`, and must NOT log `used ICMP echo` or
   `(method=icmp)`.
2. **RUN B (`scanner-rawcapable`, negative control)** must log
   `used ICMP echo` and `(method=icmp)`, and must NOT log
   `used TCP ping (fallback)` or `(method=tcp-ping)` -- proving RUN A's
   assertion isn't a tautology; if this ever flipped, RUN A's assertion
   would no longer be a meaningful regression check.
3. RUN A's scan must still have WORKED despite the missing capability:
   host state `up`, both ports 80/443 `open`.
4. RUN A's rendered report (`report --latest --format json`) must show
   `scan.status == "completed"` with real plugin findings persisted
   (e.g. `http_server_version_disclosure`, plugin_id `100036`).

A real run against this exact codebase produced (verbatim):

```
2026-07-22T20:52:42.204Z [DEBUG] host discovery for 172.19.0.2 used TCP ping (fallback)
2026-07-22T20:52:42.204Z [INFO] host discovery: web (172.19.0.2) is up (method=tcp-ping)
...
2026-07-22T20:52:42.999Z [DEBUG] host discovery for 172.19.0.2 used ICMP echo
2026-07-22T20:52:42.999Z [INFO] host discovery: web (172.19.0.2) is up (method=icmp)
```

(first block: `scanner-unprivileged`; second block: `scanner-rawcapable`,
the very next run, same target IP) -- both scans completed with 17
findings persisted and a `status: "completed"` report.

### Isolation

Same posture as every other service in this directory: both scanner
services join only `cytadel-test-net` (`internal: true`), publish no host
ports, and never run `--privileged` or as root -- `scanner-rawcapable`'s
file-capability approach is specifically what lets it exercise raw ICMP
*without* ever needing root. Each scanner writes to its own
Docker-managed volume (`cytadel-scan-data-unprivileged` /
`cytadel-scan-data-rawcapable`), kept separate from Phase 2's own
`scanner`/`cytadel-scan-data`; `docker compose down -v` removes both.
