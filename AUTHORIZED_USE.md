# Authorized Use & Legal Notice

Cytadel Scan is a **detection-only** network vulnerability scanner intended for
defensive security work: inventorying your own infrastructure, verifying patch
levels, and producing evidence for remediation. Read this before you run it
against anything.

## Detection-only by design

Cytadel **inspects** — it never exploits. Every check reads only what a service
voluntarily discloses:

- version banners and service-identification strings,
- TLS certificates and negotiated protocol/cipher parameters,
- HTTP response headers and status codes,
- configuration exposed through normal, unauthenticated responses.

Cytadel does **not**, and will not, send exploit payloads, attempt to gain,
modify, or damage access to a target, brute-force credentials, or perform
denial-of-service. There is no code path that weaponizes a finding. A "finding"
is a statement about an observed version/configuration condition, matched
against a local vulnerability database — not proof of exploitability.

## You must be authorized

Scanning systems you do not own or lack explicit written permission to test may
be illegal in your jurisdiction (for example, in the United States, the Computer
Fraud and Abuse Act; in the United Kingdom, the Computer Misuse Act 1990; and
comparable statutes elsewhere). **You are solely responsible** for ensuring you
have authorization for every target you scan.

To enforce this, Cytadel **refuses to scan** until the operator explicitly
affirms authorization, either by:

- passing `--i-am-authorized` on the command line (optionally with
  `--authorized-by <who>` to record the operator identity), or
- confirming at the interactive prompt when stdin is a terminal.

If stdin is not a terminal and `--i-am-authorized` was not given, the scan is
refused. The authorization affirmation is written to the log for your records.
Bypassing, disabling, or automating around this gate to scan targets you are not
authorized to test is misuse of the tool.

## The bundled Docker target is test-only

The environment under [`docker/`](docker/README.md) is a **disposable,
deliberately misconfigured, detection-only** target that exists solely to
exercise Cytadel's own plugins in the integration tests. It runs only on an
`internal: true` Docker network with **no published host ports** and **no real
credentials**. It is **not** a product, **not** hardened, and must **never** be
deployed, exposed, or reused outside the integration-test harness.

## No warranty

This software is provided "as is", without warranty of any kind. The authors and
contributors accept no liability for any misuse, damage, or legal consequence
arising from its use. Using Cytadel Scan means you accept full responsibility for
how, and against what, you run it.
