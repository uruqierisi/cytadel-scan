#!/bin/sh
# docker/web/gen-certs.sh
#
# Runs INSIDE the image build (certgen stage) only -- generates a fresh,
# self-signed, EXPIRED cert on every build; nothing is ever committed to
# the repo. Deliberately otherwise-strong (2048-bit RSA / SHA-256) so this
# container isolates the "expired" TLS signal from the "weak crypto"
# scenario, which lives on docker/tls-legacy instead.
#
# CN is deliberately something this box's real hostname/service name will
# never match, so plugins/tls_cert_hostname_mismatch.lua also has something
# real to find once the Phase 2 scanner resolves a hostname for this
# target.
set -eu

MISMATCHED_CN="legacy-internal-app.example.invalid"

mkdir -p /certs/expired

echo "== generating expired cert (2048-bit RSA, SHA-256, backdated to 2020) =="
FAKETIME="2020-01-01 00:00:00" LD_PRELOAD=/usr/lib/faketime/libfaketimeMT.so.1 \
    openssl req -x509 -newkey rsa:2048 -keyout /certs/expired/server.key \
    -out /certs/expired/server.crt -days 30 -noenc -sha256 -subj "/CN=${MISMATCHED_CN}"

chmod 0644 /certs/expired/server.crt
chmod 0600 /certs/expired/server.key

echo "== verification =="
openssl x509 -in /certs/expired/server.crt -noout -subject -dates -text | grep -E "Subject:|Signature Algorithm|Public-Key|notBefore|notAfter"
