#!/bin/sh
# docker/tls-legacy/gen-certs.sh
#
# Runs INSIDE the image build (certgen stage) only -- fresh keys every
# build, nothing committed to the repo. Both certs use a CN that will never
# match this box's real hostname/service name, so
# plugins/tls_cert_hostname_mismatch.lua also fires once the Phase 2
# scanner resolves a hostname for this target.
#
#   /certs/weak/server.{key,crt}       -- 1024-bit RSA + MD5 signature,
#                                          currently valid (isolates the
#                                          "weak crypto" signal from the
#                                          time-validity ones).
#   /certs/notyetvalid/server.{key,crt} -- strong key/sig (2048-bit RSA /
#                                          SHA-256), but notBefore is
#                                          genuinely in the future (built
#                                          under a faked 2030 clock via
#                                          libfaketime) --
#                                          tls_cert_not_yet_valid.lua.
set -eu

MISMATCHED_CN="legacy-internal-app.example.invalid"

mkdir -p /certs/weak /certs/notyetvalid

echo "== generating weak-but-current cert (1024-bit RSA, MD5 signature) =="
openssl req -x509 -newkey rsa:1024 -keyout /certs/weak/server.key -out /certs/weak/server.crt \
    -days 825 -noenc -md5 -subj "/CN=${MISMATCHED_CN}"

echo "== generating not-yet-valid cert (2048-bit RSA, SHA-256, backdated clock puts notBefore in 2030) =="
FAKETIME="2030-01-01 00:00:00" LD_PRELOAD=/usr/lib/faketime/libfaketimeMT.so.1 \
    openssl req -x509 -newkey rsa:2048 -keyout /certs/notyetvalid/server.key \
    -out /certs/notyetvalid/server.crt -days 825 -noenc -sha256 -subj "/CN=${MISMATCHED_CN}"

chmod 0644 /certs/weak/server.crt /certs/notyetvalid/server.crt
chmod 0600 /certs/weak/server.key /certs/notyetvalid/server.key

echo "== verification =="
openssl x509 -in /certs/weak/server.crt -noout -subject -dates -text | grep -E "Subject:|Signature Algorithm|Public-Key|notBefore|notAfter"
openssl x509 -in /certs/notyetvalid/server.crt -noout -subject -dates -text | grep -E "Subject:|Signature Algorithm|Public-Key|notBefore|notAfter"
