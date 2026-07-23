#!/bin/sh
# docker/tls-legacy/entrypoint.sh
#
# Runs two independent openssl(1) s_server listeners (the source-compiled,
# weak-cipher-capable 1.1.1w build from this image's sslbuild stage) in the
# foreground: one deliberately-weak TLS endpoint (8443) and one
# not-yet-valid-cert endpoint (993). `-www` makes each answer a plain GET
# with a small built-in status page, which is enough for the engine's HTTP-
# over-TLS probe on 8443 (a recognized HTTP port) to get a real response.
set -eu

openssl s_server -accept 8443 \
    -cert /certs/weak/server.crt -key /certs/weak/server.key \
    -cipher "RC4-SHA:DES-CBC3-SHA:@SECLEVEL=0" -no_tls1_2 -no_tls1_3 \
    -www &
WEAK_PID=$!

openssl s_server -accept 993 \
    -cert /certs/notyetvalid/server.crt -key /certs/notyetvalid/server.key \
    -cipher "DEFAULT:@SECLEVEL=0" \
    -www &
NOTYET_PID=$!

trap 'kill "$WEAK_PID" "$NOTYET_PID" 2>/dev/null; exit 0' TERM INT

wait "$WEAK_PID" "$NOTYET_PID"
