# docker/sidecar/Dockerfile
#
# Verification/toolbox container ONLY -- this is NOT part of the
# vulnerable test target. It attaches to the same internal-only network as
# the target containers and is used to prove each service's condition
# from inside the network (curl/openssl/nc), exactly the position the
# Phase 2 Cytadel scanner container will occupy as a sidecar on this same
# network. It has no ports of its own and reaches nothing outside the
# internal network either (the network itself has no route out --
# internal: true in docker-compose.yml).
FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

RUN apk add --no-cache \
        curl=8.14.1-r2 \
        openssl=3.3.7-r0 \
        netcat-openbsd=1.226-r0 \
        bind-tools=9.18.49-r0

CMD ["sleep", "infinity"]
