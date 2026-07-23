#!/bin/sh
# docker/ssh-vulnerable/entrypoint.sh
#
# Generates fresh host keys on every container start (never baked into the
# image / never committed) and then execs sshd in the foreground so it is
# PID 1 and receives signals directly (clean `docker compose down`).
set -eu

if [ ! -f /etc/ssh/keys/ssh_host_rsa_key ]; then
    ssh-keygen -q -t rsa -b 3072 -N '' -f /etc/ssh/keys/ssh_host_rsa_key
fi
if [ ! -f /etc/ssh/keys/ssh_host_ed25519_key ]; then
    ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/keys/ssh_host_ed25519_key
fi

exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
