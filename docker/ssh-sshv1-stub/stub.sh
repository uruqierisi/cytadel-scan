#!/bin/sh
# docker/ssh-sshv1-stub/stub.sh
#
# Prints one RFC 4253 SSH version-exchange line advertising the "1.99"
# dual-protocol backward-compatibility value, then exits -- see this
# directory's Dockerfile for why this is a synthetic stub rather than a
# real SSH-1 daemon. Deliberately does nothing else: no read, no key
# exchange, no further output.
printf 'SSH-1.99-OpenSSH_stub_test_only\r\n'
