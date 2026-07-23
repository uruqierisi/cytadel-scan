# docker/ssh-sshv1-stub/Dockerfile
#
# TEST-ONLY, disposable target. NOT a real SSH-1 daemon.
#
# Why a stub instead of a real service (documented per the task brief's
# "if hard to pin, say so" instruction): OpenSSH removed SSH protocol 1
# support from its own source tree in the 7.6 release (2017) and no current
# distro packages a build with it re-enabled -- there is no realistic,
# reproducible way to `apt install` or pin a genuinely-functioning SSH-1
# daemon today the way docker/ssh-vulnerable pins a real OpenSSH 8.9p1.
# Standing up an actual working SSH-1 implementation would mean building and
# running genuinely ancient, exploitable third-party SSH code inside the
# test harness for a protocol whose only relevant fact to Cytadel's
# detection-only engine is four bytes of plaintext banner
# (src/net/svc_ssh.c / src/net/banner_grab.c: the engine reads whatever the
# peer sends on connect, up to a byte cap, and never performs an actual key
# exchange for SSH-1 or SSH-2). So this container is a minimal, honest
# stand-in: it opens a TCP listener on port 22 and writes exactly one
# version-exchange line advertising protocol "1.99" (the RFC 4253 dual
# SSH-1/SSH-2 backward-compatibility value), then closes -- precisely the
# banner condition plugins/ssh_sshv1_supported.lua (100010) parses, and
# nothing else. It never accepts input, never completes a key exchange,
# and cannot be interacted with beyond that one line.
FROM busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662

COPY stub.sh /stub.sh
RUN chmod +x /stub.sh

EXPOSE 22

# -lk: persistent listener (accepts connections repeatedly); -e runs
# /stub.sh once per connection, which prints the single banner line and
# exits (busybox nc then closes the connection).
CMD ["nc", "-lk", "-p", "22", "-e", "/stub.sh"]
