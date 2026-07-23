# docker/ssh-vulnerable/Dockerfile
#
# TEST-ONLY, disposable target: a genuinely real, unmodified OpenSSH server
# from Ubuntu 22.04 LTS's own package archive. As of this writing, Ubuntu
# 22.04 "jammy" ships openssh-server 1:8.9p1-3ubuntu0.16, which falls
# squarely in the OpenSSH 8.5-9.7 band plugins/ssh_known_vulnerable_openssh.lua
# (100011) flags as CVE-2024-6387 (regreSSHion)-banded, Medium severity,
# heuristic. This is a REAL sshd binary at a REAL, currently-shipping
# distro-pinned version -- not a synthetic banner stub (contrast
# docker/ssh-sshv1-stub, which is a stub; see its Dockerfile for why).
#
# Also triggers plugins/ssh_version_disclosure.lua (100012, Info) simply by
# existing and disclosing its version in the banner, as essentially all real
# sshd builds do.
FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ENV DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends openssh-server=1:8.9p1-3ubuntu0.16 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /etc/ssh/keys

COPY sshd_config /etc/ssh/sshd_config

# Host keys are generated fresh at container start (entrypoint.sh below),
# never baked into the image or committed to the repo -- a stable image
# with a baked-in host key would be a bad practice to demonstrate even in a
# disposable test target.
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
