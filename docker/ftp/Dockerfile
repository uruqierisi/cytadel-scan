# docker/ftp/Dockerfile
#
# TEST-ONLY, disposable target: a real vsftpd daemon whose greeting banner
# text advertises anonymous access and which speaks plain (unencrypted) FTP.
# Triggers:
#   - plugins/ftp_anonymous_banner_hint.lua (100001, Info) -- banner text
#     contains "anonymous" (see vsftpd.conf's banner_file).
#   - plugins/ftp_cleartext_protocol.lua (100002, Low) -- any FTP service
#     found (this daemon never negotiates AUTH TLS).
#   - engine cpe_map.c (vendor/product/version resolution) -- the banner also
#     carries the literal marker "vsFTPd 3.0.3" so cpe_map resolves this port
#     to (vsftpd_project, vsftpd, 3.0.3). Without the version token in the
#     greeting the CPE never resolves and the port is (correctly) counted as
#     an unresolvable data-quality event rather than CVE-checked -- M9 Gap #1.
#     Keep BOTH "vsFTPd <version>" and "anonymous" in banner.txt.
#
# Never scanned/logged into by Cytadel's plugins beyond the greeting banner
# -- see plugins/README.md's "Why no live anonymous-login attempt" note.
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

RUN apt-get update -qq \
    && apt-get install -y --no-install-recommends vsftpd=3.0.3-13+b2 \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/run/vsftpd/empty

COPY vsftpd.conf /etc/vsftpd.conf
COPY banner.txt /etc/vsftpd_banner.txt

# vsftpd refuses to run its data/control setup as root by default in some
# distros' packaging when writable dirs are group/world-writable; the
# ftp/ftp_anon user already exists in the debian package's own postinst.
# anonymous_enable is intentionally ON: this is a disposable, isolated,
# never-published test target whose entire purpose is to present the
# advertised-anonymous-access banner text our plugin keys on -- there is no
# real credential here and no path to the host/LAN (see docker/README.md's
# isolation model).
EXPOSE 21

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
