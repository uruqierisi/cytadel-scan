# docker/tls-legacy/Dockerfile
#
# TEST-ONLY, disposable target. Every actively-maintained OpenSSL package we
# could find (Debian bookworm/buster, Alpine 3.9-3.20 -- all tried and
# rejected, see docker/README.md's "what we could not pin" section) is
# built with RC4/DES/EXPORT cipher support compiled OUT entirely, so no
# apt/apk-installable openssl or nginx build can ever negotiate the weak
# cipher suites plugins/tls_weak_cipher.lua looks for. Rather than depend on
# an archived/EOL distro's dead package mirrors (trading one kind of
# fragility for another), this stage compiles upstream, unmodified OpenSSL
# 1.1.1w (the final 1.1.1 release) FROM SOURCE, with its own
# 'enable-weak-ssl-ciphers'/'enable-rc4'/'enable-ssl3' options -- a
# reproducible, checksum-pinned build, not a binary someone else stopped
# maintaining.
#
# This one container deliberately maximizes TLS-plugin coverage on a single
# service (see nginx.conf-style comment in gen-certs.sh and
# docker/README.md's coverage table):
#   :8443 -- self-signed, mismatched-CN, MD5-signed, 1024-bit RSA key,
#            SSLv3/TLSv1-only, RC4/3DES-only cert -- exercises
#            self_signed + hostname_mismatch + weak_sig_alg +
#            weak_key_size + deprecated_protocol + weak_cipher in one place.
#   :993  -- (IMAPS's conventional port, chosen only because it is on the
#            engine's TLS-candidate port list -- src/net/svc_token.c) a
#            self-signed, mismatched-CN, NOT-YET-VALID cert (notBefore in
#            the future) -- exercises tls_cert_not_yet_valid.lua, the one
#            stock TLS check no other container in this test target
#            reaches.

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS sslbuild

RUN apk add --no-cache build-base=0.5-r3 perl=5.38.5-r0 linux-headers=6.6-r0 wget=1.24.5-r0 ca-certificates=20260413-r0

WORKDIR /build
ARG OPENSSL_VERSION=1.1.1w
ARG OPENSSL_SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
RUN wget -q "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz" -O openssl.tar.gz \
    && echo "${OPENSSL_SHA256}  openssl.tar.gz" | sha256sum -c - \
    && tar xzf openssl.tar.gz \
    && cd "openssl-${OPENSSL_VERSION}" \
    && ./config --prefix=/opt/legacyssl --openssldir=/opt/legacyssl \
         enable-weak-ssl-ciphers enable-rc4 enable-ssl3 enable-ssl3-method \
    && make -j"$(nproc)" \
    && make install_sw

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS certgen
RUN apk add --no-cache openssl=3.3.7-r0 libfaketime=0.9.10-r3
COPY gen-certs.sh /gen-certs.sh
RUN chmod +x /gen-certs.sh && /gen-certs.sh

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc

COPY --from=sslbuild /opt/legacyssl /opt/legacyssl
COPY --from=certgen /certs /certs
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV LD_LIBRARY_PATH=/opt/legacyssl/lib
ENV PATH=/opt/legacyssl/bin:$PATH

EXPOSE 8443 993

ENTRYPOINT ["/entrypoint.sh"]
