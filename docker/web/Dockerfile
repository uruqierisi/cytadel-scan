# docker/web/Dockerfile
#
# TEST-ONLY, disposable target: nginx 1.18.0 (real, EOL, unmodified --
# plugins/http_known_vulnerable_server.lua) serving two deliberately
# misconfigured virtual hosts. See nginx.conf's header comment for the
# full per-port breakdown and plugins/README.md for exactly which plugin
# each condition maps to.
#
# All TLS material is generated HERE, at build time, by gen-certs.sh --
# nothing is committed to the repo and every build produces fresh keys.

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc AS certgen
RUN apk add --no-cache openssl=3.3.7-r0 libfaketime=0.9.10-r3
COPY gen-certs.sh /gen-certs.sh
RUN chmod +x /gen-certs.sh && /gen-certs.sh

FROM nginx:1.18.0@sha256:e90ac5331fe095cea01b121a3627174b2e33e06e83720e9a934c7b8ccc9c55a0

COPY nginx.conf /etc/nginx/nginx.conf
COPY --from=certgen /certs /etc/nginx/certs

# Intentionally no index.html -- see nginx.conf's "Index of /" comment.
RUN rm -f /usr/share/nginx/html/index.html /usr/share/nginx/html/50x.html \
    && printf 'Cytadel integration-test fixture file (directory listing target).\n' \
       > /usr/share/nginx/html/readme.txt

EXPOSE 80 443
