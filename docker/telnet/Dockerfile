# docker/telnet/Dockerfile
#
# TEST-ONLY, disposable target: a real BusyBox telnetd presenting genuine
# Telnet protocol negotiation (IAC option bytes) and a login prompt on port
# 23. Triggers plugins/telnet_cleartext_protocol.lua (100040, Medium),
# which fires on Telnet service presence alone (src/net/service_detect.c
# maps port 23 to the frozen "telnet" service token whether or not a
# banner was captured) -- Cytadel never attempts to log in.
#
# No real credentials exist in this image: there are no password-bearing
# accounts, so even if something tried to authenticate, nothing would
# succeed. telnetd itself is only ever reachable from the isolated internal
# test network (see docker/README.md).
FROM busybox:1.36@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662

EXPOSE 23

CMD ["telnetd", "-F", "-p", "23"]
