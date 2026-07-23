#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/tcp_connect.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "strerror_safe.h"

cytadel_port_state_t cytadel_net_tcp_connect_probe(const char *ip, uint16_t port,
                                                     int timeout_ms) {
    if (ip == NULL || port == 0) {
        return CYTADEL_PORT_FILTERED;
    }
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("tcp connect probe: socket() failed for %s:%u: %s",
                          ip, (unsigned)port, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return CYTADEL_PORT_FILTERED;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("tcp connect probe: fcntl(O_NONBLOCK) failed for %s:%u: %s",
                          ip, (unsigned)port, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        close(fd);
        return CYTADEL_PORT_FILTERED;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        cytadel_log_warn("tcp connect probe: invalid IPv4 literal '%s'", ip);
        close(fd);
        return CYTADEL_PORT_FILTERED;
    }

    cytadel_port_state_t state;
    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        /* Rare for a non-blocking socket, but possible (e.g. loopback). */
        state = CYTADEL_PORT_OPEN;
    } else if (errno == EINPROGRESS) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLOUT;
        pfd.revents = 0;

        int poll_rc = poll(&pfd, 1, timeout_ms);
        if (poll_rc == 0) {
            /* No response within the budget -- detection-only, so we do
             * not distinguish "host down" from "firewall silently drops":
             * both are reported as filtered. */
            state = CYTADEL_PORT_FILTERED;
        } else if (poll_rc < 0) {
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            cytadel_log_warn("tcp connect probe: poll() failed for %s:%u: %s",
                              ip, (unsigned)port, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
            state = CYTADEL_PORT_FILTERED;
        } else {
            int so_error = 0;
            socklen_t so_error_len = sizeof(so_error);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0) {
                char errbuf[CYTADEL_STRERROR_BUF_LEN];
                cytadel_log_warn("tcp connect probe: getsockopt(SO_ERROR) failed for %s:%u: %s",
                                  ip, (unsigned)port, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
                state = CYTADEL_PORT_FILTERED;
            } else if (so_error == 0) {
                state = CYTADEL_PORT_OPEN;
            } else if (so_error == ECONNREFUSED) {
                state = CYTADEL_PORT_CLOSED;
            } else {
                state = CYTADEL_PORT_FILTERED;
            }
        }
    } else if (errno == ECONNREFUSED) {
        state = CYTADEL_PORT_CLOSED;
    } else {
        state = CYTADEL_PORT_FILTERED;
    }

    /* Detection-only (docs/build-plan.md / the detection-only rule): never send
     * or read a single byte beyond the TCP handshake itself -- close
     * immediately on every path above. */
    close(fd);
    return state;
}
