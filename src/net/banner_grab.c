#define _POSIX_C_SOURCE 200809L

#include "banner_grab.h"

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

/* Non-blocking connect + poll(POLLOUT), same shape as
 * cytadel_net_tcp_connect_probe() (tcp_connect.c) but this variant keeps
 * the socket open on success and returns its fd instead of closing it --
 * banner_grab needs to read from the connection afterward, tcp_connect.c's
 * probe never does (detection-only port classification only). Returns the
 * connected fd (>= 0) on success, -1 on any connect failure (fd already
 * closed in that case). */
static int cytadel_banner_connect(const char *ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("banner grab: socket() failed for %s:%u: %s", ip, (unsigned)port,
                          cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("banner grab: fcntl(O_NONBLOCK) failed for %s:%u: %s", ip, (unsigned)port,
                          cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        cytadel_log_warn("banner grab: invalid IPv4 literal '%s'", ip);
        close(fd);
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        return fd; /* rare for non-blocking, but possible (e.g. loopback) */
    }
    if (errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLOUT;
    pfd.revents = 0;

    int poll_rc = poll(&pfd, 1, (timeout_ms < 0) ? 0 : timeout_ms);
    if (poll_rc <= 0) {
        close(fd);
        return -1;
    }

    int so_error = 0;
    socklen_t so_error_len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &so_error_len) != 0 || so_error != 0) {
        close(fd);
        return -1;
    }

    return fd;
}

int cytadel_net_banner_grab(const char *ip, uint16_t port, int connect_timeout_ms,
                             int read_timeout_ms, cytadel_banner_t *out_banner) {
    if (out_banner != NULL) {
        memset(out_banner, 0, sizeof(*out_banner));
    }
    if (ip == NULL || port == 0 || out_banner == NULL) {
        return -1;
    }

    int fd = cytadel_banner_connect(ip, port, connect_timeout_ms);
    if (fd < 0) {
        return -1;
    }

    if (read_timeout_ms < 0) {
        read_timeout_ms = 0;
    }

    size_t len = 0;
    /* Bounded read loop: never writes past out_banner->data[CYTADEL_BANNER_
     * MAX_LEN] (the last byte is reserved for the NUL terminator below),
     * and `remaining` is recomputed from the running `len` on every
     * iteration so a fast/chunked/malicious sender cannot overrun the
     * buffer no matter how many recv() calls it takes to fill it. */
    while (len < CYTADEL_BANNER_MAX_LEN) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int poll_rc = poll(&pfd, 1, read_timeout_ms);
        if (poll_rc <= 0) {
            break; /* timeout, or poll() error -- keep whatever was read so far */
        }

        size_t remaining = CYTADEL_BANNER_MAX_LEN - len;
        ssize_t n = recv(fd, out_banner->data + len, remaining, 0);
        if (n <= 0) {
            break; /* EOF (n == 0) or recv() error (n < 0) */
        }
        len += (size_t)n;
    }

    out_banner->data[len] = '\0';
    out_banner->len = len;

    close(fd);
    return 0;
}
