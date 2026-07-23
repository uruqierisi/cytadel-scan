#define _POSIX_C_SOURCE 200809L

#include "http_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <strings.h> /* strncasecmp */
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "strerror_safe.h"

/* Bounded working buffer for the raw response (status line + headers +
 * enough of the body to find an optional <title>). Independent of
 * CYTADEL_KB_VALUE_MAX_LEN -- what we ultimately store in the KB (server/
 * status/title) is much smaller than what we may need to read to find
 * them. */
#define CYTADEL_HTTP_RESPONSE_MAX_LEN 8192

/* Same non-blocking connect()+poll(POLLOUT) shape as tcp_connect.c's probe
 * and banner_grab.c's cytadel_banner_connect() -- duplicated here rather
 * than shared, matching this codebase's existing pattern of each src/net
 * primitive owning its own connect step (tcp_connect.c and banner_grab.c
 * already do this independently for the same reason: each needs slightly
 * different post-connect behavior). Returns the connected fd (>= 0) on
 * success, -1 on any failure (fd already closed). */
static int cytadel_http_connect(const char *ip, uint16_t port, int timeout_ms) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_warn("http probe: socket() failed for %s:%u: %s", ip, (unsigned)port,
                          cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        close(fd);
        return -1;
    }

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        return fd;
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

static int cytadel_http_build_request(const char *host, char *out, size_t out_len) {
    /* HTTP/1.0 + "Connection: close" avoids chunked-transfer/keep-alive
     * handling entirely -- the server closes the connection when done, so
     * a plain bounded read-until-EOF-or-cap is sufficient to capture the
     * headers and (usually) enough of the body to find a <title>. `host`
     * is only ever this codebase's own resolved IPv4 literal
     * (CYTADEL_NET_IP_STR_MAX = 46 bytes) or a caller-supplied hostname
     * bounded the same way -- either way this is bounds-checked via
     * snprintf's return value, never assumed to fit. */
    int written = snprintf(out, out_len, "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n",
                            host);
    if (written < 0 || (size_t)written >= out_len) {
        return -1;
    }
    return written;
}

/* Bounded, index-checked HTTP/1.x response parser. `buf` need not be
 * NUL-terminated beyond `len` -- every access below is guarded by an
 * explicit bound against `len` before it happens, so a truncated/garbage/
 * oversized response (this codebase's untrusted-input hardening concern)
 * can never cause an out-of-bounds read here, only a partially- or
 * un-populated *out. */
static void cytadel_http_parse_response(const char *buf, size_t len, cytadel_http_probe_result_t *out) {
    out->status = -1;
    out->server[0] = '\0';
    out->server_len = 0;
    out->title[0] = '\0';
    out->title_len = 0;

    if (len == 0) {
        return;
    }

    /* Status line: "HTTP/<version> SP <3-digit-status> ..." */
    if (len >= 5 && memcmp(buf, "HTTP/", 5) == 0) {
        size_t i = 5;
        while (i < len && buf[i] != ' ' && buf[i] != '\n') {
            i++;
        }
        if (i < len && buf[i] == ' ') {
            i++;
            if (i + 3 <= len && buf[i] >= '0' && buf[i] <= '9' && buf[i + 1] >= '0' &&
                buf[i + 1] <= '9' && buf[i + 2] >= '0' && buf[i + 2] <= '9') {
                out->status = (buf[i] - '0') * 100 + (buf[i + 1] - '0') * 10 + (buf[i + 2] - '0');
            }
        }
    }

    /* Skip to the end of the status line, then walk header lines until a
     * blank line (end of headers) or the buffer is exhausted. */
    size_t pos = 0;
    while (pos < len && buf[pos] != '\n') {
        pos++;
    }
    if (pos < len) {
        pos++;
    }

    size_t headers_end = len; /* if no blank line is ever found, there is no body to search */
    size_t line_start = pos;
    while (line_start < len) {
        size_t line_end = line_start;
        while (line_end < len && buf[line_end] != '\n') {
            line_end++;
        }
        size_t content_end = line_end;
        if (content_end > line_start && buf[content_end - 1] == '\r') {
            content_end--;
        }

        if (content_end == line_start) {
            headers_end = (line_end < len) ? line_end + 1 : line_end;
            break;
        }

        size_t colon = line_start;
        while (colon < content_end && buf[colon] != ':') {
            colon++;
        }
        if (colon < content_end) {
            size_t name_len = colon - line_start;
            size_t value_start = colon + 1;
            while (value_start < content_end && (buf[value_start] == ' ' || buf[value_start] == '\t')) {
                value_start++;
            }
            size_t value_len = content_end - value_start;

            if (name_len == 6 && strncasecmp(buf + line_start, "Server", 6) == 0) {
                size_t copy_len = (value_len < sizeof(out->server) - 1) ? value_len
                                                                          : sizeof(out->server) - 1;
                memcpy(out->server, buf + value_start, copy_len);
                out->server[copy_len] = '\0';
                out->server_len = copy_len;
            }
        }

        line_start = (line_end < len) ? line_end + 1 : line_end;
    }

    if (headers_end >= len) {
        return; /* no body captured (or none present) -- no <title> to find */
    }

    const char *body = buf + headers_end;
    size_t body_len = len - headers_end;
    static const char open_tag[] = "<title>";
    static const char close_tag[] = "</title>";
    const size_t open_len = sizeof(open_tag) - 1;
    const size_t close_len = sizeof(close_tag) - 1;

    for (size_t i = 0; i + open_len <= body_len; i++) {
        if (strncasecmp(body + i, open_tag, open_len) != 0) {
            continue;
        }
        size_t title_start = i + open_len;
        for (size_t j = title_start; j + close_len <= body_len; j++) {
            if (strncasecmp(body + j, close_tag, close_len) == 0) {
                size_t title_len = j - title_start;
                size_t copy_len =
                    (title_len < sizeof(out->title) - 1) ? title_len : sizeof(out->title) - 1;
                memcpy(out->title, body + title_start, copy_len);
                out->title[copy_len] = '\0';
                out->title_len = copy_len;
                return;
            }
        }
        return; /* <title> found but no matching </title> within body_len -- stop looking */
    }
}

int cytadel_net_http_probe_plain(const char *ip, uint16_t port, int connect_timeout_ms,
                                  int read_timeout_ms, cytadel_http_probe_result_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->status = -1;
    }
    if (ip == NULL || out == NULL) {
        return -1;
    }

    int fd = cytadel_http_connect(ip, port, connect_timeout_ms);
    if (fd < 0) {
        return -1;
    }

    char request[300];
    int req_len = cytadel_http_build_request(ip, request, sizeof(request));
    if (req_len < 0) {
        close(fd);
        return -1;
    }

    size_t sent = 0;
    while (sent < (size_t)req_len) {
        ssize_t n = send(fd, request + sent, (size_t)req_len - sent, 0);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        sent += (size_t)n;
    }

    if (read_timeout_ms < 0) {
        read_timeout_ms = 0;
    }

    char buf[CYTADEL_HTTP_RESPONSE_MAX_LEN + 1];
    size_t len = 0;
    while (len < CYTADEL_HTTP_RESPONSE_MAX_LEN) {
        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        int poll_rc = poll(&pfd, 1, read_timeout_ms);
        if (poll_rc <= 0) {
            break;
        }
        ssize_t n = recv(fd, buf + len, CYTADEL_HTTP_RESPONSE_MAX_LEN - len, 0);
        if (n <= 0) {
            break;
        }
        len += (size_t)n;
    }
    buf[len] = '\0';
    close(fd);

    cytadel_http_parse_response(buf, len, out);
    return 0;
}

int cytadel_net_http_probe_tls(SSL *ssl, const char *host, int read_timeout_ms,
                                cytadel_http_probe_result_t *out) {
    if (out != NULL) {
        memset(out, 0, sizeof(*out));
        out->status = -1;
    }
    if (ssl == NULL || host == NULL || out == NULL) {
        return -1;
    }

    char request[300];
    int req_len = cytadel_http_build_request(host, request, sizeof(request));
    if (req_len < 0) {
        return -1;
    }

    size_t sent = 0;
    while (sent < (size_t)req_len) {
        int n = SSL_write(ssl, request + sent, (int)((size_t)req_len - sent));
        if (n <= 0) {
            return -1;
        }
        sent += (size_t)n;
    }

    /* The underlying socket was already switched to blocking mode with
     * SO_RCVTIMEO/SO_SNDTIMEO by cytadel_net_tls_connect() (tls_session.c)
     * -- SSL_read() below already respects that kernel-level timeout, so
     * no separate poll() step is needed (or possible to do meaningfully
     * for TLS reads, since SSL_read() may need to perform its own
     * internal re-reads for record framing that a raw poll() on the fd
     * cannot observe). read_timeout_ms is accepted for API symmetry with
     * the plain variant but the actual bound comes from the socket
     * timeout already configured on this session. */
    (void)read_timeout_ms;

    char buf[CYTADEL_HTTP_RESPONSE_MAX_LEN + 1];
    size_t len = 0;
    while (len < CYTADEL_HTTP_RESPONSE_MAX_LEN) {
        int n = SSL_read(ssl, buf + len, (int)(CYTADEL_HTTP_RESPONSE_MAX_LEN - len));
        if (n <= 0) {
            break;
        }
        len += (size_t)n;
    }
    buf[len] = '\0';

    cytadel_http_parse_response(buf, len, out);
    return 0;
}
