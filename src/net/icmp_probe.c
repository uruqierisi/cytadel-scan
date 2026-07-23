/* _DEFAULT_SOURCE (ahead of _POSIX_C_SOURCE) is required for glibc to
 * expose the BSD-derived `struct ip` (netinet/ip.h) and `struct icmphdr`
 * (netinet/ip_icmp.h) used to build/parse raw ICMP packets -- neither is
 * part of strict POSIX, so _POSIX_C_SOURCE alone (as used by the rest of
 * this codebase) hides them. */
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "icmp_probe.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "log.h"
#include "strerror_safe.h"

static uint16_t cytadel_icmp_checksum(const void *data, size_t len) {
    const uint8_t *bytes = data;
    uint32_t sum = 0;

    size_t i = 0;
    while (i + 1 < len) {
        uint16_t word = (uint16_t)((bytes[i] << 8) | bytes[i + 1]);
        sum += word;
        i += 2;
    }
    if (i < len) {
        sum += (uint16_t)(bytes[i] << 8);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

static long cytadel_icmp_elapsed_ms(const struct timespec *start, const struct timespec *now) {
    return (now->tv_sec - start->tv_sec) * 1000L + (now->tv_nsec - start->tv_nsec) / 1000000L;
}

cytadel_icmp_result_t cytadel_icmp_echo_probe(const char *ip, int timeout_ms) {
    if (ip == NULL) {
        return CYTADEL_ICMP_UNAVAILABLE;
    }
    if (timeout_ms < 0) {
        timeout_ms = 0;
    }

    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_debug("icmp echo probe: raw socket unavailable for %s: %s",
                           ip, cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        return CYTADEL_ICMP_UNAVAILABLE;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &dest.sin_addr) != 1) {
        cytadel_log_warn("icmp echo probe: invalid IPv4 literal '%s'", ip);
        close(fd);
        return CYTADEL_ICMP_UNAVAILABLE;
    }

    uint16_t ident = (uint16_t)(getpid() & 0xFFFF);
    uint16_t seq = 1;

    struct icmphdr req;
    memset(&req, 0, sizeof(req));
    req.type = ICMP_ECHO;
    req.code = 0;
    req.un.echo.id = htons(ident);
    req.un.echo.sequence = htons(seq);
    req.checksum = 0;
    req.checksum = htons(cytadel_icmp_checksum(&req, sizeof(req)));

    if (sendto(fd, &req, sizeof(req), 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        char errbuf[CYTADEL_STRERROR_BUF_LEN];
        cytadel_log_debug("icmp echo probe: sendto() failed for %s: %s", ip,
                           cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
        close(fd);
        return CYTADEL_ICMP_NO_REPLY;
    }

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(fd);
        return CYTADEL_ICMP_NO_REPLY;
    }

    cytadel_icmp_result_t result = CYTADEL_ICMP_NO_REPLY;
    uint8_t buf[128];

    for (;;) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            break;
        }
        long remaining_ms = (long)timeout_ms - cytadel_icmp_elapsed_ms(&start, &now);
        if (remaining_ms <= 0) {
            break; /* timed out -- no reply */
        }

        struct pollfd pfd;
        pfd.fd = fd;
        pfd.events = POLLIN;
        pfd.revents = 0;

        int poll_rc = poll(&pfd, 1, (int)remaining_ms);
        if (poll_rc == 0) {
            break; /* timed out -- no reply */
        }
        if (poll_rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            cytadel_log_debug("icmp echo probe: poll() failed for %s: %s", ip,
                               cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
            break;
        }

        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            char errbuf[CYTADEL_STRERROR_BUF_LEN];
            cytadel_log_debug("icmp echo probe: recvfrom() failed for %s: %s", ip,
                               cytadel_strerror_safe(errno, errbuf, sizeof(errbuf)));
            break;
        }

        /* A raw IPPROTO_ICMP socket receives every ICMP packet delivered
         * to this host, not just replies to our own probe -- keep waiting
         * (until the deadline) for one that actually matches. */
        if ((size_t)n < sizeof(struct ip)) {
            continue;
        }
        const struct ip *ip_hdr = (const struct ip *)(const void *)buf;
        size_t ip_hdr_len = (size_t)ip_hdr->ip_hl * 4u;
        if (ip_hdr_len < sizeof(struct ip) || (size_t)n < ip_hdr_len + sizeof(struct icmphdr)) {
            continue;
        }
        const struct icmphdr *icmp_hdr = (const struct icmphdr *)(const void *)(buf + ip_hdr_len);
        if (icmp_hdr->type == ICMP_ECHOREPLY &&
            ntohs(icmp_hdr->un.echo.id) == ident &&
            ntohs(icmp_hdr->un.echo.sequence) == seq &&
            from.sin_addr.s_addr == dest.sin_addr.s_addr) {
            result = CYTADEL_ICMP_REPLY_UP;
            break;
        }
    }

    close(fd);
    return result;
}
