#include "cytadel_test.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#include "cytadel/net/port_range.h"
#include "cytadel/net/port_scanner.h"
#include "cytadel/net/tcp_connect.h"

/* Hermetic loopback fixture: binds a real TCP listener on an
 * OS-assigned (ephemeral) 127.0.0.1 port, so there is no fixed port that
 * could collide with something else already running, and no dependency on
 * external network access. Returns the listening fd and writes the bound
 * port number into *out_port. */
static int cytadel_test_bind_ephemeral_listener(uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CYTADEL_ASSERT(fd >= 0);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; /* ask the OS for an ephemeral port */

    CYTADEL_ASSERT(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    CYTADEL_ASSERT(listen(fd, 1) == 0);

    struct sockaddr_in bound;
    socklen_t bound_len = sizeof(bound);
    CYTADEL_ASSERT(getsockname(fd, (struct sockaddr *)&bound, &bound_len) == 0);

    *out_port = ntohs(bound.sin_port);
    return fd;
}

static void test_open_port_is_detected(void) {
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral_listener(&port);

    cytadel_port_state_t state = cytadel_net_tcp_connect_probe("127.0.0.1", port, 1000);
    CYTADEL_ASSERT_EQ(state, CYTADEL_PORT_OPEN);

    close(listen_fd);
}

static void test_closed_port_is_detected(void) {
    /* Bind-then-close: reserves a port the OS just handed us (so it can't
     * collide with anything else), then immediately releases it so
     * nothing is listening -- loopback delivers an immediate RST /
     * ECONNREFUSED for a connect to a closed port, which is deterministic
     * on Linux, unlike probing an arbitrary fixed "probably closed" port
     * number. */
    uint16_t port;
    int listen_fd = cytadel_test_bind_ephemeral_listener(&port);
    close(listen_fd);

    cytadel_port_state_t state = cytadel_net_tcp_connect_probe("127.0.0.1", port, 1000);
    CYTADEL_ASSERT_EQ(state, CYTADEL_PORT_CLOSED);
}

static void test_port_scan_classifies_open_and_closed(void) {
    uint16_t open_port;
    int listen_fd = cytadel_test_bind_ephemeral_listener(&open_port);

    uint16_t closed_port;
    int closed_listen_fd = cytadel_test_bind_ephemeral_listener(&closed_port);
    close(closed_listen_fd);

    cytadel_port_list_t ports;
    ports.count = 2;
    uint16_t port_values[2] = { open_port, closed_port };
    ports.ports = port_values;

    cytadel_port_scan_opts_t opts;
    opts.connect_timeout_ms = 1000;
    opts.backend = NULL; /* auto-select */

    cytadel_port_result_t *results = NULL;
    size_t result_count = 0;
    int rc = cytadel_port_scan("127.0.0.1", &ports, &opts, &results, &result_count);

    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(result_count, 2);
    CYTADEL_ASSERT_EQ(results[0].port, open_port);
    CYTADEL_ASSERT_EQ(results[0].state, CYTADEL_PORT_OPEN);
    CYTADEL_ASSERT_EQ(results[1].port, closed_port);
    CYTADEL_ASSERT_EQ(results[1].state, CYTADEL_PORT_CLOSED);

    free(results);
    close(listen_fd);
}

static void test_port_scan_empty_list_returns_empty(void) {
    cytadel_port_list_t ports;
    ports.count = 0;
    ports.ports = NULL;

    cytadel_port_result_t *results = (cytadel_port_result_t *)0x1; /* poison */
    size_t result_count = 999;

    int rc = cytadel_port_scan("127.0.0.1", &ports, NULL, &results, &result_count);

    CYTADEL_ASSERT_EQ(rc, 0);
    CYTADEL_ASSERT_EQ(result_count, 0);
    CYTADEL_ASSERT(results == NULL);
}

int main(void) {
    test_open_port_is_detected();
    test_closed_port_is_detected();
    test_port_scan_classifies_open_and_closed();
    test_port_scan_empty_list_returns_empty();
    CYTADEL_TEST_PASS();
}
