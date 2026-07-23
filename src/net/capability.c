#define _POSIX_C_SOURCE 200809L

#include "cytadel/net/capability.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

bool cytadel_net_can_use_raw_sockets(void) {
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) {
        return false;
    }
    close(fd);
    return true;
}
