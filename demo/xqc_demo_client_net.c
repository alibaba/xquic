/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <string.h>

#include "xqc_demo_client_net.h"

int
xqc_demo_cli_parse_numeric_addr(const char *server_addr,
    unsigned short server_port, struct sockaddr_in6 *addr, int *addr_len)
{
    struct sockaddr_in *addr4;

    if (server_addr == NULL || addr == NULL || addr_len == NULL) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    *addr_len = 0;

    addr4 = (struct sockaddr_in *)addr;
    if (inet_pton(AF_INET, server_addr, &addr4->sin_addr) == 1) {
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(server_port);
        *addr_len = sizeof(*addr4);
        return 0;
    }

    if (inet_pton(AF_INET6, server_addr, &addr->sin6_addr) == 1) {
        addr->sin6_family = AF_INET6;
        addr->sin6_port = htons(server_port);
        *addr_len = sizeof(*addr);
        return 0;
    }

    memset(addr, 0, sizeof(*addr));
    return -1;
}
