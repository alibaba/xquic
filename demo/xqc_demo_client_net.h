/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_DEMO_CLIENT_NET_H_INCLUDED_
#define _XQC_DEMO_CLIENT_NET_H_INCLUDED_

#include <xquic/xquic.h>

int xqc_demo_cli_parse_numeric_addr(const char *server_addr,
    unsigned short server_port, struct sockaddr_in6 *addr, int *addr_len);

#endif /* _XQC_DEMO_CLIENT_NET_H_INCLUDED_ */
