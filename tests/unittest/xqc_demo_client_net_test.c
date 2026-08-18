/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include <string.h>

#include "demo/xqc_demo_client_net.h"
#include "xqc_demo_client_net_test.h"

void
xqc_test_demo_client_numeric_addr(void)
{
    struct sockaddr_in6 addr;
    struct sockaddr_in *addr4;
    int addr_len;

    CU_ASSERT_EQUAL(xqc_demo_cli_parse_numeric_addr("127.0.0.1", 8443,
                    &addr, &addr_len), 0);
    addr4 = (struct sockaddr_in *)&addr;
    CU_ASSERT_EQUAL(addr4->sin_family, AF_INET);
    CU_ASSERT_EQUAL(ntohs(addr4->sin_port), 8443);
    CU_ASSERT_EQUAL(addr_len, sizeof(*addr4));

    CU_ASSERT_EQUAL(xqc_demo_cli_parse_numeric_addr("::1", 443,
                    &addr, &addr_len), 0);
    CU_ASSERT_EQUAL(addr.sin6_family, AF_INET6);
    CU_ASSERT_EQUAL(ntohs(addr.sin6_port), 443);
    CU_ASSERT_EQUAL(addr_len, sizeof(addr));
}

void
xqc_test_demo_client_invalid_addr(void)
{
    struct sockaddr_in6 addr;
    int addr_len = -1;

    memset(&addr, 0xff, sizeof(addr));
    CU_ASSERT_EQUAL(xqc_demo_cli_parse_numeric_addr("not-an-ip", 8443,
                    &addr, &addr_len), -1);
    CU_ASSERT_EQUAL(addr.sin6_family, AF_UNSPEC);
    CU_ASSERT_EQUAL(addr_len, 0);
}
