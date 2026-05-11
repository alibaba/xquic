/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_CID_TEST_H
#define XQC_CID_TEST_H

void xqc_test_cid();

/*
 * Issue #585: cover the off-by-one boundary of xqc_cid_set_insert_cid.
 * RFC 9000 Section 5.1.1: active CID count (UNUSED + USED) MUST NOT exceed
 * active_connection_id_limit. The previous "> limit" check allowed (limit + 1)
 * active CIDs. The fix uses ">= limit"; this test pins the corrected behavior.
 */
void xqc_test_cid_active_limit();

#endif