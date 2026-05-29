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

/*
 * Issue #776: handshake CIDs must not count toward active_connection_id_limit
 * per RFC 9000 §5.1.1.  Reproduces the nginx interop failure scenario.
 */
void xqc_test_cid_handshake_exclusion();

/* mark_original idempotency: repeated calls must not inflate original_cid_cnt */
void xqc_test_cid_mark_original_idempotent();

/* delete_cid must decrement original_cid_cnt when removing an original CID */
void xqc_test_cid_delete_original();

#endif

