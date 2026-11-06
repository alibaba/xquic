/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_CID_TEST_H
#define XQC_CID_TEST_H

void xqc_test_cid();

/* the debug log of a NEW_CONNECTION_ID frame shows the frame's token */
void xqc_test_new_cid_log_token();

/* the debug log of an MP_NEW_CONNECTION_ID frame shows the frame's token */
void xqc_test_mp_new_cid_log_token();

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

/* rejected NEW_CONNECTION_ID must not leave orphaned engine hash entries */
void xqc_test_new_conn_id_insert_failure_hash_rollback();

/* two-phase retirement cleanup of a single expired SCID */
void xqc_test_retired_scid_cleanup();

/* expired RETIRED CIDs are purged in batch; non-expired ones stay and the
 * timer is re-armed */
void xqc_test_retired_scid_batch_cleanup();

/* safety-net branch: pre-existing REMOVED CIDs are purged when the timer fires */
void xqc_test_removed_scid_safety_net();

/* CID hash removal must preserve an equal key owned by another connection. */
void xqc_test_conns_hash_remove_owned_entry();

/* Removing an equal key with a non-owner must leave all mappings intact. */
void xqc_test_conns_hash_reject_non_owner();

/*
 * MP_NEW_CONNECTION_ID for a path ID within our limit but above the peer's
 * is stored rather than retired, and later MAX_PATH_ID keeps it.
 */
void xqc_test_mp_new_cid_above_curr_max_path_id();

/* rejected MP_NEW_CONNECTION_ID frames leave no connection ID set behind */
void xqc_test_mp_new_cid_rejected_without_cid_set();

/*
 * a path ID abandoned above the peer's limit stays abandoned after the
 * peer's MAX_PATH_ID allows it
 */
void xqc_test_mp_abandon_above_curr_max_path_id();

/* rejected PATH_ABANDON frames leave no connection ID set behind */
void xqc_test_mp_abandon_rejected_without_cid_set();

/* MP_RETIRE_CONNECTION_ID for a path ID without our connection IDs */
void xqc_test_mp_retire_cid_without_cid_set();

/* a failed connection ID set lookup is an error, not a retirement */
void xqc_test_cid_set_lookup_error();

/*
 * a Retire Prior To that retires every connection ID of the peer, the one
 * in use included, stores the new one and moves the path to it
 */
void xqc_test_retire_prior_to_full_set();

/* a Retire Prior To that leaves the limit exceeded is still an error */
void xqc_test_retire_prior_to_still_over_limit();

/* the same as xqc_test_retire_prior_to_full_set, for path ID 1 */
void xqc_test_mp_retire_prior_to_full_set();

/*
 * a retired connection ID is freed once its RETIRE_CONNECTION_ID frame is
 * acknowledged, so that repeated rotations keep one connection ID
 */
void xqc_test_retire_prior_to_rotation_bounded();

/* the same as xqc_test_retire_prior_to_rotation_bounded, for path ID 1 */
void xqc_test_mp_retire_prior_to_rotation_bounded();

/* too many retired connection IDs awaiting an acknowledgment is an error */
void xqc_test_retire_prior_to_unacked_limit();

#endif

