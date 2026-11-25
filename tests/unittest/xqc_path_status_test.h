/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PATH_STATUS_TEST_H
#define XQC_PATH_STATUS_TEST_H

/* the peer's status frames, numbered from 0 (RFC 10069 Section 4.3) */
void xqc_test_path_status_first_seq_zero(void);

/* each side indicates its status independently (RFC 10069 Section 3.3) */
void xqc_test_path_status_local_and_peer_apart(void);
void xqc_test_path_status_before_validation(void);

#endif /* XQC_PATH_STATUS_TEST_H */
