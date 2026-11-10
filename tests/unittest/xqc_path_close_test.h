/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_PATH_CLOSE_TEST_H
#define XQC_PATH_CLOSE_TEST_H

/* PATH_ABANDON for a path ID without a path is answered */
void xqc_test_path_abandon_reply_without_path(void);

/* PATH_ABANDON says why a path is abandoned (RFC 10069 Section 4.2.1) */
void xqc_test_path_abandon_code_application(void);
void xqc_test_path_abandon_code_reply(void);
void xqc_test_path_abandon_code_broken_path(void);

#endif /* XQC_PATH_CLOSE_TEST_H */
