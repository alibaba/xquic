/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef _XQC_MOQT_WEBTRANSPORT_H_INCLUDED_
#define _XQC_MOQT_WEBTRANSPORT_H_INCLUDED_

#include <moq/xqc_moqt.h>
#include <xquic/xqc_webtransport.h>

#ifdef XQC_ENABLE_WEBTRANSPORT
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Bind in WT session_create_notify after CONNECT selects moqt-22. Requires
 * WT draft-16, an open session with no streams/binding, and no AUTHORITY/PATH
 * Setup Options (draft-22 6.2.1, 9.1.1/9.1.2). CONNECT/Origin policy remains
 * application-owned. Copies config/callbacks; H3 application data is unchanged.
 * Start with xqc_moqt_session_start; readiness still requires both SETUPs.
 * Use MoQT APIs for this WT session's streams/datagrams after binding.
 * Destroy in WT session_close_notify, before the H3 connection is destroyed.
 * MoQT callbacks may close/send, but must not destroy the MoQT session.
 */
XQC_EXPORT_PUBLIC_API
xqc_moqt_session_t *xqc_moqt_session_create_webtransport(
    xqc_wt_session_t *transport, const xqc_moqt_config_t *config,
    const xqc_moqt_callbacks_t *callbacks, void *user_data);

#ifdef __cplusplus
}
#endif
#endif
#endif
