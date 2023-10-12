
/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_REINJECTION_H
#define XQC_REINJECTION_H

#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include "src/common/xqc_common.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_frame_parser.h"
#include "src/transport/xqc_multipath.h"


#define XQC_MP_FIRST_DATA_OFFSET  1460
#define XQC_MP_FIRST_FRAME_OFFSET 128 * 1024 /* 128k */
#define XQC_MP_PKT_REINJECTED(po) (po->po_flag & (XQC_POF_REINJECTED_ORIGIN | XQC_POF_REINJECTED_REPLICA))

void xqc_associate_packet_with_reinjection(xqc_packet_out_t *reinj_origin,
    xqc_packet_out_t *reinj_replica);

void xqc_conn_reinject_unack_packets(xqc_connection_t *conn, 
    xqc_reinjection_mode_t mode);

xqc_int_t xqc_conn_try_reinject_packet(xqc_connection_t *conn, 
    xqc_packet_out_t *packet_out);

#endif /* XQC_REINJECTION_H */


