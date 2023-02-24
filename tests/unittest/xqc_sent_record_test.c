/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_sent_record_test.h"
#include "src/transport/xqc_send_ctl.h"
#include "src/common/xqc_list.h"
#include <CUnit/CUnit.h>


void 
xqc_test_sent_record()
{
    int pn_array[10] = {1, 13, 66, 98, 101, 102, 233, 234, 235};
    int i = 0;
    int ret;
    xqc_sent_record_t sent_record;

    xqc_sent_record_init(&sent_record);

    for (i = 0; i < 9; i++) {
        xqc_sent_record_add(&sent_record, pn_array[i], 0);
    }

    xqc_list_head_t *pos, *next;
    xqc_packet_number_node_t *pnode;
    i = 0;
    xqc_list_for_each_safe(pos, next, &sent_record.sent_pn_list) {
        pnode = xqc_list_entry(pos, xqc_packet_number_node_t, pn_list);
        // printf("|pn[%d]:%d|", i, (int)pnode->pkt_num);
        CU_ASSERT(pn_array[i++] == pnode->pkt_num);
    }


    xqc_packet_number_t gap;

    ret = xqc_sent_record_pn_gap(&sent_record, 13, 102, &gap);
    CU_ASSERT(XQC_OK == ret && 4 == gap);

    ret = xqc_sent_record_pn_gap(&sent_record, 14, 102, &gap);
    CU_ASSERT(XQC_ERROR == ret);

    ret = xqc_sent_record_pn_gap(&sent_record, 66, 103, &gap);
    CU_ASSERT(XQC_ERROR == ret);

    ret = xqc_sent_record_pn_gap(&sent_record, 235, 236, &gap);
    CU_ASSERT(XQC_ERROR == ret);

    ret = xqc_sent_record_pn_gap(&sent_record, 98, 98, &gap);
    CU_ASSERT(XQC_OK == ret && 0 == gap);

    
    xqc_packet_number_t lost_sent_pn;

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 66, 5, &lost_sent_pn);
    CU_ASSERT(XQC_OK == ret && XQC_MAX_UINT64_VALUE == lost_sent_pn);

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 101, 5, &lost_sent_pn);
    CU_ASSERT(XQC_OK == ret && XQC_MAX_UINT64_VALUE == lost_sent_pn);

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 234, 5, &lost_sent_pn);
    // printf("|lost_sent_pn:%d|", (int)lost_sent_pn);
    CU_ASSERT(XQC_OK == ret && 66 == lost_sent_pn);

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 105, 5, &lost_sent_pn);
    CU_ASSERT(XQC_ERROR == ret && XQC_MAX_UINT64_VALUE == lost_sent_pn);

    sent_record.latest_rtt_pn = 67;
    xqc_sent_record_del(&sent_record);

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 234, 5, &lost_sent_pn);
    CU_ASSERT(XQC_OK == ret && XQC_MAX_UINT64_VALUE == lost_sent_pn);

    ret = xqc_sent_record_lost_sent_pn(&sent_record, 236, 5, &lost_sent_pn);
    CU_ASSERT(XQC_ERROR == ret && XQC_MAX_UINT64_VALUE == lost_sent_pn);

    xqc_sent_record_release(&sent_record);
}



void 
xqc_test_sent_record_get_largest_pn_in_ack()
{
    xqc_ack_info_t ack_info;
    ack_info.n_ranges = 2;
    ack_info.ranges[0].high = 10;
    ack_info.ranges[0].low = 8;
    ack_info.ranges[1].high = 6;
    ack_info.ranges[1].low = 2;

    int pn_array[10] = {5, 6, 8, 11, 12, 102, 233, 234, 235};
    
    xqc_sent_record_t sent_record;
    xqc_sent_record_init(&sent_record);

    for (int i = 0; i < 9; i++) {
        xqc_sent_record_add(&sent_record, pn_array[i], 0);
    }

    xqc_packet_number_node_t *largest_pn_node = NULL;

    int ret = xqc_sent_record_get_largest_pn_in_ack(&sent_record, &ack_info, &largest_pn_node);
    CU_ASSERT(XQC_OK == ret && 8 == largest_pn_node->pkt_num);

    xqc_sent_record_release(&sent_record);
}