/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_recv_record_test.h"
#include "src/transport/xqc_packet.h"
#include "src/transport/xqc_recv_record.h"
#include "src/transport/xqc_recv_timestamps_info.h"
#include <string.h>
#include <CUnit/CUnit.h>
#include <stdio.h>

void
xqc_test_recv_record()
{
    xqc_list_head_t *pos;
    xqc_pktno_range_node_t *pnode;
    xqc_recv_record_t record;
    memset(&record, 0, sizeof(xqc_recv_record_t));
    xqc_init_list_head(&record.list_head);

    xqc_recv_record_add(&record, 0);
    xqc_recv_record_add(&record, 1);
    xqc_recv_record_add(&record, 10);
    xqc_recv_record_add(&record, 2);

    xqc_list_for_each(pos, &record.list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        //printf("low:%llu, high=%llu\n", pnode->pktno_range.low, pnode->pktno_range.high);
    }

    /* printf("largest=%llu\n", xqc_recv_record_largest(&record)); */
    CU_ASSERT(10 == xqc_recv_record_largest(&record));


    xqc_recv_record_del(&record, 5);
    xqc_list_for_each(pos, &record.list_head) {
        pnode = xqc_list_entry(pos, xqc_pktno_range_node_t, list);
        //printf("low:%llu, high=%llu\n", pnode->pktno_range.low, pnode->pktno_range.high);
    }

    xqc_recv_record_destroy(&record);
}


/*
 * The receive timestamps ring flags the slots whose packet opens a new
 * range in a 64-bit word, so the flags of slots 31 and above must be
 * shifted as 64-bit values. Each range costs two bytes in the size
 * estimate of the ACK frame's timestamps.
 */
void
xqc_test_recv_timestamps_range_flag()
{
    const uint64_t  gapped = 40, consecutive = 10;
    const uint64_t  ranges = ((1ULL << gapped) - 1) & ~1ULL;
    uint64_t        pn;

    xqc_recv_timestamps_info_t *ts_info = xqc_recv_timestamps_info_create();
    CU_ASSERT_PTR_NOT_NULL_FATAL(ts_info);

    /* every other packet number: each packet after the first opens a range */
    for (pn = 0; pn < 2 * gapped; pn += 2) {
        xqc_recv_timestamps_info_add_pkt(ts_info, pn, 1000 * pn);
    }
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_need_bytes_estimate(ts_info)
              == 1 + gapped * 2 + 4 + (gapped - 1));

    /* consecutive packets clear only their own slots */
    for (pn = 2 * gapped - 1; pn < 2 * gapped - 1 + consecutive; pn++) {
        xqc_recv_timestamps_info_add_pkt(ts_info, pn, 1000 * pn);
    }
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_length(ts_info)
              == gapped + consecutive);

    /* abnormal: a reordered packet is not recorded */
    xqc_recv_timestamps_info_add_pkt(ts_info, 1, 1000);
    CU_ASSERT(ts_info->new_range_flag == ranges);
    CU_ASSERT(xqc_recv_timestamps_info_length(ts_info)
              == gapped + consecutive);

    xqc_recv_timestamps_info_destroy(ts_info);
}
