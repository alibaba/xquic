#include "src/transport/xqc_recv_timestamps_info.h"
#include "src/common/xqc_malloc.h"

#define RECV_TIMESTAMPS_INFO_NEXT_IDX(pkt_num) ((pkt_num + 1) & (XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH - 1))

static unsigned int
xqc_popcountll(uint64_t num)
{
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll(num);
#elif defined(_MSC_VER)
    return __popcnt64(num);
#else
    unsigned int count = 0;
    while (num) {
        count += num & 1;
        num >>= 1;
    }
    return count;
#endif
}

xqc_recv_timestamps_info_t *
xqc_recv_timestamps_info_create()
{
    xqc_recv_timestamps_info_t *ts_info =
                    xqc_calloc(1, sizeof(xqc_recv_timestamps_info_t));
    ts_info->is_first_pkt = 1;
    return ts_info;
}

void
xqc_recv_timestamps_info_destroy(xqc_recv_timestamps_info_t *ts_info)
{
    if (ts_info) {
        xqc_free(ts_info);
    }
}

void
xqc_recv_timestamps_info_add_pkt(xqc_recv_timestamps_info_t *ts_info,
    xqc_packet_number_t pkt_num, xqc_usec_t recv_time)
{
    if (ts_info->is_first_pkt) {
        ts_info->is_first_pkt = 0;
        ts_info->expected_next_pkt_num = pkt_num;
    }
    /* don't support reporting out-of-order packet */
    if (pkt_num < ts_info->expected_next_pkt_num) {
        return;
    } else if (pkt_num > ts_info->expected_next_pkt_num) {
        ts_info->new_range_flag |= 1 << (ts_info->end_idx);
    } else {
        ts_info->new_range_flag &= ~(1 << (ts_info->end_idx));
    }
    ts_info->pkt_nums[ts_info->end_idx] = pkt_num;
    ts_info->recv_timestamps[ts_info->end_idx] = recv_time;
    ts_info->end_idx = RECV_TIMESTAMPS_INFO_NEXT_IDX(ts_info->end_idx);
    if (ts_info->end_idx == ts_info->start_idx) {
        ts_info->start_idx = RECV_TIMESTAMPS_INFO_NEXT_IDX(ts_info->start_idx);
    }
    ts_info->expected_next_pkt_num = pkt_num + 1;
    ts_info->cur_len += 1;
}

void
xqc_recv_timestamps_info_clear(xqc_recv_timestamps_info_t *ts_info)
{
    ts_info->start_idx = 0;
    ts_info->end_idx = 0;
    ts_info->cur_len = 0;
    ts_info->new_range_flag = 0;
}

int
xqc_recv_timestamps_info_length(xqc_recv_timestamps_info_t *ts_info)
{
    if (ts_info == NULL) {
        return 0;
    }
    return ts_info->cur_len;
}

int
xqc_recv_timestamps_info_fetch(xqc_recv_timestamps_info_t *ts_info, uint32_t idx,
    xqc_packet_number_t *pkt_num, xqc_usec_t *recv_time)
{
    if (idx > ts_info->cur_len) {
        return 0;
    }
    int inner_idx = ((idx + ts_info->start_idx) & (XQC_RECV_TIMESTAMPS_INFO_MAX_LENGTH - 1));
    *pkt_num = ts_info->pkt_nums[inner_idx];
    *recv_time = ts_info->recv_timestamps[inner_idx];
    return 1;
}

/*
* Additional fields for ACK_RECEIVE_TIMESTAMPS {
*                Timestamp Range Count (i),
*                Timestamp Ranges (..) ...,
*                }
* here, Timestamp Range {
*             Gap (i),
*             Timestamp Delta Count (i),
*             Timestamp Delta (i) ...,
*             }
* estimated_bytes = 1 (Timestamp Range Count) + 2 (gap and timestamp_delta_count for one TS_Range) * range_count + 
*          4 (TS Delta for the first pkt in first range) + 1 (TS Delta for left pkts)
*/
size_t
xqc_recv_timestamps_info_need_bytes_estimate(xqc_recv_timestamps_info_t *ts_info){
    if (ts_info->cur_len == 0) {
        /* for no timestamp reporting */
        return 1;
    }
    int range_count = xqc_popcountll(ts_info->new_range_flag) + 1;
    int est_byte = 1 + range_count * 2 + 4 + (ts_info->cur_len - 1);
    return est_byte;
}

void
xqc_recv_timestamps_info_set_nobuf_flag(xqc_recv_timestamps_info_t *ts_info, uint8_t nobuf_for_ts)
{
    ts_info->nobuf_for_ts_in_last_ext_ack = nobuf_for_ts;
}