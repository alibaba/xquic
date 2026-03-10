#include "src/recv_ts/xqc_recv_ts.h"
#include "src/common/xqc_varint.h"
#include <stdlib.h>
#include <string.h>

static inline uint32_t
next_idx(uint32_t idx, uint32_t capacity)
{
    return (idx + 1) % capacity;
}

static inline int
get_range_flag(const xqc_recv_ts_t *ts, uint32_t idx)
{
    uint32_t byte_idx = idx / 8;
    uint32_t bit_idx  = idx % 8;
    return (ts->range_flags[byte_idx] >> bit_idx) & 1;
}

static inline void
set_range_flag(xqc_recv_ts_t *ts, uint32_t idx, int val)
{
    uint32_t byte_idx = idx / 8;
    uint32_t bit_idx  = idx % 8;
    if (val) {
        ts->range_flags[byte_idx] |= (1u << bit_idx);
    } else {
        ts->range_flags[byte_idx] &= ~(1u << bit_idx);
    }
}

xqc_recv_ts_t *
xqc_recv_ts_create(const xqc_recv_ts_config_t *config)
{
    xqc_recv_ts_t *ts = calloc(1, sizeof(*ts));
    if (ts == NULL) {
        return NULL;
    }

    uint32_t cap = XQC_RECV_TS_DEFAULT_CAPACITY;
    if (config && config->capacity > 0) {
        /* Round up to power of 2 for efficient modular arithmetic */
        cap = config->capacity;
        uint32_t v = cap - 1;
        v |= v >> 1; v |= v >> 2; v |= v >> 4;
        v |= v >> 8; v |= v >> 16;
        cap = v + 1;
    }

    ts->config.capacity = cap;
    ts->pkt_nums = calloc(cap, sizeof(uint64_t));
    ts->recv_times = calloc(cap, sizeof(xqc_usec_t));

    uint32_t flag_bytes = (cap + 7) / 8;
    ts->range_flags = calloc(flag_bytes, 1);

    if (!ts->pkt_nums || !ts->recv_times || !ts->range_flags) {
        xqc_recv_ts_destroy(ts);
        return NULL;
    }

    ts->is_first = 1;
    return ts;
}

void
xqc_recv_ts_destroy(xqc_recv_ts_t *ts)
{
    if (ts == NULL) {
        return;
    }
    free(ts->pkt_nums);
    free(ts->recv_times);
    free(ts->range_flags);
    free(ts);
}

void
xqc_recv_ts_add(xqc_recv_ts_t *ts, uint64_t pkt_num, xqc_usec_t recv_time)
{
    if (ts == NULL) {
        return;
    }

    if (ts->is_first) {
        ts->is_first = 0;
        ts->expected_next_pn = pkt_num;
    }

    /* Drop out-of-order packets */
    if (pkt_num < ts->expected_next_pn) {
        return;
    }

    /* Determine if this starts a new range (gap in packet numbers) */
    int new_range = (pkt_num > ts->expected_next_pn) ? 1 : 0;

    set_range_flag(ts, ts->end_idx, new_range);

    ts->pkt_nums[ts->end_idx] = pkt_num;
    ts->recv_times[ts->end_idx] = recv_time;

    ts->end_idx = next_idx(ts->end_idx, ts->config.capacity);

    if (ts->end_idx == ts->start_idx) {
        /* Buffer full, advance start; clear stale range flag of evicted slot */
        set_range_flag(ts, ts->start_idx, 0);
        ts->start_idx = next_idx(ts->start_idx, ts->config.capacity);
    } else {
        ts->cur_len++;
    }

    ts->expected_next_pn = pkt_num + 1;
}

void
xqc_recv_ts_clear(xqc_recv_ts_t *ts)
{
    if (ts == NULL) {
        return;
    }
    ts->start_idx = 0;
    ts->end_idx = 0;
    ts->cur_len = 0;

    uint32_t flag_bytes = (ts->config.capacity + 7) / 8;
    memset(ts->range_flags, 0, flag_bytes);
}

uint32_t
xqc_recv_ts_count(const xqc_recv_ts_t *ts)
{
    return ts ? ts->cur_len : 0;
}

int
xqc_recv_ts_fetch(const xqc_recv_ts_t *ts, uint32_t idx,
    uint64_t *pkt_num, xqc_usec_t *recv_time)
{
    if (ts == NULL || idx >= ts->cur_len) {
        return -1;
    }

    uint32_t real_idx = (ts->start_idx + idx) % ts->config.capacity;
    if (pkt_num) *pkt_num = ts->pkt_nums[real_idx];
    if (recv_time) *recv_time = ts->recv_times[real_idx];
    return 0;
}

uint32_t
xqc_recv_ts_range_count(const xqc_recv_ts_t *ts)
{
    if (ts == NULL || ts->cur_len == 0) {
        return 0;
    }

    uint32_t ranges = 1;
    for (uint32_t i = 0; i < ts->cur_len; i++) {
        uint32_t real_idx = (ts->start_idx + i) % ts->config.capacity;
        if (get_range_flag(ts, real_idx)) {
            ranges++;
        }
    }
    return ranges;
}

size_t
xqc_recv_ts_estimate_bytes(const xqc_recv_ts_t *ts)
{
    if (ts == NULL || ts->cur_len == 0) {
        return 1;
    }

    uint32_t ranges = xqc_recv_ts_range_count(ts);
    /* 1 (range count) + 2 * ranges (gap + delta_count) + 4 (first delta) + (n-1) (rest) */
    return 1 + ranges * 2 + 4 + (ts->cur_len > 0 ? ts->cur_len - 1 : 0);
}

xqc_int_t
xqc_recv_ts_export_for_ack(const xqc_recv_ts_t *ts,
    uint8_t *out_buf, size_t out_len, uint32_t ts_exponent)
{
    if (ts == NULL || out_buf == NULL) {
        return XQC_ERROR_INVAL;
    }

    uint8_t *p = out_buf;
    uint8_t *end = out_buf + out_len;
    size_t n;

    uint32_t ranges = xqc_recv_ts_range_count(ts);

#define WRITE_VARINT(val) do {                          \
    n = xqc_varint_encode(p, (size_t)(end - p), val);   \
    if (n == 0) return XQC_ERROR_NOBUF;                 \
    p += n;                                             \
} while (0)

    WRITE_VARINT(ranges);

    if (ts->cur_len == 0) {
        return (xqc_int_t)(p - out_buf);
    }

    uint64_t divisor = 1;
    for (uint32_t e = 0; e < ts_exponent; e++) {
        divisor *= 2;
    }

    /* Walk through entries, grouping into ranges */
    uint32_t i = 0;
    xqc_usec_t prev_ts = 0;

    while (i < ts->cur_len) {
        /* Find end of current range */
        uint32_t range_end = i + 1;
        while (range_end < ts->cur_len) {
            uint32_t real_idx = (ts->start_idx + range_end) % ts->config.capacity;
            if (get_range_flag(ts, real_idx)) {
                break;
            }
            range_end++;
        }

        uint32_t delta_count = range_end - i;

        /* Gap: if not first range, compute gap from previous range's last pn */
        if (i == 0) {
            WRITE_VARINT(0);
        } else {
            uint32_t prev_idx = (ts->start_idx + i - 1) % ts->config.capacity;
            uint32_t cur_idx = (ts->start_idx + i) % ts->config.capacity;
            uint64_t gap = ts->pkt_nums[cur_idx] - ts->pkt_nums[prev_idx] - 1;
            WRITE_VARINT(gap);
        }

        WRITE_VARINT(delta_count);

        /* Write deltas */
        for (uint32_t j = i; j < range_end; j++) {
            uint32_t real_idx = (ts->start_idx + j) % ts->config.capacity;
            xqc_usec_t t = ts->recv_times[real_idx];

            uint64_t delta;
            if (j == 0 && i == 0) {
                /* Very first entry: absolute timestamp */
                delta = (uint64_t)t / divisor;
            } else {
                /* All subsequent entries (including first entry of non-first range):
                 * delta relative to previous timestamp. prev_ts is carried across ranges. */
                int64_t d = t - prev_ts;
                delta = (uint64_t)(d >= 0 ? d : -d) / divisor;
            }
            prev_ts = t;

            WRITE_VARINT(delta);
        }

        i = range_end;
    }

#undef WRITE_VARINT

    return (xqc_int_t)(p - out_buf);
}
