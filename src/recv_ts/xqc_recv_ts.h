#ifndef XQC_RECV_TS_H
#define XQC_RECV_TS_H

#include "include/xqc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Improved QUIC Receive Timestamps (draft-ietf-quic-receive-ts-00).
 *
 * Fixes from xqc_recv_timestamps_info:
 * - Dynamic bit array for range flags (not limited to uint64_t / 64 entries)
 * - Configurable buffer capacity
 * - Clean delta encoding export for ACK_EXTENDED frames
 */

#define XQC_RECV_TS_DEFAULT_CAPACITY  128

typedef struct {
    uint32_t  capacity;
} xqc_recv_ts_config_t;

/* Timestamp range for ACK export */
typedef struct {
    uint64_t  gap;
    uint32_t  delta_count;
    int64_t  *deltas;
} xqc_ts_range_t;

typedef struct {
    xqc_recv_ts_config_t  config;

    uint64_t   *pkt_nums;
    xqc_usec_t *recv_times;
    uint8_t    *range_flags;    /* dynamic bit array: 1 = new range start */
    uint32_t    start_idx;
    uint32_t    end_idx;
    uint32_t    cur_len;
    uint64_t    expected_next_pn;
    int         is_first;
} xqc_recv_ts_t;

xqc_recv_ts_t *xqc_recv_ts_create(const xqc_recv_ts_config_t *config);
void xqc_recv_ts_destroy(xqc_recv_ts_t *ts);

/**
 * Record receipt of a packet. Out-of-order packets (pn < expected) are dropped.
 */
void xqc_recv_ts_add(xqc_recv_ts_t *ts, uint64_t pkt_num, xqc_usec_t recv_time);

/**
 * Clear all recorded timestamps (after ACK is sent).
 */
void xqc_recv_ts_clear(xqc_recv_ts_t *ts);

/**
 * Get current number of recorded timestamps.
 */
uint32_t xqc_recv_ts_count(const xqc_recv_ts_t *ts);

/**
 * Fetch a specific entry by index (0 = oldest).
 * Returns 0 on success, -1 on error.
 */
int xqc_recv_ts_fetch(const xqc_recv_ts_t *ts, uint32_t idx,
    uint64_t *pkt_num, xqc_usec_t *recv_time);

/**
 * Count the number of timestamp ranges (for ACK_EXTENDED encoding).
 */
uint32_t xqc_recv_ts_range_count(const xqc_recv_ts_t *ts);

/**
 * Estimate the number of bytes needed for timestamp encoding in ACK frame.
 */
size_t xqc_recv_ts_estimate_bytes(const xqc_recv_ts_t *ts);

/**
 * Export timestamps as delta-encoded ranges for ACK_EXTENDED frame.
 *
 * Format per range:
 *   Gap (varint): gap in packet numbers to this range
 *   Timestamp Delta Count (varint): number of deltas in range
 *   Timestamp Delta (varint): delta-encoded timestamps
 *
 * out_buf: output buffer, out_len: buffer size
 * ts_exponent: timestamp granularity exponent (receive_timestamps_exponent)
 *
 * Returns bytes written, or negative error.
 */
xqc_int_t xqc_recv_ts_export_for_ack(const xqc_recv_ts_t *ts,
    uint8_t *out_buf, size_t out_len, uint32_t ts_exponent);

#ifdef __cplusplus
}
#endif

#endif /* XQC_RECV_TS_H */
