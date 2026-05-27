/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <CUnit/CUnit.h>
#include "xqc_frame_type_bit_test.h"
#include "src/transport/xqc_frame.h"


/*
 * Verify that high-bit frame type bitmask values (bit >= 32) are non-zero.
 */
void
xqc_test_frame_type_bit_high_bits_nonzero()
{
    /* Bit 31: XQC_FRAME_BIT_SID -- boundary, should still fit in uint32 */
    CU_ASSERT(XQC_FRAME_BIT_SID != 0);
    CU_ASSERT(XQC_FRAME_BIT_SID == (1ULL << 31));

    /* Bit 32: XQC_FRAME_BIT_REPAIR_SYMBOL -- first to overflow int */
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL != 0);
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL == (1ULL << 32));

    /* Bit 33: XQC_FRAME_BIT_NUM -- also overflows int */
    CU_ASSERT(XQC_FRAME_BIT_NUM != 0);
    CU_ASSERT(XQC_FRAME_BIT_NUM == (1ULL << 33));

    /* Verify they are distinct from each other and from low bits */
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL != XQC_FRAME_BIT_SID);
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL != XQC_FRAME_BIT_NUM);
    CU_ASSERT(XQC_FRAME_BIT_NUM != XQC_FRAME_BIT_SID);
}


/*
 * Verify every bit position is unique, non-zero, and single-bit.
 */
void
xqc_test_frame_type_bit_uniqueness()
{
    /* all bitmask values in xqc_frame_type_t order */
    const xqc_frame_type_bit_t all_bits[] = {
        XQC_FRAME_BIT_PADDING,
        XQC_FRAME_BIT_PING,
        XQC_FRAME_BIT_ACK,
        XQC_FRAME_BIT_RESET_STREAM,
        XQC_FRAME_BIT_STOP_SENDING,
        XQC_FRAME_BIT_CRYPTO,
        XQC_FRAME_BIT_NEW_TOKEN,
        XQC_FRAME_BIT_STREAM,
        XQC_FRAME_BIT_MAX_DATA,
        XQC_FRAME_BIT_MAX_STREAM_DATA,
        XQC_FRAME_BIT_MAX_STREAMS,
        XQC_FRAME_BIT_DATA_BLOCKED,
        XQC_FRAME_BIT_STREAM_DATA_BLOCKED,
        XQC_FRAME_BIT_STREAMS_BLOCKED,
        XQC_FRAME_BIT_NEW_CONNECTION_ID,
        XQC_FRAME_BIT_RETIRE_CONNECTION_ID,
        XQC_FRAME_BIT_PATH_CHALLENGE,
        XQC_FRAME_BIT_PATH_RESPONSE,
        XQC_FRAME_BIT_CONNECTION_CLOSE,
        XQC_FRAME_BIT_HANDSHAKE_DONE,
        XQC_FRAME_BIT_ACK_MP,
        XQC_FRAME_BIT_PATH_ABANDON,
        XQC_FRAME_BIT_PATH_STATUS,
        XQC_FRAME_BIT_PATH_STANDBY,
        XQC_FRAME_BIT_PATH_AVAILABLE,
        XQC_FRAME_BIT_MP_NEW_CONNECTION_ID,
        XQC_FRAME_BIT_MP_RETIRE_CONNECTION_ID,
        XQC_FRAME_BIT_MAX_PATH_ID,
        XQC_FRAME_BIT_PATH_FROZEN,
        XQC_FRAME_BIT_DATAGRAM,
        XQC_FRAME_BIT_EXTENSION,
        XQC_FRAME_BIT_SID,
        XQC_FRAME_BIT_REPAIR_SYMBOL,
        XQC_FRAME_BIT_NUM,
    };
    const int count = sizeof(all_bits) / sizeof(all_bits[0]);

    CU_ASSERT(count == XQC_FRAME_NUM + 1);  /* 0..XQC_FRAME_NUM inclusive */

    /* Each value must be non-zero */
    for (int i = 0; i < count; i++) {
        CU_ASSERT(all_bits[i] != 0);
    }

    /* Each value must be a single-bit power of two */
    for (int i = 0; i < count; i++) {
        CU_ASSERT((all_bits[i] & (all_bits[i] - 1)) == 0);
    }

    /* No two values may be equal (collision test) */
    for (int i = 0; i < count; i++) {
        for (int j = i + 1; j < count; j++) {
            CU_ASSERT(all_bits[i] != all_bits[j]);
        }
    }

    /* OR of all bits must have exactly `count` bits set */
    xqc_frame_type_bit_t combined = 0;
    for (int i = 0; i < count; i++) {
        combined |= all_bits[i];
    }
    int popcount = 0;
    xqc_frame_type_bit_t tmp = combined;
    while (tmp) {
        popcount += tmp & 1;
        tmp >>= 1;
    }
    CU_ASSERT(popcount == count);
}


/*
 * Verify bitmask classification macros handle high-bit frame types.
 */
void
xqc_test_frame_type_bit_bitmask_macros()
{
    /* XQC_NEED_REPAIR: excluded frame types */
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_REPAIR_SYMBOL) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_SID) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_DATAGRAM) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_ACK) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_PADDING) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_PING) == 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_CONNECTION_CLOSE) == 0);

    /* Frames that DO need repair */
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_STREAM) != 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_CRYPTO) != 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_MAX_DATA) != 0);
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_HANDSHAKE_DONE) != 0);

    /* Combined: STREAM + REPAIR_SYMBOL -> only STREAM needs repair */
    CU_ASSERT(XQC_NEED_REPAIR(XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_REPAIR_SYMBOL)
              == XQC_FRAME_BIT_STREAM);

    /* XQC_IS_ACK_ELICITING */
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_ACK) == 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_ACK_MP) == 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_PADDING) == 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_CONNECTION_CLOSE) == 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_STREAM) != 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);
    CU_ASSERT(XQC_IS_ACK_ELICITING(XQC_FRAME_BIT_SID) != 0);

    /* XQC_CAN_IN_FLIGHT */
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_ACK) == 0);
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_ACK_MP) == 0);
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_CONNECTION_CLOSE) == 0);
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_PADDING) != 0);
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_STREAM) != 0);
    CU_ASSERT(XQC_CAN_IN_FLIGHT(XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);
}


/*
 * Bitmask round-trip: set/get/clear on boundary bit positions.
 */
void
xqc_test_frame_type_bit_roundtrip()
{
    xqc_frame_type_bit_t mask = 0;

    /* Set individual bits and verify */
    mask |= XQC_FRAME_BIT_PADDING;        /* bit 0 */
    mask |= XQC_FRAME_BIT_SID;            /* bit 31 */
    mask |= XQC_FRAME_BIT_REPAIR_SYMBOL;  /* bit 32 */
    mask |= XQC_FRAME_BIT_NUM;            /* bit 33 */

    /* Verify each bit is independently recoverable */
    CU_ASSERT((mask & XQC_FRAME_BIT_PADDING) != 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_SID) != 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_NUM) != 0);

    /* Verify bits NOT set are zero */
    CU_ASSERT((mask & XQC_FRAME_BIT_PING) == 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_STREAM) == 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_DATAGRAM) == 0);

    /* Verify exact value */
    xqc_frame_type_bit_t expected = (1ULL << 0) | (1ULL << 31) | (1ULL << 32) | (1ULL << 33);
    CU_ASSERT(mask == expected);

    /* Clear high bit and verify others remain */
    mask &= ~XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT((mask & XQC_FRAME_BIT_REPAIR_SYMBOL) == 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_PADDING) != 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_SID) != 0);
    CU_ASSERT((mask & XQC_FRAME_BIT_NUM) != 0);
}
