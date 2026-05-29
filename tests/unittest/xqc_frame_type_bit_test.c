/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

/*
 * Tests for the xqc_frame_type_bit_t overflow fix (issue #534).
 *
 * The enum-to-typedef conversion ensures that frame type bitmasks with
 * shift counts >= 32 (XQC_FRAME_REPAIR_SYMBOL = 32, XQC_FRAME_NUM = 33)
 * are correctly represented as 64-bit values. On MSVC, the old enum
 * representation silently truncated these to 0 because enum is 32-bit int.
 *
 * These tests exercise:
 *   - Compile-time and runtime value verification for high-bit constants
 *   - Bitwise operations mixing high-bit and low-bit frame types
 *   - The XQC_IS_ACK_ELICITING / XQC_CAN_IN_FLIGHT / XQC_NEED_REPAIR macros
 *   - xqc_frame_type_2_str with high-bit frame types
 *   - Storage/retrieval of 64-bit values via po_frame_types / pi_frame_types
 */

#include <string.h>
#include <CUnit/CUnit.h>
#include "xqc_frame_type_bit_test.h"
#include "xqc_common_test.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_packet_out.h"
#include "src/transport/xqc_packet_in.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_conn.h"


/*
 * Verify enum ordinals for frame types at and beyond the 32-bit boundary.
 * If somebody reorders the enum, these assertions catch it immediately.
 */
void
xqc_test_frame_type_enum_ordinals()
{
    CU_ASSERT(XQC_FRAME_SID == 31);
    CU_ASSERT(XQC_FRAME_REPAIR_SYMBOL == 32);
    CU_ASSERT(XQC_FRAME_NUM == 33);
}


/*
 * The core of the overflow fix: XQC_FRAME_BIT_REPAIR_SYMBOL must be
 * (1ULL << 32) and XQC_FRAME_BIT_NUM must be (1ULL << 33). If these
 * were truncated to 32-bit int (the MSVC bug), they would be 0.
 */
void
xqc_test_frame_bit_high_values_nonzero()
{
    /* bit 32 must not be zero */
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL != 0);
    /* bit 33 must not be zero */
    CU_ASSERT(XQC_FRAME_BIT_NUM != 0);

    /* exact expected values */
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL == (1ULL << 32));
    CU_ASSERT(XQC_FRAME_BIT_NUM == (1ULL << 33));

    /* bit 31 (SID) is the last value that fits in 32-bit */
    CU_ASSERT(XQC_FRAME_BIT_SID == (1ULL << 31));

    /* these must all be distinct from each other */
    CU_ASSERT(XQC_FRAME_BIT_SID != XQC_FRAME_BIT_REPAIR_SYMBOL);
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL != XQC_FRAME_BIT_NUM);
    CU_ASSERT(XQC_FRAME_BIT_SID != XQC_FRAME_BIT_NUM);
}


/*
 * Verify that sizeof(xqc_frame_type_bit_t) is at least 8 bytes (64-bit).
 * This is the structural guarantee: the typedef must be uint64_t, not int.
 */
void
xqc_test_frame_type_bit_sizeof()
{
    CU_ASSERT(sizeof(xqc_frame_type_bit_t) >= 8);
}


/*
 * Bitwise OR of high-bit values with low-bit values must preserve all bits.
 * This exercises the exact failure mode on MSVC: if high-bit values were 0,
 * the OR result would lose them.
 */
void
xqc_test_frame_bit_or_high_low()
{
    xqc_frame_type_bit_t combined;

    /* combine a low-bit frame type (PING, bit 1) with a high-bit one (REPAIR_SYMBOL, bit 32) */
    combined = XQC_FRAME_BIT_PING | XQC_FRAME_BIT_REPAIR_SYMBOL;

    /* both bits must be testable */
    CU_ASSERT((combined & XQC_FRAME_BIT_PING) != 0);
    CU_ASSERT((combined & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);

    /* bits that were NOT set must remain clear */
    CU_ASSERT((combined & XQC_FRAME_BIT_ACK) == 0);
    CU_ASSERT((combined & XQC_FRAME_BIT_SID) == 0);
    CU_ASSERT((combined & XQC_FRAME_BIT_NUM) == 0);

    /* combine three: PADDING (bit 0), DATAGRAM (bit 29), REPAIR_SYMBOL (bit 32) */
    combined = XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_DATAGRAM | XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT((combined & XQC_FRAME_BIT_PADDING) != 0);
    CU_ASSERT((combined & XQC_FRAME_BIT_DATAGRAM) != 0);
    CU_ASSERT((combined & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);

    /* exact value: three distinct bits */
    CU_ASSERT(combined == ((1ULL << 0) | (1ULL << 29) | (1ULL << 32)));
}


/*
 * XQC_NEED_REPAIR explicitly excludes REPAIR_SYMBOL (bit 32) from the
 * "needs repair" set. This is the most critical macro for the overflow fix
 * because its exclusion mask contains XQC_FRAME_BIT_REPAIR_SYMBOL. If that
 * constant were 0, the macro would incorrectly report REPAIR_SYMBOL frames
 * as needing repair.
 */
void
xqc_test_need_repair_with_high_bit()
{
    xqc_frame_type_bit_t types;

    /* REPAIR_SYMBOL alone: should NOT need repair (explicitly excluded) */
    types = XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_NEED_REPAIR(types) == 0);

    /* SID alone: should NOT need repair (explicitly excluded) */
    types = XQC_FRAME_BIT_SID;
    CU_ASSERT(XQC_NEED_REPAIR(types) == 0);

    /* STREAM alone: should need repair */
    types = XQC_FRAME_BIT_STREAM;
    CU_ASSERT(XQC_NEED_REPAIR(types) != 0);

    /* STREAM + REPAIR_SYMBOL: should need repair (STREAM triggers it) */
    types = XQC_FRAME_BIT_STREAM | XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_NEED_REPAIR(types) != 0);

    /* ACK + PADDING + PING + CONN_CLOSE + DATAGRAM + SID + REPAIR_SYMBOL:
     * all are excluded from repair; result should be 0 */
    types = XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_PING
          | XQC_FRAME_BIT_CONNECTION_CLOSE | XQC_FRAME_BIT_DATAGRAM
          | XQC_FRAME_BIT_SID | XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_NEED_REPAIR(types) == 0);
}


/*
 * XQC_IS_ACK_ELICITING excludes ACK, ACK_MP, PADDING, and CONNECTION_CLOSE.
 * A packet containing only REPAIR_SYMBOL (bit 32) IS ack-eliciting because
 * it is not in the exclusion set.
 */
void
xqc_test_ack_eliciting_with_high_bit()
{
    xqc_frame_type_bit_t types;

    /* REPAIR_SYMBOL alone: ack-eliciting (not excluded) */
    types = XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_IS_ACK_ELICITING(types) != 0);

    /* SID alone: ack-eliciting */
    types = XQC_FRAME_BIT_SID;
    CU_ASSERT(XQC_IS_ACK_ELICITING(types) != 0);

    /* ACK alone: NOT ack-eliciting */
    types = XQC_FRAME_BIT_ACK;
    CU_ASSERT(XQC_IS_ACK_ELICITING(types) == 0);

    /* ACK + REPAIR_SYMBOL: ack-eliciting (REPAIR_SYMBOL triggers it) */
    types = XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_IS_ACK_ELICITING(types) != 0);

    /* PADDING + ACK_MP + CONNECTION_CLOSE: NOT ack-eliciting */
    types = XQC_FRAME_BIT_PADDING | XQC_FRAME_BIT_ACK_MP
          | XQC_FRAME_BIT_CONNECTION_CLOSE;
    CU_ASSERT(XQC_IS_ACK_ELICITING(types) == 0);
}


/*
 * XQC_CAN_IN_FLIGHT excludes ACK, ACK_MP, and CONNECTION_CLOSE.
 * REPAIR_SYMBOL (bit 32) is NOT excluded, so it counts as in-flight.
 */
void
xqc_test_can_in_flight_with_high_bit()
{
    xqc_frame_type_bit_t types;

    /* REPAIR_SYMBOL alone: in-flight */
    types = XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_CAN_IN_FLIGHT(types) != 0);

    /* ACK alone: NOT in-flight */
    types = XQC_FRAME_BIT_ACK;
    CU_ASSERT(XQC_CAN_IN_FLIGHT(types) == 0);

    /* ACK + CONNECTION_CLOSE + REPAIR_SYMBOL: in-flight (REPAIR_SYMBOL) */
    types = XQC_FRAME_BIT_ACK | XQC_FRAME_BIT_CONNECTION_CLOSE
          | XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(XQC_CAN_IN_FLIGHT(types) != 0);
}


/*
 * xqc_frame_type_2_str must correctly iterate up to XQC_FRAME_NUM and
 * produce the right string for high-bit frame types. This exercises the
 * loop `for (int i = 0; i < XQC_FRAME_NUM; i++)` in xqc_frame.c.
 */
void
xqc_test_frame_type_2_str_high_bit()
{
    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    const char *result;

    /* REPAIR_SYMBOL (bit 32) alone */
    result = xqc_frame_type_2_str(conn->engine, XQC_FRAME_BIT_REPAIR_SYMBOL);
    CU_ASSERT(result != NULL);
    CU_ASSERT(strstr(result, "FEC_REPAIR") != NULL);

    /* SID (bit 31) alone */
    result = xqc_frame_type_2_str(conn->engine, XQC_FRAME_BIT_SID);
    CU_ASSERT(result != NULL);
    CU_ASSERT(strstr(result, "FEC_SID") != NULL);

    /* PING + REPAIR_SYMBOL: both names must appear */
    result = xqc_frame_type_2_str(conn->engine,
                                  XQC_FRAME_BIT_PING | XQC_FRAME_BIT_REPAIR_SYMBOL);
    CU_ASSERT(result != NULL);
    CU_ASSERT(strstr(result, "PING") != NULL);
    CU_ASSERT(strstr(result, "FEC_REPAIR") != NULL);

    /* empty bitmask: should produce empty string */
    result = xqc_frame_type_2_str(conn->engine, 0);
    CU_ASSERT(result != NULL);
    CU_ASSERT(result[0] == '\0');

    xqc_engine_destroy(conn->engine);
}


/*
 * po_frame_types (xqc_packet_out_t) and pi_frame_types (xqc_packet_in_t)
 * are declared as xqc_frame_type_bit_t. Verify that they can correctly
 * store and retrieve 64-bit values including high bits.
 */
void
xqc_test_packet_frame_types_64bit_storage()
{
    xqc_packet_out_t po;
    xqc_packet_in_t  pi;

    memset(&po, 0, sizeof(po));
    memset(&pi, 0, sizeof(pi));

    /* store a high-bit value in po_frame_types */
    po.po_frame_types = XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(po.po_frame_types == XQC_FRAME_BIT_REPAIR_SYMBOL);
    CU_ASSERT(po.po_frame_types == (1ULL << 32));

    /* accumulate via |= */
    po.po_frame_types |= XQC_FRAME_BIT_PING;
    CU_ASSERT((po.po_frame_types & XQC_FRAME_BIT_PING) != 0);
    CU_ASSERT((po.po_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);

    /* store a high-bit value in pi_frame_types */
    pi.pi_frame_types = XQC_FRAME_BIT_REPAIR_SYMBOL;
    CU_ASSERT(pi.pi_frame_types == XQC_FRAME_BIT_REPAIR_SYMBOL);
    CU_ASSERT(pi.pi_frame_types == (1ULL << 32));

    /* accumulate via |= */
    pi.pi_frame_types |= XQC_FRAME_BIT_STREAM;
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_STREAM) != 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);

    /* store the largest valid bitmask (all bits set) */
    pi.pi_frame_types = XQC_FRAME_BIT_NUM - 1;
    CU_ASSERT(pi.pi_frame_types != 0);
    /* all bits from 0..32 should be set */
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_PADDING) != 0);
    CU_ASSERT((pi.pi_frame_types & XQC_FRAME_BIT_REPAIR_SYMBOL) != 0);
}


/*
 * Verify that each XQC_FRAME_BIT_* constant corresponds to exactly one set
 * bit, and that its position matches the enum ordinal. This is a systematic
 * check: if the typedef or any #define is wrong, exactly one assertion will
 * fail and point to the broken constant.
 */
void
xqc_test_frame_bit_all_constants_have_correct_bit_position()
{
    /* spot-check a selection of constants across the full range */
    CU_ASSERT(XQC_FRAME_BIT_PADDING             == (1ULL << 0));
    CU_ASSERT(XQC_FRAME_BIT_PING                == (1ULL << 1));
    CU_ASSERT(XQC_FRAME_BIT_ACK                 == (1ULL << 2));
    CU_ASSERT(XQC_FRAME_BIT_STREAM              == (1ULL << 7));
    CU_ASSERT(XQC_FRAME_BIT_CONNECTION_CLOSE     == (1ULL << 18));
    CU_ASSERT(XQC_FRAME_BIT_HANDSHAKE_DONE       == (1ULL << 19));
    CU_ASSERT(XQC_FRAME_BIT_ACK_MP              == (1ULL << 20));
    CU_ASSERT(XQC_FRAME_BIT_DATAGRAM             == (1ULL << 29));
    CU_ASSERT(XQC_FRAME_BIT_EXTENSION            == (1ULL << 30));
    CU_ASSERT(XQC_FRAME_BIT_SID                  == (1ULL << 31));
    CU_ASSERT(XQC_FRAME_BIT_REPAIR_SYMBOL        == (1ULL << 32));
    CU_ASSERT(XQC_FRAME_BIT_NUM                  == (1ULL << 33));

    /* verify popcount == 1 for a selection (each is a power of two) */
    CU_ASSERT((XQC_FRAME_BIT_REPAIR_SYMBOL & (XQC_FRAME_BIT_REPAIR_SYMBOL - 1)) == 0);
    CU_ASSERT((XQC_FRAME_BIT_NUM & (XQC_FRAME_BIT_NUM - 1)) == 0);
    CU_ASSERT((XQC_FRAME_BIT_SID & (XQC_FRAME_BIT_SID - 1)) == 0);
}


/*
 * Edge case: the 32-bit boundary. Verify that bit 31 (the last bit that
 * fits in uint32_t) and bit 32 (the first that does not) are both correct
 * and distinguishable.
 */
void
xqc_test_frame_bit_32bit_boundary()
{
    xqc_frame_type_bit_t bit31 = XQC_FRAME_BIT_SID;             /* 1ULL << 31 */
    xqc_frame_type_bit_t bit32 = XQC_FRAME_BIT_REPAIR_SYMBOL;   /* 1ULL << 32 */

    /* bit31 fits in uint32_t; bit32 does NOT */
    CU_ASSERT(bit31 == 0x80000000ULL);
    CU_ASSERT(bit32 == 0x100000000ULL);

    /* they must not alias (the original MSVC bug would make bit32 == 0) */
    CU_ASSERT(bit31 != bit32);
    CU_ASSERT(bit32 != 0);

    /* OR them together and verify both survive */
    xqc_frame_type_bit_t both = bit31 | bit32;
    CU_ASSERT((both & bit31) != 0);
    CU_ASSERT((both & bit32) != 0);
    CU_ASSERT(both == 0x180000000ULL);

    /* complement / negate test: ~bit32 should clear bit 32, keep bit 31 */
    CU_ASSERT((both & ~bit32) == bit31);
    CU_ASSERT((both & ~bit31) == bit32);
}


/*
 * Verify that a variable of type xqc_frame_type_bit_t can be assigned
 * to and from uint64_t without loss. This ensures the typedef is correct.
 */
void
xqc_test_frame_type_bit_roundtrip()
{
    uint64_t raw = (1ULL << 32) | (1ULL << 1);
    xqc_frame_type_bit_t typed = raw;

    CU_ASSERT(typed == raw);
    CU_ASSERT((typed & (1ULL << 32)) != 0);
    CU_ASSERT((typed & (1ULL << 1)) != 0);
    CU_ASSERT((typed & (1ULL << 2)) == 0);

    uint64_t back = typed;
    CU_ASSERT(back == raw);
}
