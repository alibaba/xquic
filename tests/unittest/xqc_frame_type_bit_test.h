/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_FRAME_TYPE_BIT_TEST_H_INCLUDED_
#define _XQC_FRAME_TYPE_BIT_TEST_H_INCLUDED_

void xqc_test_frame_type_enum_ordinals();
void xqc_test_frame_bit_high_values_nonzero();
void xqc_test_frame_type_bit_sizeof();
void xqc_test_frame_bit_or_high_low();
void xqc_test_need_repair_with_high_bit();
void xqc_test_ack_eliciting_with_high_bit();
void xqc_test_can_in_flight_with_high_bit();
void xqc_test_frame_type_2_str_high_bit();
void xqc_test_packet_frame_types_64bit_storage();
void xqc_test_frame_bit_all_constants_have_correct_bit_position();
void xqc_test_frame_bit_32bit_boundary();
void xqc_test_frame_type_bit_roundtrip();

#endif /* _XQC_FRAME_TYPE_BIT_TEST_H_INCLUDED_ */
