/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include <stdio.h>
#include <string.h>
#include <CUnit/Basic.h>
#include <CUnit/CUnit.h>

#include "xqc_random_test.h"
#include "xqc_timer_test.h"
#include "xqc_pq_test.h"
#include "xqc_conn_test.h"
#include "xqc_engine_test.h"
#include "xqc_common_test.h"
#include "xqc_vint_test.h"
#include "xqc_recv_record_test.h"
#include "xqc_reno_test.h"
#include "xqc_cubic_test.h"
#include "xqc_packet_test.h"
#include "xqc_stream_frame_test.h"
#include "xqc_wakeup_pq_test.h"
#include "xqc_process_frame_test.h"
#include "xqc_tp_test.h"
#include "xqc_tls_test.h"
#include "xqc_crypto_test.h"
#include "xqc_h3_test.h"
#include "xqc_stable_test.h"
#include "xqc_dtable_test.h"
#include "utils/xqc_2d_hash_table_test.h"
#include "utils/xqc_ring_array_test.h"
#include "utils/xqc_ring_mem_test.h"
#include "utils/xqc_huffman_test.h"
#include "xqc_encoder_test.h"
#include "xqc_qpack_test.h"
#include "xqc_prefixed_str_test.h"
#include "xqc_cid_test.h"
#include "xqc_id_hash_test.h"


static int xqc_init_suite(void) { return 0; }
static int xqc_clean_suite(void) { return 0; }

int 
main()
{
    CU_pSuite pSuite = NULL;
    unsigned int failed_tests_count;

    if (CU_initialize_registry() != CUE_SUCCESS) {
        printf("CU_initialize error\n");
        return (int)CU_get_error();
    }

    pSuite = CU_add_suite("libxquic_TestSuite", xqc_init_suite, xqc_clean_suite);
    if (NULL == pSuite) {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }     

    if (!CU_add_test(pSuite, "xqc_test_get_random", xqc_test_get_random)
        || !CU_add_test(pSuite, "xqc_test_engine_create", xqc_test_engine_create)
        || !CU_add_test(pSuite, "xqc_test_conn_create", xqc_test_conn_create)
        || !CU_add_test(pSuite, "xqc_test_timer", xqc_test_timer)
        || !CU_add_test(pSuite, "xqc_test_pq", xqc_test_pq)
        || !CU_add_test(pSuite, "xqc_test_common", xqc_test_common)
        || !CU_add_test(pSuite, "xqc_test_vint", xqc_test_vint)
        || !CU_add_test(pSuite, "xqc_test_recv_record", xqc_test_recv_record)
        || !CU_add_test(pSuite, "xqc_test_reno", xqc_test_reno)
        || !CU_add_test(pSuite, "xqc_test_cubic", xqc_test_cubic)
        || !CU_add_test(pSuite, "xqc_test_short_header_parse_cid", xqc_test_short_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_long_header_parse_cid", xqc_test_long_header_packet_parse_cid)
        || !CU_add_test(pSuite, "xqc_test_engine_packet_process", xqc_test_engine_packet_process)
        || !CU_add_test(pSuite, "xqc_test_stream_frame", xqc_test_stream_frame)
        || !CU_add_test(pSuite, "xqc_test_wakeup_pq", xqc_test_wakeup_pq)
        || !CU_add_test(pSuite, "xqc_test_process_frame", xqc_test_process_frame)
        || !CU_add_test(pSuite, "xqc_test_parse_padding_frame", xqc_test_parse_padding_frame)
        || !CU_add_test(pSuite, "xqc_test_large_ack_frame", xqc_test_large_ack_frame)
        || !CU_add_test(pSuite, "xqc_test_h3_frame", xqc_test_frame)
        || !CU_add_test(pSuite, "xqc_test_transport_params", xqc_test_transport_params)
        || !CU_add_test(pSuite, "xqc_test_tls", xqc_test_tls)
        || !CU_add_test(pSuite, "xqc_test_crypto", xqc_test_crypto)
        || !CU_add_test(pSuite, "xqc_test_h3_stream", xqc_test_stream)
        || !CU_add_test(pSuite, "xqc_test_stable", xqc_test_stable)
        || !CU_add_test(pSuite, "xqc_test_dtable", xqc_test_dtable)
        || !CU_add_test(pSuite, "test_2d_hash_table", test_2d_hash_table)
        || !CU_add_test(pSuite, "test_ring_array", test_ring_array)
        || !CU_add_test(pSuite, "xqc_test_ring_mem", xqc_test_ring_mem)
        || !CU_add_test(pSuite, "xqc_test_huffman", xqc_test_huffman)
        || !CU_add_test(pSuite, "xqc_test_encoder", xqc_test_encoder)
        || !CU_add_test(pSuite, "xqc_test_h3_ins", xqc_test_ins)
        || !CU_add_test(pSuite, "xqc_test_h3_rep", xqc_test_rep)
        || !CU_add_test(pSuite, "xqc_qpack_test", xqc_qpack_test)
        || !CU_add_test(pSuite, "xqc_test_prefixed_str", xqc_test_prefixed_str)
        || !CU_add_test(pSuite, "xqc_cid_test", xqc_test_cid)
        || !CU_add_test(pSuite, "xqc_test_id_hash", xqc_test_id_hash)
        /* ADD TESTS HERE */) 
    {
        CU_cleanup_registry();
        return (int)CU_get_error();
    }

    CU_basic_set_mode(CU_BRM_VERBOSE);
    CU_basic_run_tests();
    failed_tests_count = CU_get_number_of_tests_failed();

    CU_cleanup_registry();
    if (CU_get_error() == CUE_SUCCESS) {
        return (int)failed_tests_count;
    } else {
        printf("CUnit Error: %s\n", CU_get_error_msg());
        return (int)CU_get_error();
    }
}
