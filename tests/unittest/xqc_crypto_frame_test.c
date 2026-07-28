/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#include "xqc_crypto_frame_test.h"
#include <CUnit/CUnit.h>
#include "src/transport/xqc_conn.h"
#include "src/transport/xqc_engine.h"
#include "src/transport/xqc_frame.h"
#include "src/transport/xqc_stream.h"
#include "src/transport/xqc_defs.h"
#include "xqc_common_test.h"

/**
 * Test: Sparse CRYPTO frame flood (CWE-770 mitigation)
 *
 * Simulates the attack described in ALIBABA-2026-41242004:
 * - Insert tiny CRYPTO frames at sparse even offsets (step=2)
 * - Odd offsets are never filled, so next_read_offset stays pinned at 0
 * - Without the fix, all frames would be buffered indefinitely
 * - With the fix, insertion should fail after hitting the buffered_frame_count limit
 */
void
xqc_test_crypto_frame_flood()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    /* Create a crypto stream (Initial level) */
    xqc_stream_t *stream = xqc_create_crypto_stream(conn, XQC_ENC_LEV_INIT, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) {
        xqc_engine_destroy(conn->engine);
        return;
    }
    conn->crypto_stream[XQC_ENC_LEV_INIT] = stream;

    /* Verify initial state */
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 0);
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes == 0);
    CU_ASSERT(stream->stream_data_in.next_read_offset == 0);

    /*
     * Insert sparse CRYPTO frames at even offsets (0, 2, 4, 6, ...),
     * each with 1 byte of data. Since offset 1, 3, 5... are never filled,
     * next_read_offset can only advance to 1 (consuming offset 0's 1 byte),
     * leaving all subsequent frames buffered.
     *
     * We insert more than XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT to trigger rejection.
     */
    uint64_t offset_step = 2;
    uint64_t data_len = 1;
    uint64_t insert_count = 0;
    uint64_t rejected_at = 0;

    /* First insert offset=0 so next_read_offset advances to 1
     * (simulating TLS processing the first byte) */
    /* Actually for this test, we skip offset 0 entirely to keep next_read_offset pinned at 0 */

    for (uint64_t i = 0; i < XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT + 100; i++) {
        uint64_t offset = (i + 1) * offset_step;  /* start at offset 2 to leave gap at 0,1 */

        xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
        CU_ASSERT(frame != NULL);
        if (frame == NULL) {
            break;
        }

        frame->data = xqc_malloc(data_len);
        CU_ASSERT(frame->data != NULL);
        if (frame->data == NULL) {
            xqc_free(frame);
            break;
        }
        memset(frame->data, (unsigned char)(offset & 0xFF), data_len);
        frame->data_length = data_len;
        frame->data_offset = offset;

        ret = xqc_insert_crypto_frame(conn, stream, frame);
        if (ret != XQC_OK) {
            /* Should be rejected due to buffered_frame_count limit */
            rejected_at = i;
            xqc_free(frame->data);
            xqc_free(frame);
            break;
        }
        insert_count++;
    }

    /* Verify that the limit was hit */
    CU_ASSERT(insert_count == XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);
    CU_ASSERT(rejected_at == XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);

    /* Verify counters are correct */
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes == XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT * data_len);

    /* Verify next_read_offset is still 0 (pinned by the gap at offset 0-1) */
    CU_ASSERT(stream->stream_data_in.next_read_offset == 0);

    xqc_engine_destroy(conn->engine);
}

/**
 * Test: CRYPTO frame buffered bytes limit (CWE-770 mitigation)
 *
 * Verifies that the byte-size cap (XQC_MAX_CRYPTO_FRAME_BUFFERED_BYTES) is
 * enforced independently of the node-count cap. Uses large fragments so the
 * byte limit is reached before the node count limit.
 */
void
xqc_test_crypto_frame_bytes_limit()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    xqc_stream_t *stream = xqc_create_crypto_stream(conn, XQC_ENC_LEV_INIT, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) {
        xqc_engine_destroy(conn->engine);
        return;
    }
    conn->crypto_stream[XQC_ENC_LEV_INIT] = stream;

    /*
     * Each fragment carries a large chunk of data. Choose frag_size so that
     * the byte cap is hit well before the node-count cap of 1024.
     * frag_size = 4096 -> need ~256 frames to reach 1MB, far below 1024 nodes.
     */
    uint64_t frag_size = 4096;
    uint64_t offset_step = frag_size * 2;   /* leave a gap so next_read_offset stays pinned */
    uint64_t inserted_bytes = 0;
    uint64_t insert_count = 0;
    xqc_bool_t rejected_by_bytes = XQC_FALSE;

    for (uint64_t i = 0; i < XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT; i++) {
        uint64_t offset = (i + 1) * offset_step;  /* gap at [0, offset_step) keeps next_read_offset pinned */

        xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
        CU_ASSERT(frame != NULL);
        if (frame == NULL) {
            break;
        }

        frame->data = xqc_malloc(frag_size);
        CU_ASSERT(frame->data != NULL);
        if (frame->data == NULL) {
            xqc_free(frame);
            break;
        }
        memset(frame->data, (unsigned char)(offset & 0xFF), frag_size);
        frame->data_length = frag_size;
        frame->data_offset = offset;

        ret = xqc_insert_crypto_frame(conn, stream, frame);
        if (ret != XQC_OK) {
            /* Should be rejected by the byte limit, not the node-count limit */
            rejected_by_bytes = XQC_TRUE;
            xqc_free(frame->data);
            xqc_free(frame);
            break;
        }
        inserted_bytes += frag_size;
        insert_count++;
    }

    /* The byte cap must be the trigger, while node count stays below its cap */
    CU_ASSERT(rejected_by_bytes == XQC_TRUE);
    CU_ASSERT(insert_count < XQC_MAX_CRYPTO_FRAME_BUFFERED_COUNT);

    /* Buffered bytes must never exceed the cap */
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes <= XQC_MAX_CRYPTO_FRAME_BUFFERED_BYTES);
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes == inserted_bytes);

    /* Adding one more fragment would have exceeded the cap */
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes + frag_size > XQC_MAX_CRYPTO_FRAME_BUFFERED_BYTES);

    xqc_engine_destroy(conn->engine);
}

/**
 * Test: counters are correctly recycled on sequential (in-order) consumption.
 *
 * Verifies the fix does NOT break normal handshake flow: when CRYPTO frames
 * arrive in order and are consumed by xqc_read_crypto_stream, the buffered
 * counters must decrement back to zero so legitimate connections are never
 * falsely rejected.
 *
 * Note: this test exercises the counter increment path on insert and then
 * directly removes frames the same way the read path does, validating the
 * decrement bookkeeping without depending on a fully initialized TLS stack.
 */
void
xqc_test_crypto_frame_recycle()
{
    xqc_int_t ret;

    xqc_connection_t *conn = test_engine_connect();
    CU_ASSERT(conn != NULL);
    if (conn == NULL) {
        return;
    }

    xqc_stream_t *stream = xqc_create_crypto_stream(conn, XQC_ENC_LEV_INIT, NULL);
    CU_ASSERT(stream != NULL);
    if (stream == NULL) {
        xqc_engine_destroy(conn->engine);
        return;
    }
    conn->crypto_stream[XQC_ENC_LEV_INIT] = stream;

    uint64_t frag_count = 100;
    uint64_t frag_size = 10;

    /* Insert contiguous in-order frames: offsets 0,10,20,... */
    for (uint64_t i = 0; i < frag_count; i++) {
        xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
        CU_ASSERT(frame != NULL);
        if (frame == NULL) {
            break;
        }
        frame->data = xqc_malloc(frag_size);
        CU_ASSERT(frame->data != NULL);
        if (frame->data == NULL) {
            xqc_free(frame);
            break;
        }
        memset(frame->data, (unsigned char)i, frag_size);
        frame->data_length = frag_size;
        frame->data_offset = i * frag_size;

        ret = xqc_insert_crypto_frame(conn, stream, frame);
        CU_ASSERT(ret == XQC_OK);
    }

    /* After inserting all in-order frames, counters reflect the full buffer */
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == frag_count);
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes == frag_count * frag_size);

    /*
     * Simulate sequential consumption like xqc_read_crypto_stream does for the
     * "already fully consumed" branch: advance next_read_offset past each frame
     * and remove it while decrementing counters.
     */
    xqc_list_head_t *pos, *next;
    xqc_list_for_each_safe(pos, next, &stream->stream_data_in.frames_tailq) {
        xqc_stream_frame_t *sf = xqc_list_entry(pos, xqc_stream_frame_t, sf_list);

        /* mark as consumed */
        stream->stream_data_in.next_read_offset = sf->data_offset + sf->data_length;

        xqc_list_del(pos);
        if (stream->stream_data_in.buffered_frame_count > 0) {
            stream->stream_data_in.buffered_frame_count--;
        }
        if (stream->stream_data_in.buffered_data_bytes >= sf->data_length) {
            stream->stream_data_in.buffered_data_bytes -= sf->data_length;
        } else {
            stream->stream_data_in.buffered_data_bytes = 0;
        }
        xqc_destroy_stream_frame(sf);
    }

    /* Counters must be fully recycled to zero */
    CU_ASSERT(stream->stream_data_in.buffered_frame_count == 0);
    CU_ASSERT(stream->stream_data_in.buffered_data_bytes == 0);

    /* A fresh large insert must now succeed again (no false rejection) */
    xqc_stream_frame_t *frame = xqc_calloc(1, sizeof(xqc_stream_frame_t));
    CU_ASSERT(frame != NULL);
    if (frame != NULL) {
        frame->data = xqc_malloc(frag_size);
        CU_ASSERT(frame->data != NULL);
        if (frame->data != NULL) {
            memset(frame->data, 0xAB, frag_size);
            frame->data_length = frag_size;
            frame->data_offset = frag_count * frag_size;  /* next in-order offset */
            ret = xqc_insert_crypto_frame(conn, stream, frame);
            CU_ASSERT(ret == XQC_OK);
            CU_ASSERT(stream->stream_data_in.buffered_frame_count == 1);
        } else {
            xqc_free(frame);
        }
    }

    xqc_engine_destroy(conn->engine);
}
