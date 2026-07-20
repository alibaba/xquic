#include <stdio.h>

#include "src/common/xqc_list.h"
#include "src/common/xqc_malloc.h"
#include "moq/moq_media/xqc_moq_media_track.h"
#include "moq/moq_media/xqc_moq_datachannel.h"
#include "moq/moq_transport/xqc_moq_session.h"
#include "moq/moq_transport/xqc_moq_stream.h"

#define XQC_TEST_ASSERT(expr) \
    do { \
        if (!(expr)) { \
            fprintf(stderr, "assert failed: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
            return -1; \
        } \
    } while (0)

typedef struct {
    xqc_int_t close_ret;
    xqc_int_t close_count;
    xqc_int_t cancel_ret;
    xqc_int_t cancel_count;
    uint64_t cancel_error_code;
} xqc_test_stream_ctx_t;

static xqc_int_t
xqc_test_stream_close(void *stream)
{
    xqc_test_stream_ctx_t *ctx = stream;
    ctx->close_count++;
    return ctx->close_ret;
}

static xqc_int_t
xqc_test_stream_cancel(void *stream, uint64_t err_code)
{
    xqc_test_stream_ctx_t *ctx = stream;
    ctx->cancel_count++;
    ctx->cancel_error_code = err_code;
    return ctx->cancel_ret;
}

static void
xqc_test_init_stream(xqc_moq_stream_t *stream, xqc_moq_track_t *track,
    xqc_test_stream_ctx_t *ctx, uint64_t group_id, uint64_t object_id)
{
    xqc_memzero(stream, sizeof(*stream));
    xqc_init_list_head(&stream->list_member);
    xqc_init_list_head(&stream->recv_list_member);
    xqc_init_list_head(&stream->request_list_member);
    stream->track = track;
    stream->group_id = group_id;
    stream->object_id = object_id;
    stream->trans_stream = ctx;
    stream->trans_ops.close = xqc_test_stream_close;
    stream->trans_ops.cancel = xqc_test_stream_cancel;
}

static int
xqc_test_cancel_request_uses_moq_cancelled_code(void)
{
    xqc_moq_session_t session;
    xqc_memzero(&session, sizeof(session));
    session.use_unified_setup = 1;
    xqc_init_list_head(&session.local_request_stream_list);

    xqc_test_stream_ctx_t ctx = {0};
    xqc_moq_stream_t stream;
    xqc_memzero(&stream, sizeof(stream));
    xqc_init_list_head(&stream.request_list_member);
    stream.local_request = 1;
    stream.request_type = XQC_MOQ_MSG_PUBLISH_NAMESPACE;
    stream.request_id = 42;
    stream.trans_stream = &ctx;
    stream.trans_ops.cancel = xqc_test_stream_cancel;
    xqc_list_add_tail(&stream.request_list_member, &session.local_request_stream_list);

    XQC_TEST_ASSERT(xqc_moq_cancel_request(&session, 42) == XQC_OK);
    XQC_TEST_ASSERT(ctx.cancel_count == 1);
    XQC_TEST_ASSERT(ctx.cancel_error_code == XQC_MOQ_REQUEST_CANCELLED);
    XQC_TEST_ASSERT(xqc_moq_cancel_request(&session, 43) == -XQC_ESTREAM_NFOUND);

    xqc_list_del_init(&stream.request_list_member);
    return 0;
}

static void
xqc_test_init_media_track(xqc_moq_media_track_t *media_track, xqc_moq_session_t *session)
{
    xqc_memzero(media_track, sizeof(*media_track));
    xqc_memzero(session, sizeof(*session));
    media_track->track.session = session;
    media_track->track.track_role = XQC_MOQ_TRACK_FOR_PUB;
    media_track->track.track_info.track_type = XQC_MOQ_TRACK_AUDIO;
    xqc_init_list_head(&media_track->track.write_stream_list);
}

static int
xqc_test_cancel_write_before_closes_old_streams(void)
{
    xqc_moq_media_track_t media_track;
    xqc_moq_session_t session;
    xqc_test_init_media_track(&media_track, &session);

    xqc_test_stream_ctx_t ctx1 = {0};
    xqc_test_stream_ctx_t ctx2 = {0};
    xqc_test_stream_ctx_t ctx3 = {0};
    xqc_moq_stream_t stream1;
    xqc_moq_stream_t stream2;
    xqc_moq_stream_t stream3;
    xqc_test_init_stream(&stream1, &media_track.track, &ctx1, 1, 0);
    xqc_test_init_stream(&stream2, &media_track.track, &ctx2, 2, 0);
    xqc_test_init_stream(&stream3, &media_track.track, &ctx3, 3, 0);
    media_track.track.subgroup_stream = &stream2;
    xqc_list_add_tail(&stream1.list_member, &media_track.track.write_stream_list);
    xqc_list_add_tail(&stream2.list_member, &media_track.track.write_stream_list);
    xqc_list_add_tail(&stream3.list_member, &media_track.track.write_stream_list);

    xqc_moq_group_filter_t filter = {
        .type = XQC_MOQ_GROUP_FILTER_BEFORE,
        .group_id = 3,
    };

    XQC_TEST_ASSERT(xqc_moq_track_cancel_write(&media_track.track, &filter) == XQC_OK);
    XQC_TEST_ASSERT(ctx1.close_count == 1);
    XQC_TEST_ASSERT(ctx2.close_count == 1);
    XQC_TEST_ASSERT(stream1.cancel_write_close == 1);
    XQC_TEST_ASSERT(stream2.cancel_write_close == 1);
    XQC_TEST_ASSERT(ctx3.close_count == 0);
    XQC_TEST_ASSERT(xqc_list_empty(&stream1.list_member));
    XQC_TEST_ASSERT(xqc_list_empty(&stream2.list_member));
    XQC_TEST_ASSERT(!xqc_list_empty(&stream3.list_member));
    XQC_TEST_ASSERT(media_track.track.subgroup_stream == NULL);
    XQC_TEST_ASSERT(media_track.track.drop_write_group_id_before == 3);
    XQC_TEST_ASSERT(xqc_moq_track_should_drop_write_object(&media_track.track, 2, 0));
    XQC_TEST_ASSERT(!xqc_moq_track_should_drop_write_object(&media_track.track, 3, 0));

    xqc_list_del_init(&stream3.list_member);
    return 0;
}

static int
xqc_test_cancel_write_exact_only_closes_matching_group(void)
{
    xqc_moq_media_track_t media_track;
    xqc_moq_session_t session;
    xqc_test_init_media_track(&media_track, &session);

    xqc_test_stream_ctx_t ctx1 = {0};
    xqc_test_stream_ctx_t ctx2 = {0};
    xqc_moq_stream_t stream1;
    xqc_moq_stream_t stream2;
    xqc_test_init_stream(&stream1, &media_track.track, &ctx1, 1, 0);
    xqc_test_init_stream(&stream2, &media_track.track, &ctx2, 2, 0);
    xqc_list_add_tail(&stream1.list_member, &media_track.track.write_stream_list);
    xqc_list_add_tail(&stream2.list_member, &media_track.track.write_stream_list);

    xqc_moq_group_filter_t filter = {
        .type = XQC_MOQ_GROUP_FILTER_EXACT,
        .group_id = 2,
    };

    XQC_TEST_ASSERT(xqc_moq_track_cancel_write(&media_track.track, &filter) == XQC_OK);
    XQC_TEST_ASSERT(ctx1.close_count == 0);
    XQC_TEST_ASSERT(ctx2.close_count == 1);
    XQC_TEST_ASSERT(stream2.cancel_write_close == 1);
    XQC_TEST_ASSERT(!xqc_list_empty(&stream1.list_member));
    XQC_TEST_ASSERT(xqc_list_empty(&stream2.list_member));
    XQC_TEST_ASSERT(media_track.track.drop_write_group_id_before == 0);
    XQC_TEST_ASSERT(!xqc_moq_track_should_drop_write_object(&media_track.track, 2, 0));
    XQC_TEST_ASSERT(!xqc_moq_track_should_drop_write_object(&media_track.track, 1, 0));

    xqc_list_del_init(&stream1.list_member);
    return 0;
}

static int
xqc_test_cancel_write_closes_datachannel_subgroup_stream(void)
{
    xqc_moq_dc_track_t dc_track;
    xqc_moq_session_t session;
    xqc_memzero(&dc_track, sizeof(dc_track));
    xqc_memzero(&session, sizeof(session));
    dc_track.track.session = &session;
    dc_track.track.track_role = XQC_MOQ_TRACK_FOR_PUB;
    dc_track.track.track_info.track_type = XQC_MOQ_TRACK_DATACHANNEL;
    xqc_init_list_head(&dc_track.track.write_stream_list);

    xqc_test_stream_ctx_t ctx = {0};
    xqc_moq_stream_t stream;
    xqc_test_init_stream(&stream, &dc_track.track, &ctx, 7, 0);
    xqc_moq_track_on_write_stream(&dc_track.track, &stream, 7, 0, 0);

    xqc_moq_group_filter_t filter = {
        .type = XQC_MOQ_GROUP_FILTER_EXACT,
        .group_id = 7,
    };

    XQC_TEST_ASSERT(xqc_moq_track_cancel_write(&dc_track.track, &filter) == XQC_OK);
    XQC_TEST_ASSERT(ctx.close_count == 1);
    XQC_TEST_ASSERT(xqc_list_empty(&stream.list_member));
    XQC_TEST_ASSERT(!xqc_moq_track_should_drop_write_object(&dc_track.track, 7, 1));
    return 0;
}

static int
xqc_test_cancel_write_before_advances_datachannel_next_group(void)
{
    xqc_moq_dc_track_t dc_track;
    xqc_moq_session_t session;
    xqc_memzero(&dc_track, sizeof(dc_track));
    xqc_memzero(&session, sizeof(session));
    dc_track.track.session = &session;
    dc_track.track.track_role = XQC_MOQ_TRACK_FOR_PUB;
    dc_track.track.track_info.track_type = XQC_MOQ_TRACK_DATACHANNEL;
    dc_track.track.cur_group_id = 1;
    dc_track.track.cur_object_id = 0;
    xqc_init_list_head(&dc_track.track.write_stream_list);

    xqc_moq_group_filter_t filter = {
        .type = XQC_MOQ_GROUP_FILTER_BEFORE,
        .group_id = 5,
    };

    XQC_TEST_ASSERT(xqc_moq_track_cancel_write(&dc_track.track, &filter) == XQC_OK);
    XQC_TEST_ASSERT(xqc_moq_track_should_drop_write_object(&dc_track.track, 2, 0));
    uint64_t group_id = 2;
    uint64_t object_id = 0;
    xqc_moq_track_advance_write_location(&dc_track.track, &group_id, &object_id);
    XQC_TEST_ASSERT(group_id == 5);
    XQC_TEST_ASSERT(object_id == 0);
    XQC_TEST_ASSERT(dc_track.track.cur_group_id == 5);
    XQC_TEST_ASSERT(dc_track.track.cur_object_id == 1);
    XQC_TEST_ASSERT(!xqc_moq_track_should_drop_write_object(&dc_track.track, group_id, object_id));
    return 0;
}

static int
xqc_test_cancel_write_rejects_subscriber_track(void)
{
    xqc_moq_media_track_t media_track;
    xqc_moq_session_t session;
    xqc_test_init_media_track(&media_track, &session);
    media_track.track.track_role = XQC_MOQ_TRACK_FOR_SUB;

    xqc_moq_group_filter_t filter = {
        .type = XQC_MOQ_GROUP_FILTER_BEFORE,
        .group_id = 1,
    };

    XQC_TEST_ASSERT(xqc_moq_track_cancel_write(&media_track.track, &filter) == -XQC_EPARAM);
    return 0;
}

int
main(void)
{
    if (xqc_test_cancel_request_uses_moq_cancelled_code() != 0) {
        return 1;
    }

    if (xqc_test_cancel_write_before_closes_old_streams() != 0) {
        return 1;
    }

    if (xqc_test_cancel_write_exact_only_closes_matching_group() != 0) {
        return 1;
    }

    if (xqc_test_cancel_write_closes_datachannel_subgroup_stream() != 0) {
        return 1;
    }

    if (xqc_test_cancel_write_before_advances_datachannel_next_group() != 0) {
        return 1;
    }

    if (xqc_test_cancel_write_rejects_subscriber_track() != 0) {
        return 1;
    }

    return 0;
}
