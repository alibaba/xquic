#include "moq/moq_media/xqc_moq_container_loc.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

#define XQC_MOQ_LOC_ID_L            0x10
#define XQC_MOQ_LOC_SEID_0000_KEY   0xE0
#define XQC_MOQ_LOC_SEID_0000_DELTA 0xC0
#define XQC_MOQ_LOC_V_LEVEL         0x00

static xqc_int_t xqc_moq_encode_video_container_loc(xqc_moq_video_frame_t *video_frame,
    uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len);
static xqc_int_t xqc_moq_decode_video_container_loc(uint8_t *buf, xqc_int_t buf_len,
    xqc_moq_video_frame_t *video_frame);
static xqc_int_t xqc_moq_encode_audio_container_loc(xqc_moq_audio_frame_t *audio_frame,
    uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len);
static xqc_int_t xqc_moq_decode_audio_container_loc(uint8_t *buf, xqc_int_t buf_len,
    xqc_moq_audio_frame_t *audio_frame);

const xqc_moq_media_container_ops_t xqc_moq_loc_ops = {
    .encode_video   = xqc_moq_encode_video_container_loc,
    .decode_video   = xqc_moq_decode_video_container_loc,
    .encode_audio   = xqc_moq_encode_audio_container_loc,
    .decode_audio   = xqc_moq_decode_audio_container_loc,
};

static xqc_int_t
xqc_moq_encode_video_container_loc(xqc_moq_video_frame_t *video_frame, uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len)
{
    uint8_t *p = buf;

    /*https://datatracker.ietf.org/doc/html/draft-ietf-avtext-framemarking-16#section-3.2*/
    uint8_t ID_L = XQC_MOQ_LOC_ID_L;
    uint8_t SEID_0000;
    if (video_frame->type == XQC_MOQ_VIDEO_KEY) {
        SEID_0000 = XQC_MOQ_LOC_SEID_0000_KEY;
    } else if (video_frame->type == XQC_MOQ_VIDEO_DELTA) {
        SEID_0000 = XQC_MOQ_LOC_SEID_0000_DELTA;
    } else {
        return -XQC_EPARAM;
    }

    p = xqc_put_varint(p, video_frame->seq_num);
    p = xqc_put_uint64be(p, video_frame->timestamp_us);

    *p++ = ID_L;
    *p++ = SEID_0000;

    xqc_memcpy(p, video_frame->video_data, video_frame->video_len);
    p += video_frame->video_len;

    *encoded_len = p - buf;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_decode_video_container_loc(uint8_t *buf, xqc_int_t buf_len, xqc_moq_video_frame_t *video_frame)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t val;
    uint8_t ID_L;
    uint8_t SEID_0000;
    ret = xqc_vint_read(buf + processed, buf + buf_len - processed, &video_frame->seq_num);
    if (ret < 0) {
        return -XQC_EILLEGAL_FRAME;
    }
    processed += ret;

    memcpy(&val, buf + processed, sizeof(val));
    processed += sizeof(val);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    val = bswap_64(val);
#endif
    video_frame->timestamp_us = val;

    ID_L = *(buf + processed);
    processed++;
    SEID_0000 = *(buf + processed);
    processed++;
    if (ID_L != XQC_MOQ_LOC_ID_L) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (SEID_0000 == XQC_MOQ_LOC_SEID_0000_KEY) {
        video_frame->type = XQC_MOQ_VIDEO_KEY;
    } else if (SEID_0000 == XQC_MOQ_LOC_SEID_0000_DELTA) {
        video_frame->type = XQC_MOQ_VIDEO_DELTA;
    } else {
        return -XQC_EILLEGAL_FRAME;
    }

    video_frame->video_data = buf + processed;
    video_frame->video_len = buf_len - processed;

    return XQC_OK;
}


static xqc_int_t
xqc_moq_encode_audio_container_loc(xqc_moq_audio_frame_t *audio_frame, uint8_t *buf, size_t buf_cap, xqc_int_t *encoded_len)
{
    uint8_t *p = buf;

    /*https://www.rfc-editor.org/rfc/rfc6464#section-3*/
    uint8_t ID_L = XQC_MOQ_LOC_ID_L;
    uint8_t V_LEVEL = XQC_MOQ_LOC_V_LEVEL; /* level is unused now */

    p = xqc_put_varint(p, audio_frame->seq_num);
    p = xqc_put_uint64be(p, audio_frame->timestamp_us);

    *p++ = ID_L;
    *p++ = V_LEVEL;

    xqc_memcpy(p, audio_frame->audio_data, audio_frame->audio_len);
    p += audio_frame->audio_len;

    *encoded_len = p - buf;
    return XQC_OK;
}

static xqc_int_t
xqc_moq_decode_audio_container_loc(uint8_t *buf, xqc_int_t buf_len, xqc_moq_audio_frame_t *audio_frame)
{
    xqc_int_t processed = 0;
    xqc_int_t ret = 0;
    uint64_t val;
    uint8_t ID_L;
    uint8_t V_LEVEL;
    ret = xqc_vint_read(buf + processed, buf + buf_len - processed, &audio_frame->seq_num);
    if (ret < 0) {
        return -XQC_EILLEGAL_FRAME;
    }
    processed += ret;

    memcpy(&val, buf + processed, sizeof(val));
    processed += sizeof(val);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    val = bswap_64(val);
#endif
    audio_frame->timestamp_us = val;

    ID_L = *(buf + processed);
    processed++;
    V_LEVEL = *(buf + processed);
    processed++;
    if (ID_L != XQC_MOQ_LOC_ID_L) {
        return -XQC_EILLEGAL_FRAME;
    }
    if (V_LEVEL != XQC_MOQ_LOC_V_LEVEL) {
        return -XQC_EILLEGAL_FRAME;
    }

    audio_frame->audio_data = buf + processed;
    audio_frame->audio_len = buf_len - processed;

    return XQC_OK;
}
