/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#include <moq/xqc_loc.h>
#include "moq/moqt/xqc_moqt_codec.h"
#include "src/common/xqc_str.h"

static const uint64_t xqc_loc_keys[] = {8, 9, 12, 13, 15, 16, 17};

static xqc_int_t xqc_loc_validate(const xqc_loc_metadata_t *metadata);

static xqc_int_t
xqc_loc_validate(const xqc_loc_metadata_t *metadata)
{
    if (metadata->present & ~XQC_LOC_FIELDS) {
        return -XQC_EPARAM;
    }
    if ((metadata->present & XQC_LOC_TIMESCALE) && !metadata->timescale) {
        return -XQC_EPARAM;
    }
    const struct iovec *bytes[] = {&metadata->video_marking,
        &metadata->video_config, &metadata->audio_config, &metadata->codec};
    const unsigned masks[] = {XQC_LOC_VIDEO_MARKING, XQC_LOC_VIDEO_CONFIG,
        XQC_LOC_AUDIO_CONFIG, XQC_LOC_CODEC};
    for (size_t i = 0; i < 4; i++) {
        if (!(metadata->present & masks[i])) {
            continue;
        }
        if (bytes[i]->iov_len > XQC_LOC_MAX_BYTES
            || (bytes[i]->iov_len && bytes[i]->iov_base == NULL))
        {
            return -XQC_EPARAM;
        }
    }
    if ((metadata->present & XQC_LOC_VIDEO_MARKING)
        && (metadata->video_marking.iov_len < 1
            || metadata->video_marking.iov_len > 4))
    {
        return -XQC_EPARAM;
    }
    return XQC_OK;
}

xqc_int_t
xqc_loc_encode(const xqc_loc_metadata_t *metadata, uint8_t *buf, size_t cap)
{
    if (metadata == NULL || (buf == NULL && cap)
        || xqc_loc_validate(metadata) != XQC_OK)
    {
        return -XQC_EPARAM;
    }
    xqc_moqt_kv_t kv[7] = {0};
    kv[0].value.integer = metadata->timescale;
    kv[1].value.bytes = metadata->video_marking;
    kv[2].value.integer = metadata->audio_level;
    kv[3].value.bytes = metadata->video_config;
    kv[4].value.bytes = metadata->audio_config;
    kv[5].value.integer = metadata->timestamp;
    kv[6].value.bytes = metadata->codec;
    size_t len = 0;
    uint64_t previous = 0;
    for (size_t i = 0; i < 7; i++) {
        if (!(metadata->present & (1u << i))) {
            continue;
        }
        kv[i].type = xqc_loc_keys[i];
        xqc_int_t n = xqc_moqt_kv_encode(&kv[i], previous, NULL, 0);
        if (n < 0) {
            return n;
        }
        len += n;
        previous = kv[i].type;
    }
    if (len > XQC_LOC_MAX_BYTES) {
        return -XQC_ELIMIT;
    }
    if (buf == NULL) {
        return (xqc_int_t)len;
    }
    if (cap < len) {
        return -XQC_ENOBUF;
    }
    previous = 0;
    size_t pos = 0;
    for (size_t i = 0; i < 7; i++) {
        if (metadata->present & (1u << i)) {
            pos += xqc_moqt_kv_encode(&kv[i], previous, buf + pos, cap - pos);
            previous = kv[i].type;
        }
    }
    return (xqc_int_t)len;
}

xqc_int_t
xqc_loc_decode(const uint8_t *buf, size_t len, xqc_loc_metadata_t *metadata)
{
    if (metadata == NULL || (buf == NULL && len)) {
        return -XQC_EPARAM;
    }
    if (len > XQC_LOC_MAX_BYTES) {
        return -XQC_ELIMIT;
    }
    xqc_loc_metadata_t result = {0};
    result.timescale = 1000000;
    size_t pos = 0, count = 0;
    uint64_t previous = 0;
    while (pos < len) {
        if (++count > XQC_LOC_MAX_PROPERTIES) {
            return -XQC_ELIMIT;
        }
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(buf + pos, len - pos, previous, &kv);
        if (n < 0) {
            return -XQC_EILLEGAL_FRAME;
        }
        pos += n;
        previous = kv.type;
        size_t i;
        for (i = 0; i < 7 && xqc_loc_keys[i] != kv.type; i++) {
            /* Match a known LOC property; unknown types remain opaque. */
        }
        if (i == 7) {
            continue;
        }
        if (result.present & (1u << i)) {
            return -XQC_EILLEGAL_FRAME;
        }
        result.present |= 1u << i;
        switch (kv.type) {
        case 8:
            result.timescale = kv.value.integer;
            break;
        case 9:
            result.video_marking = kv.value.bytes;
            break;
        case 12:
            if (kv.value.integer > UINT8_MAX) {
                return -XQC_EILLEGAL_FRAME;
            }
            result.audio_level = (uint8_t)kv.value.integer;
            break;
        case 13:
            result.video_config = kv.value.bytes;
            break;
        case 15:
            result.audio_config = kv.value.bytes;
            break;
        case 16:
            result.timestamp = kv.value.integer;
            break;
        case 17:
            result.codec = kv.value.bytes;
            break;
        }
    }
    if (xqc_loc_validate(&result) != XQC_OK) {
        return -XQC_EILLEGAL_FRAME;
    }
    *metadata = result;
    return XQC_OK;
}
