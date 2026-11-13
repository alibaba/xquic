/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_LOC_H_INCLUDED_
#define _XQC_LOC_H_INCLUDED_

#include <moq/xqc_moqt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_LOC_TIMESCALE       0x01u
#define XQC_LOC_VIDEO_MARKING   0x02u
#define XQC_LOC_AUDIO_LEVEL     0x04u
#define XQC_LOC_VIDEO_CONFIG    0x08u
#define XQC_LOC_AUDIO_CONFIG    0x10u
#define XQC_LOC_TIMESTAMP       0x20u
#define XQC_LOC_CODEC           0x40u
#define XQC_LOC_FIELDS          0x7fu
#define XQC_LOC_MAX_PROPERTIES  64
#define XQC_LOC_MAX_BYTES       UINT16_MAX

/* LOC-05 section 2.3. Byte views borrow input and are read-only. */
typedef struct {
    unsigned        present;
    uint64_t        timestamp;
    uint64_t        timescale; /* Absent: 1000000, Unix epoch microseconds. */
    uint8_t         audio_level;
    struct iovec    video_marking;
    struct iovec    video_config;
    struct iovec    audio_config;
    struct iovec    codec;
} xqc_loc_metadata_t;

/*
 * Public Object properties only; no payload prefix or media conversion.
 * Encode returns bytes, supports (NULL, 0) sizing, and requires disjoint
 * input/output. Decode consumes the whole list. Unknown keys are skipped.
 * Errors: EPARAM for local arguments, ENOBUF for output, EILLEGAL_FRAME for
 * malformed input, ELIMIT for budgets. Failure leaves outputs unchanged.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_loc_encode(const xqc_loc_metadata_t *metadata, uint8_t *buf,
    size_t cap);

XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_loc_decode(const uint8_t *buf, size_t len,
    xqc_loc_metadata_t *metadata);

#ifdef __cplusplus
}
#endif
#endif /* _XQC_LOC_H_INCLUDED_ */
