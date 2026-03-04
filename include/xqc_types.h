#ifndef XQC_TYPES_H
#define XQC_TYPES_H

#include <stdint.h>
#include <xquic/xquic_typedef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* draft-moq-delivery-feedback-00 (experimental): crosslayer event types */
typedef enum {
    XQC_EVENT_PACING_GAIN_UPDATE    = 1,
    XQC_EVENT_PACING_RATE_UPDATE    = 2,
    XQC_EVENT_TARGET_BITRATE_UPDATE = 3,
} xqc_crosslayer_event_type_t;

typedef struct {
    xqc_crosslayer_event_type_t type;
    union {
        struct { float gain; xqc_usec_t expire_us; }       pacing_gain;
        struct { uint64_t rate; xqc_usec_t expire_us; }    pacing_rate;      /* bytes/s */
        struct { uint64_t bitrate; xqc_usec_t expire_us; } target_bitrate;   /* bps */
    } payload;
} xqc_crosslayer_event_t;

#ifdef __cplusplus
}
#endif

#endif /* XQC_TYPES_H */

