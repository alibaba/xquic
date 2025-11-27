#ifndef _XQC_MOQ_CONTAINER_LOC_H_INCLUDED_
#define _XQC_MOQ_CONTAINER_LOC_H_INCLUDED_

#include "moq/xqc_moq.h"
#include "moq/moq_media/xqc_moq_container.h"

#define XQC_MOQ_LOC_HDR_CAPTURE_TIMESTAMP   0x2
#define XQC_MOQ_LOC_HDR_VIDEO_CONFIG        0xD
#define XQC_MOQ_LOC_HDR_VIDEO_FRAME_MARKING 0x4
#define XQC_MOQ_LOC_HDR_AUDIO_LEVEL         0x6

extern const xqc_moq_media_container_ops_t xqc_moq_loc_ops;

#endif /* _XQC_MOQ_CONTAINER_LOC_H_INCLUDED_ */
