/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#ifndef XQC_INTEROP_MEDIA_H
#define XQC_INTEROP_MEDIA_H

#include <moq/xqc_loc.h>
#include <moq/xqc_msf.h>

#define XQC_INTEROP_MEDIA_CATALOG 1
#define XQC_INTEROP_MEDIA_VIDEO   2
#define XQC_INTEROP_MEDIA_FRAMES  3
#define XQC_INTEROP_MEDIA_BYTES   1024

typedef struct {
    unsigned kind, count;
    int error;
    size_t offsets[XQC_INTEROP_MEDIA_FRAMES];
    size_t lengths[XQC_INTEROP_MEDIA_FRAMES];
    uint8_t bytes[XQC_INTEROP_MEDIA_FRAMES][XQC_INTEROP_MEDIA_BYTES];
} xqc_interop_media_t;

int xqc_interop_media_catalog(uint8_t *buf, size_t cap);
int xqc_interop_media_sample(unsigned index, xqc_moqt_object_t *object,
    uint8_t *properties, size_t cap);
void xqc_interop_media_receive(xqc_interop_media_t *media,
    const xqc_moqt_object_t *object);
int xqc_interop_media_track(const xqc_interop_media_t *media,
    char *name, size_t cap);
int xqc_interop_media_render(const xqc_interop_media_t *media);

#endif
