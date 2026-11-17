/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */

#ifndef _XQC_MSF_H_INCLUDED_
#define _XQC_MSF_H_INCLUDED_

#include <moq/xqc_moqt.h>

#ifdef __cplusplus
extern "C" {
#endif

#define XQC_MSF_VERSION          "draft-01"
#define XQC_MSF_CATALOG_NAME     "catalog"
#define XQC_MSF_MAX_TRACKS       32
#define XQC_MSF_MAX_JSON         65535
#define XQC_MSF_MAX_STRING       4096
#define XQC_MSF_MAX_DEPTH        16

typedef struct xqc_msf_catalog_s xqc_msf_catalog_t;

/*
 * MSF-01 independent plaintext LOC profile. Strings are UTF-8 MSF strings,
 * not binary MoQT names; the application resolves section 11.1.2 encoding.
 * NULL namespace inherits the catalog namespace. Zero numbers are omitted.
 */
typedef struct {
    const char    *name;
    const char    *track_namespace;
    const char    *codec;
    const char    *mime_type;
    const char    *role;
    const char    *channel_config;
    uint32_t       width;
    uint32_t       height;
    uint32_t       samplerate;
    uint32_t       timescale;
    xqc_bool_t     is_live;
} xqc_msf_track_t;

/*
 * Returns JSON byte count (no terminator), or a negative error. (NULL, 0)
 * sizes output. Strings/tracks must not overlap output. No delta, initRef,
 * encryption or dependent-track interpretation is provided by this profile.
 * catalog_namespace supplies inherited-name context; NULL means "".
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_msf_catalog_encode(const char *catalog_namespace,
    const xqc_msf_track_t *tracks, size_t count, uint8_t *buf, size_t cap);

/*
 * Owns parsed storage; output changes only on success. Caller assembles one
 * complete catalog Object first. Errors: EPARAM local arguments,
 * EILLEGAL_FRAME malformed JSON/fields, EPROTO unsupported profile/version,
 * ELIMIT budget, EMALLOC allocation, ENOBUF encode capacity.
 */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_msf_catalog_decode(const uint8_t *buf, size_t len,
    const char *catalog_namespace, xqc_msf_catalog_t **catalog);

XQC_EXPORT_PUBLIC_API
size_t xqc_msf_catalog_track_count(const xqc_msf_catalog_t *catalog);

/* Read-only strings borrow catalog storage; namespace is always resolved. */
XQC_EXPORT_PUBLIC_API
xqc_int_t xqc_msf_catalog_track(const xqc_msf_catalog_t *catalog, size_t index,
    xqc_msf_track_t *track);

XQC_EXPORT_PUBLIC_API
void xqc_msf_catalog_destroy(xqc_msf_catalog_t *catalog);

#ifdef __cplusplus
}
#endif
#endif /* _XQC_MSF_H_INCLUDED_ */
