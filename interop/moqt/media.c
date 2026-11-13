/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "media.h"

/*
 * Independently encoded, unencrypted 16x16 VP8 keyframe. Repeated at 25 fps.
 * FFmpeg 8.1.1/libvpx: -f lavfi -i color=c=red:s=16x16:r=25 -frames:v 3
 * -c:v libvpx -g 1 -threads 1 -deadline best -f ivf. See README provenance.
 */
static const uint8_t xqc_interop_vp8[] = {
    0xf0, 0x02, 0x00, 0x9d, 0x01, 0x2a, 0x10, 0x00,
    0x10, 0x00, 0x00, 0x47, 0x08, 0x85, 0x85, 0x88,
    0x85, 0x84, 0x88, 0x02, 0x02, 0x02, 0x75, 0xaa,
    0x03, 0xf8, 0x03, 0xfa, 0x02, 0x0d, 0x4d, 0x18,
    0x00, 0xfe, 0xfd, 0x6e, 0xf3, 0xff, 0xe3, 0x99,
    0x37, 0x30, 0xc4, 0xff, 0x8e, 0x6d, 0xff, 0xf1,
    0x61, 0x3c, 0x0e, 0x28, 0xc8, 0xff, 0xf1, 0x51,
    0x00
};

int
xqc_interop_media_catalog(uint8_t *buf, size_t cap)
{
    xqc_msf_track_t track = {.name = "video", .codec = "vp8",
        .mime_type = "video/vp8", .role = "video", .width = 16,
        .height = 16, .timescale = 1000, .is_live = 1};
    /* MSF-01 5: an independent snapshot on the catalog Track. */
    return xqc_msf_catalog_encode(NULL, &track, 1, buf, cap);
}

int
xqc_interop_media_sample(unsigned index, xqc_moqt_object_t *object,
    uint8_t *properties, size_t cap)
{
    if (index >= XQC_INTEROP_MEDIA_FRAMES) {
        return -XQC_EPARAM;
    }
    xqc_loc_metadata_t metadata = {
        .present = XQC_LOC_TIMESTAMP | XQC_LOC_TIMESCALE | XQC_LOC_CODEC,
        .timestamp = index * 40, .timescale = 1000, .codec = {"vp8", 3}
    };
    int n = xqc_loc_encode(&metadata, properties, cap);
    if (n < 0) {
        return n;
    }
    /* MSF-01 4.1/6: every keyframe is its own GOP, Object and stream. */
    *object = (xqc_moqt_object_t){.group_id = index, .priority = 128,
        .properties = {properties, n},
        .payload = {(void *)xqc_interop_vp8, sizeof(xqc_interop_vp8)},
        .payload_length = sizeof(xqc_interop_vp8)};
    return 0;
}

void
xqc_interop_media_receive(xqc_interop_media_t *m,
    const xqc_moqt_object_t *o)
{
    if (m->error) {
        return;
    }
    int catalog = m->kind == XQC_INTEROP_MEDIA_CATALOG;
    uint64_t id = o->group_id;
    if ((!catalog && m->kind != XQC_INTEROP_MEDIA_VIDEO)
        || id >= (catalog ? 1 : XQC_INTEROP_MEDIA_FRAMES)
        || o->object_id || o->subgroup_id || o->datagram
        || o->status != XQC_MOQT_OBJECT_NORMAL || o->end_of_group
        || o->range != XQC_MOQT_RANGE_NONE || o->priority != 128
        || !o->payload_length || o->payload_length > XQC_INTEROP_MEDIA_BYTES
        || o->payload_offset != m->offsets[id]
        || m->offsets[id] >= o->payload_length
        || o->payload.iov_len > o->payload_length - m->offsets[id]
        || (o->payload.iov_len && !o->payload.iov_base)
        || (m->offsets[id] && m->lengths[id] != o->payload_length))
    {
        m->error = -XQC_EILLEGAL_FRAME;
        return;
    }
    if (!o->payload_offset) {
        xqc_loc_metadata_t metadata;
        int rc = xqc_loc_decode(o->properties.iov_base,
                               o->properties.iov_len, &metadata);
        if (rc != 0 || (catalog && o->properties.iov_len)
            || (!catalog
                && (metadata.present != (XQC_LOC_TIMESTAMP
                                         | XQC_LOC_TIMESCALE | XQC_LOC_CODEC)
                    || metadata.timestamp != id * 40
                    || metadata.timescale != 1000
                    || metadata.codec.iov_len != 3
                    || memcmp(metadata.codec.iov_base, "vp8", 3))))
        {
            m->error = rc ? rc : -XQC_EPROTO;
            return;
        }
        m->lengths[id] = o->payload_length;
    }
    if (o->payload.iov_len) {
        memcpy(m->bytes[id] + m->offsets[id], o->payload.iov_base,
               o->payload.iov_len);
    }
    m->offsets[id] += o->payload.iov_len;
    if (m->offsets[id] == m->lengths[id]) {
        if (!catalog && (m->lengths[id] != sizeof(xqc_interop_vp8)
            || memcmp(m->bytes[id], xqc_interop_vp8, sizeof(xqc_interop_vp8))))
        {
            m->error = -XQC_EPROTO;
            return;
        }
        m->count++;
    }
}

int
xqc_interop_media_track(const xqc_interop_media_t *m,
    char *name, size_t cap)
{
    if (m->error || m->kind != XQC_INTEROP_MEDIA_CATALOG || m->count != 1) {
        return m->error ? m->error : -XQC_EILLEGAL_FRAME;
    }
    xqc_msf_catalog_t *catalog = NULL;
    int rc = xqc_msf_catalog_decode(m->bytes[0], m->lengths[0], "", &catalog);
    if (rc != 0) {
        return rc;
    }
    xqc_msf_track_t track;
    rc = -XQC_EPROTO;
    if (xqc_msf_catalog_track_count(catalog) == 1
        && xqc_msf_catalog_track(catalog, 0, &track) == 0
        && track.codec && !strcmp(track.codec, "vp8")
        && track.role && !strcmp(track.role, "video")
        && track.mime_type && !strcmp(track.mime_type, "video/vp8")
        && !*track.track_namespace && track.width == 16 && track.height == 16
        && track.timescale == 1000 && strlen(track.name) < cap)
    {
        memcpy(name, track.name, strlen(track.name) + 1);
        rc = 0;
    }
    xqc_msf_catalog_destroy(catalog);
    return rc;
}

int
xqc_interop_media_render(const xqc_interop_media_t *m)
{
    if (m->error || m->kind != XQC_INTEROP_MEDIA_VIDEO
        || m->count != XQC_INTEROP_MEDIA_FRAMES)
    {
        return -1;
    }
    FILE *input = tmpfile(), *output = tmpfile();
    int rc = -1;
    if (!input || !output) {
        goto end;
    }
    uint8_t header[32] = {'D', 'K', 'I', 'F', 0, 0, 32, 0,
        'V', 'P', '8', '0', 16, 0, 16, 0, 25, 0, 0, 0, 1, 0, 0, 0,
        XQC_INTEROP_MEDIA_FRAMES};
    if (fwrite(header, 1, sizeof(header), input) != sizeof(header)) {
        goto end;
    }
    for (unsigned i = 0; i < XQC_INTEROP_MEDIA_FRAMES; i++) {
        uint8_t frame[12] = {0};
        if (m->lengths[i] != sizeof(xqc_interop_vp8)
            || m->offsets[i] != m->lengths[i])
        {
            goto end;
        }
        frame[0] = sizeof(xqc_interop_vp8);
        frame[4] = i;
        if (fwrite(frame, 1, sizeof(frame), input) != sizeof(frame)
            || fwrite(m->bytes[i], 1, m->lengths[i], input) != m->lengths[i])
        {
            goto end;
        }
    }
    if (fflush(input) || fseek(input, 0, SEEK_SET)) {
        goto end;
    }
    const char *decoder = getenv("XQC_INTEROP_FFMPEG");
    if (!decoder || !*decoder) {
        decoder = "ffmpeg";
    }
    pid_t child = fork();
    if (child == 0) {
        if (dup2(fileno(input), STDIN_FILENO) < 0
            || dup2(fileno(output), STDOUT_FILENO) < 0)
        {
            _exit(126);
        }
        fclose(input);
        fclose(output);
        execlp(decoder, decoder, "-v", "error", "-xerror", "-threads", "1",
               "-f", "ivf", "-i", "pipe:0", "-frames:v", "3",
               "-vf", "scale=16:16", "-pix_fmt", "gray", "-f", "rawvideo",
               "pipe:1", (char *)NULL);
        _exit(127);
    }
    if (child < 0) {
        goto end;
    }
    int status = 0, waited = 0;
    for (unsigned i = 0; i < 500; i++) {
        pid_t result = waitpid(child, &status, WNOHANG);
        if (result == child) {
            waited = 1;
            break;
        }
        if (result < 0 && errno != EINTR) {
            break;
        }
        struct timespec pause = {.tv_nsec = 10000000};
        nanosleep(&pause, NULL);
    }
    if (!waited) {
        kill(child, SIGKILL);
        while (waitpid(child, &status, 0) < 0 && errno == EINTR) { }
    }
    if (!waited || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        fprintf(stderr, "media decoder failed or timed out\n");
        goto end;
    }
    rewind(output);
    uint8_t pixels[16 * 16 * XQC_INTEROP_MEDIA_FRAMES];
    if (fread(pixels, 1, sizeof(pixels), output) != sizeof(pixels)
        || fgetc(output) != EOF)
    {
        fprintf(stderr, "media decoder returned incomplete frames\n");
        goto end;
    }
    /* Render actual decoded luma, never encoded-byte or callback counts. */
    for (unsigned i = 0; i < XQC_INTEROP_MEDIA_FRAMES; i++) {
        fprintf(stderr, "media rendered frame %u (16x16 VP8)\n", i);
        for (unsigned y = 0; y < 16; y++) {
            for (unsigned x = 0; x < 16; x++) {
                fputc(" .:-=+*#%@"[pixels[i * 256 + y * 16 + x] * 9 / 255],
                      stderr);
            }
            fputc('\n', stderr);
        }
    }
    fprintf(stderr, "displayed 3 frames, decoded 0 audio blocks\n");
    rc = 0;
end:
    if (input) {
        fclose(input);
    }
    if (output) {
        fclose(output);
    }
    return rc;
}
