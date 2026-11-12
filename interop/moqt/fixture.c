/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <stdlib.h>
#include <string.h>
#include "fixture.h"

/* aiomoqt 0.14.1 moq_interop_client.py, MOQ_TEST_CASES. */
int
xqc_interop_fixture_case(const char *name, xqc_interop_fixture_t *f)
{
    *f = (xqc_interop_fixture_t){0, 0, 0, 2, 5, 5, 64, 32, 2,
                                1, 1, 1, 0, 200};
    if (strcmp(name, "data-subgroup-basic") == 0) {
        f->last_object = 4;
        f->markers = 0;
        f->priority = 128;
    } else if (strcmp(name, "moq-test-subgroup-per-group-eog") == 0) {
        /* Defaults. */
    } else if (strcmp(name, "moq-test-subgroup-per-object") == 0) {
        f->mode = 1;
        f->last_group = 1;
        f->last_object = 3;
        f->objects_per_group = 4;
        f->markers = 0;
    } else if (strcmp(name, "moq-test-two-subgroups-eog") == 0) {
        f->mode = 2;
        f->last_object = 6;
        f->objects_per_group = 6;
    } else if (strcmp(name, "moq-test-datagram") == 0) {
        f->mode = 3;
        f->last_object = 4;
        f->markers = 0;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-datagram-eog") == 0) {
        f->mode = 3;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-extensions") == 0) {
        f->extensions = 1;
    } else if (strcmp(name, "moq-test-increments") == 0) {
        f->first_group = 10;
        f->last_group = 24;
        f->first_object = 3;
        f->last_object = 7;
        f->objects_per_group = 3;
        f->size0 = 40;
        f->size = 24;
        f->group_step = 7;
        f->object_step = 2;
        f->markers = 0;
    } else if (strcmp(name, "moq-test-forward-zero") == 0) {
        f->last_group = 1;
        f->last_object = 2;
        f->objects_per_group = 3;
        f->markers = 0;
    } else {
        return -1;
    }
    return 0;
}

unsigned
xqc_interop_fixture_count(const xqc_interop_fixture_t *f)
{
    if (!f->group_step || !f->object_step
        || f->last_group < f->first_group
        || f->last_object < f->first_object)
    {
        return 0;
    }
    return ((f->last_group - f->first_group) / f->group_step + 1)
        * ((f->last_object - f->first_object) / f->object_step + 1);
}

int
xqc_interop_fixture_parse(const xqc_moqt_namespace_t *ns,
    xqc_interop_fixture_t *f)
{
    long v[15];
    size_t start = ns->count >= 16 ? ns->count - 16 : ns->count;
    char buf[24], *end;

    if (start == ns->count || ns->fields[start].iov_len != 11
        || memcmp(ns->fields[start].iov_base, "moq-test-00", 11))
    {
        return -1;
    }
    for (size_t i = 0; i < 15; i++) {
        const struct iovec *field = &ns->fields[start + i + 1];
        if (!field->iov_len || field->iov_len >= sizeof(buf)) {
            return -1;
        }
        memcpy(buf, field->iov_base, field->iov_len);
        buf[field->iov_len] = 0;
        v[i] = strtol(buf, &end, 10);
        if (*end || v[i] < (i == 12 || i == 13 ? -1 : 0)
            || v[i] > 4096)
        {
            return -1;
        }
    }
    if (v[0] > 3 || !v[9] || !v[10] || v[11] > 1 || v[14]
        || v[3] < v[1] || v[4] < v[2] || !v[5]
        || v[6] > 1024 || v[7] > 1024 || v[8] > 100
        || !((v[12] == -1 && v[13] == -1)
             || (v[12] == 1 && v[13] == 2)))
    {
        return -1;
    }
    *f = (xqc_interop_fixture_t){v[0], v[1], v[2], v[3], v[4],
        v[5], v[6], v[7], v[8], v[9], v[10], v[11], v[12] == 1, 200};
    unsigned count = xqc_interop_fixture_count(f);
    return count && count <= XQC_INTEROP_MAX_OBJECTS ? 0 : -1;
}

void
xqc_interop_oracle_object(xqc_interop_oracle_t *o,
    const xqc_moqt_object_t *obj)
{
    const xqc_interop_fixture_t *f = &o->fixture;
    if (!xqc_interop_fixture_count(f)) {
        o->failed = 1;
        return;
    }
    uint64_t g = obj->group_id, id = obj->object_id;
    if (g < f->first_group || g > f->last_group
        || id < f->first_object || id > f->last_object
        || (g - f->first_group) % f->group_step
        || (id - f->first_object) % f->object_step)
    {
        o->failed = 1;
        return;
    }
    unsigned width = (f->last_object - f->first_object) / f->object_step + 1;
    unsigned n = (g - f->first_group) / f->group_step * width
        + (id - f->first_object) / f->object_step;
    unsigned sg = f->mode == 1 ? id : f->mode == 2 ? id % 2 : 0;
    unsigned priority = f->priority == 128 ? 128 : 200 + g % 2;
    if (n >= XQC_INTEROP_MAX_OBJECTS || obj->datagram != (f->mode == 3)
        || (!obj->datagram && obj->subgroup_id != sg)
        || (obj->datagram && obj->end_of_group && f->priority != 128)
        || obj->priority != priority || obj->range != XQC_MOQT_RANGE_NONE)
    {
        o->failed = 1;
        return;
    }
    int marker = f->markers && (id + f->object_step > f->last_object);
    if (marker) {
        if (obj->status != XQC_MOQT_OBJECT_END_GROUP || o->seen[n]
            || obj->payload_length || obj->end_of_group)
        {
            o->failed = 1;
        }
        o->seen[n] = 1;
        o->markers++;
        return;
    }
    unsigned size = id == f->first_object ? f->size0 : f->size;
    if (obj->status != XQC_MOQT_OBJECT_NORMAL || o->seen[n]
        || obj->payload_length != size || obj->payload_offset != o->offsets[n]
        || obj->payload.iov_len > size - o->offsets[n])
    {
        o->failed = 1;
        return;
    }
    if (obj->payload_offset == 0) {
        const unsigned char props[] = {2, 1, 3, 1, 'x'};
        if (f->extensions) {
            if (obj->properties.iov_len != sizeof(props)
                || memcmp(obj->properties.iov_base, props, sizeof(props)))
            {
                o->failed = 1;
            }
        } else if (obj->properties.iov_len) {
            o->failed = 1;
        }
    }
    const unsigned char *bytes = obj->payload.iov_base;
    for (size_t i = 0; i < obj->payload.iov_len; i++) {
        if (bytes[i] != 't') {
            o->failed = 1;
        }
    }
    o->offsets[n] += obj->payload.iov_len;
    if (o->offsets[n] == size) {
        o->seen[n] = 1;
        o->objects++;
    }
}

int
xqc_interop_oracle_complete(const xqc_interop_oracle_t *o, int forward_zero)
{
    return !o->failed && (forward_zero
        ? o->objects == 0 && o->markers == 0
        : o->objects + o->markers == xqc_interop_fixture_count(&o->fixture));
}
