/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include "fixture.h"
#include "moq/moqt/xqc_moqt_codec.h"

static int xqc_interop_properties_valid(const xqc_interop_fixture_t *f,
    const xqc_moqt_object_t *obj, int origin);

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
    } else if (strcmp(name, "subscribe-cancel-live") == 0) {
        f->last_group = 2;
        f->markers = 0;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-subgroup-per-group-eog") == 0) {
        /* Defaults. */
    } else if (strcmp(name, "moq-test-subgroup-per-group-no-eog") == 0) {
        /*
         * Draft-22 Sections 11.3.1 and 11.3.2: FIN closes the Subgroup;
         * without END_OF_GROUP it does not establish the Group's final ID.
         */
        f->markers = 0;
    } else if (strcmp(name,
                      "moq-test-subgroup-per-group-nonzero-start") == 0)
    {
        f->first_group = 6;
        f->last_group = 8;
        f->first_object = 3;
        f->last_object = 5;
    } else if (strcmp(name,
                      "moq-test-subgroup-per-object-sparse-ids") == 0)
    {
        f->mode = 1;
        f->first_group = 4;
        f->last_group = 4;
        f->first_object = 2;
        f->last_object = 8;
        f->object_step = 3;
        f->markers = 0;
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
    } else if (strcmp(name, "moq-test-two-subgroups-no-eog") == 0) {
        f->mode = 2;
        f->last_object = 6;
        f->objects_per_group = 6;
        f->markers = 0;
    } else if (strcmp(name, "moq-test-datagram") == 0) {
        f->mode = 3;
        f->last_object = 4;
        f->markers = 0;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-datagram-nonzero-start") == 0) {
        f->mode = 3;
        f->first_group = 6;
        f->last_group = 8;
        f->first_object = 3;
        f->last_object = 5;
        f->markers = 0;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-datagram-sparse-ids") == 0) {
        f->mode = 3;
        f->first_group = 10;
        f->last_group = 24;
        f->first_object = 3;
        f->last_object = 7;
        f->group_step = 7;
        f->object_step = 2;
        f->markers = 0;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-datagram-eog") == 0) {
        f->mode = 3;
        f->pace_ms = 20;
    } else if (strcmp(name, "moq-test-extensions") == 0) {
        f->extensions = 3;
    } else if (strcmp(name, "moq-test-extensions-integer-only") == 0) {
        f->extensions = 1;
    } else if (strcmp(name, "moq-test-extensions-variable-only") == 0) {
        f->extensions = 2;
    } else if (strcmp(name, "moq-test-object-fragmentation") == 0) {
        /* draft-22 Section 11.3: Subgroup streams carry serialized Objects. */
        f->mode = XQC_INTEROP_MODE_FRAGMENTED;
        f->last_group = 0;
        f->last_object = 0;
        f->size0 = 96;
        f->size = 96;
        f->markers = 0;
        f->pace_ms = 2;
    } else if (strcmp(name, "moq-test-object-large-id") == 0) {
        /* draft-22 Sections 2.1, 2.3 and 11.3 carry 64-bit Object IDs. */
        f->first_group = UINT64_C(1) << 40;
        f->last_group = f->first_group + 1;
        f->first_object = (UINT64_C(1) << 40) + 5;
        f->last_object = f->first_object + 4;
        f->object_step = 2;
        f->markers = 0;
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
    uint64_t group_delta = (f->last_group - f->first_group) / f->group_step;
    uint64_t object_delta = (f->last_object - f->first_object)
        / f->object_step;
    if (group_delta == UINT64_MAX || object_delta == UINT64_MAX) {
        return 0;
    }
    uint64_t groups = group_delta + 1;
    uint64_t objects = object_delta + 1;
    if (objects > UINT_MAX / groups) {
        return 0;
    }
    return (unsigned)(groups * objects);
}

static int
xqc_interop_properties_valid(const xqc_interop_fixture_t *f,
    const xqc_moqt_object_t *obj, int origin)
{
    static const uint8_t integer_property[] = {2, 1};
    static const uint8_t variable_property[] = {5, 1, 'x'};
    static const uint8_t both_properties[] = {2, 1, 3, 1, 'x'};
    if (!origin) {
        const uint8_t *expected = f->extensions == 1 ? integer_property
            : f->extensions == 2 ? variable_property : both_properties;
        size_t expected_len = f->extensions == 1
            ? sizeof(integer_property) : f->extensions == 2
              ? sizeof(variable_property) : sizeof(both_properties);
        return obj->properties.iov_len == expected_len
            && !memcmp(obj->properties.iov_base, expected, expected_len);
    }

    const uint8_t *data = obj->properties.iov_base;
    size_t offset = 0;
    uint64_t previous_type = 0;
    unsigned seen = 0;
    while (offset < obj->properties.iov_len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(data + offset,
            obj->properties.iov_len - offset, previous_type, &kv);
        if (n <= 0 || (kv.type != 2 && kv.type != 5)) {
            return 0;
        }
        unsigned bit = kv.type == 2 ? 1 : 2;
        if (!(f->extensions & bit) || (seen & bit)) {
            return 0;
        }
        seen |= bit;
        previous_type = kv.type;
        offset += n;
    }
    return seen == f->extensions;
}

int
xqc_interop_fixture_parse(const xqc_moqt_namespace_t *ns,
    xqc_interop_fixture_t *f)
{
    long long v[15];
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
        errno = 0;
        v[i] = strtoll(buf, &end, 10);
        long long max = i >= 1 && i <= 4 ? LLONG_MAX : 4096;
        if (errno == ERANGE || *end
            || v[i] < (i == 12 || i == 13 ? -1 : 0)
            || v[i] > max)
        {
            return -1;
        }
    }
    if (v[0] > XQC_INTEROP_MODE_FRAGMENTED
        || !v[9] || !v[10] || v[11] > 1 || v[14]
        || v[3] < v[1] || v[4] < v[2] || !v[5]
        || v[6] > 1024 || v[7] > 1024 || v[8] > 100
        || !((v[12] == -1 && v[13] == -1)
             || (v[12] == 1 && v[13] == -1)
             || (v[12] == -1 && v[13] == 2)
             || (v[12] == 1 && v[13] == 2)))
    {
        return -1;
    }
    *f = (xqc_interop_fixture_t){v[0], v[1], v[2], v[3], v[4],
        v[5], v[6], v[7], v[8], v[9], v[10], v[11],
        (v[12] == 1 ? 1 : 0) | (v[13] == 2 ? 2 : 0), 200};
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
        || (!o->ignore_priority && obj->priority != priority)
        || obj->range != XQC_MOQT_RANGE_NONE)
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
        if (f->extensions) {
            /* MoQT Test -00 2.14/2.15: integer ID 2 and byte ID 5. */
            if (!xqc_interop_properties_valid(f, obj, o->origin)) {
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

int
xqc_interop_history_window(const xqc_interop_fixture_t *f,
    unsigned available, const xqc_moqt_location_t *start,
    const xqc_moqt_location_t *end, unsigned *first, unsigned *last)
{
    unsigned count = xqc_interop_fixture_count(f);
    if (!count || count > XQC_INTEROP_MAX_OBJECTS || !available
        || available > count || f->group_step != 1 || f->object_step != 1
        || f->mode || f->markers)
    {
        return -1;
    }
    uint64_t width = f->last_object - f->first_object + 1;
    xqc_moqt_location_t largest = {
        f->first_group + (available - 1) / width,
        f->first_object + (available - 1) % width,
    };
    if (start->group_id > end->group_id
        || (start->group_id == end->group_id
            && start->object_id > end->object_id)
        || start->group_id > largest.group_id
        || (start->group_id == largest.group_id
            && start->object_id > largest.object_id))
    {
        return -1;
    }
    /* Draft-22 3.2.1: a valid empty range is Header + FIN, not an error. */
    *first = available;
    *last = available - 1;
    for (unsigned i = 0; i < available; i++) {
        uint64_t group = f->first_group + i / width;
        uint64_t object = f->first_object + i % width;
        if ((group > start->group_id
                || (group == start->group_id && object >= start->object_id))
            && (group < end->group_id
                || (group == end->group_id && object <= end->object_id)))
        {
            if (*first == available) {
                *first = i;
            }
            *last = i;
        }
    }
    return 0;
}

int
xqc_interop_history_complete(const xqc_interop_oracle_t *o,
    const xqc_moqt_location_t *start, const xqc_moqt_location_t *end)
{
    unsigned first, last, count = xqc_interop_fixture_count(&o->fixture);
    if (o->failed || o->markers
        || xqc_interop_history_window(&o->fixture, count, start, end,
                                      &first, &last))
    {
        return 0;
    }
    for (unsigned i = 0; i < count; i++) {
        if (!!o->seen[i] != (i >= first && i <= last)) {
            return 0;
        }
    }
    return o->objects == (first > last ? 0 : last - first + 1);
}

void
xqc_interop_retention_event(xqc_interop_retention_t *s,
    const xqc_moqt_namespace_t *name, int available)
{
    const char *prefix[] = {"moq-test",
        "publish-namespace-multi-publisher-retention", s->run};
    if (name->count != 4) {
        s->failed = 1;
        return;
    }
    for (unsigned i = 0; i < 3; i++) {
        if (name->fields[i].iov_len != strlen(prefix[i])
            || memcmp(name->fields[i].iov_base, prefix[i], strlen(prefix[i])))
        {
            s->failed = 1;
            return;
        }
    }
    const struct iovec *field = &name->fields[3];
    unsigned slot;
    if (field->iov_len == 6 && !memcmp(field->iov_base, "shared", 6)) {
        slot = 0;
    } else if (field->iov_len == 4 && !memcmp(field->iov_base, "sync", 4)) {
        slot = 1;
    } else {
        s->failed = 1;
        return;
    }
    if (!!available == !!s->present[slot]
        || (!slot && !available && !s->allow_remove))
    {
        s->failed = 1;
    }
    s->present[slot] = !!available;
    if (available) {
        s->adds[slot]++;
    } else {
        s->removes[slot]++;
    }
}
