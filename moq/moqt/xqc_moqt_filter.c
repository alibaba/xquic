/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#include "xqc_moqt_session.h"
#include "src/common/utils/vint/xqc_variable_len_int.h"

static xqc_int_t
xqc_moqt_filter_uint(const uint8_t **p, const uint8_t *end, uint64_t *value)
{
    xqc_int_t n = xqc_vi64_read(*p, end, value);
    if (n < 0) {
        return XQC_ERROR;
    }
    *p += n;
    return XQC_OK;
}

/* Draft-22 §8.6 and §§9.20.10–9.20.14. */
static xqc_int_t
xqc_moqt_filter_key(const xqc_moq_message_parameter_t *p,
    xqc_moqt_filter_rule_t *key, const uint8_t **ranges)
{
    const uint8_t *data = p->value;
    if (data == NULL || p->length == 0) {
        return XQC_ERROR;
    }
    const uint8_t *end = data + p->length;
    uint64_t length;
    key->type = p->type;
    if (xqc_moqt_filter_uint(&data, end, &length) != XQC_OK
        || length != (size_t)(end - data))
    {
        return XQC_ERROR;
    }
    if (data == end) {
        return 0;
    }
    key->set = *data++;
    key->property = 0;
    if (p->type == XQC_MOQT_PARAM_OBJECT_PROPERTY_FILTER
        || p->type == XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER)
    {
        if (xqc_moqt_filter_uint(&data, end, &key->property) != XQC_OK
            || (key->property & 1))
        {
            return XQC_ERROR;
        }
    }
    *ranges = data;
    return data < end ? 1 : XQC_ERROR;
}

xqc_bool_t
xqc_moqt_filter_replaces(const xqc_moq_message_parameter_t *update,
    const xqc_moq_message_parameter_t *old)
{
    xqc_moqt_filter_rule_t a, b;
    const uint8_t *ranges;
    xqc_int_t n = xqc_moqt_filter_key(update, &a, &ranges);
    return n == 0 || (n == 1 && xqc_moqt_filter_key(old, &b, &ranges) == 1
                       && a.set == b.set && a.property == b.property);
}

xqc_int_t
xqc_moqt_filters_compile(const xqc_moqt_message_t *m, uint64_t limit,
    xqc_moqt_filters_t *filters)
{
    filters->rule_count = filters->range_count = 0;
    unsigned removed = 0;
    for (size_t i = 0; i < m->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &m->parameters[i];
        if (!xqc_moqt_is_range_filter(p->type)) {
            continue;
        }
        xqc_moqt_filter_rule_t key = {0};
        const uint8_t *data;
        xqc_int_t ret = xqc_moqt_filter_key(p, &key, &data);
        unsigned bit = 1U << (p->type - XQC_MOQT_PARAM_SUBGROUP_FILTER);
        if (ret < 0 || !limit || (removed & bit)) {
            return XQC_ERROR;
        }
        for (size_t j = 0; j < filters->rule_count; j++) {
            const xqc_moqt_filter_rule_t *prior = &filters->rules[j];
            if (prior->type == key.type && (ret == 0
                || (prior->set == key.set && prior->property == key.property)))
            {
                return XQC_ERROR;
            }
        }
        if (ret == 0) {
            removed |= bit;
            continue;
        }
        const uint8_t *end = p->value + p->length;
        uint64_t previous = 0;
        key.first = filters->range_count;
        while (data < end) {
            uint64_t start, delta, last = UINT64_MAX;
            if (filters->range_count >= limit
                || filters->range_count == XQC_MOQT_MAX_FILTER_RANGES
                || xqc_moqt_filter_uint(&data, end, &start) != XQC_OK
                || start > UINT64_MAX - previous)
            {
                return XQC_ERROR;
            }
            start += previous;
            xqc_bool_t has_end = data < end;
            if (has_end) {
                if (xqc_moqt_filter_uint(&data, end, &delta) != XQC_OK
                    || delta > UINT64_MAX - start)
                {
                    return XQC_ERROR;
                }
                last = start + delta;
            }
            if (key.type == XQC_MOQT_PARAM_PRIORITY_FILTER) {
                if (start > UINT8_MAX || (has_end && last > UINT8_MAX))
                {
                    return XQC_ERROR;
                }
            }
            filters->ranges[filters->range_count++] =
                (xqc_moqt_filter_range_t){start, last};
            previous = last;
        }
        key.count = filters->range_count - key.first;
        filters->rules[filters->rule_count++] = key;
    }
    return XQC_OK;
}

xqc_int_t
xqc_moqt_delivery_filters(xqc_moqt_session_t *s,
    const xqc_moqt_message_t *state, xqc_moqt_filters_t **filters)
{
    xqc_moqt_filters_t compiled = {0};
    if (xqc_moqt_filters_compile(state, XQC_MOQT_MAX_FILTER_RANGES,
                                 &compiled) != XQC_OK)
    {
        return XQC_ERROR;
    }
    if (compiled.rule_count == 0) {
        if (*filters != NULL) {
            xqc_free(*filters);
            s->buffered_bytes -= sizeof(compiled);
            *filters = NULL;
        }
        return XQC_OK;
    }
    if (*filters == NULL) {
        if (sizeof(compiled) > s->config.max_buffered_bytes - s->buffered_bytes) {
            return XQC_ERROR;
        }
        *filters = xqc_malloc(sizeof(compiled));
        if (*filters == NULL) {
            return XQC_ERROR;
        }
        s->buffered_bytes += sizeof(compiled);
    }
    **filters = compiled;
    return XQC_OK;
}

static xqc_bool_t
xqc_moqt_filter_property(const struct iovec *properties, uint64_t type,
    uint64_t *value, unsigned depth)
{
    uint64_t previous = 0;
    const uint8_t *bytes = properties->iov_base;
    if (bytes == NULL) {
        return XQC_FALSE;
    }
    size_t offset = 0;
    while (offset < properties->iov_len) {
        xqc_moqt_kv_t kv;
        xqc_int_t n = xqc_moqt_kv_decode(bytes + offset,
            properties->iov_len - offset, previous, &kv);
        if (n < 0) {
            return XQC_FALSE;
        }
        if (kv.type == type) {
            *value = kv.value.integer;
            return XQC_TRUE;
        }
        if (kv.type == XQC_MOQT_PROPERTY_IMMUTABLE && depth < 8
            && xqc_moqt_filter_property(&kv.value.bytes, type, value, depth + 1))
        {
            return XQC_TRUE;
        }
        previous = kv.type;
        offset += n;
    }
    return XQC_FALSE;
}

static xqc_bool_t
xqc_moqt_filter_contains(const xqc_moqt_filters_t *filters,
    const xqc_moqt_filter_rule_t *rule, uint64_t value)
{
    for (size_t i = rule->first; i < rule->first + rule->count; i++) {
        if (value >= filters->ranges[i].start && value <= filters->ranges[i].end) {
            return XQC_TRUE;
        }
    }
    return XQC_FALSE;
}

/* The Nth bit represents a rule, not a potentially sparse SetID. */
static unsigned
xqc_moqt_filter_failed_sets(const xqc_moqt_filters_t *filters, unsigned failed)
{
    unsigned excluded = failed;
    for (size_t i = 0; i < filters->rule_count; i++) {
        if (!(failed & (1U << i))) {
            continue;
        }
        for (size_t j = 0; j < filters->rule_count; j++) {
            if (filters->rules[i].set == filters->rules[j].set) {
                excluded |= 1U << j;
            }
        }
    }
    return excluded;
}

xqc_bool_t
xqc_moqt_filters_match(const xqc_moqt_filters_t *filters,
    const xqc_moqt_object_t *o)
{
    /* A range marker is a statement about history, not a selectable Object. */
    if (filters == NULL || !filters->rule_count || o->range) {
        return XQC_TRUE;
    }
    unsigned failed = 0;
    for (size_t i = 0; i < filters->rule_count; i++) {
        const xqc_moqt_filter_rule_t *rule = &filters->rules[i];
        uint64_t value;
        xqc_bool_t present = XQC_TRUE;
        switch (rule->type) {
        case XQC_MOQT_PARAM_SUBGROUP_FILTER:
            value = o->subgroup_id;
            present = !o->datagram;
            break;
        case XQC_MOQT_PARAM_OBJECTID_FILTER:
            value = o->object_id;
            break;
        case XQC_MOQT_PARAM_PRIORITY_FILTER:
            value = o->priority;
            break;
        default:
            present = xqc_moqt_filter_property(&o->properties, rule->property,
                                                &value, 0);
            break;
        }
        if (!present || !xqc_moqt_filter_contains(filters, rule, value)) {
            failed |= 1U << i;
        }
    }
    return xqc_moqt_filter_failed_sets(filters, failed)
           != (1U << filters->rule_count) - 1;
}

xqc_bool_t
xqc_moqt_filters_project(const xqc_moqt_message_t *interest,
    const struct iovec *properties, xqc_moqt_message_t *delivery)
{
    xqc_moqt_filters_t filters;
    if (xqc_moqt_filters_compile(interest, XQC_MOQT_MAX_FILTER_RANGES,
                                 &filters) != XQC_OK)
    {
        return XQC_FALSE;
    }
    delivery->parameter_count = 0;
    if (!filters.rule_count) {
        return XQC_TRUE;
    }
    unsigned failed = 0, objects = 0;
    for (size_t i = 0; i < filters.rule_count; i++) {
        const xqc_moqt_filter_rule_t *rule = &filters.rules[i];
        if (rule->type != XQC_MOQT_PARAM_TRACK_PROPERTY_FILTER) {
            objects |= 1U << i;
            continue;
        }
        uint64_t value;
        if (!xqc_moqt_filter_property(properties, rule->property, &value, 0)
            || !xqc_moqt_filter_contains(&filters, rule, value))
        {
            failed |= 1U << i;
        }
    }
    unsigned excluded = xqc_moqt_filter_failed_sets(&filters, failed);
    unsigned all = (1U << filters.rule_count) - 1;
    if (excluded == all) {
        return XQC_FALSE;
    }
    /* A surviving Track-only set admits all Objects. */
    if ((excluded | xqc_moqt_filter_failed_sets(&filters, objects)) != all) {
        return XQC_TRUE;
    }
    size_t rule = 0;
    for (size_t i = 0; i < interest->parameter_count; i++) {
        const xqc_moq_message_parameter_t *p = &interest->parameters[i];
        if (!xqc_moqt_is_range_filter(p->type)) {
            continue;
        }
        xqc_moqt_filter_rule_t key;
        const uint8_t *ranges;
        if (xqc_moqt_filter_key(p, &key, &ranges) == 1) {
            if ((objects & ~excluded) & (1U << rule)) {
                delivery->parameters[delivery->parameter_count++] = *p;
            }
            rule++;
        }
    }
    return XQC_TRUE;
}
