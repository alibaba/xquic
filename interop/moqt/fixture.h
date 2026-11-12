/* Copyright (c) 2026, Alibaba Group Holding Limited. */
#ifndef XQC_INTEROP_FIXTURE_H
#define XQC_INTEROP_FIXTURE_H

#include <moq/xqc_moqt.h>

#define XQC_INTEROP_MAX_OBJECTS 256

typedef struct {
    unsigned mode, first_group, first_object, last_group, last_object;
    unsigned objects_per_group, size0, size, pace_ms, group_step, object_step;
    unsigned markers, extensions, priority;
} xqc_interop_fixture_t;

typedef struct {
    xqc_interop_fixture_t fixture;
    size_t offsets[XQC_INTEROP_MAX_OBJECTS];
    unsigned char seen[XQC_INTEROP_MAX_OBJECTS];
    unsigned objects, markers, failed;
} xqc_interop_oracle_t;

int xqc_interop_fixture_case(const char *name, xqc_interop_fixture_t *f);
int xqc_interop_fixture_parse(const xqc_moqt_namespace_t *ns,
    xqc_interop_fixture_t *f);
unsigned xqc_interop_fixture_count(const xqc_interop_fixture_t *f);
void xqc_interop_oracle_object(xqc_interop_oracle_t *oracle,
    const xqc_moqt_object_t *object);
int xqc_interop_oracle_complete(const xqc_interop_oracle_t *oracle,
    int forward_zero);

#endif
