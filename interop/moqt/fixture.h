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

typedef struct {
    char run[33];
    unsigned present[2], adds[2], removes[2], allow_remove, failed;
} xqc_interop_retention_t;

int xqc_interop_fixture_case(const char *name, xqc_interop_fixture_t *f);
int xqc_interop_fixture_parse(const xqc_moqt_namespace_t *ns,
    xqc_interop_fixture_t *f);
unsigned xqc_interop_fixture_count(const xqc_interop_fixture_t *f);
void xqc_interop_oracle_object(xqc_interop_oracle_t *oracle,
    const xqc_moqt_object_t *object);
int xqc_interop_oracle_complete(const xqc_interop_oracle_t *oracle,
    int forward_zero);
int xqc_interop_history_window(const xqc_interop_fixture_t *f,
    unsigned available, const xqc_moqt_location_t *start,
    const xqc_moqt_location_t *end, unsigned *first, unsigned *last);
int xqc_interop_history_complete(const xqc_interop_oracle_t *oracle,
    const xqc_moqt_location_t *start, const xqc_moqt_location_t *end);
void xqc_interop_retention_event(xqc_interop_retention_t *state,
    const xqc_moqt_namespace_t *name, int available);

#endif
