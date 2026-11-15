/**
 * @copyright Copyright (c) 2026, Alibaba Group Holding Limited
 */
#ifndef XQC_MOQT_DEMO_H
#define XQC_MOQT_DEMO_H

#include <stddef.h>
#include <string.h>

int xqc_demo_moqt_main(int argc, char **argv);

static inline int
xqc_demo_moqt_origin_allowed(const char *origin, size_t length,
    const char *allowed)
{
    if (!origin || !length || !allowed) {
        return 0;
    }
    while (*allowed) {
        while (*allowed == ' ' || *allowed == '\t') {
            allowed++;
        }
        size_t size = strcspn(allowed, ",");
        size_t trimmed = size;
        while (trimmed && (allowed[trimmed - 1] == ' '
                          || allowed[trimmed - 1] == '\t'))
        {
            trimmed--;
        }
        if (trimmed == length && !(trimmed == 1 && *allowed == '*')
            && !memcmp(origin, allowed, length))
        {
            return 1;
        }
        allowed += size;
        if (*allowed == ',') {
            allowed++;
        }
    }
    return 0;
}

#endif
