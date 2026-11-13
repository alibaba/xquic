/*
 * Shared helpers for the CBMC harnesses of the xquic parsers.
 *
 * Input model: one heap object of exactly `len` bytes (1 <= len <= MAXLEN)
 * with unconstrained contents.  The parsers get [buf, buf + len), so any
 * read at or after `buf + len` is an out-of-bounds access for CBMC, not a
 * read of a neighbouring frame as it could be in a real packet buffer.
 */
#ifndef CBMC_XQC_COMMON_H
#define CBMC_XQC_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef MAXLEN
#define MAXLEN 64
#endif

size_t nondet_size_t(void);
unsigned char nondet_uchar(void);
uint64_t nondet_u64(void);
uint32_t nondet_u32(void);
int nondet_int(void);

/* A buffer of a nondeterministic length in [minlen, MAXLEN]. */
static inline unsigned char *
cbmc_buf(size_t minlen, size_t *lenp)
{
    size_t len = nondet_size_t();
    __CPROVER_assume(len >= minlen && len <= MAXLEN);
    unsigned char *buf = malloc(len);
    __CPROVER_assume(buf != NULL);
    *lenp = len;
    return buf;
}

#endif
