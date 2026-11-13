/*
 * xqc_vint_read() reduced to its contract (proved for the real function by
 * harness_vint_read in harness/frame_parser.c):
 *   - fails (-1) iff p >= end or the length that the two high bits of *p
 *     select does not fit in [p, end);
 *   - else returns that length and a value below 2^(8 * len - 2).
 * The value is not tied to the bytes: this over-approximates the real
 * function, so a property proved with the stub holds for the real one.  The
 * stub still reads the first and the last byte of the varint, so a parser
 * that hands it a pointer outside its buffer is still caught.
 */
#include <stdint.h>
#include <stddef.h>

uint64_t nondet_u64(void);

int
xqc_vint_read(const unsigned char *p, const unsigned char *end, uint64_t *valp)
{
    if (p >= end) {
        return -1;
    }
    int len = 1 << (p[0] >> 6);
    if (end - p < len) {
        return -1;
    }
    volatile unsigned char last = p[len - 1];
    (void)last;
    uint64_t v = nondet_u64();
    __CPROVER_assume(v < ((uint64_t)1 << (8 * len - 2)));
    *valp = v;
    return len;
}
