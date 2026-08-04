#ifndef _XQC_MOQ_D18_INT_H_INCLUDED_
#define _XQC_MOQ_D18_INT_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

size_t xqc_moq_d18_int_len(uint64_t value);

uint8_t *xqc_moq_d18_int_write(uint8_t *buf, uint64_t value);

/* Returns the encoded byte count, or -1 for a truncated/invalid input. */
int xqc_moq_d18_int_read(const uint8_t *pos, const uint8_t *end,
    uint64_t *value);

#endif /* _XQC_MOQ_D18_INT_H_INCLUDED_ */
