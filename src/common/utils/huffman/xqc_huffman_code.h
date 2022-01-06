/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_HUFFMAN_CODE_H_
#define _XQC_HUFFMAN_CODE_H_

#include <stdio.h>
#include <stdint.h>

/**
 * huffman encode table
 */

typedef struct {
    /* bits count of huffman code */
    uint32_t bits;
    /* Huffman code as hex aligned to LSB of symbol */
    uint32_t lsb;
} xqc_huffman_enc_code_t;

extern const xqc_huffman_enc_code_t xqc_huffman_enc_code_table[];



/**
 * huffman decode table
 */

typedef enum {
    /* the end of huffman encoded bytes. */
    XQC_HUFFMAN_END = 0x01,

    /* symbol is available */
    XQC_HUFFMAN_SYM = 0x02,

    /* decoding failure. */
    XQC_HUFFMAN_FAIL = 0x04
} xqc_huffman_dec_flag;

typedef struct {
    /* huffman decoding state, which is 
       the index of next decode code */
    uint8_t state;

    /* xqc_huffman_dec_flag */
    uint8_t flags;

    /* symbol */
    uint8_t sym;
} xqc_huffman_dec_code_t;

extern const xqc_huffman_dec_code_t xqc_huffman_dec_code_table[256][16];

#endif