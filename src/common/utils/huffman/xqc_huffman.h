/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef XQC_HUFFMAN_H
#define XQC_HUFFMAN_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "include/xquic/xquic_typedef.h"
#include "src/common/xqc_common.h"


/**
 * calc the encoded length of bytes
 * @param src the buffer that would be encoded
 * @param len length of src
 * @return the size of encoded huffman bytes
 */
size_t xqc_huffman_enc_len(const uint8_t *src, size_t len);


/**
 * encode bytes
 * @param dest the destination buffer for encoded huffman bytes, which shall 
 * always be long enough cause the length could be calculated before encoding 
 * @param src the bytes to be encoded
 * @param srclen length of src
 * @return end point of encoded buffer
 */
uint8_t *xqc_huffman_enc(uint8_t *dest, const uint8_t *src, size_t srclen);



typedef struct {
    /* huffman decoding state. We stripped leaf nodes, so the
       value range is [0..255], inclusive. */
    uint8_t    state;

    /* true if decode finished */
    xqc_bool_t end;

    /* whether processing high_bits now. when */
    xqc_bool_t high_bits;

    /* use for debug */
    uint8_t    pre_state;
    uint8_t    bit;
} xqc_huffman_dec_ctx;


void xqc_huffman_dec_ctx_init(xqc_huffman_dec_ctx *ctx);


/**
 * decode huffman encoded byte string into literal
 * @param ctx decode context, used to remember decode states
 * @param dest destination buffer
 * @param dstlen length of dest
 * @param src huffman encoded bytes buffer, which can be truncated
 * @param srclen length of src
 * @param fin the end flag of huffman encoded buffer
 * @param write bytes written
 * @return  < 0 for Could not decode huffman string. >= 0  for bytes consumed
 */
ssize_t xqc_huffman_dec(xqc_huffman_dec_ctx *ctx,
    uint8_t *dest, size_t dstlen, const uint8_t *src, size_t srclen, int fin, size_t *write);

#endif /* XQC_HUFFMAN_H */
