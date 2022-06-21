/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_INSTRUCTION_H_
#define _XQC_INSTRUCTION_H_

#include "src/http3/xqc_var_buf.h"
#include "src/http3/qpack/xqc_prefixed_int.h"
#include "src/http3/qpack/xqc_prefixed_str.h"
#include "src/common/xqc_common_inc.h"
#include "src/http3/qpack/xqc_qpack_defs.h"



/* stages for parsing encoder instruction bytes */
typedef enum xqc_ins_enc_stage_s {
    XQC_INS_ES_OPCODE = 0,
    XQC_INS_ES_CAPACITY,
    XQC_INS_ES_STATE_INDEX,
    XQC_INS_ES_STATE_NAME,
    XQC_INS_ES_STATE_VALUE,
    XQC_INS_ES_STATE_FINISH,
} xqc_ins_enc_stage_t;

/* encoder instruction types */
typedef enum xqc_ins_enc_type_s {
    /* Set Dynamic Table Capacity */
    XQC_INS_TYPE_ENC_SET_DTABLE_CAP = 0,

    /* Insert With Name Reference */
    XQC_INS_TYPE_ENC_INSERT_NAME_REF,

    /* Insert With Literal Name */
    XQC_INS_TYPE_ENC_INSERT_LITERAL,

    /* Duplicate */
    XQC_INS_TYPE_ENC_DUP,

} xqc_ins_enc_type_t;


/* context for parsing encoder instructions */
typedef struct xqc_ins_enc_ctx_s {
    xqc_ins_enc_stage_t state;
    xqc_ins_enc_type_t  type;
    uint8_t             table;
    xqc_prefixed_int_t  name_index;
    xqc_prefixed_int_t  capacity;
    xqc_prefixed_str_t *name;
    xqc_prefixed_str_t *value;
} xqc_ins_enc_ctx_t;


/**
 * @brief create context for parsing encoder instruction bytes
 * @return xqc_ins_encode_ctx_t* 
 */
xqc_ins_enc_ctx_t *
xqc_ins_encoder_ctx_create();

/**
 * @brief destroy context for parsing encoder instruction bytes
 * @param ctx the pointer of context to be destroyed
 */
void
xqc_ins_encoder_ctx_free(xqc_ins_enc_ctx_t *ctx);

/**
 * @brief parse encoder instruction bytes
 * @return >= 0 for bytes processed, < 0 for failure
 */
ssize_t
xqc_ins_parse_encoder(unsigned char *buf, uint64_t buf_len, xqc_ins_enc_ctx_t *ctx);



/* stages for parsing decoder instructions */
typedef enum xqc_ins_dec_stage_s {
    XQC_INS_DS_STATE_OPCODE = 0,
    XQC_INS_DS_STATE_STREAM_ID,
    XQC_INS_DS_STATE_INCREMENT,
    XQC_INS_DS_STATE_FINISH,
} xqc_ins_dec_stage_t;


/* decoder instruction types */
typedef enum xqc_ins_dec_type_s {
    /* Section Acknowledgement */
    XQC_INS_TYPE_DEC_SECTION_ACK,

    /* Stream Cancellation */
    XQC_INS_TYPE_DEC_STREAM_CANCEL,

    /* Insert Count Increment */
    XQC_INS_TYPE_DEC_INSERT_CNT_INC,

} xqc_ins_dec_type_t;

/* context for parsing decoder instructions */
typedef struct xqc_ins_dec_ctx_s {
    xqc_ins_dec_stage_t state;
    xqc_ins_dec_type_t  type;
    xqc_prefixed_int_t  stream_id;
    xqc_prefixed_int_t  increment;
} xqc_ins_dec_ctx_t;


/**
 * @brief create context for parsing decoder instruction bytes
 * @return xqc_ins_dec_ctx_t* decoder context
 */
xqc_ins_dec_ctx_t *xqc_ins_decoder_ctx_create();
void xqc_ins_decoder_ctx_free(xqc_ins_dec_ctx_t *ctx);

/**
 * @brief parse decoder instructions from input buf
 * @param ctx the parsing context
 */
ssize_t xqc_ins_parse_decoder(unsigned char *buf, uint64_t buf_len, xqc_ins_dec_ctx_t *ctx);


/**
 * @brief Set Dynamic Table Capacity
 */
xqc_int_t xqc_ins_write_set_dtable_cap(xqc_var_buf_t *buf, uint64_t capacity);

/**
 * @brief Insert With Name Reference
 */
xqc_int_t xqc_ins_write_insert_name_ref(xqc_var_buf_t *buf, xqc_flag_t t, uint64_t index,
    unsigned char *value, uint64_t vlen);

/**
 * @brief Insert With Literal Name
 */
xqc_int_t xqc_ins_write_insert_literal_name(xqc_var_buf_t *buf, unsigned char *name, uint64_t nlen,
    unsigned char *value, uint64_t vlen);

/**
 * @brief Duplicate
 */
xqc_int_t xqc_ins_write_dup(xqc_var_buf_t *buf, uint64_t index);

/**
 * @brief Section Acknowledgement
 */
xqc_int_t xqc_ins_write_section_ack(xqc_var_buf_t *buf, uint64_t stream_id);

/**
 * @brief Stream Cancellation
 */
xqc_int_t xqc_ins_write_stream_cancel(xqc_var_buf_t *buf, uint64_t stream_id);

/**
 * @brief Insert Count Increment
 */
xqc_int_t xqc_ins_write_icnt_increment(xqc_var_buf_t *buf, uint64_t increment);


#endif