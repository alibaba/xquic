/**
 * xqc_webtransport_stream.h
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */
#ifndef XQC_WEBTRANSPORT_STREAM_H
#define XQC_WEBTRANSPORT_STREAM_H


#include <src/common/utils/var_buf/xqc_var_buf.h>
#include <xquic/xqc_http3.h>
#include <xquic/xqc_webtransport.h>


#ifdef __cplusplus
extern "C" {
#endif

/**
 * @note only one send stream or recv stream can be obtained by one unistream
 * @note send stream and recv stream can be obtained by one bidistream at the
 * same time
 */
typedef struct xqc_wt_send_stream_s xqc_wt_send_stream_t;
typedef struct xqc_wt_recv_stream_s xqc_wt_recv_stream_t;


typedef struct xqc_wt_buffer_s
{
    uint8_t                *data;
    size_t                  capacity;
    size_t                  len;
    size_t                  offset;
    struct xqc_wt_buffer_s *next;
} xqc_wt_buffer_t;

typedef struct xqc_wt_buffer_list_s
{
    xqc_wt_buffer_t *head;
    xqc_wt_buffer_t *tail;
} xqc_wt_buffer_list_t;


// xqc_wt_stream_map_t暂时不使用，后续再整合到stream里面
typedef struct xqc_wt_stream_map_s
{
    xqc_id_hash_table_t *FuncMap;
} xqc_wt_stream_map_t;

typedef struct xqc_wt_send_stream_s
{
    xqc_h3_stream_t        *h3_stream;
    xqc_stream_t           *stream;
    wt_stream_close_func_pt close_func;
    xqc_bool_t              send_header_flag;
} xqc_wt_send_stream_t;

typedef struct xqc_wt_recv_stream_s
{
    xqc_h3_stream_t        *h3_stream;
    xqc_stream_t           *stream;
    wt_stream_close_func_pt close_func;
} xqc_wt_recv_stream_t;


typedef struct xqc_wt_unistream_s
{
    xqc_wt_unistream_type_t type;   // 并非 xqc_webtransport_stream_t
    union fin_t
    {
        xqc_bool_t send_fin;
        xqc_bool_t recv_fin;
    } fin;

    uint64_t          sessionID;
    xqc_h3_stream_t  *h3_stream;   // 多余的 暂时保留
    xqc_connection_t *conn;
    xqc_bool_t packet_parsed_flag;   // default value = XQC_FALSE , when packet
                                     // parsed , set it to XQC_TRUE

    union stream
    {
        xqc_wt_send_stream_t *send_stream;
        xqc_wt_recv_stream_t *recv_stream;
    } stream;

    wt_stream_close_func_pt close_func;

} xqc_wt_unistream_t;

typedef struct xqc_wt_bidistream_s
{
    xqc_wt_send_stream_t   *send_stream;
    xqc_wt_recv_stream_t   *recv_stream;
    wt_stream_close_func_pt send_stream_close_func;
    wt_stream_close_func_pt recv_stream_close_func;

    xqc_bool_t packet_parsed_flag;   // default value = XQC_FALSE , when packet
                                     // parsed , set it to XQC_TRUE
    uint64_t         sessionID;
    xqc_h3_stream_t *h3_stream;

    xqc_bool_t send_fin;
    xqc_bool_t recv_fin;
} xqc_wt_bidistream_t;


void xqc_wt_send_stream_set_write_deadline(xqc_wt_send_stream_t *wt_stream,
    xqc_usec_t                                                   deadline);

xqc_h3_stream_t *xqc_wt_unistream_get_h3_stream(xqc_wt_unistream_t *wt_stream);


/* 这里整合了三种stream 类型： send , recv , bidi(同时包含send 和 recv)
 * send 和 recv 的close_func 由自己管理
 * 这里要同时考虑2种情况
 */

uint64_t xqc_wt_unistream_getid(xqc_wt_unistream_t *wt_stream);

/*
 *According to https://www.w3.org/TR/webtransport/#webtransport-stream
 *TODO feature:
 *    stop For send
 *    reset For read
 */

xqc_wt_bidistream_t *xqc_wt_create_bidistream(xqc_h3_stream_t *h3_stream,
    xqc_wt_session_t *session, wt_stream_close_func_pt send_close_func,
    wt_stream_close_func_pt recv_close_func, xqc_bool_t passive_created);

xqc_h3_stream_t *xqc_wt_bidistream_get_h3_stream(
    xqc_wt_bidistream_t *wt_stream);

xqc_int_t xqc_wt_bidistream_destroy(xqc_wt_bidistream_t *wt_stream);

xqc_int_t xqc_wt_bidistream_send(xqc_wt_bidistream_t *wt_stream, void *data,
    uint32_t len, int fin);

void xqc_wt_unistream_set_sessionID(xqc_wt_unistream_t *wt_stream,
    uint64_t                                            sessionID);


#ifdef __cplusplus
}
#endif

#endif
