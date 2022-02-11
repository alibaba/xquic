/**
 * @copyright Copyright (c) 2022, Alibaba Group Holding Limited
 */

#ifndef _XQC_ERRNO_H_INCLUDED_
#define _XQC_ERRNO_H_INCLUDED_

/*
 *  QUIC Transport Protocol error codes
 */
typedef enum {
    TRA_NO_ERROR                    =  0x0,
    TRA_INTERNAL_ERROR              =  0x1,
    TRA_CONNECTION_REFUSED_ERROR    =  0x2,
    TRA_FLOW_CONTROL_ERROR          =  0x3,
    TRA_STREAM_LIMIT_ERROR          =  0x4,
    TRA_STREAM_STATE_ERROR          =  0x5,
    TRA_FINAL_SIZE_ERROR            =  0x6,
    TRA_FRAME_ENCODING_ERROR        =  0x7,
    TRA_TRANSPORT_PARAMETER_ERROR   =  0x8,
    TRA_CONNECTION_ID_LIMIT_ERROR   =  0x9,
    TRA_PROTOCOL_VIOLATION          =  0xA,
    TRA_INVALID_TOKEN               =  0xB,
    TRA_APPLICATION_ERROR           =  0xC,
    TRA_CRYPTO_BUFFER_EXCEEDED      =  0xD,
    TRA_HS_CERTIFICATE_VERIFY_FAIL  =  0x1FE, /* for handshake certificate verify error */
    TRA_CRYPTO_ERROR                =  0x1FF, /* 0x1XX */
} xqc_trans_err_code_t;

#define TRA_CRYPTO_ERROR_BASE   0x100

/*
 *  QUIC Http/3 Protocol error codes
 */
typedef enum {
    H3_NO_ERROR                     = 0x100,
    H3_GENERAL_PROTOCOL_ERROR       = 0x101,
    H3_INTERNAL_ERROR               = 0x102,
    H3_STREAM_CREATION_ERROR        = 0x103,
    H3_CLOSED_CRITICAL_STREAM       = 0x104,
    H3_FRAME_UNEXPECTED             = 0x105,
    H3_FRAME_ERROR                  = 0x106,
    H3_EXCESSIVE_LOAD               = 0x107,
    H3_ID_ERROR                     = 0x108,
    H3_SETTINGS_ERROR               = 0x109,
    H3_MISSING_SETTINGS             = 0x10A,
    H3_REQUEST_REJECTED             = 0x10B,
    H3_REQUEST_CANCELLED            = 0x10C,
    H3_REQUEST_INCOMPLETE           = 0x10D,
    H3_CONNECT_ERROR                = 0x10F,
    H3_VERSION_FALLBACK             = 0x110,
} xqc_h3_err_code_t;

/*
 * QUIC QPACK protocol error codes
 */
typedef enum {
    QPACK_DECOMPRESSION_FAILED = 0x200,
    QPACK_ENCODER_STREAM_ERROR = 0x201,
    QPACK_DECODER_STREAM_ERROR = 0x202,
} xqc_qpack_err_code_t;


#define XQC_OK      0
#define XQC_ERROR   -1


/* xquic transport internal error codes: 6xx */
typedef enum {
    XQC_ENOBUF                          = 600,      /* not enough buf space */
    XQC_EVINTREAD                       = 601,      /* parse frame error */
    XQC_ENULLPTR                        = 602,      /* empty pointer, usually a malloc failure */
    XQC_EMALLOC                         = 603,      /* malloc failure */
    XQC_EILLPKT                         = 604,      /* illegal packet, don't close connection, just drop it */
    XQC_ELEVEL                          = 605,      /* incorrect encryption level */
    XQC_ECREATE_CONN                    = 606,      /* fail to create a connection */
    XQC_CLOSING                         = 607,      /* connection is closing, operation denied */
    XQC_ECONN_NFOUND                    = 608,      /* fail to find the corresponding connection */
    XQC_ESYS                            = 609,      /* system error, usually a public library interface failure */
    XQC_EAGAIN                          = 610,      /* write blocking, similar to EAGAIN */
    XQC_EPARAM                          = 611,      /* wrong parameters */
    XQC_ESTATE                          = 612,      /* abnormal connection status */
    XQC_ELIMIT                          = 613,      /* exceed cache limit */
    XQC_EPROTO                          = 614,      /* violation of protocol */
    XQC_ESOCKET                         = 615,      /* socket interface error */
    XQC_EFATAL                          = 616,      /* fatal error, engine will immediately destroy the connection */
    XQC_ESTREAM_ST                      = 617,      /* abnormal flow status */
    XQC_ESEND_RETRY                     = 618,      /* send retry failure */
    XQC_ECONN_BLOCKED                   = 619,      /* connection-level flow control */
    XQC_ESTREAM_BLOCKED                 = 620,      /* stream-level flow control */
    XQC_EENCRYPT                        = 621,      /* encryption error */
    XQC_EDECRYPT                        = 622,      /* decryption error */
    XQC_ESTREAM_NFOUND                  = 623,      /* fail to find the corresponding stream */
    XQC_EWRITE_PKT                      = 624,      /* fail to create a package or write a package header */
    XQC_ECREATE_STREAM                  = 625,      /* fail to create stream */
    XQC_ESTREAM_RESET                   = 626,      /* stream has been reset */
    XQC_EDUP_FRAME                      = 627,      /* duplicate frames */
    XQC_EFINAL_SIZE                     = 628,      /* STREAM frame final size error */
    XQC_EVERSION                        = 629,      /* this version is not supported and requires negotiation */
    XQC_EWAITING                        = 630,      /* need to wait */
    XQC_EIGNORE_PKT                     = 631,      /* ignore unknown packet/frame, don't close connection */
    XQC_EGENERATE_CID                   = 632,      /* connection ID generation error */
    XQC_EANTI_AMPLIFICATION_LIMIT       = 633,      /* server reached the anti-amplification limit */
    XQC_ECONN_NO_AVAIL_CID              = 634,      /* no available connection ID */
    XQC_ECONN_CID_NOT_FOUND             = 635,      /* can't find cid in connection */
    XQC_EILLEGAL_FRAME                  = 636,      /* illegal stream & frame, close connection */
    XQC_ECID_STATE                      = 637,      /* abnormal connection ID status */
    XQC_EACTIVE_CID_LIMIT               = 638,      /* active cid exceed active_connection_id_limit */
    XQC_EALPN_NOT_SUPPORTED             = 639,      /* alpn is not supported by server */
    XQC_EALPN_NOT_REGISTERED            = 640,      /* alpn is not registered */

    XQC_EMP_NOT_SUPPORT_MP              = 650,      /* Multipath - don't support multipath */
    XQC_EMP_NO_AVAIL_PATH_ID            = 651,      /* Multipath - no available path id */
    XQC_EMP_CREATE_PATH                 = 652,      /* Multipath - create path error */
    XQC_EMP_INVALID_PATH_ID             = 653,      /* Multipath - invalid path id error */
    XQC_EMP_INVALID_FRAME               = 654,      /* Multipath - invalid frame */
    XQC_EMP_INVALID_QOE_SIGNAL          = 660,      /* Multipath - invalid qoe signal */

    XQC_E_MAX,
} xqc_transport_error_t;

#define TRANS_ERR_START 600
static const int TRANS_ERR_CNT = XQC_E_MAX - TRANS_ERR_START;


/* xquic TLS internal error codes: 7xx */
typedef enum {
    XQC_TLS_INVALID_ARGUMENT            = 700,
    XQC_TLS_UNKNOWN_PKT_TYPE            = 701,
    XQC_TLS_NOBUF                       = 702,
    XQC_TLS_PROTO                       = 703,
    XQC_TLS_INVALID_STATE               = 704,
    XQC_TLS_ACK_FRAME                   = 705,
    XQC_TLS_STREAM_ID_BLOCKED           = 706,
    XQC_TLS_STREAM_IN_USE               = 707,
    XQC_TLS_STREAM_DATA_BLOCKED         = 708,
    XQC_TLS_FLOW_CONTROL                = 709,
    XQC_TLS_STREAM_LIMIT                = 710,
    XQC_TLS_FINAL_OFFSET                = 711,
    XQC_TLS_CRYPTO                      = 712,
    XQC_TLS_PKT_NUM_EXHAUSTED           = 713,
    XQC_TLS_REQUIRED_TRANSPORT_PARAM    = 714,
    XQC_TLS_MALFORMED_TRANSPORT_PARAM   = 715,
    XQC_TLS_FRAME_ENCODING              = 716,
    XQC_TLS_DECRYPT                     = 717,
    XQC_TLS_STREAM_SHUT_WR              = 718,
    XQC_TLS_STREAM_NOT_FOUND            = 719,
    XQC_TLS_VERSION_NEGOTIATION         = 720,
    XQC_TLS_STREAM_STATE                = 721,
    XQC_TLS_NOKEY                       = 722,
    XQC_TLS_EARLY_DATA_REJECTED         = 723,
    XQC_TLS_RECV_VERSION_NEGOTIATION    = 724,
    XQC_TLS_CLOSING                     = 725,
    XQC_TLS_DRAINING                    = 726,
    XQC_TLS_TRANSPORT_PARAM             = 727,
    XQC_TLS_DISCARD_PKT                 = 728,
    XQC_TLS_FATAL                       = 729,
    XQC_TLS_NOMEM                       = 730,
    XQC_TLS_CALLBACK_FAILURE            = 731,
    XQC_TLS_INTERNAL                    = 732,
    XQC_TLS_DATA_REJECT                 = 733,
    XQC_TLS_CLIENT_INITIAL_ERROR        = 734,
    XQC_TLS_CLIENT_REINTIAL_ERROR       = 735,
    XQC_TLS_ENCRYPT_DATA_ERROR          = 736,
    XQC_TLS_DECRYPT_DATA_ERROR          = 737,
    XQC_TLS_CRYPTO_CTX_NEGOTIATED_ERROR = 738, 
    XQC_TLS_SET_TRANSPORT_PARAM_ERROR   = 739,
    XQC_TLS_SET_CIPHER_SUITES_ERROR     = 740,
    XQC_TLS_DERIVE_KEY_ERROR            = 741,
    XQC_TLS_DO_HANDSHAKE_ERROR          = 742,
    XQC_TLS_POST_HANDSHAKE_ERROR        = 743,
    XQC_TLS_UPDATE_KEY_ERROR            = 744,
    XQC_TLS_DECRYPT_WHEN_KU_ERROR       = 745,

    XQC_TLS_ERR_MAX,
} xqc_tls_error_t;

#define TLS_ERR_START 700
static const int TLS_ERR_CNT = XQC_TLS_ERR_MAX - TLS_ERR_START;


/* xquic HTTP3/QPACK application error codes: 8xx */
typedef enum {
    /* HTTP/3 error codes */
    XQC_H3_EMALLOC                      = 800,  /* malloc failure */
    XQC_H3_ECREATE_STREAM               = 801,  /* fail to create a stream */
    XQC_H3_ECREATE_REQUEST              = 802,  /* fail to create a request */
    XQC_H3_EGOAWAY_RECVD                = 803,  /* GOAWAY received, operation denied */
    XQC_H3_ECREATE_CONN                 = 804,  /* fail to create a connection */
    XQC_H3_EQPACK_ENCODE                = 805,  /* QPACK - encode error */
    XQC_H3_EQPACK_DECODE                = 806,  /* QPACK - decode error */
    XQC_H3_EPRI_TREE                    = 807,  /* priority tree error */
    XQC_H3_EPROC_CONTROL                = 808,  /* fail to process control stream */
    XQC_H3_EPROC_REQUEST                = 809,  /* fail to process request stream */
    XQC_H3_EPROC_PUSH                   = 810,  /* fail to process push stream */
    XQC_H3_EPARAM                       = 811,  /* wrong parameters */
    XQC_H3_BUFFER_EXCEED                = 812,  /* http send buffer exceeds the maximum */
    XQC_H3_DECODE_ERROR                 = 813,  /* decode error */
    XQC_H3_INVALID_STREAM               = 814,  /* invalid stream, such as multiple control streams, etc. */
    XQC_H3_CLOSE_CRITICAL_STREAM        = 815,  /* illegal closure of control stream and qpack encoder/decoder stream */
    XQC_H3_STATE_ERROR                  = 816,  /* http3 decoding status error */
    XQC_H3_CONTROL_ERROR                = 817,  /* control stream error, such as setting not send first or send twice */
    XQC_H3_CONTROL_DECODE_ERROR         = 818,  /* control stream decode error, such as encountering an unrecognized frame type */
    XQC_H3_CONTROL_DECODE_INVALID       = 819,  /* control stream decode invalid, eg. illegal remaining length */
    XQC_H3_PRIORITY_ERROR               = 820,  /* priority error */
    XQC_H3_INVALID_FRAME_TYPE           = 821,  /* invalid frame type */
    XQC_H3_UNSUPPORT_FRAME_TYPE         = 822,  /* unsupported frame type */
    XQC_H3_INVALID_HEADER               = 823,  /* invalid header field, such as the length exceeds the limit, etc. */
    XQC_H3_SETTING_ERROR                = 824,  /* SETTING error */
    XQC_H3_BLOCKED_STREAM_EXCEED        = 825,  /* blocked_stream exceed limit */
    XQC_H3_STREAM_RECV_ERROR            = 826,  /* call xqc_stream_recv error */

    XQC_H3_ERR_MAX,
} xqc_h3_error_t;

#define H3_ERR_START 800
static const int H3_ERR_CNT = XQC_H3_ERR_MAX - H3_ERR_START;


typedef enum {
    /* QPACK error codes */
    XQC_QPACK_DECODER_VARINT_ERROR      = 900,  /* qpack decode variable-length integer error */
    XQC_QPACK_ENCODER_ERROR             = 901,  /* qpack encode error */
    XQC_QPACK_DECODER_ERROR             = 902,  /* qpack decode error */
    XQC_QPACK_DYNAMIC_TABLE_ERROR       = 903,  /* qpack dynamic table error */
    XQC_QPACK_STATIC_TABLE_ERROR        = 904,  /* qpack static table error */
    XQC_QPACK_SET_DTABLE_CAP_ERROR      = 905,  /* set dynamic table capacity error */
    XQC_QPACK_SEND_ERROR                = 906,  /* send data error or control message error */
    XQC_QPACK_SAVE_HEADERS_ERROR        = 907,  /* failed to save name-value to header structure */
    XQC_QPACK_UNKNOWN_INSTRUCTION       = 908,  /* unknown encoder/decoder instruction */
    XQC_QPACK_INSTRUCTION_ERROR         = 909,  /* error instruction */
    XQC_QPACK_DYNAMIC_TABLE_REFERRED    = 910,  /* dynamic table entry is still referred */
    XQC_QPACK_DYNAMIC_TABLE_VOID_ENTRY  = 911,  /* entry inexists in dynamic table */
    XQC_QPACK_STATE_ERROR               = 912,  /* state is error */
    XQC_QPACK_DYNAMIC_TABLE_NOT_ENOUGH  = 913,  /* dynamic table not enough */
    XQC_QPACK_HUFFMAN_DEC_ERROR         = 914,  /* huffman decode error */
    XQC_QPACK_HUFFMAN_DEC_STATE_ERROR   = 915,  /* huffman decode state error */

    XQC_QPACK_ERR_MAX,
} xqc_qpack_error_t;

#define QPACK_ERR_START 900
static const int QPACK_ERR_CNT = XQC_QPACK_ERR_MAX - QPACK_ERR_START;


#endif /* _XQC_ERRNO_H_INCLUDED_ */
