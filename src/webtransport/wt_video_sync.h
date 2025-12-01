/**
 * @copyright Copyright (c) 2024, Alibaba Group Holding Limited
 * 视频传输DEMO server端
 * 基于xqc_webtransport实现
 * 大部分核心内容在wt_video_server.cpp中
 * wt_video_sync_common.cpp wt_video_sync.h wt_video_sync.cpp 只是为了快速配置video_sync_demo考虑，后续会重构
 */

#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <xquic/xquic_typedef.h>
#include <xquic/xquic.h>
#include <xquic/xqc_http3.h>
#include <functional>
#include <atomic>
#include <xquic/xqc_webtransport.h>


extern "C" {
#include "wt_video_sync_common.h"
#include "../../demo/xqc_hq.h"
#include "../src/common/utils/vint/xqc_discrete_int_parser.h"
    extern size_t
        xqc_put_varint_len(uint64_t n);
    extern uint8_t*
        xqc_put_varint(uint8_t* p, uint64_t n);
};

class WTRequest;
class WTServer;
class WTSession;

typedef std::function<void()> wt_stream_close_function_pt;
typedef std::function<int(WTServer*, xqc_wt_session_t*, xqc_wt_unistream_t*)> wt_request_handler_pt;

typedef int StreamErrorCode;
typedef int SessionErrorCode;

typedef xqc_h3_stream_t  wt_quic_stream_type;

#define WTFirstErrorCode 0x52e4a40fa8db
#define WTLastErrorCode  0x52e5ac983162

class WTErrors {
public:
    static int webtransportCodeToHTTPCode(StreamErrorCode streamErrorCode);
    static std::tuple<StreamErrorCode, std::optional<std::string>> httpCodeToWebtransportCode(int quicErrorCode);
    static bool isWebTransportError(int err);
};

typedef struct user_datagram_block_s {
    unsigned char *data;
    size_t         data_len;
    size_t         to_send_size;
    size_t         data_sent;
    size_t         data_recv;
    size_t         data_lost;
    size_t         dgram_lost;
} user_dgram_blk_t;



class WTStreamMap {
public:
    std::map<xqc_stream_id_t, wt_stream_close_function_pt> mFuncMap;
    std::mutex m_lock;

public:
    WTStreamMap() {}

    void AddStream(xqc_stream_id_t stream_id, wt_stream_close_function_pt func);
    void RemoveStream(xqc_stream_id_t stream_id);
    void CloseSession();
};

class WTSendStream {
public:
    WTSendStream(wt_quic_stream_type *stream,
    const std::vector<uint64_t> &streamHdr,
    wt_stream_close_function_pt func) {
        mStream = stream;
        mStreamHdr = streamHdr;
        onClose = func;
    }

    int maybeSendStreamHeader(); // not used
    int Write(const uint8_t *data, size_t len); // 1
    void cancelWrite(int errorCode); 
    void closeWithSession();
    int  Close();
    int  SetWriteDeadline(uint64_t time); // not used
    xqc_stream_id_t StreamID();

public:
    wt_quic_stream_type *mStream = nullptr;
    std::vector<uint64_t> mStreamHdr;
    wt_stream_close_function_pt onClose = nullptr;
    std::once_flag mOnceFlag;
};

class WTReceiveStream {
public:
    WTReceiveStream(wt_quic_stream_type *stream,
    wt_stream_close_function_pt func) {
        mStream = stream;
        onClose = func;
    }

    int Read(std::vector<uint8_t> &outputByte);
    void CancelRead(int errorCode);
    void closeWithSession();
    int SetReadDeadline(uint64_t time); // not used now , need to be considered
    xqc_stream_id_t StreamID();

public:
    wt_quic_stream_type *mStream = nullptr;
    wt_stream_close_function_pt onClose = nullptr;
};

class WTStream {
public:
    WTStream(wt_quic_stream_type* quicStr, const std::vector<uint64_t>& hdr, wt_stream_close_function_pt closeFunc);
    ~WTStream();

    void RegisterClose(bool isSendSide);
    void closeWithSession();
    int SetDeadline(uint64_t time); 
    xqc_stream_id_t StreamID();
    int  maybeConvertStreamError(int errorCode); // not used 
    bool isTimeoutError(int errorCode); // not defined
public:
    WTSendStream* mSendStream = nullptr;
    WTReceiveStream* mReceiveStream = nullptr;
    std::mutex m_lock;
    bool       mSendSideClosed = false;
    bool       mRecvSideClosed = false;
    wt_stream_close_function_pt onClose = nullptr;
};

template <class T>
class WTAcceptQueue {
public:
    std::vector<T*> mQueue;
    std::mutex m_lock;
};

class WTServer;

class WTConnection { // 仍然作为内部接口引入
public:
    xqc_h3_conn_t* xqc_conn = nullptr;
    uint64_t          mConnTraceId = 0;
    struct event* ev_timeout = nullptr;
    struct sockaddr_in6     peer_addr;
    socklen_t               peer_addrlen = 0;
    xqc_cid_t               cid;

    // dgram
    user_dgram_blk_t   *dgram_blk;
    size_t              dgram_mss;
    uint8_t             dgram_not_supported;

    WTServer* server = nullptr;

    wt_quic_stream_type* createStream() { // not used
        return nullptr;
    }
    wt_quic_stream_type* createUniStream(); // not used

};

class WTRequest {
public:
    WTConnection* connection = nullptr;
    xqc_h3_request_t* h3_request = nullptr;
    bool              is_header_recved = false;
    std::map<std::string, std::string> request_headers;
    std::string request_parameters;
    std::map<std::string, std::string> request_parameterMap;

    int                         header_sent = 0;
    int                         header_recvd = 0;
    size_t                      send_body_len = 0;
    size_t                      recv_body_len = 0;
    char* recv_buf = nullptr;

    void parseRequestParameter();

public:
    WTRequest();
    virtual ~WTRequest();
};

class WTSession {
public:
    uint64_t mSessionID = 0;
    WTConnection* mConn = nullptr;
    wt_quic_stream_type* mStream = nullptr;
    
    std::vector<uint64_t> mStreamHdr;
    std::vector<uint64_t> mUniStreamHdr;
    std::mutex mCloseLock;
    int        mCloseError = 0;
    std::map<int, wt_stream_close_function_pt> mStreamCtxs;

    std::mutex mAcceptQueueLock;
    std::vector<WTStream*> mAcceptQueue;
    std::mutex mReceiveQueueLock;
    std::vector<WTReceiveStream*> mReceiveStream;

    WTStreamMap* mStreams;

    std::once_flag mOnceFlag;

    std::function<void(WTReceiveStream*)> onAcceptUnistreamCallback = nullptr;
    std::function<int(xqc_h3_conn_t* h3_conn, xqc_h3_stream_t* stream, uint8_t* data, size_t size, int* ret)> onUnistreamDataRecvCallback = nullptr;

    bool containUnistream(wt_quic_stream_type* stream) {
        mReceiveQueueLock.lock();
        bool ret = false;
        for (auto rs : mReceiveStream )
        {
            if (rs->mStream == stream) {
                ret = true;
                break;
            }
        }
        mReceiveQueueLock.unlock();
        return ret;
    }

public:
    void registerOnAcceptUnistreamCallback(std::function<void(WTReceiveStream*)> callback) {
        onAcceptUnistreamCallback = callback;
    }

    void registerOnUnistreamDataRecvCallback(std::function<int(xqc_h3_conn_t* h3_conn, xqc_h3_stream_t* stream, uint8_t* data, size_t size, int* ret)> callback) {
        onUnistreamDataRecvCallback = callback;
    }

private:
    int mCapsuleParseState = 0; // 0: type, 1: len, 2: body
    unsigned char* mCapsuleBuffer;
    size_t mCapsuleBufferLen = 0;
    size_t mCapsuleBufferCap = 0;
    size_t mCurrentParseOffset = 0;
    uint64_t mCapsuleFrameType = 0;
    uint64_t mCapsuleLen = 0;
    size_t mCapsuleBeginLenOffset = 0;
    xqc_discrete_int_pctx_t     mPctx;

    uint8_t *mBufferNeedToSend = nullptr;
    uint64_t mBufferCurrentSendOffset = 0;
    uint64_t mBufferSendCapacity = 0;
    uint64_t mBufferSendLength = 0;

    int _writeQuicStreamData();

public:
    WTSession(uint64_t sessionID, WTConnection* qconn, wt_quic_stream_type* requestStr);

    void OnQuicStreamCanRecv(wt_quic_stream_type*quicStream);


    WTStream* addStream(wt_quic_stream_type*qstr, bool addStreamHeader);
    WTReceiveStream* addReceiveStream(wt_quic_stream_type* qstr);
    WTSendStream* addSendStream(wt_quic_stream_type* qstr);
    void addIncomingStream(wt_quic_stream_type* qstr);
    void addIncomingUniStream(wt_quic_stream_type* qstr);
    //void acceptStream();
    //void acceptUniStream();
    WTStream* openStream(int *errorCode);
    //int addStreamCtxCancel();
    //void openStreamSync();
    WTSendStream* openUniStream(int* errorCode);
    //void openUniStreamSync();
    int  closeWithError(int sessionError, const std::string& msg);
    int  sendDatagram(const std::vector<uint8_t>& data);


protected:
    std::tuple<bool, int>  _closeWithError(int sessionError, const std::string& msg);

    void handleConn();
    int  parseNextCapsule();

    void OnAcceptQueueAdded() {

    }
    void OnReceiveQueueAdded() {
        /*if (onAcceptUnistreamCallback)
        {
            onAcceptUnistreamCallback();
        }*/
    }
};



class WTServer {
public:
    struct NetConfig {
        struct sockaddr mAddr;
        int             mAddrLen;
        char            ip[64];
        short           port;
        int             ipv6;
        CC_TYPE         cc;
        int             pacing;
        int             conn_timeout;
    };
    enum WTSettingsID {
        /* h3 settings */
        WT_SETTINGS_ENABLE_WEBTRANSPORT = 0x2b603742,
        WT_SETTINGS_DATAGRAM = 0x33,
        WT_SETTINGS_EXTENDEDCONNECT = 0x8,
    };

    struct QuicConfig {
        /* cipher config */
        char cipher_suit[CIPHER_SUIT_LEN];
        char groups[TLS_GROUPS_LEN];

        int  stk_len;                           /* session ticket len */
        char stk[2048];   /* session ticket buf */
        /* retry */
        int  retry_on;

        /* dummy mode */
        int  dummy_mode;

        /* multipath */
        int  multipath;

        /* multipath version */
        int  multipath_version;
        /* support interop test */
        int is_interop_mode;

        /* ack on any path */
        int  mp_ack_on_any_path;

        /* scheduler */
        char mp_sched[32];

        uint32_t reinjection;

        uint64_t keyupdate_pkt_threshold;
        uint64_t least_available_cid_count;

        size_t max_pkt_sz;
    };

    struct EnvConfig {
        std::string mLogPath;
        int         mLogLevel;
        std::string mSourceFileDir;
        std::string mPrivKeyPath;
        std::string mCertPemPath;
        int         mKeyOutputFlag;
        std::string mKeyOutPath;
    };

    NetConfig mNetCfg;
    QuicConfig mQuicCfg;
    EnvConfig mEnvCfg;

    struct event_base* eb;

    xqc_engine_t* engine;
    struct event* ev_engine;

    /* ipv4 server */
    int                 fd = 0;
    struct sockaddr_in  local_addr;
    socklen_t           local_addrlen;
    struct event* ev_socket;

    /* ipv6 server */
    int                 fd6;
    struct sockaddr_in6 local_addr6;
    socklen_t           local_addrlen6;
    struct event* ev_socket6;

    /* used to remember fd type to send stateless reset */
    int                 current_fd = 0;

    int                 log_fd = 0;
    int                 keylog_fd = 0;
    
    void writeKeyLogFile(const xqc_cid_t* scid, const char* line);

    void registerRequestHandler(const std::string& requestPath, wt_request_handler_pt handler);

    void onConnectionCreate(xqc_h3_conn_t* h3_conn, const xqc_cid_t* cid);
    void onConnectionClose(xqc_h3_conn_t* h3_conn, const xqc_cid_t* cid, void* conn_user_data);
    virtual void onStreamCanWrite(xqc_stream_t* stream, void* user_data) {

    }
    int  onWebtransportRequest(WTRequest* request);
    bool canHandleWebTransportRequest(const std::string &path);
    void initArgs(int argc, char **argv);
public:
    xqc_engine_t* h3_engine;
    uint64_t      ReorderingTimeout;
    wt_stream_close_function_pt  mCtxCancel;
    int           mInitErr = 0;

protected:
    // std::map<xqc_h3_conn_t*, WTConnection*> m_h3_conn_map; // not used
    std::map<std::string, wt_request_handler_pt> m_request_handle_map;
    std::atomic_uint64_t m_con_id_gen = 0;

public:

    wt_request_handler_pt getRequestHandler(const std::string& path) {
        auto it = m_request_handle_map.find(path);
        if (it != m_request_handle_map.end()) {
            return it->second;
        }
        return nullptr;
    }
    WTServer() {
    }
    int initialize();
    
    void registerPath(const std::string &path);

protected:

    uint64_t timeout();
    int init();
    int close();
    
protected:
    void handleH3Request();

public:
    virtual bool checkOrigin(xqc_h3_request_t* request) {
        return true;
    }
    virtual void onHandlePath(const std::string& path) {

    }
};

void startWebtransportServer(int argc, char* argv[], WTServer *server,xqc_webtransport_callbacks_t *wt_cbs);
void stopWebtransportServer();