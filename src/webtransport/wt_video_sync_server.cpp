/**
 * @copyright Copyright (c) 2024, Alibaba Group Holding Limited
* !!!!请勿code review本代码！！！
 * !!!!请勿code review本代码！！！
 * !!!!请勿code review本代码！！！
 * 本代码仅仅为了视频传输demo中的WTServer依赖而存在
 * 后续会删除本文件，目前仅仅是为了测试视频传输DEMO，后续会重构视频传输DEMO中的WTServer
 * 视频传输DEMO server端
 * 基于xqc_webtransport实现
 * 大部分核心内容在wt_video_server.cpp中
 * wt_video_sync_common.cpp wt_video_sync.h wt_video_sync.cpp 只是为了快速配置engine考虑，后续会重构
 */

#define _GNU_SOURCE
#define _ITERATOR_DEBUG_LEVEL 0

#include <ctype.h>
#include <errno.h>
#include "../tests/platform.h"
#include <event2/event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>
// #include <io.h>

#include "wt_video_sync.h"
#include "xqc_webtransport_defs.h"
#include <assert.h>
#include <cstring>
#include <deque>
#include <map>
#include <semaphore>
#include <src/webtransport/xqc_webtransport_session.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
#include <xquic/xqc_webtransport.h>
// #include <src/webtransport/xqc_webtransport_conn.h>

extern "C"
{
#include "../tests/getopt.h"
    extern xqc_int_t xqc_h3_stream_write_customdataframe_to_buffer(xqc_h3_stream_t *h3s, unsigned char *data,
                                                                   uint64_t data_size, uint64_t *vintValueList,
                                                                   size_t valueSize, uint8_t fin);
    extern void xqc_h3_stream_destroy(xqc_h3_stream_t *h3s);
    extern void xqc_destroy_stream(xqc_stream_t *stream);
};
extern "C"
{
};

#ifndef XQC_SYS_WINDOWS
#else
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "event.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")

#endif

#pragma warning(push)
#pragma warning(disable : 2440)
#pragma warning(disable : 2397)

extern "C"
{
#include "../../demo/xqc_hq.h"
#include "wt_video_sync_common.h"
};

#define USE_WT_VIDEO_DEMO 0

#if USE_WT_VIDEO_DEMO

#endif

struct DemoBuffer
{
    uint8_t *data = nullptr;
    size_t capacity = 0;
    size_t len = 0;
    size_t offset = 0;
    DemoBuffer(size_t l)
    {
        capacity = l;
        len = l;
        data = (uint8_t *)malloc(l);
        memset(data, 0, sizeof(data));
    }
    DemoBuffer(void *d, size_t l)
    {
        data = (uint8_t *)d;
        len = l;
        capacity = l;
    }
    ~DemoBuffer()
    {
        free(data);
    }
};

std::binary_semaphore smphSignalMainToThread{0};
std::mutex mDataLock;
class Server : public WTServer
{
  public:
    std::vector<DemoBuffer *> Buffers;

  public:
    Server() : WTServer()
    {
        registerRequestHandler("/publish", [&](WTServer *s, xqc_wt_session_t *session, xqc_wt_unistream_t *unistream) {
            // add request handler

            return 0;
        });
        registerRequestHandler("/subscribe",
                               [&](WTServer *s, xqc_wt_session_t *session, xqc_wt_unistream_t *unistream) {
                                   // add request handler
                                   return 0;
                               });
    }
};

auto g_server = new Server;

std::string path_cut(std::string s)
{
    std::string ans = "";
    int idx = 0;
    while (idx < s.size() && s[idx] != '?')
    {
        ans += s[idx];
        idx++;
    }
    return ans;
}

using URL_PATH = std::string;
std::map<URL_PATH, xqc_wt_session_t *> path_session_map;
std::unordered_map<xqc_wt_session_t *, std::string> session_path_map;
std::thread *RecvThread;
std::vector<DemoBuffer *> pendingBufferList;
int last_buf_len = 0;

void test_write_thread(xqc_wt_session_t *session, xqc_wt_unistream_t *stream, void *data, size_t data_len)
{
    if (pendingBufferList.empty())
    {
        return;
    }

    auto Buffer = *pendingBufferList.begin();
    pendingBufferList.erase(pendingBufferList.begin());

    last_buf_len = Buffer->len;

    xqc_h3_stream_t *h3_stream = session->h3_stream;
    xqc_wt_unistream_t *unistream = xqc_wt_create_unistream(XQC_WT_STREAM_TYPE_SEND, session, NULL, h3_stream);

    if (unistream != NULL)
        xqc_wt_unistream_send(unistream, Buffer->data, Buffer->len, 1);

    xqc_wt_unistream_close(unistream);
}

int wt_create_session_notify(xqc_webtransport_session_t *session, xqc_http_headers_t *headers, const xqc_cid_t *cid,
                             void *h3c_user_data)
{
    std::string path = (char *)headers->headers[3].value.iov_base;
    path = path_cut(path);
    session_path_map[session] = path;
    path_session_map[path] = session;

    auto handler = g_server->getRequestHandler(path);
    if (handler == nullptr)
    {
        return 0;
    }
    else
    {
        handler(g_server, session, nullptr);
    }
    if (path == "/publish")
    {
        // No operation temporarily
    }
    else if (path == "/subscribe")
    {
        pendingBufferList.clear();
    }
}

// /publish?stream_id=1
// /subscribe?stream_id=1

int Rest_frame_len = -1; //默认值是-1 表示未解析，解析完成后同样赋值为-1
int parse_offset = 0; // 已解析偏移量
DemoBuffer *buffer = new DemoBuffer(1 << 25);
bool check_packet_header(uint8_t *data)
{
    uint8_t check_xor = data[0], check_sum = data[1];

    uint8_t sum_xor = 0;
    uint16_t sum_add = 0;
    for (int i = 2; i < 2 + 4; i++)
        sum_xor ^= data[i];
    for (int i = 2; i < 2 + 4; i++)
        sum_add += data[i] + 1, sum_add %= 256;

    if (check_xor != sum_xor)
    {
        return false;
    }
    return true;
}

DemoBuffer *buffer_copy(DemoBuffer *buf)
{
    int buf_len = buf->len;
    auto new_buf = new DemoBuffer(buf_len);
    for (int i = 0; i < buf_len; i++)
    {
        new_buf->data[i] = buf->data[i];
    }

    return new_buf;
}

void process_data(void *origin_data, int data_len)
{
    uint8_t *data = (uint8_t *)origin_data;
    if (Rest_frame_len == -1) // 未解析，在这里解析
    {
        if (!check_packet_header(data))
        {
            // xqc_log
            return;
        }

        uint32_t frame_len =
            ((uint32_t)data[2] << 0) | ((uint32_t)data[3] << 8) | ((uint32_t)data[4] << 16) | ((uint32_t)data[5] << 24);
        assert(frame_len <= (1 << 16));

        Rest_frame_len = frame_len + 6;

        if (buffer->capacity < Rest_frame_len) // 重新扩容
        {
            buffer->~DemoBuffer();
            buffer = new DemoBuffer(Rest_frame_len);
        }
        buffer->len = Rest_frame_len;
    }

    int read_till = data_len > Rest_frame_len ? Rest_frame_len : data_len;
    DemoBuffer *buf = buffer;
    int tmplen = parse_offset;
    memcpy(buf->data + tmplen, data, read_till);
    parse_offset += read_till;
    Rest_frame_len -= read_till;

    if (Rest_frame_len == 0)
    {
        auto tmp_buf = buffer_copy(buf);
        pendingBufferList.push_back(tmp_buf);

        Rest_frame_len = -1;
        parse_offset = data_len - read_till;
        buf = new DemoBuffer(1 << 25);

        if (parse_offset > 0)
        {
            auto buf = new DemoBuffer(1 << 25);
            memcpy(buf->data, data + read_till, parse_offset);
        }
    }
}
void test_recv_thread(void *data, int data_len)
{
    process_data(data, data_len);
}
xqc_int_t wt_default_unistream_read_notify(xqc_wt_unistream_t *stream, xqc_wt_session_t *session, void *data,
                                           size_t data_len, void *strm_user_data)
{
    // auto id = xqc_wt_unistream_get_sessionID(stream);

    std::string path = session_path_map[session];

    if (path == "/publish")
    {
        test_recv_thread(data, data_len);
        if (path_session_map.count("/subscribe"))
        {
            auto subscribe_session = path_session_map["/subscribe"];

            test_write_thread(subscribe_session, stream, data, data_len);
        }
    }
}


int main(int argc, char *argv[])
{

    xqc_webtransport_callbacks_t wt_cbs = {.dgram_cbs = {},
                                           .session_cbs =
                                               {
                                                   .webtransport_session_create_notify = wt_create_session_notify,
                                               },
                                           .stream_cbs = {
                                               .wt_unistream_read_notify = wt_default_unistream_read_notify,
                                           }};
    startWebtransportServer(argc, argv, g_server, &wt_cbs);
    return 0;
}
