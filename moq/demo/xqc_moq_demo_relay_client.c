#define _GNU_SOURCE
#include <errno.h>
#include <event2/event.h>
#include <fcntl.h>
#include <inttypes.h>
#include <memory.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <xquic/xqc_http3.h>
#include <xquic/xquic.h>
#include <xquic/xquic_typedef.h>

#include "tests/platform.h"
#include "xqc_moq_demo_comm.h"

#ifndef XQC_SYS_WINDOWS
#include <getopt.h>
#include <sys/wait.h>
#include <unistd.h>
#else
#include "getopt.h"
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "Bcrypt.lib")
#pragma comment(lib, "crypt32")
#endif

#include "moq/moq_transport/xqc_moq_message.h"
#include <moq/xqc_moq.h>

#define DEBUG printf ("%s:%d (%s)\n", __FILE__, __LINE__, __FUNCTION__);

#define TEST_ADDR "127.0.0.1"
#define TEST_PORT 2445 // 连接到relay端口

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100 * 1024 * 1024)
#define XQC_MAX_LOG_LEN 2048
#define XQC_TLS_SPECIAL_GROUPS "X25519:P-256:P-384:P-521"

extern long xqc_random (void);
extern xqc_usec_t xqc_now ();

xqc_app_ctx_t ctx;
struct event_base *eb;

int g_ipv6 = 0;
int g_test_duration = 30; // 测试持续时间（秒）
xqc_moq_role_t g_role = XQC_MOQ_PUBSUB;

// 测试状态跟踪 - 纯订阅者模式
typedef struct
{
  int subscribe_sent;
  int subscribe_ok_received;
  int announce_received; // 接收到relay转发的announce
  int test_completed;
  struct event *test_timer;
} test_state_t;

test_state_t g_test_state = { 0 };

char *
xqc_now_spec ()
{
  static char now_spec[128];
  time_t now = time (NULL);
  struct tm *tm_now = localtime (&now);
  snprintf (now_spec, sizeof (now_spec), "%04d-%02d-%02d %02d:%02d:%02d",
            tm_now->tm_year + 1900, tm_now->tm_mon + 1, tm_now->tm_mday,
            tm_now->tm_hour, tm_now->tm_min, tm_now->tm_sec);
  return now_spec;
}

void
save_session_cb (const char *data, size_t data_len, void *user_data)
{
  FILE *fp = fopen ("test_session", "wb");
  if (!fp)
    {
      printf ("Failed to open test_session file\n");
      return;
    }

  int write_size = fwrite (data, 1, data_len, fp);
  if (data_len != write_size)
    {
      printf ("save_session_cb error\n");
    }
  fclose (fp);
}

void
save_tp_cb (const char *data, size_t data_len, void *user_data)
{
  FILE *fp = fopen ("tp_localhost", "wb");
  if (!fp)
    {
      printf ("Failed to open tp_localhost file\n");
      return;
    }

  int write_size = fwrite (data, 1, data_len, fp);
  if (data_len != write_size)
    {
      printf ("save_tp_cb error\n");
    }
  fclose (fp);
}

void
xqc_client_save_token (const unsigned char *token, unsigned token_len,
                       void *user_data)
{
  int fd = open ("./xqc_token", O_TRUNC | O_CREAT | O_WRONLY, 0666);
  if (fd < 0)
    {
      printf ("save token error %s\n", strerror (get_sys_errno ()));
      return;
    }

  ssize_t n = write (fd, token, token_len);
  if (n < token_len)
    {
      printf ("save token error %s\n", strerror (get_sys_errno ()));
    }
  close (fd);
}

void
xqc_client_socket_write_handler (user_conn_t *user_conn)
{
  DEBUG
  xqc_conn_continue_send (ctx.engine, &user_conn->cid);
}

void
xqc_client_socket_read_handler (user_conn_t *user_conn, int fd)
{
  xqc_int_t ret;
  ssize_t recv_size = 0;
  ssize_t recv_sum = 0;
  unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];

  do
    {
      recv_size = recvfrom (fd, packet_buf, sizeof (packet_buf), 0,
                            user_conn->peer_addr, &user_conn->peer_addrlen);
      if (recv_size < 0 && get_sys_errno () == EAGAIN)
        {
          break;
        }

      if (recv_size < 0)
        {
          printf ("recvfrom: recvmsg = %zd(%s)\n", recv_size,
                  strerror (get_sys_errno ()));
          break;
        }

      if (recv_size == 0)
        {
          break;
        }

      recv_sum += recv_size;

      if (user_conn->get_local_addr == 0)
        {
          user_conn->get_local_addr = 1;
          socklen_t tmp = sizeof (struct sockaddr_in6);
          int ret = getsockname (
              user_conn->fd, (struct sockaddr *)user_conn->local_addr, &tmp);
          if (ret < 0)
            {
              printf ("getsockname error, errno: %d\n", get_sys_errno ());
              break;
            }
          user_conn->local_addrlen = tmp;
        }

      uint64_t recv_time = xqc_now ();

      ret = xqc_engine_packet_process (
          ctx.engine, packet_buf, recv_size, user_conn->local_addr,
          user_conn->local_addrlen, user_conn->peer_addr,
          user_conn->peer_addrlen, (xqc_usec_t)recv_time, user_conn);
      if (ret != XQC_OK)
        {
          printf ("xqc_client_read_handler: packet process err, ret: %d\n",
                  ret);
          return;
        }
    }
  while (recv_size > 0);

  xqc_engine_finish_recv (ctx.engine);
}

static void
xqc_client_socket_event_callback (int fd, short what, void *arg)
{
  user_conn_t *user_conn = (user_conn_t *)arg;

  if (what & EV_WRITE)
    {
      xqc_client_socket_write_handler (user_conn);
    }
  else if (what & EV_READ)
    {
      xqc_client_socket_read_handler (user_conn, fd);
    }
  else
    {
      printf ("event callback: what=%d\n", what);
      exit (1);
    }
}

void
xqc_convert_addr_text_to_sockaddr (int type, const char *addr_text,
                                   unsigned int port, struct sockaddr **saddr,
                                   socklen_t *saddr_len)
{
  if (type == AF_INET6)
    {
      *saddr = calloc (1, sizeof (struct sockaddr_in6));
      memset (*saddr, 0, sizeof (struct sockaddr_in6));
      struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)(*saddr);
      inet_pton (type, addr_text, &(addr_v6->sin6_addr.s6_addr));
      addr_v6->sin6_family = type;
      addr_v6->sin6_port = htons (port);
      *saddr_len = sizeof (struct sockaddr_in6);
    }
  else
    {
      *saddr = calloc (1, sizeof (struct sockaddr_in));
      memset (*saddr, 0, sizeof (struct sockaddr_in));
      struct sockaddr_in *addr_v4 = (struct sockaddr_in *)(*saddr);
      inet_pton (type, addr_text, &(addr_v4->sin_addr.s_addr));
      addr_v4->sin_family = type;
      addr_v4->sin_port = htons (port);
      *saddr_len = sizeof (struct sockaddr_in);
    }
}

void
xqc_client_init_addr (user_conn_t *user_conn, const char *server_addr,
                      int server_port)
{
  int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
  xqc_convert_addr_text_to_sockaddr (ip_type, server_addr, server_port,
                                     &user_conn->peer_addr,
                                     &user_conn->peer_addrlen);

  if (ip_type == AF_INET6)
    {
      user_conn->local_addr
          = (struct sockaddr *)calloc (1, sizeof (struct sockaddr_in6));
      memset (user_conn->local_addr, 0, sizeof (struct sockaddr_in6));
      user_conn->local_addrlen = sizeof (struct sockaddr_in6);
    }
  else
    {
      user_conn->local_addr
          = (struct sockaddr *)calloc (1, sizeof (struct sockaddr_in));
      memset (user_conn->local_addr, 0, sizeof (struct sockaddr_in));
      user_conn->local_addrlen = sizeof (struct sockaddr_in);
    }
}

static int
xqc_client_create_socket (int type, const struct sockaddr *saddr,
                          socklen_t saddr_len)
{
  int size;
  int fd = -1;
  int flags = 1;

  fd = socket (type, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      printf ("create socket failed, errno: %d\n", get_sys_errno ());
      return -1;
    }

#ifdef XQC_SYS_WINDOWS
  if (ioctlsocket (fd, FIONBIO, &flags) == SOCKET_ERROR)
    {
      goto err;
    }
#else
  if (fcntl (fd, F_SETFL, O_NONBLOCK) == -1)
    {
      printf ("set socket nonblock failed, errno: %d\n", get_sys_errno ());
      goto err;
    }
#endif

  size = 1 * 1024 * 1024;
  if (setsockopt (fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof (int)) < 0)
    {
      printf ("setsockopt failed, errno: %d\n", get_sys_errno ());
      goto err;
    }

  if (setsockopt (fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof (int)) < 0)
    {
      printf ("setsockopt failed, errno: %d\n", get_sys_errno ());
      goto err;
    }

#if !defined(__APPLE__)
  int val = IP_PMTUDISC_DO;
  setsockopt (fd, IPPROTO_IP, IP_MTU_DISCOVER, &val, sizeof (val));
#endif

#if !defined(__APPLE__)
  if (connect (fd, (struct sockaddr *)saddr, saddr_len) < 0)
    {
      printf ("connect socket failed, errno: %d\n", get_sys_errno ());
      goto err;
    }
#endif

  return fd;

err:
  close (fd);
  return -1;
}

int
xqc_client_create_conn_socket (user_conn_t *user_conn)
{
  int ip_type = (g_ipv6 ? AF_INET6 : AF_INET);
  user_conn->fd = xqc_client_create_socket (ip_type, user_conn->peer_addr,
                                            user_conn->peer_addrlen);
  if (user_conn->fd < 0)
    {
      printf ("xqc_create_socket error\n");
      return -1;
    }

  user_conn->ev_socket
      = event_new (eb, user_conn->fd, EV_READ | EV_PERSIST,
                   xqc_client_socket_event_callback, user_conn);
  event_add (user_conn->ev_socket, NULL);

  return 0;
}

// 测试完成回调
void
test_completion_callback (int fd, short what, void *arg)
{
  printf ("\n=== 测试结果总结 ===\n");
  printf ("测试持续时间: %d秒\n", g_test_duration);
  printf ("\n测试步骤完成情况:\n");
  printf ("1. Subscribe Namespace发送: %s\n",
          g_test_state.subscribe_sent ? "✓" : "✗");
  printf ("2. Subscribe Namespace OK接收: %s\n",
          g_test_state.subscribe_ok_received ? "✓" : "✗");
  printf ("3. Relay转发Announce接收: %s\n",
          g_test_state.announce_received ? "✓" : "✗");

  int success_count = g_test_state.subscribe_sent
                      + g_test_state.subscribe_ok_received
                      + g_test_state.announce_received;
  printf ("\n总体成功率: %d/3\n", success_count);

  if (success_count == 3)
    {
      printf (
          "🎉 测试完全成功！Relay的subscribe_namespace转发功能正常工作。\n");
    }
  else
    {
      printf ("⚠️  测试部分失败，请检查relay实现。\n");
    }

  printf ("\n测试逻辑说明:\n");
  printf ("1. 纯订阅者客户端发送subscribe_namespace订阅'moq'前缀\n");
  printf ("2. Relay转发subscribe_namespace到上游服务器\n");
  printf ("3. 上游服务器发布匹配的track并announce\n");
  printf ("4. Relay转发announce给订阅的客户端\n");
  printf ("5. 客户端收到转发的announce消息，测试成功\n");

  g_test_state.test_completed = 1;
  event_base_loopbreak (eb);
}

// 纯订阅者客户端 - 不发送announce消息
// 只等待接收来自relay转发的announce消息

// Session setup回调 - 按正确的测试逻辑执行
void
on_session_setup (xqc_moq_user_session_t *user_session, char *extdata)
{
  DEBUG;
  printf ("=== Session Setup完成 ===\n");

  if (extdata)
    {
      printf ("extdata: %s\n", extdata);
    }

  xqc_moq_session_t *session = user_session->session;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;

  user_conn->moq_session = session;
  user_conn->video_subscribe_id = -1;
  user_conn->audio_subscribe_id = -1;
  user_conn->countdown = 100;

  // 创建track用于测试
  xqc_moq_selection_params_t video_params;
  memset (&video_params, 0, sizeof (xqc_moq_selection_params_t));
  video_params.codec = "av01";
  video_params.mime_type = "video/mp4";
  video_params.width = 720;
  video_params.height = 720;
  video_params.bitrate = 1000000;
  video_params.framerate = 30;

  xqc_moq_track_t *video_track = xqc_moq_track_create (
      session, "test-namespace", "test-track", XQC_MOQ_TRACK_VIDEO,
      &video_params, XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_SUB);
  if (video_track == NULL)
    {
      printf ("create video track error\n");
      return;
    }
  user_conn->video_track = video_track;

  printf ("\n=== 纯订阅者测试流程开始 ===\n");
  printf ("步骤1: 客户端作为纯订阅者，发送subscribe_namespace订阅'moq'前缀\n");

  // 第一步：发送subscribe_announces消息（作为订阅者）
  xqc_moq_subscribe_namespace_msg_t subscribe_namespace_msg;
  memset (&subscribe_namespace_msg, 0, sizeof (subscribe_namespace_msg));
  subscribe_namespace_msg.request_id = 1; // 设置请求ID
  subscribe_namespace_msg.track_namespace_prefix
      = calloc (1, sizeof (xqc_moq_msg_track_namespace_t));
  subscribe_namespace_msg.track_namespace_prefix->track_namespace_num = 1;
  subscribe_namespace_msg.track_namespace_prefix->track_namespace_len
      = calloc (1, sizeof (uint64_t));
  subscribe_namespace_msg.track_namespace_prefix->track_namespace_len[0]
      = strlen ("moq");
  subscribe_namespace_msg.track_namespace_prefix->track_namespace
      = calloc (1, sizeof (char *));
  subscribe_namespace_msg.track_namespace_prefix->track_namespace[0]
      = calloc (1, strlen ("moq") + 1);
  strcpy (subscribe_namespace_msg.track_namespace_prefix->track_namespace[0],
          "moq");
  subscribe_namespace_msg.params_num = 0;
  subscribe_namespace_msg.params = NULL;

  xqc_int_t ret
      = xqc_moq_write_subscribe_namespace (session, &subscribe_namespace_msg);
  if (ret < 0)
    {
      printf ("xqc_moq_write_subscribe_namespace error: %d\n", ret);
    }
  else
    {
      printf ("✓ Subscribe Namespace消息发送成功: namespace_prefix=moq\n");
      g_test_state.subscribe_sent = 1;
    }

  // 清理内存
  free (subscribe_namespace_msg.track_namespace_prefix->track_namespace[0]);
  free (subscribe_namespace_msg.track_namespace_prefix->track_namespace);
  free (subscribe_namespace_msg.track_namespace_prefix->track_namespace_len);
  free (subscribe_namespace_msg.track_namespace_prefix);

  printf ("步骤2: 等待relay转发来自上游服务器的announce消息\n");
  printf ("✓ 客户端现在只作为纯订阅者，不会发送任何announce消息\n");

  // 设置测试完成定时器
  if (!g_test_state.test_timer)
    {
      g_test_state.test_timer
          = evtimer_new (eb, test_completion_callback, NULL);
      struct timeval test_tv = { g_test_duration, 0 };
      event_add (g_test_state.test_timer, &test_tv);
      printf ("测试将在%d秒后结束\n", g_test_duration);
    }

  printf ("=== 等待测试流程继续... ===\n");
}

// Announce回调 - 接收relay转发的announce消息
void
on_announce (xqc_moq_user_session_t *user_session,
             xqc_moq_announce_msg_t *announce)
{
  DEBUG;
  printf ("\n=== 收到Relay转发的Announce消息 ===\n");
  printf ("步骤3: 客户端收到relay转发的announce消息\n");

  if (announce->track_namespace && announce->track_namespace->track_namespace
      && announce->track_namespace->track_namespace[0])
    {
      printf ("✓ 转发的Track Namespace: %s\n",
              announce->track_namespace->track_namespace[0]);

      // 检查是否是我们期望的namespace
      if (strcmp (announce->track_namespace->track_namespace[0], "moq-date")
          == 0)
        {
          printf ("✓ 成功接收到匹配的track namespace: moq-date\n");
          printf ("✓ Relay的subscribe_namespace转发功能正常工作！\n");
          g_test_state.announce_received = 1; // 标记为成功接收announce
        }
      else
        {
          printf ("✗ 接收到的namespace不匹配，期望: moq-date，实际: %s\n",
                  announce->track_namespace->track_namespace[0]);
        }
    }
  else
    {
      printf ("✗ 接收到的announce消息格式有误\n");
    }

  printf ("=== Subscribe Announces转发测试完成 ===\n\n");
}

// 纯订阅者模式 - 不需要announce_ok回调

// Subscribe Announces OK回调
void
on_subscribe_namespace_ok (
    xqc_moq_user_session_t *user_session,
    xqc_moq_subscribe_namespace_ok_msg_t *subscribe_namespace_ok)
{
  DEBUG;
  printf ("=== 收到Subscribe Namespace OK消息 ===\n");
  printf ("✓ Relay确认了我们的subscribe_namespace订阅\n");
  printf ("✓ Request ID: %" PRIu64 "\n", subscribe_namespace_ok->request_id);
  printf ("现在等待relay转发匹配的announce消息...\n");
  g_test_state.subscribe_ok_received = 1;
}

// Subscribe OK回调
void
on_subscribe_ok (xqc_moq_user_session_t *user_session,
                 xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
  DEBUG;
  printf ("=== 收到Subscribe OK消息 ===\n");
  printf ("✓ Subscribe ID: %" PRIu64 "\n", subscribe_ok->subscribe_id);
  printf ("  Expire MS: %" PRIu64 "\n", subscribe_ok->expire_ms);
  printf ("  Content Exist: %d\n", subscribe_ok->content_exist);
  printf ("  Largest Group ID: %" PRIu64 "\n", subscribe_ok->largest_group_id);
  printf ("  Largest Object ID: %" PRIu64 "\n",
          subscribe_ok->largest_object_id);
  g_test_state.subscribe_ok_received = 1;
}

// Subscribe Error回调
void
on_subscribe_error (xqc_moq_user_session_t *user_session,
                    xqc_moq_subscribe_error_msg_t *subscribe_error)
{
  DEBUG;
  printf ("=== 收到Subscribe Error消息 ===\n");
  printf ("✗ Subscribe ID: %" PRIu64 "\n", subscribe_error->subscribe_id);
  printf ("  Error Code: %" PRIu64 "\n", subscribe_error->error_code);
  printf ("  Reason: %s\n", subscribe_error->reason_phrase
                                ? subscribe_error->reason_phrase
                                : "No reason");
  printf ("  Track Alias: %" PRIu64 "\n", subscribe_error->track_alias);
}

// 其他回调函数
void
on_datachannel (xqc_moq_user_session_t *user_session)
{
  DEBUG;
  printf ("=== Datachannel Ready ===\n");
}

void
on_datachannel_msg (struct xqc_moq_user_session_s *user_session, uint8_t *msg,
                    size_t msg_len)
{
  DEBUG;
  if (msg && msg_len > 0)
    {
      printf ("Received datachannel msg: %.*s\n", (int)msg_len, (char *)msg);
    }
}

void
on_object_datagram (xqc_moq_user_session_t *user_session,
                    xqc_moq_object_datagram_t *object_datagram)
{
  DEBUG;
  printf ("Received object datagram: %.*s\n",
          (int)strlen ((char *)object_datagram->payload),
          (char *)object_datagram->payload);
}

// 连接创建回调
int
xqc_client_conn_create_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                               void *user_data, void *conn_proto_data)
{
  DEBUG;
  printf ("=== 连接创建成功 ===\n");

  xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;

  xqc_moq_session_callbacks_t callbacks = {
    .on_session_setup = on_session_setup,
    .on_datachannel = on_datachannel,
    .on_datachannel_msg = on_datachannel_msg,
    .on_subscribe_ok = on_subscribe_ok,
    .on_subscribe_error = on_subscribe_error,
    .on_datagram = on_object_datagram,
    .on_announce = on_announce,
    .on_subscribe_namespace_ok = on_subscribe_namespace_ok,
  };

  xqc_moq_session_t *session = xqc_moq_session_create (
      conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14,
      g_role, callbacks, "test-client");
  if (session == NULL)
    {
      printf ("create session error\n");
      return -1;
    }

  xqc_moq_configure_bitrate (session, 1000000, 8000000, 1000000);
  return 0;
}

// 连接关闭回调
int
xqc_client_conn_close_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                              void *user_data, void *conn_proto_data)
{
  DEBUG;
  printf ("=== 连接关闭 ===\n");

  if (user_data)
    {
      xqc_moq_user_session_t *user_session
          = (xqc_moq_user_session_t *)user_data;
      user_conn_t *user_conn = (user_conn_t *)user_session->data;
      xqc_conn_stats_t stats = xqc_conn_get_stats (ctx.engine, cid);

      printf ("连接统计: send_count:%u, recv_count:%u\n", stats.send_count,
              stats.recv_count);

      // 清理定时器
      if (user_conn && user_conn->ev_send_timer)
        {
          event_del (user_conn->ev_send_timer);
          event_free (user_conn->ev_send_timer);
          user_conn->ev_send_timer = NULL;
        }

      if (user_conn && user_conn->ev_announce_timer)
        {
          event_del (user_conn->ev_announce_timer);
          event_free (user_conn->ev_announce_timer);
          user_conn->ev_announce_timer = NULL;
        }

      if (user_session->session)
        {
          xqc_moq_session_destroy (user_session->session);
        }
      free (user_session);
    }

  if (!g_test_state.test_completed)
    {
      printf ("连接意外关闭，结束测试\n");
      event_base_loopbreak (eb);
    }

  return 0;
}

// 握手完成回调
void
xqc_client_conn_handshake_finished (xqc_connection_t *conn, void *user_data,
                                    void *conn_proto_data)
{
  DEBUG;
  printf ("=== 握手完成 ===\n");
}

// 信号处理
void
stop (int signo)
{
  printf ("\n收到信号 %d，正在停止测试...\n", signo);
  if (!g_test_state.test_completed)
    {
      test_completion_callback (0, 0, NULL);
    }
}

int
main (int argc, char *argv[])
{
  signal (SIGINT, stop);
  signal (SIGTERM, stop);

  int ret;
  char c_log_level = 'd';
  int ch = 0;
  char server_addr[64] = TEST_ADDR;
  int server_port = TEST_PORT;
  xqc_cong_ctrl_callback_t cong_ctrl = xqc_bbr_cb;

  while ((ch = getopt (argc, argv, "a:p:r:l:t:h")) != -1)
    {
      switch (ch)
        {
        case 'a':
          printf ("连接地址: %s\n", optarg);
          snprintf (server_addr, sizeof (server_addr), "%s", optarg);
          break;
        case 'p':
          printf ("连接端口: %s\n", optarg);
          server_port = atoi (optarg);
          break;
        case 'r':
          printf ("角色: %s\n", optarg);
          if (strcmp (optarg, "pub") == 0)
            {
              g_role = XQC_MOQ_PUBLISHER;
            }
          else if (strcmp (optarg, "sub") == 0)
            {
              g_role = XQC_MOQ_SUBSCRIBER;
            }
          else if (strcmp (optarg, "pubsub") == 0)
            {
              g_role = XQC_MOQ_PUBSUB;
            }
          else
            {
              printf ("无效角色，使用默认值 pubsub\n");
            }
          break;
        case 'l':
          printf ("日志级别: %s\n", optarg);
          c_log_level = optarg[0];
          break;
        case 't':
          printf ("测试持续时间: %s秒\n", optarg);
          g_test_duration = atoi (optarg);
          if (g_test_duration <= 0)
            g_test_duration = 30;
          break;
        case 'h':
        default:
          printf ("用法: %s [-a addr] [-p port] [-r role] [-l log_level] [-t "
                  "duration]\n",
                  argv[0]);
          printf ("  -a addr: 服务器地址 (默认: %s)\n", TEST_ADDR);
          printf ("  -p port: 服务器端口 (默认: %d)\n", TEST_PORT);
          printf ("  -r role: pub|sub|pubsub (默认: pubsub)\n");
          printf ("  -l log_level: 日志级别 e|d (默认: d)\n");
          printf ("  -t duration: 测试持续时间（秒） (默认: 30)\n");
          printf ("  -h: 显示帮助\n");
          return (ch == 'h') ? 0 : -1;
        }
    }

  printf ("\n=== MOQ Relay Announce测试客户端 ===\n");
  printf ("连接目标: %s:%d\n", server_addr, server_port);
  printf ("角色: %s\n", g_role == XQC_MOQ_PUBLISHER    ? "Publisher"
                        : g_role == XQC_MOQ_SUBSCRIBER ? "Subscriber"
                                                       : "PubSub");
  printf ("测试时长: %d秒\n", g_test_duration);
  printf ("开始时间: %s\n", xqc_now_spec ());
  printf ("=====================================\n");

  memset (&ctx, 0, sizeof (ctx));
  xqc_app_open_log_file (&ctx, "./test_client.log");
  xqc_platform_init_env ();

  // 引擎配置
  xqc_engine_ssl_config_t engine_ssl_config;
  memset (&engine_ssl_config, 0, sizeof (engine_ssl_config));
  engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
  engine_ssl_config.groups = XQC_TLS_SPECIAL_GROUPS;

  xqc_engine_callback_t callback = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

  xqc_transport_callbacks_t tcbs = {
    .write_socket = xqc_app_write_socket,
    .save_token = xqc_client_save_token,
    .save_session_cb = save_session_cb,
    .save_tp_cb = save_tp_cb,
  };

  xqc_config_t config;
  if (xqc_engine_get_default_config (&config, XQC_ENGINE_CLIENT) < 0)
    {
      return -1;
    }
  xqc_app_set_log_level (c_log_level, &config);
  config.cid_len = 12;

  ctx.engine = xqc_engine_create (XQC_ENGINE_CLIENT, &config,
                                  &engine_ssl_config, &callback, &tcbs, &ctx);
  if (ctx.engine == NULL)
    {
      printf ("创建引擎失败\n");
      return -1;
    }

  eb = event_base_new ();
  ctx.ev_engine = event_new (eb, -1, 0, xqc_app_engine_callback, &ctx);

  // 连接回调
  xqc_conn_callbacks_t conn_cbs = {
    .conn_create_notify = xqc_client_conn_create_notify,
    .conn_close_notify = xqc_client_conn_close_notify,
    .conn_handshake_finished = xqc_client_conn_handshake_finished,
  };
  xqc_moq_init_alpn_by_custom (ctx.engine, &conn_cbs, XQC_MOQ_TRANSPORT_QUIC,
                               XQC_MOQ_SUPPORTED_VERSION_14);

  // 创建用户会话
  xqc_moq_user_session_t *user_session
      = calloc (1, sizeof (xqc_moq_user_session_t) + sizeof (user_conn_t));
  user_conn_t *user_conn = (user_conn_t *)user_session->data;

  xqc_client_init_addr (user_conn, server_addr, server_port);
  ret = xqc_client_create_conn_socket (user_conn);
  if (ret < 0)
    {
      printf ("创建连接socket失败\n");
      return -1;
    }

  // 连接设置
  xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = cong_ctrl,
        .cc_params = {
            .customize_on = 1, 
            .bbr_ignore_app_limit = 1,
        },
        .max_datagram_frame_size = 1024,
    };

  xqc_conn_ssl_config_t conn_ssl_config;
  memset (&conn_ssl_config, 0, sizeof (conn_ssl_config));
  conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

  // 建立连接
  printf ("正在连接到 %s:%d...\n", server_addr, server_port);
  const xqc_cid_t *cid = xqc_connect (
      ctx.engine, &conn_settings, NULL, 0, server_addr, 0, &conn_ssl_config,
      user_conn->peer_addr, user_conn->peer_addrlen, XQC_ALPN_MOQ_QUIC_V14,
      user_session);

  if (cid == NULL)
    {
      printf ("连接失败\n");
      return -1;
    }

  memcpy (&user_conn->cid, cid, sizeof (xqc_cid_t));
  printf ("连接请求已发送\n");

  // 运行事件循环
  event_base_dispatch (eb);

  // 清理
  xqc_engine_destroy (ctx.engine);

  printf ("\n测试客户端已退出\n");
  return g_test_state.test_completed ? 0 : -1;
}