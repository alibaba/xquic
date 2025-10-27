#include <string.h>
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

#include "src/common/xqc_malloc.h"
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

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 2445
#define CLIENT_REMOTE_ADDR "127.0.0.1"
#define CLIENT_REMOTE_PORT 4433

#define XQC_PACKET_TMP_BUF_LEN 1500
#define MAX_BUF_SIZE (100 * 1024 * 1024)
#define XQC_MAX_LOG_LEN 2048
#define XQC_TLS_SPECIAL_GROUPS "X25519:P-256:P-384:P-521"

// Subscribe Announces 管理数据结构
typedef struct subscribe_announces_entry_s
{
  xqc_moq_session_t *session;                      // 订阅者的session
  xqc_moq_msg_track_namespace_t *namespace_prefix; // 订阅的namespace前缀
  uint64_t request_id;                             // 请求ID
  struct subscribe_announces_entry_s *next;        // 链表指针
} subscribe_announces_entry_t;

typedef struct announced_track_s
{
  xqc_moq_msg_track_namespace_t *track_namespace; // track的namespace
  xqc_moq_session_t *source_session;              // 发布者的session
  struct announced_track_s *next;                 // 链表指针
} announced_track_t;

// 全局的subscribe_announces管理结构
static subscribe_announces_entry_t *g_subscribe_announces_list = NULL;
static announced_track_t *g_announced_tracks_list = NULL;

extern long xqc_random (void);
extern xqc_usec_t xqc_now ();

// Subscribe Announces 管理工具函数

// 复制track namespace
static xqc_moq_msg_track_namespace_t *
copy_track_namespace (const xqc_moq_msg_track_namespace_t *src)
{
  if (!src)
    return NULL;

  xqc_moq_msg_track_namespace_t *dst
      = xqc_calloc (1, sizeof (xqc_moq_msg_track_namespace_t));
  dst->track_namespace_num = src->track_namespace_num;
  dst->track_namespace_len
      = xqc_calloc (src->track_namespace_num, sizeof (uint64_t));
  dst->track_namespace
      = xqc_calloc (src->track_namespace_num, sizeof (char *));

  for (size_t i = 0; i < src->track_namespace_num; i++)
    {
      dst->track_namespace_len[i] = src->track_namespace_len[i];
      dst->track_namespace[i]
          = xqc_calloc (1, src->track_namespace_len[i] + 1);
      memcpy (dst->track_namespace[i], src->track_namespace[i],
              src->track_namespace_len[i]);
    }

  return dst;
}

// 释放track namespace
static void
free_track_namespace (xqc_moq_msg_track_namespace_t *namespace)
{
  if (!namespace)
    return;

  for (size_t i = 0; i < namespace->track_namespace_num; i++)
    {
      if (namespace->track_namespace && namespace->track_namespace[i])
        {
          xqc_free (namespace->track_namespace[i]);
        }
    }
  if (namespace->track_namespace)
    {
      xqc_free (namespace->track_namespace);
    }
  if (namespace->track_namespace_len)
    {
      xqc_free (namespace->track_namespace_len);
    }
  xqc_free (namespace);
}

// 检查namespace前缀是否匹配
static int
namespace_prefix_matches (const xqc_moq_msg_track_namespace_t *prefix,
                          const xqc_moq_msg_track_namespace_t *full_namespace)
{
  // 空指针检查 - 如果任一参数为NULL，则视为不匹配
  if (!prefix || !full_namespace)
    {
      printf ("namespace_prefix_matches: NULL pointer detected\n");
      return 0;
    }

  // 如果前缀为空，则匹配所有namespace
  if (prefix->track_namespace_num == 0)
    {
      printf ("namespace_prefix_matches: Empty prefix matches all\n");
      return 1;
    }

  // 检查track_namespace和track_namespace_len数组是否为NULL
  if (!prefix->track_namespace || !prefix->track_namespace_len)
    {
      printf ("namespace_prefix_matches: NULL prefix arrays\n");
      return 0;
    }

  if (!full_namespace->track_namespace || !full_namespace->track_namespace_len)
    {
      printf ("namespace_prefix_matches: NULL full_namespace arrays\n");
      return 0;
    }

  // 如果前缀比完整namespace长，则不匹配
  if (prefix->track_namespace_num > full_namespace->track_namespace_num)
    {
      printf ("namespace_prefix_matches: Prefix longer than namespace\n");
      return 0;
    }

  // 特殊情况：如果前缀只有一个元素且为"moq"，则匹配所有namespace
  if (prefix->track_namespace_num == 1 && prefix->track_namespace[0]
      && strcmp (prefix->track_namespace[0], "moq") == 0)
    {
      printf (
          "namespace_prefix_matches: 'moq' single prefix matches anything\n");
      return 1;
    }

  // 比较每个namespace元素
  for (size_t i = 0; i < prefix->track_namespace_num; i++)
    {
      // 检查字符串指针
      if (!prefix->track_namespace[i] || !full_namespace->track_namespace[i])
        {
          printf ("namespace_prefix_matches: NULL string at index %zu\n", i);
          // 如果有NULL字符串，则视为不匹配
          return 0;
        }

      // 如果前缀是"moq"，则特殊处理为通配符
      if (strcmp (prefix->track_namespace[i], "moq") == 0)
        {
          printf ("namespace_prefix_matches: 'moq' prefix matches anything at "
                  "index %zu\n",
                  i);
          continue;
        }

      // 检查长度
      if (prefix->track_namespace_len[i]
          != full_namespace->track_namespace_len[i])
        {
          printf ("namespace_prefix_matches: Length mismatch at index %zu: "
                  "%llu vs %llu\n",
                  i, (unsigned long long)prefix->track_namespace_len[i],
                  (unsigned long long)full_namespace->track_namespace_len[i]);
          return 0;
        }

      // 比较内容
      if (memcmp (prefix->track_namespace[i],
                  full_namespace->track_namespace[i],
                  prefix->track_namespace_len[i])
          != 0)
        {
          printf ("namespace_prefix_matches: Content mismatch at index %zu\n",
                  i);
          return 0;
        }

      printf ("namespace_prefix_matches: Match at index %zu: %s\n", i,
              prefix->track_namespace[i]);
    }

  printf ("namespace_prefix_matches: Full match\n");
  return 1; // 匹配
}

// 添加subscribe_announces订阅
static void
add_subscribe_announces_entry (
    xqc_moq_session_t *session,
    const xqc_moq_msg_track_namespace_t *namespace_prefix, uint64_t request_id)
{
  subscribe_announces_entry_t *entry
      = xqc_calloc (1, sizeof (subscribe_announces_entry_t));
  entry->session = session;
  entry->namespace_prefix = copy_track_namespace (namespace_prefix);
  entry->request_id = request_id;
  entry->next = g_subscribe_announces_list;
  g_subscribe_announces_list = entry;

  printf (
      "Added subscribe_announces entry for session %p, request_id: %" PRIu64
      "\n",
      session, request_id);

  // 打印当前所有订阅
  printf ("当前所有subscribe_announces订阅:\n");
  int count = 0;
  subscribe_announces_entry_t *current = g_subscribe_announces_list;
  while (current)
    {
      count++;
      printf ("  订阅 %d: session=%p, request_id=%" PRIu64 "\n", count,
              current->session, current->request_id);
      current = current->next;
    }
  printf ("总共 %d 个订阅\n", count);
}

// 移除subscribe_announces订阅
static void
remove_subscribe_announces_entries_for_session (xqc_moq_session_t *session)
{
  subscribe_announces_entry_t **current = &g_subscribe_announces_list;
  while (*current)
    {
      if ((*current)->session == session)
        {
          subscribe_announces_entry_t *to_remove = *current;
          *current = (*current)->next;
          free_track_namespace (to_remove->namespace_prefix);
          xqc_free (to_remove);
          printf ("Removed subscribe_announces entry for session %p\n",
                  session);
        }
      else
        {
          current = &(*current)->next;
        }
    }
}

// 添加announced track记录
static void
add_announced_track (xqc_moq_session_t *source_session,
                     const xqc_moq_msg_track_namespace_t *track_namespace)
{
  // 检查是否已存在相同的track
  announced_track_t *existing = g_announced_tracks_list;
  while (existing)
    {
      if (existing->source_session == source_session
          && namespace_prefix_matches (track_namespace,
                                       existing->track_namespace)
          && namespace_prefix_matches (existing->track_namespace,
                                       track_namespace))
        {
          printf ("Track already announced, skipping\n");
          return;
        }
      existing = existing->next;
    }

  announced_track_t *track = xqc_calloc (1, sizeof (announced_track_t));
  track->track_namespace = copy_track_namespace (track_namespace);
  track->source_session = source_session;
  track->next = g_announced_tracks_list;
  g_announced_tracks_list = track;

  printf ("Added announced track from session %p\n", source_session);
}

// 移除session相关的announced tracks
static void
remove_announced_tracks_for_session (xqc_moq_session_t *session)
{
  announced_track_t **current = &g_announced_tracks_list;
  while (*current)
    {
      if ((*current)->source_session == session)
        {
          announced_track_t *to_remove = *current;
          *current = (*current)->next;
          free_track_namespace (to_remove->track_namespace);
          xqc_free (to_remove);
          printf ("Removed announced track for session %p\n", session);
        }
      else
        {
          current = &(*current)->next;
        }
    }
}

// 向匹配的订阅者转发announce消息
static void
forward_announce_to_subscribers (
    const xqc_moq_msg_track_namespace_t *track_namespace)
{
  // 检查输入参数
  if (!track_namespace)
    {
      printf ("Error: track_namespace is NULL in "
              "forward_announce_to_subscribers\n");
      return;
    }

  // 检查是否有订阅者
  if (!g_subscribe_announces_list)
    {
      printf ("No subscribers to forward announce to\n");
      return;
    }

  printf ("\n=== Forwarding Announce Message ===\n");
  printf ("Announce message namespace details:\n");
  for (size_t i = 0; i < track_namespace->track_namespace_num; i++)
    {
      if (track_namespace->track_namespace
          && track_namespace->track_namespace[i])
        {
          printf ("  - namespace[%zu]: %s\n", i,
                  track_namespace->track_namespace[i]);
        }
      else
        {
          printf ("  - namespace[%zu]: NULL\n", i);
        }
    }

  int forwarded_count = 0;
  subscribe_announces_entry_t *entry = g_subscribe_announces_list;
  while (entry)
    {
      // 检查entry和session有效性
      if (!entry->namespace_prefix || !entry->session)
        {
          printf ("Warning: Invalid subscriber entry found\n");
          entry = entry->next;
          continue;
        }

      printf ("检查订阅者session %p:\n", entry->session);
      printf ("  订阅者namespace_prefix详情:\n");
      for (size_t i = 0; i < entry->namespace_prefix->track_namespace_num; i++)
        {
          if (entry->namespace_prefix->track_namespace
              && entry->namespace_prefix->track_namespace[i])
            {
              printf ("  - namespace[%zu]: %s\n", i,
                      entry->namespace_prefix->track_namespace[i]);
            }
          else
            {
              printf ("  - namespace[%zu]: NULL\n", i);
            }
        }

      // 检查namespace前缀是否匹配
      int matches = namespace_prefix_matches (entry->namespace_prefix,
                                              track_namespace);
      printf ("  匹配结果: %s\n", matches ? "匹配" : "不匹配");

      if (matches)
        {
          printf ("Forwarding announce to subscriber session %p\n",
                  entry->session);

          // 创建announce消息并发送
          xqc_moq_announce_msg_t announce_msg;
          memset (&announce_msg, 0, sizeof (announce_msg));
          announce_msg.track_namespace
              = (xqc_moq_msg_track_namespace_t *)track_namespace;
          announce_msg.params_num = 0;
          announce_msg.params = NULL;
          announce_msg.request_id = 0; // 设置请求ID

          xqc_int_t ret
              = xqc_moq_write_announce (entry->session, &announce_msg);
          if (ret < 0)
            {
              printf ("Failed to forward announce to subscriber: %d\n", ret);
            }
          else
            {
              printf ("Successfully forwarded announce to subscriber\n");
              forwarded_count++;
            }
        }
      entry = entry->next;
    }

  printf ("Total forwarded to %d subscribers\n", forwarded_count);
  printf ("=== End Forwarding Announce ===\n\n");
}

typedef enum
{
  MODE_CLIENT = 1, // 仅作为客户端
  MODE_SERVER = 2, // 仅作为服务器
  MODE_RELAY = 3,  // 同时作为客户端和服务器的中继
} run_mode_t;

typedef struct
{
  user_conn_t base;
  int is_from_upstream;
} relay_user_conn_t;

xqc_moq_session_t *g_downstream_session[10];
int g_downstream_session_count = 0;

// 上游session管理
xqc_moq_session_t *g_upstream_session = NULL;

/* 封装了客户端和服务器上下文 */
typedef struct
{
  xqc_app_ctx_t client_ctx;
  xqc_app_ctx_t server_ctx;
  struct event_base *eb;
  run_mode_t mode;
  xqc_moq_role_t role;
  int frame_num;
  int ipv6;
  int connect_upstream; // 是否连接上游服务器
} combined_ctx_t;

// 连接重试上下文
typedef struct
{
  char server_addr[64];
  int server_port;
  int retry_count;
  int max_retries;
  struct event *retry_timer;
} connection_retry_t;

connection_retry_t g_retry_ctx;
// 全局上下文
combined_ctx_t g_ctx;

void xqc_app_send_callback (int fd, short what, void *arg);
int xqc_server_accept (xqc_engine_t *engine, xqc_connection_t *conn,
                       const xqc_cid_t *cid, void *user_data);
void xqc_server_refuse (xqc_engine_t *engine, xqc_connection_t *conn,
                        const xqc_cid_t *cid, void *user_data);
int xqc_server_conn_closing_notify (xqc_connection_t *conn,
                                    const xqc_cid_t *cid, xqc_int_t err_code,
                                    void *conn_user_data);

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
on_server_session_setup (xqc_moq_user_session_t *user_session, char *extdata)
{
  DEBUG;

  if (extdata)
    {
      printf ("extdata:%s\n", extdata);
    }

  xqc_moq_session_t *session = user_session->session;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;

  user_conn->moq_session = session;
  user_conn->video_subscribe_id = -1;
  user_conn->audio_subscribe_id = -1;
  user_conn->countdown = g_ctx.frame_num;

  if (g_ctx.role == XQC_MOQ_SUBSCRIBER)
    {
      return;
    }

  xqc_moq_selection_params_t video_params;
  memset (&video_params, 0, sizeof (xqc_moq_selection_params_t));
  video_params.codec = "av01";
  video_params.mime_type = "video/mp4";
  video_params.width = 720;
  video_params.height = 720;
  video_params.bitrate = 1000000;
  video_params.framerate = 30;
  // for server temporary use
  xqc_moq_track_t *video_track = xqc_moq_track_create (
      session, "moq-date", "date", XQC_MOQ_TRACK_VIDEO, &video_params,
      XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_PUB);
  if (video_track == NULL)
    {
      printf ("create video track error\n");
    }
  user_conn->video_track = video_track;
  user_conn->clock_track = video_track;

  g_downstream_session[g_downstream_session_count++] = session;
  // interop experiment
  // only for connect to server and subscribe
  // xqc_moq_subscribe_latest(session, "moq-date", "date");
}

static int
xqc_server_create_socket (const char *addr, unsigned int port)
{
  printf ("Server creating socket on %s:%d at %s\n", addr, port,
          xqc_now_spec ());
  int fd;
  int type = g_ctx.ipv6 ? AF_INET6 : AF_INET;
  g_ctx.server_ctx.local_addrlen = g_ctx.ipv6 ? sizeof (struct sockaddr_in6)
                                              : sizeof (struct sockaddr_in);
  struct sockaddr *saddr = (struct sockaddr *)&g_ctx.server_ctx.local_addr;
  int size;
  int optval = 1;

  fd = socket (type, SOCK_DGRAM, 0);
  if (fd < 0)
    {
      printf ("create socket failed, errno: %d\n", get_sys_errno ());
      return -1;
    }

#ifdef XQC_SYS_WINDOWS
  if (ioctlsocket (fd, FIONBIO, &optval) == SOCKET_ERROR)
    {
      goto err;
    }
#else
  if (fcntl (fd, F_SETFL, O_NONBLOCK) == -1)
    {
      printf ("set socket nonblock failed, errno: %d\n", errno);
      goto err;
    }
#endif

  optval = 1;
  if (setsockopt (fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof (optval)) < 0)
    {
      printf ("setsockopt failed, errno: %d\n", get_sys_errno ());
      goto err;
    }

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

  if (type == AF_INET6)
    {
      memset (saddr, 0, sizeof (struct sockaddr_in6));
      struct sockaddr_in6 *addr_v6 = (struct sockaddr_in6 *)saddr;
      addr_v6->sin6_family = type;
      addr_v6->sin6_port = htons (port);
      addr_v6->sin6_addr = in6addr_any;
    }
  else
    {
      memset (saddr, 0, sizeof (struct sockaddr_in));
      struct sockaddr_in *addr_v4 = (struct sockaddr_in *)saddr;
      addr_v4->sin_family = type;
      addr_v4->sin_port = htons (port);
      addr_v4->sin_addr.s_addr = inet_addr (addr);
    }

  if (bind (fd, saddr, g_ctx.server_ctx.local_addrlen) < 0)
    {
      printf ("bind socket failed, errno: %d\n", get_sys_errno ());
      goto err;
    }

  return fd;

err:
  close (fd);
  return -1;
}

void
xqc_server_socket_write_handler (xqc_app_ctx_t *ctx)
{
  DEBUG
}

int g_recv_total = 0;
void
xqc_server_socket_read_handler (xqc_app_ctx_t *ctx)
{
  ssize_t recv_sum = 0;
  struct sockaddr_in6 peer_addr;
  socklen_t peer_addrlen = g_ctx.ipv6 ? sizeof (struct sockaddr_in6)
                                      : sizeof (struct sockaddr_in);
  ssize_t recv_size = 0;
  unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
  uint64_t recv_time;
  xqc_int_t ret;

  do
    {
      recv_size = recvfrom (ctx->listen_fd, packet_buf, sizeof (packet_buf), 0,
                            (struct sockaddr *)&peer_addr, &peer_addrlen);
      if (recv_size < 0 && get_sys_errno () == EAGAIN)
        {
          break;
        }

      if (recv_size < 0)
        {
          printf ("!!!!!!!!!recvfrom: recvmsg = %zd err=%s\n", recv_size,
                  strerror (get_sys_errno ()));
          break;
        }

      recv_sum += recv_size;
      recv_time = xqc_now ();
      printf ("Server received %zd bytes at %llu\n", recv_size, recv_time);

      ret = xqc_engine_packet_process (
          ctx->engine, packet_buf, recv_size,
          (struct sockaddr *)(&ctx->local_addr), ctx->local_addrlen,
          (struct sockaddr *)(&peer_addr), peer_addrlen, (xqc_usec_t)recv_time,
          NULL);
      if (ret != XQC_OK)
        {
          printf ("xqc_server_read_handler: packet process err: %d\n", ret);
          return;
        }
    }
  while (recv_size > 0);

  xqc_engine_finish_recv (ctx->engine);
}

static void
xqc_server_socket_event_callback (int fd, short what, void *arg)
{
  xqc_app_ctx_t *ctx = (xqc_app_ctx_t *)arg;

  if (what & EV_WRITE)
    {
      xqc_server_socket_write_handler (ctx);
    }
  else if (what & EV_READ)
    {
      xqc_server_socket_read_handler (ctx);
    }
  else
    {
      printf ("server event callback: what=%d\n", what);
      exit (1);
    }
}

/* ============================ 客户端相关代码 ============================ */

void
xqc_client_socket_write_handler (user_conn_t *user_conn)
{
  DEBUG
  xqc_conn_continue_send (g_ctx.client_ctx.engine, &user_conn->cid);
}

void
xqc_client_socket_read_handler (user_conn_t *user_conn, int fd)
{
  xqc_int_t ret;
  ssize_t recv_size = 0;
  ssize_t recv_sum = 0;
  unsigned char packet_buf[XQC_PACKET_TMP_BUF_LEN];
  static ssize_t rcv_sum = 0;

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
          printf ("Client recvfrom: recvmsg = %zd(%s)\n", recv_size,
                  strerror (get_sys_errno ()));
          break;
        }

      if (recv_size == 0)
        {
          break;
        }

      recv_sum += recv_size;
      rcv_sum += recv_size;
      printf ("Client received %zd bytes\n", recv_size);

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
          g_ctx.client_ctx.engine, packet_buf, recv_size,
          user_conn->local_addr, user_conn->local_addrlen,
          user_conn->peer_addr, user_conn->peer_addrlen, (xqc_usec_t)recv_time,
          user_conn);
      if (ret != XQC_OK)
        {
          printf ("xqc_client_read_handler: packet process err, ret: %d\n",
                  ret);
          return;
        }
    }
  while (recv_size > 0);

  xqc_engine_finish_recv (g_ctx.client_ctx.engine);
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
      printf ("client event callback: what=%d\n", what);
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
  int ip_type = (g_ctx.ipv6 ? AF_INET6 : AF_INET);
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

  /* create fd & set socket option */
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

  /* connect to peer addr */
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
  int ip_type = (g_ctx.ipv6 ? AF_INET6 : AF_INET);
  user_conn->fd = xqc_client_create_socket (ip_type, user_conn->peer_addr,
                                            user_conn->peer_addrlen);
  if (user_conn->fd < 0)
    {
      printf ("xqc_create_socket error\n");
      return -1;
    }

  user_conn->ev_socket
      = event_new (g_ctx.eb, user_conn->fd, EV_READ | EV_PERSIST,
                   xqc_client_socket_event_callback, user_conn);
  event_add (user_conn->ev_socket, NULL);

  return 0;
}

/* ============================ 共享回调函数 ============================ */

void
on_announce (xqc_moq_user_session_t *user_session,
             xqc_moq_announce_msg_t *announce)
{
  DEBUG;
  // 参数检查
  if (!user_session || !announce)
    {
      printf ("Error: Invalid parameters in on_announce\n");
      return;
    }

  xqc_moq_session_t *session = user_session->session;
  if (!session)
    {
      printf ("Error: NULL session in on_announce\n");
      return;
    }

  user_conn_t *user_conn = (user_conn_t *)user_session->data;
  if (!user_conn)
    {
      printf ("Error: NULL user_conn in on_announce\n");
      return;
    }

  relay_user_conn_t *relay_conn = (relay_user_conn_t *)user_conn;
  xqc_int_t ret;

  printf ("=== Received Announce Message ===\n");

  // 检查track_namespace有效性
  if (!announce->track_namespace || !announce->track_namespace->track_namespace
      || !announce->track_namespace->track_namespace[0])
    {
      printf ("Error: Invalid track_namespace in announce message\n");
      return;
    }

  printf ("Track Namespace: %s\n",
          announce->track_namespace->track_namespace[0]);

  // 发送announce_ok响应
  xqc_moq_announce_ok_msg_t announce_ok_msg;
  memset (&announce_ok_msg, 0, sizeof (announce_ok_msg));
  announce_ok_msg.request_id = announce->request_id;

  ret = xqc_moq_write_announce_ok (session, &announce_ok_msg);
  if (ret < 0)
    {
      printf ("Failed to send announce_ok: %d\n", ret);
      return;
    }
  printf ("Announce OK response sent successfully\n");

  // 添加到announced tracks列表
  add_announced_track (session, announce->track_namespace);

  // 向匹配的subscribe_announces订阅者转发announce消息
  forward_announce_to_subscribers (announce->track_namespace);

  // 在中继模式下，需要将announce消息转发到下游连接
  if (g_ctx.mode == MODE_RELAY)
    {
      if (relay_conn->is_from_upstream)
        {
          // 这是来自上游的announce消息，需要转发到下游
          printf ("Received upstream announce, forwarding to downstream connections\n");
          // TODO: 实现转发逻辑到下游连接
        }
      else
        {
          // 这是来自下游的announce消息，需要转发到上游
          printf ("Received downstream announce, forwarding to upstream connection\n");
          // TODO: 实现转发逻辑到上游连接
        }
    }

  printf ("Announce message processing completed\n");
}

void
on_announce_ok (xqc_moq_user_session_t *user_session,
                xqc_moq_announce_ok_msg_t *announce_ok)
{
  DEBUG;
  printf ("Received announce_ok message: request_id:%llu\n",
          announce_ok->request_id);
}

// 向上游转发subscribe_announces的函数
void
forward_subscribe_announces_to_upstream (
    xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
  printf ("=== Forwarding Subscribe Announces to Upstream ===\n");

  if (!g_upstream_session)
    {
      printf ("Warning: Upstream session not established, cannot forward subscribe_announces\n");
      return;
    }

  if (!subscribe_namespace || !subscribe_namespace->track_namespace_prefix)
    {
      printf ("Error: Invalid subscribe_namespace in "
              "forward_subscribe_announces_to_upstream\n");
      return;
    }

  printf ("Found upstream session: %p\n", g_upstream_session);
  printf ("Preparing to send subscribe_announces message to upstream\n");

  // 创建要转发的subscribe_announces消息
  xqc_moq_subscribe_namespace_msg_t upstream_msg;
  memset (&upstream_msg, 0, sizeof (upstream_msg));

  // 复制namespace前缀
  upstream_msg.track_namespace_prefix
      = xqc_calloc (1, sizeof (xqc_moq_msg_track_namespace_t));
  upstream_msg.track_namespace_prefix->track_namespace_num
      = subscribe_namespace->track_namespace_prefix->track_namespace_num;
  upstream_msg.track_namespace_prefix->track_namespace
      = xqc_calloc (upstream_msg.track_namespace_prefix->track_namespace_num,
                    sizeof (char *));
  upstream_msg.track_namespace_prefix->track_namespace_len
      = xqc_calloc (upstream_msg.track_namespace_prefix->track_namespace_num,
                    sizeof (uint64_t));

  for (size_t i = 0;
       i < upstream_msg.track_namespace_prefix->track_namespace_num; i++)
    {
      if (subscribe_namespace->track_namespace_prefix->track_namespace[i])
        {
          size_t len = subscribe_namespace->track_namespace_prefix
                           ->track_namespace_len[i];
          upstream_msg.track_namespace_prefix->track_namespace[i]
              = xqc_malloc (len + 1);
          memcpy (
              upstream_msg.track_namespace_prefix->track_namespace[i],
              subscribe_namespace->track_namespace_prefix->track_namespace[i],
              len);
          upstream_msg.track_namespace_prefix->track_namespace[i][len] = '\0';
          upstream_msg.track_namespace_prefix->track_namespace_len[i] = len;

          printf ("  - Forwarding namespace[%zu]: %s (len: %zu)\n", i,
                  upstream_msg.track_namespace_prefix->track_namespace[i],
                  len);
        }
    }

  upstream_msg.params_num = 0;
  upstream_msg.params = NULL;
  upstream_msg.request_id = subscribe_namespace->request_id;

  // 发送到上游服务器
  xqc_int_t ret
      = xqc_moq_write_subscribe_namespace (g_upstream_session, &upstream_msg);
  if (ret < 0)
    {
      printf ("Failed to send subscribe_announces to upstream: %d\n", ret);
    }
  else
    {
      printf ("Successfully sent subscribe_announces to upstream\n");
      printf ("This will trigger upstream server to publish relevant tracks\n");
    }

  // 清理内存
  for (size_t i = 0;
       i < upstream_msg.track_namespace_prefix->track_namespace_num; i++)
    {
      if (upstream_msg.track_namespace_prefix->track_namespace[i])
        {
          xqc_free (upstream_msg.track_namespace_prefix->track_namespace[i]);
        }
    }
  xqc_free (upstream_msg.track_namespace_prefix->track_namespace);
  xqc_free (upstream_msg.track_namespace_prefix->track_namespace_len);
  xqc_free (upstream_msg.track_namespace_prefix);
}

// Subscribe Announces 相关回调函数
void
on_subscribe_namespace (xqc_moq_user_session_t *user_session,
                        xqc_moq_subscribe_namespace_msg_t *subscribe_namespace)
{
  DEBUG;
  printf ("\n\n=== Received Subscribe Namespace Message ===\n");
  printf ("Received time: %s\n", xqc_now_spec ());

  // 参数检查，但更宽松
  if (!user_session)
    {
      printf ("Error: NULL user_session in on_subscribe_namespace\n");
      return;
    }

  if (!subscribe_namespace)
    {
      printf ("Error: NULL subscribe_namespace in on_subscribe_namespace\n");
      return;
    }

  xqc_moq_session_t *session = user_session->session;
  if (!session)
    {
      printf ("Error: NULL session in on_subscribe_namespace\n");
      return;
    }

  user_conn_t *user_conn = (user_conn_t *)user_session->data;
  if (user_conn)
    {
      printf ("Subscribe Namespace from session: %p\n", session);
    }

  // 检查track_namespace_prefix有效性，但更宽松
  if (!subscribe_namespace->track_namespace_prefix)
    {
      printf ("Error: NULL track_namespace_prefix\n");
      return;
    }

  if (!subscribe_namespace->track_namespace_prefix->track_namespace)
    {
      printf ("Error: NULL track_namespace array\n");
      return;
    }

  printf ("Track Namespace Prefix details:\n");
  printf ("  - namespace_num: %" PRIu64 "\n",
          subscribe_namespace->track_namespace_prefix->track_namespace_num);

  if (subscribe_namespace->track_namespace_prefix->track_namespace_num == 0)
    {
      printf (
          "Warning: Empty track_namespace_prefix (num=0), but continuing\n");
    }
  else
    {
      for (size_t i = 0;
           i
           < subscribe_namespace->track_namespace_prefix->track_namespace_num;
           i++)
        {
          if (!subscribe_namespace->track_namespace_prefix->track_namespace[i])
            {
              printf ("  - namespace[%zu]: NULL\n", i);
            }
          else
            {
              printf ("  - namespace[%zu]: %s (len: %" PRIu64 ")\n", i,
                      subscribe_namespace->track_namespace_prefix
                          ->track_namespace[i],
                      subscribe_namespace->track_namespace_prefix
                          ->track_namespace_len[i]);
            }
        }
    }

  // 添加到订阅列表
  add_subscribe_announces_entry (session,
                                 subscribe_namespace->track_namespace_prefix,
                                 0); // 使用0作为request_id

  // 在中继模式下，需要向上游转发这个subscribe_announces
  if (g_ctx.mode == MODE_RELAY && g_ctx.connect_upstream)
    {
      printf ("\n=== Relay Forwarding Subscribe Announces to Upstream ===\n");
      printf ("Received downstream subscribe_announces, forwarding to upstream server\n");

      // 向上游转发subscribe_announces
      forward_subscribe_announces_to_upstream (subscribe_namespace);
    }

  // 发送subscribe_announces_ok响应
  printf ("Sending Subscribe Namespace OK response...\n");

  // 创建subscribe_announces_ok消息
  xqc_moq_subscribe_namespace_ok_msg_t subscribe_namespace_ok;
  memset (&subscribe_namespace_ok, 0, sizeof (subscribe_namespace_ok));
  subscribe_namespace_ok.request_id = subscribe_namespace->request_id;

  // 发送响应
  xqc_int_t ret = xqc_moq_write_subscribe_namespace_ok (
      session, &subscribe_namespace_ok);
  if (ret < 0)
    {
      printf ("Failed to send subscribe_namespace_ok: %d\n", ret);
    }
  else
    {
      printf ("Subscribe Namespace OK response sent successfully\n");
    }

  printf ("Subscribe Namespace request processed\n");

  // 检查现有的announced tracks，将匹配的发送给订阅者
  if (g_announced_tracks_list)
    {
      printf ("Checking existing announced tracks:\n");
      int track_count = 0;
      announced_track_t *track = g_announced_tracks_list;
      while (track)
        {
          track_count++;

          if (!track->track_namespace)
            {
              printf (
                  "Warning: Found invalid track with NULL track_namespace\n");
              track = track->next;
              continue;
            }

          printf ("Checking track %d:\n", track_count);
          for (size_t i = 0; i < track->track_namespace->track_namespace_num;
               i++)
            {
              if (track->track_namespace->track_namespace[i])
                {
                  printf ("  - namespace[%zu]: %s\n", i,
                          track->track_namespace->track_namespace[i]);
                }
            }

          // 尝试匹配，但更宽松地处理错误
          int matches = 0;
          if (subscribe_namespace->track_namespace_prefix->track_namespace_num
                  > 0
              && subscribe_namespace->track_namespace_prefix
                         ->track_namespace[0]
                     != NULL)
            {
              matches = namespace_prefix_matches (
                  subscribe_namespace->track_namespace_prefix,
                  track->track_namespace);
              printf ("Matching result: %s\n",
                      matches ? "Match" : "No match");
            }
          else
            {
              // 如果namespace_prefix为空，则视为匹配所有track
              matches = 1;
              printf ("Empty namespace_prefix matches all tracks\n");
            }

          if (matches)
            {
              printf ("Found matching existing track, forwarding announce\n");

              xqc_moq_announce_msg_t announce_msg;
              memset (&announce_msg, 0, sizeof (announce_msg));
              announce_msg.track_namespace = track->track_namespace;
              announce_msg.params_num = 0;
              announce_msg.params = NULL;
              announce_msg.request_id = 1; // 设置请求ID

              xqc_int_t ret = xqc_moq_write_announce (session, &announce_msg);
              if (ret < 0)
                {
                  printf ("Failed to send existing announce: %d\n", ret);
                }
              else
                {
                  printf (
                      "Successfully sent existing announce to subscriber\n");
                }
            }
          track = track->next;
        }
      printf ("Checked %d announced tracks\n", track_count);
    }
  else
    {
      printf ("No existing announced tracks to forward\n");
    }

  printf ("=== End Subscribe Namespace Processing ===\n\n");
}

void
on_datachannel (xqc_moq_user_session_t *user_session)
{
  DEBUG;
  xqc_int_t ret;
  xqc_moq_session_t *session = user_session->session;
  ret = xqc_moq_write_datachannel (session, (uint8_t *)"datachannel req",
                                   strlen ("datachannel req")+1);
  if (ret < 0)
    {
      printf ("xqc_moq_write_datachannel error\n");
    }
}

void
on_datachannel_msg (struct xqc_moq_user_session_s *user_session, uint8_t *msg,
                    size_t msg_len)
{
  DEBUG;
  if (msg && msg_len > 0)
    {
      printf ("Received datachannel msg: %s\n", (char *)msg);
    }
}

void
on_audio_frame (xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
                xqc_moq_audio_frame_t *audio_frame)
{
  DEBUG;
  xqc_moq_session_t *session = user_session->session;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;
  relay_user_conn_t *relay_conn = (relay_user_conn_t *)user_conn;

  printf ("Received audio frame: subscribe_id:%" PRIu64 ", seq_num:%" PRIu64
          ", timestamp_us:%" PRIu64 "\n",
          subscribe_id, audio_frame->seq_num, audio_frame->timestamp_us);

  /* 在中继模式下，可以转发收到的帧 */
  if (g_ctx.mode == MODE_RELAY && relay_conn->is_from_upstream)
    {
      printf (
          "Relay: Could forward audio frame from upstream to downstream\n");
    }
}

void
on_object_datagram (xqc_moq_user_session_t *user_session,
                    xqc_moq_object_datagram_t *object_datagram)
{

  // DEBUG;
  printf ("Received object datagram: payload:%s\n",
          (char *)object_datagram->payload);
  user_conn_t *user_conn = (user_conn_t *)user_session->data;
  xqc_moq_session_t *now_session = user_session->session;

  for (int i = 0; i < g_downstream_session_count; i++)
    {
      if (g_downstream_session[i] != NULL
          && g_downstream_session[i] != now_session)
        {
          printf ("clock id = %" PRIu64 "\n", user_conn->clock_subscribe_id);
          xqc_moq_write_object_datagram (g_downstream_session[i], 0, 0,
                                         user_conn->object_id, 0,
                                         (uint8_t *)object_datagram->payload,
                                         strlen (object_datagram->payload));
        }
    }
  // if(g_downstream_session != NULL) {
  //     printf("clock id = %"PRIu64"\n", user_conn->clock_subscribe_id);
  //     xqc_moq_write_object_datagram(g_downstream_session, 0, 0,
  //      user_conn->object_id, 0,
  //       (uint8_t*)object_datagram->payload,
  //       strlen(object_datagram->payload));
  // }
  // else {
  //     printf("no downstream found\n");
  // }
}

void
on_goaway (xqc_moq_user_session_t *user_session, xqc_moq_goaway_msg_t *goaway)
{
  DEBUG;
  // printf("Received GOAWAY message: %s\n", goaway->new_URI);
}

void
on_subscribe (xqc_moq_user_session_t *user_session, uint64_t subscribe_id,
              xqc_moq_track_t *track, xqc_moq_subscribe_msg_t *msg)
{
  DEBUG;
  xqc_moq_session_t *session = user_session->session;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;
  xqc_int_t ret;

  printf ("on_subscribe: track_namespace: %s, track_name: %s\n",
          msg->track_namespace->track_namespace[0], msg->track_name);
  if (strcmp (msg->track_namespace->track_namespace[0], "moq-date") != 0)
    {
      printf ("on_subscribe: track_namespace not match\n");
      return;
    }

  if (strcmp (msg->track_name, "date") != 0)
    {
      printf ("on_subscribe: track_name not match\n");
      return;
    }

  xqc_moq_subscribe_ok_msg_t subscribe_ok;
  subscribe_ok.subscribe_id = subscribe_id;
  subscribe_ok.expire_ms = 0;
  subscribe_ok.content_exist = 1;
  subscribe_ok.largest_group_id = 0;
  subscribe_ok.largest_object_id = 0;
  subscribe_ok.params_num = 0;
  ret = xqc_moq_write_subscribe_ok (session, &subscribe_ok);
  if (ret < 0)
    {
      printf ("xqc_moq_write_subscribe_ok error\n");
    }

  user_conn->ev_send_timer
      = evtimer_new (g_ctx.eb, xqc_app_send_callback, user_conn);
  struct timeval time = { 1, 0 };
  event_add (user_conn->ev_send_timer, &time);
}

/* ============================ Server callbacks ============================
 */

int
xqc_server_accept (xqc_engine_t *engine, xqc_connection_t *conn,
                   const xqc_cid_t *cid, void *user_data)
{
  DEBUG;
  xqc_moq_user_session_t *user_session = calloc (
      1, sizeof (xqc_moq_user_session_t) + sizeof (relay_user_conn_t));
  relay_user_conn_t *relay_conn = (relay_user_conn_t *)(user_session->data);

  relay_conn->is_from_upstream = 0;

  xqc_moq_session_callbacks_t callbacks = {
    .on_session_setup = on_server_session_setup,
    .on_datachannel = on_datachannel,
    .on_datachannel_msg = on_datachannel_msg,
    /* For Publisher */
    .on_subscribe = on_subscribe,
    // .on_request_keyframe = on_request_keyframe,
    // /* For Subscriber */
    // .on_subscribe_error = on_subscribe_error,
    // .on_catalog = on_catalog,
    // .on_video = on_video_frame,
    .on_audio = on_audio_frame,
    .on_goaway = on_goaway,
    .on_datagram = on_object_datagram,
    .on_announce = on_announce,
    .on_announce_ok = on_announce_ok,
    .on_subscribe_namespace = on_subscribe_namespace, // 确保此回调已设置
  };

  printf ("服务器回调函数已设置，包括on_subscribe_namespace=%p\n",
          on_subscribe_namespace);

  xqc_moq_session_t *session = xqc_moq_session_create (
      conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14,
      g_ctx.role, callbacks, NULL);
  if (session == NULL)
    {
      printf ("create session error\n");
      free (user_session);
      return -1;
    }
  xqc_moq_configure_bitrate (session, 1000000, 8000000, 1000000);

  xqc_conn_set_transport_user_data (conn, user_session);

  relay_conn->base.peer_addr = calloc (1, sizeof (struct sockaddr_in6));
  relay_conn->base.peer_addrlen = sizeof (struct sockaddr_in6);
  xqc_int_t ret = xqc_conn_get_peer_addr (
      conn, (struct sockaddr *)relay_conn->base.peer_addr,
      sizeof (struct sockaddr_in6), &relay_conn->base.peer_addrlen);
  if (ret != XQC_OK)
    {
      printf ("get peer addr error, ret:%d\n", ret);
      return -1;
    }

  printf ("-- server_accept user_session :%p, relay_conn: %p\n", user_session,
          relay_conn);

  memcpy (&relay_conn->base.cid, cid, sizeof (*cid));
  relay_conn->base.fd = g_ctx.server_ctx.listen_fd;

  return 0;
}

void
xqc_server_refuse (xqc_engine_t *engine, xqc_connection_t *conn,
                   const xqc_cid_t *cid, void *user_data)
{
  DEBUG;
  printf ("Server refused connection\n");
  if (user_data)
    {
      xqc_moq_user_session_t *user_session
          = (xqc_moq_user_session_t *)user_data;
      free (user_session);
    }
}

/* ============================ Client callbacks ============================
 */

void
on_client_session_setup (xqc_moq_user_session_t *user_session, char *extdata)
{
  DEBUG;

  if (extdata)
    {
      printf ("extdata:%s\n", extdata);
    }

  xqc_moq_session_t *session = user_session->session;
  user_conn_t *user_conn = (user_conn_t *)user_session->data;

  user_conn->moq_session = session;
  user_conn->video_subscribe_id = -1;
  user_conn->audio_subscribe_id = -1;
  user_conn->countdown = g_ctx.frame_num;

  xqc_moq_selection_params_t video_params;
  memset (&video_params, 0, sizeof (xqc_moq_selection_params_t));
  video_params.codec = "av01";
  video_params.mime_type = "video/mp4";
  video_params.width = 720;
  video_params.height = 720;
  video_params.bitrate = 1000000;
  video_params.framerate = 30;
  // for server temporary use
  xqc_moq_track_t *video_track = xqc_moq_track_create (
      session, "moq-date", "date", XQC_MOQ_TRACK_VIDEO, &video_params,
      XQC_MOQ_CONTAINER_LOC, XQC_MOQ_TRACK_FOR_SUB);
  if (video_track == NULL)
    {
      printf ("create video track error\n");
    }
  user_conn->video_track = video_track;

  // 测试发送announce消息
  xqc_moq_announce_msg_t announce_msg;
  memset (&announce_msg, 0, sizeof (announce_msg));

  announce_msg.track_namespace
      = xqc_calloc (1, sizeof (xqc_moq_msg_track_namespace_t));
  announce_msg.track_namespace->track_namespace_num = 1;
  announce_msg.track_namespace->track_namespace_len
      = xqc_calloc (1, sizeof (uint64_t));
  announce_msg.track_namespace->track_namespace_len[0] = strlen ("moq-date");
  announce_msg.track_namespace->track_namespace
      = xqc_calloc (1, sizeof (char *));
  announce_msg.track_namespace->track_namespace[0]
      = xqc_calloc (1, strlen ("moq-date") + 1);
  strcpy (announce_msg.track_namespace->track_namespace[0], "moq-date");

  announce_msg.request_id = 1; // 设置请求ID
  announce_msg.params_num = 0;
  announce_msg.params = NULL;

  xqc_int_t ret = xqc_moq_write_announce (session, &announce_msg);
  if (ret < 0)
    {
      printf ("xqc_moq_write_announce error\n");
    }
  else
    {
      printf ("Client sent announce message for track_namespace: moq-date\n");
    }

  // 清理内存
  xqc_free (announce_msg.track_namespace->track_namespace[0]);
  xqc_free (announce_msg.track_namespace->track_namespace);
  xqc_free (announce_msg.track_namespace->track_namespace_len);
  xqc_free (announce_msg.track_namespace);

  // interop experiment
  // only for connect to server and subscribe
  xqc_moq_subscribe_latest (session, "moq-date", "date");

  // 在中继模式下，不向上游发送subscribe_announces
  // 中继应该等待上游主动发布track，然后转发给下游订阅者
  printf ("Current role: %d (XQC_MOQ_SUBSCRIBER=%d)\n", g_ctx.role,
          XQC_MOQ_SUBSCRIBER);

  if (g_ctx.mode != MODE_RELAY)
    {
      // 创建并发送subscribe_announces消息
      printf ("\n=== 准备发送Subscribe Announces消息 ===\n");
      printf ("发送时间: %s\n", xqc_now_spec ());
      printf ("发送会话: %p\n", session);

      // 创建subscribe_announces消息
      xqc_moq_subscribe_namespace_msg_t subscribe_namespace;
      memset (&subscribe_namespace, 0, sizeof (subscribe_namespace));

      // 设置track_namespace_prefix
      subscribe_namespace.track_namespace_prefix
          = xqc_calloc (1, sizeof (xqc_moq_msg_track_namespace_t));
      if (!subscribe_namespace.track_namespace_prefix)
        {
          printf ("Failed to allocate track_namespace_prefix\n");
          return;
        }

      subscribe_namespace.track_namespace_prefix->track_namespace_num = 1;
      subscribe_namespace.track_namespace_prefix->track_namespace_len
          = xqc_calloc (1, sizeof (uint64_t));
      if (!subscribe_namespace.track_namespace_prefix->track_namespace_len)
        {
          xqc_free (subscribe_namespace.track_namespace_prefix);
          printf ("Failed to allocate track_namespace_len\n");
          return;
        }

      subscribe_namespace.track_namespace_prefix->track_namespace
          = xqc_calloc (1, sizeof (char *));
      if (!subscribe_namespace.track_namespace_prefix->track_namespace)
        {
          xqc_free (
              subscribe_namespace.track_namespace_prefix->track_namespace_len);
          xqc_free (subscribe_namespace.track_namespace_prefix);
          printf ("Failed to allocate track_namespace\n");
          return;
        }

      // 设置为通配符，订阅所有namespace
      const char *namespace_prefix = "moq";
      subscribe_namespace.track_namespace_prefix->track_namespace_len[0]
          = strlen (namespace_prefix);
      subscribe_namespace.track_namespace_prefix->track_namespace[0]
          = xqc_calloc (1, strlen (namespace_prefix) + 1);
      if (!subscribe_namespace.track_namespace_prefix->track_namespace[0])
        {
          xqc_free (
              subscribe_namespace.track_namespace_prefix->track_namespace);
          xqc_free (
              subscribe_namespace.track_namespace_prefix->track_namespace_len);
          xqc_free (subscribe_namespace.track_namespace_prefix);
          printf ("Failed to allocate track_namespace[0]\n");
          return;
        }

      strcpy (subscribe_namespace.track_namespace_prefix->track_namespace[0],
              namespace_prefix);

      // 重要：确保params为NULL，避免解码时尝试读取无效内存
      subscribe_namespace.params = NULL;
      subscribe_namespace.request_id = 1;
      printf (
          "  - namespace[0]: %s (len: %" PRIu64 ")\n",
          subscribe_namespace.track_namespace_prefix->track_namespace[0],
          subscribe_namespace.track_namespace_prefix->track_namespace_len[0]);

      // 发送消息
      printf ("调用xqc_moq_write_subscribe_announces发送消息...\n");
      xqc_int_t ret
          = xqc_moq_write_subscribe_namespace (session, &subscribe_namespace);
      if (ret < 0)
        {
          printf ("Failed to send subscribe_announces message: %d\n", ret);
        }
      else
        {
          printf ("Subscribe Announces message sent successfully, ret = %d\n",
                  ret);
        }

      // 清理资源
      xqc_free (
          subscribe_namespace.track_namespace_prefix->track_namespace[0]);
      xqc_free (subscribe_namespace.track_namespace_prefix->track_namespace);
      xqc_free (
          subscribe_namespace.track_namespace_prefix->track_namespace_len);
      xqc_free (subscribe_namespace.track_namespace_prefix);

      printf ("=== Subscribe Announces消息发送完成 ===\n\n");
    }
  else
    {
      // 中继模式：等待上游发布track
      printf ("\n=== Relay Mode: Waiting for Upstream Tracks ===\n");
      printf ("Relay connected to upstream server, waiting for track announcements...\n");
      printf ("Will automatically forward upstream announces to downstream subscribers\n");
      printf ("=== Relay Waiting Mode Activated ===\n\n");
    }
}

void
on_subscribe_ok (xqc_moq_user_session_t *user_session,
                 xqc_moq_subscribe_ok_msg_t *subscribe_ok)
{
  DEBUG;
  printf ("recv_subscribe_ok\n");
}

int
xqc_client_conn_create_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                               void *user_data, void *conn_proto_data)
{
  DEBUG;
  xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
  relay_user_conn_t *relay_conn = (relay_user_conn_t *)user_session->data;

  relay_conn->is_from_upstream = 1;

  xqc_moq_session_callbacks_t callbacks = {
    .on_session_setup = on_client_session_setup,
    .on_datachannel = on_datachannel,
    .on_datachannel_msg = on_datachannel_msg,
    /* For Publisher */
    // .on_request_keyframe = on_request_keyframe,
    // /* For Subscriber */
    .on_subscribe_ok = on_subscribe_ok,
    // .on_subscribe_error = on_subscribe_error,
    // .on_catalog = on_catalog,
    // .on_video = on_video_frame,
    .on_audio = on_audio_frame,
    .on_datagram = on_object_datagram,
    .on_announce = on_announce,
    .on_announce_ok = on_announce_ok,
    .on_subscribe_namespace = on_subscribe_namespace, // 确保此回调已设置
  };

  printf ("客户端回调函数已设置，包括on_subscribe_namespace=%p\n",
          on_subscribe_namespace);

  xqc_moq_session_t *session = xqc_moq_session_create (
      conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14,
      g_ctx.role, callbacks, "extdata");
  if (session == NULL)
    {
      printf ("create session error\n");
      return -1;
    }
  xqc_moq_configure_bitrate (session, 1000000, 8000000, 1000000);
  return 0;
}

int
xqc_client_conn_close_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                              void *user_data, void *conn_proto_data)
{
  DEBUG;
  if (user_data)
    {
      xqc_moq_user_session_t *user_session
          = (xqc_moq_user_session_t *)user_data;
      user_conn_t *user_conn = (user_conn_t *)user_session->data;
      xqc_conn_stats_t stats
          = xqc_conn_get_stats (g_ctx.client_ctx.engine, cid);

      printf ("Client connection closed: send_count:%u, recv_count:%u\n",
              stats.send_count, stats.recv_count);

      // 先取消定时器事件，防止在释放内存后仍然尝试访问
      if (user_conn && user_conn->ev_send_timer)
        {
          event_del (user_conn->ev_send_timer);
          event_free (user_conn->ev_send_timer);
          user_conn->ev_send_timer = NULL;
        }

      if (user_session->session)
        {
          // 清理subscribe_announces和announced_tracks相关记录
          remove_subscribe_announces_entries_for_session (
              user_session->session);
          remove_announced_tracks_for_session (user_session->session);

          xqc_moq_session_destroy (user_session->session);
        }
      free (user_session);
    }

  if (g_ctx.mode == MODE_CLIENT)
    {
      event_base_loopbreak (g_ctx.eb);
    }

  return 0;
}

void
xqc_client_conn_handshake_finished (xqc_connection_t *conn, void *user_data,
                                    void *conn_proto_data)
{
  DEBUG;
  printf ("=== Client Handshake Completed, Establishing Upstream MOQ Session ===\n");

  xqc_moq_user_session_t *user_session = (xqc_moq_user_session_t *)user_data;
  if (!user_session)
    {
      printf ("Error: user_session is NULL in client handshake finished\n");
      return;
    }

  // 创建MOQ会话回调
  xqc_moq_session_callbacks_t callbacks = {
    .on_session_setup = on_client_session_setup,
    .on_datachannel = on_datachannel,
    .on_datachannel_msg = on_datachannel_msg,
    .on_datagram = on_object_datagram,
    .on_announce = on_announce,
    .on_announce_ok = on_announce_ok,
    .on_subscribe = on_subscribe,
    .on_subscribe_ok = on_subscribe_ok,
    .on_subscribe_namespace = on_subscribe_namespace,
    .on_audio = on_audio_frame,
  };

  // 创建上游MOQ会话
  xqc_moq_session_t *session = xqc_moq_session_create (
      conn, user_session, XQC_MOQ_TRANSPORT_QUIC, XQC_MOQ_SUPPORTED_VERSION_14,
      XQC_MOQ_SUBSCRIBER, callbacks, "relay-upstream");
  if (session == NULL)
    {
      printf ("Failed to create upstream MOQ session\n");
      return;
    }

  // 设置全局上游session
  g_upstream_session = session;
  printf ("Upstream MOQ session established successfully, session: %p\n", session);

  xqc_moq_configure_bitrate (session, 1000000, 8000000, 1000000);
}

/* ============================ Server connection callbacks
 * ============================ */

int
xqc_server_conn_create_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                               void *user_data, void *conn_proto_data)
{
  DEBUG;
  printf ("Server connection created\n");
  return 0;
}

int
xqc_server_conn_close_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                              void *user_data, void *conn_proto_data)
{
  DEBUG;
  if (user_data)
    {
      xqc_moq_user_session_t *user_session
          = (xqc_moq_user_session_t *)user_data;
      user_conn_t *user_conn = (user_conn_t *)user_session->data;
      xqc_conn_stats_t stats
          = xqc_conn_get_stats (g_ctx.server_ctx.engine, cid);

      printf ("Server connection closed: send_count:%u, recv_count:%u\n",
              stats.send_count, stats.recv_count);

      // 先取消定时器事件，防止在释放内存后仍然尝试访问
      if (user_conn && user_conn->ev_send_timer)
        {
          event_del (user_conn->ev_send_timer);
          event_free (user_conn->ev_send_timer);
          user_conn->ev_send_timer = NULL;
        }

      if (user_session->session)
        {
          // 清理subscribe_announces和announced_tracks相关记录
          remove_subscribe_announces_entries_for_session (
              user_session->session);
          remove_announced_tracks_for_session (user_session->session);

          xqc_moq_session_destroy (user_session->session);
        }
      free (user_session);
    }
  return 0;
}

int
xqc_server_conn_closing_notify (xqc_connection_t *conn, const xqc_cid_t *cid,
                                xqc_int_t err_code, void *conn_user_data)
{
  DEBUG;
  printf ("Server connection closing with error code: %d\n", err_code);
  return XQC_OK;
}

void
xqc_server_conn_handshake_finished (xqc_connection_t *conn, void *user_data,
                                    void *conn_proto_data)
{
  DEBUG;
  printf ("Server handshake completed successfully\n");
}

/* ============================ Data send callback ============================
 */

void
xqc_app_send_callback (int fd, short what, void *arg)
{
  user_conn_t *user_conn = (user_conn_t *)arg;
  relay_user_conn_t *relay_conn = (relay_user_conn_t *)user_conn;
  xqc_int_t ret;

  // 检查是否已达到发送帧数上限
  if (user_conn->countdown-- <= 0)
    {
      printf ("Reached frame limit, closing connection\n");

      if (user_conn->moq_session)
        {
          xqc_moq_write_goaway (user_conn->moq_session, 0, NULL);
        }

      if (relay_conn->is_from_upstream)
        {
          xqc_conn_close (g_ctx.client_ctx.engine, &user_conn->cid);
        }
      else
        {
          xqc_conn_close (g_ctx.server_ctx.engine, &user_conn->cid);
        }
      return;
    }

  // if(user_conn->clock_subscribe_id != -1 && user_conn->moq_session != NULL)
  // {
  //     static uint64_t clock_count = 0;
  //     user_conn->object_id++;
  //     char *clock_info = xqc_now_spec();
  //     printf("timestamp for now: %s, count: %"PRIu64"\n", clock_info,
  //     ++clock_count); char buf[1024];
  //     // 将clock_info写入buf
  //     snprintf(buf, sizeof(buf), "%s", clock_info);
  //     ret = xqc_moq_write_subgroup_msg(user_conn->moq_session,
  //     user_conn->clock_subscribe_id, user_conn->clock_track,
  //                                     (uint8_t*)buf, strlen(buf));
  //     if(ret < 0) {
  //         printf("xqc_moq_write_subgroup_msg error\n");
  //         return;
  //     }

  //     // send datagram
  //     ret = xqc_moq_write_object_datagram(user_conn->moq_session, 0, 0,
  //     user_conn->object_id, 0, (uint8_t*)buf, strlen(buf)); if(ret < 0) {
  //         printf("xqc_moq_write_object_datagram error\n");
  //         return;
  //     }
  // }

  struct timeval time = { 1, 0 };
  event_add (user_conn->ev_send_timer, &time);
}

void
stop (int signo)
{
  printf ("Received signal %d, stopping...\n", signo);
  event_base_loopbreak (g_ctx.eb);

  if (g_ctx.mode == MODE_CLIENT || g_ctx.mode == MODE_RELAY)
    {
      xqc_engine_destroy (g_ctx.client_ctx.engine);
    }

  if (g_ctx.mode == MODE_SERVER || g_ctx.mode == MODE_RELAY)
    {
      xqc_engine_destroy (g_ctx.server_ctx.engine);
    }

  fflush (stdout);
  exit (0);
}

int
init_server_engine ()
{
  xqc_engine_ssl_config_t engine_ssl_config;
  memset (&engine_ssl_config, 0, sizeof (engine_ssl_config));
  engine_ssl_config.private_key_file = "./server.key";
  engine_ssl_config.cert_file = "./server.crt";
  engine_ssl_config.ciphers = XQC_TLS_CIPHERS;
  engine_ssl_config.groups = XQC_TLS_GROUPS;

  xqc_conn_settings_t conn_settings = {
        .cong_ctrl_callback = xqc_bbr_cb,
        .cc_params = {
            .customize_on = 1, 
            .bbr_ignore_app_limit = 1,
        },
        .max_datagram_frame_size = 1024,
    };

  xqc_config_t config;
  if (xqc_engine_get_default_config (&config, XQC_ENGINE_SERVER) < 0)
    {
      return -1;
    }
  config.cid_len = 12;

  xqc_app_set_log_level ('d', &config);

  xqc_engine_callback_t callback = {
        .set_event_timer = xqc_app_set_event_timer,
        .log_callbacks = {
            .xqc_log_write_err = xqc_app_write_log,
            .xqc_log_write_stat = xqc_app_write_log,
        },
    };

  xqc_transport_callbacks_t tcbs = {
    .server_accept = xqc_server_accept,
    .server_refuse = xqc_server_refuse,
    .write_socket = xqc_app_write_socket,
    .conn_closing = xqc_server_conn_closing_notify,
  };

  g_ctx.server_ctx.engine
      = xqc_engine_create (XQC_ENGINE_SERVER, &config, &engine_ssl_config,
                           &callback, &tcbs, &g_ctx.server_ctx);
  if (g_ctx.server_ctx.engine == NULL)
    {
      printf ("Error creating server engine\n");
      return -1;
    }

  xqc_server_set_conn_settings (g_ctx.server_ctx.engine, &conn_settings);

  xqc_conn_callbacks_t conn_cbs = {
    .conn_create_notify = xqc_server_conn_create_notify,
    .conn_close_notify = xqc_server_conn_close_notify,
    .conn_handshake_finished = xqc_server_conn_handshake_finished,
  };
  xqc_moq_init_alpn_by_custom (g_ctx.server_ctx.engine, &conn_cbs,
                               XQC_MOQ_TRANSPORT_QUIC,
                               XQC_MOQ_SUPPORTED_VERSION_14);

  return 0;
}

int
init_client_engine ()
{
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

  xqc_app_set_log_level ('d', &config);
  config.cid_len = 12;

  g_ctx.client_ctx.engine
      = xqc_engine_create (XQC_ENGINE_CLIENT, &config, &engine_ssl_config,
                           &callback, &tcbs, &g_ctx.client_ctx);
  if (g_ctx.client_ctx.engine == NULL)
    {
      printf ("Error creating client engine\n");
      return -1;
    }

  xqc_conn_callbacks_t conn_cbs = {
    .conn_create_notify = xqc_client_conn_create_notify,
    .conn_close_notify = xqc_client_conn_close_notify,
    .conn_handshake_finished = xqc_client_conn_handshake_finished,
  };
  xqc_moq_init_alpn_by_custom (g_ctx.client_ctx.engine, &conn_cbs,
                               XQC_MOQ_TRANSPORT_QUIC,
                               XQC_MOQ_SUPPORTED_VERSION_14);

  return 0;
}

int
create_client_connection (const char *server_addr, int server_port)
{
  printf ("Attempting to create client connection to %s:%d\n", server_addr,
          server_port);

  if (!g_ctx.client_ctx.engine)
    {
      printf ("Error: Client engine is NULL\n");
      return -1;
    }

  xqc_moq_user_session_t *user_session = calloc (
      1, sizeof (xqc_moq_user_session_t) + sizeof (relay_user_conn_t));
  if (!user_session)
    {
      printf ("Failed to allocate user_session memory\n");
      return -1;
    }

  relay_user_conn_t *relay_conn = (relay_user_conn_t *)user_session->data;
  relay_conn->is_from_upstream = 1;

  printf ("Initializing client address...\n");
  xqc_client_init_addr (&relay_conn->base, server_addr, server_port);

  if (!relay_conn->base.peer_addr)
    {
      printf ("Error: Failed to initialize peer address\n");
      free (user_session);
      return -1;
    }

  printf ("Creating client socket...\n");
  int ret = xqc_client_create_conn_socket (&relay_conn->base);
  if (ret < 0)
    {
      printf ("Failed to create client connection socket: %d\n", ret);
      if (relay_conn->base.peer_addr)
        free (relay_conn->base.peer_addr);
      if (relay_conn->base.local_addr)
        free (relay_conn->base.local_addr);
      free (user_session);
      return -1;
    }
  printf ("Client socket created successfully\n");

  xqc_conn_settings_t conn_settings = { 0 };
  conn_settings.cong_ctrl_callback = xqc_bbr_cb;
  conn_settings.cc_params.customize_on = 1;
  conn_settings.cc_params.bbr_ignore_app_limit = 1;
  conn_settings.proto_version = XQC_VERSION_V1;
  conn_settings.max_datagram_frame_size = 1024;

  xqc_conn_ssl_config_t conn_ssl_config;
  memset (&conn_ssl_config, 0, sizeof (conn_ssl_config));
  conn_ssl_config.cert_verify_flag |= XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED;

  printf ("Calling xqc_connect...\n");
  const xqc_cid_t *cid;

  // 打印调试信息
  printf ("Debug - Engine: %p\n", g_ctx.client_ctx.engine);
  printf ("Debug - server_addr: %s\n", server_addr);
  printf ("Debug - peer_addr: %p\n", relay_conn->base.peer_addr);
  printf ("Debug - peer_addrlen: %d\n", (int)relay_conn->base.peer_addrlen);
  printf ("Debug - ALPN: %s\n", XQC_ALPN_MOQ_QUIC_V14);

  cid = xqc_connect (g_ctx.client_ctx.engine, &conn_settings, NULL, 0,
                     server_addr, 0, &conn_ssl_config,
                     relay_conn->base.peer_addr, relay_conn->base.peer_addrlen,
                     XQC_ALPN_MOQ_QUIC_V14, user_session);

  if (!cid)
    {
      printf ("xqc_connect failed - returned NULL\n");
      printf ("Engine: %p, peer_addr: %p, peer_addrlen: %d\n",
              g_ctx.client_ctx.engine, relay_conn->base.peer_addr,
              (int)relay_conn->base.peer_addrlen);

      // 清理socket
      if (relay_conn->base.ev_socket)
        {
          event_free (relay_conn->base.ev_socket);
        }
      if (relay_conn->base.fd >= 0)
        {
          close (relay_conn->base.fd);
        }
      if (relay_conn->base.peer_addr)
        {
          free (relay_conn->base.peer_addr);
        }
      if (relay_conn->base.local_addr)
        {
          free (relay_conn->base.local_addr);
        }
      free (user_session);
      return -1;
    }

  memcpy (&relay_conn->base.cid, cid, sizeof (xqc_cid_t));
  printf ("Client connection initiated successfully to %s:%d\n", server_addr,
          server_port);

  return 0;
}

void
xqc_connection_retry_callback (int fd, short what, void *arg)
{
  connection_retry_t *retry_ctx = (connection_retry_t *)arg;

  retry_ctx->retry_count++;

  if (retry_ctx->retry_count >= retry_ctx->max_retries)
    {
      printf ("Maximum retry attempts (%d) reached, giving up.\n",
              retry_ctx->max_retries);
      event_free (retry_ctx->retry_timer);
      return;
    }

  printf ("Retry attempt %d/%d connecting to %s:%d\n", retry_ctx->retry_count,
          retry_ctx->max_retries, retry_ctx->server_addr,
          retry_ctx->server_port);

  if (create_client_connection (retry_ctx->server_addr, retry_ctx->server_port)
      == 0)
    {
      printf ("Connection successfully established after %d retries\n",
              retry_ctx->retry_count);
      event_free (retry_ctx->retry_timer);
      return;
    }

  // 指数退避策略
  struct timeval tv;
  int wait_time = 1 << (retry_ctx->retry_count - 1);
  if (wait_time > 30)
    wait_time = 30;

  tv.tv_sec = wait_time;
  tv.tv_usec = 0;

  printf ("Connection failed, will retry in %d seconds\n", wait_time);
  event_add (retry_ctx->retry_timer, &tv);
}

// 尝试重试连接
void
init_connection_retry (const char *server_addr, int server_port,
                       int max_retries)
{
  memset (&g_retry_ctx, 0, sizeof (connection_retry_t));
  strncpy (g_retry_ctx.server_addr, server_addr,
           sizeof (g_retry_ctx.server_addr) - 1);
  g_retry_ctx.server_port = server_port;
  g_retry_ctx.retry_count = 0;
  g_retry_ctx.max_retries = max_retries;

  g_retry_ctx.retry_timer
      = evtimer_new (g_ctx.eb, xqc_connection_retry_callback, &g_retry_ctx);
}

int
main (int argc, char *argv[])
{
  signal (SIGINT, stop);
  signal (SIGTERM, stop);

  memset (&g_ctx, 0, sizeof (g_ctx));
  g_ctx.role = XQC_MOQ_PUBSUB;
  g_ctx.frame_num = 100;
  g_ctx.mode = MODE_RELAY;    // 默认Relay
  g_ctx.connect_upstream = 0; // 默认不连接上游服务器

  char server_addr[64] = SERVER_ADDR;
  int server_port = SERVER_PORT;
  char client_remote_addr[64] = CLIENT_REMOTE_ADDR;
  int client_remote_port = CLIENT_REMOTE_PORT;

  int ch = 0;
  while ((ch = getopt (argc, argv, "m:r:p:c:n:a:s:u")) != -1)
    {
      switch (ch)
        {
        case 'm':
          if (strcmp (optarg, "client") == 0)
            {
              g_ctx.mode = MODE_CLIENT;
            }
          else if (strcmp (optarg, "server") == 0)
            {
              g_ctx.mode = MODE_SERVER;
            }
          else if (strcmp (optarg, "relay") == 0)
            {
              g_ctx.mode = MODE_RELAY;
            }
          else
            {
              printf ("Unknown mode: %s\n", optarg);
              return -1;
            }
          break;
        case 'r':
          if (strcmp (optarg, "pub") == 0)
            {
              g_ctx.role = XQC_MOQ_PUBLISHER;
              printf ("Role set to PUBLISHER\n");
            }
          else if (strcmp (optarg, "sub") == 0)
            {
              g_ctx.role = XQC_MOQ_SUBSCRIBER;
              printf ("Role set to SUBSCRIBER\n");
            }
          else if (strcmp (optarg, "pubsub") == 0)
            {
              g_ctx.role = XQC_MOQ_PUBSUB;
              printf ("Role set to PUBSUB\n");
            }
          else
            {
              printf ("Unknown role: %s\n", optarg);
              return -1;
            }
          break;
        case 'p': /* 服务器端口 */
          server_port = atoi (optarg);
          break;
        case 'c': /* 客户端连接的远程端口 */
          client_remote_port = atoi (optarg);
          break;
        case 's': /* 客户端连接的远程端口 (sport选项) */
          client_remote_port = atoi (optarg);
          g_ctx.connect_upstream = 1; // 设置连接上游服务器标志
          break;
        case 'n': /* 发送帧数 */
          g_ctx.frame_num = atoi (optarg);
          break;
        case 'a': /* 服务器地址 */
          snprintf (server_addr, sizeof (server_addr), "%s", optarg);
          break;
        case 'u': /* 连接上游服务器 */
          g_ctx.connect_upstream = 1;
          break;
        default:
          printf ("Usage: %s [-m mode] [-r role] [-p server_port] [-c "
                  "client_remote_port] [-s client_remote_port] [-n frame_num] "
                  "[-a server_addr] [-u]\n",
                  argv[0]);
          printf ("  -m mode: client, server, relay (default: relay)\n");
          printf ("  -r role: pub, sub, pubsub (default: pubsub)\n");
          printf ("  -p server_port: server listening port (default: 2445)\n");
          printf ("  -c client_remote_port: client connection remote port "
                  "(default: 4433)\n");
          printf ("  -s client_remote_port: same as -c, client connection "
                  "remote port\n");
          printf ("  -n frame_num: number of frames to send (default: 100)\n");
          printf ("  -a server_addr: server address (default: 127.0.0.1)\n");
          printf ("  -u: connect to upstream server in relay mode (default: "
                  "false)\n");
          return -1;
        }
    }

  g_ctx.eb = event_base_new ();
  if (!g_ctx.eb)
    {
      printf ("Failed to create event base\n");
      return -1;
    }

  xqc_platform_init_env ();

  if (g_ctx.mode == MODE_SERVER || g_ctx.mode == MODE_RELAY)
    {
      xqc_app_open_log_file (&g_ctx.server_ctx, "./rslog");

      if (init_server_engine () != 0)
        {
          return -1;
        }

      g_ctx.server_ctx.listen_fd
          = xqc_server_create_socket (server_addr, server_port);
      if (g_ctx.server_ctx.listen_fd < 0)
        {
          printf ("Failed to create server socket\n");
          return -1;
        }

      g_ctx.server_ctx.ev_engine = event_new (
          g_ctx.eb, -1, 0, xqc_app_engine_callback, &g_ctx.server_ctx);
      g_ctx.server_ctx.ev_socket = event_new (
          g_ctx.eb, g_ctx.server_ctx.listen_fd, EV_READ | EV_PERSIST,
          xqc_server_socket_event_callback, &g_ctx.server_ctx);
      event_add (g_ctx.server_ctx.ev_socket, NULL);

      printf ("Server initialized on %s:%d\n", server_addr, server_port);
    }

  if (g_ctx.mode == MODE_CLIENT
      || (g_ctx.mode == MODE_RELAY && g_ctx.connect_upstream))
    {
      xqc_app_open_log_file (&g_ctx.client_ctx, "./rclog");

      if (init_client_engine () != 0)
        {
          return -1;
        }

      g_ctx.client_ctx.ev_engine = event_new (
          g_ctx.eb, -1, 0, xqc_app_engine_callback, &g_ctx.client_ctx);

      // 确保连接上游服务器
      printf ("准备连接上游服务器 %s:%d\n", client_remote_addr,
              client_remote_port);

      init_connection_retry (client_remote_addr, client_remote_port, 5);

      if (create_client_connection (client_remote_addr, client_remote_port)
          != 0)
        {
          printf ("Initial connection attempt failed, scheduling retry...\n");
          struct timeval tv = { 5, 0 }; // 5秒后重试
          event_add (g_retry_ctx.retry_timer, &tv);
        }
      else
        {
          printf ("成功发起到上游服务器的连接\n");
        }

      printf ("Client initialized to connect to %s:%d\n", client_remote_addr,
              client_remote_port);
    }

  switch (g_ctx.mode)
    {
    case MODE_CLIENT:
      printf ("Started in CLIENT mode, connecting to %s:%d\n",
              client_remote_addr, client_remote_port);
      break;
    case MODE_SERVER:
      printf ("Started in SERVER mode, listening on %s:%d\n", server_addr,
              server_port);
      break;
    case MODE_RELAY:
      if (g_ctx.connect_upstream)
        {
          printf ("Started in RELAY mode, listening on %s:%d and connecting "
                  "to %s:%d\n",
                  server_addr, server_port, client_remote_addr,
                  client_remote_port);
        }
      else
        {
          printf ("Started in RELAY mode (no upstream), listening on %s:%d\n",
                  server_addr, server_port);
        }
      break;
    }

  event_base_dispatch (g_ctx.eb);

  if (g_ctx.mode == MODE_CLIENT
      || (g_ctx.mode == MODE_RELAY && g_ctx.connect_upstream))
    {
      xqc_engine_destroy (g_ctx.client_ctx.engine);
    }

  if (g_ctx.mode == MODE_SERVER || g_ctx.mode == MODE_RELAY)
    {
      xqc_engine_destroy (g_ctx.server_ctx.engine);
    }

  printf ("Program terminated\n");
  return 0;
}