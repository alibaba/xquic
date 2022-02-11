# event_log 模块

## 模块介绍

event_log模块是log模块的扩展功能模块，目的是结合qlog规范定义的事件类型规范化日志打印。
qlog规范：https://datatracker.ietf.org/doc/draft-marx-qlog-event-definitions-quic-h3/

## 模块使用

### 开启event_log功能

#### 编译时

在cmake编译xquic时添加“-DXQC_ENABLE_EVENT_LOG=1”将编译event_log相关功能，默认状态不编译。

#### 运行时

通过xqc_engine_create函数创建engine对象时，根据传入的xqc_config_t对象的cfg_log_event参数选择是否启用event_log功能，当cfg_log_event>0时开启。

### 使用event_log功能

#### 调用事件日志打印

在事件发生的位置调用xqc_log_event函数

```C
xqc_log_event(log, 事件类型, 事件相关参数);
```

> 其中log为xqc_log_t对象，编译时会根据事件类型检查传入的事件相关参数与事件的回调函数格式是否符合。

现有qlog事件相关参数如下（详见xqc_log_event_callback.h）：

<table class=MsoNormalTable border=1 cellspacing=0 cellpadding=0 width=547
 style='width:410.4pt;border-collapse:collapse;border:none;mso-border-alt:solid #D9D9D9 .75pt;
 mso-yfti-tbllook:1184;mso-padding-alt:0cm 5.4pt 0cm 5.4pt'>
 <tr style='mso-yfti-irow:0;mso-yfti-firstrow:yes;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;mso-border-alt:
  solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal align=center style='text-align:center'>事件类型</p>
  </td>
  <td width=378 style='width:283.2pt;border:solid #D9D9D9 1.0pt;border-left:
  none;mso-border-left-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal align=center style='text-align:center'>事件相关参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:1;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>CON_CONNECTION_STARTED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_connection_t *conn, xqc_int_t local</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:2;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>CON_CONNECTION_CLOSED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_connection_t *conn</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:3;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>CON_CONNECTION_ID_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_connection_t *conn</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:4;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>CON_CONNECTION_STATE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_connection_t *conn</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:5;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>SEC_KEY_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_engine_ssl_config_t ssl_config,
  xqc_int_t local</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:6;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_VERSION_INFORMATION</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>uint32_t local_count, uint32_t *local_version,
  uint32_t remote_count, uint32_t *remote_version, uint32_t <span class=GramE>choose</span></span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:7;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_ALPN_INFORMATION</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>size_t local_count, uint8_t *local_alpn,
  size_t remote_count, const uint8_t *remote_alpn, size_t alpn_len, const
  unsigned char *alpn</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:8;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_PARAMETERS_SET</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_connection_t *conn, xqc_int_t local</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:9;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_PACKET_SENT</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_packet_out_t *packet_out</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:10;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_PACKET_RECEIVED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_packet_in_t *packet_in</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:11;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_PACKET_BUFFERED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_packet_in_t *packet_in</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:12;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_PACKETS_ACKED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_packet_in_t *packet_in,
  xqc_packet_number_t high, xqc_packet_number_t low</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:13;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_DATAGRAMS_SENT</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>ssize_t size</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:14;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_DATAGRAMS_RECEIVED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>ssize_t size</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:15;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_STREAM_STATE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_stream_t *stream, xqc_int_t
  stream_type, xqc_int_t state</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:16;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>TRA_FRAMES_PROCESSED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据<span lang=EN-US>frame</span>类型不同，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:17;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>REC_PARAMETERS_SET</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_send_ctl_t *ctl</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:18;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>REC_METRICS_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_send_ctl_t *ctl</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:19;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>REC_CONGESTION_STATE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>char *new_state</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:20;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>REC_LOSS_TIMER_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_send_ctl_t *ctl,</span></p>
  <p class=MsoNormal><span lang=EN-US>xqc_usec_t <span class=GramE>inter</span>_time,
  xqc_int_t type, xqc_int_t event</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:21;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>REC_PACKET_LOST</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_packet_out_t *packet_out</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:22;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_PARAMETERS_SET</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_h3_conn_t *h3_conn, xqc_int_t local</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:23;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_PARAMETERS_RESTORED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_h3_conn_t *h3_conn</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:24;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_STREAM_TYPE_SET</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_h3_stream_t *h3_stream, xqc_int_t
  local</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:25;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_FRAME_CREATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据<span lang=EN-US>frame</span>类型不同，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:26;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_FRAME_PARSED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_h3_stream_t *h3_stream</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:27;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>HTTP_SETTING_PARSED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>uint64_t identifier, uint64_t value</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:28;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_STATE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据类型属于编码器<span lang=EN-US>/</span>解码器，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:29;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_STREAM_STATE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>xqc_h3_stream_t *h3_stream</span></p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:30;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_DYNAMIC_TABLE_UPDATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据动态表插入<span lang=EN-US>/</span>删除，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:31;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_HEADERS_ENCODED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据<span lang=EN-US>prefix</span>和<span lang=EN-US>header</span>，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:32;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_HEADERS_DECODED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据<span lang=EN-US>prefix</span>和<span lang=EN-US>header</span>，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:33;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_INSTRUCTION_CREATED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据指令不同，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:34;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>QPACK_INSTRUCTION_PARSED</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal>根据指令不同，传入参数不同</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:35;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_REPORT</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>report</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:36;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_FATAL</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>fatal</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:37;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_ERROR</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>error</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:38;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_WARN</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>warn</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:39;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_STATS</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>stats</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:40;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_INFO</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>info</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
 <tr style='mso-yfti-irow:41;mso-yfti-lastrow:yes;height:24.25pt'>
  <td width=170 style='width:127.2pt;border:solid #D9D9D9 1.0pt;border-top:
  none;mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-alt:solid #D9D9D9 .75pt;
  padding:.75pt .75pt .75pt .75pt;height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>GEN_DEBUG</span></p>
  </td>
  <td width=378 style='width:283.2pt;border-top:none;border-left:none;
  border-bottom:solid #D9D9D9 1.0pt;border-right:solid #D9D9D9 1.0pt;
  mso-border-top-alt:solid #D9D9D9 .75pt;mso-border-left-alt:solid #D9D9D9 .75pt;
  mso-border-alt:solid #D9D9D9 .75pt;padding:.75pt .75pt .75pt .75pt;
  height:24.25pt'>
  <p class=MsoNormal><span lang=EN-US>debug</span>级别通用日志打印，类似<span lang=EN-US>printf</span>传入格式化字符串和参数</p>
  </td>
 </tr>
</table>

#### 注册新事件

在已实现的qlog事件基础上可根据实现特点和需求注册自定义的事件，注册新事件方法如下：

* 在xqc_log.h的xqc_log_type_t枚举类中添加事件名

```C
typedef enum {
    /* connectivity event */
    CON_SERVER_LISTENING,
    CON_CONNECTION_STARTED,
    CON_CONNECTION_CLOSED,
    CON_CONNECTION_ID_UPDATED,
    CON_SPIN_BIM_UPDATED,
    CON_CONNECTION_STATE_UPDATED,

    ... ...
} xqc_log_type_t;
```

* 在xqc_log.c的xqc_log_type_str函数中添加事件对应的事件名表示

```C
const char *
xqc_log_type_str(xqc_log_type_t type)
{
    static const char* event_type2str[] = {
            [CON_SERVER_LISTENING]              = "server_listening",
            [CON_CONNECTION_STARTED]            = "connection_started",
            [CON_CONNECTION_CLOSED]             = "connection_closed",
            [CON_CONNECTION_ID_UPDATED]         = "connection_id_updated",
            [CON_SPIN_BIM_UPDATED]              = "spin_bin_updated",
            [CON_CONNECTION_STATE_UPDATED]      = "connection_state_updated",
            
            ... ...
    };
    return event_type2str[type];
}
```

> 形如：\[事件类型\] = "事件名"

* 在xqc_log.c的xqc_log_type_2_level函数中设置事件的日志级别

```C
xqc_log_level_t
xqc_log_type_2_level(xqc_log_type_t type)
{
    switch (type) {
    case GEN_REPORT:
        return XQC_LOG_REPORT;
    case GEN_FATAL:
        return XQC_LOG_FATAL;
    case GEN_ERROR:
        return XQC_LOG_ERROR;
    case GEN_WARN:
        return XQC_LOG_WARN;
        
    ... ...
}
```

* 在xqc_log_event_callback.h中定义日志的回调函数，回调函数格式为

```C
xqc_log_事件类型_callback(xqc_log_t *log, const char *func, ...)
```

> 传参的log和func为固定参数，可选参数部分为事件相关的参数

* 在xqc_log_event_callback.c中实现日志的回调函数，根据事件类型规范日志格式并调用xqc_log_implement函数（定义在xqc_log.h中，使用方式类似printf函数）打印

```C
xqc_log_implement(log, 事件类型, func, 日志格式, 打印参数);
```

### event_log日志分析

#### 日志格式

```text
[时间] [事件名] |scid:所属连接的scid|打印日志的函数名|打印日志内容|
```

> 事件的具体打印内容和格式详见xqc_log_event_callback.c文件

常用grep:
> 过滤特定事件：grep "\[事件名\]"
>
> 过滤特定连接：grep "|scid:所属连接的scid|"

#### 后处理将日志转换为qlog格式

通过python等脚本语言将日志格式转变为qlog规范中定义的格式(.qlog) --- todo

借助 [qvis](https://qvis.quictools.info/#/files) （一个针对qlog规范的可视化工具）解析.qlog文件，方便使用者分析学习xquic的传输过程。
