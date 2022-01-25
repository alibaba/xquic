# QUIC Transport APIs
## Macros
### Memory Restrictions
#### XQC_SUPPORT_VERSION_MAX
Max count of versions supported by XQUIC. actually XQUIC support draft-29 and QUIC version 1 right now.

#### XQC_RESET_TOKEN_MAX_KEY_LEN
Max length of stateless reset token supported by XQUIC.

#### XQC_MAX_SEND_MSG_ONCE
Max iovec count when sending data with xqc_send_mmsg_pt callback.

#### XQC_MAX_CID_LEN/XQC_MIN_CID_LEN
Max and Min length of connection id.

### Default Configurations
#### XQC_TLS_CIPHERS
Default tls cipher list, which will be used if application don't specify a cipher list.

#### XQC_TLS_GROUPS
Default tls curves list, which will be used if application don't specify a curves list.

### Values
#### XQC_TRUE/XQC_FALSE
Values for xqc_bool_t, stands for boolean values.

#### XQC_SOCKET_ERROR/XQC_SOCKET_EAGAIN
Error codes for write_socket and write_mmsg callback functions.

## Enums
### xqc_engine_type_t
Type of engine, according to the C/S role of application.
**​**

#### XQC_ENGINE_SERVER (0x00)
Server role.
**​**

#### XQC_ENGINE_CLIENT (0x01)
Client Role.

### xqc_proto_version_t
Supported QUIC versions by xquic.
**​**

#### XQC_IDRAFT_INIT_VER (0x00)
Initial version

#### XQC_VERSION_V1 (0x01)
Version defined by RFC 9000.

#### XQC_IDRAFT_VER_29 (0x02)
Draft version 29.

#### XQC_IDRAFT_VER_NEGOTIATION (0x03)
Version not supported, and shall be negotiated.

#### XQC_VERSION_MAX
Support version count.

### xqc_cert_verify_flag_e
Certificate verify flag.

#### XQC_TLS_CERT_FLAG_NEED_VERIFY (0x00)
Verify certificate.

#### XQC_TLS_CERT_FLAG_ALLOW_SELF_SIGNED (0x01)
Self-signed certificates is allowed.

### xqc_0rtt_flag_t
Statistics flag of 0-RTT packets during the lifetime of QUIC connection.

#### XQC_0RTT_NONE (0x00)
No 0-RTT packets were sent or received.

#### XQC_0RTT_ACCEPT (0x01)
0-RTT packets were accepted.

#### XQC_0RTT_REJECT (0x02)
0-RTT packets were rejected.

## Types
### xqc_engine_t
xquic engine, manages connections, alpn registrations, generic environmental config and callback functions. Instance of xqc_engine_t can be created by _**xqc_engine_create**_ and be destroyed by _**xqc_engine_destroy**_.

All xquic mechanisms depends on xqc_engint_t, including creating a QUIC connection. When using xquic, engine MUST be the first object to be created, and the last to be destroyed.


### xqc_connection_t
xquic connection, stands for QUIC connection.


### xqc_stream_t
xquic stream, stands for QUIC stream.


### xqc_msec_t/xqc_usec_t
timestamp definition, as microsecond and millisecond.


## Callback Functions
xquic divide its callback functions into 2 categories, Engine-Layer-Callback-Function and Connection-Layer-Callback-Function.

Engine-Layer-Callback-Function mainly handles the environmental events, like timer, log, timestamp, etc.
Connection-Layer-Callback-Function mainly handles the connection events, like connection creation, 

**ALPN implementation considerations**
In consideration of ALPN implementations, xquic divides Connection-Callback-Functions into Transport-Callback-Functions and ALPN-Callback-Functions.

Transport-Callback-Functions is the abstraction of QUIC Transport protocol event aggregation, mainly includes the common attributes of QUIC Transport protocol between different Application-Layer-Protocols, like session ticket, write socket, stateless reset, etc. No matter what ALPN is, these callback functions will directly interact with application.

ALPN-Callback-Functions mainly involves the concepts of connection and stream data, and includes connection event callback functions and stream event callback functions. These callback functions will interact with Application-Layer-Protocols first, then Application-Layer-Protocols will define its interaction with application.

As Transport-Callback-Functions are reusable, classification of these callback functions may help to reduce workload when implementing a new kind of Application-Layer-Protocol.

### Engine Callback Functions
#### xqc_timestamp_pt
```
typedef xqc_usec_t (*xqc_timestamp_pt)(void);
```
By default, xquic will use _**gettimeofday**_ to get the time. Unfortunately, on some operating systems, the result of this function might not be precise, and application might get other methods to get precise timestamp.
xqc_timestamp_pt callback function allows application to set its own timestamp, especially on embedded systems. This function will be triggered when doing congestion control,  setting timer, and timestamp in micro-second MUST be returned.

Setting this callback function is optional, if not set, xquic will use _**gettimeofday**_ to get timestamp.

#### xqc_set_event_timer_pt
```
typedef void (*xqc_set_event_timer_pt)(xqc_usec_t wake_after, void *engine_user_data);
```
xquic don't have an implementation of timer, but will notify application to set a timer with **_xqc_set_event_timer_pt_** callback function. applications shall implement the timer, and invoke **_xqc_engine_main_logic_** after timer expires.

This callback function MUST be set.

#### xqc_cid_generate_pt
```
typedef ssize_t (*xqc_cid_generate_pt)(const xqc_cid_t *ori_cid, uint8_t *cid_buf,
    size_t cid_buflen, void *engine_user_data);
```
Generate CID  callback function, will be triggered when creating new connection or generating new connection id.
The **_ori_cid_** parameter will be NULL when creating connection, and be the original cid generated before when retiring it or generating a new cid.

This callback function is optional. If this callback function is not set, xquic will generate cid by itself.

#### xqc_keylog_pt
```
typedef void (*xqc_keylog_pt)(const char *line, void *engine_user_data);
```
TLS keylog callback, is used on Wireshark to decrypt QUIC packets, and will be triggered when new early traffic secret/handshake traffic secret/traffic secret is available, and will be passed to application with parameter _line_.

This callback function is optional.


#### xqc_log_write_err/xqc_log_write_stat
```
void (*xqc_log_write_err)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
void (*xqc_log_write_stat)(xqc_log_level_t lvl, const void *buf, size_t size, void *engine_user_data);
```
xquic log callback functions. **_xqc_log_write_err_** will be triggered when there is a xquic error log with specified error log level, and **_xqc_log_write_stat_** will be triggered when updating rtt or closing a connection.

This callback function is optional.

### QUIC Connection Callback Functions
#### xqc_socket_write_pt/xqc_send_mmsg_pt
```
typedef ssize_t (*xqc_socket_write_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
typedef ssize_t (*xqc_send_mmsg_pt)(const struct iovec *msg_iov, unsigned int vlen,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *conn_user_data);
```
Write socket callback function, will be triggered when there is data need to be written to socket. Application shall send data to peer immediately after been notified. 

xquic provides 2 callback functions for writing data, xqc_socket_write_pt will be triggered everytime there is a QUIC packet, but xqc_send_mmsg_pt might be triggered with multiple QUIC packets, and these packet were stored in _msg_iov_ parameter.
xqc_send_mmsg_pt is designed to be used with sendmmsg, provides much more efficiency, with max size defined by **_XQC_MAX_SEND_MSG_ONCE_**. When using this feature, application shall set this callback, and enable **_sendmmsg_on_** parameter of **_xqc_config_t_** when initiating xqc_engine_t.

Application MUST implement at least one callback function, and if application choose to use xqc_send_mmsg_pt, it MUST also enable sendmmsg_on parameter from xqc_config_t.


#### xqc_server_accept_pt
```
typedef int (*xqc_server_accept_pt)(xqc_engine_t *engine, xqc_connection_t *conn,
    const xqc_cid_t *cid, void *user_data);
```
Accept QUIC connection callback function, which will be trigger when server initiating a new connection. Application MUST decide whether to accept this connection, by returning -1 to refuse connection while others to accept.


This callback function is mandatory for server.


#### xqc_stateless_reset_pt
```
typedef ssize_t (*xqc_stateless_reset_pt)(const unsigned char *buf, size_t size,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen, void *user_data);
```
Stateless reset callback function, which will be trigger when processing a UDP packet that is not relative to a QUIC connection.

This callback function is optional, if not set, will ignore packets that cause a stateless reset event.


#### xqc_conn_notify_pt
```
typedef int (*xqc_conn_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *conn_user_data);
```
QUIC connection event callback. This is a general type for QUIC connection events, including connection creation and closure, and will be triggered when creating or closing a QUIC connection.

This callback function is mandatory, which will be related to Application-Layer-Protocols.


#### xqc_stream_notify_pt
```
typedef int (*xqc_stream_notify_pt)(xqc_stream_t *stream, void *strm_user_data);
```
General callback function definition for stream create, close, read and write, will be invoked on stream creation, closure, read data, write data events. These event callback functions are defined in xqc_stream_callbacks_t.

Application MUST implement these callback functions defined in xqc_stream_callbacks_t.


#### xqc_save_token_pt
```
typedef void (*xqc_save_token_pt)(const unsigned char *token, uint32_t token_len,
    void *conn_user_data);
```
QUIC new token callback, will be triggered on receiving NEW_TOKEN frame. Application shall save the data from this callback function to device, and use the token as the parameter of future connection.
The token is used in future connections for address validation.

This callback function is strongly advised for client.

#### xqc_save_session_pt
```
typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);
typedef xqc_save_string_pt xqc_save_session_pt;
```
QUIC session ticket callback function, will be triggered on receiving New Session Ticket. Application shall save the data from this callback function to device, and can use the restored data in future connection to take advantage of resumption and 0-RTT feature.

This callback function is strongly advised for client.


#### xqc_save_trans_param_pt
```
typedef void (*xqc_save_string_pt)(const char *data, size_t data_len, void *conn_user_data);
typedef xqc_save_string_pt xqc_save_trans_param_pt;
```
QUIC transport parameter callback function, will be triggered on receiving server's Transport Parameters in Encrypted Extensions. Application shall save the data from this callback function to device, and can use the restored data in future connection to take advantage of resumption and 0-RTT feature.
xquic defines its own format of transport parameters, which is also human-readable.

This callback function is strongly advised for client.


#### xqc_handshake_finished_pt
```
typedef void (*xqc_handshake_finished_pt)(xqc_connection_t *conn, void *conn_user_data);
```
Handshake finished callback function, will be trigger when the QUIC connection handshake is completed, that is, when the TLS stack has both sent a Finished message and verified the peer's Finished message.
As handshake states are essential to a QUIC connection, handshake finish event is used in statistics and useful for debugging.


This callback function is strongly advised.

#### xqc_conn_ping_ack_notify_pt
```
typedef void (*xqc_conn_ping_ack_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *cid,
    void *ping_user_data, void *conn_user_data);
```
Notification of acknowledgement of application sent PING frame. xquic has a default max_idle_timeout of 120 seconds, and provide xqc_conn_send_ping interface to actively send PING frame to keep alive. This callback function will be triggered when ACK frame of application sent PING frame is received and processed, just to notify that PING was successful.


NOTICE: PING frame might be lost and can not be recovered, there might be no ACK for it, applications should not wait for ack notification of ping all the time, which might cost a lot of memory if connection persisted for very long time.

This callback function is advised for clients.

#### xqc_conn_update_cid_notify_pt
```
typedef void (*xqc_conn_update_cid_notify_pt)(xqc_connection_t *conn, const xqc_cid_t *retire_cid,
    const xqc_cid_t *new_cid, void *conn_user_data);
```
Connection ID update notification callback function, will be invoked when SCID changes. Application must remember the new_cid from this callback function.

This callback function is mandatory.

#### xqc_cert_verify_pt
```
typedef int (*xqc_cert_verify_pt)(const unsigned char *certs[], const size_t cert_len[],
    size_t certs_len, void *conn_user_data);
```
Certificate verify callback function, will be invoked on receiving peer's certificate.


This callback function is optional.

## Data types
### xqc_log_callbacks_t
xqc_log_callbacks_t is the aggregation of xquic log callback functions.
#### 
#### xqc_log_write_err
Trace log callback function, including XQC_LOG_FATAL, XQC_LOG_ERROR, XQC_LOG_WARN, XQC_LOG_STATS, XQC_LOG_INFO, XQC_LOG_DEBUG, xquic will output logs with the level higher or equal to the level configured.

#### xqc_log_write_stat
Statistics log callback function, will be triggered when write XQC_LOG_REPORT or XQC_LOG_STATS level logs. Invoked mainly on connection and stream closed.


### xqc_engine_callback_t
Aggregation of xquic Engine-Layer-Callback-Functions.

### xqc_transport_callbacks_t
xqc_transport_callbacks_t is the aggregation of xquic Transport-Callback-Functions. These callback functions are designed to be reusable between different Application-Layer-Protocol implementations.


### xqc_app_proto_callbacks_t
#### xqc_conn_callbacks_t
QUIC connection callback functions, belong to ALPN-Callback-Function category. Application-Layer-Protocols will always be concerned about basic connection events, like creation and closure.

Application-Layer-Protocols shall define its connection events. These functions will notify connection event to Application-Layer-Protocols first, then Application-Layer-Protocols shall convert the event to its definition.


#### xqc_stream_callbacks_t
QUIC stream callback functions, belong to ALPN-Callback-Function category. QUIC stream data is the content of Application-Layer-Protocols, for which Application-Layer-Protocols will have their own terms and definitions.

Besides, Application-Layer-Protocol implementations shall define its interfaces with application layer, just to transfer QUIC Transport events to its own events.

### xqc_config_t
Generic config for xquic, used to initialize an engine.

### xqc_conn_settings_t
#### xqc_cc_params_t
Congestion control settings.

#### xqc_cong_ctrl_callback_t
Definition of congestion control callback functions, applications may include its own congestion control algorithm, by implementing the callback functions included in this struct, and passing the implementation to xquic by _**xqc_server_set_conn_settings**_ or _**xqc_connect**_ interfaces with _**xqc_conn_settings_t**_ parameter.


#### xqc_conn_ssl_config_t
SSL config for xquic connections, mainly for xquic clients.

#### xqc_linger_t
xquic introduces a mechanism like _SO_LINGER_ option of tcp, will delay connection closing until all buffered data are sent.

### xqc_conn_stats_t
QUIC connection statistics information, including sending and receiving of transported data, network usage estimation, early data, connection error, etc.

see _**xqc_conn_get_stats**_.

## Interfaces
### Engine-Layer Interfaces
#### xqc_engine_create
```
xqc_engine_t *xqc_engine_create(xqc_engine_type_t engine_type,
    const xqc_config_t *engine_config,
    const xqc_engine_ssl_config_t *ssl_config,
    const xqc_engine_callback_t *engine_callback,
    const xqc_transport_callbacks_t *transport_cbs,
    void *user_data);
```
xqc_engine_create creates a new xqc_engine_t object.


Application can create one or more engines in a process, but multiple engines MUST NOT share one thread, as xquic is single-threaded.

#### xqc_engine_destroy
```
void xqc_engine_destroy(xqc_engine_t *engine);
```
Destroy an engine object.

When destroying engine, if there is any available connection, engine will close and destroy connections immediately.


#### xqc_engine_register_alpn
```
xqc_int_t xqc_engine_register_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len,
    xqc_app_proto_callbacks_t *ap_cbs);
```
Application-Layer-Protocols are designed to be extensible, and can be used as a plugin to provide more flexibility. AKA, ALPN registration is the abstraction of the Application-Layer-Protocols.

One xquic engine supports multiple Application-Layer-Protocol registrations, with name of Application-Layer-Protocol as the key, different Application-Layer-Protocols MUST have different names.

Once registered, the context of related Application-Layer-Protocol is setup and no more operations are needed during the lifetime of engine object. And when registered by server, this Application-Layer-Protocol will be used when receiving ClientHello from client to negotiate the Application-Layer-Protocol.

Applications can extend Application-Layer-Protocols by implementing xqc_app_proto_callbacks_t on their terms and definitions on QUIC connection and stream data.

#### xqc_engine_unregister_alpn
```
xqc_int_t xqc_engine_unregister_alpn(xqc_engine_t *engine, const char *alpn, size_t alpn_len);
```
Unregister an registered Application-Layer-Protocol, with Application-Layer-Protocol's name as the key


#### xqc_engine_get_default_config
```
xqc_int_t xqc_engine_get_default_config(xqc_config_t *config, xqc_engine_type_t engine_type);
```
Get the default config of xquic engine.

#### xqc_engine_set_config
```
xqc_int_t xqc_engine_set_config(xqc_engine_t *engine, const xqc_config_t *engine_config);
```
Configurate engine. 

#### xqc_server_set_conn_settings
```
void xqc_server_set_conn_settings(const xqc_conn_settings_t *settings);
```
Set default settings for xquic connections. New configurations will be effective for future created connections.


#### xqc_engine_set_log_level
```
void xqc_engine_set_log_level(xqc_engine_t *engine, xqc_log_level_t log_level);
```
Set log level of an engine. This can be called anytime during the lifetime of an engine.


#### xqc_engine_finish_recv/xqc_engine_recv_batch
```
void xqc_engine_finish_recv(xqc_engine_t *engine);
void xqc_engine_recv_batch(xqc_engine_t *engine, xqc_connection_t *conn);
```
Receive all data from socket and trigger engine event process flow.

#### xqc_dcid_str_by_scid
```
unsigned char *xqc_dcid_str_by_scid(xqc_engine_t *engine, const xqc_cid_t *scid);
```
Get Destination Connection ID of a connection with Source Connection ID.

If SCID is invalid, NULL will be returned.


#### xqc_engine_config_get_cid_len
```
uint8_t xqc_engine_config_get_cid_len(xqc_engine_t *engine);
```
Get configurated source connection id length


### Connection-Layer Interfaces
#### xqc_connect
```
const xqc_cid_t *xqc_connect(xqc_engine_t *engine,
    const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len,
    const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config,
    const struct sockaddr *peer_addr, socklen_t peer_addrlen,
    const char *alpn, void *user_data);
```
Create client QUIC connections instance and connect to server.

The returned _**xqc_cid_t**_ is the source connection id of endpoint's QUIC connection, shall be stored as the identification of connection. Source connection id might be changed in future, and application shall modify its stored source connection id value.


#### xqc_conn_close
```
xqc_int_t xqc_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);
```
Close xquic connection instance.

_xqc_conn_close_ will close the connection. xquic will send CONNECTION_CLOSE frame to peer and waiting for destruction. Application MUST not destroy its context related to xquic connection, until the connection close notify callback function is triggered.

#### xqc_conn_get_errno
```
xqc_int_t xqc_conn_get_errno(xqc_connection_t *conn);
```
Get error code of specified connection.


#### xqc_conn_set_transport_user_data
```
void xqc_conn_set_transport_user_data(xqc_connection_t *conn, void *user_data);
```
Set user_data for Transport callback functions.


#### xqc_conn_set_alp_user_data
```
void xqc_conn_set_alp_user_data(xqc_connection_t *conn, void *app_proto_user_data);
```
Set user_data for ALPN callback functions.  


#### xqc_conn_get_peer_addr
```
xqc_int_t xqc_conn_get_peer_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);
```
Get peer's address information.


#### xqc_conn_get_local_addr
```
xqc_int_t xqc_conn_get_local_addr(xqc_connection_t *conn, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *local_addr_len);
```
Get local address information.


#### xqc_conn_send_ping
```
xqc_int_t xqc_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);
```
Send PING to keep alive.

#### xqc_conn_is_ready_to_send_early_data
```
xqc_bool_t xqc_conn_is_ready_to_send_early_data(xqc_connection_t *conn);
```
Check if early data is ready to send.


#### xqc_conn_continue_send
```
xqc_int_t xqc_conn_continue_send(xqc_engine_t *engine, const xqc_cid_t *cid);
```
Continue sending.
If write socket is temporarily unavailable, data will be buffered in xquic. When write event is ready again, call xqc_conn_continue_send to continue to send data.

#### xqc_conn_get_stats
```
xqc_conn_stats_t xqc_conn_get_stats(xqc_engine_t *engine, const xqc_cid_t *cid);
```
Get statistics of a connection.


### Stream-Layer Interfaces
#### xqc_stream_create
```
xqc_stream_t *xqc_stream_create(xqc_engine_t *engine, const xqc_cid_t *cid, void *user_data);
```
Create a QUIC stream to send data.

#### xqc_stream_close
```
xqc_int_t xqc_stream_close(xqc_stream_t *stream);
```
Close a QUIC stream.


#### xqc_stream_set_user_data
```
void xqc_stream_set_user_data(xqc_stream_t *stream, void *user_data);
```
Set stream layer user_data.


#### xqc_get_conn_user_data_by_stream
```
void *xqc_get_conn_user_data_by_stream(xqc_stream_t *stream);
```
Get user_data of connection with stream instance, which could be the parameter of xqc_stream_create set by client, or the parameter of xqc_stream_set_user_data set by server.


#### xqc_stream_id
```
xqc_stream_id_t xqc_stream_id(xqc_stream_t *stream);
```
Get stream_id of a stream.


#### xqc_stream_recv
```
ssize_t xqc_stream_recv(xqc_stream_t *stream, unsigned char *recv_buf, size_t recv_buf_size,
    uint8_t *fin);
```
Receive data from a stream.


#### xqc_stream_send
```
ssize_t xqc_stream_send(xqc_stream_t *stream, unsigned char *send_data, size_t send_data_size,
    uint8_t fin);
```
Send data through a stream.


Application can send a single fin STREAM frame with send_data_len is 0.

### Global Interfaces
#### xqc_packet_parse_cid
```
xqc_int_t xqc_packet_parse_cid(xqc_cid_t *dcid, xqc_cid_t *scid, uint8_t cid_len,
                               const unsigned char *buf, size_t size);
```
Get cid from payload of a UDP packet.

#### xqc_cid_is_equal
```
xqc_int_t xqc_cid_is_equal(const xqc_cid_t *dst, const xqc_cid_t *src);
```
Compare two cids.
If equal, XQC_OK will be returned.

#### xqc_scid_str
```
unsigned char *xqc_scid_str(const xqc_cid_t *scid);
```
Transfer scid to human-readable string.

#### xqc_dcid_str
```
unsigned char *xqc_dcid_str(const xqc_cid_t *dcid);
```
Transfer dcid to human-readable string.


# HTTP/3 APIs
## Enums
### xqc_request_notify_flag_t
The read notify flag of _xqc_h3_request_read_notify_pt_ callback function.

#### XQC_REQ_NOTIFY_READ_NULL
Read header section flag, this will be set when there is nothing to read.

#### XQC_REQ_NOTIFY_READ_HEADER
Read header section flag, this will be set when the first HEADERS is processed.


#### XQC_REQ_NOTIFY_READ_BODY
Read body flag, this will be set when a DATA frame is processed.

#### XQC_REQ_NOTIFY_READ_TRAILER
Read trailer section flag, this will be set when trailer HEADERS frame is processed.

#### XQC_REQ_NOTIFY_READ_EMPTY_FIN
Read empty fin flag, notify callback will be triggered when a single fin frame is received while HEADERS and DATA were notified. This flag will NEVER be set with other flags.

### xqc_http3_nv_flag_t
Flags for name/value of input headers in xqc_h3_request_send_headers, could be used to optimize the usage of dynamic table.

#### XQC_HTTP_HEADER_FLAG_NONE
No flag is set. encode header with default strategy.

#### XQC_HTTP_HEADER_FLAG_NEVER_INDEX
header's name and value shall be encoded as literal, and shall never be indexed.

#### XQC_HTTP_HEADER_FLAG_NEVER_INDEX_VALUE
Header's value is variant and shall never be put into dynamic table and be indexed. this will reduce useless data in dynamic table and might increase the hit rate.

Some headers might be frequent but with different values, it is a waste to put these value into dynamic table. application layer can use this flag to tell QPACK not to put value into dynamic table.
## Types
### xqc_h3_conn_t
HTTP/3 connection, relies on QUIC Transport connection.

### xqc_h3_request_t
HTTP/3 request stream, relies on QUIC Transport bidirectional streams.

### Callback Functions
#### xqc_h3_conn_notify_pt
```
typedef int (*xqc_h3_conn_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid, 
    void *h3c_user_data);
```
Definition for http3 connection state callback function. including create and close.


#### xqc_h3_handshake_finished_pt
```
typedef void (*xqc_h3_handshake_finished_pt)(xqc_h3_conn_t *h3_conn, void *h3c_user_data);
```
Handshake complete callback function, will be triggered when QUIC Transport Handshake completes.


#### xqc_h3_conn_ping_ack_notify_pt
```
typedef void (*xqc_h3_conn_ping_ack_notify_pt)(xqc_h3_conn_t *h3_conn, const xqc_cid_t *cid,
    void *ping_user_data, void *h3c_user_data);
```
Notification of PING frame acknowledgment from peer. 


#### xqc_h3_request_notify_pt
```
typedef int (*xqc_h3_request_notify_pt)(xqc_h3_request_t *h3_request, void *h3s_user_data);
```
Generic request notify callback function, including request creation, closing, write events.


#### xqc_h3_request_read_notify_pt
```
typedef int (*xqc_h3_request_read_notify_pt)(xqc_h3_request_t *h3_request, 
    xqc_request_notify_flag_t flag, void *h3s_user_data);
```
Read data callback function, will be triggered when an entire HEADERS or DATA frame is received and decoded.

see _xqc_request_notify_flag_t_.

## Data Types
### xqc_http_header_t
Definition of http header.
#### name/value
The name and value of a http header.

#### flags
Header flags of xqc_http3_nv_flag_t with OR operator, see xqc_http3_nv_flag_t.


### xqc_http_headers_t
#### headers
Array of headers.

#### count
Number of headers.

#### capacity
Capacity of headers.

#### total_len
Sum of the length of names and values in headers array.


### xqc_request_stats_t
The statistics information of a request stream. see _xqc_h3_request_get_stats_.
#### send_body_size
Total size of sent body.

#### recv_body_size
Total size of received body.

#### send_header_size
Total size of sent headers.

#### recv_header_size
Total size of received headers.


#### stream_err
Error code of http3 request or QUIC Transport stream.


### xqc_h3_conn_settings_t
HTTP/3 connection settings.
#### max_field_section_size
SETTINGS_MAX_FIELD_SECTION_SIZE parameter of http3 settings frame.

#### max_pushes
Max push streams, which is actually not used.

#### qpack_max_table_capacity
SETTINGS_QPACK_MAX_TABLE_CAPACITY parameter of http3 settings frame.

#### qpack_blocked_streams
SETTINGS_QPACK_BLOCKED_STREAMS parameter of http3 settings frame.


### xqc_h3_conn_callbacks_t
Aggregation of http3 connection events.

#### h3_conn_create_notify
http3 connection creation callback, REQUIRED for server, OPTIONAL for client.

#### h3_conn_close_notify
http3 connection closing callback.


#### h3_conn_handshake_finished
handshake finished callback. which will be triggered when HANDSHAKE_DONE is received.

#### h3_conn_ping_acked
ping callback. which will be triggered when ping is acked.
This function is optional


### xqc_h3_request_callbacks_t
#### h3_request_create_notify
Request creation notify. it will be triggered after a request was created, and is required for server, optional for client.

#### h3_request_close_notify
Request close notify. which will be triggered after a request was closed.


#### h3_request_read_notify
request read notify callback. which will be triggered after received http headers or body.

#### h3_request_write_notify
Request write notify callback. when triggered, users can continue to send headers or body


### xqc_h3_callbacks_t
Aggregation of http3 connection and request callback functions. These callback functions are between http3 layer and application layer.

## Interfaces
### H3-Context Interfaces
H3-Context stores the address of callback functions between http3 layer and application layer.

#### xqc_h3_ctx_init
```
xqc_int_t xqc_h3_ctx_init(xqc_engine_t *engine, xqc_h3_callbacks_t *h3_cbs);
```
Initialize h3 context into xqc_engine_t, this MUST BE called before create any http3 connection.

#### xqc_h3_ctx_destroy
```
xqc_int_t xqc_h3_ctx_destroy(xqc_engine_t *engine);
```
Destroy h3 context, after this interface is invoked, h3 connection or h3 request MUST NOT be created.

#### xqc_h3_engine_set_max_dtable_capacity
```
void xqc_h3_engine_set_max_dtable_capacity(xqc_engine_t *engine, size_t capacity);
```
Set max h3 max dynamic table capacity. This function will only affect future created h3 connections, the existent h3 connections will not be influenced.


#### xqc_h3_engine_set_max_field_section_size
```
void xqc_h3_engine_set_max_field_section_size(xqc_engine_t *engine, size_t size);
```
Set max h3 field section size.


### H3-Connection Interfaces
#### xqc_h3_connect
```
const xqc_cid_t *xqc_h3_connect(xqc_engine_t *engine, const xqc_conn_settings_t *conn_settings,
    const unsigned char *token, unsigned token_len, const char *server_host, int no_crypto_flag,
    const xqc_conn_ssl_config_t *conn_ssl_config, const struct sockaddr *peer_addr,
    socklen_t peer_addrlen, void *user_data);
```
Create a http3 connection instance.
This interface is mainly designed for clients.

#### xqc_h3_conn_close
```
xqc_int_t xqc_h3_conn_close(xqc_engine_t *engine, const xqc_cid_t *cid);
```
Destroy a http connection instance.


#### xqc_h3_conn_get_xqc_conn
```
xqc_connection_t *xqc_h3_conn_get_xqc_conn(xqc_h3_conn_t *h3c);
```
Get instance of xquic's Transport connection, on which the instance of h3 is relied.


#### xqc_h3_conn_get_errno
```
xqc_int_t xqc_h3_conn_get_errno(xqc_h3_conn_t *h3c);
```
Get connection error code.


#### xqc_h3_conn_set_user_data
```
void xqc_h3_conn_set_user_data(xqc_h3_conn_t *h3c, void *user_data);
```
Set user_data for http3 connection, user_data could be the application layer context of  http3 connection.


#### xqc_h3_conn_set_settings
```
void xqc_h3_conn_set_settings(xqc_h3_conn_t *h3c,
    const xqc_h3_conn_settings_t *h3_conn_settings);
```
Set settings for h3 connection, users can invoke this functions when h3_conn_create_notify callback function is triggered.

#### xqc_h3_conn_get_peer_addr
```
xqc_int_t xqc_h3_conn_get_peer_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr, socklen_t addr_cap,
    socklen_t *peer_addr_len);
```
Get peer address information, server should call this when h3_conn_create_notify triggers.


#### xqc_h3_conn_get_local_addr
```
xqc_int_t xqc_h3_conn_get_local_addr(xqc_h3_conn_t *h3c, struct sockaddr *addr,  socklen_t addr_cap,
    socklen_t *local_addr_len);
```
Get local address information, server should call this when h3_conn_create_notify triggers.

#### xqc_h3_conn_send_ping
```
xqc_int_t xqc_h3_conn_send_ping(xqc_engine_t *engine, const xqc_cid_t *cid, void *ping_user_data);
```
Send PING to peer, if ack received, h3_conn_ping_acked will callback with user_data.

#### xqc_h3_conn_is_ready_to_send_early_data
```
xqc_bool_t xqc_h3_conn_is_ready_to_send_early_data(xqc_h3_conn_t *h3c);
```
Check if sending early data is available on h3 connection.


#### xqc_h3_conn_set_qpack_dtable_cap
```
xqc_int_t xqc_h3_conn_set_qpack_dtable_cap(xqc_h3_conn_t *h3c, size_t capacity);
```
Set dynamic table capacity of a existent h3 connection.
If capacity shrinks, and new capacity can't hold the inserted entries in the original dynamic table, the earliest entries will be erased.


### H3-Request Interfaces
#### xqc_h3_request_create
```
xqc_h3_request_t *xqc_h3_request_create(xqc_engine_t *engine, const xqc_cid_t *cid, 
    void *user_data);
```
Create a http3 request.

#### xqc_h3_request_close
```
xqc_int_t xqc_h3_request_close(xqc_h3_request_t *h3_request);

```
Close a http3 request.
After this interface is invoked, the destruction of http request instance will be notified through  h3_request_close_notify callback function.

#### xqc_h3_request_get_stats
```
xqc_request_stats_t xqc_h3_request_get_stats(xqc_h3_request_t *h3_request);
```
Get statistics information of h3 request. Application can invoke this interface anytime before request is destroyed, but MUST NOT invoke it after h3_request_close_notify function was triggered.


#### xqc_h3_request_set_user_data
```
void xqc_h3_request_set_user_data(xqc_h3_request_t *h3_request, void *user_data);
```
set user_data of a http3 request, which will be used as parameter of request callback functions.
Server should set user_data when h3_request_create_notify triggers, as connections on servers are passively created.


#### xqc_h3_request_send_headers
```
ssize_t xqc_h3_request_send_headers(xqc_h3_request_t *h3_request, xqc_http_headers_t *headers,
    uint8_t fin);
```
Send http headers to peer on a h3 request stream.


#### xqc_h3_request_send_body
```
ssize_t xqc_h3_request_send_body(xqc_h3_request_t *h3_request, unsigned char *data, 
    size_t data_size, uint8_t fin);
```
Send http body to the peer on a h3 request stream.

#### xqc_h3_request_finish
```
ssize_t xqc_h3_request_finish(xqc_h3_request_t *h3_request);
```
Finish request stream on endpoint's direction. if fin is not sent yet, and application has nothing to send anymore, call this function to send a QUIC STREAM frame with only fin. This might be useful when Trailer Section attribute is used.

If there is data in h3 request stream's send buffer, the fin will be attached with the last data block. If all the data were sent, xquic will send a QUIC Transport STREAM frame with zero-length data and fin set.

#### xqc_h3_request_recv_headers
```
xqc_http_headers_t *xqc_h3_request_recv_headers(xqc_h3_request_t *h3_request, uint8_t *fin);
```
Receive headers from a request. This function shall be invoked after h3_request_read_notify was triggered and XQC_REQ_NOTIFY_READ_HEADER or XQC_REQ_NOTIFY_READ_TRAILER flags are set.

As there will be only Header Section and Trailer Section on a h3 request stream, there will be at most 2 HEADERS frame, hence at most 2 headers can be received by application.

#### xqc_h3_request_recv_body
```
ssize_t xqc_h3_request_recv_body(xqc_h3_request_t *h3_request, unsigned char *recv_buf, 
    size_t recv_buf_size, uint8_t *fin);
```
Receive body from a request stream. This function shall be invoked after h3_request_read_notify was triggered and XQC_REQ_NOTIFY_READ_BODY flag is set.

Multiple DATA frames can be sent on a h3 request stream, application will be notified multiple times whenever a DATA frame is received and decoded.

xquic will fill the input recv_buf until all the data are copied or all the capacity of recv_buf is used, with the copied size as return value.


#### xqc_h3_get_conn_user_data_by_request
```
void *xqc_h3_get_conn_user_data_by_request(xqc_h3_request_t *h3_request);
```
Get connection's user_data by request


#### xqc_h3_stream_id
```
xqc_stream_id_t xqc_h3_stream_id(xqc_h3_request_t *h3_request);
```
Get the stream_id of QUIC Transport stream on which the h3 request stream relies.
