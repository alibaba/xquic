# 摘要（Abstract）
本文定义了一个QUIC传输协议的扩展，以提供在QUIC连接上发送和接收不可靠数据报的支持。

# 备忘录状态（Status of This Memo）
本文是一个互联网标准跟踪文件。

本文是国际互联网工程任务组（IETF)的输出文档，代表了IETF社区的共识，已经过公众审查，并由互联网工程指导委员会（IESG)批准出版。有关互联网标准的更多资料，请参阅RFC7841第2节。

有关本文的当前状态、勘误表以及如何提供反馈信息，请参考（<https://www.rfc-editor.org/info/rfc9221>）。

# 版权声明（Copyright Notice）
版权所有（c) 2022年 IETF Trust和本文作者。保留所有权利。

本文受BCP 78和IETF Trust关于IETF文件的法律规定（<https://trustee.ietf.org/license-info>）约束，在本文发布之日起生效。请仔细阅读这些文件，其描述了您与本文相关的权利和限制。从本文中提取的代码组件必须包含 Trust Legal Provisions 第 4.e 节所述的修订版 BSD 许可证文本，并且遵循该许可证中的约定不提供任何保证。

# 1. 介绍（Introduction）
QUIC传输协议[RFC9000]为传输可靠的应用数据流提供了一个安全的、多路复用的连接。QUIC使用携带了多种类型帧的数据包传输数据，每种帧类型都约定了其所包含的数据在丢失后是否重传。需要可靠传输的应用数据流使用 STREAM 帧发送。

有些应用，尤其是需要传输实时数据的应用，更倾向于使用不可靠传输。过去这些应用直接依赖 UDP[RFC0768] 协议，并通过 DTLS[RFC6347] 协议增加安全性。这里扩展QUIC以支持传输不可靠应用数据，其可以与基于流的可靠传输，共享加密和身份验证上下文的额外好处，这为安全传输报文提供了另外一种选择。

本文为QUIC协议定义了两种新的 DATAGRAM 帧类型，用于传输不需要重传的应用数据。

## 1.1 文档约定（Specification of Requirements）
本文中用到的关键字"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL"当且仅当它们以如上所述全部大写字母出现时，才按照 BCP 14 [RFC2119] [RFC8174] 中的描述进行解释。

# 2. 动机（Motivation）
使用QUIC传输不可靠数据优于现有解决方案:

- 需要在两个端点间同时传输可靠流和不可靠数据报的应用，可以通过在QUIC上同时发送可靠数据帧和不可靠数据，共享单个握手和身份验证上下文而获益。与同时打开TLS连接和DTLS连接相比，这可以减少握手所需的延迟。

- QUIC使用了比DTLS握手更精细的丢包恢复机制，这可以更快地恢复QUIC丢失的数据包。

- QUIC数据报受QUIC拥塞算法控制，为可靠和不可靠数据传输提供单一的拥塞控制会更加有用且高效。

这些特性对于优化音频/视频流应用、游戏应用和其他实时网络应用非常有用。

QUIC不可靠传输也可以用于在QUIC上实现IP隧道，例如用于虚拟专用网（VPN)。网络层隧道协议通常需要一个可靠的和经过验证的握手，之后是不可靠IP数据包的安全传输。这可能需要控制数据走TLS连接，IP数据包走DTLS隧道。单一的QUIC连接可以同时支持可靠流及不可靠数据报传输两个部分。

# 3. 传输参数（Transport Parameter）
QUIC 可以用传输参数（name=max_datagram_frame_size，value=0x20）通告对接收 DATAGRAM 帧类型的支持。 max_datagram_frame_size 传输参数是一个整数值（表示为可变长度整数），其表示端点可以接收的 DATAGRAM 帧的最大长度（包括帧类型、长度和有效负载），以字节为单位。

此参数的默认值为 0，表示端点不支持 DATAGRAM 帧。大于 0 的值表示端点支持 DATAGRAM 帧类型并愿意在此连接上接收此类帧。

端点在握手期间（如果使用0-RTT，则是上一次握手期间），在未收到具有非零值的 max_datagram_frame_size 传输参数之前，不得（**MUST NOT**）发送 DATAGRAM 帧。端点不得（**MUST NOT**）发送大于对端通告的 max_datagram_frame_size 长度的 DATAGRAM 帧。如果端点未收到对端支持 DATAGRAM 帧的通告，则在收到 DATAGRAM 帧时必须（**MUST**）以 PROTOCOL_VIOLATION 类型错误终止连接。类似地，接收到大于其对端通告长度的 DATAGRAM 帧的端点也必须（**MUST**）以 PROTOCOL_VIOLATION 类型错误终止连接。

为方便 DATAGRAM 帧的使用，建议（**RECOMMENDED**）令 max_datagram_frame_size = 65535 以指示此端点可接受任何适合QUIC数据包大小的 DATAGRAM 帧。

max_datagram_frame_size 传输参数是单向限制，是对是否支持 DATAGRAM 帧的指示。使用 DATAGRAM 帧的应用可以（**MAY**）选择只在一个方向上协商和使用它们。

当客户端使用 0-RTT 时，可以（**MAY**）保存服务端的 max_datagram_frame_size 传输参数的值。这使得客户端可以在 0-RTT 数据包中发送 DATAGRAM 帧。当服务端决定接受 0-RTT 数据时，必须（**MUST**）发送一个 max_datagram_frame_size 传输参数，其值大于或等于在发送 NewSessionTicket 消息的连接中发给客户端的值。客户端在 0-RTT 状态下，在保存握手期间服务端新通告的 max_datagram_frame_size 传输参数时，必须（**MUST**）验证新值是否大于或等于之前保存的值，如果不是，客户端必须（**MUST**）终止连接并返回错误码 PROTOCOL_VIOLATION。

使用 DATAGRAM 帧的应用协议必须定义它们对缺少 max_datagram_frame_size 传输参数的处置措施。如果应用集成 DATAGRAM 支持，而对端未通告 max_datagram_frame_size 传输参数，则应用协议可能直接在握手阶段挂掉连接。

# 4. DATAGRAM 帧类型（Datagram Frame Types）
DATAGRAM 帧用于以不可靠的方式传输应用数据。 DATAGRAM 帧中的 Type 字段采用 0b0011000X 的形式（或值 0x30 和 0x31）。 DATAGRAM 帧中 Type 字段的最低位是 LEN 位（0x01），表示是否存在 Length 字段：如果该位设置为 0，则 Length 字段不存在，Datagram Data 字段扩展到数据包的末尾； 如果该位设置为 1，则存在长度字段。

DATAGRAM 帧结构如下所示：
```
DATAGRAM Frame {
  Type （i) = 0x30..0x31,
  [Length （i)],
  Datagram Data （..),
}
```
图1: DATAGRAM 帧格式

DATAGRAM 帧包含如下字段：

Length：长度，一个可变长度整数，指定 Datagram Data 字段的长度（以字节为单位）。 该字段仅在 LEN 位设置为 1 时存在。当 LEN 位设置为 0 时，Datagram Data 字段延伸到 QUIC 数据包的末尾。 请注意，允许使用空（即零长度） Datagram Data。

Datagram Data：数据报负载，要发送的数据报的字节数。

# 5. 行为与用法（Behavior and Usage）
当应用在QUIC连接上发送数据报时，QUIC将生成一个新的 DATAGRAM 帧并在第一个可用数据包中发送。该帧应该（**SHOULD**）尽快投递（由拥塞控制等因素决定，如下所述），并且可以（**MAY**）与其他帧合并。

当 QUIC 端点接收到一个有效的 DATAGRAM 帧时，只要它能够处理该帧并将数据保存到内存中，就应该（**SHOULD**）立即传递给应用。

与 STREAM 帧一样，DATAGRAM 帧包含应用数据，并且必须（**MUST**）使用 0-RTT 或 1-RTT 密钥进行保护。

请注意，虽然 max_datagram_frame_size 传输参数限制了 DATAGRAM 帧的最大长度，但还可以通过 max_udp_payload_size 传输参数和端点之间路径的最大传输单元 （MTU) 进一步降低该限制。 DATAGRAM 帧不能被分段，因此，应用协议还需要处理最大数据报长度受其他因素限制的情况。

## 5.1. 多路复用数据报（Multiplexing Datagrams）
DATAGRAM 帧作为一个整体属于一个 QUIC 连接，并且与 QUIC 层的任何流 ID 无关。然而，预计应用将希望通过使用标识符来区分特定的 DATAGRAM 帧，例如用于数据报的逻辑流以及区分不同类型的数据报。

定义用于多路复用不同类型的数据报或数据报流的标识符，是运行在 QUIC 上的应用协议的职责。应该由应用定义 Datagram Data 字段的语义及其解析方式。

如果应用需要支持多个数据报流的并发，一种推荐的模式是在 Datagram Data 字段的开头使用可变长度整数表示标识符。这种方式比较简单，可用最小的空间对大量流进行编码。

QUIC 实现应该（**SHOULD**）向应用提供一个 API，为 DATAGRAM 帧和 QUIC 流分配各自不同的优先级。

## 5.2. 确认处理流程（Acknowledgement Handling）
虽然 DATAGRAM 帧在丢包检测时不会重传，但它们也是 ACK 触发帧（[RFC9002])。接收方应该（**SHOULD**）支持延迟发送 ACK 帧（在 max_ack_delay 指定的限制内）以对接收到仅包含 DATAGRAM 帧的数据包做出响应，因为即使这些包短期内未被确认，发送方也不会采取任何行动。当情况表明数据包可能丢失时，因为其不知道数据包的有效负载，且由 max_ack_delay 或其他协议组件控制时，接收方仍需继续发送 ACK 帧。

与任何 ACK 触发帧一样，当发送方怀疑仅包含 DATAGRAM 帧的数据包丢失时，它会发送探测包以引发更快的 ACK 确认，如 [RFC9002] 的第 6.2.4 节所述。

如果发送方检测到包含特定 DATAGRAM 帧的数据包可能已经丢失，则QUIC实现可以（**MAY**）通知应用它认为数据报已丢失了。

类似地，如果包含 DATAGRAM 帧的数据包被确认，则QUIC实现可以（**MAY**）通知发送方，应用数据报已被成功发送和接收。由于乱序，可能导致某个 DATAGRAM 帧被认为已丢失后又被接收并确认。需要注意的是，对 DATAGRAM 帧的确认仅表明接收方的传输层接收并处理了该帧，并不保证接收方的应用层成功处理了该数据。因此，此通知信号不能替代表示处理成功的应用层指示。

## 5.3 流控（Flow Control）
DATAGRAM 帧不提供任何明确的流控信号，并且不影响其他流或连接范围的流控限制。

不为 DATAGRAM 帧提供流控，其风险是接收方可能无法提供必要的资源来处理这些帧。 例如，它可能无法将帧内容存储在内存中。 但是，由于 DATAGRAM 帧本质上是不可靠的，如果接收方无法处理它们，DATAGRAM 帧可能（**MAY**）会被丢弃。

## 5.4 拥塞控制（Congestion Control）
DATAGRAM 帧由 QUIC 连接的控制器进行拥塞控制。因此在拥塞控制器允许之前，连接可能无法发送应用生成的 DATAGRAM 帧 [RFC9002]。此时发送方必须（**MUST**）延迟发送DATAGRAM 帧直到控制器允许发送或丢弃（此时它可以通知应用）。 使用包同步（[RFC9002] 的第 7.7 节）的实现也可以延迟 DATAGRAM 帧的发送以保持一致的包同步。

QUIC实现可以选择让应用指定一个发送过期时间，超过该时间，受拥塞控制的 DATAGRAM 帧应该被丢弃不传输。

# 6. 安全考虑（Security Considerations）
DATAGRAM 帧与在 QUIC 连接中传输的其余数据具有相同的安全属性，因此 [RFC9000] 的安全考虑也适用。 使用 DATAGRAM 帧传输的所有应用数据与 STREAM 帧一样，必须（**MUST**）由 0-RTT 或 1-RTT 密钥保护。

允许以 0-RTT 发送 DATAGRAM 帧的应用层协议需要一个配置文件，该配置定义了 0-RTT 许可； 参见 [RFC9001] 的第 5.6 节。

DATAGRAM 帧可能会被路径上能够丢弃数据包的恶意方检测到。 由于 DATAGRAM 帧不使用传输级重传，因此使用 DATAGRAM 帧的连接，可能会由于它们对丢包的不同响应而与其他连接区分开来。

# 7.  IANA考虑（IANA Considerations）
## 7.1. QUIC传输参数（QUIC Transport Parameter）
本文在 <https://www.iana.org/assignments/quic> 中 "QUIC Transport Parameters"注册表中添加了1个新值：

Value: **0x20**

Parameter Name: **max_datagram_frame_size**

Status: permanent

Specification: RFC 9221

## 7.2. QUIC帧类型（QUIC Frame Types）
本文在 <https://www.iana.org/assignments/quic> 中 "QUIC Frame Types"注册表中添加了2个新值：

Value: **0x30-0x31**

Frame Name: **DATAGRAM**

Status: permanent¶

Specification: RFC 9221


# 8. 参考资料（References）
## 8.1. 规范引用（Normative References）
[RFC2119]
Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC8174]
Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.

[RFC9000]
Iyengar, J., Ed. and M. Thomson, Ed., "QUIC: A UDP-Based Multiplexed and Secure Transport", RFC 9000, DOI 10.17487/RFC9000, May 2021, <https://www.rfc-editor.org/info/rfc9000>.

[RFC9001]
Thomson, M., Ed. and S. Turner, Ed., "Using TLS to Secure QUIC", RFC 9001, DOI 10.17487/RFC9001, May 2021, <https://www.rfc-editor.org/info/rfc9001>.

[RFC9002]
Iyengar, J., Ed. and I. Swett, Ed., "QUIC Loss Detection and Congestion Control", RFC 9002, DOI 10.17487/RFC9002, May 2021, <https://www.rfc-editor.org/info/rfc9002>.

## 8.2. 资料引用（Informative References）
[RFC0768]
Postel, J., "User Datagram Protocol", STD 6, RFC 768, DOI 10.17487/RFC0768, August 1980, <https://www.rfc-editor.org/info/rfc768>.

[RFC6347]
Rescorla, E. and N. Modadugu, "Datagram Transport Layer Security Version 1.2", RFC 6347, DOI 10.17487/RFC6347, January 2012, <https://www.rfc-editor.org/info/rfc6347>.

# 致谢（Acknowledgments）
原始提案来自Ian Swett.

本文档得到了 IETF QUIC 工作组的许多贡献者的评论和意见，其中包括 Nick Banks、Lucas Pardue、Rui Paulo、Martin Thomson、Victor Vasiliev 和 Chris Wood 的实质性意见。

# 本文作者通讯地址

Tommy Pauly
Apple Inc.
One Apple Park Way
Cupertino, CA 95014
United States of America
Email: tpauly@apple.com

Eric Kinnear
Apple Inc.
One Apple Park Way
Cupertino, CA 95014
United States of America
Email: ekinnear@apple.com

David Schinazi
Google LLC
1600 Amphitheatre Parkway
Mountain View, CA 94043
United States of America
Email: dschinazi.ietf@gmail.com
