# 1. Introduction

因特网上大范围地使用了HTTP语义，这些语义通常与HTTP/1.1 和 HTTP/2一起使用。
HTTP/1.1 已经被用于各种传输层和会话层，而HTTP/2主要是与TCP上的TLS一起使用。 
HTTP/3在一个新的传输层协议QUIC上支持了相同的语义。

## 1.1. Prior versions of HTTP

HTTP/1.1 [HTTP11] 使用以空格分隔的文本字段来传输HTTP消息。
虽然这些交换信息是人类可读的，但是使用空白来作为消息格式，增加了解析的复杂度，以及行为多样性的容忍度。
由于HTTP/1.1不包括多路复用层，所以经常使用多个并发的TCP连接。然而，这对拥塞控制和网络效率有负面影响，因为TCP不会在多个连接之间共享拥塞控制。

HTTP/2 [HTTP2] 引入了二进制分帧和多路复用层，从而在不修改传输层的前提下改善延迟。
然而，因为HTTP/2多路复用的并发原理对于TCP的丢包恢复机制是不可见的，
一个丢包或者乱序的包就会导致所有活动的事务遭受停顿，不管事务是否收到这个丢包的影响。

## 1.2. Delegation to QUIC

QUIC传输层协议纳入了流多路复用和针对每条流的流控制，与HTTP/2基础分帧层提供的类似。
通过在stream层提供可靠性，在整个连接上提供拥塞控制，相对于TCP映射，QUIC有能力改善HTTP的性能。
QUIC同样在传输层纳入了TLS 1.3 [TLS13]，提供了和TLS over TCP同等的保密性和完整性，以及通过TCP快速打开[TFO]带来的建连延迟改善。

本文定义了一种基于QUIC传输协议的HTTP语义映射，主要借鉴了了HTTP/2的设计。
HTTP/3依靠QUIC提供数据的机密性和完整性保护、身份验证、 可靠性，以及流上可靠有序传输。
将流的生命周期和流控制都委托给了QUIC的同时，每条流上使用了类似的二进制分帧。
一些HTTP/2特性归入到QUIC中，同时另外的特性在QUIC上层实现。

[QUIC-TRANSPORT] 对QUIC进行了阐述。[HTTP2] 对 HTTP/2进行了阐述。

# 2. HTTP/3 Protocol Overview

HTTP/3提供了通过QUIC传输协议来传输HTTP语义的功能，和类似HTTP/2的内部分帧层。
一旦客户端知晓某个指定终端上支持HTTP/3服务，它就可以打开一个QUIC连接。
QUIC提供了协议协商，基于流的多路复用，以及流控制。3.1节中描述了如何发现HTTP/3终端。

在每条流中，HTTP/3通信的基本单元是帧（frame，参考7.2节）。出于不同目的，定义了每个帧的类型。
比如，HEADERS和DATA帧是HTTP请求和响应的基础（参考4.1节）。
Frames that apply to the entire connection are conveyed on a dedicated control stream.
适用于整个连接的帧在专用的控制流上传输。

[QUIC-TRANSPORT]的第2章中，描述了使用QUIC流的抽象概念来实现请求的多路复用。
每个请求-响应对预设了一个QUIC流。每个流之间都是独立的，因此一个发生阻塞、丢包的流不会影响其他流的进展。

Server push是一种HTTP/2 [HTTP2] 引入的交互模式，这种模式允许服务端向客户端推送一个request-response交换，从而来让客户端发出指示的请求。
这种方式在网络利用率和潜在延迟收益之间做了权衡。使用了一些HTTP/3帧来实施服务端推送，比如PUSH_PROMISE，MAX_PUSH_ID，以及CANCEL_PUSH。

而在HTTP/2中，压缩了请求和响应字段来进行传输。
因为HPACK [HPACK]依赖了压缩字段分段的有序传输（QUIC不提供这样的保证），所以HTTP/3使用了QPACK [QPACK] 来替换HPACK。
QPACK使用了隔离的单向流来修改和追踪字段表状态，而编码后的字段分段只参考表的状态而不修改它。

## 2.1. Document Organization

以下章节提供了HTTP/3连接生命周期的概述：

* 连接设立和管理（第3章）覆盖了如何发现HTTP/3终端，以及如何建立HTTP/3连接。
* HTTP请求生命周期（第4章）描述了如何使用帧来表达HTTP语义。
* 连接关闭（第5章）描述了如何终止HTTP/3连接，包括文明终止和意外终止。

以下章节描述了线路上的协议和与传输的交互：

* stream映射与用途（第6章）描述了QUIC流的使用方式。
* HTTP分帧层（第7章）描述了在大多数流上使用的帧。
* 错误处理（第8章）描述了如何在一条流上或者整个连接上处理和表示错误条件。

本文最后的章节中提供了如下资源：

* HTTP/3扩展（第9章）描述了如何在未来的文档中添加新功能。
* 附录A提供了HTTP/2 与 HTTP/3之间更具体的对比。

## 2.2. Conventions and Terminology

终止（abort）：连接或流的突发终止，可能由错误条件引起。

客户端（client）：开始一个HTTP/3连接的终端。客户端发送HTTP请求，并接受HTTP响应。

连接（connection）：一个两端之间的传输层连接，使用了QUIC作为传输协议。

连接错误（connection error）：影响整个HTTP/3连接的错误。

终端（endpoint）：连接的客户端或者服务端。

帧（frame）：HTTP/3中流通信时的最小单元，包含一个头部和一个根据帧类型组织的变长字节序列。
本文和[QUIC-TRANSPORT]中都存在称为“帧”的协议元素。
当引用[QUIC-TRANSPORT]中的帧时，帧的名字之前会添加引语“QUIC”。比如，“QUIC CONNECTION_CLOSE 帧”。
没有这个引语的引用（帧）指7.2节中定义的帧。

  HTTP/3 connection: A QUIC connection where the negotiated
   application protocol is HTTP/3.
HTTP/3连接（HTTP/3 connection）：一个QUIC连接，其协商的应用协议是HTTP/3。

对端（peer）：一个终端。在讨论某个终端时，"对端 "指的是与主要讨论对象相距较远的终端。

接收端（receiver）：一个正在接收帧的终端。

发送端（sender）：一个正在传输帧的终端

服务端：接受一个HTTP/3连接的端点。 服务端接收HTTP请求，并发送HTTP响应。

流（stream）：QUIC传输提供的一个双向或者单向的字节流。一个HTTP/3连接内的所有流都可以被认为是 "HTTP/3流"，但HTTP/3内定义了多种流类型。

流错误（stream error）：个别HTTP/3流上的应用级（application-level）错误。

术语 "content" 在 [SEMANTICS] 第6.4节中定义。

最后，术语 "resource"、"message"、"user agent"、"origin server"、"gateway"、"intermediary"、"proxy" 和 "tunnel"在 [SEMANTICS] 第3节中定义。

本文档中的数据包图片使用 [QUIC-TRANSPORT] 第1.3节中定义的格式来说明字段的顺序和大小。

# 3. Connection Setup and Management

## 3.1. Discovering an HTTP/3 Endpoint

HTTP依赖了权威响应的概念：对于指定目标资源，（在目标URI中识别的）源服务端组织响应消息的时候，认为对请求最合适的那个响应。
在 [SEMANTICS] 的4.3节中讨论了给一个HTTP URI设置权威的服务端的事项。

“Https”方案将权限和证书结合起来，其中客户端认为（通过URI的权威模块识别的）主机的证书是可信的。
在收到TLS握手的服务器证书后，客户端必须使用[SEMANTICS]第4.3.4节中描述的过程来验证该证书是否与URI的源服务器相匹配。 如果证书不能对URI的源服务器进行验证，客户端必须不考虑（MUST NOT）该服务器对该源的权威性。

客户端可以（MAY）使用带“https”的URI来访问资源：首先将主机标识解析为IP地址，
接着建立一个到这个地址和指定端口的QUIC连接（包括上述服务器证书的验证），
然后在这个安全的连接上发送一个将URI指向服务端的HTTP/3请求消息。
除非有其他机制用于选择HTTP/3，否则在TLS握手过程中的应用层协议协商（ALPN；见[RFC7301]）扩展中使用令牌 "h3"。

连通性问题（例如，阻塞UDP）可能导致QUIC建连失败；这种情况下客户端应当（SHOULD）尝试使用基于TCP的HTTP版本。

服务端可以（MAY）在任何UDP端口上开启HTTP/3服务；另外一种服务通告的方式总是包含了一个显式端口，以及包含和方案相关的显式端口或者默认端口的URI。

### 3.1.1. HTTP Alternative Services

终端可以通过Alt-Svc响应头或者HTTP/2 ALTSVC帧宣告自己支持HTTP/3
如响应头Alt-Svc: h3=":50781" 表示相同主机下的50781端口支持HTTP/3

当接收到表明支持HTTP/3的响应头时，客户端可以（MAY）尝试建立QUIC连接，如果连接建立成功，客户端可以使用本文中描述的映射发送HTTP请求。

### 3.1.2. Other Schemes

尽管HTTP独立于传输协议，“http”方案将 权限 和 在权限模块认证的任何主机的指定端口上接受TCP连接的能力结合起来。
由于HTTP/3不使用TCP，因此它无法直接访问权威服务端上由“http”URI识别的资源。
然而，诸如[ALTSVR]的协议扩展允许权威服务端来识别其他的权威但可以通过HTTP/3访问的服务。

在对不是“https”方案的源发送请求之前，客户端必须（MUST）保证服务端愿意为该方案提供服务。
对于 "http 方案"的源，[RFC8164]中描述了一种实验性的方法来实现这一目标。 
将来可能会为各种方案定义其他机制。

## 3.2 Connection Establishment

HTTP/3依赖QUIC version 1作为传输层，将来的规范可能会定义使用HTTP/3的其他QUIC传输版本。

QUIC握手协议必须大于等于TLS 1.3。
HTTP/3客户端必须（MUST）支持在TLS握手期间向服务端指示目标主机的机制。 如果服务端是通过域名（[DNS-TERMS]）标识的，则客户端必须发送服务端名称指示（SNI; [RFC6066]）TLS扩展，除非使用了指示目标主机的替代机制。

QUIC连接的建立如 [QUIC-TRANSPORT] 中所述。在建立连接的过程中，TLS 握手中ALPN token "h3" 用来表明是否支持HTTP/3。可以在一次握手中提供对其他应用层协议的支持。

虽然与核心QUIC协议有关的连接级选项是在初始加密握手中设置的，但HTTP/3特定的设置是在SETTINGS帧中传达的。在建立QUIC连接后，每个终端必须发送一 SETTINGS帧（第 7.2.4 节，作为各自 HTTP 控制流的初始帧（见第 6.2.1 节）。

## 3.3. Connection Reuse

HTTP/3连接可用于多个请求。为了达到最好的性能，如果客户端一般不会关闭连接，除非客户端认为不再需要继续和服务端进行通信（比如，用户离开指定web页），或者知道服务端关闭了连接。

一旦建立上和服务端的连接，该连接可以（MAY）用于请求其他URI，只要服务端是经过认证的。
要将现有连接用于新的源，客户端必须通过 [SEMANTICS] 第4.3.4节中所述的过程，来验证服务端为新的源服务端提供的证书。 这意味着客户端将需要保留服务端证书以及验证该证书所需的任何其他信息，不这样做的客户端将无法为其他的源重用该连接。

如果证书因任何原因不能被新的源接受，该连接决不能被重新使用，应该为新的源建立新的连接。如果证书不能被验证的原因可能适用于其他已经与连接相关联的源，客户端应该为这些源重新验证服务端证书。例如，如果因为证书过期或被撤销而导致证书验证失败，这可能会被用来使所有其他用于建立授权的源无效。

同一个IP地址和UDP端口的情况下，客户端不应该（SHOULD NOT）打开多个HTTP/3连接，其中IP地址和端口从URI、选择的替代服务[ALTSVR]、或配置代理或其中任何一个的名称解析中获得。客户端可以（MAY）使用不同的传输或TLS配置，打开多个到相同IP地址和UDP端口的连接，但应该（SHOULD）避免以同一个配置创建多个连接。

建议服务端尽可能长地维护HTTP/3连接，如果有必要才关闭空闲的连接。如果任一个终端选择关闭HTTP/3连接，它应当（SHOULD）先发送一个GOAWAY帧（5.2节），这样两端可以可靠地决策是否之前发送的帧已被处理，且可以优雅完成或终止剩下的所有任务。

如果服务端不希望客户端针对特定来源复用HTTP/3连接，可以通过响应请求发送421（错误定向的请求）状态码来表明该请求对服务端不具有权威性（见 [SEMANTICS] 的7.4节）

# 4. HTTP Request Lifecycle

## 4.1. HTTP Message Exchanges

客户端在客户端发起的双向QUIC流上发送HTTP请求。客户端必须（MUST）在一个指定的流上发送单个请求。
服务端在和请求相同的流上发送0到多个临时的HTTP响应，然后再发单个最终的HTTP响应，详见下文。关于临时和最终HTTP响应的描述，请参见[SEMANTICS]的第15章。

推送的响应在一个服务端发起的单向QUIC流上进行发送；参考6.2.2小节。
和标准的响应方式一样，服务端发送0到多个临时的HTTP响应，然后发送单个最终的HTTP响应。
在4.4节中对推送进行了更加详细的描述。

在指定的流上，收到多个请求，或者在一个最终的HTTP响应之后再收到一个HTTP响应，必须（MUST）把这种情况当成是异常。

一个HTTP消息（请求或响应）由以下内容组成：

1. 头部字段区：作为单个HEADERS帧发送（参考7.2.2小节）。
1. （可选项）载荷：如果有载荷，就作为一列DATA帧发送（参考7.2.1小节），
1. （可选项）尾部字段区：如果有这个字段，则以单个HEADERS帧的形式发送。

头部字段区和尾部字段区在 [SEMANTICS] 的6.3和6.5节中进行了说明；载荷在 [SEMANTICS] 的6.4节中进行了说明。

如果收到一列无效的帧，必须（MUST）把这种情况当成是H3_FRAME_UNEXPECTED类型的连接错误（第8章）。实际上，出现在HEADERS帧之前的DATA帧，或者出现在尾部HEADERS帧之后的HEADERS或DATA帧，都是无效的。其他帧类型（尤其是未知帧类型）可能会受其自身规则的约束，请参阅第9节。

服务端可以（MAY）在响应消息的帧之前、之后、中间发送一个或多个PUSH_PROMISE帧（参考7.2.5小节）。
这些PUSH_PROMISE帧不是响应的一部分（参考4.4节）。PUSH_PROMISE帧不允许出现在推送响应中；必须把包含PUSH_PROMISE的推送响应当做H3_FRAME_UNEXPECTED类型的连接错误（见第8章）。

在一个请求或者推送流上，未知类型的帧（第9章），包括保留帧（第7.2.8小节），可以（MAY）在本章描述的其他帧之前、之后、中间发送。

HEADERS和PUSH_PROMISE帧可能引用QPACK动态表的更新。虽然这些更新不是消息交换的直接部分，但是他们必须在消息可以被销毁前被接收并处理，详情参考4.1.1.

Transfer codings (see Section 6.1 of [HTTP11]) are not defined for HTTP/3; the Transfer-Encoding header field MUST NOT be used.
未为HTTP/3定义传输编码（请参见[HTTP11]的6.1节），不得（MUST NOT）使用Transfer-Encoding标头字段。

当且只当同一个请求的最终响应之前有一个或多个信息响应（1xx，参考 [SEMANTICS] 第15.2节），响应才可以（MAY）包括多个消息。临时响应不包含载荷体或尾部。

一个HTTP请求/响应交换完全占用了客户端发起的双向QUIC流。在发送请求之后，客户端必须（MUST）关闭流的发送。除非使用了CONNECT方法（参考4.2节），客户端必须不能（MUST NOT）根据收到的响应来关闭流。在发送最终响应之后，服务端必须（MUST）关闭流的发送。此刻，QUIC流就完全关闭了。

当关闭了一条流，这意味着最终HTTP消息（final HTTP message）结束了。因为一些消息过大，只要收到消息足够多的内容来进行处理，终端应当（SHOULD）开始处理并发HTTP消息。如果尚未收到足够多的消息来生成一个完整的响应，但是客户端发起的流关闭了连接，服务端应当（SHOULD）以H3_REQUEST_INCOMPLETE错误码终止响应（见第8章）。

如果响应不依赖请求的任何部分，即使请求还没有发送和接收，服务端可以在客户端发送一整个请求之前发送一个完整的响应。
当服务端不需要接收请求的剩余部分，它可以（MAY）终止读取请求流，发送一个完整的响应，并干净地关闭流的发送部分。
当要求客户端停止在请求流上发送时，应当（SHOULD）使用H3_NO_ERROR错误码。
尽管客户端总是可以因为其他原因而丢弃响应，但是在客户在请求突然终止之后，它必须不能（MUST NOT）丢弃完整的响应。
如果服务端发送了部分或者完整的响应，但是没有终止读取请求，客户端应当（SHOULD）继续发送请求的实体，并正常关闭流。

### 4.1.1. Field Formatting and Compression

HTTP消息以 一系列被称为HTTP字段的 key-value对的形式 携带了元数据，见[SEMANTICS]中6.3和6.5节。
[https://www.iana.org/assignments/http-fields/](https://www.iana.org/assignments/http-fields/) 中的“超文本传输协议（HTTP）字段名注册表”维护了已注册的HTTP字段的列表。

字段名是包含ASCII字符码子集的字符串，[SEMANTICS]第5.1节讨论了更具体的HTTP字段名和值的属性。
在HTTP/2中，字段名的字符必须（MUST）在编码前转换成小写格式。
字段名中包含大写字符的请求或响应必须（MUST）被当成异常（4.1.3小节）。

与HTTP/2一样，HTTP/3不使用Connection头部字段来表示连接特定的字段；
在这个协议中，连接特定元数据通过其他方式传输。
终端必须不能（MUST NOT）生成包含连接特定字段的HTTP/3字段区。
任何包含连接特定字段的消息必须（MUST）被当成异常（4.1.3小节）。

唯一的例外是TE头部字段，它可以（MAY）出现在HTTP/3请求头部中；当它出现时，除了“trailiers”，它必须不能（MUST NOT）包含任何其他值。

将HTTP/1.x消息转换为HTTP/3的中间适配器必须删除[SEMANTICS]第7.6.1节中讨论的特定连接头部字段，否则它们的消息将被其他HTTP/3终端视为非法的（第4.1.3节）。

#### 4.1.1.1. Pseudo-Header Fields、

和HTTP/2一样，HTTP/3采用了一系列以 ’:’（ASCII码 0x3a） 字符开始的伪头部字段。
这些为头部字段携带了目标URI，请求的方法，以及响应的状态码。

伪头部字段不是HTTP字段。除了本文中定义的，终端必须不能（MUST NOT）生成其他的伪头部字段；
然而，一个扩展可以协商修改此限制（参见第9节）。

伪头部字段只在它们定义的上下文中有效。
为请求定义的伪头部字段必须不能（MUST NOT）出现在响应中；为响应定义的伪头部字段必须不能（MUST NOT）出现在请求中。
伪头部字段必须不能（MUST NOT）出现在尾部字段。
终端必须（MUST）把包含未定义或者无效伪头部字段的请求或响应当成是异常（参考4.1.3）。

所有伪头部字段必须（MUST）出现在头部字段区的常规头部字段之前。
任何请求或响应中，如果头部字段区中，伪头部字段出现在常规头部字段之后，必须（MUST）认为这是一种异常。（4.1.3小节）

请求的伪头部字段定义如下：

":method"：包含了HTTP方法（[SEMANTICS]第9章）。

":scheme"：包含了目标URI的方案部分（[URI]第3.1小节）。
":scheme”不限于”http”和”https”方案的URI。一个代理或者网管可以将请求转换成非HTTP的方案，从而来使HTTP与非HTTP服务进行交互。
关于使用 "https "以外的方案的指导，请参见3.1.2节。

":authority”：包含了目标URI的权限部分（[URI第3.2节]）。权限必须不能（MUST NOT）在”http”或”https”方案中包含已废弃的”userinfo”子模块。
为了保证准确赋值HTTP/1.1请求行，对 - 具有原始形式或者星号形式请求目标的 - HTTP/1.1请求进行转换时，必须（MUST）删除这个伪头部字段。（参考[SEMANTICS]第7.1节）。
直接生成HTTP/3请求的客户端应当（SHOULD）使用":authority”伪头部字段来替代Host字段。
如果HTTP/3请求中没有Host字段，一个将HTTP/3请求转换成HTTP/1.1请求的中间媒介必须（MUST）构建一个Host字段，并将”:authority”伪头部字段的值拷贝到这个字段中。

":path”：包含了目标URI的路径和查询部分（“path-absolute”，一个可选的 ’?’ 字符且跟着一个”query”），参考[URI]的3.3节和3.4节。星号格式的请求中，":path”伪头部字段包含了’*’。
“http”或 “https” URI中，这个伪头部字段必须不能（MUST NOT）为空；
不包含路径模块的“http” 或 “https” URI必须包含一个 ‘/’ 。但是有一个例外：”http”或”https”URI的OPTIONS请求不包含路径模块。
这些必须（MUST）包含带 ’*‘ 符号的”:path”伪头部字段（参考[SEMANTICS]第7.1节）。

所有HTTP/3请求的”:method”，”:scheme", 以及”:path”伪头部字段必须（MUST）只包含一个值，除非是CONNECT请求；（参考4.2节）

如果":scheme”伪头部字段标识了一个有强制权限模块的方案（包括”http”和”https”）, 
请求必须（MUST）包含":authority”伪头部字段或”Host”头部字段，且必须不能为空。
如果同时出现了这两个字段，它们必须（MUST）包含相同的值。
如果方案没有强制权限模块，并且请求目标中也没有，那么请求必须不能（MUST NOT）包含”.authority”伪头部字段或“Host”头部字段。

删除了强制的伪头部字段，或者包含无效伪头部字段的HTTP请求是非法的。（4.1.3小节）
HTTP/3没有定义像HTTP/1.1请求行一样携带版本标识的方式。

对于响应，定义了单个":status”伪头部字段，这个字段携带了HTTP状态码，参考[SEMANTICS]第15章。
这个伪头部字段必须（MUST）包含在所有响应中；否则，这个响应就是非法的（4.1.3小节）。、

HTTP/3没有定义像HTTP/1.1请求行一样携带版本或者原因的方式。

#### 4.1.1.2. Field Compression

[QPACK]描述了HPACK的一种变体，它使编码器能够对压缩可能造成的队头阻塞进行某种程度的控制， 这使得编码器能够平衡压缩效率和延迟。 HTTP/3使用QPACK来压缩头部和尾部字段，包括头部字段中的伪头部字段。

为了更高的压缩效率，可以（MAY）在压缩前，将“Cookie”字段分割到多个单独的字段行中，每个带一个或多个cookie对。
如果解压缩字段区包含了多个cookie字段行，在将它们传到到上下文（比如HTTP/1.1连接，或者一个通用的HTTP服务应用）而非HTTP/2或者HTTP/3之前，必须（MUST）使用两个8位字节定位符0x3B和0x20（ASCII字符串“; ”，一个分号和一个空格）来将它们整合成单个8位字节字符串。

#### 4.1.1.3. Header Size Constraints

一个HTTP/3实现可以（MAY）强加一个消息头部的最大尺寸限制，从而来约束它在一个HTTP消息上接收的消息头部最大尺寸。
如果服务端收到的头部区尺寸大于这个限制，可以发送一个HTTP 431（请求头部字段过大）状态码（[RFC6585]）。
客户端可以丢弃它不能处理的响应。字段列表的大小根据压缩前字段的大小计算，包括名称和值的字节长度，加上每个字段32字节的开销。

如果实现希望将这个限制通知给对端，可以将这个字段加入到SETTINGS_MAX_FIELD_SECTION_SIZE参数中进行传递。
收到这个参数的实现不应该（SHOULD NOT）发送头部超过这个限制的HTTP消息，因为对端很有可能会拒绝处理。
然而，一个HTTP消息在到达源服务器之前可以穿越一个或多个中间媒介（参见[SEMANTICS]的3.7节）。 
因为这个限制是由每个处理消息的实现单独应用的，所以消息即使小于这个限制，也不保证一定就会被接受。

### 4.1.2. Request Cancellation and Rejection

一旦请求流被打开，请求可以被任何一个终端取消。 
客户端如果对响应不再感兴趣，就会取消请求；服务端如果不能或选择不响应，就会取消请求。 
在可能的情况下，建议（RECOMMENDED）服务端发送带有适当状态代码的HTTP响应，而不是取消已经开始处理的请求。

实现应该（SHOULD）通过 突然终止仍然打开的流的任何方向 来取消请求，这意味着重置流的发送部分和中止流的接收部分的读取（参见第2.4节[QUIC-TRANSPORT]）。

当服务端在没有执行任何应用处理的情况下取消请求时，该请求被视为 "已拒绝 "。 服务端应该以错误码H3_REQUEST_REJECTED中止其响应流。
在这种情况下，"已处理 "意味着流中的一些数据被传递给了一些更高一层的软件，而这些软件可能因此采取了一些行动。 客户端可以把被服务端拒绝的请求当作根本没有发送过，从而可以在以后重试。

对于服务端已经部分或全部处理的request，必须不能（MUST NOT）用H3_REQUEST_REJECTED错误码。
当服务端在部分处理之后放弃响应，它应当（SHOULD）以H3_REQUEST_CANCELLED错误码退出响应流。
when a server has requested closure of the request stream with this error code.
客户端应该使用错误码H3_REQUEST_CANCELLED来取消请求。 
收到这个错误码后，如果没有进行任何处理，服务端可以使用错误代码H3_REQUEST_REJECTED突然终止响应。
客户端不能使用H3_REQUEST_REJECTED错误码，除非服务端用这个错误码要求关闭请求流。

如果一个stream在接收到完整的response之后被取消，客户端可以忽略取消，使用这个response。然而，如果一个stream在接收到部分response之后被取消，这个response不应当被使用。

只有像GET、PUT或DELETE这样的幂等操作才可以安全地重试；客户端不应该自动重试一个非幂等方法的请求，除非它有办法知道请求语义是独立于方法的幂等操作，或者有办法检测到原始请求从未被应用（详见[SEMANTICS]第9.2.2节）。

### 4.1.3. Malformed Requests and Responses

一个请求或响应会因为如下原因而非法：

* 出现了禁止的字段或者伪头部字段，
* 缺失了强制要求的伪头部字段，
* 伪头部字段值无效
* 伪头部字段出现在字段之后，
* HTTP消息序列无效，
* 包含大写字段名
* 字段名或者值中包含无效字符

包含载荷体的请求或响应可以包含Content-Length头部字段。如果请求的Content-length头部字段的值和组成实体的DATA帧的载荷长度之和不相等，那么这个请求也是非法的。
如果响应没有载荷（详见[SEMANTICS]第6.4.1小节），即使DATA帧中没有内容，它的content-length字段也可以为非0值.

处理HTTP请求或响应的中间媒介（例如任何不是通道的中间媒介）必须不能（MUST NOT）转发非法的请求或响应，
一旦检测到非法请求或响应，必须认为这是一种 H3_MESSAGE_ERROR 类型的流错误。

服务端在收到非法请求之后，可以（MAY）在关闭或重置流之前，发送一个HTTP响应，来指示错误。
客户端必须不能（MUST NOT）接受非法响应。
这些要求是为了抵御几种针对HTTP的常见攻击；必须极其严格遵守这些要求，否则可能导致实现收到这些攻击。

## 4.2. The CONNECT Method

CONNECT方法要求接收者，发布一条到以request-target（[SEMANTICS]第9.3.6节）区分的目标源服务端的信道。这主要被HTTP代理用于建立和源服务端的TLS会话，从而来与"https"资源进行交互。

在HTTP/1.x，CONNECT用来将整个HTTP连接转换成连接到远端主机的信道。在HTTP/2和HTTP/3，CONNECT方法被用来在单个流上建立信道。

CONNECT请求必须（MUST）按如下规则进行构建：

* “.method:” 伪头部字段填成“CONNECT”；
* 删除“.scheme”和“.path”伪头部字段；
* “.authority”伪头部包含了将连接的主机和端口（等同于CONNECT请求中的request-target的authority-form，详见[SEMANTICS]第7.1节）

请求流在请求的结尾保持打开来传输数据。一个不遵守这些约束的CONNECT请求是非法的。

支持CONNECT的代理建立的到服务端TCP连接([RFC0793]) 以":authority"伪头部字段区分。一旦成功建连，代理就会给客户端发送包含2xx系列状态码的HEADERS帧，如[SEMANTICS]第15.3节定义。

所有流上的DATA帧和TCP连接上收发的数据相对应。客户端发送的任何DATA帧的有效载荷被代理传送给TCP服务端；代理从TCP服务端收到的数据会被打包成DATA帧。注意不能保证尺寸和TPC分段数能够和HTTP DATA或QUIC STREAM帧的尺寸和数量匹配。

一旦完成CONNECT方法，流上就只能发送DATA帧。如果扩展定义了Extension帧在这种情况下的使用状况，则可以（MAY）使用Extension帧。如果收到任何其他已知的帧类型，必须（MUST）将其当做是H3_FRAME_UNEXPECTED类型的连接错误（见第8章）。

TCP连接可以被任一对等端终止。当客户端终止请求流时（也就是代理商的接收流进入到“Data Recved”状态），代理会设置到服务端TCP连接的FIN位。当代理收到了设置了FIN位的包，它会关闭它到客户端的发送流。在单向上保持半关闭状态的TCP连接是无效的，但服务端通常不关心，因此客户端如果还想从CONNECT的目标收数据的话，不应该（SHOULD NOT）关闭发送流。

通过粗暴地终止流来发出TCP连接错误信号。代理将任何TCP连接错误当成H3_CONNECT_ERROR类型的流错误（见第8章），包括收到带设置了RST为的TCP分段。对应地，如果代理探测到流错误或者QUIC连接错误，它必须（MUST）关闭TCP连接。如果底层TCP实现允许，代理应当（SHOULD）发送设置了RST位的TCP分段。

由于CONNECT创建了一条通往任意服务端的隧道，所以支持CONNECT的代理应该（SHOULD）将其使用限制在一组已知端口或安全的请求目标列表中；更多细节请参见[SEMANTICS]第9.3.6节。

## 4.3. HTTP Upgrade

HTTP/3不支持HTTP升级机制（[SEMANTICS]第7.8节），也不支持101（切换协议）信息状态码（[SEMANTICS]第15.2.2小节）

## 4.4. Server Push

Server Push是一种交互模式，服务端在预料到客户端会发送指定请求之后，允许服务端向客户端推送一个request-response交换。这种方式抵消了潜在延迟增益的网络占用。HTTP/3 server push和第8.2节中描述的 [HTTP/2] 很相似，但是使用不同的机制。

每个server push都会被服务端分配一个唯一的Push ID。 在整个HTTP/3连接的生命周期中，Push ID用于在各种情况下引用推送。

Push ID的空间从0开始，到MAX_PUSH_ID帧设置的最大值结束（见7.2.7节）。
特别地，在客户端发送MAX_PUSH_ID帧后，服务端才能进行推送。 
客户端发送MAX_PUSH_ID帧来控制服务端可以承诺的推送次数。
服务端应该按顺序使用Push ID，从零开始。当没有发送MAX_PUSH_ID帧或流引用的Push ID大于最大Push ID时，客户端必须将收到的推送流视为类型为H3_ID_ERROR（第8章）的连接错误。

Push ID在一个或多个PUSH_PROMISE帧（第7.2.5节）中使用，这些帧携带了请求消息的头部字段。
这些帧在生成推送的请求流上发送，这允许服务端推送与客户端请求相关联。
当在多个请求流上应答同一Push ID时，解压后的请求字段部分必须以相同的顺序包含相同的字段，并且每个字段中的名称和值都必须是相同的。

然后，Push ID 被包含在最终实现这些承诺的推送流中（见第 6.2.2 节）。
推送流标识了它所实现的承诺的Push ID，然后包含对承诺请求的响应（如4.1节所述）。

最后，Push ID可以在CANCEL_PUSH帧中使用（ 见7.2.3节）。 
客户端使用此帧表示它们不希望收到承诺的资源；服务端使用此帧表示它们将无法履行先前的承诺。

不是所有的请求都能被推送。服务端可以（MAY）推送具备如下属性的请求：

* 可以缓存；参考[SEMANTICS]第9.2.3小节
* 安全的；参考[SEMANTICS]第9.2.1小节；
* 不包含请求实体或尾部去

服务端必须（MUST）在服务端授权的".authority"伪头部字段中包含一个值。如果客户端尚未验证推送请求所指示的源的连接，则它必须执行与 在连接上发送针对该源的请求之前执行 相同的验证过程（见第3.3节）。 如果该验证失败，则客户端不得认为（MUST NOT）该源服务器具有权威性。

一收到一个PUSH_PROMISE帧，但是它携带的请求不能缓存、风险未知、暗示存在请求实体，或者客户端不认为发这个请求的服务端是权威的，客户端应当（SHOULD）就立刻发送一个CANCEL_PUSH帧。不得（MUST NOT）使用或缓存任何相应的响应。

每个推送的响应和一个或者多个请求相关联。推送和收到PUSH_PROMISE帧的请求流相关联。
同一个服务端推送可以通过在多个请求流中，使用带相同Push ID的PUSH_PROMISE帧，从而与多个客户端请求关联起来。这些关联行为不会影响协议的操作，但是用户代理可以（MAY）在决定如何使用被推送的资源时考虑采用。

与响应特定部分相关的PUSH_PROMISE帧的排序至关重要。服务端应当（SHOULD）在发送引用了promised响应的HEADERS或者DATA帧之前，发送一个PUSH_PROMISE帧。这减少了客户端请求那些会被服务端推送的资源的概率。
如果服务端迟一点兑现承诺，服务端在push stream上推送响应；参考6.6.2小节。push stream区分它兑现的承诺的Push ID，然后向承诺的请求推送一个响应，响应的格式和4.1节描述的响应格式相同。

由于乱序的原因，推送流数据可能在对应的PUSH_PROMISE帧之前到达。当客户端收到一个目前Push ID未知的推送流，相关的客户端请求和推送请求头部字段都是未知的。客户端可以缓存流数据，并等待相关PUSH_PROMISE。
客户端可以使用流的流控制（[QUIC-TRANSPORT]第4.1节）来限制服务器在推送流上送入的数据量。

客户端取消推送后，推送流数据也可以到达。
在这种情况下，客户端可以用错误代码H3_REQUEST_CANCELLED中止读取流。
这将要求服务端不要传输其他数据，并表示收到数据后会将其丢弃。

如果客户端实现了HTTP缓存，那么可以缓存那些可缓存的（参考[CACHING]第3章）推送的响应。在服务端收到推送响应的时候，认为它在原始服务器（例如，如果出现了”no-cache”缓存响应指令（[CACHING]第5.2.2.3小节））上就被成功校验了。

不能缓存的推送响应必须不能（MUST NOT）被任何HTTP缓存存储。它们可以（MAY）被单独提供给应用。

# 5. Connection Closure

一旦建立，HTTP/3 connection可以用于很多个request和response持续一段时间，直到被关闭。connection关闭可以在几种不同的情况下发生

## 5.1 Idle Connections

每个QUIC终端在握手时定义一个空闲超时时间。如果QUIC连接空闲时间超过超时时间，对端会假设连接已经被关闭。如果现有连接的空闲时间超过QUIC握手期间协商的空闲超时时间，则HTTP/3实现需要新打开一个HTTP/3连接来处理新的请求，当接近空闲超时时间时，也应当这么做，请参阅[QUIC-TRANSPORT]的10.1节。

HTTP客户端预期连接是打开的，在有response或server push的时候。如果客户端没有预期从服务端收到response，允许空闲连接关闭比维持一个可能不再使用的连接更好。网关可能更倾向于保持连接，而愿意引发与服务器建连的延迟。服务端不应当主动保持连接打开。

## 5.2. Connection Shutdown

即使连接不空闲，但是其中任何一个终端都可以决定停用连接，并开始文明地关闭连接。终端通过发送一个GOAWAY帧来文明的关闭一个HTTP/3连接（7.2.6节）。

GOAWAY帧包含了一个标识，向接收者表明了这个连接中已经或者可能将会被处理的请求或推送的范围。
服务端发送了一个客户端发起的双向Stream ID；客户端发送一个Push ID（4.4节）。
标识大于等于指定值的请求或推送会被GOAWAY的发送者拒绝（4.1.2节）。
如果没有请求或推送被处理，这个标识可以（MAY）是0。

GOAWAY帧中的信息可以让客户端和服务端在连接关闭前，在接受哪个请求或推送的问题上达成一致。
在发送GOAWAY帧的时候，终端应当（SHOULD）显式地取消所有标识大于等于指示值的请求或推送，从而来清除受影响流的传输状态。如果后续还有请求或者推送达到，终端应当（SHOULD）继续如此处理。

从对端收到GOAWAY帧之后，终端必须不能（MUST NOT）在这个连接上发起新的请求、承诺新的推送。
客户端可以（MAY）建立新的连接来发送额外的请求。

一些请求或推送可能已经在传输中：
  * 在收到GOAWAY帧的时候，如果客户端已经发送了请求，且请求的Stream id大于等于收到的GOAWAY帧中的标识，这些请求不会被处理。客户端可以在一个不同的连接上安全地重试未被处理的请求。当服务端关闭连接时，无法重试请求的客户端将失去所有正在处理中的请求。

    如果请求的Stream ID比来自服务端的GOAWAY帧中的Stream ID小，那么这个请求可能被处理了；直到收到响应、流被单独重置、收到另一个Stream ID比有关请求低的GOAWAY、连接终止，才能知晓请求的状态。

    如果请求是单独的且还没被处理，服务端可以（MAY）拒绝那些小于指示ID的请求。

  * 如果服务端在承诺了推送之后，服务端收到了一个GOAWAY帧，但是服务端推送的Push ID大于或者等于GOAWAY帧中的标识，因此这些推送会被拒绝。

当服务端提前知道要关闭连接的时候，即使提前量很小，服务端也应当（SHOULD）发送GOAWAY帧，这样远端可以知道请求是否被部分处理。比如，如果一个HTTP客户端在服务端关闭QUIC连接的同时发送了一个POST，客户端无法知道服务端是否开始处理POST请求，除非服务端发送了GOAWAY帧来表示它在哪个stream上进行操作。

端点可以发送多个指示不同标识符的GOAWAY帧，但是每个帧中的标识符不得大于任何先前帧中的标识符，因为客户端可能已经在另一个HTTP连接上重试了未处理的请求。 接收到包含比先前接收到的标识符更大的标识符的GOAWAY，必须将其视为H3_ID_ERROR类型的连接错误； 请参阅第8节。

尝试文明终止连接的终端可以发送一个GOAWAY帧，并将值设置为最大可能值（服务端2^62-4，客户端2^62-1）。这保证了对端停止创建新的请求或推送。在开始等待任何传输中的请求或推送到达的过程中，终端可以在连接终止之前，发送另一个GOAWAY帧来表明它可能接受的请求或推送。这保证了连接可以在不丢请求的情况下，文明的关闭连接。

客户端在选择GOAWAY帧的Push ID是有更高的灵活性。2^62 - 1 表示服务端可以继续承诺过的推送。更小的值意味着客户端会拒绝Push ID大于等于这个值的所有推送。跟服务端一样，只要Push ID不大于所有之前发送的值，客户端就可以（MAY）发送后续的GOAWAY帧。

即使当GOAWAY表明指定请求或推送在接收之后不会被处理或接受，下层的传输资源还是存在的。发起这些请求的终端可以取消它们来清理传输状态。

一旦所有接受的请求和推送被处理，终端可以允许让连接变成空闲，或可以（MAY）开始连接的立刻关闭。完成连接文明关闭的终端应当（SHOULD）使用H3_NO_ERROR错误码。

如果客户端用尽了所有可用双向流ID来发送请求，服务端不需要发送GOAWAY帧，因为客户端不能再发请求了。

## 5.3 Immediate Application Closure

HTTP/3的实现可以在任何时候关闭QUIC connection。这会向对端发送一个QUIC CONNECTION_CLOSE帧，表示应用层终止了连接。application error code表示关闭connection的原因。
有关在HTTP/3中关闭连接时可以使用的错误码，请参见第8节。

在关闭connection之前，发送GOAWAY允许客户端重试一些requests。将GOAWAY帧和QUIC CONNECTION_CLOSE帧合并到同一个包能够增加帧被客户端接收的几率。

If there are open streams that have not been explicitly closed, they are implicitly closed when the connection is closed; see Section 10.2 of [QUIC-TRANSPORT].
如果有打开的流没有被显式关闭，那么当连接关闭时，它们会被隐式关闭；参见 [QUIC-TRANSPORT] 的 10.2 节。

## 5.4 Transport Closure

出于多方面原因，QUIC传输层可以告知应用层connection已经终止了。终止可能由于对端明确关闭，传输层的错误，或者网络连通性的变化。

如果一个connection没有用GOAWAY frame终止，客户端必须假设全部或部分被发送的requests已经被处理过了。

# 6. Stream Mapping and Usage

QUIC流提供可靠有序的传输，但是不保证不同流之间有序。在QUIC version 1中，包含HTTP帧的流数据被分帧封装在QUIC STREAM中，但是这些帧对HTTP分帧层是不可见的。传输层对接收到的流数据进行缓存并排序，将一个可靠的字节流暴露给应用程序。
虽然QUIC允许在流内进行无序传输，但HTTP/3并没有利用这个功能。

QUIC流可以是单向的也可以是双向的，流可以由客户端初始化，也可以由服务器初始化。

当HTTP字段和数据通过QUIC发送，QUIC层处理了大多数流管理的事务，HTTP不需要做任何解复用的事情。在QUIC流上发送的数据总是会映射到指定的HTTP事务或整个HTTP/3连接上下文。

## 6.1 Bidirectional Streams

所有由客户端启动的双向流都用于HTTP请求和响应。
双向流保证响应能关联上请求，这些流称为请求流。
客户端首个请求stream为0，随后的请求stream为4，8，等等。
为了打开这些流，HTTP/3服务端应当（SHOULD）配置允许的流数量和初始流控制窗口的非0最小值。同时为了不必要的限制并发性，同时应（SHOULD）至少允许100个请求。

HTTP/3不使用服务器初始化的双向流，尽管扩展可以定义这些流的使用；客户端收到服务端发起的双向流之后，必须把它当成是H3_STREAM_CREATION_ERROR类型（第8章）的连接错误，除非有一个支持这种功能的扩展，并且客户端与服务端经过了协商。

## 6.2 Unidirectional Streams

流开始时会发送一个单字节的头作为stream type，头后面的数据格式由stream type决定。

```
   Unidirectional Stream Header {
     Stream Type (i),
   }

                   Figure 1: Unidirectional Stream Header
```

本文中定义了两种流类型：控制流（6.2.1小节）和推送流（6.2.2小节）。[QPACK]定义了两种额外的流类型。其他流类型可以通过HTTP/3扩展进行定义；更多细节请参考第9章。某些流类型是保留的（第6.2.3节）。

在HTTP/3连接的生命周期的早期，它们的性能易受单向流上数据的创建和交换的影响。
过度限制这些流的数量和流控窗口的终端，会增加远端很早就达到限制并阻塞的风险。

实际上，实现应该考虑远端可能希望在它们允许使用的单向流上进行预留的流操作（6.2.3小节）。
为了避免阻塞，客户端和服务端发送的传输参数都必须（MUST）允许对端创建至少一个用于HTTP控制流的单向流，以及强制扩展要求的单向流（基础HTTP/3协议和QPACK要求最少3个），同时应当（SHOULD）在每个流上提供最少1024个字节的流控信用。

值得注意的是，如果对端在创建关键的单向流之前耗尽了初始的流控信用，不要求终端生成额外的流控窗口来创建更多的单向流。终端应当（SHOULD）和创建强制扩展要求的单向流（比如QPACK编、解码流）一样，先创建HTTP控制流，再在它们对端允许的前提下创建额外的流。

如果接收者不支持流头部指示的流类型，流中剩余的数据会因为语义未知而不能被消费。
收到未知流类型，可以（MAY）以一个H3_STREAM_CREATION_ERROR错误码终止流的读取。但是必须不能（MUST NOT）认为这个流是哪种类型的连接错误。

实现可以（MAY）在知道对端是否支持该type前发送stream types。但是能修改已存在协议组件（QPACK或其他扩展）状态和语意的type，不能（MUST NOT）在知道对端支持前发送。

除非有其他特殊的说明，发送者都可以关闭或重置单向流。接受者必须（MUST）兼容在收到单向流头部之前，关闭或重置单向流。

### 6.2.1 Control Streams

控制流的流类型是0x00。这条流上的数据只发送HTTP/3帧。（7.2节）

两端必须在连接开始时发起一个crontrol stream，并且发送SETTINGS frame作为这个stream的第一帧。如果这个control stream的第一帧不是SETTINGS frame，必须被视作连接错误H3_MISSING_SETTINGS。两端各自只允许发送一个crontrol stream；接收到第二个control stream必须被视作连接错误H3_STREAM_CREATE_ERROR。发送者必须不能（MUST NOT）关闭控制流，接收者必须不能（MUST NOT）请求发送者关闭控制流。如果crontrol stream被关闭，必须被视为连接错误H3_CLOSED_CRITICAL_STREAM。连接错误在第8章中介绍。

Because the contents of the control stream are used to manage the behavior of other streams, endpoints SHOULD provide enough flow control credit to keep the peer's control stream from becoming blocked.
因为控制流的内容被用来管理其他流的行为，所以终端应该提供足够的流控信用，以防止对端的控制流被阻塞。

使用一对单向流而不是一个双向流，是为了两端都能尽快发送自己的数据。根据QUIC连接上0-RTT的使能情况，客户端或服务端可以先发送流数据。

### 6.2.2 Push Streams

服务端推送是一种在HTTP/2引入的可选的特性，允许服务端在尚未请求之前先发起响应，详情参考4.4节。

推送流的流类型为0x01，紧接着为Push ID，编码为可变长数字。剩下的数据由HTTP/3帧组成（见7.2），通过0个或多个临时HTTP响应，后跟一个最终的HTTP响应，从而兑现了承诺。Server Push和Push ID详见4.1节。

只有服务端才能push，收到客户端发起的推送流，服务端应当视为H3_STREAM_CREATION_ERROR类型的连接错误。

```
   Push Stream Header {
     Stream Type (i) = 0x01,
     Push ID (i),
   }

                        Figure 2: Push Stream Header
```

每个Push ID必须只被使用一次。如果push stream header包含被其他push stream header使用过的Push ID，必须被视作H3_ID_ERROR类型的连接错误。

### 6.2.3 Reserved Stream Types

Stream types类似于"0x1f * N + 0x21"被预留用作被忽略的type。
这些流没有实际的意义，被用作应用层的填充（padding），可以用在当前没有请求数据要发送的连接上。
对端接收到时不能（MUST NOT）认为这些流有任何意义。

这种流的载荷和长度由不同的发送方实现自由选择。当发送一个保留的流类型时，实现可以（MAY）干净地终止该流或重置它。当重置流时，应（SHOULD）使用H3_NO_ERROR错误码或保留的错误码（第8.1节）。

# 7. HTTP Framing Layer

HTTP帧通过QUIC流来进行传输，如第6章所述。HTTP/3定义了三种流类型：控制流，请求流，推送流。本章描述了HTTP/3帧格式和允许出现这些帧的流类型；参考表1。附录A.2. 对HTTP/2帧和HTTP/3帧做了对比。

```
   +--------------+----------------+----------------+--------+---------+
   | Frame        | Control Stream | Request        | Push   | Section |
   |              |                | Stream         | Stream |         |
   +==============+================+================+========+=========+
   | DATA         | No             | Yes            | Yes    | Section |
   |              |                |                |        | 7.2.1   |
   +--------------+----------------+----------------+--------+---------+
   | HEADERS      | No             | Yes            | Yes    | Section |
   |              |                |                |        | 7.2.2   |
   +--------------+----------------+----------------+--------+---------+
   | CANCEL_PUSH  | Yes            | No             | No     | Section |
   |              |                |                |        | 7.2.3   |
   +--------------+----------------+----------------+--------+---------+
   | SETTINGS     | Yes (1)        | No             | No     | Section |
   |              |                |                |        | 7.2.4   |
   +--------------+----------------+----------------+--------+---------+
   | PUSH_PROMISE | No             | Yes            | No     | Section |
   |              |                |                |        | 7.2.5   |
   +--------------+----------------+----------------+--------+---------+
   | GOAWAY       | Yes            | No             | No     | Section |
   |              |                |                |        | 7.2.6   |
   +--------------+----------------+----------------+--------+---------+
   | MAX_PUSH_ID  | Yes            | No             | No     | Section |
   |              |                |                |        | 7.2.7   |
   +--------------+----------------+----------------+--------+---------+
   | Reserved     | Yes            | Yes            | Yes    | Section |
   |              |                |                |        | 7.2.8   |
   +--------------+----------------+----------------+--------+---------+

              Table 1: HTTP/3 Frames and Stream Type Overview
```

SETTINGS帧只能出现在Control Stream的第一个帧中：表1中用标记（1）标出。相关章节中会提供特定的指导。
值得注意的是，不像QUIC帧，HTTP/3帧可以出现在多个包中。

## 7.1. Frame Layout

所有帧的格式如下：

```
   HTTP/3 Frame Format {
     Type (i),
     Length (i),
     Frame Payload (..),
   }

                       Figure 3: HTTP/3 Frame Format
```

每个帧包含下面的字段：

Type：变长整数帧类型

Length：表示帧载荷长度的变长整数，

Frame Payload：载荷，语意由Type字段决定

每个帧必须恰好包含以上定义的字段， payload实际长度和length不符合的情况，必须被当成H3_FRAME_ERROR类型的连接错误（见第8章）。
In particular, redundant length encodings MUST be verified to be self-consistent; see Section 10.8.
特别是，必须验证冗余长度编码是自洽的，参见10.8节。

文明终止一个流，如果流的最后一个帧被截断，必须（MUST）把这种情况当成是H3_FRAME_ERROR类型的连接错误（第8章）。可以在粗暴终止的流

## 7.2. Frame Definitions

### 7.2.1. DATA

DATA frames（type=0x0）传输任意长度的字节序列，作为HTTP请求或者回包的载荷。

DATA frames必须关联一个HTTP请求或者回包。如果DATA frame在control stream中被接收，接受端必须视作一个H3_FRAME_UNEXPECTED类型的连接错误（第8章）。

```
   DATA Frame {
     Type (i) = 0x0,
     Length (i),
     Data (..),
   }

                            Figure 4: DATA Frame
```

### 7.2.2 HEADERS

HEADERS frame（type=0x1）用来携带QPACK编码的HTTP field section。详见QPACK文档

```
   HEADERS Frame {
     Type (i) = 0x1,
     Length (i),
     Encoded Field Section (..),
   }

                          Figure 5: HEADERS Frame
```

HEADERS frames只能用在 request streams 或 push streams。在控制流上收到HEADERS帧，接收者必须（MUST）响应一个H3_FRAME_UNEXPECTED类型的连接错误。

### 7.2.3. CANCEL_PUSH

CANCEL_PUSH frame（type=0x3）用于在push stram被创建前取消server push。CANCEL_PUSH frame用Push ID作为标识，Push ID为变长的整数。

客户端发送CANCEL_PUSH时，意味着它不想要接受服务端承诺的资源。
服务端收到这个frame时，终止发送server push的响应。但是这个机制具体的处理方式因推送流的状态而异：
尚未创建推送流（旧版本是尚未推送）：不创建（不推送）；

* 已经打开流：服务端应当粗暴地终止流（旧版本是发送一个QUIC RESET_STREAM帧，并终止响应的传输）
* 已经完成推送：服务端可以粗暴地终止流，也可以什么都不做（旧版本没说明）

服务端发送CANCEL_PUSH表明自己将不会履行之前发送的承诺，客户端不能指望对应的承诺会兑现，除非它已经收到并处理了承诺的响应。无论推送流是否已经打开，当服务端确定该承诺不会被履行时，都应该（SHOULD）发送一个CANCEL_PUSH帧。 如果流已经被打开，服务器可以用错误码 H3_REQUEST_CANCELLED 中止对该流的发送。

发送CALCEL_PUSH对推送流的现有状态不会产生直接影响。客户端不应当（SHOULD NOT）在收到推送流之后再发一个CANCEL_PUSH帧。因为服务端可能还没有处理CANCEL_PUSH，所以推送流可能在客户端发送CANCEL_PUSH之后到达。客户端应当（SHOULD）以一个H3_REQUEST_CANCELLED错误码结束流的读取。
CANCEL_PUSH frame只能在control stream中发送，在其他流中发送必须被视作H3_FRAME_UNEXPECTED类型的流错误。

```
   CANCEL_PUSH Frame {
     Type (i) = 0x3,
     Length (i),
     Push ID (i),
   }

                        Figure 6: CANCEL_PUSH Frame
```

CANCEL_PUSH frame携带变长的整数Push ID，表示将被取消的server push。如果CANCEL_PUSH帧中引用的Push ID比当前连接中允许的值要大，必须（MUST）被当成H3_ID_ERROR类型的连接错误；

客户端可能会收到CANCEL_PUSH frame，其中Push ID可能因为乱序而还未被PUSH_PROMISE frame声明的。如果服务端收到的CANCEL_PUSH帧，但是Push ID没有在PUSH_PROMISE帧中提及，必须（MUST）将其当成H3_ID_ERROR类型的连接错误。

### 7.2.4. SETTINGS

SETTINGS frame (type=0x4) 用来传输配置参数，从而来影响终端通信的方式，比如终端行为的偏好与约束。一个SETTINGS参数也可以被称为“setting”；每个配置参数的标识和值可以被称为“setting identifier”和“setting value”。

SETTINGS帧往往用于连接，而不是单个流。SETTINGS帧必须（MUST）以每个对等端的每个控制流的第一个帧发送，且必须不能（MUST NOT）后续再发。如果终端在控制流上收到第二个SETTINGS帧，必须（MUST）以 H3_FRAME_UNEXPECTED类型的连接错误进行响应。

除了控制流，其他类型的流必须不能（MUST NOT）发送SETTINGS帧。如果终端在其他流类型上收到SETTINGS帧，必须（MUST）以H3_FRAME_UNEXPECTED类型的连接错误进行响应。

SETTINGS参数不是协商生成的；参数表明发送方的特性，被接收方使用。但是SETTINGS可以实现隐式协商，每个对端使用SETTINGS宣告自己支持的集合，双方根据两个集合选择哪些被使用。SETTINGS不提供机制表明选择何时生效。

同一个参数两端可能会宣告不同的值。比如，客户端可能希望回包字段区足够大，而服务端对请求大小更谨慎。

setting identifier不能出现超过一次。否则被视作H3_SETTINGS_ERROR类型的连接错误。

SETTINGS frame的载荷由0个或多个参数构成，每个参数由变长整数的ID和变长的value组成，value用QUIC variable-length integer编码。

```
   Setting {
     Identifier (i),
     Value (i),
   }

   SETTINGS Frame {
     Type (i) = 0x4,
     Length (i),
     Setting (..) ...,
   }

                          Figure 7: SETTINGS Frame
```

实现必须忽略带有它不理解的标识符的任何参数。

#### 7.2.4.1. Defined SETTINGS Parameters

HTTP/3中定义了以下设置项：

SETTINGS_MAX_FIELD_SECTION_SIZE (0x6): 默认值为无穷大，见4.1.1.3节。

"0x1f * N + 0x21"格式的Setting identifiers被预留用在测试忽略不认识的identifiers。这种setting没有定义的意义，终端应当（SHOULD）至少包含一个这种setting在SETTINGS frame中，但是接收方必须忽略这种setting。
因为该setting没有任何定义的含义，所以它的值可以为任何值。

HTTP/2中同样预留了（参考11.2.2小节）设置标识，但和HTTP/3的不冲突。必须不能（MUST NOT）发送这些设置，一旦收到，则必须（MUST）当成H3_SETTINGS_ERROR类型的连接错误。

可以通过对HTTP 3的扩展来定义其他设置项。更多详细信息请参见第9章。

#### 7.2.4.2 Initialization

HTTP实现必须不能（MUST NOT）发送对端不能理解的帧或者请求。

一开始所有配置都是初始值。由于携带配置的包有可能丢失或延迟，每个终端应当（SHOULD）在收到对端SETTINGS帧使用初始值。当SETTINGS帧到达，需要将配置的值改为SETTINGS中的新值。
这避免了在发送消息前等待SETTINGS帧。终端必须不能（MUST NOT）在发送SETTINGS帧之前要求从对端收到数据；一旦传输层就绪，必须（MUST）尽快发送配置。

而服务端上，每个客户端的配置的初始值都是默认值。

对于使用1-RTT QUIC 连接的客户端，每个服务端的配置的初始值是默认值。
在QUIC处理包含SETTINGS的数据包之前，1-RTT密钥总是可用的，即使服务端立刻发送了SETTINGS。
在发请求之前，客户端不应该（SHOULD NOT）无限期的等待SETTINGS，
相反应该（SHOULD）处理收到的数据报，从而在发送第一个请求之前，增加处理SETTINGS的可能性。

当使用了0-RTT QUIC连接，每个服务端配置的初始值是之前会话中使用的值。
客户端应当（SHOULD）将服务端提供的配置和连接的恢复信息存在一起，
但是可以（MAY）选择某些情况下不存储配置（比如，在SETTINGS帧之前收到会话票证）。
当使用0-RTT方案时，客户端必须（MUST）使用存储的配置，如果没有存储，就使用默认值。
一旦服务端提供了新的配置，客户端必须（MUST）使用新的值。

服务端可以记住它通告的配置，或者将其加上完整性保护，存在票证中，并在收到0-RTT数据的时候恢复这个信息。服务端将HTTP/3配置值用于决定是否接受0-RTT数据。
如果服务端不能决定客户端记住的配置是否跟它当前配置兼容，它必须不能（MUST NOT）接受0-RTT数据。
如果客户端遵循的配置不违反服务端当前配置，记住的配置就是兼容的。

服务端可以（MAY）接受0-RTT，后续在它的SETTINGS帧中提供不同配置。
如果服务端接受了0-RTT数据，它的SETTINGS帧必须不能（MUST NOT）减少任何限制或者改变任何值，否则客户端的0-RTT可能违反这个配置。
服务端必须（MUST）包括所有与默认值不同的配置。
如果服务端接受0-RTT但接着又发了和之前阐述的配置不兼容的配置，这就是一种H3_SETTINGS_ERROR类型的错误。
如果服务端接受了0-RTT，但是接着发了一个SETTINGS帧，并且这个帧删除了一个之前非默认值、且客户端理解的配置值，
必须（MUST）将这种情况认为是一种H3_SETTINGS_ERROR类型的连接错误。

### 7.2.5 PUSH_PROMISE

PUSH_PROMISE frame (type=0x05)用于服务端向客户端发送请求头部字段区，如HTTP/2中一样。

```
   PUSH_PROMISE Frame {
     Type (i) = 0x5,
     Length (i),
     Push ID (i),
     Encoded Field Section (..),
   }

                        Figure 8: PUSH_PROMISE Frame
```

Push ID: 变长的整数标识server push的操作。Push ID用于push stream headers（4.4节）和CANCEL_PUSH frames（7.2.3节）。

Encoded Field Section: QPACK编码的request header，详见[QPACK]

服务端不能使用超过客户端在MAX_PUSH_ID frame声明的Push ID， 客户端接收到大于自己声明的Push ID时必须视作H3_ID_ERROR类型的连接错误。

服务端可以（MAY）在多个PUSH_PROMISE帧中使用同一个Push ID。如果这么做的话解压缩后的请求头部集合中的字段必须（MUST）相同且顺序也一致，同时每个字段中的名称和值也必须严格匹配。客户端应当（SHOULD）对比请求头部区中承诺的资源进行多次对比。如果客户端收到了一个已经承诺过的但不匹配的Push ID，必须（MUST）响应H3_GENERAL_PROTOCOL_ERROR类型的连接错误。如果解压后的字段区严格匹配，客户端应当（SHOULD）推送的内容与每个流关联起来。

允许对同一个Push ID重复索引主要是为了减少并发请求引起的冗余。服务端应当（SHOULD）避免长时间复用一个Push ID。客户端可能会消费服务端推送响应，但不会保存以作后用。客户端如果发现一个PUSH_PROMISE帧中的Push ID是它们已经消费过的，则需要强制忽略这个PUSH_PROMISE。

如果在控制流上收到PUSH_PROMISE，客户端必须（MUST）以 H3_FRAME_UNEXPECTED类型的连接错误进行响应。

客户端必须不能（MUST NOT）发送PUSH_PROMISE帧。如果服务端收到PUSH_PROMISE帧，必须（MUST）将这种情况当成H3_FRAME_UNEXPECTED类型的连接错误。

服务端推送机制详见4.4章。

### 7.2.6. GOAWAY

GOAWAY frame (type=0x7) 被任一终端用来优雅关闭连接。GOWAY允许终端完成之前的请求处理的同时拒绝接受新的请求。这个特性提供了管理操作，比如服务器维护，GOAWAY自己不会关闭连接。

```
   GOAWAY Frame {
     Type (i) = 0x7,
     Length (i),
     Stream ID/Push ID (..),
   }

                           Figure 9: GOAWAY Frame
```

GOAWAY帧总是在控制流上进行发送。在S-->C的方向上，它携带了由客户端发起的双向连接的变长整数QUIC Stream ID。客户端如果接收到其他类型的Stream ID，必须（MUST）将这种情况当成是H3_ID_ERROR类型的连接错误。

在Client到Server的方向上，GOAWAY帧携带了变长整数形式的Push ID。

GOAWAY帧用于connection而不是特定的stream。客户端必须（MUST）把在控制流以外的流中收到的GOAWAY frame视作H3_FRAME_UNEXPECTED类型的连接错误。

GOAWAY帧的更多使用信息详见5.2节。

### 7.2.7 MAX_PUSH_ID

MAX_PUSH_ID frame (type=0xD)用来控制服务端server push 的次数。设置了服务端在PUSH_PROMISE帧和CANCEL_PUSH帧中能使用的Push ID的最大值。server push 的次数同时也受QUIC传输层控制。

MAX_PUSH_ID frame 永远在control stram中发送，在其他stream中接收到必须被视作H3_FRAME_UNEXPECTED类型的连接错误。

服务端不能发送MAX_PUSH_ID frame ，否则客户端视为H3_FRAME_UNEXPECTED类型的连接错误。

最大Push ID在HTTP/3连接创建时被复位，意味着服务端在收到 MAX_PUSH_ID frame前不能进行server push。客户端通过增加maximum Push ID使用更多的server push。

```
   MAX_PUSH_ID Frame {
     Type (i) = 0xd,
     Length (i),
     Push ID (i),
   }

                        Figure 10: MAX_PUSH_ID Frame
```


MAX_PUSH_ID 帧携带一个可变长度的整数，该整数标识了服务器可以使用的 Push ID 的最大值（见第 4.4 节）。 MAX_PUSH_ID frame不能减少Push ID最大值；如果收到的 MAX_PUSH_ID 帧包含的值比之前收到的值小，则必须作为 H3_ID_ERROR 类型的连接错误处理。

### 7.2.8 Reserved Frame Types

保留了"0x1f * N + 0x21"类型的帧来满足忽略未知类型的需求。这些类型没有语意，可以在允许发送帧的任何流上发送， 这使它们可以用于应用程序层填充。对端收到这些帧时必须不能（MUST NOT）认为有任何意义。

载荷和长度由实现方式选择。

有一些帧类型，在HTTP/2中使用，但HTTP/3中没有，也被预留了（11.2.1小节）。必须不能（MUST NOT）发送这些帧类型，一旦收到必须（MUST）当成是H3_FRAME_UNEXPECTED类型的连接错误。

# 8. Error Handling

当一个流无法成功完成时，QUIC允许应用程序突然终止（重置）该流并传达原因（[QUIC-TRANSPORT]的2.4节），这称为“流错误”。 

HTTP/3实现可以决定关闭QUIC流并传达错误的类型，错误码在第8.1节中定义。 
流错误与指示错误情况的HTTP状态码不同：流错误表示发送方未能传输或使用完整的请求或响应，而HTTP状态代码指示成功接收到请求的结果。

如果需要终止整个连接，则QUIC同样提供一种机制来传达原因（参阅[QUIC-TRANSPORT]的5.3节）， 这称为“连接错误”。 与流错误类似，HTTP/3实现可以终止QUIC连接，并使用第8.1节中的错误码传达原因。

虽然关闭流和连接的原因被称为 "错误"，但这些操作并不一定表明连接或任何一个实现有问题。 例如，如果不再需要请求的资源，流可以被重置。

端点可以选择在某些情况下将流错误作为连接错误处理，关闭整个连接以响应单个流的条件。
在做出这个选择之前，实现者需要考虑对未完成请求的影响。

因为可以不协商就定义新的错误码（第9章），在意外上下文使用错误码，或这收到未知错误码，必须等同于H3_NO_ERROR。然而，关闭流的时候忽视错误码可能有其他影响（参考4.1节）。

## 8.1. HTTP/3 Error Codes

当粗暴地终止流、停止流的读取、或者立刻关闭HTTP/3连接的时候，使用以下错误码：

H3_NO_ERROR (0x100): 关闭连接或流但没有错误的时候使用

H3_GENERAL_PROTOCOL_ERROR (0x101): 某种形式上，对端违反了协议，但又没有对应更具体的错误码，或者终端不愿意使用更具体的错误码

H3_INTERNAL_ERROR (0x102): HTTP协议栈发生了一个内部错误

H3_STREAM_CREATION_ERROR (0x103): 终端发现它的对端创建了一个它不会接受的流。

H3_CLOSED_CRITICAL_STREAM (0x104): HTTP/3连接要求的流被关闭或者重置了

H3_FRAME_UNEXPECTED (0x105): 在当前状态或者当前流上，收到了一个不允许的帧。

H3_FRAME_ERROR (0x106): 收到的帧格式不对，或者大小不对

H3_EXCESSIVE_LOAD (0x107): 终端检测到对端当前的行为可能会导致过量的负载。

H3_ID_ERROR (0x108): 错误使用Stream ID或Push ID，比如超过了限制，减小了限制，或者重用

H3_SETTINGS_ERROR (0x109): 终端在SETTNGS帧的载荷中检测到了错误

H3_MISSING_SETTINGS (0x10a): 在控制流开始的时候没有收到SETTING帧

H3_REQUEST_REJECTED (0x10b): 服务端拒绝了请求，并不会交由应用处理。

H3_REQUEST_CANCELLED (0x10c): 请求或它的响应（包括推送的响应）被取消

H3_REQUEST_INCOMPLETE (0x10d): 客户端请求不完整，流被终止

H3_MESSAGE_ERROR (0x10e): HTTP消息格式错误，无法处理。

H3_CONNECT_ERROR (0x10f): 响应CONNECT请求而建立的TCP连接被重置或粗暴地关闭了

H3_VERSION_FALLBACK (0x110): 无法在HTTP/3上提供请求的操作，对端应当在HTTP/1.1上重试。

保留了”0x1f * N + 0x21”格式的错误码（N是非负整数）来实现这样的需求：将未知的错误码等同于H3_NO_ERROR（第9章）。
当他们需要发送H3_NO_ERROR错误码的时候，实现应当（SHOULD）以一定概率从这个空间中选择一个错误码

# 9. Extensions to HTTP/3

HTTP/3允许扩展协议。在本节描述的限制范围内，协议扩展可以提供附加的服务或者改变协议的各方面。扩展只在单个HTTP/3 connection中生效

扩展适用于本文档中定义的协议元素。对已存在的HTTP扩展选项不生效，如定义新的methods，status code，或者header fields

扩展允许使用新的frame type（4.2节），新的settings（4.2.5.1节），新的error codes（8节），或者新的单向stream types（3.2节）。登记系统用来管理这些扩展：frame types (Section 10.3)、settings (Section 10.4)、error codes (Section 10.5)和stream types (Section 10.6).

实现必须忽略未知的或者不支持的值。实现必须丢弃未知的或者不支持的frames和单向streams。这意味着任何扩展点都能被安全的使用，而不用提前准备或协商。然而，一个已知的帧类型应该在什么位置，比如SETTINGS帧作为控制帧的第一帧，位置帧类型不满足这个要求，并应当（SHOULD）被当成错误。

改变已有协议语义的扩展必须在使用前进行协商。举个例子，改变HEADERS frame结构的扩展在对端发出接受信号前不能被使用。调整修订后设计的生效时间是复杂的，因此为已有协议元素的新定义申请新的标识可能更高效。

本文档没有授权特定的method用来协商扩展，但是setting（4.2.5.1）可以用来实现这个目的。如果双方都设置了愿意使用，这个扩展就能被使用。如果setting用来做扩展协商，setting中省略的扩展默认都是不开启的。

# 10. Security Considerations

HTTP/3的安全注意事项需要和HTTP/2 over TLS的安全注意事项兼容。然而，[HTTP2]第10章的很多注意事项适用于 [QUIC-TRANSPORT] ，且在 [QUIC-TRANSPORT] 有所讨论。

## 10.1. Server Authority

HTTP/3依赖于HTTP的权限定义。[SEMANTICS]的第17.1节讨论了建立授权的安全注意事项。

## 10.2. Cross-Protocol Attacks

在TLS和QUIC握手时使用的ALPN，在应用层数据被处理前建立了目标应用协议，
使终端能够保证对端使用相同的协议。

这并不能保证对所有跨协议攻击的保护。QUIC-TRANSPORT]第21.5节描述了一些利用QUIC数据包的明文对不使用认证传输的终端进行请求伪造的方法。

## 10.3. Intermediary Encapsulation Attacks

HTTP/3字段编码允许了那些在HTTP中语法无效的字段名称（[SEMANTICS]第5.1节）。
必须（MUST）将包含无效字段名的请求或响应当成异常（4.1.3小节）。因此中间媒介不能
将带无效字段名的HTTP/3请求或响应转换成HTTP/1.1消息。

同样地，HTTP/3可以传输无效的字段值。虽然大多数可以被编码的值不会改变字段解析，
但是如果CR、LF、NUL字符是一字不差的转换的，攻击者可能利用这一点。
任何在字段值中包含不允许字符的请求或响应必须（MUST）被当成异常（4.1.3小节）。
[SEMANTICS]第5.5节的“field-content” ABNF 规则定义了有效的字符。

## 10.4. Cacheability of Pushed Responses

推送响应中没有显示的客户端请求；请求在服务端的PUSH_PROMISE帧中。

缓存推送响应可能基于源服务端的Cache-Control头部字段
但是，如果单个服务主机有多个租户，就会导致问题。
比如，一个服务端在它的URI空间上为多个用户都提供一小块空间。

如果同一个服务端上，多个租户共享了空间，这个服务端必须（MUST）保证租户不能推送它们没有权限的资源表示。
如果不能做到这点，会导致某个租户提供一个引起缓存爆满的表示，从而覆盖了真正有权限的租户提供的实际表示。

客户端需要拒绝推送不可信的源服务器的响应（见4.4节）。

## 10.5. Denial-of-Service Considerations

相对于HTTP/1.1或HTTP/2连接，HTTP/3连接可以要求更多的资源来进行操作。
字段压缩和流控制都依赖了更多的资源来存储更多的状态。这些特性的配置保证了它们使用的内存是具有严格边界的。

PUSH_PROMISE帧的数量也受到了类似方法的限制。接收服务端推送的客户端应当（SHOULD）限制它一次性发布Push ID的数量。

无法保证处理容量像状态容量一样被有效限制。

滥发未定义协议元素（对端会忽略）会导致对端花费额外的处理时间。
设置多个未定义的SETTINGS参数、未知帧类型、未知流类型实现，可以导致这个问题。
而且有些使用方法还是完全合法的，比如可选扩展、抵御流量分析的填充。

字段区的压缩同样会浪费处理资源；（潜在的滥用情况详见[QPACK]第7章）

所有这些特性，比如服务端推送、未知协议元素、字段压缩，都有合法的使用场景。
只有在不必要或者超量使用的时候，这些特征才会额外带来负担。

不监控这些行为的终端具有受DOS攻击的风险。实现应当（SHOULD）跟踪并限制这些特性的使用。
终端可以（MAY）将可疑的活动当成H3_EXCESSIVE_LOAD类型的连接错误（第8章），但是误判就会导致打断有效的连接和请求。

### 10.5.1. Limits on Field Section Size

一个大字段区（第4.1节）会导致实现消耗大量状态。对路由敏感的头部字段可以出现在头部字段区域的尾部，这阻止了头部字段区流向它最终的目标。
这种排序以及其他原因，比如保证缓存的正确性，意味着终端可能需要缓存整个头部字段区。
因为没有针对字段区域的硬性限制，一些终端可能被迫为头部字段消耗大量内存。

终端可以使用SETTINGS_MAX_FIELD_SECTION_SIZE（第4.1.1.3小节）配置来建议对端限制字段区域的大小。
这个配置只是建议性的，因此终端可以（MAY）发送超过这个限制的字段区，但是面临着请求或响应被当成异常的风险。
这个配置适用于一个连接，因此任何请求或响应都可能碰到一个具有更低未知限制的路由节点。
一个中间媒介可以通过传递不同对端展示的值来避免这个问题，但是他们没有这么做的义务。

如果一个服务端收到的字段区比它愿意处理的尺寸更大，可以发送一个HTTP 431（请求头部字段过大）状态码[RFC6585]。
客户端可以丢弃它无法处理的响应。

### 10.5.2. CONNECT Issues

因为创建流的消耗相对TCP连接的创建和维护来说，开销并不高昂，因此使用CONNECT方法，可以在一个代理上创建不成比例的负载。因此，支持CONNECT的代理在接受的并发请求数上可能更为保守。

由于外部的TCP连接停留在TIME_WAIT状态，代理在关闭传输CONNECT消息的流之后，还可以维护TCP连接的一些资源。考虑到这一点，代理可能会在TCP连接终止后的一段时间内延迟增加QUIC流限制。

## 10.6. Use of Compression

如果数据压缩的上下文被攻击者破解，攻击者可以恢复加密后的数据。
HTTP/3可以进行字段的压缩（4.1.1小节）；
以下注意点同样适用于压缩后的HTTP content-codings；(详见[SEMANTICS]第8.4.1小节)

有一些攻击明确针对了暴露web特性的压缩（比如[BREACH]攻击）。
攻击者诱发了多个包含不同文本的请求，再观察每个请求的秘文长度，如果猜对了密钥，那么秘文长度就更短。

在一个安全通道上进行通信的实现必须不能（MUST NOT）压缩那些既包含了机密数据又包含了受攻击者控制数据的内容，
除非为每种数据源提供了隔离的压缩上下文（compression contexts）。
如果不能决定数据源的可靠性，必须不能（MUST NOT）对数据进行压缩。

[QPACK]描述了更多关于字段区压缩的注意事项。

## 10.7. Padding and Traffic Analysis

可以使用填充来掩盖帧的实际大小，减少收到针对HTTP的特定攻击的风险，
比如，包括受攻击者控制的明文和加密数据的压缩内容受攻击的场景。（比如[BREACH]）

HTTP/2在另外帧中采用了PADDING帧和Padding字段来抵御流量分析，
而HTTP/3既可以依赖传输层填充，也可以采用保留帧（7.2.8小节）和流类型（6.2.3小节）。
根据填充间隔、填充与受保护信息的安排关系、丢包时是否采用填充、实现如何控制填充，这些填充方法会产生不同的结果。

保留的流类型，可以用来给人一种“即使在连接空闲时也在发送流量”的感觉。 
因为HTTP流量经常以突发方式发生，所以可以使用明显的流量来掩盖此类突发的时间或持续时间，甚至达到似乎在发送恒定数据流的地步。 
然而，由于这种流量仍然受到接收方的流量控制，如果不能及时排空这种流并提供额外的流量控制信用，就会限制发送者发送真实流量的能力。

为了减少针对压缩的攻击，相对于填充，禁用或限制压缩可能是更好的对策。

使用填充的保护效果可能没有想象中那样立竿见影。多余的填充甚至可能适得其反。
填充最多只能增大攻击者观察的数据量，从而让攻击者更加难以推断出长度信息。
错误的填充方案很容易就会被破解。实际上，使用可预测分布的随机填充的保护强度很低；
如果将载荷填充为固定大小，载荷大小跨越固定尺寸边界的时候，同样泄露了信息。
如果攻击者可以控制明文的话，它就可能做到这个。

## 10.8. Frame Parsing

一些协议元素包含嵌套的长度元素，通常以具有显式长度的帧的形式包含可变长度的整数。
这可能会给不谨慎的实现者带来安全风险。实现者必须（MUST）确保帧的长度与其包含的字段的长度完全匹配。

## 10.9. Early Data

在HTTP/3中使用0-RTT给重放攻击提供了契机。
因此和HTTP/3一起使用0-RTT时，必须（MUST）使用[HTTP-REPLAY]中的反重放缓解方法。
当将[HTTP-REPLAY]应用于HTTP/3时，对TLS层的引用指的是在QUIC内执行的握手，而对应用数据的所有引用指的是流的内容。

## 10.10. Migration

特定的HTTP实现使用客户端地址来记录日志或者访问控制。
由于QUIC客户端的地址可能在连接生命周期内改变（并且未来版本可能支持同时使用多个地址），
因此如果这样的实现明确或显式接受源地址可能改变，它们就需要动态检索客户端当前的地址。

## 10.11. Privacy Considerations

HTTP/3的几个特性使观察者可将将单个客户端或服务端的多个动作关联起来。
这些包括了配置的值，刺激反馈的定时，以及所有受配置控制的特性的处理。

只要这些特性在行为上产生了巨大的差异，就可以使用它们来作为识别一个指定客户端的基础。

HTTP/3使用单QUIC连接的特性，使用户在一个站点上的行为可以关联起来。
不同的源复用连接允许了这些源之间活动的关联性。

QUIC的一些特性要求立刻响应，并可以用来测量到它们对端的延迟；
在某些特定场景下，这个特性可能存在隐私问题。
