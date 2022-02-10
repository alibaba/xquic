# 摘要
本文定义了QUIC传输协议的核心特性。QUIC为应用提供经过流控的流（Stream），可用于结构化通信、低延迟连接建立和网络路径迁移。QUIC还包含在多种部署情况下确保机密性、完整性和可用性的安全措施。随附文件描述了用于密钥协商的TLS集成、丢包检测和一个拥塞控制算法示例。

# 1. 概述（Overview）
QUIC是一种安全的通用传输层协议。本文定义了QUIC的版本1，它符合在[QUIC-INVARIANTS]中定义的QUIC的版本无关特性。

QUIC是一种面向连接的协议，可在客户端和服务端之间建立有状态的交互。

QUIC握手结合了加密和传输参数的协商。QUIC集成了TLS握手[TLS13]，使用定制的框架来保护数据包。TLS和QUIC的集成在[QUIC-TLS]中有更详细的说明。握手的设计使得可以尽快交换应用数据：如果之前有过握手过程和保存配置，那么客户端可以启用立即发送数据（0-RTT）的选项。

在QUIC协议中，终端（Endpoint）通过交换QUIC包（Packet）通信。大多数数据包中包含帧（Frame），帧携带控制信息和应用数据。QUIC验证每个数据包的完整性，并尽可能对所有数据包进行加密。QUIC协议承载在[UDP]协议之上，以更方便其在现有系统和网络中部署。

应用层协议建立QUIC连接，在其上通过流（Stream）来交换信息，流是有序的字节序列。QUIC可以创建两种类型的流：双向流和单向流，双向流允许两端互相收发数据，单向流只允许单个终端发送数据。基于credit的方案用于限制流的创建数并限制可以发送的数据量。

QUIC提供必要的反馈，以实现可靠传输和拥塞控制。在[QUIC-RECOVERY]第6章中描述了一种用于检测丢包和恢复数据的算法。QUIC依靠拥塞控制来避免网络拥塞。在[QUIC-RECOVERY]第7章有一个示例性的拥塞控制算法。

QUIC连接不严格绑定到某条网络路径。连接标识符（CID）的引入允许连接迁移到新的网络路径。不过在当前的QUIC版本中只有客户端才能迁移。这种设计还允许在网络拓扑或地址映射发生变更后重新建链，例如可NAT重新绑定导致的接续。

QUIC为终止连接提供多个选项，使得应用可以优雅关闭，终端可以协商超时时间，出现错误会立即导致连接关闭，并且无状态重置（Stateless Reset）机制可以在一个终端失去状态后终止连接。

## 1.1. 文档结构（Document Structure）

本文描述了QUIC协议的核心，文档结构如下：

* 流是QUIC提供的基本服务抽象：
  - 第2章 流相关的核心概念
  - 第3章 流状态参考模型
  - 第4章 流控操作
  
* 连接是QUIC终端通信的上下文
  - 第5章 连接相关的核心概念
  - 第6章 版本协商
  - 第7章 建链流程
  - 第8章 地址校验和拒绝服务攻击的规避措施
  - 第9章 连接迁移
  - 第10章 连接关闭的选项及流程
  - 第11章 流和连接的错误处理指引
  
* 包和帧是QUIC通信的基本单位
  - 第12章 包和帧相关的概念
  - 第13章 数据传输、重传和确认模型
  - 第14章 承载QUIC包的UDP报文大小规则

* 最后是QUIC协议元素的编码细节
  - 第15章 版本号约定
  - 第16章 变长整数编码
  - 第17章 包格式详解
  - 第18章 传输参数
  - 第19章 帧格式详解
  - 第20章 错误码

随附文档描述了QUIC的丢包检测和拥塞控制（参见[QUIC-RECOVERY]）、TLS的使用和其他加密机制（参见[QUIC-TLS]）。

本文描述了QUIC版本1，其满足[QUIC-INVARIANTS]描述的与版本无关的QUIC协议特性。

需要引用QUIC版本1，参考这篇文档，需要引用QUIC版本无关特性的受限集合，请参考[QUIC-INVARIANTS]。

## 1.2. 术语与定义（Terms and Definitions）
本文中的关键词"MUST"，"MUST NOT"，"REQUIRED"，"SHALL"，"SHALL NOT"，"SHOULD"，"SHOULD NOT"，"RECOMMENDED"，"NOT RECOMMENDED"，"MAY"，以及"OPTIONAL"，当且仅当他们全部以大写字母出现的时候，需要按BCP 14[RFC2119][RFC8174]所述的方式理解。

本文中常用术语如下所示：

QUIC（QUIC）：本文描述的传输协议，QUIC是一个名字，不是缩略语。

终端（Endpoint）参与QUIC连接的实体，可以生成、接收和处理QUIC包。QUIC只有两种类型的终端：客户端和服务端。

客户端（Client）：发起连接的QUIC终端。

服务端（Server）：接收连接的QUIC终端。

QUIC包（QUIC packet）：可被一个UDP报文封装的完整的QUIC处理单元，一个UDP报文可以包含一个或多个QUIC包。

ACK触发包（Ack-eliciting packet）：包含除ACK、PADDING和CONNECTION_CLOSE以外的帧的QUIC包，触发接收端回应一个ACK确认，参见第13.2.1小节。

帧（Frame）：QUIC定义的结构化的协议信息单元。QUIC有多种帧类型，不同类型的帧携带不同的信息。一个QUIC包中可包含一个或多个帧。

地址（Address）：在不加限制的情况下，是由IP版本、IP地址和UDP端口号组成的元组，表示网络路径的一端。

连接ID（Connection ID，CID）：用于标识QUIC连接终端的标识符。每个终端为其对端选择一个或多个CID，并包含在发送给对端的数据包中。该值在对端是可见的。

流（Stream）：在QUIC连接中传输有序字节的单向或双向通道。一个QUIC连接可以同时承载多个流。

应用（Application）：使用QUIC收发数据的实体。

本文使用术语"QUIC包", "UDP报文"和"IP包"表示对应的协议单元，也就是，一个或多个QUIC包可以被封装在一个UDP报文内，一个UDP报文被封装在一个IP数据包中。

## 1.3. 符号约定（Notational Conventions）
本文中的数据包和数据帧使用自定义的格式说明，引入这种格式是为了简要描述协议元素，而不是正式定义。

复合字段：首先给出命名，后接由一对大括号括起的字段列表，列表中的每个字段都用逗号分隔。

单个字段：包括长度信息，固定、可选和重复指示，遵循如下符号约定，其中长度单位为位（bit）：

x (A)：表示x的长度为A位

x (i)：表示x是变长整数值，其长度编码参见第16章。

x (A..B)：表示x是一个长度介于A到B位之间的值，A省略的话，表示从0位开始，B省略的话表示无上限，一般按字节取整

x (L) = C：表示x是一个固定值C，x的长度为L，L可以使用上述3种长度形式之一。

x (L) = C..D：表示x的取值范围为从C到D闭区间的值，长度为L如上所示。

[x (L)]：表示x为可选，且长度为L。

x (L) ...：表示x以长度L重复0到多次

本文使用网络字节序，即大端字节序。字段从每个字节最高有效位开始，按照惯例，单个字段通过名字来引用复合字段。

```
   Example Structure {
     One-bit Field (1),
     7-bit Field with Fixed Value (7) = 61,
     Field with Variable-Length Integer (i),
     Arbitrary-Length Field (..),
     Variable-Length Field (8..24),
     Field With Minimum Length (16..),
     Field With Maximum Length (..128),
     [Optional Field (64)],
     Repeated Field (8) ...,
   }
```
图1: Example Format

当在上下文中提到某个1比特长度的字段，可以通过在其所在字节中将该字段所在位设为1，其余置0，来指示该字段的位置，例如，0x80可以表示该字段在该字节的最高有效位上，如图1的One-bit字段。

# 2. 流（Streams）
QUIC中的流为应用提供了一个轻量级的、有序的字节流抽象。流可以是单向或双向的。

可以通过直接发送数据来创建流。与流管理相关的其他流程，如关闭、取消和流控管理，都旨在带来最小的开销。例如，单个STREAM帧（第19.8节）可以打开流、携带数据并关闭流。流也可以是持久的，可以持续整个连接的生命周期。

流可以由任一终端创建，可以与其他流并行交错发送数据，并且可以取消。QUIC不保证不同流上的字节是保序的。

QUIC允许任意数量的流并行发送数据，并允许在一个流上发送任意数量的数据，但需要接受流控约束和流限制，参见第4章。

## 2.1. 流类型和标识（Stream Types and Identifiers）
流可以是单向和双向的，单向流只从流的发起方发送数据到对端。双向流可以同时收发数据。

一个连接中的流由一个62位的整数(0到2^62^-1)标识，称为流ID，由第16章中定义的变长整数编码。在一个连接中，任意流的ID都是不同的，QUIC端禁止(**MUST NOT**)重用流ID。

流ID的最低有效位（0x01）标识流的发起者。客户端启动的流的流ID为偶数（位设置为0），服务端启动的流的流ID为奇数（位设置为1）。

流ID的第二个最低有效位（0x02）区分双向流（位设置为0）和单向流（位设置为1），因此，来自流ID的两个最低有效位将流识别为四种类型之一，如表1中总结的：

|Bits| Stream Type                      |
|:---|:---|
|0x0 | Client-Initiated, Bidirectional  |
|0x1 | Server-Initiated, Bidirectional  |
|0x2 | Client-Initiated, Unidirectional |
|0x3 | Server-Initiated, Unidirectional |

表1: Stream ID Types

每个类型流的ID取值空间从最小值开始（0x00到0x03，相应的），后续的流ID在此基础上线性递增。乱序使用流ID会导致该类型下所有较低编号的流都被打开。

## 2.2. 收发数据（Sending and Receiving Data）
STREAM帧（参见第19.8节）封装应用发送的数据，QUIC端在STREAM帧中使用流ID和Offset字段按序放置数据。

QUIC端必须（**MUST**）将流数据按序投递给应用，投递有序字节流要求QUIC端缓冲任何无序接收的数据，直至达到通告的流控限制。

QUIC协议中没有特别指出允许乱序投递流数据。然而，在实现中可以（**MAY**）选择提供向应用投递无序数据的能力。

QUIC端可从某个流中多次接收相同Offset的数据，重复的数据可以（**MAY**）被丢弃，但这些相同Offset的数据不得（**MUST NOT**）改变，如果有变更则视为PROTOCOL_VIOLATION类型的连接错误。

流是有序的字节流抽象，QUIC看不到除流外的其他结构。在数据传输、丢包重传或投递给接收端的应用时，QUIC不会保存每个STREAM帧的边界。

终端不得（**MUST NOT**）在任何流上发送数据，除非确保数据在其对端设置的流控窗口内，流量控制在第4章中有详细描述。

## 2.3. 流的优先级（Stream Prioritization）
如果分配给流的资源的优先级正确，则流复用会对应用性能产生重大改进。

QUIC不提供彼此交换优先级信息的机制，而是依赖于从应用接收优先级信息。

QUIC的实现应该（**SHOULD**）提供给应用可以指示流的相对优先级的方法，QUIC依据应用提供的信息来确定如何将资源分配给活动流。

## 2.4. 基于流的操作（Operations on Streams）
本文没有定义QUIC的API，但定义了一组应用层协议可以依赖的流上的函数。应用层协议可以假设QUIC实现提供了一个接口，其中包括本节中描述的操作。设计用于特定应用层协议的实现可能仅提供该协议需要的那些操作。

在流的发送侧，应用层协议可以：

* 写数据，确保流上有为待写数据保留基于流控的发送许可（第4.1节）；
* 结束流（优雅关闭），触发设置了FIN位的STREAM帧（第19.8节）；
* 重置流（突然终止），如果流不在终止态，则触发一个RESET_STREAM帧（第19.4节）。

在流的接收侧，应用层协议可以：

* 读数据；
* 终止读取流，请求关闭，可能触发STOP_SENDING帧（第19.5节）。

应用层协议还可以请求获知流上的状态变化，包括对端何时打开或重置流、对端何时中止读取流、新数据何时可用以及基于流控，何时可以或不可以写入数据。

# 3. 流状态（Stream States）
本节以描述流的接收侧与发送侧来说明流的特性，并介绍了两种状态机：一种是流的发送侧对应的状态机（第3.1节），另一种是流的接收侧的状态机（第3.2节）。

单向流依据流类型和端角色，决定用发送状态机还是接收状态机，双向流的两侧，两种状态机都采用。在大多数情况下，无论是单向流还是双向流，这些状态机的使用方式都是相同的。对双向流来说，打开流的条件有一点复杂，因为无论是由发送侧还是接收侧的打开，都会使流双向开启。

本节中显示的状态机能提供大量信息。本文使用流状态机来描述这些规则，即在什么场景下，发送什么类型的帧，期待怎样的回应，在什么场景能接收什么类型的帧。尽管状态机旨在方便实现QUIC，但并不限制实现。一个实现可以定义不同的状态机，只要它的行为与其他实现这些状态的实现一致即可。

> 注意：在某些场景下，一个事件或动作可能引起状态迁移多次，例如，发送设置FIN位的STREAM帧的动作可引起流的发送侧的两次状态迁移：从Ready态跃迁到Send态，再从Send态迁移到Data Send态。

## 3.1. 发送方流状态（Sending Stream States）
下图是流的发送侧的状态机

```
          o
          | Create Stream (Sending)
          | Peer Creates Bidirectional Stream
          v
      +-------+
      | Ready | Send RESET_STREAM
      |       |-----------------------.
      +-------+                       |
          |                           |
          | Send STREAM /             |
          |      STREAM_DATA_BLOCKED  |
          v                           |
      +-------+                       |
      | Send  | Send RESET_STREAM     |
      |       |---------------------->|
      +-------+                       |
          |                           |
          | Send STREAM + FIN         |
          v                           v
      +-------+                   +-------+
      | Data  | Send RESET_STREAM | Reset |
      | Sent  |------------------>| Sent  |
      +-------+                   +-------+
          |                           |
          | Recv All ACKs             | Recv ACK
          v                           v
      +-------+                   +-------+
      | Data  |                   | Reset |
      | Recvd |                   | Recvd |
      +-------+                   +-------+

```
图2: States for Sending Parts of Streams

由终端（类型0、2是客户端，1、3是服务端）启动的流的发送侧是由应用创建。Ready态表示新创建的流可以从应用接收数据，流数据在这种状态下可以被缓存以备发送。

第一个STREAM或STREAM_DATA_BLOCKED帧的发送使得流的发送侧进入Send态，一个实现可以选择延迟为流分配流ID，直到第一个STREAM发送并进入Send态，这样可以采取更好的优先级策略。

由对端（类型0是服务端，1是客户端）启动的双向流，在本端接收侧创建的同时，同步创建发送侧，进入Ready态。

在Send态，本端使用STREAM帧传输（必要时重传）流数据，并遵守由对端设置的流控限制，接收和处理MAX_STREAM_DATA帧。如果因为流控限制（第4.1节）暂时不能发送，则会生成并发送STREAM_DATA_BLOCKED帧。

在应用指示已发送完所有流数据，并已发送设置了FIN位的STREAM帧后，流的发送侧进入Data Sent态。在此状态下，本端仅在必要时重传流数据（对端ACK显示有丢包），不需要继续检查流控限制或发送STREAM_DATA_BLOCKED帧，此时可能会收到对端的MAX_STREAM_DATA帧，本端可以安全地忽略它们，对端收齐数据之后将不再重复发送MAX_STREAM_DATA。

一旦所有流数据都被成功确认，流的发送侧进入Data Recvd状态，这是一个终止状态。

在Ready、Send或Data Sent任一状态，应用可以发信号表示它希望放弃流数据传输，或者，本端也可能会收到对端的STOP_SENDING帧。在上述情况下，本端都要发送RESET_STREAM帧，之后进入Reset Sent状态。

终端可能（**MAY**）在流上发送的第一帧就是RESET_STREAM，这使得流的发送侧打开后立即切换到Reset Sent状态。

一旦包含RESET_STREAM的数据包被确认，流的发送侧立即进入Reset Recvd状态，这也是一个终止状态。

## 3.2. 接收方流状态（Receiving Stream States）
图3是从对端接收数据的流的接收侧的状态机，流的接收侧的状态仅反映流的发送侧的一些状态，不会跟踪发送侧上无法观察到的状态，例如Ready状态。相应的，流的接收侧会跟踪向应用投递数据的情况，其中一些状态发送方不可见。

```
          o
          | Recv STREAM / STREAM_DATA_BLOCKED / RESET_STREAM
          | Create Bidirectional Stream (Sending)
          | Recv MAX_STREAM_DATA / STOP_SENDING (Bidirectional)
          | Create Higher-Numbered Stream
          v
      +-------+
      | Recv  | Recv RESET_STREAM
      |       |-----------------------.
      +-------+                       |
          |                           |
          | Recv STREAM + FIN         |
          v                           |
      +-------+                       |
      | Size  | Recv RESET_STREAM     |
      | Known |---------------------->|
      +-------+                       |
          |                           |
          | Recv All Data             |
          v                           v
      +-------+ Recv RESET_STREAM +-------+
      | Data  |--- (optional) --->| Reset |
      | Recvd |  Recv All Data    | Recvd |
      +-------+<-- (optional) ----+-------+
          |                           |
          | App Read All Data         | App Read Reset
          v                           v
      +-------+                   +-------+
      | Data  |                   | Reset |
      | Read  |                   | Read  |
      +-------+                   +-------+

```
图3: States for Receiving Parts of Streams

当端接收到某流的第一个STREAM、STREAM_DATA_BLOCKED或RESET_STREAM帧时，会创建该流的接收侧（客户端的类型1和3，或服务端的类型0和2）。对于由对端发起的双向流，端接收到某流的MAX_STREAM_DATA或STOP_SENDING帧也会创建该流的接收侧，流的接收侧的初始状态是Recv。

对于双向流，当流的发送侧（类型0为客户端，类型1为服务端）进入Ready状态时，接收侧进入Recv状态。

当接收到MAX_STREAM_DATA或STOP_SENDING帧时，端会打开双向流，因为收到未打开的流的MAX_STREAM_DATA帧表示对端已打开流并提供流控管理，接收到未打开的流的STOP_SENDING帧表示对端不再希望接收此流上的数据。如果数据包丢失或乱序，任一帧都可能在STREAM或STREAM_DATA_BLOCKED帧之前到达。

在创建某流ID对应的流之前，所有同类型的流ID比之要小的流都必须（**MUST**）已创建完成，这能确保流的创建顺序在两端都是一致的。

在Recv状态下，端接收STREAM和STREAM_DATA_BLOCKED帧，缓存收到的数据，按序重组之后投递给应用，应用消费完数据，缓冲区可用之后可发送MAX_STREAM_DATA帧以允许对端发送更多数据。

当接收到带有FIN位的STREAM帧时，流的最终大小确定（参见第4.5节），流的接收侧因此进入Size Known状态。在此状态下，端不再需要发送MAX_STREAM_DATA帧，只需接收某些流数据的重传即可。

一旦接收完所有数据，流的接收侧就进入Data Recvd状态，接收到与导致流切换为Size Known态相同的STREAM帧后也可能会切入此状态。接收齐所有数据后，可以丢弃该流上收到的任何STREAM或STREAM_DATA_BLOCKED帧。

Data Recvd状态持续到数据被投递给应用，一旦数据投递完，流即进入Data Read状态，这是一个终止状态。

在Recv或Size Known状态下收到RESET_STREAM帧会使得流进入Reset Recvd状态。这可能会导致向应用投递流数据的过程中断。

在Data Recvd状态，收到RESET_STREAM时，可能已经接收完所有流数据；类似地，在Reset Recvd态，即接收到RESET_STREAM帧后，剩余的流数据也有可能到达。一个实现可以自由选择如何处置这种状况。

发送RESET_STREAM意味着端不能保证流数据的完整投递，但收到RESET_STREAM，并不意味着不再投递流数据。一个实现可以中断流数据的投递，丢弃任何未消费的数据，并发出RESET_STREAM的接收信号，但如果此时流数据被完全接收并被缓冲以供应用读取，则实现可以选择扣压RESET_STREAM信号或保留。如果RESET_STREAM被扣压，则流的接收侧仍然处于Data Recvd态。

一旦应用接收到指示流被重置的信号，流的接收侧即切换到Reset Read状态，这也是一个终止状态。

## 3.3. 允许的帧类型（Permitted Frame Types）

流的发送方仅发送三种影响发送方或接收方的流状态的帧类型：STREAM（第19.8节）,STREAM_DATA_BLOCKED（第19.13节），和RESET_STREAM（第19.4节）。

发送方在终止状态（Data Recvd或Reset Recvd）不得（**MUST NOT**）发送任何这些帧。发送方在处于Reset Sent态（即在发送RESET_STREAM帧之后）或终止态时不得（**MUST NOT**）发送STREAM或STREAM_DATA_BLOCKED帧。接收方在任何状态下都可接收这三种帧，因为承载它们的数据包可能存在延迟或乱序。

流的接收方可发送MAX_STREAM_DATA帧（第19.10节）和STOP_SENDING帧（第19.5节）。

接收方在Recv态时仅可发送MAX_STREAM_DATA帧，在除了Reset Recvd和Reset Read态（即尚未收到RESET_STREAM）的其他状态，都可以发送STOP_SENDING帧。不过，在Data Recvd状态下发送STOP_SENDING帧几乎没有价值，因为所有流数据都已接收。由于数据包的延迟或乱序，发送方可以在任何状态下收到上述两种类型的帧。

## 3.4. 双向流状态（Bidirectional Stream States）

双向流由发送侧和接收侧组成。实现可以将双向流的状态表示为发送侧和接收侧流状态的组合。最简单的模型是在发送侧或接收侧处于非终止状态时将流状态表示为“打开”，当发送侧和接收侧都处于终止状态时将流表示为“关闭”。

表2呈现了一个更复杂的双向流状态映射模型，其可以松散地对应到HTTP/2[HTTP2]中定义的流状态。此时，发送侧或接收侧的多个状态被映射到同一个复合状态。请注意，这只是这种映射的一种可能表达，其要求在切换到“关闭”或“半关闭”状态之前确认数据。

|Sending Part	            |Receiving Part	            |Composite State     |
|:---|:---|:---|
|No Stream / Ready	        |No Stream / Recv (*1)	    |idle|
|Ready / Send / Data Sent	|Recv / Size Known	        |open|
|Ready / Send / Data Sent	|Data Recvd / Data Read	    |half-closed (remote)|
|Ready / Send / Data Sent	|Reset Recvd / Reset Read	|half-closed (remote)|
|Data Recvd	                |Recv / Size Known	        |half-closed (local)|
|Reset Sent / Reset Recvd	|Recv / Size Known	        |half-closed (local)|
|Reset Sent / Reset Recvd	|Data Recvd / Data Read	    |closed|
|Reset Sent / Reset Recvd	|Reset Recvd / Reset Read	|closed|
|Data Recvd	                |Data Recvd / Data Read	    |closed|
|Data Recvd	                |Reset Recvd / Reset Read	|closed|      

表2: Possible Mapping of Stream States to HTTP/2

>Note (*1)：如果流尚未被创建或者其接收侧处于Recv态但尚未接收到任何数据，则将流置为 idle态。

## 3.5. 请求状态转换（Solicited State Transitions）

如果应用不再对它在流上接收的数据感兴趣，它可以中止读取流并指定应用级错误码。

如果流处于Recv或Size Known状态，传输应该（**SHOULD**）通过发送一个STOP_SENDING帧来提示相反方向的流关闭。这通常表示应用不再读取它从流中接收的数据，但这不是说传入的数据将被忽略。

发送STOP_SENDING帧后接收到的STREAM帧仍计入连接和流控，即使这些帧在接收方可能被丢弃。

STOP_SENDING帧请求接收到该帧的终端发送RESET_STREAM帧。如果流处于Ready或Send状态，则接收到STOP_SENDING帧的终端必须（**MUST**）发送RESET_STREAM帧。如果流处于Data Sent态，此端可以（**MAY**）延迟发送RESET_STREAM帧，直到已发送的数据都被确认或声明丢失。如果有数据被声明丢失，终端应该（**SHOULD**）发送一个RESET_STREAM帧而不是重传数据。

终端应该（**SHOULD**）将错误码从STOP_SENDING帧复制到它发送的RESET_STREAM帧，但也可以使用任何应用级错误码。发送了STOP_SENDING帧的终端可以（**MAY**）忽略随后接收到的RESET_STREAM帧中的错误码。

STOP_SENDING应该（**SHOULD**）只由尚未被对端重置的流这一侧发送。STOP_SENDING对于处于Recv或Size Known状态的流最有用。

如果先前包含STOP_SENDING的数据包丢失，则本端应再次发送STOP_SENDING帧。但是，一旦所有流数据都收齐或接收到RESET_STREAM帧——也就是说，流处于除Recv或Size Known之外的其他状态——发送STOP_SENDING帧就不必要了。

希望将双向流的两个方向都关闭的终端可以通过发送RESET_STREAM帧来终止一个方向，并且可以通过发送STOP_SENDING帧触发相反方向的关闭。

# 4. 流量控制（Flow Control）
接收方需要限制他们必须缓冲的数据量，以防止被较快的发送方的大量数据淹没或被恶意发送方消耗大量内存。为了使接收方能够限制一个连接的内存消耗，可以将各个流或一个多流连接视为一个整体进行流控。QUIC接收方可以控制发送方在某一个流或所有流上可发送的最大数据量，如第4.1节和第4.2节所述。

类似地，为了限制一个连接内的并发流数，QUIC一端可限制对端能发起的最大累加流个数，如第4.6节所述。

对CRYPTO帧数据的流控方式与普通数据不同。QUIC依靠加密协议实现来避免数据的过度缓冲，参见[QUIC-TLS]。为了避免在多个层进行过多的缓冲，QUIC实现应该（**SHOULD**）为加密协议实现提供一个接口来告知其缓冲限制。

## 4.1. 数据流控（Data Flow Control）

QUIC采用基于限额的流量控制方案，其中接收方通告它在给定流上或整个连接上可以接收的总字节数的限额。这导致QUIC中有两个级别的数据流控制：
* 基于流的流控，它通过限制可以在单个流上可发送的数据量来防止单个流消耗整个连接的接收缓冲区。

* 基于连接的流控，它通过限制所有流上通过STREAM帧发送的流数据的总字节数来防止发送方超出接收方的连接缓冲区容量。

发送方不得（**MUST NOT**）发送超过任一限制的数据。

接收方在握手期间通过传输参数为所有流设置初始限制（第7.4节）。随后，接收方向发送方发送MAX_STREAM_DATA帧（第19.10节）或MAX_DATA帧（第19.9节）以通告更大的限制。

接收方可以通过发送带有相应流ID的MAX_STREAM_DATA帧来通告流的更大限额。MAX_STREAM_DATA帧指定流的绝对字节偏移量上限。接收方可以基于流上当前消费的数据偏移量来确定要通告的流控偏移量。

接收方可以通过发送MAX_DATA帧来为一个连接通告更大的限额，该帧指定所有流的绝对字节偏移总和的上限。接收方维护在所有流上接收到的字节的累积总和，用于判定是否违反了通告的连接或流上数据限额。接收方可以根据所有流上消耗的字节总和来确定要通告的最大数据限额。

一旦接收方通告了连接或流上的限额，再通告一个更小的限额不会导致错误，但会被发送方忽略。

如果发送方违反了通告的连接或流上的数据限额，则接收方必须（**MUST**）以FLOW_CONTROL_ERROR类型的错误关闭连接，有关错误处理的详细信息，请参阅第11章。

发送方必须（**MUST**）忽略不增加流控限额的任何MAX_STREAM_DATA或MAX_DATA帧。

如果发送方已发送数据达到限额，则将无法发送新数据并被视为阻塞，发送方应该（**SHOULD**）发送一个STREAM_DATA_BLOCKED或DATA_BLOCKED帧来向接收方表明它有数据要写入但被流控限额阻塞。如果发送方被阻塞的时间长于空闲超时定时器（第10.1节），即使发送方有可用于传输的数据，接收方也可能关闭连接。为了防止连接关闭，受流控阻塞的发送方应该（**SHOULD**）在没有ACK触发包数据包传输时定期发送STREAM_DATA_BLOCKED或DATA_BLOCKED帧。

## 4.2. 增加流控上限（Increasing Flow Control Limits）

在MAX_STREAM_DATA和MAX_DATA帧中通告多少限额以及何时发送这两种帧，是由实现决定的，但本节将提供了一些注意事项。

为避免阻塞发送方，接收方可以（**MAY**）在一个RTT中多次发送MAX_STREAM_DATA或MAX_DATA帧，或者提前足够时间量发送这两种帧，以便为丢包和后续恢复留出时间。

控制帧会增加连接开销，因此，频繁发送变化很小的MAX_STREAM_DATA和MAX_DATA帧是不可取的。另一方面，如果更新不那么频繁，则需要更大的限额增量以避免阻塞发送方，从而要求接收方承担更大的资源消耗。在确定通告多大的限额时，需要在资源消耗和连接开销之间进行权衡。

接收方可以使用自动调整机制，根据RTT估计或应用消费接收到的数据的速率来调整通告限额的频率和数值，类似于常见的TCP实现。作为一种优化，只有当有其他帧要发送时，本端才可以发送与流控相关的帧，以确保流控不会导致发送额外的数据包。

被阻塞的发送方可以不发送STREAM_DATA_BLOCKED或DATA_BLOCKED帧。因此，接收方不得（**MUST NOT**）等待STREAM_DATA_BLOCKED或DATA_BLOCKED帧到达之后再发送MAX_STREAM_DATA或MAX_DATA帧，因为这样做可能会导致发送方在连接的其余时间被阻塞。即使发送方发送了这些帧，接收方等待它们到达再回应也会导致发送方被阻塞至少整个RTT。

当发送方在被阻塞后收到新的限额时，它可能会发送大量数据作为响应，导致短期拥塞。有关发送方如何避免这种拥塞的讨论，请参见[QUIC-RECOVERY]第7.7节。

## 4.3. 流控性能（Flow Control Performance）

如果本端无法确保其对端始终具有大于此连接上的带宽延迟乘积的可用流控限额，则其接收吞吐量将受到流控的限制。

数据包丢失会导致接收缓冲区出现间隙，从而阻止应用消费数据并释放接收缓冲区空间。

及时发送流控限额的更新可以提高性能。仅发送携带流控帧的数据包会增加网络负载并对性能产生不利影响。将流控帧与其他帧（例如ACK帧）一起发送可降低这些更新的成本。

## 4.4. 处理流关闭（Handling Stream Cancellation）

终端间需要最终就每个流消耗的流控限额达成一致，以便能够满足连接级流量控制。

收到RESET_STREAM帧后，终端将设置匹配的流的状态为终止态，并忽略到达该流的其他数据。

RESET_STREAM可以立即终止流的一个方向。对于双向流，RESET_STREAM对相反方向的数据流没有影响。两端都必须（**MUST**）在未终止方向上保持流的流控状态，直到该方向进入终止状态。

## 4.5. 流最终大小（Stream Final Size）

最终大小是流消耗的流控限额。假设流上的每个连续字节都发送一次，最终大小就是发送的字节数，更一般地说，是比这些字节中的最大偏移字节量高1，如果没有发送字节，则为零。

无论流如何终止，发送方始终将流的最终大小可靠地传递给接收方。最终大小是带有FIN标志的STREAM帧的Offset或Length字段的总和，注意这些字段可能是隐式的。或者，RESET_STREAM帧的Final Size字段会携带此值，这保证了两端就发送方在该流上消耗了多少流控限额达成一致。

当流的接收侧进入Size Known或Reset Recvd态(参见第3章)时，终端将知道流的最终大小。接收方必须（**MUST**）使用流的最终大小作为流上发送的所有字节数来参与连接级流控的计算。

终端不得（**MUST NOT**）在流上发送等于或超过最终大小的数据。

一旦知道流的最终大小，它就不能变化。如果接收到的RESET_STREAM或STREAM帧指示流的最终大小发生变化，终端应该（**SHOULD**）响应类型为FINAL_SIZE_ERROR的错误。有关错误处理的详细信息，请参阅第11章。接收方应该（**SHOULD**）将接收到大于等于最终大小的数据视为FINAL_SIZE_ERROR类型的错误，即使在流关闭之后也是如此。不过生成这些错误不是强制性的，因为要求端生成这些错误也意味着端需要维护流关闭后的最终大小，这可能意味着重要的状态承诺。

## 4.6. 控制并发（Controlling Concurrency）

本端可以限制对端可以打开的传入流的累积数量，只能打开流ID小于 (max_streams * 4 + first_stream_id_of_type)的流，见表1。初始限制在传输参数中设置，参见第18.2节，随后可以使用MAX_STREAMS帧通告后续限额，参见第19.11节。单向和双向流分别有各自的限额。

如果接收到的max_streams传输参数或MAX_STREAMS帧的值大于2^60^，这将允许无法表示为变长整数的最大流ID，参见第16章。上述两种情况，连接都必须（**MUST**）关闭。如果有问题的值是在传输参数中收到的，连接错误类型为TRANSPORT_PARAMETER_ERROR；如果是在帧中收到，则连接错误类型为FRAME_ENCODING_ERROR。详情参见第16章。

终端不得（**MUST NOT**）超过其对端设置的限制。接收到流ID超过其发送限制的帧的终端必须（**MUST**）将此视为STREAM_LIMIT_ERROR类型的连接错误，有关错误处理的详细信息，请参阅第11章。

一旦接收方使用MAX_STREAMS帧通告流限额，再通告较小的限额就无效。必须（**MUST**）忽略不增加流限额的MAX_STREAMS帧。

与流和连接上的流控制一样，本文让实现来决定何时以及什么场景应该通过MAX_STREAMS向对端通告允许多少个流。当流关闭时，实现可能会选择增加限制，以保持对端可用的流数量大致一致。

由于对端的限制而无法打开新流的终端应该（**SHOULD**）发送一个STREAMS_BLOCKED帧 (参见第19.14节)。该信号对调试很有用。终端不得（**MUST NOT**）等待此信号到达后再通告额外的限额，否则将意味着对端将被阻塞至少整个RTT，如果对端选择不发送STREAMS_BLOCKED帧，则可能无限期地阻塞。

# 5. 连接（Connections）

QUIC连接在客户端和服务端之间共享状态。

每个连接都从握手阶段开始，在此期间，两端使用加密握手协议[QUIC-TLS]协商共享秘钥及应用层协议。两端通过握手（第7章）确认通讯意愿（第8.1节）并为连接交换参数（第7.4节）。

应用层协议可以在握手阶段使用连接，但有一些限制。0-RTT允许客户端在收到服务端响应之前发送应用数据。然而，0-RTT没有提供针对重放攻击的保护，参见[QUIC-TLS]第9.2节。服务端也可以在收到最终加密握手消息（确认客户端的身份和活性之用）之前发送应用数据到客户端。这些功能为应用层协议提供牺牲安全性以换取较低时延的选项。

连接ID的使用（第5.1节）允许连接迁移到新的网络路径，终端可以直接发起迁移，也可以在中间设备变更时强制迁移。第9章描述了与迁移相关的安全和隐私问题的治理措施。

对于不再需要的连接，客户端和服务端可以通过多种方式终止连接，如第10章所述。

## 5.1. 连接ID（Connection ID，CID）

每个连接都拥有一组连接标识符或称连接ID（后续统一简称“CID”），每个连接标识符都可以标识该连接。每个终端都可以独立选择自己的CID供对端使用。

CID的主要功能是确保较低协议层（UDP、IP）的寻址更改不会导致QUIC连接的数据包传输到错误的终端。任一终端都使用特定于实现（也可能是特定于部署）的方法选择CID，使得对端发送的携带该CID的数据包能路由过来，并在接收到时识别出来。

终端可以使用多个CID，以便外部观察者在没有终端协作上下文时无法识别来自同一连接的不同CID的数据包，参见第9.5节。

CID不得（**MUST NOT**）包含任何可被外部观察者（即不与发送端合作的观察者）用于将它们与同一连接的其他CID相关联的信息。作为一个简单的例子，这意味着同一连接上不得（**MUST NOT**）多次给出相同CID。

具有长报文头的数据包包含源连接ID（Source Connection ID，后续统一简称“SCID”）和目的连接ID（Destination Connection ID，后续统一简称“DCID”）字段。这些字段可用于填写新的CID，详细信息请参阅第7.2节。

具有短报文头的数据包（第17.3节）仅包含DCID，并显式省略长度。对端应明确知道DCID字段的长度。使用基于CID进行路由的负载均衡器的终端，可以与负载均衡器就CID的固定长度达成一致，或者就编码方式达成一致，约定在某固定部分显式编码长度信息，这样即使CID的长度不同，仍然能为负载均衡器使用。

Version Negotiation包（第17.2.1小节）回显客户端填写的CID，以便正确路由到客户端并证明该数据包是对客户端发送的数据包的响应。

当不需要用CID路由到正确的终端时，可以使用零长度CID。但是，使用零长度CID时，如果在同一本地IP地址和UDP端口上复用连接，可能导致对端在连接迁移、NAT重新绑定和客户端端口重用的时候失败。使用零长度CID时，终端不得（**MUST NOT**）为多个并发连接使用相同的IP地址和端口，除非确定不需要使用这些协议功能。

当终端使用非零长度的DCID发送数据包时，它需要在对端用NEW_CONNECTION_ID帧(参见第19.15节)提供的CID列表中选择一个。

### 5.1.1. 发布连接ID（Issuing Connection IDs）

每个CID都有一个对应的序号，以便在NEW_CONNECTION_ID或RETIRE_CONNECTION_ID帧时引用它。在握手期间，终端发出的长包头（第17.2节）的SCID字段中会携带初始CID，其序号为0，如果在传输参数中也携带了preferred_address CID，则该CID的序号为1。

可以使用NEW_CONNECTION_ID帧（第19.15节）将其他CID发送给对端，但每个新发布的CID的序号必须（**MUST**）加1。客户端发送的第一个DCID字段指定的CID和Retry包中的CID的都不需要指定序号。

当终端发布CID后，它在连接期间或者说直到对端通过RETIRE_CONNECTION_ID帧（第19.16节）停用该CID之前，都必须（**MUST**）接收携带此CID的数据包。已发布但未停用的CID被视为活动ID，任何活动CID都可以在任何时间在当前连接的任意类型数据包中使用。这也包括服务端通过preferred_address传输参数发布的CID。

终端应该（**SHOULD**）确保它的对端有足够数量的可用和未使用的CID。终端使用active_connection_id_limit传输参数通告他们愿意维护的活动CID的数量。终端不得（**MUST NOT**）提供超过对端限制的CID数。如果在NEW_CONNECTION_ID帧中同时指定足够大的Retire Prior To字段让对端停用该序号之前的所有CID，可以（**MAY**）临时超出限制。

NEW_CONNECTION_ID帧可能会导致终端增加一些活动CID并根据Retire Prior To字段停用某些CID。在处理NEW_CONNECTION_ID帧增加或停用活动CID后，如果活动CID的数量仍然超过其active_connection_id_limit传输参数中通告的值，则终端必须（**MUST**）关闭连接并显示CONNECTION_ID_LIMIT_ERROR类型的错误。

当对端停用某个CID后，终端应该（**SHOULD**）提供一个新的CID。如果该终端提供的CID数量未达到对端的active_connection_id_limit限制，则其在收到具有以前未使用（但发布过）的CID的数据包时可以（**MAY**）提供新的CID。终端可以（**MAY**）自行限制连接发布的CID总数，以避免CID耗尽的风险（参见第10.3.2小节），这样做也可以（**MAY**）减少它需要维护的每条路径的状态数量，就如路径验证（活跃）状态，每个发布的CID，都有可能对应一条交互路径（维护起来很耗资源）。

发起连接迁移并需要非零长度CID的终端应该（**SHOULD**）确保其对端可用的CID池还有余量，以允许对端在迁移时使用新的CID，如果该池耗尽，对端将无法响应。

在握手期间选择零长度CID的终端不能发布新的CID，通过任何网络路径向此终端发送的任何数据包的DCID字段的长度都必须为0。

### 5.1.2. 消费和停用连接ID（Consuming and Retiring Connection IDs）

在连接期间，终端可以随时将其填写的DCID变更为另一个可用的CID。终端在迁移时使用CID以响应对端，有关更多详细信息，请参阅第9.5节。

终端维护一组从其对端接收到的CID，在发送数据包时可以使用其中的任何一个。当终端希望在使用中删除某个CID时，它会向其对端发送RETIRE_CONNECTION_ID帧，表示不会再次使用该CID，并请求对端发送NEW_CONNECTION_ID帧将其替换为新的CID。

如第9.5节所述，终端将CID限制为关联单个本端地址或单个目的地址。当终端不再需要使用该CID关联的本地地址或目的地址时，则应该（**SHOULD**）停用该CID。

在某些情况下，终端可能需要停止接受某些其先前发布的CID，则可以发送NEW_CONNECTION_ID，内含Retire Prior To字段，表示先于此序号的CID全部停用。终端应该（**SHOULD**）继续允许接收先前发布的CID，直到它们被对端停用。如果终端不能再处理指定的CID，它可以（**MAY**）关闭连接。

在接收到内含增长的Retire Prior To字段的NEW_CONNECTION_ID帧后，在将新提供的CID添加到活动CID集合之前，对端必须（**MUST**）停用相应的CID并通过发送RETIRE_CONNECTION_ID帧通知对方。这种顺序使得终端可以替换所有活动CID，而不会出现对端没有可用CID的可能性，并且不会超出对端在active_connection_id_limit传输参数中设置的限制，参见第18.2节。在发送RETIRE_CONNECTION_ID请求时未能及时停用该CID可能导致连接失败，因为对端可能已经无法使用该CID。

在尚未收到对应的RETIRE_CONNECTION_ID帧的确认之前，终端应该（**SHOULD**）限制本地停用的CID的数量。终端应该（**SHOULD**）允许发送和跟踪至少两倍于active_connection_id_limit传输参数值的RETIRE_CONNECTION_ID帧的数量。就算可以（**MAY**）将超过active_connection_id_limit限制的需要停用的CID视为CONNECTION_ID_LIMIT_ERROR类型的连接错误，终端也不得（**MUST NOT**）在未停用CID的情况下遗忘该CID。

在发送NEW_CONNECTION_ID帧，携带的Retire Prior To值停用所有CID之后，收到对端响应的RETIRE_CONNECTION_ID帧之前，终端不应（**SHOULD NOT**）发送新的NEW_CONNECTION_ID帧更新Retire Prior To字段。

## 5.2. 匹配连接与数据包（Matching Packets to Connections）

传入的数据包在接收时会被分类。一类数据包可以关联到现有连接，另一类数据包——对服务端——可能创建一个新连接。

如果数据包具有与现有连接对应的非零长度的DCID，QUIC会相应地处理该数据包，将之与该CID关联。请注意，一个连接可以关联多个CID，参见第5.1节。

如果DCID的长度为零，并且数据包中的寻址信息，与终端用来标识具有零长度CID的连接的寻址信息匹配，则QUIC会将数据包作为该连接的一部分进行处理。终端可以仅使用目的IP和端口或同时使用源地址和目的地址进行标识，尽管这会使连接变得脆弱，如第5.1节所述。

终端可以为任何不能归属于现有连接的数据包发送Stateless Reset包（参见第10.3节）。无状态重置机制允许对端更快地识别连接何时变得不可用。

如果数据包与该连接的状态不一致，则即使与现有连接匹配的数据包也将被丢弃。例如，如果数据包指示的协议版本与连接的协议版本不同，或者预期的密钥变得可用，但数据包保护策略去除失败，则数据包将会被丢弃。

缺乏强大完整性保护的无效数据包，例如Initial包、Retry包或Version Negotiation包之类的数据包也可以（**MAY**）被丢弃。如果在发现错误之前处理了这些数据包的内容，则终端必须（**MUST**）生成连接错误，或者完全回滚在该处理期间所做的任何更改。

### 5.2.1. 客户端数据包处理（Client Packet Handling）

发往客户端的有效数据包总是包含与客户端选择的值匹配的DCID。选择接收零长度CID数据包的客户端可以使用本地地址和端口来标识连接。与现有连接不匹配的数据包——基于DCID，或者，如果此值为零长度，基于本地IP地址和端口——将被丢弃。

由于数据包乱序或丢失，客户端可能会收到使用尚未启用的密钥进行加密的数据包。客户端可以（**MAY**）丢弃这些数据包，或者也可以（**MAY**）缓存它们以待后续秘钥解密。

如果客户端接收到的数据包使用的版本与它最初选择的版本不同，都必须（**MUST**）丢弃该数据包。

### 5.2.2. 服务端数据包处理（Server Packet Handling）
如果服务端收到一个其不支持的版本的数据包，但是该数据包的长度满足它支持的某个版本的数据包大小限制，则服务端应该（**SHOULD**）发送一个Version Negotiation包以开启新连接，如第6.1节所述。同时，服务端可以（**MAY**）限制Version Negotiation包的回应频率，服务端必须（**MUST**）丢弃比它支持的版本长度要小的数据包。

对服务端收到的第一个其不支持版本的数据包，某些特定于版本的字段可能有不同的语义和编码。特别的是，不同的版本可能有不同的数据包保护秘钥，服务端不太可能解码其不支持的版本的数据包。但如上所述，如果其长度合适，服务端应该（**SHOULD**）回以其支持版本的协商包。

具有受支持版本或无版本字段的数据包使用CID或本地地址和端口（对于具有零长度CID的数据包）匹配连接，之后由匹配的连接进行后续处理。如果匹配失败，服务端的处理如下所述：

如果数据包是完全符合规范的Initial包，则服务端继续握手（参见第7章），这会使得服务端切换到客户端选择的版本。

如果服务端拒绝接受新连接，它应该（**SHOULD**）发送一个Initial包，其中包含一个错误码为CONNECTION_REFUSED的CONNECTION_CLOSE帧。

如果数据包是0-RTT包，服务端可以（**MAY**）缓存有限数量的这类数据包，以等待随后发送的Initial包。客户端在收到服务端响应之前无法发送Handshake包，因此服务端在这种场景下应该（**SHOULD**）忽略任何此类Handshake包。

除此以外的其他任何场景下，服务端都必须（**MUST**）丢弃传入的数据包。

### 5.2.3. LB注意事项（ Considerations for Simple Load Balancers）

服务端部署的时候可以仅使用源和目的IP地址和端口在服务端之间进行负载均衡。对客户端IP地址或端口的更改可能会导致数据包被转发到错误的服务端。当客户端的地址更改时，可以使用以下方法之一部署服务端来保证连接的连续性：

服务端可以使用带外机制根据CID将数据包转发到正确的服务端。

如果服务端可以使用专用的服务端IP地址或端口，而不是客户端最初连接到的IP地址或端口，则服务端可以使用preferred_address传输参数来请求客户端将连接移动到该专用地址。请注意，客户端可以选择不使用preferred_address。

如果部署中的服务端没有具体的实施方案以在客户端地址更改时保持连接的连续性，应该（**SHOULD**）使用disable_active_migration传输参数指示其不支持迁移。disable_active_migration传输参数不会在客户端对preferred_address传输参数进行操作后禁止连接迁移。

使用这种简单形式的负载均衡的服务端部署必须（**MUST**）避免创建无状态重置预言机制；参见第21.11节。

## 5.3. 连接操作（Operations on Connections）

本文没有定义QUIC的API，不过，它为应用层协议可以依赖的QUIC连接定义了一组函数。应用层协议可以假设QUIC实现提供了一个接口，其中包括本节中描述的操作。设计用于特定应用层协议的QUIC实现可能仅提供该协议要用到的那些操作。

作为客户端角色，应用层协议可以：

* 打开一个连接，与服务端开始第7章中描述的交互；
* 在可用时启用Early Data（0-RTT数据）；

当Early Data被服务端接受或拒绝时被通知。

作为服务端角色，应用层协议可以：

* 侦听传入连接，为第7章中描述的交互做准备；
* 如果支持Early Data，则在发送给客户端的TLS会话恢复消息中嵌入应用控制数据；
* 如果支持Early Data，则从客户端的TLS会话恢复消息中提取应用控制数据，并根据该信息选择接受或拒绝Early Data。

作为任一角色，应用层协议都可以：

* 为每种类型允许的流个数初始值设置最小值，如传输参数中所述（第7.4节）；
* 通过为流和连接设置流控限额来控制接收缓冲区的资源分配；
* 确认握手是成功完成还是仍在进行中；
* 通过生成PING帧（第19.2节）或在空闲超时到期之前请求传输层发送其他帧（第10.1节），保持连接不静默关闭；
* 立即关闭（第10.2节）连接。

# 6. 版本协商（Version Negotiation）

版本协商机制使得服务端可以表明它不支持客户端正在使用的版本。服务端发送Version Negotiation包以响应可能启动新连接的每个数据包，详细信息请参阅第5.2节。

客户端发送的第一个数据包的大小将决定服务端是否发送Version Negotiation包。支持多个QUIC版本的客户端应该（**SHOULD**）确保他们发送的第一个UDP报文的大小，是其支持的所有版本的最小容许数据报文长度中的最大值，必要时使用PADDING帧（第19.1节）。这可确保服务端在存在彼此都支持的版本时做出响应。如果服务端收到的UDP报文长度小于其支持的所有版本的最小容许报文长度的最小值，则它可能不会发送Version Negotiation包，见第14.1节。

## 6.1. 发送版本协商包（Sending Version Negotiation Packets）

如果客户端选择的版本不为服务端所接受，则服务端以Version Negotiation包回应（参见第17.2.1小节），包里面包括服务端可接受的版本列表。客户端不得（**MUST NOT**）发送Version Negotiation包来响应接收到的Version Negotiation包。

本系统允许服务端在丢失状态的情况下处理其不支持版本的数据包。因为其作为响应发送的Initial包或Version Negotiation包可能会丢失，但客户端会发送新数据包，直到它成功收到响应或放弃连接尝试。

服务端可以（**MAY**）控制它发送的Version Negotiation包的数量。例如，能够将数据包识别为0-RTT包的服务端可能会选择不发送Version Negotiation包响应，期望客户端最终会发送Initial包。

## 6.2. 处理版本协商包（Handling Version Negotiation Packets）

Version Negotiation包的设计是为了让QUIC协商用于连接的版本以支持将来定义的功能。未来的标准跟踪规范可能会改变使用当前版本建立连接，但支持多QUIC版本的客户端在收到Version Negotiation包时的实现方式。

仅支持当前QUIC版本的客户端如果收到一个Version Negotiation包，则必须（**MUST**）放弃当前的连接尝试，以下场景除外：

如果客户端收到并成功处理了其他数据包（包括早前的Version Negotiation包），则客户端必须（**MUST**）忽略此Version Negotiation包。

如果此Version Negotiation包内支持的版本列表包含了当前客户端使用的版本，则客户端必须（**MUST**）忽略此Version Negotiation包。

如何实现版本协商是留给未来的标准跟踪规范定义的工作。特别是，未来的工作需要确保对版本降级攻击的鲁棒性，见第21.12节。

## 6.3. 使用保留版本（Using Reserved Versions）

为了支持将来服务端使用的新版本，客户端需要正确处理不受支持的版本。一些版本号（0x?a?a?a?a，如第15章所定义）被保留用于包含版本号的字段中。

终端可以（**MAY**）在任何会被未知或不支持版本忽略的字段中添加保留版本号，以测试对端是否正确忽略了该值。例如，终端可以在Version Negotiation包中包含保留版本号，参见第17.2.1小节。终端可以（**MAY**）发送带有保留版本号的数据包，以测试对端是否正确丢弃了该数据包。

# 7. 加密和传输握手（Cryptographic and Transport Handshake）

QUIC依靠结合加密和传输握手来尽可能降低连接建立时延。QUIC使用CRYPTO帧（第19.6节）来传输加密握手信息。本文中定义的QUIC版本标识为0x00000001，并使用[QUIC-TLS]中描述的TLS加密协议，不同的QUIC版本可能使用不同的加密握手协议。

QUIC提供可靠、保序的加密握手数据传输。QUIC的数据包保护机制会加密尽可能多的握手报文。加密握手必须（**MUST**）提供以下属性：

* 经过认证的秘钥交换，其中
    - 服务端需要进行身份认证；
    - 客户端可选地进行身份认证；
    - 每次连接都需要产生不同且不相关的密钥，并且
    - 密钥材料可用于0-RTT和1-RTT包保护。
* 经过认证的两个终端进行传输参数交换，以及服务端传输参数的机密性保护（参见第7.4节）。
* 经过认证的应用层协议协商（TLS为此使用应用层协议 (ALPN)[ALPN]协商）。

CRYPTO帧可以在不同的数据包编号（Packet Number，后续统一简称“包号”）空间中发送（第12.3节）。CRYPTO帧使用的偏移量用于确保加密握手数据的有序传输，每个包号空间中的编号从0开始。

图4显示了一个简化的握手以及握手期间数据包和帧的交换过程。以星号（“*”）提示的是在握手期间可以进行应用数据交换的步骤。一旦握手完成，终端就可以自由地交换应用数据了。

```
   Client                                               Server

   Initial (CRYPTO)
   0-RTT (*)              ---------->
                                              Initial (CRYPTO)
                                            Handshake (CRYPTO)
                          <----------                1-RTT (*)
   Handshake (CRYPTO)
   1-RTT (*)              ---------->
                          <----------   1-RTT (HANDSHAKE_DONE)

   1-RTT                  <=========>                    1-RTT
 
```
图4: Simplified QUIC Handshake

终端可以在握手期间发送数据包来测试显式拥塞通知(ECN)支持，详情参见第13.4节。如果支持ECN，终端会在回应对端的第一个数据包的ACK帧内携带ECN计数，如第13.4.2小节所述。

终端必须（**MUST**）明确协商应用层协议，这可以避免对正在使用的协议存在分歧的情况。

## 7.1. 握手流程示例（Example Handshake Flows）

[QUIC-TLS]中提供了有关TLS如何与QUIC集成的详细信息，此处仅展示一些示例。第8.1.2小节的示例有支持客户端地址验证交换的扩展版本。

一旦任何地址验证交换完成，就可以启动加密握手协商加密密钥。加密握手在Initial（第17.2.2小节）和Handshake（第17.2.4小节）数据包中携带。

图5是1-RTT握手的概要图，其每行显示一个QUIC包，行首显示数据包类型和包号，冒号“：”后是通常包含在这些数据包中的帧。例如，第一个数据包的类型为Initial，包号为0，并包含一个携带ClientHello的CRYPTO帧。

多个QUIC包——即使是不同的数据包类型——都可以合并成一个单一的UDP报文，参见第12.2节节。因此，这种握手可以包含少则四个UDP报文或更多（受协议固有的限制，例如拥塞控制和反放大机制）。例如，服务端的第一个UDP报文就包含Initial包、Handshake包和1-RTT包中的“0.5-RTT数据”。

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                          Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
                                    <- 1-RTT[0]: STREAM[1, "..."]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[0]: STREAM[0, "..."], ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[0]

```
图5: Example 1-RTT Handshake

图6是0-RTT握手，发送单个0-RTT包的连接示例。注意到，如第12.3节所述，服务端在1-RTT包中确认客户端0-RTT数据，客户端在相同的包号空间中发送1-RTT包。

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH]
   0-RTT[0]: STREAM[0, "..."] ->

                                    Initial[0]: CRYPTO[SH] ACK[0]
                                     Handshake[0] CRYPTO[EE, FIN]
                             <- 1-RTT[0]: STREAM[1, "..."] ACK[0]

   Initial[1]: ACK[0]
   Handshake[0]: CRYPTO[FIN], ACK[0]
   1-RTT[1]: STREAM[0, "..."] ACK[0] ->

                                             Handshake[1]: ACK[0]
            <- 1-RTT[1]: HANDSHAKE_DONE, STREAM[3, "..."], ACK[1]

```
图6: Example 0-RTT Handshake

## 7.2. 协商连接ID（Negotiating Connection IDs）

CID用于确保数据包的路由一致，如第5.1节所述。长包头含两个CID：DCID由数据包的接收方选择，用于提供一致的路由，SCID用于让对端设置DCID。

在握手期间，带有长包头（第17.2节）的数据包用于确立两端使用的CID。每个终端使用SCID字段来告知对端，让对端在发送给他们的数据包中填入DCID字段。在处理第一个Initial包后，每个终端将其发送的后续数据包中的DCID字段设置为其接收到的SCID字段的值。

如果之前未从服务端收到Initial包或Retry包，客户端会使用不可预测的值填充DCID字段。该DCID的长度必须（**MUST**）至少为8个字节。在收到来自服务端的数据包之前，客户端在此连接上发送的所有数据包都必须（**MUST**）使用相同的DCID值。

客户端发送的第一个Initial包中的DCID字段用于确定Initial包的数据包保护密钥，这些密钥在收到Retry包后会发生变化；参见[QUIC-TLS]第5.2节。

客户端使用其选择的值填充SCID字段，并设置SCID长度字段以指示长度。

客户端第一次发送的0-RTT包与第一个Initial包需要填写相同的DCID和SCID值。

在第一次从服务端收到Initial或Retry包后，客户端使用服务端提供的SCID作为后续发送的数据包的DCID，包括任何0-RTT包。这意味着客户端可能需要在连接建立期间两次更改它在DCID字段中填入的CID：一次响应来自服务端的Initial包，一次响应Retry包。一旦客户端从服务端收到一个有效的Initial包，在该连接上接收到的具有不同SCID的任何后续数据包都必须（**MUST**）丢弃。

在收到的第一个Initial或Retry包后，客户端必须（**MUST**）将发送数据包的DCID改为新的CID。服务端必须（**MUST**）根据第一个收到的Initial包设置它用于发送数据包的DCID。仅当值取自NEW_CONNECTION_ID帧时，才允许变更DCID；如果后续的Initial包包含不同的SCID，它们必须（**MUST**）被丢弃。这避免了对具有不同SCID的多个Initial包进行可能的无状态处理而导致的不可预测的结果。

终端发送的DCID可以在连接的生命周期内改变，特别是在响应连接迁移时（第9章），详细信息请参阅第5.1.1小节。

## 7.3. 认证连接ID（Authenticating Connection IDs）

在握手期间对CID进行操作，另一个选择是对所有相关传输参数进行认证，参见第7.4节。这确保用于握手的所有CID也通过加密握手进行身份认证。

每个终端在发送Initial包时，需将其在数据包头中填写的SCID字段，也填入initial_source_connection_id传输参数中，参见第18.2节。服务端收到Initial包后，也需要将收到的数据包头中的DCID值，填入其响应的数据包的original_destination_connection_id传输参数中。如果因为某些原因，服务端需要回应Retry包，则需要在retry_source_connection_id传输参数中填入Retry包头的SCID字段。

上述握手期间填写的传输参数的值必须（**MUST**）与本端发送（或接收，用于服务端）的实际值相匹配，接收端也必须（**MUST**）验证这一点。这样可以确保攻击者无法在握手过程中，在其篡改的数据包中注入自己的CID，影响后续正确CID的选择。

若来自任一终端的initial_source_connection_id传输参数缺失，或来自服务端的original_destination_connection_id传输参数缺失，终端必须（**MUST**）视为TRANSPORT_PARAMETER_ERROR类型的连接错误。

终端必须（**MUST**）将以下内容视为TRANSPORT_PARAMETER_ERROR或PROTOCOL_VIOLATION类型的连接错误：
* 收到服务端Retry包，但未填写retry_source_connection_id传输参数；
* 未收到服务端的Retry包，但却填写了retry_source_connection_id传输参数；
* 对端填写的相应传输参数与Initial包中的DCID或SCID字段不匹配；

如果选择了零长度CID，则相应的传输参数将包含一个零长度值。

图7展示了在完整握手中如何使用连接ID（DCID=目的连接ID，SCID=源连接ID），包括Initial包交换时的CID填写，以及后续1-RTT包交换时DCID的填写方式：

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

```
图7: Use of Connection IDs in a Handshake

图8展示了增加了Retry包交换的握手过程：

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                       <- Retry: DCID=C1, SCID=S2
   Initial: DCID=S2, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

```
图8: Use of Connection IDs in a Handshake with Retry

在这两种情况下（图7和图8），客户端都将initial_source_connection_id传输参数的值设置为C1。

当握手不包括Retry时（图7），服务端将original_destination_connection_id设置为S1（注意该值由客户端选择），并将initial_source_connection_id设置为S3。在这种情况下，服务端不填写retry_source_connection_id传输参数。

当握手包括Retry时（图8），服务端将original_destination_connection_id设置为S1，retry_source_connection_id设置为S2，并将initial_source_connection_id设置为S3。

## 7.4. 传输参数（Transport Parameters）

在连接建立期间，两端都会对其传输参数进行了经过身份认证的声明。终端需要遵循每个参数定义的限制，也需要遵循其参数描述中的处理原则。

传输参数由两端独立声明。每个终端都可以无视对端参数，自行选择传输参数值。

传输参数的编码在第18章中有详细说明。

QUIC在加密Handshake包中携带编码的传输参数。握手完成后，对端声明的传输参数即可用。每个终端都需验证对端提供的传输参数的值。

第18.2节中有每个传输参数的定义。

终端必须（**MUST**）将收到的具有无效值的传输参数视为TRANSPORT_PARAMETER_ERROR类型的连接错误。

在给定的传输参数扩展中，终端不得（**MUST NOT**）包含一个传输参数的多个副本，终端应该（**SHOULD**）将此种情况视为TRANSPORT_PARAMETER_ERROR类型的连接错误。

终端在握手期间使用传输参数来认证CID的协商过程，参见第7.3节。

ALPN(参见[ALPN])允许客户端在连接建立期间通告其支持的多种应用层协议。在握手期间通告的传输参数适用于所有这些应用层协议。应用层协议也可以推荐传输参数的值，例如初始流控限额。客户端可以为传输参数设置约束，但如果这些约束有冲突，则可能使得客户端无法支持多个应用层协议。

### 7.4.1. 0-RTT的传输参数（Values of Transport Parameters for 0-RTT）

是否使用0-RTT取决于客户端和服务端是否可以使用先前连接协商的协议参数。为了启用0-RTT，终端需要将服务端传输参数的值与它在连接上收到的其他会话凭证一起存储。终端还要存储应用层协议或加密握手所需的所有信息；参见[QUIC-TLS]第4.6节。在使用会话凭证尝试0-RTT连接时将会用到先前存储的传输参数的值。

握手完成后，客户端使用握手中商定的传输参数。记住直到握手完成并且客户端开始发送1-RTT包，传输参数才可适用于新连接。并非所有传输参数都要被保存，因为有些参数不适用于未来的连接，或者它们对0-RTT的使用没有影响。

定义新的传输参数（第7.4.2小节），必须（**MUST**）指定：对0-RTT来说，其存储方式是强制的、可选的还是禁止的。客户端不需要保存它无法处理的传输参数。

客户端不得（**MUST NOT**）保存如下传输参数：
* ack_delay_exponent
* max_ack_delay
* initial_source_connection_id
* original_destination_connection_id
* preferred_address
* retry_source_connection_id
* stateless_reset_token

客户端必须（**MUST**）使用在握手中拿到的服务端的最新值，如果服务端未提供，则使用默认值。

尝试发送0-RTT数据的客户端必须（**MUST**）保存服务端处理需要用到的所有其他传输参数。服务端可以保存这些传输参数，或者可以在会话凭证中存储受完整性保护的副本，并在收到0-RTT数据时从中恢复信息。服务端使用这些传输参数来确定是否可以接受0-RTT数据。

如果服务端接受0-RTT数据，则服务端不得（**MUST NOT**）自行降低任何限制或更改可能违反客户端0-RTT约束的任何值。特别是，接受0-RTT数据的服务端，如下参数不得（**MUST NOT**）小于其存储过的传输参数的值：
* active_connection_id_limit
* initial_max_data
* initial_max_stream_data_bidi_local
* initial_max_stream_data_bidi_remote
* initial_max_stream_data_uni
* initial_max_streams_bidi
* initial_max_streams_uni

为某些传输参数省略或设置零值可能会导致0-RTT数据能启用但不可用。对于0-RTT，允许发送应用数据的传输参数的适用子集应该（**SHOULD**）设置为非零值。这些参数集包括initial_max_data和（1）initial_max_streams_bidi或initial_max_stream_data_bidi_remote或（2）initial_max_streams_uni或initial_max_stream_data_uni。

服务端可能在流上采用更大的初始流流控限额值，比客户端发送0-RTT时采用的值要大。握手完成后，客户端使用initial_max_stream_data_bidi_remote或initial_max_stream_data_uni的新值来更新所有发送流上的流控限额。

服务端可以（**MAY**）存储和恢复先前通告的max_idle_timeout、max_udp_payload_size和disable_active_migration参数的值，如果它选择较小的值，则表示其拒绝0-RTT。因为在接受0-RTT数据的同时降低这些参数的值可能会降低连接的性能。具体来说，降低max_udp_payload_size可能会导致丢包，与直接拒绝0-RTT数据相比，性能会更差。

如果不能恢复传输参数，服务端必须（**MUST**）拒绝0-RTT数据。

当以0-RTT包发送帧时，客户端必须（**MUST NOT**）只使用保存的传输参数，重要的是，它不得（**MUST NOT**）使用从服务端更新的传输参数或从1-RTT包中接收的帧中学习到的新值。来自握手的传输参数更新值仅适用于1-RTT包。例如，所有0-RTT包都需要采用来自先前保存的流控限额参数，即使这些值因握手或1-RTT包中的帧加大也不考虑。在0-RTT中使用更新的传输参数，服务端可以（**MAY**）将其视为PROTOCOL_VIOLATION类型的连接错误。

### 7.4.2. 新传输参数（New Transport Parameters）

新的传输参数可用于协商新的协议行为。终端必须（**MUST**）忽略它不支持的传输参数。缺少某个传输参数会因此禁用使用该参数协商的任何可选协议功能。如第18.1节所述，保留了一些标识符以满足此要求。

不理解某个传输参数的客户端可以丢弃它并在后续连接上尝试0-RTT。但是，如果客户端之后添加对该传输参数的支持，则它可能会在尝试0-RTT时违反此传输参数建立的约束。新的传输参数可以通过设置最保守的默认值来规避此问题。客户端可以通过存储所有参数来规避这个问题，包括当前不支持的参数。

可以根据第22.3节中的规则注册新的传输参数。

## 7.5. 加密消息缓存考虑（Cryptographic Message Buffering）

实现需要为乱序接收到的CRYPTO帧维护一个数据缓冲区。由于CRYPTO帧没有流量控制，因此终端可能会潜在要求其对端缓冲无限量的数据。

在握手期间，终端实现必须（**MUST**）支持至少缓存4096字节的乱序CRYPTO帧数据，当然其也可以（**MAY**）缓冲更多数据，因为更大的缓冲区允许握手期间交换更大的密钥或凭证。在整个连接的生命周期内，终端的缓冲区大小不需要保持不变。

在握手期间无法缓存CRYPTO帧可能会导致连接失败。如果在握手期间超出终端的缓冲区大小，它可以临时扩展其缓冲区以完成握手。如果终端不扩展其缓冲区，则必须（**MUST**）使用CRYPTO_BUFFER_EXCEEDED错误码关闭连接。

握手完成后，如果终端无法缓冲CRYPTO帧中的数据，它可以（**MAY**）丢弃该CRYPTO帧和后续的CRYPTO帧，或者它也可用CRYPTO_BUFFER_EXCEEDED错误码关闭连接。包含被丢弃的CRYPTO帧的数据包必须（**MUST**）被确认，因为即使CRYPTO帧被丢弃，其他数据包也可以（**MAY**）被接收和处理。

# 8. 地址验证（Address Validation）

地址验证功能确保终端不能用于流量放大攻击。在这种攻击中，攻击者发送数据包到服务端，其中包含指向受害者的欺骗性源地址信息。如果服务端生成更多或更大的数据包来响应，则会放出比攻击者本身更大的流量来攻击受害者。

针对放大攻击的主要防御措施，是验证对端是否可在其声明的传输地址上接收数据包。因此，在从尚未验证的地址收到数据包后，终端必须（**MUST**）将发往此地址的流量限制为不超过其接收的三倍。这种对响应大小的限制称为反放大限制。

地址验证在连接建立期间（参见第8.1节）和连接迁移期间（参见第8.2节）执行。

## 8.1. 连接建立期间的地址验证（ Address Validation during Connection Establishment）

连接建立隐式地为两端提供地址验证。特别的，收到用Initial包中通告的握手密钥保护的数据包，可以确认对端成功处理了该Initial包。一旦终端成功处理了来自对端的Handshake包，它就可以认为对端地址已经过验证。

此外，如果对端使用本端指定的CID并且CID包含至少64位，则本端可以（**MAY**）考虑对端地址已经验证。

对于客户端，其第一个Initial包中的DCID字段的值，使得它可以将验证服务端地址，作为成功处理任何数据包的一部分。因为来自服务端的Initial包使用从该值派生的密钥进行保护（参见[QUIC-TLS]第5.2节）。

initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id)
或者，该值可由服务端在Version Negotiation包中回显（第6章），或包含在Retry包中的完整性标签中（参见[QUIC-TLS]第5.8节）。

在验证客户端地址之前，服务端发送的字节数不得（**MUST NOT**）超过它们接收到的字节数的三倍。这限制了可以使用欺骗源地址进行的任何放大攻击的规模。为了在地址验证之前避免放大，服务端必须（**MUST**）计算数据报中收到的所有负载字节，这些字节是唯一归属于单个连接的。其总量包含成功处理的数据包的数据报文和全部丢弃的数据包的数据报文。

客户端必须（**MUST**）确保包含Initial包的UDP报文具有至少1200字节的UDP负载，并根据需要添加PADDING帧。这样做使得服务端在完成地址验证之前可发送更多数据。

如果服务端回应的Initial或Handshake包丢失，但客户端已收到其发送的所有数据的确认，如果此时服务端达到其反放大限制时，则可能会发生死锁。在这种情况下，客户端没有理由发送额外的数据包，服务端无法发送更多数据，因为它没有验证客户端的地址。为了防止这种死锁，客户端必须（**MUST**）在探测超时(PTO)时发送一个数据包，参见[QUIC-RECOVERY]第6.2节。具体来说，如果客户端没有握手密钥，则客户端必须（**MUST**）在包含至少1200字节的UDP报文中发送Initial包，或者发送Handshake包。

服务端可能希望在开始加密握手之前验证客户端地址，客户端会在Initial包中携带令牌来提供地址验证。此令牌是由服务端在连接建立期间发送的Retry包（参见第8.1.2小节）携带，或者客户端可以使用之前连接中服务端用NEW_TOKEN（参见第8.1.3小节）帧通告的令牌。

服务端除了在地址验证之前的发送限制之外，还有拥塞控制器限制它可以发送的流量。客户端仅受拥塞控制器的约束。

### 8.1.1. 令牌生成（Token Construction）

服务端在NEW_TOKEN帧或Retry包中发送的令牌是在相同的字段中填写的，但需要进行不同的处理，令牌生成时必须（**MUST**）考虑能区分是以那种方式提供给客户端的。

### 8.1.2. 使用Retry包进行地址验证（Address Validation Using Retry Packets）

收到客户端的Initial包后，服务端可以通过发送包含令牌的Retry包（第17.2.5小节）来请求地址验证。客户端收到Retry包后，在该连接上随后发送的所有Initial包中都必须（**MUST**）携带此令牌。

收到客户端的Initial包后，如果其中携带了包含在Retry包中提供的令牌，服务端不能发送另一个Retry包，它只能拒绝连接或允许连接继续。

攻击者不可能为自己的地址生成有效的令牌（参见第8.1.4小节）而客户端能够返回该令牌，就可向服务端证明其已经收到该令牌。

服务端也可以使用Retry包来推迟连接建立的状态维护和处理成本。QUIC要求服务端提供不同的CID，以及第18.2节中定义的original_destination_connection_id传输参数，可以强制服务端证明它或它合作的实体已经从客户端接收到初始Initial包。提供不同的CID还使得服务端可以对后续数据包的路由方式进行一些控制，例如可用于将连接路由到不同的服务端实例。

如果服务端收到携带无效Retry令牌，但其他字段都有效的Initial包，因为知道客户端不会再接受另一个Retry令牌，服务端可以丢弃这样的数据包并让客户端超时以检测到握手失败，但这可能会对客户端造成明显的延迟损失。因此，服务端应该（**SHOULD**）立即以错误码INVALID_TOKEN关闭连接（参见第10.2节）。请注意，此时服务端尚未为连接建立任何状态，因此不会进入关闭周期。

图9展示了使用Retry包的流程。

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH] ->

                                                   <- Retry+Token

   Initial+Token[1]: CRYPTO[CH] ->

                                    Initial[0]: CRYPTO[SH] ACK[1]
                          Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
                                    <- 1-RTT[0]: STREAM[1, "..."]

```
图9: Example Handshake with Retry

### 8.1.3. 后续连接的地址验证（Address Validation for Future Connections）

服务端可以（**MAY**）在连接期间为客户端提供地址验证令牌，方便其将此令牌用于后续连接。地址验证对于0-RTT尤为重要，因为服务端可能会向客户端发送大量数据以响应0-RTT数据。

服务端使用NEW_TOKEN帧（第19.7节）为客户端提供可用于验证后续连接的地址验证令牌。在后续的连接中，客户端在Initial包中携带此令牌以提供地址验证。客户端必须（**MUST**）在它发送的所有Initial包中携带令牌，除非服务端通过Retry包用更新的令牌替换旧令牌。客户端不得（**MUST NOT**）将在Retry包中提供的令牌用于未来的连接。服务端可以（**MAY**）丢弃任何不携带预期令牌的Initial包。

Retry包提供的令牌可立即使用，NEW_TOKEN帧中携带的令牌要在一段时间之后才使用。因此，令牌应该（**SHOULD**）有一个截止时间，它可以是一个明确的截止时间，也可以是一个时间戳但可用于动态计算截止时间。服务端可以将截止时间直接或以加密形式保存在令牌中。

使用NEW_TOKEN发布的令牌不得（**MUST NOT**）包含能够让观察者将值关联到发出它的连接上的信息。例如，它不能包含先前的CID或寻址信息，除非这些值已加密。服务端必须（**MUST**）确保它发送的每个NEW_TOKEN帧在所有客户端中都是唯一的，不过因为丢包而重传的NEW_TOKEN帧除外。使得服务端能够区分令牌是来自Retry还是NEW_TOKEN的信息可以（**MAY**）被服务端以外的实体访问。

两个不同连接上的客户端端口号不太可能相同，因此验证端口不大可行。

在NEW_TOKEN帧中发布的令牌，可以让服务端判定该连接是否可信（例如，证书中包含服务端名称）。当客户端连接到一个其保存了可用而未用的令牌的服务端时，它应该（**SHOULD**）在其Initial包的Token字段中填入该令牌。携带令牌使得服务端可以及时验证客户端地址，而无需额外的环回时间。客户端不得（**MUST NOT**）携带不适用于它所连接的服务端的令牌，除非客户端明确知道发出令牌的服务端和客户端正连接的服务端正在共同管理此令牌。客户端可以（**MAY**）使用以前连接到该服务端的任何令牌。

令牌使得服务端可以将发出令牌的连接与任何使用它的连接之间的活动关联起来。客户端想要打破与服务端的连接一致性的话，可以丢弃NEW_TOKEN帧提供的令牌。相比之下，在Retry包中获得的令牌必须（**MUST**）在连接尝试期间立即使用，不能在后续连接尝试中使用。

客户端不应该（**SHOULD NOT**）在不同的连接尝试中重用来自NEW_TOKEN帧的令牌。在不同连接中重用令牌的话，可能被网络路径上的其他实体关联，参见第9.5节。

客户端可能会在单个连接上收到多个令牌。除了避免被关联之外，这些令牌都可以用于连接尝试。服务端可以发送额外的令牌以在多次连接尝试中启动地址验证，或者替换可能变得无效的旧令牌。对于客户端，这种模糊性意味着发送最新未使用的令牌是最有可能是有效的，虽然保存和使用旧令牌没有负面影响，但客户端可以认为旧令牌对服务端进行地址验证的用处不大。

当服务端收到带有地址验证令牌的Initial包时，它必须（**MUST**）尝试验证令牌，除非它已经完成了地址验证。如果令牌无效，那么服务端应该（**SHOULD**）像地址未经过验证一样处理，比如可能发送一个Retry包。NEW_TOKEN帧和Retry包提供的令牌可以被服务端区分（参见第8.1.1小节），后者需要严格地验证。如果验证成功，服务端应该（**SHOULD**）允许握手继续进行。

> 注意：将客户端视为未验证而不是丢弃数据包的基本原理是：客户端可能已经在使用先前连接中NEW_TOKEN帧收到的令牌，并且如果服务端丢失状态，它可能无法验证令牌，如果丢弃该数据包可能会导致连接失败。

在无状态设计中，服务端可以使用加密和经过身份验证的令牌将信息传递给客户端，服务端在未来连接中可以从中恢复有效信息并用于验证客户端地址。令牌未集成到加密握手中，就不会对其进行身份验证。客户端可能重用令牌，为了避免针对此属性的攻击，服务端可以将令牌限制为仅用于客户端地址验证。

客户端可以（**MAY**）使用在连接上获得的令牌进行后续任何使用相同版本的连接尝试。在选择要使用的令牌时，客户端不需要考虑正在尝试的连接的其他属性，包括可能的应用层协议、会话凭证或其他连接属性的选择。

### 8.1.4. 地址验证的令牌完整性考虑（Address Validation Token Integrity）
地址验证令牌必须（**MUST**）难以猜测。在令牌中包含一个至少128位的随机值就足够了，但这取决于服务端是否记住它发送给客户端的值。

基于令牌的方案允许服务端将与验证相关的任何状态维护转嫁给客户端。为了使此设计起作用，令牌必须（**MUST**）受到完整性保护以防止客户端修改或伪造。如果没有完整性保护，恶意客户端可能会生成或猜测服务端可接受的令牌值。只有服务端需要访问令牌的完整性保护密钥。

令牌不需要单一的明确定义的格式，因为生成和使用令牌的都是服务端。在Retry包中发送的令牌应该（**SHOULD**）包含允许服务端验证客户端数据包中的源IP地址和端口是否保持不变的信息。

在NEW_TOKEN帧携带的令牌必须（**MUST**）包含让服务端验证客户端IP地址从令牌发出时起是否更改的信息。服务端也可以通过NEW_TOKEN帧中的令牌来决定是否发送Retry包，即使客户端地址已更改。如果客户端IP地址发生变化，服务端必须（**MUST**）遵守反放大限制，详情参阅第8章。请注意，在存在NAT的情况下，此要求可能不足以保护共享NAT的其他主机免受放大攻击。

攻击者可以重放令牌以将服务端用作DDoS攻击中的放大器。为了防止此类攻击，服务端必须（**MUST**）确保阻止或限制令牌的重放。服务端应该（**SHOULD**）确保在Retry包中发送的令牌仅在短时间内被接受，因为它们会被客户端立即返回。NEW_TOKEN帧（第19.7节）中提供的令牌需要更长的生效时间，但不应该（**SHOULD NOT**）重复接受。如果可能，鼓励服务端只认可一次令牌。令牌也可以（**MAY**）包含有关客户端的附加信息，以进一步缩小适用性或重用性。

## 8.2. 路径验证（Path Validation）

在连接迁移期间，两端都使用路径验证（参见第9章）来验证地址变更后的可达性。在路径验证中，终端测试特定本地地址与特定对端地址之间的可达性，其中地址是IP地址和端口的二元组。

路径验证测试在路径上发往对端的数据包是否可被对端接收。路径验证用于确保从迁移中的对端收到的数据包不携带欺骗性源地址。

路径验证不验证对端是否可以在返回方向发包。不能使用确认包用于返回路径验证，因为它们包含的信息不足并且可能被欺骗。终端独立确定路径每个方向的可达性，因此返回方向可达性只能由对端确认。

任一终端均可随时启用路径验证。例如，一个终端可能会检查对端在静默一段时间后是否仍然保有其源地址。

路径验证并非设计为NAT穿越机制。尽管此处描述的机制对于创建支持NAT穿越的NAT绑定可能有效，但我们期待的是一个终端能够接收数据包，而无需先在该路径上发送数据包。有效的NAT穿越需要额外的同步机制，这里没有涉及。

在进行路径验证时，终端可以（**MAY**）在发送PATH_CHALLENGE或PATH_RESPONSE帧时捎带其他类型的帧。例如终端可以在发送PATH_CHALLENGE时捎带PADDING帧用于路径最大传输单元发现 (PMTUD)，参见见第14.2.1小节，终端在发送PATH_RESPONSE响应时也可以捎带它自己的PATH_CHALLENGE帧。

终端在从新的本地地址发送探测包时需要使用新的CID，参见第9.5节。在探测新路径时，终端需要确保其对端具有可用于响应的未使用的CID。如果active_connection_id_limit允许，在同一个数据包中发送NEW_CONNECTION_ID和PATH_CHALLENGE帧，可确保对端在发送响应时有未使用的CID。

终端可以选择同时探测多条路径。用于同时探测的路径的数量受其对端先前提供的额外CID数量的限制，因为用于探测的每个新本地地址都需要一个以前未使用的CID。

### 8.2.1. 启动路径验证（Initiating Path Validation）

为了启动路径验证，终端需发送一个PATH_CHALLENGE帧，其中包含不可预测的要在路径上验证的负载。

终端可以（**MAY**）发送多个PATH_CHALLENGE帧以防止数据包丢失。不过，终端不应该（**SHOULD NOT**）在单个数据包中携带多个PATH_CHALLENGE帧。

终端不应该（**SHOULD NOT**）以超过Initial包的频率发送包含PATH_CHALLENGE帧的数据包来探测新路径。这确保了在新路径上的连接迁移不会比建立新连接更多。

终端必须（**MUST**）在每个PATH_CHALLENGE帧中使用不同的不可预测的数据，以便它可以将对端的PATH_RESPONSE响应与相应的PATH_CHALLENGE帧相关联。

终端必须（**MUST**）将包含PATH_CHALLENGE帧的UDP报文扩展到至少1200字节大小，除非路径的反放大限制不允许发送此大小的数据报。发送这种大小的UDP报文可以确保从本端到对端的网络路径可以用于QUIC连接，参见第14章。

当终端由于反放大限制而无法将数据报大小扩展到1200字节时，将不能验证路径MTU。为确保路径MTU足够大，在成功接收到PATH_RESPONSE之后，或在路径上接收到足够多的字节以发送更大的数据报而不会导致超出反放大限制后，终端必须（**MUST**）通过发送包含PATH_CHALLENGE帧的至少1200字节的UDP报文来执行第二次路径验证。

与扩展数据报文的其他情况不同，终端不得（**MUST NOT**）丢弃包含PATH_CHALLENGE或PATH_RESPONSE帧的较小的UDP报文。

### 8.2.2. 路径验证响应（Path Validation Responses）

在接收到PATH_CHALLENGE帧时，终端必须（**MUST**）通过在PATH_RESPONSE帧中回显包含在PATH_CHALLENGE帧中的数据来响应。除非受到拥塞控制的约束，否则终端不得延迟包含PATH_RESPONSE帧的数据包的发送。

PATH_RESPONSE帧必须（**MUST**）在收到PATH_CHALLENGE帧的网络路径上发送。这确保只有当路径在两个方向都有效时，对端的路径验证才会成功。发起路径验证的终端不得（**MUST NOT**）强制执行此要求，因为这会导致对迁移的攻击，参见第9.3.3小节。

终端必须（**MUST**）将包含PATH_RESPONSE帧的数据报文扩展到至少1200字节的最小允许最大数据报大小。这可验证该路径是否能够在两个方向上都携带这种大小的数据报文。但是，如果最终待发数据报文大小超过反放大限制，终端不得（**MUST NOT**）扩展包含PATH_RESPONSE的数据报文。不过这种情况只有在其收到的PATH_CHALLENGE帧也未扩展时才有可能。（反放大机制，如果包含PATH_CHALLENGE的数据报文有1200，那么响应报文可以到1200，不超过3600即可）

终端不得（**MUST NOT**）发送多个PATH_RESPONSE帧以响应一个PATH_CHALLENGE帧，参见第13.3节。终端应根据需要发送更多PATH_CHALLENGE帧以唤起更多的PATH_RESPONSE帧。

### 8.2.3. 路径验证成功（Successful Path Validation）

当收到与先前PATH_CHALLENGE帧中携带的数据相同的PATH_RESPONSE帧时，路径验证成功。在任何网络路径上收到的PATH_RESPONSE帧都能验证发送PATH_CHALLENGE的路径可达性。

如果终端在未扩展到至少1200字节的数据报文中发送PATH_CHALLENGE帧，并且PATH_RESPONSE响应可以验证其地址，则表示验证路径通过，但不表示验证了路径MTU。因此，终端现在可以发送已接收数据量三倍的数据。然后，终端必须（**MUST**）用扩展的数据报发起另一次路径验证，以验证该路径是否支持所需的MTU。

收到对包含PATH_CHALLENGE帧的数据包的ACK确认不是充分的验证，因为该确认可能被恶意第三方欺骗。

### 8.2.4. 路径验证失败（Failed Path Validation）

仅当尝试路径验证的终端放弃其路径验证的尝试时，路径验证才算失败。

终端应该（**SHOULD**）基于定时器来决定是否放弃路径验证。设置此计时器时，实现要注意新路径的往返时间可能比初始路径更长。建议（**RECOMMENDED**）使用当前PTO或新路径的PTO（使用kInitialRtt，如[QUIC-RECOVERY]中定义）中较大值的三倍。

在路径验证失败之前，会等待多个PTO，因此单个PATH_CHALLENGE或PATH_RESPONSE帧的丢失才不会导致路径验证失败。

注意到终端可能会在新路径上接收包含其他帧的数据包，但路径验证需要收到携带满足条件的数据的PATH_RESPONSE帧才算成功。

当终端放弃路径验证时，它已经判定该路径不可用。这并不一定意味着连接失败——终端可以根据需要继续通过其他路径发送数据包。如果没有可用路径，终端可以等待新路径可用或关闭连接。没有到达对端的有效网络路径的终端可以（**MAY**）发出NO_VIABLE_PATH连接错误信号，注意这只有在网络路径存在但不支持所需的MTU时才有可能发生（第14章）。

也有可能因为失败之外的其他原因而放弃路径验证。一般在旧路径上的路径验证正在进行的同时启动了到新路径的连接迁移，就会发生这种情况。

# 9. 连接迁移（Connection Migration）

CID的使用使得连接在终端地址（IP地址和端口）的变更中存续下来，如由终端迁移到新网络引起的变更。本节介绍终端迁移到新地址的过程。

QUIC的设计依赖于终端在握手期间保持地址稳定。在握手完成确认之前，终端不得（**MUST NOT**）发起连接迁移，如[QUIC-TLS]第4.1.2小节所定义。

如果终端设置了disable_active_migration传输参数，在握手期间，终端也不得（**MUST NOT**）使用不同的本地地址向对端发送数据包（包括探测数据包，参见第9.1节），除非终端是按preferred_address传输参数进行回应的。如果对端违反此要求，本端必须（**MUST**）要么丢弃该路径上的传入数据包，不生成Stateless Reset包，要么继续进行路径验证并允许对端迁移。生成Stateless Reset包或启动连接关闭都将使得网络中的第三方可以通过欺骗的方式关闭连接或以其他方式操纵观察到的流量。

并非所有对端地址的变更都是有意或主动的迁移。对端可能会遇到NAT重绑定：由于中间节点（通常是NAT）为连接分配新的传出端口或是新的传出IP地址而导致的地址变更。如果终端检测到对端地址的任何变更，终端必须（**MUST**）执行路径验证（第8.2节），除非它先前已验证该地址。

当终端从没有经过验证的路径发送数据包时，它可以（**MAY**）丢失连接状态。需要进行连接迁移的终端可以（**MAY**）在丢失连接状态之前等待新路径变得可用。

本文限制服务端将连接迁移到新的客户端地址，除非是如第9.6节中所述的场景。客户端负责启动所有迁移。在接收到来自客户端地址的非探测数据包之前，服务端不会主动向该地址发送非探测数据包（参见第9.1节）。如果客户端收到来自未知服务端地址的数据包，其必须（**MUST**）丢弃这些数据包。

## 9.1. 探测新路径（Probing a New Path）

在将连接迁移到新的本地地址之前，终端可以（**MAY**）使用路径验证（第8.2节）从新的本地地址探测对端可达性。路径验证失败仅意味着新路径不可用于此连接。除非没有可用的有效替代路径，否则路径验证失败不会导致连接结束。

PATH_CHALLENGE、PATH_RESPONSE、NEW_CONNECTION_ID和PADDING帧是“探测帧”，所有其他帧都是“非探测帧”。仅包含探测帧的数据包是“探测数据包”，包含任何其他帧的数据包是“非探测数据包”。

## 9.2. 启动连接迁移（Initiating Connection Migration）

终端可以通过从新地址发送包含非探测帧的数据包，将连接迁移到这个新的本地地址。

每个终端在连接建立期间会验证其对端的地址。因此，待迁移的终端是知道对端愿意在其当前地址上接收报文的，因此，终端可以迁移到新的本地地址，而无需先验证对端的地址。

为了在新路径上确认可达性，终端需要在新路径上启动路径验证（第8.2节）。终端可以（**MAY**）推迟路径验证，直到对端发送下一个非探测帧到其新地址。

迁移时，新路径可能不支持终端的当前发送速率。因此，终端需要重置其拥塞控制器和RTT估计，如第9.4节所述。

新路径可能不具有相同的ECN功能。因此，终端需要验证ECN功能，如第13.4节所述。

## 9.3. 响应连接迁移（Responding to Connection Migration）

接收到对端从新地址发来的包含非探测帧的数据包表明对端已迁移到该地址。

如果接收方允许迁移，它必须（**MUST**）将后续数据包发往新的对端地址，并且必须（**MUST**）启动路径验证（第8.2节）以验证对端对该地址的所有权（如果验证尚未进行）。如果接收方没有来自对端的未使用CID，则在对端提供之前，它将无法在新路径上发送任何数据，参见第9.5节。

终端仅在回应最高包号的非探测数据包时变更其目的地址，这可确保终端在收到重新排序的数据包时不会将数据包投递到旧的对端地址。

终端可以（**MAY**）将数据发往未经验证的对端地址，但它必须（**MUST**）防止潜在的攻击，如第9.3.1和9.3.2小节所述。如果该地址最近可见，则终端可以（**MAY**）跳过对端地址的验证。特别是，如果终端在检测到某种形式的虚假迁移后迁回到先前经过验证的路径，则跳过地址验证并恢复丢包检测和拥塞状态可以降低攻击对性能的影响。

在变更其发送非探测数据包的地址后，终端可以放弃对其他地址的路径验证。

从新的对端地址接收数据包可能是对端NAT重绑定的结果。

在验证新的客户端地址后，服务端应该（**SHOULD**）向客户端发送新的地址验证令牌（第8章）。

### 9.3.1. 对端地址欺骗（Peer Address Spoofing）

第三方可能会填写假的源地址指向受害方，从而导致终端向受害方发送过多的数据。如果终端发送的数据明显多于第三方，则可能导致连接迁移会放大攻击者可以向受害者生成的数据量。

如第9.3节所述，终端需要验证对端的新地址以确认对端对新地址的所有权。在对端的地址被认为有效之前，终端会限制它发往该地址的数据量，参见第8章。如果没有此限制，终端有可能被用于对毫无戒心的受害者进行拒绝服务攻击。

如果终端如上所述跳过对端地址的验证，则不需要限制其发送速率。

### 9.3.2. On-Path地址欺骗（On-Path Address Spoofing）

on-path攻击者可以通过复制和转发具有虚假源地址的数据包使其在原数据包之前到达，带有虚假源地址的数据包将被视为来自迁移连接，从而导致受害端向虚假地址的连接迁移，而原数据包将被视为重复数据包并被丢弃。在连接迁移之后，地址验证将失败，因为虚假源地址的实体没有必要的加密密钥来读取或响应发送给它的PATH_CHALLENGE帧，即使它想发也不能。

为防止连接因此类虚假迁移而失败，当新对端地址的验证失败时，终端必须（**MUST**）迁回最后验证过的对端地址。此外，从合法对端地址接收到具有更大数据包序号的数据包将触发另一次连接迁移，这将导致对虚假迁移地址的验证被放弃，这使得攻击者在迁移中仅注入了一个数据包。

如果终端没有保存最后验证的对端地址的状态，它必须（**MUST**）放弃所有连接状态并以静默方式关闭连接。这导致连接上的新数据包按照一般方式处理，例如，终端可以（**MAY**）发送Stateless Reset包以响应任何后续传入的数据包。

### 9.3.3. Off-Path包转发（Off-Path Packet Forwarding）

能够观察到数据包的非路径（off-path）攻击者可能会将真实数据包的副本转发到终端。如果复制的数据包在真正的数据包之前到达，这将被识别为NAT重绑定。后到的真实的数据包都将被作为副本丢弃。如果攻击者能够继续转发数据包，则可能会导致终端迁移到经过攻击者的某条路径。这将攻击者置于路径上，使其能够观察或丢弃所有后续数据包。

这种类型的攻击依赖于攻击者使用与两终端之间的直接路径具有大致相同特征的路径。如果发送的数据包相对较少，或者数据包丢失与攻击尝试同时发生，则更可能被攻击。

在初始路径上接收到具有更大的数据包号的非探测包（non-probing packets）将导致终端移回合法的路径。在此路径上发送触发包会增加攻击失败的可能性。因此，减轻这种攻击依赖于触发包的交换。

为了回迁到原来的路径，终端必须（**MUST**）使用PATH_CHALLENGE帧验证之前的活动路径。这会导致在该路径上发送新的探测包。如果路径不再可行（viable），验证尝试将超时并失败；如果路径可行（viable）但不再需要，则验证将成功，但只会在路径上发送探测包（probing packets）。

在活动路径上接收到PATH_CHALLENGE的终端应该（**SHOULD**）发送非探测数据包作为响应。如果非探测数据包（non-probing packet）在攻击者生成的任何副本之前到达，则会导致连接迁移回初始路径。任何后续迁移到其他路径都会重新启动整个过程。

这种防御是不完善的，但这并不是一个严重的问题。尽管多次尝试使用初始路径，但通过攻击者的路径确实比初始路径快，则无法区分攻击和路由改进。

终端还可以使用启发式探索法（heuristics）来提高对这种类型攻击的检测。例如，如果最近在旧路径上接收到数据包，则不大可能是NAT重绑定，同样，在IPv6路径上很少进行重绑定。终端也可以查找重复的数据包。相反，CID的更改更可能表示有意的（intentional）迁移，而不是攻击。

## 9.4. 丢包检测和拥塞控制（Loss Detection and Congestion Control）

新路径上的可用容量可能与旧路径不同。在旧路径上发送的数据包不得（**MUST NOT**）参与新路径的拥塞控制或RTT估计。

在确认对端对其新地址的所有权后，终端必须（**MUST**）立即将新路径的拥塞控制器和往返时间估计器重置为初始值（参见[QUIC-RECOVERY]的附录A.3或B.3），除非对端地址唯一变化的是其端口号。由于仅端口变更通常是NAT重绑定或其他中间设备活动的结果，因此在这些情况下，终端可以（**MAY**）保留其拥塞控制状态和RTT估计，而不是恢复到初始值。如果将旧路径保留的拥塞控制状态用于具有显著不同特性的新路径，发送方可能会过于激进地传输，直到拥塞控制器和RTT估计器适应为止。通常，建议实现在新路径上使用历史数据时要谨慎。

当终端在迁移期间从/向多个地址发送数据和探测包时，接收端处可能会出现明显的乱序，因为不同路径可能具有不同的RTT。接收方仍将发送覆盖所有接收到的数据包的ACK帧。

尽管在连接迁移期间可能使用多条路径，但只需要维护一个单独的拥塞控制上下文和丢包恢复上下文（如[QUIC-RECOVERY]中所述）可能就足够了。例如，终端可能会延迟切换到新的拥塞控制上下文，直到确认不再需要旧路径（例如第9.3.3小节中描述的情况）。

发送方可以对探测数据包进行单独处理，以保证它们的丢包检测是独立的，不会导致拥塞控制器过度降低其发送速率。当发送PATH_CHALLENGE时，终端可能会设置一个单独的定时器，如果收到相应的PATH_RESPONSE，则停止该定时器，如果定时器在收到PATH_RESPONSE之前到期，终端可能会发送一个新的PATH_CHALLENGE帧并启动一个更长的定时器。这个定时器应该（**SHOULD**）按照[QUIC-RECOVERY]第6.2.1小节的描述设置，并且不得（**MUST NOT**）更激进。

## 9.5. 连接迁移对隐私的影响（Privacy Implications of Connection Migration）

在多条网络路径上使用稳定的CID将使得被动观察者可以关联这些路径之间的活动。需要迁移网络的终端可能不希望它们的活动被除对端以外的任何实体关联，因此从不同的本地地址发送时会使用不同的CID，如第5.1节所述。为了有效实现这一点，终端需要确保它们提供的CID不能被任何其他实体关联起来。

在任何时候，终端都可以（**MAY**）将它们填写的DCID变更为尚未在另一条路径上使用的值。

当从多个本地地址发送数据时，终端不得（**MUST NOT**）重用SCID——例如在第9.2节中描述的启动连接迁移或在第9.1节中描述的探测新的网络路径时。

类似地，当发往多个目的地址时，终端也不得（**MUST NOT**）重用DCID。由于网络变更不受其对端控制，终端可能会收到具有新的源地址但与旧地址有相同DCID字段的数据包，在这种情况下，终端如果从同一个本地地址发往新地址的话，可以（**MAY**）继续使用当前CID。

这些关于CID重用的要求仅适用于数据包的发送，因为在不改变CID的情况下无意识变更路径是可能的，例如，经过一段时间的网络静默之后，NAT重绑定可能会导致在客户端恢复发包时在新路径上发送数据包。终端如何响应此类事件参见第9.3节。

在每条新网络路径上的双向数据包中启用不同的CID，可以消除将同一连接的不同路径关联起来的可能性。包头保护确保不能用数据包序号关联活动，但不能阻止使用数据包的其他属性（例如时间和大小）来关联活动。

终端不应该（**SHOULD NOT**）向要求零长度CID的对端发起迁移，因为新路径上的流量可能很容易关联到旧路径上的流量。如果服务端能够将具有零长度CID的数据包关联到正确的连接，则意味着服务端正在使用其他信息来解复用并关联数据包。例如，服务端可能会为每个客户端提供一个唯一的地址——例如，使用HTTP替代服务[ALTSVC]。使得跨多个网络路径也能正确路由数据包的信息，但同时也可能使得这些路径上的活动被除对端以外的其他实体关联。

在一段时间静默之后再发送流量时，客户端可能希望通过切换到新的CID、源UDP端口或IP地址（参见[RFC8981]）来降低可关联性。变更数据包的源地址也可能会导致服务端检测到连接迁移。这确保即使对于没有经历NAT重绑定或真正迁移的客户端，也可以使用支持迁移的机制。变更地址会导致对端重置其拥塞控制状态（请参阅第9.4节），因此地址应该（**SHOULD**）不要频繁变更。

耗尽可用CID的终端无法再继续探测新路径或启动迁移，也无法响应其对端的探测或迁移尝试。为了确保迁移可行，并且在不同路径上发送的数据包不能被相互关联，终端应该（**SHOULD**）在对端体迁移之前提供新的CID，参见第5.1.1小节。如果判断对端可能已经用尽了可用的CID，则待迁移终端可能需要在新网络路径上发送的所有数据包中都包含NEW_CONNECTION_ID帧。

## 9.6. 服务端的首选地址（Server's Preferred Address）

QUIC允许多个服务端接受同一个IP地址上的入向连接，可以在握手后不久尝试将连接转到某个服务端提供的其他首选地址。这对客户端接入时连接到多个服务端共享的地址，之后再使用单播地址以确保连接稳定性时特别有用。本节介绍将连接迁移到首选服务端地址的协议内容。

本文中指定的QUIC版本不支持在连接中将连接迁移到新的服务端地址。如果客户端在未启动迁移到该地址时收到来自新服务端地址的数据包，则客户端应该（**SHOULD**）丢弃这些数据包。

### 9.6.1. 传输首选地址（Communicating a Preferred Address）

服务端通过在TLS握手中包含preferred_address传输参数来告知首选地址。

服务端可以（**MAY**）告知两个地址族（IPv4和IPv6）的首选地址，以允许客户端选择最适合其网络连接的地址。

一旦握手确认完成，客户端应该（**SHOULD**）选择服务端提供的两个地址之一并启动路径验证（见第8.2节）。客户端使用任何以前未使用的活动CID构造数据包，这些ID取自preferred_address传输参数或NEW_CONNECTION_ID帧。

一旦路径验证成功，客户端应该（**SHOULD**）开始使用新的CID发送后续数据包到新的服务端地址，并停止使用旧的服务端地址。如果路径验证失败，客户端必须（**MUST**）将后续数据包发往服务端的初始IP地址。

### 9.6.2. 迁移到首选地址（Migration to a Preferred Address）

迁移到首选地址的客户端必须（**MUST**）在迁移前验证它选择的地址，参见第21.5.3小节。

服务端在接受连接后的任何时候都可能收到寻址到其首选IP地址的数据包。如果此数据包包含PATH_CHALLENGE帧，则服务端会如第8.2节所述回复包含PATH_RESPONSE帧的数据包。服务端必须（**MUST**）从其初始地址发送非探测数据包，直到它在其首选地址从客户端接收到非探测数据包，直到服务端验证了该新路径。

服务端必须（**MUST**）探测从其首选地址到客户端的路径。这有助于防止攻击者发起的虚假迁移。

一旦服务端完成其路径验证并在其首选地址上接收到具有新的最大数据包序号的非探测数据包，服务端就开始仅从其首选IP地址向客户端发送非探测数据包。服务端应该（**SHOULD**）丢弃在旧IP地址上接收到的此连接的新数据包，但可以（**MAY**）继续处理在旧IP地址上接收到的延迟数据包。

服务端在preferred_address传输参数中提供的地址仅对提供它们的连接有效。客户端不得（**MUST NOT**）将这些用于其他连接，包括从当前连接恢复的连接。

### 9.6.3. 客户端迁移与首选地址的交互（Interaction of Client Migration and Preferred Address）

客户端可能需要在迁移到服务端的首选地址之前执行连接迁移。在这种情况下，客户端应该（**SHOULD**）同时执行从客户端新地址到初始和首选服务端地址的路径验证。

如果服务端首选地址的路径验证成功，则客户端必须（**MUST**）放弃对服务端初始地址的验证并迁移到服务端的首选地址。如果服务端首选地址的路径验证失败但服务端初始地址的验证成功，则客户端可以（**MAY**）切换到客户端新地址并继续发包到服务端的初始地址。

如果在服务端首选地址收到的数据包与握手期间从客户端观察到的源地址不同，则服务端必须（**MUST**）防止潜在的攻击，如第9.3.1和第9.3.2小节所述。除了有意的同时迁移之外，这也可能是因为客户端的访问网络对服务端的首选地址使用了不同的NAT绑定。

服务端应该（**SHOULD**）在收到来自不同地址的探测包时启动到客户端新地址的路径验证，参见第8章。

迁移到新地址的客户端应该（**SHOULD**）为服务端使用来自相同地址族的首选地址。

preferred_address传输参数中提供的CID不特定于所提供的地址。提供此CID是为了确保客户端具有可用于迁移的CID，但客户端可以（**MAY**）在任何路径上使用此CID。

## 9.7. IPv6流标签的使用和迁移（Use of IPv6 Flow Label and Migration）

使用IPv6发送数据的终端应该（**SHOULD**）应用符合[RFC6437]的IPv6流标签，除非本地API不允许设置IPv6流标签。

流标签生成方式，必须（**MUST**）尽量降低与先前使用的流标签关联的可能，因为稳定的流标签将能够关联多个路径上的活动，参见第9.5节。

[RFC6437] 建议使用伪随机数函数来生成流标签。一种可能的实现是用加密散列函数生成流标签，散列函数的参数有本地秘钥、源地址和目的地址、DCID字段，这可确保变更与其他可观察到的标识符的变更同步。 

# 10. 连接关闭（Connection Termination）

可以通过以下三种方式之一终止已建立的QUIC连接：

* 空闲超时（第10.1节）
* 立即关闭（第10.2节）
* 无状态重置（第10.3节）

如果终端没有可以（**MAY**）发送数据包的经过验证的路径，则它可以丢弃连接状态，参见第8.2节。

## 10.1. 空闲超时（Idle Timeout）
如果任一终端在其传输参数（第18.2节）中指定max_idle_timeout，则当连接保持空闲的时间超过两端通告的max_idle_timeout值的最小值时，连接将被静默关闭并丢弃其状态。

虽然每个终端都通告一个max_idle_timeout，但终端中真正生效的有效值是两个通告值（或唯一通告值，如果只有一个终端通告非零值）中的最小值。如果终端在有效值超时之前放弃连接，则它应启动立即关闭（第10.2节）。

当一个终端收到并成功处理来自其对端的数据包时，终端会重置其空闲定时器。如果自上次接收和处理数据包后没有发送其他确认数据包，终端也会在发送确认数据包时重置其空闲定时器。在发送数据包时重置定时器可确保在有新活动后不会关闭连接。

为避免空闲超时时间过短，终端必须（**MUST**）将空闲超时时间增加到至少是当前探测超时（PTO for Probe Timeout）的三倍。这在空闲超时之前可以允许多次探测或丢包。

### 10.1.1. 活性测试（Liveness Testing）
临近有效空闲超时时间发送的数据包有可能被对端丢弃，因为在这些数据包到达之前，对端的空闲超时期限可能已经到期。

如果对端可能很快超时，例如在PTO内，终端可以发送PING包或另一个ACK触发帧来测试连接的活跃性，参见[QUIC-RECOVERY]第6.2节。这在无法安全地重传可用的应用数据时尤其有用。请注意，哪些数据可以安全重传由应用程序确定。）

### 10.1.2. 延迟空闲超时（Deferring Idle Timeout）
如果终端正在等待响应数据但没有或无法发送应用数据，则它可能需要发送ACK触发包以避免空闲超时。

QUIC的实现可为应用提供延迟空闲超时的选项。当应用希望避免丢失与打开的连接相关联的状态，但不希望在一段时间内交换应用数据时，可以使用此功能。使用此选项，终端可以周期性发送PING帧（第19.2节），这将导致对端重置空闲超时定时器。如果这是本端自收到数据包后发送的第一个ACK触发包，则也会重置此终端的空闲超时定时器。发送PING帧会导致对端回以确认ACK响应，这也会重置对端的空闲超时定时器。

使用QUIC的应用层协议应该（**SHOULD**）提供合适的有关何时推迟空闲超时的指导。不必要地发送PING帧可能会对性能产生不利影响。

如果超过max_idle_timeout传输参数协商的时间还没有发送或接收数据包，则连接将超时（请参阅第10章）。另外，中间设备的状态也可能会提前超时。尽管[RFC4787]中的REQ-5建议2分钟的超时间隔，但经验表明，每30秒发送一次数据包是必要的，可以防止大多数中间设备丢失UDP流[GATEWAY]的状态。

## 10.2. 立即关闭（Immediate Close）
终端发送CONNECTION_CLOSE帧（第19.19节）以立即终止连接。CONNECTION_CLOSE帧会导致所有流立即关闭。可以假定打开的流被隐式重置。

发送CONNECTION_CLOSE帧后，终端立即进入“关闭中”(closing) 状态，参见第10.2.1小节。终端收到CONNECTION_CLOSE帧后，进入draining 状态，见第10.2.2小节。

违反协议会导致立即关闭。

在应用层协议指示关闭连接后，可以使用立即关闭。这可能发生在应用层协议之间协商优雅关闭之后。两个应用终端先交换同意关闭连接所需的消息，然后应用请求QUIC关闭连接。当QUIC因此启动关闭流程时，会向对端发出关闭信号，携带附有应用提供的错误码的CONNECTION_CLOSE帧。

closing和draining连接状态的存在是为了确保连接干净利落地关闭，并正确丢弃延迟或乱序的数据包。这些状态应该（**SHOULD**）至少持续三倍于[QUIC-RECOVERY]中定义的当前PTO间隔。

在退出closing或draining状态之前清除连接状态，可能会导致终端在接收到迟到的数据包时不必要地生成Stateless Reset包。有一些替代方法来确保迟到的数据包不会触发终端响应措施，例如那些能够关闭UDP套接字的终端，可以（**MAY**）提前结束这些状态以允许更快的资源恢复。保留打开套接字以接受新连接的服务端不应该（**SHOULD NOT**）提前结束closing或draining状态。

一旦其closing或draining状态结束，终端应该（**SHOULD**）丢弃所有连接状态。终端可以（**MAY**）发送一个Stateless Reset包来响应这个连接的后续传入数据包。

### 10.2.1. 关闭中连接状态（Closing Connection State）
终端在发起立即关闭后进入closing状态。

在closing状态下，终端仅保留足够的信息来生成包含CONNECTION_CLOSE帧的数据包并将数据包标识为属于该连接。处于closing状态的终端发送一个包含CONNECTION_CLOSE帧的数据包，以响应该连接上的传入数据包。

终端应该（**SHOULD**）限制它在关闭状态下生成数据包的速率。例如，终端可以等待足够数量的数据包或足够的时间之后再响应接收到的数据包。

终端选择的CID和QUIC版本足以识别closing态连接的数据包，终端可以（**MAY**）丢弃所有其他连接状态。closing态的终端不需要处理任何接收到的帧。终端可以（**MAY**）为传入的数据包保留数据包保护密钥，在读取时可以用于解密和处理CONNECTION_CLOSE帧。

终端可以（**MAY**）在进入closing状态时丢弃数据包保护密钥，并发送包含CONNECTION_CLOSE帧的数据包以响应收到的任何UDP报文。但是，丢弃数据包保护密钥的终端无法识别和丢弃无效数据包。为避免被用于放大攻击，此类终端必须（**MUST**）限制其发送的数据包的总字节数为接收的数据包的三倍。为了最小化终端为关闭连接保持的状态，终端可以发送完全相同的数据包以响应任何接收到的数据包。

> 注意：允许重传关闭数据包是对每个数据包均需使用新包号的要求的一个例外，参见第12.3节。发送新的包号主要有利于丢包恢复和拥塞控制，这与关闭连接无关。重传最终数据包需要较少的状态。

当处于closing状态时，终端可以从新的源地址接收数据包，可能表示连接迁移，参见第9章。处于closing状态的终端必须（**MUST**）要么丢弃从未验证地址接收的数据包，要么将其发往未验证地址的数据包的总字节数限制为从该地址接收的数据包的三倍。

终端在关闭时不应处理密钥更新（[QUIC-TLS]第6章）。密钥更新可能会阻止终端从closing状态迁移到draining状态，因为终端将无法处理随后收到的数据包，但也不会产生任何影响。

### 10.2.2. 耗尽连接状态（Draining Connection State）
一旦终端接收到CONNECTION_CLOSE帧，即表示其对端正在关闭或正在耗尽，就进入耗尽状态。虽然其他方面与closing状态相同，但处于draining状态的终端不得（**MUST NOT**）发送任何数据包。一旦连接处于draining状态，就不需要保留数据包保护密钥。

接收CONNECTION_CLOSE帧的终端可以（**MAY**）在进入draining状态之前发送包含CONNECTION_CLOSE帧的单个数据包，如果合适，使用NO_ERROR代码。终端不得（**MUST NOT**）发送更多数据包。这样做可能会导致CONNECTION_CLOSE帧的不断交换，直到终端之一退出closing状态。

如果终端收到CONNECTION_CLOSE帧，则它可以（**MAY**）从closing状态进入draining状态，这表明对端也在closing或draining。在这种情况下，当closing状态将结束时，draining状态结束。换句话说，终端使用相同的结束时间，但停止在此连接上传输任何数据包。

### 10.2.3. 握手期间立即关闭（Immediate Close during the Handshake）
发送CONNECTION_CLOSE帧时需要确保对端能够处理该帧。通常，这意味着需要在具有最高数据包保护级别的数据包中发送该帧以避免数据包被丢弃。在握手确认后（参见[QUIC-TLS]第4.1.2小节），终端必须（**MUST**）在1-RTT包中发送CONNECTION_CLOSE帧。但是，在确认握手之前，对端可能无法使用更高级的数据包保护密钥，因此可以（**MAY**）在使用较低数据包保护级别的数据包中发送另一个CONNECTION_CLOSE帧。特别地：

* 客户端知道服务端是否有握手密钥（见第17.2.2.1小节），但服务端可能不知道客户端是否有握手密钥。在这些情况下，服务端应该（**SHOULD**）在Handshake和Initial包中发送一个CONNECTION_CLOSE帧，以确保其中至少一个可以被客户端处理；

* 在0-RTT包中发送CONNECTION_CLOSE帧的客户端不能保证服务端可接受0-RTT。在Initial包中发送CONNECTION_CLOSE帧使服务端更有可能收到关闭信号，即使可能不理解应用层错误码。

* 在确认握手之前，对端可能无法处理1-RTT包，因此终端应该（**SHOULD**）在握手和1-RTT包中发送CONNECTION_CLOSE帧。服务端还应该（**SHOULD**）在Initial包中发送一个CONNECTION_CLOSE帧。

在Initial或Handshake包中发送0x1d类型的CONNECTION_CLOSE可能会暴露应用状态或用于更改应用状态。当在Initial或Handshake包中发送帧时，类型0x1d的CONNECTION_CLOSE必须（**MUST**）替换为类型为0x1c的CONNECTION_CLOSE帧。否则可能会泄露有关应用状态的信息。终端必须（**MUST**）清除Reason Phrase字段的值，并且在转换为0x1c类型的CONNECTION_CLOSE时应该（**SHOULD**）使用APPLICATION_ERROR错误码。

以多种数据包类型发送的CONNECTION_CLOSE帧可以合并为单个UDP报文，参见第12.2节。

终端可以在Initial包中发送CONNECTION_CLOSE帧，这可能是为了响应在Initial或Handshake包中收到的未经认证的信息。这种立即关闭可能会将合法连接暴露给拒绝服务攻击。QUIC没有在握手期间对路径攻击的防御措施，参见第21.2节。然而，以减少对合法对端的错误反馈为代价，如果终端丢弃非法数据包而不是使用CONNECTION_CLOSE终止连接，则某些形式的拒绝服务可能会使攻击变得更加困难。因此，如果在缺少认证的数据包中检测到错误，终端（**MAY**）丢弃数据包而不是立即关闭。

尚未建立状态的终端，例如在Initial包中检测到错误的服务端，不会进入关闭状态。没有连接状态的终端在发送CONNECTION_CLOSE帧时也不会进入closing或draining。

## 10.3. 无状态重置（Stateless Reset）
无状态重置是作为无法访问连接状态的终端的最后手段提供的。因为崩溃或中断，对端可能继续向无法正常处理连接的终端发送数据，此时终端可以（**MAY**）发送Stateless Reset包，以响应接收到它无法与活动连接关联的数据包。

Stateless Reset包不适用于指示活动连接中的错误。如果可以的话，希望传达致命连接错误的终端必须（**MUST**）使用CONNECTION_CLOSE帧。

为了支持此过程，终端需要发出无状态重置令牌，这是一个很难猜测的16字节值。如果对端随后收到Stateless Reset包，即以该无状态重置令牌结尾的UDP报文，则对端将立即终止连接。

无状态重置令牌特定于CID。终端通过在NEW_CONNECTION_ID帧的Stateless Reset Token字段来发布无状态重置令牌。服务端还可以在握手期间发出stateless_reset_token传输参数，该参数适用于它在握手期间选择的CID。这些交换受加密保护，因此只有客户端和服务端知道它们的真实值。请注意，客户端不能使用stateless_reset_token传输参数，因为它们的传输参数没有机密性保护。

当通过RETIRE_CONNECTION_ID帧（第19.16节）退出关联的CID时，令牌将失效。

接收到它无法处理的数据包的终端发送如下结构的数据包（参见第1.3节）：

```
   Stateless Reset {
     Fixed Bits(2)= 1,
     Unpredictable Bits (38..),
     Stateless Reset Token (128),
   }
```
图10: Stateless Reset Packet

这种设计使得Stateless Reset包——在可能的范围内——与具有短包头的常规数据包无法区分。

Stateless Reset包对应一整个UDP报文，从数据包头的前两位开始。第一个字节的其余部分和它后面的任意数量的字节被设置为应该（**SHOULD**）与随机值无法区分的值。数据报的最后16个字节包含一个无状态重置令牌。

对于预期接收方以外的实体，Stateless Reset包将被识别为具有短标头的数据包。为了使Stateless Reset包识别为有效的QUIC包，Unpredictable Bits字段需要包含至少38位数据（或5个字节，减去两个固定位）。

如果接收方需要使用CID，则生成的21字节的最小大小并不能保证Stateless Reset包和其他数据包无法区分。为了达到这个目的，终端应该（**SHOULD**）确保它发送的所有数据包，至少要比携带最小CID长度的数据包长22个字节，并根据需要添加PADDING帧。这确保了对端发送的任何Stateless Reset包与发送给终端的有效数据包是不可区分的。需要发送Stateless Reset包以响应43个字节或更短的数据包的话，终端应该（**SHOULD**）发送一个比该数据包短一个字节的Stateless Reset包。

这些值假设无状态重置令牌的长度与数据包保护协议AEAD约定的最小扩展长度相同。如果终端可以协商具有更大最小扩展的数据包保护方案，则需要额外的Unpredictable Bits。

终端不得（**MUST NOT**）发送比它接收的数据包大三倍或以上的Stateless Reset包，以避免被用于放大攻击。第10.3.3小节描述了对Stateless Reset包大小的附加限制。

终端必须（**MUST**）丢弃因太短不合规的QUIC包。举个例子，用[QUIC-TLS]中定义的一组AEAD函数加密后，小于21字节的短包头数据包永远是无效的。

终端必须（**MUST**）发送形式类似短包头的数据包的Stateless Reset包。另外，终端必须（**MUST**）将任何以有效无状态重置令牌结尾的数据包视为Stateless Reset包，其他QUIC版本可能允许使用长包头。

终端可以（**MAY**）发送Stateless Reset包以响应具有长包头的数据包。在无状态重置令牌可供对端使用之前，发送Stateless Reset包无效。在当前QUIC版本中，具有长包头的数据包仅在连接建立期间使用。由于无状态重置令牌在连接建立完成或接近完成之前不可用，因此忽略具有长包头的未知数据包可能与发送Stateless Reset包有一样的效果。

终端无法从具有短包头的数据包中确定SCID，它不也能在Stateless Reset包中设置DCID。因此，DCID将与先前数据包中使用的值不同。随机DCID使CID看起来像连接迁移的NEW_CONNECTION_ID帧提供的新CID，参见第19.15节。

使用随机CID会导致两个问题：

* 数据包可能无法到达对端，如果DCID对于路由到对端至关重要的话，则此数据包可能会被错误地路由。这也可能会触发另一个Stateless Reset包作为响应，参见第10.3.3小节。发送不能正确路由的Stateless Reset包是一种无效的错误检测和恢复机制。在这种情况下，终端将需要依赖其他方法（例如定时器）来检测连接是否失败。

* 随机生成的CID可由对端实体以外的实体使用，以将其识别为潜在的Stateless Reset包。偶尔使用不同CID的终端可能会对此引入一些不确定性。

这种无状态重置设计特定于QUIC版本1。支持多个QUIC版本的终端需要生成一个Stateless Reset包，该Stateless Reset包应该可被对端接收，对端应该支持本端可能支持（或在丢失状态之前可能已支持）的任何版本，新版本QUIC的设计人员需要意识到这一点，并且要么(1)重用此设计，要么(2)使用除最后16个字节以外的数据包的一部分来承载数据。

### 10.3.1. 检测无状态重置包（Detecting a Stateless Reset）
终端使用UDP报文的最后的16字节检测潜在的Stateless Reset包。终端应记住所有与它最近发送的数据报文的CID和远端地址相关联的无状态重置令牌。这包括来自NEW_CONNECTION_ID帧的Stateless Reset Token字段值和服务端的传输参数，但不包括与未使用或已停用的CID关联的无状态重置令牌。终端通过将数据报文的最后16个字节与所有关联活动连接的无状态重置令牌进行比较，将接收到的数据报识别为Stateless Reset包。

可以对每个入向数据报文执行此比较。如果来自数据报文的任何数据包被成功处理，终端可以（**MAY**）跳过此检查。但是，当入向数据报文中的第一个数据包无法与连接关联或无法解密时，必须（**MUST**）执行此比较。

终端不得（**MUST NOT**）检查与未使用或停用的CID相关联的无状态重置令牌。

当将数据报文与无状态重置令牌值进行比较时，终端必须（**MUST**）不泄漏有关令牌值的信息。例如，在特定时间周期内执行此比较可以保护各个无状态重置令牌的值免于通过timing side channels泄漏信息。另一种方法是存储和比较无状态重置令牌的转换值而不是初始令牌值，例如可使用以密钥（例如，分块加密算法Hashed Message Authentication Code（HMAC）[RFC2104]）为入参的加密安全伪随机数函数做转换。终端不应保护诸如数据包是否成功解密或有效的无状态重置令牌的数量之类的信息。

如果数据报文的最后16个字节与无状态重置令牌的值相同，则终端必须（**MUST**）进入draining期并且不再在此连接上发送任何其他数据包。

### 10.3.2. 计算无状态重置令牌（Calculating a Stateless Reset Token）
无状态重置令牌必须（**MUST**）难以猜测。为了创建无状态重置令牌，终端可以为其创建的每个连接随机生成[RANDOM]一个秘钥。但是，当在一个集群或存储池中有多个实例终端可能会丢失状态时，这会带来协调问题。无状态重置机制是专门用于处理状态丢失的情况，因此这种方法不是最理想的。

可以通过使用伪随机函数生成证明（proof），该函数采用静态密钥和终端选择的CID（参见第5.1节）作为输入，可以在到同一终端的所有连接中使用相同的静态密钥。这类函数可选HMAC[RFC2104]（HMAC(static_key, connection_id)）或基于HMAC的密钥派生函数 (HKDF)[RFC5869]（例如使用静态密钥作为输入密钥材料，CID作为salt）。函数的输出被截断为16个字节，以作为该连接的无状态重置令牌。

失去状态的终端可以使用相同的方法生成有效的无状态重置令牌。CID来自终端接收的数据包。

这种设计依赖于对端始终在其数据包中发送CID，以便终端可以使用数据包中的CID来重置连接。使用这种设计的终端必须（**MUST**）要么对所有连接使用相同的CID长度，要么对CID的长度进行编码，以便它可以在没有状态的情况下恢复。此外，它不能提供零长度的CID。

注意无状态重置令牌允许任何实体终止连接，因此一个值只能使用一次。这种选择无状态重置令牌的方法意味着CID和静态密钥的组合不得（**MUST NOT**）用于另一个连接。如果共享静态密钥的实例使用相同的CID，或者如果攻击者可以将数据包路由到没有状态但具有相同静态密钥的实例，则可能发生拒绝服务攻击，参见第21.11节。如果CID曾被无状态重置令牌重置的连接使用过，则其不得（**MUST NOT**）重用于与此连接共享静态密钥的节点上。

相同的无状态重置令牌不得（**MUST NOT**）用于多个CID。终端不需要将新值与所有以前的值进行比较，但重复值可以（**MAY**）被视为PROTOCOL_VIOLATION类型的连接错误。

请注意，Stateless Reset包没有任何加密保护。

### 10.3.3. 循环（Looping）
无状态重置的设计使得在不知道无状态重置令牌的情况下，它与有效数据包无法区分。例如，如果服务端向另一台服务端发送Stateless Reset包，它可能会收到另一个Stateless Reset包作为响应，这可能导致循环交换。

终端必须（**MUST**）确保它发送的每个Stateless Reset包都小于触发它的数据包，除非它保持足够的状态以防止循环。在出现环路的情况下，这会导致数据包最终太小而无法触发响应。

终端也可以记住它已发送的Stateless Reset包的数量，一旦达到限制就停止生成新的Stateless Reset包。对不同的远端地址使用单独的限制将确保当其他对端或连接已用完限制时，可以使用Stateless Reset包来关闭连接。

小于41字节的Stateless Reset包可能会被第三方观察者识别为Stateless Reset包，具体取决于对端CID的长度。另外，不发送Stateless Reset包来响应小数据包，可能会导致仅存在小数据包交互的连接断链场景下，无状态重置机制失效，此类故障可能只能通过其他方式（例如定时器）检测到。

# 11. 错误处理（Error Handling）
检测到错误的终端应该（**SHOULD**）向它的对端发出指示错误的信号。传输级和应用级错误都会影响整个连接，参见第11.1节。只有应用级别的错误才能隔离到单个流中，见第11.2节。

发出错误信号的帧中应该（**SHOULD**）包含最符合错误原因的代码（参见第20章）。此规约有约定错误条件以及其对应的错误码，尽管在规约条文中这些是必备的条件，但不同的实现策略可能会导致报告不同的错误。特别是，终端可以（**MAY**）在检测到错误情况时使用任何适用的错误码，不过通用错误码（例如PROTOCOL_VIOLATION或INTERNAL_ERROR）总是可以用来取代特定的错误码。

无状态复位（见第10.3节）不适用于可以用CONNECTION_CLOSE或RESET_STREAM帧指示的任何错误。具有可在连接上发送帧所需状态的终端不得（**MUST NOT**）使用无状态复位。

## 11.1. 连接错误（Connection Errors）

导致连接不可用的错误，例如明显违反协议语义或影响整个连接的状态崩溃，必须（**MUST**）使用CONNECTION_CLOSE帧（第19.19节）发出信号。

特定于应用的协议错误，需要使用帧类型为0x1d的CONNECTION_CLOSE帧发出信号。特定于传输的错误，包括本文中描述的所有错误，都需要包含在帧类型为0x1c的CONNECTION_CLOSE帧中。

CONNECTION_CLOSE帧可能丢失，如果终端在终止的连接上接收到更多数据包，则它应该（**SHOULD**）准备重传包含CONNECTION_CLOSE帧的数据包。限制重传次数和重传持续时间可以限制在终止连接上花费更多精力。

如果选择不重传包含CONNECTION_CLOSE帧的数据包，其对端有可能收不到第一包CONNECTION_CLOSE帧。对继续在已终止的连接上收到数据包的终端，其唯一可行的机制是尝试无状态重置过程（第10.3节）。

由于Initial包的AEAD不提供强身份验证，终端可以（**MAY**）丢弃无效的Initial包。不过本规约要求上报连接错误。如果终端不处理数据包中的帧或需要回退某些处理流程，则它只能丢弃数据包。丢弃无效的Initial包可用于减少拒绝服务的风险，参见第21.2节。

## 11.2. 流错误（Stream Errors）

如果应用级错误影响单个流，但因其他因素，连接仍处于可恢复状态，则终端可以发送带有适当错误码的RESET_STREAM帧（第19.4节）以仅终止受影响的流。

在不通知应用层协议的情况下重置流可能导致应用层协议进入不可恢复状态，因此RESET_STREAM必须（**MUST**）由调用QUIC的应用层协议发起。

RESET_STREAM中携带的应用层错误码的语义由应用层协议定义。只有应用层协议能够终止流。应用层协议的本地实例可直接通过API调用，远端实例使用STOP_SENDING帧，以触发本端启动RESET_STREAM流程。

应用层协议应该（**SHOULD**）定义规则，处理被任一终端提前取消的流。

# 12. 数据包和帧（ Packets and Frames）

QUIC终端通过交换数据包进行通信。数据包具有机密性和完整性保护，参见第12.1节。数据包在UDP报文中携带，参见第12.2节。

此QUIC版本在连接建立时使用长包头，参见第17.2节。带有长包头的数据包是Initial（第17.2.2小节）,0-RTT（第17.2.3小节）,Handshake（第17.2.4小节），和Retry（第17.2.5小节）。版本协商使用与版本无关的带有长包头的数据包，参见第17.2.1小节。

带有短包头的数据包为最小开销设计，并在建立连接且1-RTT密钥可用后使用，参见第17.3节。

## 12.1. 受保护的数据包（Protected Packets）

QUIC包根据类型具有不同级别的加密保护。数据包保护的详细信息可在[QUIC-TLS]中找到，本节概述其所能提供的保护措施。

Version Negotiation包没有加密保护，参见[QUIC-INVARIANTS]。

Retry包使用AEAD功能[AEAD]来防止意外修改。

Initial包使用AEAD保护，其密钥是使用在线上可见的值派生的。因此Initial包没有有效的机密性保护。Initial保护的引入是确保数据包的发送方位于网络路径上。任何从客户端接收到Initial包的实体都可以恢复密钥，这将允许它们既能正确读取数据包的内容，也能生成对端可以成功验证的Initial包。AEAD还保护Initial包免受意外修改。

所有其他数据包都使用来自加密Handshake的密钥进行保护。加密Handshake确保只有通信终端才能收到Handshake、0-RTT和1-RTT包的相应密钥。使用0-RTT和1-RTT密钥保护的数据包具有很强的机密性和完整性保护。

出现在某些数据包类型中的Packet Number字段作为包头保护的一部分可以替代机密性保护，有关详细信息，请参阅[QUIC-TLS]第5.4节。在特定包号空间中发送的每个包的底层包号都会递增，详细信息参见第12.3节。

## 12.2. 合并数据包（Coalescing Packets）

Initial（第17.2.2小节）、0-RTT（第17.2.3小节）和Handshake（第17.2.4小节）数据包包含指示数据包尾部的Length字段。包长包括Packet Number和Packet Payload字段的长度，这两个字段都是机密性保护的并且最初长度未知。一旦包头保护被移除，Payload字段的长度就会暴露。

使用Length字段，发送方可以将多个QUIC包合并为一个UDP报文。这可以减少完成加密握手所需的UDP报文的数量，之后开始发送数据。这也可用于构建路径最大传输单元(PMTU)探针，参见第14.4.1小节。接收方必须（**MUST**）能够处理合并的数据包。

按加密级别递增的顺序（Initial、0-RTT、Handshake、1-RTT，参见[QUIC-TLS]第4.1.4小节）合并数据包使得接收方更有可能一次处理所有数据包。具有短包头的数据包不包含长度，因此它只能是UDP报文中包含的最后一个数据包。如果多个帧有相同的加密级别，终端应该（**SHOULD**）尽量将它们组帧在单个数据包中，而不是分开在多个数据包中发送。

接收方可以（**MAY**）根据UDP报文中包含的第一个数据包中的信息进行路由。发送方不得（**MUST NOT**）将具有不同CID的QUIC包合并为单个UDP报文。接收方应该（**SHOULD**）忽略与数据报文中的第一个数据包具有不同DCID的任何后续数据包。

合并成单个UDP报文的每个QUIC包都是独立且完整的。接收到多QUIC包合并的UDP报文，接收方必须（**MUST**）单独处理每个QUIC包并分别确认它们，就好像它们是作为不同UDP报文的负载被接收的一样。例如，如果某包解密失败（因为密钥不可用或出于任何其他原因），接收方可以（**MAY**）丢弃或缓冲这个数据包以待后续处理，之后必须（**MUST**）尝试处理UDP报文中的剩余数据包。

Retry包（第17.2.5小节）、Version Negotiation包（第17.2.1小节）和具有短包头的数据包（第17.3节）不包含Length字段，因此不能做UDP报文的中间数据包，其实也不会出现Retry或Version Negotiation包与另一个数据包合并的情况。

## 12.3. 包号（Packet Numbers）

包号是0到2^62^-1范围内的整数。该编号用于确定数据包保护的加密随机数。每个终端对发送和接收部分分别维护一个单独的包号。

包号限制在此范围内，因为它们需要在ACK帧的最大确认字段中完整表示（第19.3节）。然而，当出现在长或短包头中时，包号长度会压缩并编码为1到4个字节，参见第17.1节。

Version Negotiation包（第17.2.1小节）和Retry包（第17.2.5小节）不包含包号。

QUIC中包号分为三个空间：
* Initial空间：所有Initial包（第17.2.2小节）都在此空间中。
* Handshake空间：所有Handshake包（第17.2.4小节）都在这个空间中。
* 应用数据空间：所有0-RTT（第17.2.3小节）和1-RTT（第17.3.1小节）数据包都在这个空间中。

如[QUIC-TLS]中所述，每种数据包类型使用不同的保护密钥。

从概念上讲，包号空间是可以处理和确认数据包的上下文。Initial包只能使用Initial包保护密钥发送，并只能在Initial包中进行确认。同样，Handshake包使用Handshake级别加密发送，只能在Handshake包中确认。

这强制在不同包号空间中发送的数据之间进行加密分离。每个空间中的包号从0开始，在同一包号空间中发送的后续包号至少增加1。

0-RTT和1-RTT数据存在于同一个包号空间中，使两种数据包类型之间的丢包恢复算法更容易实现。

QUIC终端不得（**MUST NOT**）在一个连接中的相同包号空间内重用包号。如果要发送的数据包数量达到2^62^-1，则发送方必须（**MUST**）关闭连接，并且不发送CONNECTION_CLOSE帧或任何其他数据包，在接收到对端后续数据包时，可以（**MAY**）发送Stateless Reset包（第10.3节）。

接收方必须（**MUST**）丢弃一个新的未受保护的数据包，除非在相同的包号空间，它处理过相同包号的另一个数据包。因为由于[QUIC-TLS]第9.5节中描述的原因，删除数据包保护后必须（**MUST**）发生重复抑制（Duplicate Suppression）。

为检测重复数据而跟踪所有单个数据包，终端存在累积过多状态的风险。可以通过维护一个最小处理包号来限制检测重复所需的数据量，所有小于该编号的数据包可被立即丢弃。任何最小值的设定都需要考虑RTT的巨大变化，其中需要包括对端可能在更大的RTT下探测网络路径的可能性，参见第9章。

第17.1节描述了发送方的包号编码和接收方的解码。

## 12.4. 帧和帧类型（Frames and Frame Types）

去除数据包保护后，QUIC包的负载由一系列完整的帧组成，如图11所示。Version Negotiation包、Stateless Reset包和Retry包不包含帧。

```
   Packet Payload {
     Frame (8..) ...,
   }
```
图11: QUIC Payload

包含帧的数据包的负载必须（**MUST**）至少包含一个帧，并且可以（**MAY**）包含多个帧和多种帧类型。终端必须（**MUST**）将收到不包含帧的数据包视为PROTOCOL_VIOLATION类型的连接错误。一个帧只能包含在单个QUIC包中，不能跨越多个数据包。

每个帧都以一个帧类型开始，表明它的类型，然后是附加的类型相关字段：

```
   Frame {
     Frame Type (i),
     Type-Dependent Fields (..),
   }
```
图12: Generic Frame Layout

表3列出并总结了有关本规约中定义的每种帧类型的信息。表格之后有具体说明。

   | Type Value  | Frame Type Name      | Definition    | Pkts | Spec |
   |:---|:---|:---|:---|:---|
   |0x00       | PADDING              | 第19.1节 | IH01 | NP   |   
   |0x01       | PING                 | 第19.2节 | IH01 |      |   
   |0x02-0x03| ACK                  | 第19.3节 | IH_1 | NC   |   
   |0x04       | RESET_STREAM         | 第19.4节 | __01 |      |   
   |0x05       | STOP_SENDING         | 第19.5节 | __01 |      |   
   |0x06       | CRYPTO               | 第19.6节 | IH_1 |      |   
   |0x07       | NEW_TOKEN            | 第19.7节 | ___1 |      |   
   |0x08-0x0f| STREAM               | 第19.8节 | __01 | F    |   
   |0x10       | MAX_DATA             | 第19.9节 | __01 |      |   
   |0x11       | MAX_STREAM_DATA      | 第19.10节| __01 |      |   
   |0x12-0x13| MAX_STREAMS          | 第19.11节| __01 |      |   
   |0x14       | DATA_BLOCKED         | 第19.12节| __01 |      |   
   |0x15       | STREAM_DATA_BLOCKED  | 第19.13节| __01 |      |   
   |0x16-0x17| STREAMS_BLOCKED      | 第19.14节| __01 |      |   
   |0x18       | NEW_CONNECTION_ID    | 第19.15节| __01 | P    |   
   |0x19       | RETIRE_CONNECTION_ID | 第19.16节| __01 |      |   
   |0x1a       | PATH_CHALLENGE       | 第19.17节| __01 | P    |   
   |0x1b       | PATH_RESPONSE        | 第19.18节| ___1 | P    |   
   |0x1c-0x1d| CONNECTION_CLOSE     | 第19.19节| ih01 | N    |   
   |0x1e       | HANDSHAKE_DONE       | 第19.20节| ___1 |      |   

表3: Frame Types

第19章.更详细地解释了每种帧类型的格式和语义。本节的其余部分提供了重要和一般信息的摘要。

ACK、STREAM、MAX_STREAMS、STREAMS_BLOCKED和CONNECTION_CLOSE帧中的Frame Type字段用于携带其他特定于帧的标志。对于所有其他帧，Frame Type字段仅标识帧。

表3中的Pkts列列出了每种帧类型可能出现的数据包类型，由以下字符表示：
* I：   Initial（第17.2.2小节）
* H：   Handshake（第17.2.4小节）
* 0：   0-RTT（第17.2.3小节）
* 1：   1-RTT（第17.3.1小节）
* ih：  只有0x1c类型的CONNECTION_CLOSE帧可以出现在Initial或Handshake包中。

有关这些限制的更多详细信息，请参阅第12.5节。请注意，所有帧都可以出现在1-RTT包中。终端必须（**MUST**）将接收到的数据包类型中不允许出现的帧视为PROTOCOL_VIOLATION类型的连接错误。

表3中的Spec列总结了控制帧类型处理或生成的任何特殊规则，如以下字符所示：
* N：仅包含带有此标记的帧的数据包不是ACK触发包，参见第13.2节。
* C：出于拥塞控制目的，仅包含带有此标记的帧的数据包，不计入传输中的字节数计算，见[QUIC-RECOVERY]。
* P：仅包含带有此标记的帧的数据包，可用于在连接迁移期间探测新的网络路径，参见第9.1节。
* F：带有此标记的是流控帧，参见第4章。

表3中的Pkts和Spec列不构成IANA注册管理机制的一部分，参见第22.4节。

终端必须（**MUST**）将收到未知类型的帧视为FRAME_ENCODING_ERROR类型的连接错误。

在此QUIC版本中，所有的帧都是幂等的。也就是说，多次接收相同的有效帧不应触发不良效果或报错。

Frame Type字段使用变长整数编码（第16章），但有一个前提。为确保帧解析实现的简单有效，帧类型必须（**MUST**）使用尽可能短的编码。对于本文中定义的帧类型，这意味着使用单字节编码，即使可以将这些值编码为两字节、四字节或八字节的变长整数。例如，尽管0x4001也是值为1的变长整数的合法两字节编码，但PING帧只能编码为值为0x01的单个字节。此规则适用于所有当前和未来的QUIC帧类型。终端接收到将帧类型编码为比实际所需更长字节的帧，可以（**MAY**）视为PROTOCOL_VIOLATION类型的连接错误。

## 12.5. 帧和包号空间（Frames and Number Spaces）

某些帧在其他的数据包空间中是被禁止的。这里的规则概括了TLS的规则，与连接建立相关的帧，通常可以出现在任何包号空间的数据包中，而与传输数据相关的那些只能出现在应用包号空间中：

* PADDING、PING和CRYPTO帧可以（**MAY**）出现在任何包号空间中。
* CONNECTION_CLOSE指示QUIC层错误（类型0x1c）可以（**MAY**）出现在任何包号空间中。CONNECTION_CLOSE指示应用错误（类型0x1d）必须（**MUST**）只出现在应用包号空间中。
* ACK帧可以（**MAY**）出现在任何包号空间中，但只能确认出现在该包号空间中的数据包。但是，如下所述的0-RTT包不能包含ACK帧。
* 所有其他帧类型必须（**MUST**）仅在应用包号空间中发送。

请注意，由于各种原因，无法在0-RTT包中发送以下帧：ACK、CRYPTO、HANDSHAKE_DONE、NEW_TOKEN、PATH_RESPONSE或RETIRE_CONNECTION_ID。服务端可以（**MAY**）将在0-RTT包中收到这些帧视为PROTOCOL_VIOLATION类型的连接错误。

# 13. 组包与可靠性（Packetization and Reliability）

发送方可在一个QUIC包中发送一个或多个帧，参见第12.4节。

发送方可以通过在每个QUIC包中，包含尽可能多的帧来最小化每个数据包的带宽和计算成本。发送方可以（**MAY**）等待一小段时间来收集多个帧，然后再打包发送一个大的但未超限的数据包，以避免发送大量小数据包。实现可以（**MAY**）收集应用发送行为规律或先验知识来确定是否等待以及等待多长时间。这个等待时间由实现决定，实现应谨慎地考虑这个时间，因为任何迟滞都可能增加应用可见的时延。

流复用是通过将来自多个流的STREAM帧交织成一个或多个QUIC包来实现的。单个QUIC包可以包含来自一个或多个流的多个STREAM帧。

QUIC的好处之一是避免跨多个流的队头阻塞。当发生数据包丢失时，只有在该数据包中有数据的流才会被阻塞，等待接收重传，而其他流可以继续前进。请注意，当来自多个流的数据包含在单个QUIC包中时，该数据包的丢失会阻止所有这些流的前进。建议实现在出向数据包中包含尽可能少的流，但也尽量不要因为大量padding而降低传输效率。

## 13.1. 数据包处理（Packet Processing）

在成功解密并处理完数据包内所有帧之前，不得（**MUST NOT**）回数据包确认ACK。对于STREAM帧，"处理完"意味着数据已经入队以备应用层协议接收，但不意味着已经投递给应用或应用已经消费数据。

一旦数据包被完全处理，接收端通过发送一个或多个包含已接收包号的ACK帧来确认接收。

如果终端收到对其未发送数据包的确认ACK，应该（**SHOULD**）将其视为PROTOCOL_VIOLATION类型的连接错误。有关如何实现这一点的进一步讨论，请参见第21.4节。

## 13.2. 生成确认ACK（Generating Acknowledgments）

终端需要确认它们接收和处理的所有数据包。然而，只有ACK触发包（ACK触发）会导致在ACK发送窗口期内发送ACK帧。非ACK触发包仅在因其他原因发送ACK帧时才被确认。

在无论因为什么原因需要发送数据包时，如果最近没有发过包，终端应该（**SHOULD**）尝试包含一个ACK帧。这样做有助于对端及时检测是否丢包。

通常，来自接收端的频繁确认会改善丢包和拥塞情况，但如果接收端对每个ACK触发包都回以ACK的话就太过了。必须考虑平衡这种过度负载，下面提供的指引旨在实现这种平衡。

### 13.2.1. 发送ACK帧（Sending ACK Frames）

每个数据包应该（**SHOULD**）至少被确认一次，并且必须（**MUST**）在终端用max_ack_delay传输参数通告的窗口期内至少确认一次ACK触发包，参见第18.2节。max_ack_delay声明了一个明确的约定：终端承诺会在max_ack_delay超时之前发送ACK帧确认ACK触发包。否则，RTT的估值会无谓放大，并可能导致对端错误的超时重传。发送方使用接收方通告的max_ack_delay值来确定基于定时器的超时重传，如[QUIC-RECOVERY]第6.2节所述。

终端必须（**MUST**）立即确认所有Initial和Handshake触发包，以及在通告的max_ack_delay内确认所有0-RTT和1-RTT触发包，以下情况除外：在握手确认之前，终端可能没有可用的秘钥在收到Handshake、0-RTT或1-RTT包时对其解密。因此，它可能会先缓存它们并在密钥可用时再确认它们。

由于仅包含ACK帧的数据包不受拥塞控制，因此终端在收到一个ACK触发包时不得（**MUST NOT**）发送多个这种包。

终端不得（**MUST NOT**）发送非ACK触发包来响应非ACK触发包，即使收到的包号不连续。这可以避免乒乓确认死循环，虽然其可以避免因为连接空闲导致的断链。只有当终端发送ACK帧以响应其他事件时，才可以确认非ACK触发包。

仅发送ACK帧的终端将不会收到来自其对端的确认ACK，除非这些确认包含在ACK触发包内。当有新的ACK触发包要确认时，ACK帧可以与其他帧一起发送。当只需要确认非ACK触发包时，终端可以（**MAY**）选择不发送ACK帧，直到收到ACK触发包需要发送ACK帧为止。

仅发送非ACK触发包的终端可能会选择偶尔向这些数据包内添加ACK触发帧，以保证能收到ACK。但在第13.2.4小节这种场景下，终端不得（**MUST NOT**）在非ACK触发包内插入ACK触发帧，否则会导致乒乓确认死循环。

为了帮助发送方进行丢包检测，终端应该（**SHOULD**）在接收到ACK触发包时立即生成并发送一个ACK帧：
* 当收到的数据包的编号小于另一个已收到的ACK触发包时；
* 当数据包的编号大于已接收到的最高编号的ACK触发包，并且编号不连续时；

类似地，在收到IP报头中标有ECN Congestion Experienced(CE)码点的数据包时应该（**SHOULD**）立即确认，以减少对端对拥塞事件的响应时间。

[QUIC-RECOVERY]中的算法需要对不遵循上述指引的接收端具有弹性。然而，只有在仔细考虑变更对终端和网络其他用户的连接的性能影响后，实现才可以不考虑这些要求。

### 13.2.2. 确认包频率（Acknowledgment Frequency）
接收端决定响应ACK触发包的ACK的发送频率。这个频率需要权衡考量。

终端依靠及时的ACK来检测丢包，参见[QUIC-RECOVERY]第6章。基于窗口的拥塞控制器，参见[QUIC-RECOVERY]第7章中描述的控制器，依靠ACK来管理它们的拥塞窗口。在这两种情况下，延迟确认都会对性能产生不利影响。

另一方面，减少仅携带ACK的数据包的频率会降低两端数据包传输和处理成本。它可以改善严重不对称链路上的连接吞吐量，并使用返回路径容量以减少确认流量，参见[RFC3449]第3章。

接收方应该（**SHOULD**）在收到至少两个ACK触发包后才发送一个ACK帧。该建议本质上是通用的，与TCP的ACK建议策略也是一致的，参见[RFC5681]。对网络条件、对端的拥塞控制器等的先验知识和进一步的研究和实验，可能会有更好的确认机制选择方案以提升性能。

接收方可以（**MAY**）考虑处理多少个可用数据包之后再发送ACK响应帧。

### 13.2.3. 管理ACKRanges（Managing ACK Ranges）

ACK帧内包括一个或多个ACK Ranges确认接收数据包。包含对旧数据包的确认可以减少由于前序ACK帧丢失导致的不当重传的可能，但代价是ACK帧会更大。

ACK帧应该（**SHOULD**）总是确认最近收到的数据包，并且数据包越是乱序，更快发送更新的ACK帧就越重要，以防止对端认为数据包丢失并不当重传它包含的帧。一个ACK帧应完整放入一个QUIC包，放不进去的话，则忽略较老的Ranges（具有更小包号的Ranges ）。

接收方需要限制其在ACK帧中发送的ACK Ranges的数量（第19.3.1小节），以降低ACK帧的大小并避免资源耗尽。在收到对ACK帧的确认后，接收方应该（**SHOULD**）停止跟踪那些确认的ACK Ranges。发送方可以预期能收到大多数数据包的确认，但QUIC不保证能收到接收方对其处理的每个数据包的确认。

携带多个ACK Ranges可能会导致ACK帧变得太大而无法装入数据包，接收方可以丢弃部分未确认的ACK Ranges以限制ACK帧的大小，其代价是发送方的重传次数增加，但这是必要的。接收方还可以（**MAY**）进一步限制ACK帧的大小或限制ACK帧的容量占比以腾出其他帧的空间。

接收方必须（**MUST**）保留某个ACK Range，除非其可以确保随后不会接受具有该Range范围内编号的数据包。维护一个随着Ranges丢弃而增加的最小包号，可以最小状态实现这一目标。

接收方可以丢弃所有的ACK Ranges，但必须（**MUST**）维护已成功处理的最大包号，因为它用于从后续数据包中恢复包号，参见第17.1节。

接收方在每个ACK帧中都应该（**SHOULD**）包含一个ACK Range，该Range包含最大接收包号。Largest Acknowledged字段用于发送方ECN验证，如果该值比前序ACK帧中的值要小的话可能导致ECN被不必要地禁用，参见第13.4.2小节。

第13.4.2小节给出了决定需要在ACK帧中确认哪些数据包的示例性方法。尽管此算法的目标是为每个处理的数据包生成确认，但也适用于确认丢失的情况。

### 13.2.4. 通过跟踪ACK帧来限制Ranges（Limiting Ranges by Tracking ACK Frames）

当发送包含ACK帧的数据包时，可以保存该帧中的Largest Acknowledged字段。当包含此ACK帧的数据包被确认时，接收方可以停止确认小于或等于此帧中的Largest Acknowledged字段的数据包。

仅发送非ACK触发数据包（例如ACK帧）的接收方可能在很长一段时间内都不会收到确认。这可能会导致接收方长时间维护大量ACK帧的状态，且在组帧时ACK帧可能会过大。在这种情况下，接收方可以偶尔发送PING帧或其他小的ACK触发帧，例如每个RTT一次，以触发对端回ACK。

在没有ACK帧丢失的情况下，该算法容忍至少1个RTT的乱序。在ACK帧丢失和乱序的情况下，这种方法不能保证在某些ACK Ranges移出ACK帧之前，发送方能看到它。数据包可能会被乱序接收，并且对他们进行确认的所有ACK帧都可能丢失。在这种情况下，丢包恢复算法可能会导致不当重传，但发送方的处理会继续。

### 13.2.5. 测量和报告主机延迟（Measuring and Reporting Host Delay）

接收方可以测量从接收到最大包号的数据包到发送ACK之间主动引入的延迟，并在ACK帧的ACK Delay字段中对此延迟时间进行编码，参见第19.3节。这使得此ACK帧的接收方可以依据此延迟，对路径RTT估计进行更精确的调整。

数据包在被处理之前可能会保存在操作系统内核或主机上的其他地方，当在ACK帧中填充ACK Delay字段时，终端不得（**MUST NOT**）包括它无法控制的延迟。然而，终端应该（**SHOULD**）将解密密钥不可用引起的缓冲延迟计算在内，因为这些延迟可能很大并且很可能是不可复现的。

当测量的确认延迟大于其max_ack_delay时，终端应该（**SHOULD**）上报测量延迟。在延迟可能很大时，此信息在握手期间特别有用，参见第13.2.1小节。

### 13.2.6. ACK帧和数据包保护（ACK Frames and Packet Protection）

ACK帧必须（**MUST**）只在与被确认的数据包具有相同包号空间的数据包中携带，参见第12.1节。例如，使用1-RTT密钥保护的数据包必须（**MUST**）在同样使用1-RTT密钥保护的数据包中确认。

客户端使用0-RTT包保护发送的数据包必须（**MUST**）由服务端在由1-RTT密钥保护的数据包中确认。这可能意味着如果服务端加密握手消息延迟或丢失，客户端将无法使用这些确认。请注意，同样的限制适用于受1-RTT密钥保护的服务端发送的其他数据。

### 13.2.7. PADDING帧消耗拥塞窗口（PADDING Frames Consume Congestion Window）

在数据包中包含PADDING帧是出于拥塞控制的目的，参见[QUIC-RECOVERY]。但仅包含PADDING帧的数据包只会消耗拥塞窗口，却不会生成ACK移动或扩大窗口。为避免死锁，发送方应该（**SHOULD**）确保定期发送PADDING帧之外的其他帧以触发接收方的确认。

## 13.3. 信息重传（Retransmission of Information）

确定丢失的QUIC包不需要全部重传。这同样适用于包含在丢失数据包中的帧，在新的帧中可根据需要再次发送在丢失帧中携带的信息。

新的帧和数据包用于重传确定已丢失的信息。通常，当确定包含该信息的数据包丢失时将再次发送信息，并在包含该信息的数据包被确认时停止发送。

* CRYPTO帧：在CRYPTO帧中发送的数据根据[QUIC-RECOVERY]中的规则进行重传，直到所有数据都得到确认。当相应包号空间的密钥被丢弃时，Initial和Handshake包的CRYPTO帧中的数据也将被丢弃。

* STREAM帧：除非终端在该流上发送了RESET_STREAM，否则在STREAM帧中发送的应用数据将在新的STREAM帧中进行重传。一旦终端发送RESET_STREAM帧，就不再发送其他STREAM帧。

* ACK帧：ACK帧携带最近的一组确认和Largest Acknowledged包的确认延迟，如第13.2.1小节所述。包含ACK帧的数据包的传输延迟或旧的ACK帧重传可能会导致对端计算出较大的RTT或不必要地禁用ECN。

* RESET_STREAM帧：携带流传输取消信息的RESET_STREAM帧，会一直发送直到被确认或所有流数据都被对端确认（即流的发送侧达到Reset Recvd或Data Recvd状态）。RESET_STREAM帧的内容在重传时不得（**MUST NOT**）更改。

* STOP_SENDING帧：类似地，携带取消流传输STOP_SENDING帧，也会一直发送，直到流的接收侧进入Data Recvd或Reset Recvd状态，参见第3.5节。

* CONNECTION_CLOSE帧：携带连接关闭信号的CONNECTION_CLOSE帧，被检测到丢包时，不需要重传，如何重发这些信号参见第10章。

* MAX_DATA帧：MAX_DATA帧携带连接最大可发数据量信息。如果包含最近发送的MAX_DATA帧的数据包被声明丢失或当终端决定更新其值时，则需要在MAX_DATA帧中发送更新后的值。需要小心避免过于频繁地发送此帧，因为这会导致该值的频繁更新，并发送大量不必要的MAX_DATA帧，参见第4.2节。

* MAX_STREAM_DATA帧：MAX_STREAM_DATA帧中携带当前最大流数据偏移量。与MAX_DATA一样，当包含流的最新MAX_STREAM_DATA帧的数据包丢失或需要更新该值时，将发送更新后的值，注意防止帧发送过于频繁。当流的接收部分进入Size Known 或Reset Recvd状态时，终端应该（**SHOULD**）停止发送MAX_STREAM_DATA帧。

* MAX_STREAMS帧：MAX_STREAMS帧中携带给定类型的流个数的限制。与MAX_DATA一样，当最新包含MAX_STREAMS的数据包被声明丢失或值更新时，将发送更新的值，注意防止帧发送过于频繁。

* DATA_BLOCKED、STREAM_DATA_BLOCKED和STREAMS_BLOCKED帧：这几类帧承载阻塞信号。DATA_BLOCKED帧具有连接范围，STREAM_DATA_BLOCKED帧具有流范围，而STREAMS_BLOCKED帧的范围限定为特定的流类型。如果上述某个范围中包含最近帧的数据包丢失，则发送新帧。BLOCKED帧仅当终端因为相应限制被阻塞时才发送，这些帧总是包含导致阻塞的限制原因。

* PATH_CHALLENGE帧：定期发送PATH_CHALLENGE帧以执行活性或路径验证检查，直到接收到匹配的PATH_RESPONSE帧或不再需要活性或路径验证检查。PATH_CHALLENGE帧每次发送时都需包含不同的负载。

* PATH_RESPONSE帧：PATH_RESPONSE帧对路径验证的响应只发送一次。对端应根据需要发送更多PATH_CHALLENGE帧以唤起相应的PATH_RESPONSE帧。

* NEW_CONNECTION_ID帧：新的CID在NEW_CONNECTION_ID帧中发送，如果包含它们的数据包丢失，则需要重传，重传帧携带相同的序列号值。同样，停用的CID在RETIRE_CONNECTION_ID帧中发送，如果包含它们的数据包丢失，则进行重传。

* NEW_TOKEN帧：如果包含NEW_TOKEN帧的数据包丢失，则重传它们。除了直接比较帧内容之外，不需要别的手段处理乱序或重复的NEW_TOKEN帧。

* PING和PADDING帧：PING和PADDING帧不包含任何信息，因此丢失的PING或PADDING帧不需要恢复。

* HANDSHAKE_DONE帧：HANDSHAKE_DONE帧丢包必须（**MUST**）重传，直到它被确认为止。

终端应该（**SHOULD**）优先重传数据而不是发送新数据，除非应用指定的优先级另有说明，参见第2.3节。

尽管鼓励发送方在每次发送数据包时组合包含最新信息的帧，但不禁止重传丢失包中包含的帧副本。重传丢失帧的发送方需要考虑因为包号长度、CID长度和路径MTU的变化而导致的可用负载大小的变化。接收方必须（**MUST**）接受包含过时帧的数据包，例如MAX_DATA帧携带的最大数据值小于旧数据包中的最大数据值。

一旦数据包被确认，发送方应该（**SHOULD**）避免重传来自该数据包的信息，包括在在网络乱序的情况下声明丢失后又被确认的数据包。这样做要求发送方在声明丢失后仍然保留有关数据包的信息。发送方可以在其容忍乱序的时限到期后丢弃此信息，例如PTO（[QUIC-RECOVERY]第6.2节），或基于其他事件，例如达到内存限制。

在检测到丢包时，发送方必须（**MUST**）采取适当的拥塞控制措施。[QUIC-RECOVERY]中描述了丢包检测和拥塞控制的细节。

## 13.4. 显式拥塞通知（Explicit Congestion Notification）

QUIC终端可以使用ECN[RFC3168] 来检测和响应网络拥塞。ECN允许终端在IP数据包的ECN字段中设置支持ECN的传输(ECT)码点。然后，网络节点可以通过在ECN字段中设置ECN-CE码点而不是丢弃数据包来指示拥塞[RFC8087]。如[QUIC-RECOVERY]中所述，终端通过降低其发送速率来响应报告的拥塞。

要启用ECN，QUIC发送端首先确定路径是否支持ECN标记以及对端是否报告接收到的IP标头中的ECN值，参见第13.4.2小节。

### 13.4.1. 报告ECN计数（Reporting ECN Counts）

使用ECN需要接收端从IP数据包中读取ECN字段，这在所有平台上都是不可能的。如果终端不支持ECN或无权访问接收到的ECN字段，它不会报告它接收到的数据包的ECN计数。

即使终端没有在它发送的数据包中设置ECT字段，如果可行的话，终端也必须（**MUST**）提供有关它收到的ECN标记的反馈。未能报告ECN计数将导致发送方在此连接禁用ECN。

在接收到带有ECT(0)、ECT(1)或ECN-CE码点的IP数据包时，启用ECN的终端访问ECN字段并增加相应的ECT(0)、ECT(1)或ECN-CE记数。后续的ACK帧中可携带这些ECN计数，参见第13.2节和第19.3节。

每个包号空间维护单独的确认状态和单独的ECN计数。合并的QUIC包（参见第12.2节）共享相同的IP报头，因此对于其中的每个QUIC包，ECN计数都需要增加一次。

例如，如果Initial、Handshake和1-RTT QUIC包合并为单个UDP报文，则所有三个包号空间的ECN计数都需要加1。

ECN计数仅在处理承载在IP报文中的QUIC包时增加。重复的QUIC包不会被处理，也就不会增加ECN计数。有关安全问题的考虑，请参阅第21.10节。

### 13.4.2. ECN验证（ECN Validation）

有故障的网络设备可能会损坏或错误地丢弃携带非零ECN码点的数据包。因为此类设备的存在，终端为了确保连接性，将验证每条网络路径的ECN计数，并在检测到错误时禁用该路径上的ECN。

要对新路径执行ECN验证：

终端在通过新路径发往对端的早期出向数据包的IP标头中设置ECT(0) 码点[RFC8311]。

终端监控所有带有ECT码点的数据包是否最终都被视为丢失（参见[QUIC-RECOVERY]第6章），此现象表明ECN验证失败。

如果终端有理由预期带有ECT码点的IP数据包可能会被故障网元丢弃，则终端可以仅为路径上前十个出向数据包设置ECT码点，或仅在三个PTO的时间段设置ECT码点（参见[QUIC-RECOVERY]第6.2节。如果所有标有非零ECN码点的数据包随后丢失，则可以假设是因为标记导致的丢失，需要禁用标记。

因此，在切换到服务端的首选地址或将活动连接迁移到新路径时，终端尝试为每个新连接使用ECN验证。Appendix A.4描述了一种可能的算法。

其他探测路径是否支持ECN的方法也是可行的，可以采取不同的标记策略。实现可以（**MAY**）使用RFC中定义的其他方法，参见[RFC8311]。使用ECT(1) 码点的实现需要使用报告的ECT(1)计数执行ECN验证。

#### 13.4.2.1. 接收带有ECN计数的ACK帧（Receiving ACK Frames with ECN Counts）
网络错误应用ECN-CE标记会导致连接性能的下降。因此，接收带有ECN计数的ACK帧的终端，会在使用计数之前验证这些计数。它通过将新接收的计数与上次成功处理的ACK帧的计数进行比较，来执行此验证。对ECN计数的任何增加是否正常的验证，都是基于ACK帧中新确认的数据包的ECN标记。

如果ACK帧新确认了终端发送的带有ECT(0)或ECT(1)码点集的数据包，如果相应的ECN计数不存在于ACK帧中，则ECN验证失败。这种检查将探测把ECN字段置零的网元或不报告ECN标记的对端。

如果ECT(0)或ECN-CE计数增加的总和小于最初使用ECT(0)标记发送的新确认数据包的数量，则ECN验证也会失败。类似地，如果ECT(1)或ECN-CE计数增加的总和小于使用ECT(1)标记发送的新确认数据包的数量，则ECN也验证失败。这些检查可以检测网络对ECN-CE标记的重新标记。

当ACK帧丢失时，终端可能会错过对数据包的确认。因此，ECT(0)、ECT(1)和ECN-CE计数的总增加可能大于ACK帧新确认的数据包数量。这就是为什么允许ECN计数大于已确认的数据包总数的原因。

从乱序的ACK帧验证ECN计数可能会导致失败。终端不得（**MUST NOT**）因处理到未增加Largest Acknowledged包数的ACK帧而判定ECN验证失败。

如果ECT(0)或ECT(1)的接收总数超过每个相应ECT码点发送的数据包总数，则ECN验证可能会失败。特别是，当终端收到来自从未应用的ECT码点对应的非零ECN计数时，验证将失败。此检查检测数据包何时在网络中被标记为ECT(0)或ECT(1)。

#### 13.4.2.2. ECN验证结果（ECN Validation Outcomes）

如果验证失败，则终端必须（**MUST**）禁用ECN。终端将停止在其发送的IP数据包中设置ECT码点，并假设网络路径或对端不支持ECN。

即使验证失败，终端也可以（**MAY**）在连接中的任何稍后时间重新验证相同路径的ECN。终端可以继续定期尝试验证ECN。

成功验证后，终端可以（**MAY**）继续在它发送的后续数据包中设置ECT码点，并期望该路径具有ECN能力。网络路由和路径元素可以改变中间连接，如果稍后验证失败，终端必须（**MUST**）禁用ECN。

# 14. 报文大小（Datagram Size）

一个UDP报文可以包含一个或多个QUIC包。报文大小是指携带QUIC包的单个UDP报文的负载大小。报文大小包括一个或多个QUIC包头和受保护的负载长度，但不包括UDP或IP头。

最大报文大小定义为可以使用单个UDP报文跨网络路径传输的最大UDP负载大小。如果网络路径不支持至少1200字节的最大报文大小，则不得（**MUST NOT**）使用QUIC。

QUIC假设最小IP报文大小至少为1280字节。这是IPv6最小大小[IPv6]，大多数现代IPv4网络也支持。假设IPv6的最小IP报头大小为40字节，IPv4为20字节，UDP报头大小为8字节，这将导致IPv6的最大报文大小为1232字节，IPv4为1252字节。因此，现代IPv4和所有IPv6网络路径都有望支持QUIC。

> 注意：如果路径仅支持1280字节的IPv6最小MTU，则此支持1200字节UDP负载的要求会将IPv6扩展标头的可用空间限制为32字节或IPv4选项的可用空间为52字节。这会影响Initial包和路径验证。

任何大于1200字节的最大报文大小都可以使用路径最大传输单元发现 (PMTUD)（参见第14.2.1小节)）或报文分组层PMTU发现（DPLPMTUD）（参见第14.3节）来发现。

使用max_udp_payload_size传输参数（第18.2节）可以对最大报文大小附加强制限制。一旦知道该值，发送方就可以避免超过此限制。但在此之前，如果终端发送的报文大于1200字节的最小允许最大报文大小，则它们可能会出现丢包。

UDP报文绝不得（**MUST NOT**）在IP层分片。在IPv4[IPv4]中，如果可能，必须（**MUST**）设置Don't Fragment(DF)位，以防止在路径上分片。

QUIC有时要求报文不小于一定大小，参见第8.1节的示例。但是，报文的大小没有经过验证。也就是说，如果一个终端接收到一个特定大小的报文，它无法知道其是否与发送方发送的报文大小相同。因此，当终端收到不满足大小限制的报文时，它不得（**MUST NOT**）关闭连接，终端可以（**MAY**）丢弃这样的报文。

## 14.1. 初始报文大小（Initial Datagram Size）

客户端必须（**MUST**）将所有承载Initial包的UDP报文负载扩展到至少1200字节的最小允许最大报文大小，这可以通过将PADDING帧添加到Initial包或合并Initial包实现，参见第12.2节。Initial包甚至可以与无效数据包合并，接收端可以丢弃无效数据包。类似地，服务端必须（**MUST**）将所有携带ACK触发Initial包的UDP报文负载扩展到至少1200字节的最小允许最大报文大小。

发送这种大小的UDP报文可确保网络路径在两个方向上都支持合理的路径最大传输单元 (PMTU)。此外，扩展Initial包的客户端有助于减少由服务端响应未经验证的客户端地址引起的放大攻击的幅度，参见第8章。

如果发送方认为网络路径和对端都支持它选择的大小，则包含Initial包的报文可以（**MAY**）超过1200字节。

如果UDP报文负载小于1200字节的最小允许最大报文大小，服务端必须（**MUST**）丢弃在UDP报文中携带的Initial包。服务端也可以（**MAY**）通过发送一个错误码为PROTOCOL_VIOLATION的CONNECTION_CLOSE帧来立即关闭连接，参见第10.2.3小节。

服务端还必须（**MUST**）在验证客户端地址之前限制它发送的字节数，参见第8章。

## 14.2. 路径最大传输单元（Path Maximum Transmission Unit）

PMTU是整个IP数据包的最大大小，包括IP报头、UDP报头和UDP负载。UDP负载包括一个或多个QUIC包头和受保护的负载。PMTU可以取决于路径特性，因此可以随时间变化。终端在任何给定时间发送的最大UDP负载称为终端的最大报文大小。

终端应该（**SHOULD**）使用DPLPMTUD（第14.3节）或PMTUD（第14.2.1小节）来确定到目的地的路径是否支持所需的最大报文大小而不会分片。在没有这些机制的情况下，QUIC终端不应该（**SHOULD NOT**）发送大于最小允许最大报文大小的报文。

DPLPMTUD和PMTUD都发送大于当前最大报文大小的报文，称为PMTU探测。未在PMTU探测中发送的所有QUIC包应该（**SHOULD**）调整大小以适应最大报文大小，以避免报文被分段或丢弃[RFC8085]。

如果QUIC终端确定任何一对本地和远程IP地址之间的PMTU不支持1200字节的最小允许最大报文大小，则它必须（**MUST**）在受影响的路径上立即停止发送QUIC包，除了那些在PMTU探测中的数据包或包含CONNECTION_CLOSE帧的数据包。如果找不到替代路径，终端可以（**MAY**）终止连接。

每对本地和远程地址对可以有不同的PMTU。因此，实现任何类型PMTU发现的QUIC实现应该（**SHOULD**）为本地和远程IP地址的每个组合维护最大报文大小。

QUIC实现在计算最大报文大小时可以（**MAY**）更加保守，以允许未知的隧道开销或IP报头选项/扩展。

### 14.2.1. PMTUD处理ICMP消息（Handling of ICMP Messages by PMTUD）

PMTUD[RFC1191][RFC8201] 的计算依赖于ICMP消息（也就是IPv6 Packet Too Big(PTB)消息）的接收，该消息指示IP数据包何时因为其大于本地路由器MTU被丢弃。DPLPMTUD也可以选择使用这类消息。ICMP消息的这种用法可能容易受到某些实体的攻击，这类实体可能无法观察到数据包但能成功猜测路径上使用的地址。这些攻击可能会将PMTU降低到使带宽低效的值。

终端必须（**MUST**）忽略声称PMTU已减小到低于QUIC允许的最小报文大小的ICMP消息。

[RFC1812][RFC4443]协议对ICMP的生成有要求，其引用的数据包应包含尽可能多的原数据包，且不会超过IP版本的最小MTU。引用的数据包实际上可能小一些，或者信息难以理解，如[DPLPMTUD]第1.1节。

使用PMTUD的QUIC终端应该（**SHOULD**）验证ICMP消息，以防止在[RFC8201]和[RFC8085]第5.2节指出的数据包注入。此验证应该（**SHOULD**）将ICMP消息负载中的引用数据包或相应的传输层连接的消息相关联（参见[DPLPMTUD]第4.6.1小节）。ICMP消息验证必须（**MUST**）包括匹配的IP地址和UDP端口[RFC8085]，并在可能的情况下，包括QUIC活动会话的CID。终端应该（**SHOULD**）忽略所有验证失败的ICMP消息。

终端不得（**MUST NOT**）根据ICMP消息增加PMTU，参见[DPLPMTUD]第3章的第6项。在QUIC的丢包检测算法判定引用的数据包确实丢失之前，任何响应ICMP消息减少QUIC最大报文大小的措施都可以（**MAY**）是暂时性的。

## 14.3. 报文分组层PMTU发现（Datagram Packetization Layer PMTU Discovery）

DPLPMTUD[DPLPMTUD]实现依赖于跟踪PMTU探测中携带的QUIC包的丢失或确认。使用PADDING帧的DPLPMTUD的PMTU探测实现“使用填充数据进行探测”，如[DPLPMTUD]第4.1节中所定义。

终端应该（**SHOULD**）将BASE_PLPMTU的初始值（[DPLPMTUD]第5.1节）设置为与QUIC最小允许的最大报文大小一致。MIN_PLPMTU与BASE_PLPMTU相同。

实现DPLPMTUD的QUIC终端为本地和远程IP地址的每种组合维护一个DPLPMTUD最大数据包大小 (MPS)（[DPLPMTUD]第4.4节）。这与UDP最大报文大小对应。

### 14.3.1. DPLPMTUD和Initial连接（DPLPMTUD and Initial Connectivity）

从DPLPMTUD的角度来看，QUIC是公认的分组层 (Packetization Layer，PL)。因此，当QUIC连接握手完成时，QUIC发送方可以进入DPLPMTUDBASE状态（[DPLPMTUD]第5.2节）。

### 14.3.2. 使用DPLPMTUD验证网络路径（Validating the Network Path with DPLPMTUD）

QUIC是公认的PL，因此，QUIC发送方在SEARCH_COMPLETE状态下不会实现DPLPMTUD的CONFIRMATION_TIMER，参见[DPLPMTUD]第5.2节。

### 14.3.3. DPLPMTUD处理ICMP消息（Handling of ICMP Messages by DPLPMTUD）

使用DPLPMTUD的终端需要在使用PTB信息之前验证任何接收到的ICMP PTB消息，如[DPLPMTUD]第4.6节中所定义。除了UDP端口验证之外，QUIC还可以通过其他PL信息来验证ICMP消息（例如，验证任何收到的ICMP消息的引用数据包中的CID）。

如果DPLPMTUD用到这些消息，则第14.2.1小节中描述的处理ICMP消息的注意事项也适用。

## 14.4. 发送QUIC（PMTU探测 Sending QUIC PMTU Probes）

PMTU探测是发送ACK触发包。

终端可以将PMTU探测的内容限制为PING和PADDING帧，因为大于当前最大报文大小的数据包更有可能被网络丢弃。因此，PMTU探测中携带的QUIC包丢失不是拥塞的可靠指示，不应该（**SHOULD**）触发拥塞控制反应，参见[DPLPMTUD]第3章的第7项。但是，PMTU探测会消耗拥塞窗口，这可能会延迟应用的后续传输。

### 14.4.1. 包含SCID的PMTU探测（PMTU Probes Containing Source Connection ID）

依赖DCID字段来路由入向QUIC包的终端可能需要在PMTU探测中包含CID，以将任何产生的ICMP消息（第14.2.1小节）路由回正确的终端。然而，只有长包头数据包（第17.2节）包含SCID字段，并且一旦握手完成，长包头数据包不会被对端解密或确认。

构建PMTU探测的一种方法是在单个UDP报文中合并（参见第12.2节）具有长包头的数据包（例如握手或0-RTT包（第17.2节））和短包头数据包。如果PMTU探测到达终端，带有长包头的数据包被忽略，但短包头数据包将被确认。如果PMTU探测触发ICMP消息，则ICMP消息将引用该探测的前面部分，如果SCID字段在其中，则可用于路由或验证ICMP消息。

> 注意：使用长报文头的目的只是为了保证ICMP报文中引用的报文包含一个SCID字段。这个数据包不需要是一个有效的数据包，即使当前没有使用该类型的数据包，它也可以被发送。

# 15. 版本号（Versions）
QUIC版本使用32位无符号整数标识。

版本0x00000000保留用于表示版本协商。此版本的规约标识为编号0x00000001。

其他版本的QUIC可能与此版本具有不同的属性。在[QUIC-INVARIANTS]中描述了保证在所有版本的协议中保持一致的QUIC属性。

QUIC的0x00000001版本使用TLS作为加密握手协议，如[QUIC-TLS]中所述。

版本号最高16位置零的版本保留用于未来的IETF协议文件。

遵循模式0x?a?a?a?a的版本是保留标识（即所有字节的低四位为1010（二进制）的任何版本号），用于强制执行版本协商。客户端或服务端可以（**MAY**）宣称支持这些保留版本中的任意一个。

保留的版本号永远不会表示真正的协议。客户端可以（**MAY**）使用这些版本号之一，寄望服务端启动版本协商；服务端也可以（**MAY**）宣称对这些版本之一的支持，寄望于客户端忽略该值。

# 16. 变长整数编码（Variable-Length Integer Encoding）

QUIC包和帧通常对非负整数值使用变长编码。这种编码确保较小的整数可以使用更少的字节来编码。¶

QUIC变长整数编码保留第一个字节的最高两位，其值为n表示编码的整数长度为2的n次方。整数值按网络字节序在剩余位上编码。

这意味着整数可以编码为1,2,4,8字节，其值分别不超过6-，14-，30-，62位大小。表4列举了这几种编码属性：

| 2MSB | Length | Usable Bits | Range                 |
|:---|:---|:---|:---|
| 00   | 1      | 6           | 0-63                  |
| 01   | 2      | 14          | 0-16383               |
| 10   | 4      | 30          | 0-1073741823          |
| 11   | 8      | 62          | 0-4611686018427387903 |

表4: Summary of Integer Encodings

在附录Appendix A.1有编码算法和应用示例。

除了Frame Type字段外，其余值不需要以所需的最小字节数进行编码，参见第12.4节。

版本号（第15章），报头中的包号（第17.1节）和长包头中的CID长度（第17.2节）是整数但不需要使用此编码。

# 17. 数据包格式（Packet Formats）

以下约定所有数值都以网络字节序（即大端）编码，所有字段大小均以位为单位。十六进制表示法用于表示字段的值。

## 17.1. 包号编解码（Packet Number Encoding and Decoding）

包号（以下简称“包号”）是从0到2^62^-1（第12.3节）范围内的整数。当出现在长或短包头中时，其被编码为1到4个字节。通过仅编码包号的最少有效位，可以减少其占用的空间位数。

编码后的包号受到加密保护，如[QUIC-TLS]第5.4节。

在收到对包号空间的确认之前，数据包内必须（**MUST**）包括完整包号，它不能被截断，如下所述。

在收到某个包号空间的确认ACK后，发送方必须（**MUST**）确定一个包号长度，该包号长度需要能够表示最大已确认包号与当前包号两者差值的两倍以上范围内的数值。对端收到以后应能正确解码该包号，除非其在传输过程中有延迟，导致它在很多更大编号的数据包之后到达。终端应该（**SHOULD**）使用足够大的包号进行编码，使得即使数据包在后发数据包之后到达，也可以恢复包号。

因此，包号编码的大小应至少比包括新包在内的连续未确认包的数量的以2为基的对数多一位。Appendix A.2中有伪代码和包号编码示例。

在接收方处需要先移除数据包保护，再依据其有效位的数量、这些位的值以及在成功验证的数据包中接收到的最大包号来重建完整包号。恢复完整的包号才算是成功完成数据包保护移除。

一旦移除了包头保护，解码之后的包号为最接近预期包号的值。预期包号是接收到的最高包号加一。Appendix A.3中有伪代码和包号解码的示例。

## 17.2. 长包头数据包（Long Header Packets）

```
   Long Header Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2),
     Type-Specific Bits (4),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..160),
     Source Connection ID Length (8),
     Source Connection ID (0..160),
     Type-Specific Payload (..),
   }
```
图13: Long Header Packet Format

长包头数据包是在确立1-RTT密钥之前收发的数据包。一旦1-RTT密钥可用，发送方就会切换到使用短包头发送数据包（第17.3节）。长包头形式可使得特殊数据包——例如Version Negotiation包——以这种统一的固定长度数据包的格式来表示。使用长包头的数据包包含以下字段：

* Header Form：头类型，对于长包头，字节0（第一个字节）的最高有效位(0x80)设置为1。
* Fixed Bit：固定位，字节0的下一位(0x40)一般设置为1，设为0的话，除了Version Negotiation包之外，其他情况都不是有效数据包，必须（**MUST**）丢弃。该位的值为1允许QUIC与其他协议复用，参见[RFC7983]。
* Long Packet Type：长报文类型，字节0的下两位（掩码为0x30）表示数据包类型。数据包类型在表5中列出。
* Type-Specific Bits：类型相关位，字节0的低四位（掩码为0x0f）的语义由数据包类型决定。
* Version ：版本号，QUIC版本是字节0之后的32位字段。此字段指示正在使用的QUIC版本并确定如何解释其余协议字段。
* Destination Connection ID Length：DCID长度，Version之后的一个字节表示随后的DCID字段的字节长度。此长度编码为8位无符号整数。在QUIC版本1中，该值不得（**MUST NOT**）超过20个字节。收到值大于20的版本1长包头的终端必须（**MUST**）丢弃该数据包，但为了正确构造Version Negotiation包，服务端也应该（**SHOULD**）支持其他版本的QUIC协议有更长的CID。
* Destination Connection ID：目的连接ID（DCID），Destination Connection ID紧跟Destination Connection ID Length字段。第7.2节更详细地描述了该字段的使用方式。
* Source Connection ID Length：SCID长度，DCID之后的一个字节表示其后的SCID字段的字节长度。此长度编码为8位无符号整数。在QUIC版本1中，该值不得（**MUST NOT**）超过20个字节。收到值大于20的版本1长包头的终端必须（**MUST**）丢弃该数据包，但为了正确构造Version Negotiation包，服务端也应该（**SHOULD**）支持其他版本的QUIC协议有更长的CID。
* Source Connection ID：源连接ID（SCID），SCID字段紧跟Source Connection ID Length字段。第7.2节更详细地描述了该字段的使用方式。
* Type-Specific Payload：类型相关负载，数据包的其余部分（如果有）与Long Packet Type指定的类型有关。

在此QUIC版本中，定义了以下带有长包头的数据包类型：

| Type | Name      | Section        |
| :--- | :---      | :---           |
|0x0| Initial   | Section 17.2.2 |
|0x1| 0-RTT     | Section 17.2.3 |
|0x2| Handshake | Section 17.2.4 |
|0x3| Retry     | Section 17.2.5 |

表5: Long Header Packet Types

长包头数据包的长报文类型、DCID和SCID长度、DCID和SCID字段以及版本字段与版本无关。第一个字节中的其他字段是特定于版本的。关于来自不同QUIC版本的数据包如何解释，请参阅[QUIC-INVARIANTS]。

部分字段和负载的解释特定于版本和数据包类型。关于此版本的特定于类型的语义在以下其他章节中会有描述，下面介绍此QUIC版本中的几个长包头数据包中都包含的附加字段：

* Reserved Bits：保留位，多个类型的长包头数据包中字节0有两个保留位（掩码为0x0c），这些位都使用包头保护策略来保护，参见[QUIC-TLS]第5.4节。保护之前其值必须（**MUST**）设置为0。终端在移除数据包保护和包头保护后，接收到的这些位具有非零值的数据包必须（**MUST**）视为PROTOCOL_VIOLATION类型的连接错误。仅在去除包头保护后丢弃此类数据包会使终端暴露于攻击，参见[QUIC-TLS]第9.5节。

* Packet Number Length：包号长度，在包含Packet Number字段的数据包类型中，字节0的最低两个有效位（掩码为0x03）表示Packet Number字段的长度，编码为无符号的两位整数，比Packet Number字段的长度（以字节为单位）小1，即Packet Number字段的长度是该字段的值加一。这些位使用包头保护来保护，参见[QUIC-TLS]第5.4节。

* Length：长度，这是数据包剩余部分的长度（即Packet Number和Packet Payload字段），以字节为单位，编码为变长整数（第16章）。

* Packet Number：包号，该字段的长度为1到4个字节。包号采用包头保护，参见[QUIC-TLS]第5.4节。 Packet Number字段的长度编码在字节0的Packet Number Length位中，如上所述。

* Packet Payload：包负载，这是数据包的有效载荷——包含一系列帧——使用数据包保护策略进行保护。

### 17.2.1. 版本协商包（Version Negotiation Packet）

Version Negotiation包本质上不是特定于版本的。客户端收到后，将Version字段值为0的数据包识别为Version Negotiation包。

Version Negotiation包仅由服务端发送，是在收到不支持版本的客户端数据包时回的响应。

Version Negotiation包的格式是：

```
   Version Negotiation Packet {
     Header Form (1) = 1,
     Unused (7),
     Version (32) = 0,
     Destination Connection ID Length (8),
     Destination Connection ID (0..2040),
     Source Connection ID Length (8),
     Source Connection ID (0..2040),
     Supported Version (32) ...,
   }
```
图14: Version Negotiation Packet

服务端可设置Unused字段为任意值，客户端必须（**MUST**）忽略该字段的值。在QUIC可能与其他协议复用的情况下（参见[RFC7983]），服务端应该（**SHOULD**）将此字段的最高有效位(0x40)设置为1，以便Version Negotiation包看起来具有如上所述的固定位（Fixed Bit）字段。请注意，其他版本的QUIC可能不会遵循类似的建议。

Version Negotiation包的版本字段必须（**MUST**）设置为0x00000000。

服务端必须（**MUST**）将DCID字段设置为其接收到的数据包的SCID字段的值。SCID的值必须（**MUST**）从接收到的数据包的DCID的值复制而来，它最初是由客户端随机选择的。回显两个CID为客户端提供了一些证明，即服务端收到了数据包，并且Version Negotiation包不是由没有收到Initial包的实体生成的。

未来版本的QUIC可能对CID的长度有不同的要求。特别是，CID可能具有较小的最小长度或较大的最大长度。因此，CID的版本相关规则不得（**MUST NOT**）影响关于是否发送Version Negotiation包的决定。

Version Negotiation包的其余部分是服务端支持的版本列表，每个版本号都是32位的。

Version Negotiation包不需要确认。它仅在响应指示不支持版本的数据包时发送，参见第5.2.2小节。

Version Negotiation包不包含包号和包长字段，不过在长包头格式的其他数据包中是存在的。Version Negotiation包会消耗整个UDP报文。

服务端不得（**MUST NOT**）发送多个Version Negotiation包以响应单个UDP报文。

有关版本协商过程的描述，请参见第6章。

### 17.2.2. Initial包（Initial Packet）

Initial包使用类型值为0x00的长包头。它携带客户端和服务端发送的第一个CRYPTO帧以执行密钥交换，双向都可携带ACK帧。
```
Initial Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}
```
图15: Initial Packet

Initial包包含一个长包头，内含长度或包号等字段，参见第17.2节。第一个字节包含保留位和包号长度位，也参见第17.2节。在SCID和Length字段之间，有两个额外的字段是Initial包特有的：

* Token Length：令牌长度，变长整数，指定Token字段的长度，以字节为单位。如果不存在Token，则此值为0。服务端发送的Initial包必须（**MUST**）将Token Length字段置为0。客户端收到具有非零Token Length字段的Initial包，必须（**MUST**）要么丢弃该数据包，要么回以类型为PROTOCOL_VIOLATION的连接错误。

* Token ：令牌，先前在Retry包或NEW_TOKEN帧中提供的令牌值，参见第8.1节。

为了防止被版本未知的中间设备篡改，Initial包使用与连接和版本相关的密钥（Initial密钥）保护，如[QUIC-TLS]中所述。这种方式对可以观察数据包的攻击者来说，不能提供机密性或完整性保护，但可以防止无法观察到数据包的攻击者伪装Initial包。

客户端和服务端在发送包含初始加密握手消息的任何数据包时，都采用Initial包类型。这规则适用于需要创建包含初始加密消息的新数据包的所有场景，例如在收到Retry包后须发送数据包时，参见第17.2.5小节。

服务端发送它的第一个Initial包以响应客户端Initial包。服务端可以（**MAY**）发送多个Initial包。加密密钥交换可能需要多次往返或重传。

Initial包的负载包括一个或多个包含了加密握手消息的CRYPTO帧或ACK帧，或者两者都有。0x1c类型的PING、PADDING和CONNECTION_CLOSE帧也是允许的。接收到包含其他帧的Initial包的终端可以将其视为虚假数据包或连接错误。

客户端发送的第一个数据包总是包含一个CRYPTO帧，该帧包含第一个加密握手消息的起始部分或全部。第一个CRYPTO帧总是从偏移量0开始，参见第7章。

请注意，如果服务端发送TLS HelloRetryRequest（参见[QUIC-TLS]第4.7节），则客户端将发送另一系列Initial包。这些Initial包将继续加密握手，并将包含CRYPTO帧，其起始偏移量与Initial包的第一次发送的CRYPTO帧的大小相匹配。

#### 17.2.2.1. 丢弃Initial包（Abandoning Initial Packets）

客户端在发送第一个Handshake包后停止发送和处理Initial包。服务端在收到第一个Handshake包后停止发送和处理Initial包。尽管数据包可能仍在传输中或等待确认，但在此之后无需再交换Initial包。Initial包保护密钥与任何丢包恢复和拥塞控制状态（参见[QUIC-RECOVERY]第6.4节）一起被丢弃（参见[QUIC-TLS]第4.9.1小节）。

当Initial密钥被丢弃时，CRYPTO帧中的任何数据都会被丢弃，并且不再重传。

### 17.2.3. 0-RTT包（0-RTT）

0-RTT包使用类型值为0x01的长包头，后跟Length或Packet Number字段，参见第17.2节。第一个字节包含保留位和包号长度位，参见第17.2节。作为首次传输的一部分，0-RTT包用于将early数据从客户端发往服务端，在Handshake完成之前。作为TLS握手的一部分，服务端可以接受或拒绝此数据。

有关0-RTT数据及其局限性的讨论，请参见[TLS13]第2.3节。

```
0-RTT Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 1,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}
```
图16: 0-RTT Packet

0-RTT保护数据包与1-RTT保护数据包使用相同的包号空间。

客户端收到Retry报文，很可能是0-RTT报文丢失或被服务端丢弃。客户端应该（**SHOULD**）在发送新的Initial包后尝试重新发送0-RTT包中的数据。新数据包必须（**MUST**）使用新的包号，如第17.2.5.3小节所述，重用包号可能会损害数据包保护。

如[QUIC-TLS]第4.1.1小节中所定义，客户端仅在Handshake完成后才接收其0-RTT包的确认。

一旦开始处理来自服务端的1-RTT包，客户端不得（**MUST NOT**）发送0-RTT包。这意味着0-RTT包不能包含对来自1-RTT包的帧的任何响应。例如，客户端不能在0-RTT包中发送ACK帧，因为ACK帧只能确认1-RTT包。1-RTT包的确认必须（**MUST**）在1-RTT包中携带。

服务端应该（**SHOULD**）将违反之前保存的（传输参数）限制的情况（参见第7.4.1小节）视为适当类型的连接错误（例如，超出流控限制的FLOW_CONTROL_ERROR）。

### 17.2.4. Handshake握手包（Handshake Packet）

Handshake包使用类型值为0x02的长包头，后跟Length或Packet Number字段，参见第17.2节。第一个字节包含保留位和包号长度位，参见第17.2节。它用于携带来自服务端和客户端的加密握手消息和确认。
```
Handshake Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 2,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Length (i),
  Packet Number (8..32),
  Packet Payload (8..),
}
```
图17: Handshake Protected Packet

一旦客户端收到来自服务端的Handshake包，它就会使用Handshake包向服务端发送后续的加密握手消息和确认。

Handshake包中的DCID字段包含一个由数据包接收方选择的CID，SCID是数据包的发送方希望对端使用的CID，参见第17.2节。

Handshake包有自己的包号空间，因此服务端发送的第一个Handshake包的包号为0。

此数据包的负载包含CRYPTO帧，也可能包含PING、PADDING或ACK帧。Handshake包可能（**MAY**）包含0x1c类型的CONNECTION_CLOSE帧。终端必须（**MUST**）将接收到其他帧的Handshake包视为PROTOCOL_VIOLATION类型的连接错误。

与Initial包（参见第17.2.2.1小节）一样，当Handshake保护密钥被丢弃时，其中的CRYPTO帧中的数据将被丢弃，并且不再重传。

### 17.2.5. Retry包（Retry Packet）

如图18所示，Retry包使用类型值为0x03的长包头。它携带由服务端生成的地址验证令牌。仅由希望进行重试的服务端使用，参见第8.1节。
```
Retry Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 3,
  Unused (4),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Retry Token (..),
  Retry Integrity Tag (128),
}
```
图18: Retry Packet

Retry包不包含任何受保护的字段。 Unused字段中的值由服务端设置为任意值，客户端必须（**MUST**）忽略它。除了来自长包头的字段外，它还包含以下附加字段：

* Retry Token：重试令牌，服务端可用于验证客户端地址的不透明令牌。

* Retry Integrity Tag：重试完整性标签，在[QUIC-TLS]第5.8节("Retry Packet Integrity") 中定义。

#### 17.2.5.1. 发送Retry包（Sending a Retry Packet）
服务端将客户端Initial包的SCID填入Retry包的DCID字段。

服务端在SCID字段中包含其选择的CID。该值不得（**MUST NOT**）等于客户端发送的数据包的DCID字段。客户端必须（**MUST**）丢弃包含与Initial包的DCID字段相同的SCID字段的Retry包。客户端必须（**MUST**）在它发送的后续数据包的DCID字段中使用Retry包的SCID字段中的值。

服务端可以（**MAY**）发送Retry包以响应Initial和0-RTT包。服务端可以丢弃或缓冲它收到的0-RTT包。服务端可以在接收Initial或0-RTT包时发送多个Retry包。服务端不得（**MUST NOT**）发送多个Retry包以响应单个UDP报文。

#### 17.2.5.2. 处理Retry包（Handling a Retry Packet）
对于每次连接尝试，客户端必须（**MUST**）最多接受和处理一个Retry包。在客户端接收并处理来自服务端的Initial或Retry包后，它必须（**MUST**）丢弃它接收到的任何后续Retry包。

客户端必须（**MUST**）丢弃具有无法验证的重试完整性标签的Retry包，参见[QUIC-TLS]第5.8节。这会削弱攻击者注入Retry包的能力并防止重Retry包意外损坏。客户端必须（**MUST**）丢弃带有零长度Retry Token字段的Retry包。

客户端使用包含提供的重试令牌的Initial包响应Retry包以继续建立连接。

客户端将此Initial包的DCID字段设置为Retry包中SCID字段的值。更改DCID字段还会导致更改用于保护Initial包的密钥。还需要将Token字段设置为Retry包中提供的令牌。客户端不得（**MUST NOT**）更改SCID，因为服务端会将CID作为其令牌验证逻辑的一部分，参见第8.1.4小节。

Retry包不包含包号，客户端无法明确确认。

#### 17.2.5.3. 重试后继续握手（Continuing a Handshake after Retry）
来自客户端的后续Initial包包含来自Retry包的CID和令牌值。客户端将SCID字段从Retry包复制到DCID字段并使用该值，直到收到具有更新值的Initial包，参见第7.2节。 Token字段的值被复制到所有后续的Initial包中，参见第8.1.2小节。

除了更新DCID和Token字段外，客户端发送的Initial包与第一个Initial包受到相同的限制。客户端必须（**MUST**）使用它包含在此数据包中的相同加密握手消息。服务端可以（**MAY**）将包含不同加密握手消息的数据包视为连接错误或丢弃它。请注意，包含Token字段会减少加密握手消息的可用空间，这可能导致客户端需要发送多个Initial包。

客户端可以（**MAY**）通过向服务端提供的CID发送0-RTT包，在收到Retry包后尝试0-RTT。

在处理Retry包后，客户端不得（**MUST NOT**）在任何包号空间重置包号。特别是，0-RTT包包含加密信息，这些信息很可能会在收到Retry包时重新传输。用于保护这些新0-RTT包的密钥不会因响应Retry包而改变。但是，这些数据包中发送的数据可能与之前发送的数据不同。使用相同的包号发送这些新数据包可能会损害这些数据包的数据包保护，因为相同的密钥和随机数可用于保护不同的内容。如果服务端检测到客户端重置了包号，则它可以（**MAY**）中止连接。

在客户端和服务端之间交换的Initial和Retry包中使用的CID需要复制到传输参数中，并按照第7.3节的描述进行验证。

## 17.3. 短包头数据包（Short Header Packets）

此QUIC版本定义了使用短数据包头的单个数据包类型。

### 17.3.1. 1-RTT包（1-RTT Packet）

1-RTT包使用短包头。它在版本协商和1-RTT秘钥协商后使用。

```
1-RTT Packet {
  Header Form (1) = 0,
  Fixed Bit (1) = 1,
  Spin Bit (1),
  Reserved Bits (2),
  Key Phase (1),
  Packet Number Length (2),
  Destination Connection ID (0..160),
  Packet Number (8..32),
  Packet Payload (8..),
}
```
图19: 1-RTT Packet

1-RTT包包含以下字段：

* Header Form：报头格式，对于短包头，字节0的最高有效位 (掩码为0x80) 设置为0。

* Fixed Bit：固定位，字节0的下一位 (掩码为0x40) 设置为1。该位为0的数据包在此版本中不是有效数据包，必须（**MUST**）丢弃。该位的值为1允许QUIC与其他协议复用，请参见[RFC7983]。

* Spin Bit：自旋位，字节0的第三个最高有效位 (掩码为0x20) 是延迟自旋位，按第17.4节所述设置。

* Reserved Bits：保留位，字节0的下两位（掩码为0x18）是保留位。这些位使用包头保护策略来保护，参见[QUIC-TLS]第5.4节。在保护之前其值必须（**MUST**）设置为0。收到数据包且在移除包和包头保护后，这些位为非零值的话，终端必须（**MUST**）将之视为PROTOCOL_VIOLATION类型的连接错误。仅在去除包头保护后丢弃此类数据包会使终端暴露于攻击，参见[QUIC-TLS].的第9.5节。

* Key Phase：秘钥阶段，字节0的下一位 (掩码为0x04) 表示密钥时段，它允许数据包的接收方识别用于保护数据包的密钥。详情参阅[QUIC-TLS]。该位采用包头保护，参见[QUIC-TLS]第5.4节。

* Packet Number Length：包号长度，字节0的最低有效两位（掩码为0x03）表示Packet Number字段的长度，编码为无符号的两位整数，比Packet Number字段的长度（以字节为单位）小1，即Packet Number字段的长度是该字段的值加一。这些位采用包头保护，参见[QUIC-TLS]第5.4节。

* Destination Connection ID：目的连接ID（DCID），DCID是由数据包的预期接收方选择的CID。更多详细信息，请参阅第5.1节。

* Packet Number：包号，长度为1到4个字节。Packet Number字段采用包头保护，参见[QUIC-TLS]第5.4节。Packet Number字段的长度在Packet Number Length字段中编码。有关详细信息，请参阅第17.1节。

* Packet Payload：数据包负载，1-RTT包中始终包含受1-RTT保护的有效载荷。

短包头包的报头格式位和DCID字段与版本无关。其余字段与所选的QUIC版本有关。来自不同QUIC版本的数据包如何解释详细信息，请参阅[QUIC-INVARIANTS]。

## 17.4. 延迟自旋位（Latency Spin Bit）

为1-RTT包定义的延迟自旋位（第17.3.1小节），可以启动整个连接期间从网络路径上的观察点的被动延迟监控。服务端反射收到的旋转值，而客户端在一个RTT后“翻转”它。on-path观察者可以测量两个自旋位翻转事件之间的时间，以估计连接的终端到端RTT。

自旋位仅出现在1-RTT包中，因为可以通过观察握手来测量连接的Initial RTT。因此，在版本协商和连接建立完成后，自旋位即可用。[QUIC-MANAGEABILITY]中进一步讨论了在路径上进行测量和延迟自旋位的使用方式。

自旋位是此版本QUIC的可选（**OPTIONAL**）功能。不支持该特性的终端必须（**MUST**）禁用它，如下所述。

每个终端单方面决定是否启用或禁用连接的自旋位。实现必须（**MUST**）允许客户端和服务端的上层应用全局禁用自旋位或只在每个连接的基础上禁用。即使上层应用没有禁用自旋位，终端也必须（**MUST**）随机选择每16个网络路径中的至少一个，或每16个CID中的一个，禁用自旋位的使用，以确保QUIC连接不启用自旋位在网络上能经常观察到。由于每个终端单方面地禁用自旋位，这可以保证有大约八分之一的网络路径上禁用自旋位信号。

当自旋位被禁用时，终端可以（**MAY**）将自旋位设置为任意值并且必须（**MUST**）忽略任何入向值。建议（**RECOMMENDED**）终端将自旋位设置为随机值，可为每个数据包独立选择或为每个CID独立选择。

如果在连接上启用了自旋位，终端会为每条网络路径维护一个自旋值，并在该路径上发送1-RTT包时将包头中的自旋位设置为当前存储的值。每条网络路径的终端中的自旋值初始化为0。每个终端还记住从其对端看到的每条路径上的最高包号。

当服务端收到一个1-RTT包时，如果服务端从给定网络路径上的看到的客户端的最高包号递增，它将该路径的自旋值设置为收到的数据包中的自旋位。

当客户端收到一个1-RTT包时，如果客户端从给定网络路径上的看到的服务端的最高包号递增，它将该路径的自旋值设置为接收到的数据包中自旋位的翻转值。

当变更该网络路径上使用的CID时，终端会将该网络路径的自旋值重置为0。

# 18. 传输参数编码（Transport Parameter Encoding）

[QUIC-TLS]中定义的quic_transport_parameters扩展的extension_data字段包含QUIC传输参数。它们被编码为一系列传输参数，如图20所示：
```
Transport Parameters {
  Transport Parameter (..) ...,
}
```
图20: Sequence of Transport Parameters

每个传输参数都被编码为一个（标识符、长度、值）三元组，如图21所示：

```
Transport Parameter {
  Transport Parameter ID (i),
  Transport Parameter Length (i),
  Transport Parameter Value (..),
}
```
图21: Transport Parameter Encoding

Transport Parameter Length字段是以字节为单位的Transport Parameter Value字段的长度。

QUIC将传输参数编码为字节流，然后在加密握手时交互。

## 18.1. 保留传输参数（Reserved Transport Parameters）
保留传输参数的ID是具有 31 * N + 27 形式的标识符，其中N为整数，其引入的目的是为了执行忽略未知传输参数的要求。这些传输参数没有语义，可以携带任意值。

## 18.2. 传输参数定义（Transport Parameter Definitions）

本节详细介绍本文中定义的传输参数。

此处列出的许多传输参数都具有整数值。标识为整数的传输参数使用变长整数编码，请参阅第16章。除非另有说明，否则如果传输参数不存在，则其默认值为0。

传输参数定义如下：
* original_destination_connection_id (0x00)：该参数是客户端发送的第一个Initial包中的DCID字段的值，见第7.3节。此传输参数仅由服务端发送。

* max_idle_timeout (0x01)：最大空闲超时时间是一个以毫秒为单位的值，它被编码为一个整数，见（第10.1节）。当两端都忽略此传输参数或指定值为0时，空闲超时被禁用。

* stateless_reset_token (0x02)：无状态重置令牌（Stateless Reset Token）用于验证无状态重置，参见第10.3节。该参数是一个16字节的字符串。该传输参数不得（**MUST NOT**）由客户端发送，只可以（**MAY**）由服务端发送。不发送此传输参数的服务端不能对握手期间协商的CID使用无状态重置（第10.3节）。

* max_udp_payload_size (0x03)：最大UDP负载大小，该参数是一个整数值，用于限制终端愿意接收的UDP负载大小。接收方不太可能处理负载大于此限额的UDP报文。
此参数的默认值是允许的最大UDP负载65527，低于1200的值无效。
此限额确实以与路径MTU相同的方式作为对数据报文大小的附加约束，但它是终端的属性而不是路径，参见第14章。预期这是终端专用于保存入向数据包的空间大小。

* initial_max_data (0x04)：初始最大数据大小，该参数是一个整数值，指示可以在连接上发送的最大数据量（字节数）的初始值。这相当于在完成握手后立即为连接发送一个MAX_DATA（参见第19.9节）。

* initial_max_stream_data_bidi_local (0x05)：此参数是一个整数值，指定本地发起的双向流的初始流控限额。此限额适用于由发送传输参数的终端打开的新创建的双向流。在客户端传输参数中，这适用于标识符的最低有效位设置为0x00的流，在服务端传输参数中，这适用于最低有效位设置为0x01的流。

* initial_max_stream_data_bidi_remote (0x06)：此参数是一个整数值，指定对端发起的双向流的初始流控限额。此限额适用于由接收传输参数的终端打开的新创建的双向流。在客户端传输参数中，这适用于标识符的最低有效位设置为0x01的流，在服务端传输参数中，这适用于最低有效两位设置为0x00的流。

* initial_max_stream_data_uni (0x07)：此参数是一个整数值，指定单向流的初始流控限额。此限额适用于由接收传输参数的终端打开的新创建的单向流。在客户端传输参数中，这适用于标识符的最低有效位设置为0x03的流，在服务端传输参数中，这适用于最低有效两位设置为0x02的流。

* initial_max_streams_bidi (0x08)：初始最大双向流个数，此参数是一个整数值，指示接收此传输参数的终端允许发起的初始最大双向流个数。如果此参数不存在或为零，则在发送MAX_STREAMS帧之前，对端无法打开双向流。设置这个参数相当于发送一个具有相同值的对应类型的MAX_STREAMS（第19.11节）。

* initial_max_streams_uni (0x09)：初始最大单向流个数，此参数是一个整数值，指示接收此传输参数的终端允许发起的初始最大单向流个数。如果此参数不存在或为零，则在发送MAX_STREAMS帧之前，对端无法打开单向流。设置这个参数相当于发送一个具有相同值的对应类型的MAX_STREAMS（第19.11节）。

* ack_delay_exponent (0x0a)：确认延迟指数，此参数是一个整数值，指示用于解码ACK帧中的ACK延迟字段的幂（第19.3节）。如果此值不存在，则假定默认值为3（表示乘数为8），超过20的值无效。

* max_ack_delay (0x0b)：最大确认延迟，此参数是一个整数值，表示终端将延迟发送确认的最长时间（以毫秒为单位）。这个值应该（**SHOULD**）包括接收端告警触发的预期延迟。例如，如果接收端将定时器设置为5毫秒，而告警通常最多延迟1毫秒，则它应该（**SHOULD**）发送6毫秒的max_ack_delay。如果此值不存在，则假定默认值为25毫秒，2^14^或更大的值无效。

* disable_active_migration (0x0c)：如果终端不支持在握手期间正在使用的地址上的主动连接迁移（第9章），则需要设置此参数，禁用主动迁移。接收此传输参数的终端在握手期间在发包给对端时不得（**MUST NOT**）使用新的本地地址。在客户端对preferred_address传输参数进行操作后，可以解禁连接迁移。此参数是零长度值。

* preferred_address（0x0d）：服务端的首选地址，用于在握手结束时影响服务端地址的更改，如第9.6节所述。此传输参数仅由服务端发送。服务端可以（**MAY**）选择只发送一个地址族的首选地址，方法是为另一个地址族发送全零地址和端口（0.0.0.0:0或[::]:0）。IP地址以网络字节序编码。
preferred_address传输参数包含IPv4和IPv6的地址和端口。四字节IPv4 Address字段后跟相关的两字节IPv4 Port字段。后面跟着一个16字节的IPv6 Address字段和两字节的IPv6 Port字段。在地址和端口对之后，Connection ID Length字段指示了随后的CID字段的长度。最后，一个16字节的Stateless Reset Token字段包括与CID关联的无状态重置令牌。此传输参数的格式如下图22所示。
CID字段和Stateless Reset Token字段包含一个序列号为1的替代CID，参见第5.1.1小节。将这些值与preferred_address一起发送可确保在客户端启动到preferred_address的迁移时至少有一个未使用的活动CID。
preferred_address的CID和Stateless Reset Token字段在语法和语义上与NEW_CONNECTION_ID帧（第19.15节）的相应字段相同。选择零长度CID的服务端不得（**MUST NOT**）提供首选地址。类似地，服务端不得（**MUST NOT**）在此传输参数中包含零长度的CID。客户端必须（**MUST**）将违反这些规定的行为视为TRANSPORT_PARAMETER_ERROR类型的连接错误。
```
Preferred Address {
  IPv4 Address (32),
  IPv4 Port (16),
  IPv6 Address (128),
  IPv6 Port (16),
  Connection ID Length (8),
  Connection ID (..),
  Stateless Reset Token (128),
}
```
图22: Preferred Address Format

* active_connection_id_limit (0x0e)：该参数是一个整数值，指示终端愿意存储的来自对端的最大CID个数。该值包括在握手期间收到的CID、在preferred_address传输参数中收到的CID以及在NEW_CONNECTION_ID帧中收到的CID。 active_connection_id_limit参数的值必须（**MUST**）至少为2。收到小于2的值的终端必须（**MUST**）关闭连接，错误类型为TRANSPORT_PARAMETER_ERROR。如果此传输参数不存在，则假定默认值为2。如果终端发出零长度CID，其后永远不会发送NEW_CONNECTION_ID帧，因此会忽略从其对端收到的active_connection_id_limit值。

* initial_source_connection_id (0x0f)：这是终端在连接上发送的第一个Initial包的SCID字段中填写的值，参见第7.3节。

* retry_source_connection_id (0x10)：这是服务端在Retry包的SCID字段填写的值，参见第7.3节。此传输参数仅由服务端发送。

如果初始流控限额（initial_max_stream_data_bidi_local、initial_max_stream_data_bidi_remote或initial_max_stream_data_uni）传输参数存在，则其等效于在打开后立即在相应类型的每个流上发送MAX_STREAM_DATA帧（第19.10节）。如果传输参数不存在，则该类型的流以0的流控限额开始。

客户端不得（**MUST NOT**）包含任何仅服务端适用的传输参数：original_destination_connection_id、preferred_address、retry_source_connection_id或stateless_reset_token。服务端收到上述传输参数，必须（**MUST**）将其视为TRANSPORT_PARAMETER_ERROR类型的连接错误。

# 19. 帧类型和格式（Frame Types and Formats）
如第12.4节所述，数据包包含一个或多个帧。本节描述核心QUIC帧类型的格式和语义。

## 19.1. PADDING帧（PADDING Frames）
PADDING帧（Type=0x00）没有其他语义值。PADDING帧可用于增加数据包的大小。PADDING帧可用于将Initial包填充到所需的最小大小或为受保护数据包提供针对流量分析的保护。

PADDING帧的格式如图23所示，这表明PADDING帧没有内容。即PADDING帧只由将帧标识为PADDING帧的单个字节组成。

```
PADDING Frame {
  Type (i) = 0x00,
}
```
图23: PADDING Frame Format

## 19.2. PING帧（PING Frames）
终端可以使用PING帧（Type=0x01）来验证其对端是否仍然存在或检查对端的可达性。

PING帧的格式如图24所示，这表明PING帧没有内容。

```
PING Frame {
  Type (i) = 0x01,
}
```
图24: PING Frame Format

PING帧的接收方只需要确认包含该帧的数据包。

当应用或应用层协议希望防止连接超时时，PING帧可用于保持连接处于活动状态，参见第10.1.2小节。

## 19.3. ACK帧（ACK Frames）
接收方通过发送ACK帧（Type为0x02和0x03）告知发送方他们已接收和处理数的据包。ACK帧包含一个或多个ACK Range。ACK Range标识已确认的数据包。如果帧类型为0x03，则ACK帧还包含直到此时为止，在连接上接收到的有ECN标记的QUIC包的累积计数。QUIC实现必须（**MUST**）正确处理这两种类型，并且，如果启用了ECN，终端应该（**SHOULD**）使用ECN部分中的信息来管理他们的拥塞状态。

QUIC确认是不可撤销的。一旦确认，数据包将保持确认状态，甚至不会出现在未来的ACK帧中。这与TCP选择性确认 (SACK)[RFC2018]的违例不同。

来自不同包号空间的数据包可以使用相同的包号。对数据包的确认需要指明包号和包号空间。这是通过约定承载ACK帧的数据包，只能与被确认的数据包具有相同包号空间来实现的。

Version Negotiation包和Retry包不需要确认，因为它们不含包号。这些数据包不依赖于ACK帧，而是由客户端发送的下一个Initial包隐式确认。

ACK帧的格式如图25所示。

```
ACK Frame {
  Type (i) = 0x02..0x03,
  Largest Acknowledged (i),
  ACK Delay (i),
  ACK Range Count (i),
  First ACK Range (i),
  ACK Range (..) ...,
  [ECN Counts (..)],
}
```
图25: ACK Frame Format

ACK帧包含以下字段：
* Largest Acknowledged：最大确认包号，变长整数，表示对端确认的最大数据包号，这通常是对端在生成ACK帧之前收到的最大包号。与QUIC长或短包头中的包号不同，ACK帧中的值不会被截断。

* ACK Delay：确认延迟，变长整数，确认延迟以微秒为单位，参见第13.2.5小节。通过将字段中的值乘以2^ack_delay_exponent^来解码，其中ack_delay_exponent是对端约定的传输参数，参见第18.2节。与简单地将延迟表示为整数相比，这种编码允许在相同字节数内使用更大范围的值，但代价是分辨率降低。

* ACK Range Count：ACK Range个数，变长整数，指定帧中ACK Range字段的个数。
* First ACK Range：第一个ACK Range，变长整数，指示在最大确认包号之前收到的连续数据包的个数。也就是说，该范围确认的最小数据包号等于Largest Acknowledged - First ACK Range。

* ACK Range：确认范围，包含额外的未确认(Gap) 数据包个数和确认 (ACK Range)数据包个数，两者交替出现，参见第19.3.1小节。

* ECN Counts：ECN计数，三项ECN计数，参见第19.3.2小节。

### 19.3.1. 确认范围（ACK Range）
每个ACK Range由交替的Gap和ACK Range Length值组成，按包号降序排列。ACK Range可以重复。Gap和ACK Range Length值的总个数由ACK Range Count字段决定，两者分开累加计入ACK Range Count。

ACK Range的结构如图26所示。
```
ACK Range {
  Gap (i),
  ACK Range Length (i),
}
```
图26: ACK Ranges

形成每个ACK Range的字段是：

* Gap：间隔，变长整数，表示在前面Range中最小确认包之前连续未确认的数据包的数量，编码值比实际个数小1。

* ACK Range Length：ACK范围长度，变长整数，表示在前面Gap中最小未确认包之前连续确认的数据包的数量。

Gap和ACK Range Length值使用相对整数编码以提高效率。虽然每个编码值都是正数，但这些值是相减的，因此每个ACK Range表示的包号逐渐降低。

每个ACK Range通过给出该范围中最大包号之前已确认的包数来确认一段连续范围的数据包。值为0表示仅确认最大的包号。ACK Range值越大表示范围越大，相应的，ACK Range值越小表示范围越小。因此，给定范围的最大包号，最小值由以下公式确定：
   smallest = largest - ack_range
ACK Range确认最小包号和最大包号之间的所有数据包。

每个ACK Range的最大值是通过计算减去所有前面的ACK Range Length或Gap的大小来确定的。

每个Gap表示未被确认的数据包范围。Gap中的数据包个数比Gap字段的编码值大1。

Gap字段的值使用以下公式为后续ACK Range确定最大包号值：
   largest = previous_smallest - gap - 2
如果出现计算的包号为负数，终端必须（**MUST**）生成FRAME_ENCODING_ERROR类型的连接错误。

### 19.3.2. ECN计数（ECN Counts）
ACK帧使用类型值（即类型0x03）的最低有效位来表示ECN反馈，并报告QUIC包的IP报头中接收到具有相关ECN码点ECT(0)、ECT(1)或ECN-CE。ECN计数仅在ACK帧类型为0x03时出现。

当ACK帧携带ECN时，共有三个ECN计数，如图27所示：

```
ECN Counts {
  ECT0 Count (i),
  ECT1 Count (i),
  ECN-CE Count (i),
}
```
图27: ECN Count Format

ECN Counts字段有：

* ECT0 Count：ECT0计数，变长整数，表示与ACK帧相同的包号空间中接收到的携带ECT(0) 码点的数据包总数。

* ECT1 Count：ECT1计数，变长整数，表示与ACK帧相同的包号空间中接收到的携带ECT(1) 码点的数据包总数。

* ECT-CE Count：ECN-CE计数，变长整数，表示与ACK帧相同的包号空间中接收到的携带ECN-CE码点的数据包总数。

ECN计数为每个包号空间单独维护。

## 19.4. RESET_STREAM帧（RESET_STREAM Frames）
终端使用RESET_STREAM帧（Type=0x04）立即终止流的发送部分。

发送RESET_STREAM后，终端停止传输和重传已识别流上的STREAM帧。RESET_STREAM的接收方可以丢弃在该流上已接收到的任何数据。

在单向发送流上收到RESET_STREAM帧，终端必须（**MUST**）以STREAM_STATE_ERROR错误码终止连接。

RESET_STREAM帧的格式如图28所示。

```
RESET_STREAM Frame {
  Type (i) = 0x04,
  Stream ID (i),
  Application Protocol Error Code (i),
  Final Size (i),
}
```
图28: RESET_STREAM Frame Format

RESET_STREAM帧包含以下字段：

* Stream ID：流标识，变长整数，表示正在终止的流的流ID。

* Application Protocol Error Code：应用层协议错误码，变长整数，包含应用层协议错误码（参见第20.2节），指示流关闭的原因。

* Final Size：最终大小，变长整数，指示RESET_STREAM发送方的流的最终大小，以字节为单位，参见第4.5节。

## 19.5. STOP_SENDING帧（STOP_SENDING Frames）
终端使用STOP_SENDING帧（Type=0x05）来向发送方传达入向数据被每个应用请求接收时丢弃的信息。STOP_SENDING请求对端停止在该流上发送数据。

可以为处于Recv或Size Known 状态的流发送STOP_SENDING帧，参见第3.2节。在本地发起但尚未完成创建的流上收到STOP_SENDING帧，必须（**MUST**）视为STREAM_STATE_ERROR类型的连接错误。在receive-only流上接收到STOP_SENDING帧的终端必须（**MUST**）以STREAM_STATE_ERROR错误码终止连接。

STOP_SENDING帧的格式如图29所示。

```
STOP_SENDING Frame {
  Type (i) = 0x05,
  Stream ID (i),
  Application Protocol Error Code (i),
}
```
图29: STOP_SENDING Frame Format

STOP_SENDING帧包含以下字段：

* Stream ID：流ID，变长整数，携带被忽略流的流ID的变长整数。
* Application Protocol Error Code：应用层协议错误码，变长整数，包含应用指定的发送方忽略流的原因，参见第20.2节。

## 19.6. CRYPTO帧（CRYPTO Frame）
CRYPTO帧（Type=0x06）用于传输加密握手消息。它可以在除0-RTT之外的所有数据包类型中发送。CRYPTO帧为加密协议提供了一个有序的字节流。CRYPTO帧在功能上与STREAM帧相同，只是其不带流ID，不受流控，不携带可选偏移量、可选长度和流结束标记。

CRYPTO帧的格式如图30所示。

```
CRYPTO Frame {
  Type (i) = 0x06,
  Offset (i),
  Length (i),
  Crypto Data (..),
}
```
图30: CRYPTO Frame Format

CRYPTO帧包含以下字段：

* Offset ：偏移，变长整数，指定此CRYPTO帧中数据在流中的字节偏移量。

* Length：长度，变长整数，指定此CRYPTO帧中加密数据字段的长度。

* Crypto Data：加密数据，加密消息数据负载。

每个加密级别都对应一个单独的加密握手数据流，每个数据流都从偏移量0开始。这意味着每个加密级别都被视为单独的CRYPTO数据流。

流上传输的最大偏移量——偏移量和数据长度的总和——不能超过2^62^-1。收到超过此限制的帧必须（**MUST**）被视为FRAME_ENCODING_ERROR或CRYPTO_BUFFER_EXCEEDED类型的连接错误。

与包含指示数据属于哪个流的流ID的STREAM帧不同，CRYPTO帧携带每个加密级别的单个流的数据。流没有明确的结束，因此CRYPTO帧没有FIN位。

## 19.7. NEW_TOKEN帧（NEW_TOKEN Frames）
服务端发送一个NEW_TOKEN帧（Type=0x07），给客户端提供一个令牌，以便在未来连接发送Initial包时在报文中携带。

NEW_TOKEN帧的格式如图31所示。

```
NEW_TOKEN Frame {
  Type (i) = 0x07,
  Token Length (i),
  Token (..),
}
```
图31: NEW_TOKEN Frame Format

NEW_TOKEN帧包含以下字段：

* Token Length：令牌长度，变长整数，指定令牌的长度，以字节为单位。

* Token ：令牌，客户端在未来发送Initial包携带的未明字符块。令牌不得（**MUST NOT**）为空。客户端在收到带有空Token字段的NEW_TOKEN帧时必须（**MUST**）视为FRAME_ENCODING_ERROR类型的连接错误。

如果包含NEW_TOKEN帧的数据包被错误地认定为丢失，客户端可能会收到多个包含相同令牌值的NEW_TOKEN帧，客户端需要丢弃重复值。NEW_TOKEN帧可用于关联连接尝试，参见第8.1.3小节。

客户端不得（**MUST NOT**）发送NEW_TOKEN帧。服务端收到NEW_TOKEN帧必须（**MUST**）将其视为PROTOCOL_VIOLATION类型的连接错误。

## 19.8. STREAM帧（STREAM Frames）
STREAM帧隐式地创建一个流并携带流数据。STREAM帧中的Type字段采用0b00001XXX形式（或从0x08到0x0f的一组值）。帧类型的三个低位决定了帧中存在的字段：

* 帧类型中的OFF位(0x04)指示是否存在Offset字段。设置为1时，存在Offset字段；设置为0时，Offset字段不存在并且Stream Data从偏移量0开始（即，帧包含流的第一个字节，或数据长度为0的流的末尾）。

* 帧类型中的LEN位(0x02)指示是否存在Length字段。如果该位设置为0，则Length字段不存在并且Stream Data字段扩展到数据包的末尾。如果该位设置为1，则存在Length字段。

* 帧类型中的FIN位(0x01)指示该帧是否标志着流的结束。流的最终大小是偏移量和该帧的长度之和。

如果终端在一个本地发起的尚未创建成功的流或send-only类型的流上收到STREAM帧，它必须（**MUST**）以错误码STREAM_STATE_ERROR终止连接。

STREAM帧的格式如图32所示。

```
STREAM Frame {
  Type (i) = 0x08..0x0f,
  Stream ID (i),
  [Offset (i)],
  [Length (i)],
  Stream Data (..),
}
```
图32: STREAM Frame Format

STREAM帧包含以下字段：

* Stream ID：流标识，变长整数，表示流的流ID，参见第2.1节。

* Offset：偏移，变长整数，指定此STREAM帧中数据在流中的字节偏移量。当OFF位设置为1时，此字段存在。当Offset字段不存在时，偏移量为0。

* Length：长度，变长整数，指定此STREAM帧中Stream Data字段的长度。该字段在LEN位设置为1时出现。当LEN位设置为0时，数据包中的所有剩余字节都是流数据。

* Stream Data：流数据，该流中要传输的字节。

当Stream Data字段的长度为0时，STREAM帧中的Offset是将要发送的下一个字节的偏移量。

流中的第一个字节的偏移量为0。流上可传输的最大偏移量 ——偏移量和数据长度的总和——不能超过2^62^-1，因为无法为这么大量的数据提供流控限额，收到超过此限制的帧必须（**MUST**）被视为FRAME_ENCODING_ERROR或FLOW_CONTROL_ERROR类型的连接错误。

## 19.9. MAX_DATA帧（MAX_DATA Frames）
MAX_DATA帧（Type=0x10）用于流控，以通知对端其可以在整个连接上发送的最大数据量。

MAX_DATA帧的格式如图33所示。
```
MAX_DATA Frame {
  Type (i) = 0x10,
  Maximum Data (i),
}
```
图33: MAX_DATA Frame Format

MAX_DATA帧包含以下字段：

* Maximum Data：最大数据量，变长整数，表示整个连接上可以发送的最大数据量，以字节为单位。

在STREAM帧中发送的所有数据都计入此限制。所有流的最终大小的总和——包括处于终结状态的流 ——不得（**MUST NOT**）超过接收端通告的Maximum Data值。如果终端接收到的数据大于它发送的Maximum Data，则终端必须（**MUST**）以FLOW_CONTROL_ERROR类型的错误终止连接。这也包括违反早期建链过程中保存的传输参数限制，参见第7.4.1小节。

## 19.10. MAX_STREAM_DATA帧（MAX_STREAM_DATA Frames）
MAX_STREAM_DATA帧（Type=0x11）用于流控，以通知对端其可以在该流上发送的最大数据量。

可以为处于Recv状态的流发送MAX_STREAM_DATA帧，参见第3.2节。本地发起但尚未创建成功的流收到MAX_STREAM_DATA帧必须（**MUST**）将其视为STREAM_STATE_ERROR类型的连接错误。接收到receive-only流的MAX_STREAM_DATA帧的终端必须（**MUST**）以错误STREAM_STATE_ERROR终止连接。

MAX_STREAM_DATA帧的格式如图34所示。

```
MAX_STREAM_DATA Frame {
  Type (i) = 0x11,
  Stream ID (i),
  Maximum Stream Data (i),
}
```
图34: MAX_STREAM_DATA Frame Format

MAX_STREAM_DATA帧包含以下字段：

* Stream ID：流标识，变长整数，关联的流的流ID。

* Maximum Stream Data：最大流数据量，变长整数，指示可以在该流上可发送的最大数据量，以字节为单位。

当针对此限制计算数据时，终端应该计算在流上发送或接收的数据的最大接收偏移量。丢包和乱序可能意味着该流上接收到的最大偏移量可能大于在该流上接收到的数据的总大小。收到STREAM帧可能不会增加最大接收偏移。

在流上发送的数据量不得（**MUST NOT**）超过接收端通告的最大流数据量值。如果终端接收到的数据多于它为该流设置的最大流数据量，则终端必须（**MUST**）以FLOW_CONTROL_ERROR类型错误终止连接。这包括违反建链时保存的传输参数，参见第7.4.1小节。

## 19.11. MAX_STREAMS帧（MAX_STREAMS Frames）
MAX_STREAMS帧（Type=0x12或0x13）通知对端其允许打开的给定类型的流的累积个数。类型为0x12的MAX_STREAMS帧适用于双向流，类型为0x13的MAX_STREAMS帧适用于单向流。

MAX_STREAMS帧的格式如图35所示。

```
MAX_STREAMS Frame {
  Type (i) = 0x12..0x13,
  Maximum Streams (i),
}
```
图35: MAX_STREAMS Frame Format

MAX_STREAMS帧包含以下字段：

* Maximum Streams：最大流个数，在连接的生命周期内可以打开的相应类型的流的累积总数。此值不能超过2^60^，因为无法对大于2^62^-1的流ID进行编码。接收到大于此限制的流的帧，必须（**MUST**）将其视为FRAME_ENCODING_ERROR类型的连接错误。

丢包和乱序可能会导致终端接收到一个MAX_STREAMS帧，其流个数限制比之前接收到的要低。必须（**MUST**）忽略这种不增加流个数限制的MAX_STREAMS帧。

终端不得（**MUST NOT**）打开超过其对端设置的当前流个数限制所允许的流。例如，接收单向流个数限制为3的服务端可以打开流3、7或11，但不能打开流15。如果对端打开的流比原来多，则终端必须（**MUST**）以STREAM_LIMIT_ERROR类型的错误终止连接。这也包括违反建链阶段保存的传输参数，参见第7.4.1小节。

请注意，这些帧（以及相应的传输参数）并未指定可以同时打开的流的数量。MAX_STREAMS帧只限制已关闭的流以及打开的流的总数。

## 19.12. DATA_BLOCKED帧（DATA_BLOCKED Frames）
当发送方希望发送数据但由于连接级流控而无法发送时，发送方应该（**SHOULD**）发送DATA_BLOCKED帧（Type=0x14），参见第4章。DATA_BLOCKED帧可用作流控算法调整的输入，参见第4.2节。

DATA_BLOCKED帧的格式如图36所示。

```
DATA_BLOCKED Frame {
  Type (i) = 0x14,
  Maximum Data (i),
}
```
图36: DATA_BLOCKED Frame Format

DATA_BLOCKED帧包含以下字段：

* Maximum Data：最大数据量，变长整数，指示阻塞发生时的连接级别的流量限制值。

## 19.13. STREAM_DATA_BLOCKED帧（STREAM_DATA_BLOCKED Frames）
当发送方希望发送数据但由于流级流控而无法发送时，发送方应该（**SHOULD**）发送STREAM_DATA_BLOCKED帧（Type=0x15）。该帧类似于DATA_BLOCKED（第19.12节）。

在send-only流上接收到STREAM_DATA_BLOCKED帧的终端必须（**MUST**）以错误STREAM_STATE_ERROR终止连接。

STREAM_DATA_BLOCKED帧的格式如图37所示。

```
STREAM_DATA_BLOCKED Frame {
  Type (i) = 0x15,
  Stream ID (i),
  Maximum Stream Data (i),
}
```
图37: STREAM_DATA_BLOCKED Frame Format

STREAM_DATA_BLOCKED帧包含以下字段：

* Stream ID：流标识，变长整数，指示由于流控而阻塞的流的ID。

* Maximum Stream Data：最大流数据量，变长整数，指示发生阻塞时流的偏移量。

## 19.14. STREAMS_BLOCKED帧（STREAMS_BLOCKED Frames）
当发送方希望打开流但由于其对端设置的最大流个数限制而无法打开时，发送方应该（**SHOULD**）发送STREAMS_BLOCKED帧（Type=0x16或0x17），参见第19.11节。类型为0x16的STREAMS_BLOCKED帧用于指示达到双向流限制，类型为0x17的STREAMS_BLOCKED帧用于指示达到单向流限制。

STREAMS_BLOCKED帧不会打开流，但会通知对端需要新的流并且因为流个数限制阻止了流的创建。

STREAMS_BLOCKED帧的格式如图38所示。

```
STREAMS_BLOCKED Frame {
  Type (i) = 0x16..0x17,
  Maximum Streams (i),
}
```
图38: STREAMS_BLOCKED Frame Format

STREAMS_BLOCKED帧包含以下字段：

* Maximum Streams：最大流个数，变长整数，指示发送此帧时允许的最大流个数。此值不能超过2^60^，因为无法对大于2^62^-1的流ID进行编码。接收到大于此限制的流的帧，必须（**MUST**）被其视为STREAM_LIMIT_ERROR或FRAME_ENCODING_ERROR类型的连接错误。

## 19.15. NEW_CONNECTION_ID帧（NEW_CONNECTION_ID Frames）
终端发送一个NEW_CONNECTION_ID帧（Type=0x18）来为其对端提供替代CID，这些CID可用于在迁移连接时打破可关联性，参见第9.5节。

NEW_CONNECTION_ID帧的格式如图39所示。

```
NEW_CONNECTION_ID Frame {
  Type (i) = 0x18,
  Sequence Number (i),
  Retire Prior To (i),
  Length (8),
  Connection ID (8..160),
  Stateless Reset Token (128),
}
```
图39: NEW_CONNECTION_ID Frame Format

NEW_CONNECTION_ID帧包含以下字段：

* Sequence Number：序号，发送方分配给此CID的序号，编码为变长整数，参见第5.1.1小节。

* Retire Prior To：停用此序号之前ID，变长整数，指示应该停用哪些CID，参见第5.1.2小节。

* Length：长度，一个8位无符号整数，表示CID的长度。小于1和大于20的值无效，必须（**MUST**）视为FRAME_ENCODING_ERROR类型的连接错误。

* Connection ID：连接ID（CID），由Length指定长度的CID。

* Stateless Reset Token：无状态重置令牌，一个128位值，当上述关联的CID在使用时，此令牌将用于无状态重置，参见第10.3节。

当前如果终端要求其对端发送具有零长度DCID的数据包，则该终端不得（**MUST NOT**）发送此帧。将CID的长度更改为零长度或变更零长度会导致难以识别到CID的值何时被改变。发送具有零长度DCID的数据包的终端，必须（**MUST**）将收到NEW_CONNECTION_ID帧视为PROTOCOL_VIOLATION类型的连接错误。

传输错误、超时和重传可能会导致多次收到相同的NEW_CONNECTION_ID帧。多次收到同一帧不得（**MUST NOT**）视为连接错误。接收方可以使用NEW_CONNECTION_ID帧中提供的序号来判决多次接收相同的NEW_CONNECTION_ID帧的情况。

如果终端接收到一个NEW_CONNECTION_ID帧，该帧与之前收到的NEW_CONNECTION_ID具有相同的CID，但是具有不同的无状态重置令牌或序号，或者序号相同而CID不同，则终端可以（**MAY**）将该情况视为PROTOCOL_VIOLATION类型的连接错误。

Retire Prior To字段适用于连接建立期间确定的CID和preferred_address传输参数，参见第5.1.2小节。 Retire Prior To字段中的值必须（**MUST**）小于或等于Sequence Number字段的值。接收到Retire Prior To大于Sequence Number的NEW_CONNECTION_ID帧，必须（**MUST**）将其视为FRAME_ENCODING_ERROR类型的连接错误。

一旦发送方表示Retire Prior To值之前的序号停用，在后续NEW_CONNECTION_ID帧中发送的较小的序号值将无效。接收方必须（**MUST**）忽略任何不增加Retire Before To值的NEW_CONNECTION_ID帧。

接收到序号小于先前接收的NEW_CONNECTION_ID帧中Retire Prior To字段的NEW_CONNECTION_ID帧的终端，必须（**MUST**）发送相应的RETIRE_CONNECTION_ID帧，该帧停用新接收的CID，除非它已经停用了该CID对应的序号。

## 19.16. RETIRE_CONNECTION_ID帧（RETIRE_CONNECTION_ID Frames）
终端发送RETIRE_CONNECTION_ID帧（Type=0x19）以指示它将不再使用由其对端发布的指定CID。这包括握手期间提供的CID。发送RETIRE_CONNECTION_ID帧也可以作为一个请求，请求对端发送额外CID以备将来使用，参见第5.1节。可以使用NEW_CONNECTION_ID帧（第19.15节）将新的CID传递给对端。

停用CID会使与此CID关联的无状态重置令牌失效。

RETIRE_CONNECTION_ID帧的格式如图40所示。

```
RETIRE_CONNECTION_ID Frame {
  Type (i) = 0x19,
  Sequence Number (i),
}
```
图40: RETIRE_CONNECTION_ID Frame Format

RETIRE_CONNECTION_ID帧包含以下字段：

* Sequence Number：序号，被停用的CID的序号，参见第5.1.2小节。

收到包含序号大于之前发送的所有CID的序号的RETIRE_CONNECTION_ID帧，必须（**MUST**）将其视为PROTOCOL_VIOLATION类型的连接错误。

在RETIRE_CONNECTION_ID帧中指定的序号不得（**MUST**）引用包含该帧的数据包的DCID。对端可以（**MAY**）将此视为PROTOCOL_VIOLATION类型的连接错误。

如果终端为它的对端提供了一个零长度的CID，它就不能发送这个帧。提供零长度CID的终端必须（**MUST**）将收到RETIRE_CONNECTION_ID帧视为PROTOCOL_VIOLATION类型的连接错误。

## 19.17. PATH_CHALLENGE帧（PATH_CHALLENGE Frames）
终端可以使用PATH_CHALLENGE帧（Type=0x1a）来检查对端的可达性以及用于连接迁移期间的路径验证。

PATH_CHALLENGE帧的格式如图41所示。

```
PATH_CHALLENGE Frame {
  Type (i) = 0x1a,
  Data (64),
}
```
图41: PATH_CHALLENGE Frame Format

PATH_CHALLENGE帧包含以下字段：

* Data ：数据，这个8字节字段可以包含任意数据。

在PATH_CHALLENGE帧中包含64位熵可确保接收到此数据的第三方猜测不出正确值。

此帧的接收方必须（**MUST**）生成包含相同Data值的PATH_RESPONSE帧（第19.18节）。

## 19.18. PATH_RESPONSE帧（ PATH_RESPONSE Frames）
发送PATH_RESPONSE帧（Type=0x1b）以响应PATH_CHALLENGE帧。

PATH_RESPONSE帧的格式如图42所示。PATH_RESPONSE帧的格式与PATH_CHALLENGE帧的格式相同，参见第19.17节。

```
PATH_RESPONSE Frame {
  Type (i) = 0x1b,
  Data (64),
}
```
图42: PATH_RESPONSE Frame Format

如果PATH_RESPONSE帧的Data与终端先前发送的PATH_CHALLENGE帧的Data不匹配，终端可以（**MAY**）生成PROTOCOL_VIOLATION类型的连接错误。

## 19.19. CONNECTION_CLOSE帧（CONNECTION_CLOSE Frames）
终端发送CONNECTION_CLOSE帧（Type=0x1c或0x1d）以通知其对端连接正在关闭。类型为0x1c的CONNECTION_CLOSE帧仅用于在QUIC层发出错误信号，或者无错误关闭（使用NO_ERROR码）。类型为0x1d的CONNECTION_CLOSE帧用于向使用QUIC的应用发出错误信号。

如果存在尚未显式关闭的打开流，则在连接关闭时它们会被隐式关闭。

CONNECTION_CLOSE帧的格式如图43所示。

```
CONNECTION_CLOSE Frame {
  Type (i) = 0x1c..0x1d,
  Error Code (i),
  [Frame Type (i)],
  Reason Phrase Length (i),
  Reason Phrase (..),
}
```
图43: CONNECTION_CLOSE Frame Format

CONNECTION_CLOSE帧包含以下字段：

* Error Code：错误码，变长整数，指示关闭此连接的原因。0x1c类型的CONNECTION_CLOSE帧使用来自第20.1节空间中定义的代码。0x1d类型的CONNECTION_CLOSE帧使用应用层协议定义的代码，参见第20.2节。

* Frame Type：帧类型，变长整数，编码触发此错误的帧类型。当帧类型未知时，使用值0（相当于引用PADDING帧）。与应用有关的CONNECTION_CLOSE（类型0x1d）不包括此字段。

* Reason Phrase Length：原因短语长度，变长整数，以字节为单位，指定原因短语的长度。由于CONNECTION_CLOSE帧不能拆分到不同数据包，因此对数据包大小的任何限制也会限制原因短语的可用空间。

* Reason Phrase：原因短语，连接关闭的附加诊断信息。如果发送方选择不提供除了错误码之外的详细信息，则长度可以为零。这应该（**SHOULD**）是一个UTF-8编码的字符串[RFC3629]，就算此帧不携带信息，例如语言标签之类，这也有助于创建文本的实体之外的其他实体的理解。

应用有关的CONNECTION_CLOSE（类型0x1d）帧只能使用0-RTT或1-RTT包发送，参见第12.5节。当应用希望在握手期间放弃连接时，终端可以在Initial或Handshake包中发送带有APPLICATION_ERROR错误码的CONNECTION_CLOSE帧（类型0x1c）。

## 19.20. HANDSHAKE_DONE帧（HANDSHAKE_DONE Frames）
服务端使用HANDSHAKE_DONE帧（Type=0x1e）向客户端发出握手确认信号。

HANDSHAKE_DONE帧的格式如图44所示，这表明HANDSHAKE_DONE帧没有内容。

```
HANDSHAKE_DONE Frame {
  Type (i) = 0x1e,
}
```
图44: HANDSHAKE_DONE Frame Format

HANDSHAKE_DONE帧只能由服务端发送。服务端在完成握手之前不得（**MUST NOT**）发送HANDSHAKE_DONE帧。服务端必须（**MUST**）将收到HANDSHAKE_DONE帧视为PROTOCOL_VIOLATION类型的连接错误。

## 19.21. 扩展帧（Extension Frames）
QUIC帧不使用自解释编码。因此，终端在成功处理数据包之前需要了解所有帧的语法。这允许对帧进行有效编码，但这意味着终端无法发送其对端未知类型的帧。

希望使用自定义帧的QUIC扩展必须（**MUST**）首先确保对端能够理解该帧。终端可以使用传输参数来表示它愿意接收的扩展帧的类型。一个传输参数可以指示对一种或多种扩展帧类型的支持。

除非明确定义了组合的行为，否则修改或替换核心协议功能（包括帧类型）的扩展将难以与其他修改或替换相同功能的扩展相结合。这样的扩展应该（**SHOULD**）定义它们与先前定义的扩展的之间的交互，修改相同的协议组件。

扩展帧必须（**MUST**）是受拥塞控制的，并且必须（**MUST**）触发一个ACK帧响应。替代或补充ACK帧的扩展帧除外。除非在扩展中指定，否则扩展帧不受流控限制。

IANA注册中心用于管理帧类型的分配，参见第22.4节。

# 20. 错误码（Error Codes）

QUIC的传输层错误码和应用层错误码是62位无符号整数。

## 20.1. 传输层错误码（Transport Error Codes）

本节列出了定义的QUIC传输层错误码，这些错误码可以在CONNECTION_CLOSE帧中使用，类型为0x1c。这些错误适用于整个连接。

* NO_ERROR (0x00)：终端将此与CONNECTION_CLOSE一起使用，以表示在没有任何错误的情况下即时关闭连接。

* INTERNAL_ERROR(0x01)：终端遇到内部错误，无法继续连接。

* CONNECTION_REFUSED (0x02)：服务端拒绝接受新连接。

* FLOW_CONTROL_ERROR (0x03)：终端接收到的数据多于其公布的流控限额中允许的数据，参见第4章。

* STREAM_LIMIT_ERROR (0x04)：终端接收到携带某个流标识的帧，这个流标识超过了其通告的对应的流类型的流数限制。

* STREAM_STATE_ERROR (0x05)：终端收到了某个流的帧，但该流所处状态不支持发送该帧，参见第3章。

* FINAL_SIZE_ERROR (0x06)：(1) 终端收到一个包含超过先前确定的final size的数据的STREAM帧，(2)终端收到一个包含final size小于已接收的流数据大小的STREAM帧或RESET_STREAM帧，(3) 终端收到一个STREAM帧或一个RESET_STREAM帧，其中包含与已确定的final size不同的final size。

* FRAME_ENCODING_ERROR (0x07)：终端接收到格式错误的帧——例如，未知类型的帧或确认范围大于数据包其余部分所能承载大小的ACK帧。

* TRANSPORT_PARAMETER_ERROR (0x08)：终端接收到格式错误、包含无效值、遗漏强制传输参数、包含禁止传输参数或其他错误的传输参数。

* CONNECTION_ID_LIMIT_ERROR (0x09)：对端提供的CID数量超过了通告的active_connection_id_limit。

* PROTOCOL_VIOLATION (0x0a)：终端检测到一个协议合规性错误，该错误类型不能用更具体的错误码表示。

* INVALID_TOKEN（0x0b）：服务端收到包含INVALID_TOKEN字段的客户端Initial包。

* APPLICATION_ERROR (0x0c)：应用或应用层协议错误导致连接关闭。

* CRYPTO_BUFFER_EXCEEDED (0x0d)：终端在CRYPTO帧中接收到的数据多于它可以缓冲的数据。

* KEY_UPDATE_ERROR (0x0e)：终端在执行密钥更新时检测到错误，参见[QUIC-TLS]第6章。

* AEAD_LIMIT_REACHED (0x0f)：终端已达到给定连接使用的AEAD算法的机密性或完整性限制。

* NO_VIABLE_PATH (0x10)：终端已确定网络路径无法支持QUIC。除非路径不支持足够大的MTU，否则终端不太可能收到携带此错误码的CONNECTION_CLOSE帧。

* CRYPTO_ERROR (0x0100-0x01ff)：加密握手失败。QUIC保留256个值用于携带特定于所使用的加密握手的错误码。[QUIC-TLS]第4.8节列举了使用TLS进行加密握手时发生的错误码。

有关注册新错误码的详细信息，请参阅第22.5节。

在定义这些错误码时，应用了几个原则：

* 可能需要接收方执行特定操作的错误条件被赋予单独的错误码；
* 表示常见情况的错误被赋予特定错误码；
* 错误码还将用于表示通用功能，如流量控制或传输参数处理时的错误。
* 最后提供通用错误码供实现在无法或不愿意使用更具体错误码的情况下使用。

## 20.2. 应用层协议错误码（Application Protocol Error Codes）

应用层错误码的管理留给应用层协议。RESET_STREAM帧（第19.4节）、STOP_SENDING帧（第19.5节）和类型为0x1d的CONNECTION_CLOSE帧（第19.19节）携带应用层协议错误码。

# 21. 安全考虑（Security Considerations）
QUIC的目标是提供安全的传输层连接。第21.1节概述了这些属性，随后的部分讨论了有关这些属性的限制和注意事项，包括对已知攻击和应对策略的描述。

## 21.1. 安全性概述（Overview of Security Properties）
完整的QUIC安全性分析超出了本文的范围。本节是对所需安全性的非正式描述，以指导实现者进行协议分析。

QUIC采用[SEC-CONS]中描述的威胁模型，并针对该模型的多种攻击提供保护机制。

为此，我们将攻击分为被动攻击和主动攻击。被动攻击者能够从网络读取数据包，而主动攻击者也能够将数据包写入网络。然而，被动攻击可能会让攻击者能够在QUIC连接所处路径中引起路由更改或其他变更。

攻击者还可以分为on-path攻击者或off-path的攻击者。on-path攻击者可以读取、修改或删除它观察到的任何数据包，从而使数据包到达不了其目的地，而off-path的攻击者可以观察到数据包但无法阻止原数据包到达其预定目的地。这两种类型的攻击者也可以发送任意数据包。与[SEC-CONS]第3.5节的定义不同的是，（注：在[SEC-CONS]的定义中，off-path的攻击者只能发包不能收包），off-path的攻击者能够观察数据包。

握手、数据包保护和连接迁移相关安全性是分别考虑的。

### 21.1.1. 握手（Handshake）
QUIC握手结合了TLS1.3握手并继承了[TLS13]的Appendix E.1中描述的加密属性。QUIC的许多安全性取决于提供这些属性的TLS握手。对TLS握手的任何攻击都可能影响QUIC。

任何对TLS握手的攻击，或危及会话密钥的保密性或唯一性，或伤及对端的身份认证，都会影响QUIC提供的依赖于这些密钥的其他安全保证。例如，连接迁移（第9章）取决于机密性保护的有效性，无论是TLS握手的密钥协商还是QUIC包保护，都是为了避免跨网络路径的可链接性。

对TLS握手完整性的攻击可能使得攻击者能够影响应用层协议或QUIC版本的选择。

除了TLS提供的特性外，QUIC握手还提供了一些针对握手的DoS攻击的防御措施。

#### 21.1.1.1. 防放大攻击（Anti-Amplification）
地址验证（第8章）用于验证声明一个给定地址的实体能否在该地址收到数据包。地址验证将Amplification攻击目标限制在攻击者可以观察到的数据包地址。

在地址验证之前，终端能够发送的数据量受到限制。终端向未验证地址发送不能超过接收的三倍。

> 注意：Anti-Amplification限制仅限于终端响应从未经验证的地址收到数据包时。在建立新连接或启动连接迁移时，Anti-Amplification限制不适用于客户端。

#### 21.1.1.2. 服务端DoS攻击（Server-Side DoS）
服务端对一次完整握手的往返数据计算比较费资源，因为需要进行数字签名和密钥交换。为了防止针对服务端计算资源的DoS攻击，Retry包提供了一种低耗的令牌交换机制，使得服务端可以在执行此计算之前验证客户端的IP地址，代价只是一个RTT时间。握手成功后，服务端可以向客户端发出新令牌，使得后续新连接建立的时候可以采用0-RTT。

#### 21.1.1.3. On-Path握手终止攻击（On-Path Handshake Termination）
on-path或off-path的攻击者可以通过替换或加速伪Initial包致使握手失败。因为一旦交换了有效的Initial包，后续的Handshake包就会受到握手密钥的保护，on-path攻击者除了通过丢弃数据包使得终端放弃尝试之外，无法以其他方式强制握手失败。

on-path攻击者还可以替换任一端的数据包地址，从而使其弄错对端地址。这种攻击与NAT导致的结果没有区别。

#### 21.1.1.4. 参数协商攻击（Parameter Negotiation）
整个握手过程都受到加密保护，Initial包使用版本特定的密钥进行加密，Handshake和后续数据包使用从TLS密钥交换派生的密钥进行加密。此外，传输参数的协商被打包到TLS中，提供与普通TLS协商相同的完整性保证。攻击者可以观察到客户端的传输参数（只要它知道版本对应的salt），但无法观察服务端的传输参数，也无法影响传输参数协商。

CID未加密，但在所有数据包中都受到完整性保护。

此QUIC版本没有包含版本协商机制，不兼容版本的实现将无法建立连接。

### 21.1.2. 数据包保护（Protected Packets）
数据包保护（第12.1节）对除Version Negotiation包之外的所有数据包，都进行加密认证，但由于使用特定于版本的密钥材料，对Initial和Retry包的保护受限，更多详细信息请参阅[QUIC-TLS]。本节仅考虑对受保护数据包的被动和主动攻击。

on-path和off-path的攻击者都可以发起被动攻击，在这种攻击中，他们保存观察到的数据包，以便将来针对数据包保护进行离线攻击，这对于任意网络上任意数据包的任意观察者来说都可以做到。

在无法观察到连接的有效数据包的情况下，注入数据包攻击不太可能成功，因为数据包保护确保有效数据包仅由拥有在握手期间商定密钥材料的终端生成，见第7章和第21.1.1小节。类似地，除了Initial包外，任何可观察到数据包，并尝试在这些数据包中插入新数据或修改现有数据的主动攻击者，都不能够生成接收端认为有效的数据包。

在欺骗攻击中，主动攻击者可能篡改其转发或注入的数据包中未受保护的部分，例如源地址或目的地址，这只有当攻击者可以将数据包转发到初始终端时才有效。数据包保护可以确保数据包负载只能由完成握手的终端处理，而无效数据包将被忽略。

攻击者还可以改变QUIC包和UDP报文之间的边界，致使多个QUIC包合并为一个UDP报文或将合并后的QUIC包拆分为多个UDP报文。除了包含Initial包（需要填充）的UDP报文外，修改UDP报文中数据包的排列方式对连接没有功能性影响，但可能会改变一些性能特性。

### 21.1.3. 连接迁移（Connection Migration）
连接迁移（第9章）使得终端能够在不同IP地址和Port端口的多条路径上进行传输切换，每次使用一条路径发送和接收非探测帧。路径验证（第8.2节）确定对端愿意并且能够接收在特定路径上发送的数据包。这有助于通过限制发往欺骗地址的数据包数量来减少地址欺骗的影响。

本节介绍在各种类型的DoS攻击下连接迁移的安全特性。

#### 21.1.3.1. On-Path主动攻击（On-Path Active Attacks）
可以使其观察到的数据包不再到达其预期目的地的攻击者被视为“on-path攻击者”。当客户端和服务端之间存在攻击者时，终端发送的数据包需要通过攻击者，以在给定路径上建立连接。

on-path攻击者可以：

* 观察到数据包
* 修改IP和UDP报文头
* 注入新数据包
* 使数据包延迟
* 使数据包乱序
* 丢弃数据包
* 沿数据包边界拆分和合并报文

on-path攻击者不能：

* 修改数据包的经过认证的部分并使接收方接受该数据包

on-path攻击者有机会修改它观察到的数据包，但是，对数据包经过认证的部分的任何修改，都将导致它被接收端视为无效包丢弃，因为数据包负载需要经过认证和加密。

QUIC旨在限制on-path攻击者的能力，如下所述：

1. on-path攻击者可以阻止两端在其所在路径上建立连接，如果两端不能选择不经过攻击者的其他路径，则可能连接失败。攻击者可以通过丢弃所有数据包、修改使其无法解密或其他方法来实现这个目的。
2. on-path攻击者如果也在新路径上，则可以通过使得新路径验证失败来阻止两端往新路径迁移。
3. on-path攻击者无法阻止客户端迁移到不经过攻击者的其他路径。
4. on-path攻击者可以通过延迟或丢弃数据包来降低连接的吞吐量。
5. on-path攻击者不能迫使终端接受它篡改了认证部分的数据包。

#### 21.1.3.2. Off-Path主动攻击（Off-Path Active Attacks）
off-path攻击者并不直接位于客户端和服务端之间的路径上，但可以获得客户端和服务端之间发送的部分或全部数据包的副本。它还能够将这些数据包的副本发往任一终端。

off-path攻击者可以：

* 观察到数据包
* 注入新数据包
* 乱序注入数据包

off-path攻击者不能：
* 修改终端发送的数据包
* 延迟数据包
* 丢弃数据包
* 使原数据包乱序

off-path攻击者可以修改它观察到的数据包的副本，并将这些副本注入网络，可能具有欺骗性的源地址和目的地址。

出于本次讨论的目的，假设off-path攻击者能够将修改后的数据包副本注入网络，而且该网络可以使副本比原数据包更早到达目的终端。换句话说，攻击者有能力持续“赢得”与终端之间的合法数据包的竞争，从而可能使得接收方忽略原数据包。

此处还假设攻击者拥有影响NAT状态所需的资源。特别是，攻击者可以致使终端丢失其NAT绑定，然后获得相同的终端口以用于其自己的流量。

QUIC旨在限制off-path攻击者的能力，如下所述：

1. off-path攻击者可以竞争数据包并试图成为“受限”的on-path攻击者。
2. off-path攻击者只要能够改善客户端和服务端之间的连接性，就可以使将源地址列为off-path攻击者的转发数据包的路径验证成功。
3. 一旦握手完成，off-path攻击者就不能致使连接关闭。
4. 如果off-path攻击者无法观察到新路径，它就不能致使新路径迁移失败。
5. 在迁移到新路径的过程中，off-path攻击者可能会成为“受限”的on-path攻击者，如果其在新路径也是off-path攻击者。
6. off-path攻击者可以通过影响共享的NAT状态，使其可以用客户端最初使用的同一IP地址和端口向服务端发送数据包，从而成为“受限”的on-path攻击者。

#### 21.1.3.3. “受限”的On-Path主动攻击 （Limited On-Path Active Attacks）
“受限”的on-path攻击者是一种off-path攻击者，它通过在服务端和客户端之间复制和转发原数据包来提供改进的数据包路由，使得这些数据包在原数据包副本之前到达，从而使其被目的端丢弃。

“受限”的on-path攻击者与普通on-path攻击者的区别在于它不在两端之间的初始路径上，因此终端发送的原数据包仍然能到达其目的地。这意味着将来如果无法以比初始路径更快的速度将复制的数据包路由到目的地，将不能阻止原数据包到达目的地。

“受限”的on-path攻击者可以：

* 观察到数据包
* 注入新数据包
* 修改未加密的包头
* 使数据包乱序

“受限”的on-path攻击者不能：

* 延迟数据包，使它们晚于初始路径上发送的数据包到达
* 丢弃数据包
* 修改数据包的认证加密的部分，并使接收方接受该数据包

“受限”的on-path攻击者只能将数据包延迟到原数据包到达之前的时间点，这意味着它无法提供比初始路径更糟糕的路由。如果受限on-path攻击者丢弃数据包，则原数据包副本仍将到达目的终端。

QUIC旨在限制有限的off-path攻击者的能力如下：

1. 一旦握手完成，“受限”的on-path攻击者就不能致使连接关闭。
2. 空闲连接如果客户端首先恢复活动，则“受限”的on-path攻击者无法致使该连接关闭。
3. 空闲连接如果服务端首先恢复活动，则“受限”的on-path攻击者可能会致使该连接被视为丢失状态。

请注意，因为同样的原因，这些保证与为任何NAT提供的保证相同。

## 21.2. 握手拒绝服务（Handshake Denial of Service）
作为提供加密认证的传输层协议，QUIC提供了一系列针对拒绝服务的保护机制。加密握手完成后，QUIC终端会丢弃大多数未经认证的数据包，从而极大地限制了攻击者干扰现有连接的能力。

一旦连接建立，QUIC终端可能会接受一些未经认证的ICMP数据包（参见第14.2.1小节），但这些数据包的使用非常有限。终端唯一能接受的其他类型的数据包是Stateless Reset包（第10.3节），要求其包含的令牌在使用之前一直保密。

在创建连接的过程中，QUIC仅提供针对off-path攻击的保护。所有的QUIC包都包含了证据，证明其收到了来自对端的上一包。

地址在握手期间不能更改，因此终端可以丢弃在不同网络路径上收到的数据包。

SCID和DCID字段是在握手期间防止off-path攻击的主要手段，见第8.1节。这些需要与对端通告的CID相匹配。除了Initial包和Stateless Reset包，终端只接受包含与终端先前选择的值对应的DCID字段的数据包。这是为Version Negotiation包提供的唯一保护。

客户端选择的Initial包中的DCID字段是不可预测的，这是有原因的。携带加密握手的数据包受从该CID派生的密钥和特定于QUIC版本的salt保护。这使得终端在加密握手完成后可用相同的过程来验证它们接收到的数据包。无法认证的数据包将被丢弃。以这种方式为数据包保护提供了强有力的保证，即数据包的发送方收到了Initial包并能理解它。

对于能够在连接建立之前接收QUIC包的攻击者，这些保护措施并不是有效的。这些攻击者可能发送能被QUIC终端接受的数据包。此QUIC版本尝试检测此类攻击，但可预期的是终端将无法建立连接而不是恢复。在大多数情况下，加密握手协议[QUIC-TLS]负责检测握手期间是否被篡改。

允许终端使用其他方法来检测并尝试从握手干扰中恢复。终端可以使用其他方法来识别和丢弃无效的数据包，但本文中不做强制约定。

## 21.3. 放大攻击（Amplification Attack）
攻击者可能能够从服务端接收到地址验证令牌（第8章），然后释放它用于获取该令牌的IP地址。稍后，攻击者可以通过伪装成相同地址来启动与服务端的0-RTT连接，该地址现在可能指向一个不同的（受害者）终端。因此，攻击者可能会导致服务端向受害者发送初始拥塞窗口允许的数据。

服务端应该（**SHOULD**）通过限制地址验证令牌的使用和生命周期来缓解这种攻击，见第8.1.3小节。

## 21.4. Optimistic ACK攻击（Optimistic ACK Attack）
终端确认它没有接收到的数据包可能会导致拥塞控制器允许以超出网络支持的速率发包。终端可以（**MAY**）在发送数据包时略过包号以检测此行为，终端可以将之视为PROTOCOL_VIOLATION的连接错误，立即关闭连接，见第10.2节。

## 21.5. 请求伪造攻击（Request Forgery Attacks）
请求伪造攻击指的是某攻击者终端可控制其对端，使对端向第三方受害者发出指定的攻击请求。请求伪造攻击旨在让攻击者能够获得其对端的能力，这些能力是它不具备的。对于网络协议，请求伪造攻击通常用于利用由于对端在网络中的位置，而获得的由受害者授予对端的任何隐式权限。

为了使伪造的请求有效，攻击者需要能够影响对端发送的数据包的内容和发送位置。如果攻击者可以用受控的负载来攻击某个脆弱的服务，该服务可能会执行由攻击者的对端发起但由攻击者决定的操作。

例如，Web上的跨域请求伪造[CSRF]漏洞会致使客户端发出包含授权cookie[COOKIE]的请求，允许一个站点访问本应被授权给另一个站点的信息和操作。

由于QUIC承载在UDP协议上，所以主要的攻击方式是攻击者选择对端UDP报文的回应地址，并可以控制这些数据包中的一些不受保护的内容。（QUIC终端发送的大部分数据都受到保护，这也包括对密文的控制。）如果攻击者可以使对端向受害者主机发送特定UDP报文，该主机将根据报文中的内容执行某些操作，那么攻击就成功了。

本节讨论QUIC可被用于发起请求伪造攻击的方式。

本节还描述了QUIC终端可以实施的有限对策。这些对策可以由QUIC实现或部署单方面采用，而不需要请求伪造攻击的潜在目标采取行动。但是，如果基于UDP的服务没有正确地对请求授权，这些对策可能是不够的。

因为第21.5.4小节中描述的迁移攻击非常强大并且没有足够的对策，QUIC服务端实现应该假设攻击者可以使他们生成任意目的地的任意UDP负载。QUIC服务端不应该（**SHOULD NOT**）部署在没有部署入口过滤[BCP38]并且也没有足够安全的UDP终端的网络中。

尽管通常无法保证客户端不与易受攻击的服务端位于同一网络，但此QUIC版本不允许服务端迁移，从而防止了对客户端的欺骗迁移攻击。未来任何允许服务端迁移的扩展都必须（**MUST**）为伪造攻击定义对策。


### 21.5.1. 终端的控制选项（Control Options for Endpoints）
QUIC为攻击者提供了一些机会，以影响或控制其对端发送UDP报文的目的地址：

* 初始连接建立（第7章），服务端可以在其中指定客户端发送报文的目的地址——例如，通过填充DNS记录；

* 首选地址（第9.6节），服务端可以在其中指定客户端发送报文的目的地址；

* 欺骗连接迁移（第9.3.1小节），客户端能够使用源地址欺骗使得服务端将后续报文发往目的地址；

* 欺骗数据包，使得服务端发送Version Negotiation包（第21.5.5小节）。

在所有情况下，攻击者都可以使其对端向可能不理解QUIC协议的受害者发送UDP报文。也就是说，这些数据包是在地址验证之前由对端发出，见第8章。

在数据包的加密部分之外，QUIC为终端提供了几个选项来控制其对端发送的UDP报文内容。DCID字段提供了对其对端发送的早期报文中某些字节的直接控制，参见第5.1节。客户端Initial包中的Token字段可以控制服务端Initial包某些字节，见第17.2.2小节。

此QUIC版本中没有任何措施来防止对数据包的加密部分进行间接控制。有必要假设终端能够控制对端发送的帧的内容，尤其是那些携带应用数据的帧，例如STREAM帧。尽管这在某种程度上取决于应用层协议的细节，但在许多协议中使用的上下文中可以进行一些控制。由于攻击者可以访问包保护密钥，他们很可能能够预测对端将如何加密未来的数据包。只需要能够以一定程度的成功概率预测到数据包数量和帧在数据包中的位置，攻击者就可以成功控制报文内容。

本节假设限制对报文内容的控制是不可行的。在后面的章节中所列对策的重点，是限制在地址验证之前发送的报文可用于请求伪造的方式。

### 21.5.2. 客户端Initial包请求伪造（Request Forgery with Client Initial Packets）
作为服务端的攻击者可以选择用于发布其可用性的IP地址和端口，因此假设来自客户端的Initial包可用来进行此类攻击。握手中隐含的地址验证确保对于新连接，客户端不会将其他类型的数据包发往不理解QUIC或不愿意接受QUIC连接的目的地。

Initial包保护（[QUIC-TLS]第5.2节）使服务端难以控制客户端发送的Initial包的内容。选择不可预测的DCID的客户端使得服务端无法控制来自客户端的Initial包的任何加密部分。

但是，Token字段对服务端控制开放，并允许服务端使用客户端进行请求伪造攻击。使用NEW_TOKEN帧（第8.1.3小节）提供的令牌为连接建立期间的请求伪造提供了唯一选择。

但是，客户端没有义务使用NEW_TOKEN帧。如果客户端在接收到NEW_TOKEN帧后，服务端地址发生变化时发送空Token字段，则可以避免依赖Token字段的请求伪造攻击。

如果服务端地址发生变化，客户端可以避免使用NEW_TOKEN帧。但是，不包含Token字段可能会对性能产生不利影响。服务端可以依赖NEW_TOKEN来允许发送超过3倍限制的数据，见第8.1节。特别是，这会影响客户端使用0-RTT从服务端请求数据的情况。

发送Retry包（第17.2.5小节）为服务端提供了更改Token字段的选项。发送Retry包后，服务端还可以控制来自客户端的后续Initial包的DCID字段。这也可能允许对Initial包的加密内容进行间接控制。然而，Retry包的交换验证了服务端的地址，从而防止使用后续Initial包进行请求伪造。

### 21.5.3. 首选地址请求伪造（Request Forgery with Preferred Addresses）
服务端可以指定一个首选地址，客户端在握手确认后迁移到该地址，见第9.6节。客户端发往首选地址的数据包的DCID字段可用于请求伪造。

在验证该地址之前，客户端不得（**MUST NOT**）向首选地址发送非探测帧，见第8章。这大大减少了服务端需控制的数据包加密部分的选项。

本文不提供任何特定于首选地址的使用并且可由终端实施的额外对策。第21.5.6小节中描述的通用措施可用作进一步对策。

### 21.5.4. 欺骗迁移请求伪造（Request Forgery with Spoofed Migration）
客户端能够将欺骗源地址作为显式连接迁移的一部分，从而使服务端向该地址发送报文。

服务端随后发往此欺骗地址的任何数据包中的DCID字段可用于请求伪造。客户端也可能能够影响密文。

如果服务器在地址验证之前只发送探测包（第9.1节）到某个地址，则攻击者只能对数据包的加密部分进行有限的控制。然而，特别是对于NAT重新绑定，这会对性能产生不利影响。如果服务器发送携带应用数据的帧，则攻击者可能能够控制数据报文的大部分内容。

除了第21.5.6小节中描述的通用措施外，本文不提供可由终端实施的具体对策。然而，在网络级别针对地址欺骗的对策——特别是入向过滤[BCP38]——对于使用欺骗和源自外部网络的攻击特别有效。

### 21.5.5. 通过版本协商请求伪造（Request Forgery with Version Negotiation）
如果客户端能够在包上携带一个欺骗的源地址，那么服务端可以向该地址发送Version Negotiation包（第17.2.1小节）。

对于未知版本的包，CID字段没有大小限制，这增加了客户端从结果数据报控制的数据量。该数据包的第一个字节不受客户端控制，接下来的四个字节是零，但客户端可以控制从第5个字节开始的最多512个字节。

本文没有为此攻击提供具体的对策，但可以应用通用保护（第21.5.6小节）。在这种情况下，入向过滤[BCP38]也是有效的。

### 21.5.6. 通用请求伪造对策（Generic Request Forgery Countermeasures）
防御请求伪造攻击的最有效方法是修改易受攻击的服务以使用强认证。然而，这并不总是在QUIC部署的控制范围内。本节概述了QUIC终端可以单方面采取的其他一些步骤。这些额外的步骤可自行决定，因为根据情况，它们可能会干扰或阻止QUIC的合法用法。

通过环回接口提供的服务通常缺乏适当的认证。终端可以（**MAY**）阻止连接尝试或迁移到环回地址。如果同一服务以前在不同的接口可用，或者地址是由非环回地址的服务提供的，则终端不应该（**SHOULD NOT**）允许连接或迁移到环回地址。依赖于这些功能的终端可以提供禁用这些保护的选项。

类似地，终端可以视将地址从来自global、unique-local[RFC4193]或non-private范围，更改为link-local地址[RFC4291]或private-use[RFC1918]范围中的地址，作为潜在的请求伪造攻击尝试。终端可以完全拒绝使用这些地址，但这会带来干扰合法地址的显著风险。终端不应该（**SHOULD NOT**）拒绝使用地址，除非它们对网络有特定的了解，表明将报文发往给定范围内的未验证地址是不安全的。

终端可以（**MAY**）选择通过在Initial包中不包含来自NEW_TOKEN帧的值，或在完成地址验证之前仅在数据包中发送探测帧来降低请求伪造的风险。请注意，这并不能阻止攻击者使用DCID字段进行攻击。

终端不应具有关于某些服务端位置的特定信息，这些服务端可能成为请求伪造攻击的脆弱目标。但是，随着时间的推移，可能会识别出特定的UDP端口或特定的报文模式作为攻击的常见目标。在验证目的地址之前，终端可以（**MAY**）避免向这些端口发送报文或不发送与这些模式匹配的报文。终端可以（**MAY**）不使用包含已知有问题的模式的CID。

> 注意：修改终端以应用这些保护措施比部署基于网络的保护更有效，因为终端在发包到已验证的地址时不需要执行任何额外的处理。

## 21.6. Slowloris攻击（Slowloris Attacks）
这种攻击通常被称为Slowloris [Slowloris]，它试图保持多个与目的终端的连接，并尽可能长时间地保持打开状态。针对QUIC终端，这些攻击可以通过生成避免因不活动而关闭连接所需的最小活动流量来实现。这可能包括发送少量数据，逐渐打开流控窗口以控制发送方速率，或模拟高丢包率生成ACK帧。

QUIC部署应该（**SHOULD**）为Slowloris攻击提供对策，例如增加服务端允许的最大客户端数量、限制单个IP地址允许建立的连接数量、限制连接允许的最低传输速度，并限制终端允许保持连接的时间长度。

## 21.7. 流分片和重组攻击（Stream Fragmentation and Reassembly Attacks）
恶意发送方可能故意不发送部分流数据，从而致使接收方为这些未发数据请求资源。这可能会致使不成比例的接收缓冲区内存分配和/或在接收方处创建大型且低效的数据结构。

恶意接收方可能故意不确认某些包含流数据的数据包，试图强制发送方存储大量未确认的流数据以进行重传。

如果流控窗口对应于可用内存，则可以减轻对接收方的攻击。但是，某些接收方会过量申请内存并通告超出实际可用内存的流控偏移。当终端表现良好时，超量策略可以带来更好的性能，但会使终端容易受到流分片攻击。

QUIC部署应该（**SHOULD**）为流分片攻击提供对策。这些措施可能包括避免过度申请内存、限制跟踪数据结构的大小、延迟重组STREAM帧、基于重组间隙的时间和持续时间采用启发式方法，或这些方法的某些组合。

## 21.8. 流提交攻击（Stream Commitment Attack）
恶意终端可以打开大量的流，耗尽对端状态。恶意终端可以在大量连接上重复该过程，其方式类似于TCP中的SYN洪水攻击。

通常，客户端将按顺序打开流，如第2.1节所述。然而，当几个流以较短间隔开启时，丢包或乱序可能致使打开流的STREAM帧被乱序接收。在接收到更高编号的流ID时，接收方需要打开所有相同类型的中间流，见第3.2节。因此，在新连接上，打开流ID为4000000的流将会打开1000001个客户端启动的双向流。

活动流的数量受initial_max_streams_bidi或initial_max_streams_uni传输参数的限制，并由MAX_STREAMS帧更新，如第4.6节所述。如果合理设定，这些限制可以减轻流提交攻击的影响。但是，当应用希望打开大量流时，将限制设置得太低可能会影响性能。

## 21.9. 对端拒绝服务攻击（Peer Denial of Service）
QUIC和TLS都包含在某些上下文中具有合法用途的帧或消息，但这些帧或消息可能会被滥用，致使对端消耗处理资源，而不会对连接状态产生任何可观察到的影响。

终端可以发送较小或无关紧要的消息来更改和恢复状态，例如通过向流控限制发送小增量。

如果与带宽消耗或对状态的影响相比，处理成本不成比例地大，那么这可能使得恶意对端耗尽处理能力。

虽然所有消息都有合法用途，但实现应该（**SHOULD**）跟踪与进度相关的处理成本，并将过量的任何非生产性数据包视为攻击的指示。终端可以（**MAY**）以连接错误关闭连接或丢弃数据包来响应这种情况。

## 21.10. 显式拥塞通知攻击（Explicit Congestion Notification Attacks）
on-path攻击者可以操纵IP报头中ECN字段的值来影响发送方的速率。[RFC3168]更详细地讨论了这种操作及其影响。

“受限”的on-path攻击者可以复制和发送带有被修改ECN字段的数据包，以影响发送方的速率。如果接收方会丢弃重复的数据包，攻击者需要将重复数据包与原数据包竞速才能在这次攻击中取得成功。因此，QUIC终端可忽略IP数据包中的ECN字段，除非该IP数据包中至少有一个QUIC包被成功处理，见第13.4节。

## 21.11. 无状态重置攻击（ Stateless Reset Oracle）
无状态重置可能会产生类似于TCP重置注入的拒绝服务攻击。如果攻击者能够为具有特定CID的连接生成无状态重置令牌，则此攻击是可行的。导致此令牌生成的攻击者可重置具有相同CID的活动连接。

如果数据包可以路由到共享静态密钥的不同实例（例如，通过更改IP地址或端口），则攻击者可以使服务端发送Stateless Reset包。为了防止这种拒绝服务的类型，共享一个静态密钥用于无状态重置的终端必须（**MUST**）合理考虑（见第10.3.2小节），以便具有给定CID的数据包始终能到达具有同一连接状态的实例，除非该连接不再活跃。

更一般地，如果具有相应CID的连接可以在使用相同静态密钥的任何终端上处于活动状态，则服务端不得（**MUST NOT**）生成Stateless Reset包。

对于使用动态负载均衡的集群，当活动实例保持连接状态时，负载均衡器配置可能会发生变化。即使实例保持连接状态，路由的改变和由此产生的无状态重置也会致使连接被终止。如果无法将数据包路由到正确的实例，最好发送Stateless Reset包而不是等待连接超时。不过，这只有在路由不受攻击者影响时才可以接受。

## 21.12. 版本降级（Version Downgrade）
本文定义了QUIC的Version Negotiation包（第6章），可用于协商两端之间使用的QUIC版本。但是，本文没有具体说明如何在此版本和后续版本之间进行协商。特别是，Version Negotiation包中没有任何防止版本降级攻击的机制。未来使用版本协商的QUIC版本必须（**MUST**）定义一种对版本降级攻击具有鲁棒性的机制。

## 21.13. 通过路由进行针对性攻击（Targeted Attacks by Routing）
部署应该限制攻击者针对特定服务器实例的新连接进行攻击的能力。理想情况下，路由决策独立于客户端选择的值，包括地址。一旦选择了一个实例，就可以选择一个CID，以便后续数据包能路由到同一个实例。

## 21.14. 流量分析（Traffic Analysis）
QUIC包的长度可以揭示有关这些数据包内容长度的信息。PADDING帧的引入是为了使终端有模糊数据包内容长度的能力，见第19.1节。

对抗流量分析具有挑战性，也是一个主动研究的课题。长度不是信息泄漏的唯一途径。终端也可能从其他侧信道泄露敏感信息，例如数据包的耗时。

# 22. IANA考虑（IANA Considerations）
本文为管理QUIC码点新设了几个注册表，这些注册表遵循第22.1节中定义的一组通用策略。

## 22.1. QUIC注册表的注册策略（Registration Policies forQUICRegistries）
所有QUIC注册表都容许注册临时或永久性质的码点。本节描述通用的注册策略。

### 22.1.1. 临时注册（Provisional Registrations）
临时码点注册的引入旨在允许私有用途和实验性质的QUIC的扩展。临时注册申请只需要包含码点的值和联系人信息，同时，这类码点也可以被回收并重新分配用于其他目的。

根据[RFC8126]第4.5节的规定，临时注册需要专家审查。建议专家仅拒绝申请码点范围占用剩余码点空间比例过大，或申请第一个未分配值（参见第22.1.2小节）的注册。

临时注册包括一个Date字段，指示注册上次创建或更新的时间。可在不经指定专家审查的情况下提出更新任何临时注册日期的申请。

所有QUIC注册表都包含如下字段以支持临时注册：

Value： 码点值。

Status："永久"或"临时"。

Specification：引用该值的公开可用的规约。

Date：创建或更新日期。

Change Controller：负责该注册表项的实体。

Contact：注册人的联系方式。

Notes：关于该注册项的补充信息。

临时注册可以（**MAY**）省略Specification和Notes字段，也可以包含永久注册可能需要的其他字段。申请注册时不需要携带Date字段，因为其可被设置为正式创建或更新注册项的日期。

### 22.1.2. 码点选择（Selecting Codepoints）
向QUIC注册表申请新码点，应该（**SHOULD**）使用随机选择的值，该值不能是已经分配的值和所选空间第一个未分配的码点。一次申请多个码点的话，可以（**MAY**）选择一个连续的范围。这将不同的实现对同一码点赋予不同语义的风险降到最低。

第一个未分配的码点保留，需用Standards Action策略进行分配，参见[RFC8126]第4.9节。早期码点分配过程[EARLY-ASSIGN]可用于指导这些值的分配。

对于以变长整数（参见第16章）编码的码点，例如帧类型，应该（**SHOULD**）使用编码为4或8个字节（即2^14^及以上的值）的码点，除非其对较长编码特别敏感。

需要在QUIC注册表中注册码点的应用，可以（**MAY**）将申请码点作为注册过程的一部分。如果该码点尚未分配并且满足注册策略的要求，IANA必须（**MUST**）分配所选的码点。

### 22.1.3. 回收临时码点（Reclaiming Provisional Codepoints）
为了从注册表中回收一个或部分注册项（例如使用变长编码的64-16383范围的码点）释放注册表空间，可以申请删除未使用的临时注册项。应该（**SHOULD**）仅从具有最早记录日期的码点开始执行，并且不应该（**SHOULD NOT**）回收在不到一年之前更新的注册项。

删除码点的申请必须（**MUST**）由指定的专家审核。专家必须（**MUST**）先尝试确定码点是否仍在使用中。建议专家联系注册项中列出的联系人，以及尽可能广泛联系到协议的实现者，以确定其是否知道这些码点的使用情况。另外还建议专家至少留出四个星期的时间做出回应。

如果上述流程识别出码点正在使用中或有新提出更新注册项的申请，则不得（**MUST NOT**）回收码点，而应更新注册日期。修改时可以添加备注，记录了解到的相关情况。

如果识别出码点未在使用并且没有申请注册更新，则可以（**MAY**）从注册表中删除码点。

此审查和咨询过程也适用于将临时注册变更为永久注册的申请，但其目的不是确定是否有没有使用的码点，而是确定注册项是否准备表达了任何已部署的用途。

### 22.1.4. 永久注册（Permanent Registrations）
除非另有说明，QUIC注册表中的永久注册项遵循（[RFC8126]第4.6节）指定的规约策略。指定的一个或多个专家验证规约是否存在且易于访问。鼓励专家偏向于批准注册，除非它们是滥用的、轻率的或有害的（不仅仅是看起来不漂亮或架构上可疑）。新建永久注册项时可以（**MAY**）指定附加限制。

新建注册表可能（**MAY**）需要指定一系列码点，这些码点分别由不同的注册策略管理。例如，QUIC Frame Types注册表（第22.4节）对0到63范围内的码点有更严格的策略。

对永久注册项的严格限制不会影响临时码点的注册。例如，可以申请临时注册帧类型为61的码点。

进入标准化阶段公布的注册表项都必须（**MUST**）是永久性的。

本文中的所有注册项都是永久状态，且随附有IETF的变更控制人和QUIC工作组的联系方式(quic@ietf.org)。

## 22.2. QUIC版本注册表（QUIC Versions Registry）
IANA在QUIC标题下为QUIC Versions添加了一个注册表。

QUIC Versions注册表管理32位空间，参见第15章。此注册表遵循第22.1节的注册策略。注册表中的永久注册项遵循[RFC8126]第4.6节的策略。

本文中定义的协议被分配了0x00000001码点。0x00000000码点是永久保留的，这个码点的注释有说明0x00000000是为版本协商保留的。

遵循模式0x?a?a?a?a的所有码点都是保留的，IANA不得（**MUST NOT**）分配，并且不得（**MUST NOT**）出现在分配值列表中。

## 22.3. QUIC传输参数注册表（QUIC Transport Parameters Registry）
IANA在QUIC标题下为QUIC Transport Parameters添加了一个注册表。

QUIC Transport Parameters注册表管理62位空间。此注册表遵循第22.1节中的注册策略。此注册表中的永久注册项遵循（[RFC8126]第4.6节）规约策略进行分配，但0x00和0x3f（十六进制）之间的值除外，这些值使用[RFC8126]第4.9和4.10节定义的Standards Action或IESG许可进行分配。

除了第22.1.1小节中列出的字段外，此注册表中的永久注册项必须（**MUST**）包括以下字段：

Parameter Name：参数名称，简短的参数助记符。

该注册表的初始内容如表6所示：

| Value      | Parameter Name | Specification |
|:----|:-----|:-----|
|0x00|	original_destination_connection_id	|第18.2节|
|0x01|	max_idle_timeout	                |第18.2节|
|0x02|	stateless_reset_token	            |第18.2节|
|0x03|	max_udp_payload_size	            |第18.2节|
|0x04|	initial_max_data	                |第18.2节|
|0x05|	initial_max_stream_data_bidi_local	|第18.2节|
|0x06|	initial_max_stream_data_bidi_remote	|第18.2节|
|0x07|	initial_max_stream_data_uni	        |第18.2节|
|0x08|	initial_max_streams_bidi	        |第18.2节|
|0x09|	initial_max_streams_uni	            |第18.2节|
|0x0a|	ack_delay_exponent	                |第18.2节|
|0x0b|	max_ack_delay	                    |第18.2节|
|0x0c|	disable_active_migration	        |第18.2节|
|0x0d|	preferred_address	                |第18.2节|
|0x0e|	active_connection_id_limit	        |第18.2节|
|0x0f|	initial_source_connection_id	    |第18.2节|
|0x10|	retry_source_connection_id	        |第18.2节|

表6: Initial QUIC Transport Parameters Registry 

对于形如 31 * N + 27（N为整数）值（即27, 58, 89, ...）都是保留的，这些值不得（**MUST NOT**）由IANA分配，也不得（**MUST NOT**）出现在分配值列表中。

## 22.4. QUIC帧类型注册表（QUIC Frame Types Registry）
IANA在QUIC标题下添加了一个QUIC Frame Types注册表。

QUIC Frame Types注册表管理62位空间。此注册表遵循第22.1节中的注册策略。此注册表中的永久注册项遵循（[RFC8126]第4.6节）规约策略进行分配，但0x00和0x3f（十六进制）之间的值除外，这些值使用[RFC8126]第4.9和4.10节定义的Standards Action或IESG许可进行分配。

除了第22.1.1小节中列出的字段外，此注册表中的永久注册项必须（**MUST**）包括以下字段：

Frame Type Name：帧类型名称，简短的帧类型助记符。

除了第22.1节的建议外，规约中增加永久注册项，都应该（**SHOULD**）描述终端是否可以发送该种类型的帧。大多数永久注册项都需要在传输参数中注册，参见第22.3节。另外，还需要描述帧格式及帧中所有字段的赋值语义。

初始注册表参见表3。请注意，注册表不包括表3中的Pkts和Spec列。

## 22.5. QUIC传输层错误码注册表（QUIC Transport Error Codes Registry）
IANA在QUIC标题下添加了QUIC Transport Error Codes的注册表。

QUIC Transport Error Codes注册表管理62位空间。该空间分为三个范围，由不同的策略管理。此注册表中的永久注册项分配要求遵循（[RFC8126]第4.6节）规约策略，但0x00和0x3f（十六进制）之间的值除外，这些值使用[RFC8126]第4.9和4.10节定义的Standards Action或IESG许可进行分配。

除了第22.1.1小节中列出的字段外，此注册表中的永久注册项必须（**MUST**）包括以下字段：

Code：错误码，简短参数助记符。

Description：描述，错误码语义的简要描述，如果被规约引用，则可能（**MAY**）是摘要。

初始注册表如表7所示。

|Value	|Code	                    |Description	|Specification|
|:---|:---|:---|:---|
|0x00	|NO_ERROR	                |没有错误	    |第20章|
|0x01	|INTERNAL_ERROR	            |实现错误	    |第20章|
|0x02	|CONNECTION_REFUSED	        |服务端拒绝连接	|第20章|
|0x03	|FLOW_CONTROL_ERROR	        |流控错误	    |第20章|
|0x04	|STREAM_LIMIT_ERROR	        |打开流数量超限制	|第20章|
|0x05	|STREAM_STATE_ERROR	        |在当前流状态下收到无效帧	|第20章|
|0x06	|FINAL_SIZE_ERROR	        |流上的FINAL SIZE出错	|第20章|
|0x07	|FRAME_ENCODING_ERROR	    |帧解码错	|第20章|
|0x08	|TRANSPORT_PARAMETER_ERROR	|传输参数有误	|第20章|
|0x09	|CONNECTION_ID_LIMIT_ERROR	|CID超限制	|第20章|
|0x0a	|PROTOCOL_VIOLATION	        |通用协议错误	|第20章|
|0x0b	|INVALID_TOKEN	            |收到无效令牌	|第20章|
|0x0c	|APPLICATION_ERROR	        |应用程序错误	|第20章|
|0x0d	|CRYPTO_BUFFER_EXCEEDED	    |CRYPTO缓存溢出	|第20章|
|0x0e	|KEY_UPDATE_ERROR	        |收到无效的TLS KEY UPDATE请求	|第20章|
|0x0f	|AEAD_LIMIT_REACHED	        |AEAD当前秘钥加密数据长度超限制（需要更换秘钥）	|第20章|
|0x10	|NO_VIABLE_PATH	            |没有可用的网路路径	|第20章|
|0x0100-0x01ff	|CRYPTO_ERROR	    |TLS告警码	|第20章|

表7: Initial QUIC Transport Error Codes Registry Entries

# 23. 参考资料（References）
## 23.1. 规范引用（Normative References）
[BCP38]
Ferguson, P. and D. Senie, "Network Ingress Filtering: Defeating Denial of Service Attacks which employ IP Source Address Spoofing", BCP 38, RFC 2827, May 2000, <https://www.rfc-editor.org/info/bcp38>.

[DPLPMTUD]
Fairhurst, G., Jones, T., Tüxen, M., Rüngeler, I., and T. Völker, "Packetization Layer Path MTU Discovery for Datagram Transports", RFC 8899, DOI 10.17487/RFC8899, September 2020, <https://www.rfc-editor.org/info/rfc8899>.

[EARLY-ASSIGN]
Cotton, M., "Early IANA Allocation of Standards Track Code Points", BCP 100, RFC 7120, DOI 10.17487/RFC7120, January 2014, <https://www.rfc-editor.org/info/rfc7120>.

[IPv4]
Postel, J., "Internet Protocol", STD 5, RFC 791, DOI 10.17487/RFC0791, September 1981, <https://www.rfc-editor.org/info/rfc791>.

[QUIC-INVARIANTS]
Thomson, M., "Version-Independent Properties of QUIC", RFC 8999, DOI 10.17487/RFC8999, May 2021, <https://www.rfc-editor.org/info/rfc8999>.

[QUIC-RECOVERY]
Iyengar, J., Ed. and I. Swett, Ed., "QUIC Loss Detection and Congestion Control", RFC 9002, DOI 10.17487/RFC9002, May 2021, <https://www.rfc-editor.org/info/rfc9002>.

[QUIC-TLS]
Thomson, M., Ed. and S. Turner, Ed., "Using TLS to Secure QUIC", RFC 9001, DOI 10.17487/RFC9001, May 2021, <https://www.rfc-editor.org/info/rfc9001>.

[RFC1191]
Mogul, J. and S. Deering, "Path MTU discovery", RFC 1191, DOI 10.17487/RFC1191, November 1990, <https://www.rfc-editor.org/info/rfc1191>.

[RFC2119]
Bradner, S., "Key words for use in RFCs to Indicate Requirement Levels", BCP 14, RFC 2119, DOI 10.17487/RFC2119, March 1997, <https://www.rfc-editor.org/info/rfc2119>.

[RFC3168]
Ramakrishnan, K., Floyd, S., and D. Black, "The Addition of Explicit Congestion Notification (ECN) to IP", RFC 3168, DOI 10.17487/RFC3168, September 2001, <https://www.rfc-editor.org/info/rfc3168>.

[RFC3629]
Yergeau, F., "UTF-8, a transformation format of ISO 10646", STD 63, RFC 3629, DOI 10.17487/RFC3629, November 2003, <https://www.rfc-editor.org/info/rfc3629>.

[RFC6437]
Amante, S., Carpenter, B., Jiang, S., and J. Rajahalme, "IPv6 Flow Label Specification", RFC 6437, DOI 10.17487/RFC6437, November 2011, <https://www.rfc-editor.org/info/rfc6437>.

[RFC8085]
Eggert, L., Fairhurst, G., and G. Shepherd, "UDP Usage Guidelines", BCP 145, RFC 8085, DOI 10.17487/RFC8085, March 2017, <https://www.rfc-editor.org/info/rfc8085>.

[RFC8126]
Cotton, M., Leiba, B., and T. Narten, "Guidelines for Writing an IANA Considerations Section in RFCs", BCP 26, RFC 8126, DOI 10.17487/RFC8126, June 2017, <https://www.rfc-editor.org/info/rfc8126>.

[RFC8174]
Leiba, B., "Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words", BCP 14, RFC 8174, DOI 10.17487/RFC8174, May 2017, <https://www.rfc-editor.org/info/rfc8174>.

[RFC8201]
McCann, J., Deering, S., Mogul, J., and R. Hinden, Ed., "Path MTU Discovery for IP version 6", STD 87, RFC 8201, DOI 10.17487/RFC8201, July 2017, <https://www.rfc-editor.org/info/rfc8201>.

[RFC8311]
Black, D., "Relaxing Restrictions on Explicit Congestion Notification (ECN) Experimentation", RFC 8311, DOI 10.17487/RFC8311, January 2018, <https://www.rfc-editor.org/info/rfc8311>.

[TLS13]
Rescorla, E., "The Transport Layer Security (TLS) Protocol Version 1.3", RFC 8446, DOI 10.17487/RFC8446, August 2018, <https://www.rfc-editor.org/info/rfc8446>.

[UDP]
Postel, J., "User Datagram Protocol", STD 6, RFC 768, DOI 10.17487/RFC0768, August 1980, <https://www.rfc-editor.org/info/rfc768>.

## 23.2. 资料引用（Informative References）
[AEAD]
McGrew, D., "An Interface and Algorithms for Authenticated Encryption", RFC 5116, DOI 10.17487/RFC5116, January 2008, <https://www.rfc-editor.org/info/rfc5116>.

[ALPN]
Friedl, S., Popov, A., Langley, A., and E. Stephan, "Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension", RFC 7301, DOI 10.17487/RFC7301, July 2014, <https://www.rfc-editor.org/info/rfc7301>.

[ALTSVC]
Nottingham, M., McManus, P., and J. Reschke, "HTTP Alternative Services", RFC 7838, DOI 10.17487/RFC7838, April 2016, <https://www.rfc-editor.org/info/rfc7838>.

[COOKIE]
Barth, A., "HTTP State Management Mechanism", RFC 6265, DOI 10.17487/RFC6265, April 2011, <https://www.rfc-editor.org/info/rfc6265>.

[CSRF]
Barth, A., Jackson, C., and J. Mitchell, "Robust defenses for cross-site request forgery", Proceedings of the 15th ACM conference on Computer and communications security - CCS '08, DOI 10.1145/1455770.1455782, 2008, <https://doi.org/10.1145/1455770.1455782>.

[EARLY-DESIGN]
Roskind, J., "QUIC: Multiplexed Stream Transport Over UDP", 2 December 2013, <https://docs.google.com/document/d/1RNHkx_VvKWyWg6Lr8SZ-saqsQx7rFV-ev2jRFUoVD34/edit?usp=sharing>.

[GATEWAY]
Hätönen, S., Nyrhinen, A., Eggert, L., Strowes, S., Sarolahti, P., and M. Kojo, "An experimental study of home gateway characteristics", Proceedings of the 10th ACM SIGCOMM conference on Internet measurement - IMC '10, DOI 10.1145/1879141.1879174, November 2010, <https://doi.org/10.1145/1879141.1879174>.

[HTTP2]
Belshe, M., Peon, R., and M. Thomson, Ed., "Hypertext Transfer Protocol Version 2 (HTTP/2)", RFC 7540, DOI 10.17487/RFC7540, May 2015, <https://www.rfc-editor.org/info/rfc7540>.

[IPv6]
Deering, S. and R. Hinden, "Internet Protocol, Version 6 (IPv6) Specification", STD 86, RFC 8200, DOI 10.17487/RFC8200, July 2017, <https://www.rfc-editor.org/info/rfc8200>.

[QUIC-MANAGEABILITY]
Kuehlewind, M. and B. Trammell, "Manageability of the QUIC Transport Protocol", Work in Progress, Internet-Draft, draft-ietf-quic-manageability-11, 21 April 2021, <https://tools.ietf.org/html/draft-ietf-quic-manageability-11>.

[RANDOM]
Eastlake 3rd, D., Schiller, J., and S. Crocker, "Randomness Requirements for Security", BCP 106, RFC 4086, DOI 10.17487/RFC4086, June 2005, <https://www.rfc-editor.org/info/rfc4086>.

[RFC1812]
Baker, F., Ed., "Requirements for IP Version 4 Routers", RFC 1812, DOI 10.17487/RFC1812, June 1995, <https://www.rfc-editor.org/info/rfc1812>.

[RFC1918]
Rekhter, Y., Moskowitz, B., Karrenberg, D., de Groot, G. J., and E. Lear, "Address Allocation for Private Internets", BCP 5, RFC 1918, DOI 10.17487/RFC1918, February 1996, <https://www.rfc-editor.org/info/rfc1918>.

[RFC2018]
Mathis, M., Mahdavi, J., Floyd, S., and A. Romanow, "TCP Selective Acknowledgment Options", RFC 2018, DOI 10.17487/RFC2018, October 1996, <https://www.rfc-editor.org/info/rfc2018>.

[RFC2104]
Krawczyk, H., Bellare, M., and R. Canetti, "HMAC: Keyed-Hashing for Message Authentication", RFC 2104, DOI 10.17487/RFC2104, February 1997, <https://www.rfc-editor.org/info/rfc2104>.

[RFC3449]
Balakrishnan, H., Padmanabhan, V., Fairhurst, G., and M. Sooriyabandara, "TCP Performance Implications of Network Path Asymmetry", BCP 69, RFC 3449, DOI 10.17487/RFC3449, December 2002, <https://www.rfc-editor.org/info/rfc3449>.

[RFC4193]
Hinden, R. and B. Haberman, "Unique Local IPv6 Unicast Addresses", RFC 4193, DOI 10.17487/RFC4193, October 2005, <https://www.rfc-editor.org/info/rfc4193>.

[RFC4291]
Hinden, R. and S. Deering, "IP Version 6 Addressing Architecture", RFC 4291, DOI 10.17487/RFC4291, February 2006, <https://www.rfc-editor.org/info/rfc4291>.

[RFC4443]
Conta, A., Deering, S., and M. Gupta, Ed., "Internet Control Message Protocol (ICMPv6) for the Internet Protocol Version 6 (IPv6) Specification", STD 89, RFC 4443, DOI 10.17487/RFC4443, March 2006, <https://www.rfc-editor.org/info/rfc4443>.

[RFC4787]
Audet, F., Ed. and C. Jennings, "Network Address Translation (NAT) Behavioral Requirements for Unicast UDP", BCP 127, RFC 4787, DOI 10.17487/RFC4787, January 2007, <https://www.rfc-editor.org/info/rfc4787>.

[RFC5681]
Allman, M., Paxson, V., and E. Blanton, "TCP Congestion Control", RFC 5681, DOI 10.17487/RFC5681, September 2009, <https://www.rfc-editor.org/info/rfc5681>.

[RFC5869]
Krawczyk, H. and P. Eronen, "HMAC-based Extract-and-Expand Key Derivation Function (HKDF)", RFC 5869, DOI 10.17487/RFC5869, May 2010, <https://www.rfc-editor.org/info/rfc5869>.

[RFC7983]
Petit-Huguenin, M. and G. Salgueiro, "Multiplexing Scheme Updates for Secure Real-time Transport Protocol (SRTP) Extension for Datagram Transport Layer Security (DTLS)", RFC 7983, DOI 10.17487/RFC7983, September 2016, <https://www.rfc-editor.org/info/rfc7983>.

[RFC8087]
Fairhurst, G. and M. Welzl, "The Benefits of Using Explicit Congestion Notification (ECN)", RFC 8087, DOI 10.17487/RFC8087, March 2017, <https://www.rfc-editor.org/info/rfc8087>.

[RFC8981]
Gont, F., Krishnan, S., Narten, T., and R. Draves, "Temporary Address Extensions for Stateless Address Autoconfiguration in IPv6", RFC 8981, DOI 10.17487/RFC8981, February 2021, <https://www.rfc-editor.org/info/rfc8981>.

[SEC-CONS]
Rescorla, E. and B. Korver, "Guidelines for Writing RFC Text on Security Considerations", BCP 72, RFC 3552, DOI 10.17487/RFC3552, July 2003, <https://www.rfc-editor.org/info/rfc3552>.

[SLOWLORIS]
"RSnake" Hansen, R., "Welcome to Slowloris - the low bandwidth, yet greedy and poisonous HTTP client!", June 2009, <https://web.archive.org/web/20150315054838/http://ha.ckers.org/slowloris/>.