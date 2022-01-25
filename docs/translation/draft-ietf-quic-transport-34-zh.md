
# 1. Overview

QUIC是一种安全的通用传输协议。本文定义了QUIC version 1，该版本符合 [QUIC-INVARIANTS] 中定义的QUIC的版本无关属性。

QUIC是一个面向连接的协议，可在客户端和服务端之间创建有状态的交互。

QUIC握手结合了加密和传输参数的协商。
QUIC集成了TLS([TLS13])握手协议，尽管它使用了一个自定义的框架来保护数据包。TLS和QUIC的集成在[QUIC-TLS]中有更详细的描述。
握手的结构允许尽快交换应用数据，包括客户端立即发送数据的选项（0-RTT），这需要某种形式的事先通信或配置才能启用。

终端在QUIC中通过交换QUIC数据包进行通信。大多数数据包包含帧，帧在终端之间传递控制信息和应用数据。
QUIC对每个数据包的全部内容进行身份验证，并尽可能地对每个数据包进行加密。
QUIC数据包以UDP数据报（[UDP]）的形式传送，以更好地促进在现有系统和网络中的部署。

应用层协议通过流在QUIC连接上交换信息，流是有序的字节序列。 可以创建两种类型的流：双向流，允许两个终端都发送数据；单向流，仅允许单个终端发送数据。基于信用的方案被用于限制流的创建，并约束可以发送的数据量。

QUIC提供必要的反馈，以实现可靠传输和拥塞控制。在[QUIC-RECOVERY]中描述了一种检测和恢复丢包的算法。QUIC依赖于拥塞控制来避免网络拥塞，在[QUIC-RECOVERY]中也描述了一个典型的拥塞控制算法。

QUIC连接未严格绑定到单个网络路径上。连接迁移使用连接标识符来允许连接转移到新的网络路径。在这个版本的QUIC中，只有客户端能够进行迁移。此设计还允许在网络拓扑或地址映射发生变化（如NAT重新绑定可能引起的变化）后继续连接。

建立连接后，将提供多个选项来终止连接。 应用程序可以管理正常关闭，终端可以协商超时期限，错误可以导致立即断开连接，无状态机制提供了在一个终端丢失状态后终止连接的功能。

## 1.1. Document Structure

本文描述了QUIC协议的核心，文档结构如下：

* 流是QUIC提供的基本服务抽象
   - 第2章描述了流相关的核心概念；
   - 第3章提供了流状态的参考模型；
   - 第4章概述了流量控制；
* 连接是QUIC终端之间通信的上下文
   - 第5章描述了连接相关的核心概念
   - 第6章描述了版本协商
   - 第7章详细说明了建立连接的流程
   - 第8章说明了地址校验和拒绝服务迁移的重要信息
   - 第9章说明了终端将连接迁移到新的网络链路的方法
   - 第10章列举了终止已打开连接的方法
   - 第11章提供了流和连接错误处理的指导
* 包和帧是QUIC用于通信的基本单元
   - 第12章描述了包和帧相关的概念
   - 第13章定义了数据传输、重传和确认的模型
   - 第14章定义了携带QUIC包的数据报尺寸的管理规则
* 最后，下列章节描述了QUIC协议元素的编码细节
   - 第15章（版本）
   - 第16章（整数编码）
   - 第17章（包头部）
   - 第18章（传输参数）
   - 第19章（帧）
   - 第20章（错误）

另外还有专门用于描述QUIC丢包检测和拥塞控制的[QUIC-RECOVERY]文档，以及描述了TLS和其它加密机制的[QUIC-TLS]文档。

本文定义了QUIC v1，并遵从了[QUIC-INVARIANTS]中的协议不变量。

可以引用本文来引用QUIC v1。如果需要引用QUIC协议中与版本无关的有限集合，可以引用[QUIC-INVARIANTS]文档。

## 1.2. Terms and Definitions

本文中的关键词"MUST"，"MUST NOT"，"REQUIRED"，"SHALL"，"SHALL NOT"，"SHOULD"，"SHOULD NOT"，"RECOMMENDED"，"NOT RECOMMENDED"，"MAY"，以及"OPTIONAL"，只有当他们全部以大写字母出现的时候，需要按BCP 14[RFC2119][RFC8174]所述的方式进行理解。

本文中常用术语如下所示：
QUIC：本文中描述的传输协议，QUIC是一个名称，而不是缩略词。

终端：一个参与QUIC连接，生成、接收并处理QUIC包的实体。QUIC只有两种类型终端：客户端与服务端。

客户端：发起QUIC连接的终端。

服务端：接受QUIC连接的终端。

QUIC包：QUIC在一个UDP数据报中能够封装的完整可处理的包。单个UDP数据报中可以封装一个或多个QUIC包。

Ack引发包：一个包含了除ACK，PADDING，和CONNECTION_CLOSE以外帧的QUIC包。那些帧能够引发接收者发送确认信息；参考第13.2.1小节。

帧：一个结构化的协议信息单位。有多种帧类型，每种类型携带不同的信息。帧包含在QUIC包中。

地址：没有限定的时候，IP版本，IP地址，UDP协议，UDP端口号的元组，代表了一个网络链路的端点。

连接ID：一个用于区分一个终端上的QUIC连接的显式标识。每个终端为其对端选择一个或多个连接ID，包含在向对端发送的数据包中。这个值对于对端是不透明的。

流：QUIC连接中，一个单向或者双向的有序字节通道。一个QUIC连接中可以同时承载多个并发流。

应用：使用QUIC来发送和接收数据的实体。

本文档使用 "QUIC包"、"UDP数据报"、"IP包 "等术语来指代各自协议的单位。也就是说，一个或多个QUIC数据包可以封装在UDP数据报中，而UDP数据报又封装在IP数据包中。

## 1.3. Notational Conventions

本文中的包和帧相关的图使用了custom格式。这种格式的目的是归纳协议元素，而不是定义它们。正文定义了它们的完整语义和结构细节。

定义复合字段时，首先命名它们，接着在一堆括号中列举了字段表。这个列表中的字段以逗号隔开。

描述单个字段时，包括了长度信息，以及固定值、可选性、重复的标记。单个字段使用了一下符号约定，长度以位计算：
x(A)：表示x长度是A位
x(i)： 表示x使用第16章中的可变长度编码来保存一个整数值
x (A.. B)：表示x是一个介于A和B之间的长度；如果没有A，则表示最小是0位；如果没有B，则表示没有设置上限；这个格式的值往往以字节边界结束。
x (L) = C：表示x的固定值为C，长度由L描述，可以使用上述三种长度形式中的任何一种形式。
x (L) = C.. D：表示x的值在[C, D]之间，长度由L描述，如上所述。
[x (L)]：x是可选的（且长度为L）
x (L) ...：x是多个重复0，（且每个实例的长度为L）

本文中的值都是网络字节序的（big endian）。所有字段都从字节的最高位开始。

依据惯例，单独字段引用一个复合字段的时候，使用了复合字段的名称。
比如：

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

                          Figure 1: Example Format
```

当在正文中引用单比特字段时，可以用携带该字段的字节的值与字段的值集来明确该字段的位置。
例如，可以用值0x80来引用单比特字段中最有意义的位的字节，如图1中的One-bit Field。

# 2. Streams

QUIC中的流向应用提供了一个轻量级、有序字节流的抽象。流可以单向或者双向。

可以通过发送数据来创建流。其他与流管理有关的操作——终止、取消、流量控制管理——都是最小开销设计的。比如，单个STREAM帧可以打开流，传输数据，并关闭流。流也可以长时间存活，并在连接的整个生命周期中保持。

流可以被任意一个终端创建，可以和其他交织的流同时发送数据，并可以被取消。QUIC不提供在不同流之间保证字节顺序的方法。

在流量控制约束和流限制的前提下，QUIC允许任意数量的流同时运行，也允许任意流上发送任意数量的数据；参考第4章。

## 2.1. Stream Types and Identifiers

Stream可以是单向或者双向。单向流在一个方向上传输数据：从流的发起者送往对端。双向流允许在两个方向上传输数据。
一个连接内，通过一个叫做stream ID的数字值来区分流。 stream ID是一个62位长度的整数（0 to 2^62-1），在一个连接内唯一。stream ID是变长整数；参考第16章。QUIC终端必须不能（MUST NOT）在一条连接内重复使用相同stream ID。

stream ID的最低位(0x1)标识了stream的发起方。客户端发起的stream ID是偶数（低位为0），服务端发起的stream ID为奇数（低位为1）。

stream ID倒数第2位(0x2)标识单向 / 双向，双向是0，单向是1。

因此，stream ID的最低两位共有4种值，详见下表：

```
                +======+==================================+
                | Bits | Stream Type                      |
                +======+==================================+
                | 0x0  | Client-Initiated, Bidirectional  |
                +------+----------------------------------+
                | 0x1  | Server-Initiated, Bidirectional  |
                +------+----------------------------------+
                | 0x2  | Client-Initiated, Unidirectional |
                +------+----------------------------------+
                | 0x3  | Server-Initiated, Unidirectional |
                +------+----------------------------------+

                          Table 1: Stream ID Types
```

每种类型的流空间从最小值开始(分别为0x0到0x3)；每种类型的连续流以数值递增的stream ID创建。
如果不按顺序使用stream ID，则导致该类型中所有低序号stream ID对应的流都会被打开。

## 2.2. Sending and Receiving Data

Stream frames用来承载应用发出的数据。终端通过STREAM帧中的stream ID和Offset字段来有序处理数据。

终端必须（MUST）能够以有序字节流的形式，为上层应用提供数据。这要求终端能够约定的流量控制限制内，缓存所有乱序接收的数据。

QUIC不定义具体乱序发送流数据的方法。但实现可以（MAY）选择提供乱序发送乱序数据到接收端应用的能力。

终端有可能在一个流中，多次收到同一个offset的流数据。重复收到的数据可以丢弃。对于给定offset的data数据，它在被offset必须不能（MUST NOT）改变；如果终端在一个流通道内，收到相同offset字段但内容不同的数据，可以（MAY）将其当做是PROTOCOL_VIOLATION类型的连接错误。

QUIC流对于QUIC来说，只有有序字节流抽象的概念，没有任何其他可见的结构。当STREAM帧被传输、丢失重传、回调给接收端的应用，不应该保护STREAM帧的边界。

终端必须不能（MUST NOT）在没有确认是否超过对端的流控限制的情况下，在任何流通道中发送数据。流控详见第4章。

## 2.3. Stream Prioritization

当流通到多路复用时，如果分配给流的资源具有合理的优先级，能够显著地影响应用的性能。

QUIC本身不提供优先级信息交换的机制。相反，这种机制需要从上层应用获取优先级信息来实现。

QUIC实现应当（SHOULD）为上层应用提供设定优先级的途径。实现使用应用程序提供的信息来决定如何为活动流分配资源。

## 2.4. Operations on Streams

本文档没有定义QUIC的API，而是定义了一组应用协议可以依赖的流上的函数。应用协议可以假定QUIC实现提供了一个包括本节所述操作的接口。为特定应用协议而设计的实现可能只提供该协议所使用的操作。

在一个stream的发送端，应用协议可以：

* 写数据，能够理解预留流通道流量控制信用来发送已写数据的时机；
* 结束流（文明终止）：产生一个设置了FIN位的STREAM帧（19.8节）；
* 重置流（粗暴终止）：如果一个流不处于终止状态，产生一个RESET_STREAM帧（19.4节）。

在stream接收端，应用协议可以：

* 读数据；
* 停止读并请求关闭，可能产生一个STOP_SENDING帧（19.5节）。

流上状态改变后，需要通知应用，包括对端开启或者重置steam时、对端停止一个流的读操作时、新数据可用时、因流控可以/不可以数据写数据到流中时。

# 3. Stream States

本章描述stream的发送和接收组件，包括两种状态机：发送数据的终端的流状态机（3.1节），接收数据的终端的流状态机。

单向流根据流类型和终端角色使用发送或接收状态机，双向流在两个终端同时使用两种状态机。
在大多数情况下，无论流是单向的还是双向的，这些状态机的使用方法都是相同的。
对于双向流来说，打开流的条件稍微复杂一些，因为发送侧或接收侧的打开都会导致流在两个方向上打开。

这些状态信息量巨大。本文使用了流状态来描述发送不同类型的帧的时机和方式，以及收到不同类型的帧时候的时机和方式。这些状态机的设计本意是帮助实现QUIC，而不是用来约束实现。只要实现的行为和这些状态机一致，就可以定义不同的状态机。

注意：在某些情况下，单个事件或动作可以引起多个状态的转换。 例如，发送设置了FIN位的STREAM可以导致发送流的两个状态转换：从Ready状态到Send状态，以及从Send状态到Data Sent状态。

## 3.1. Sending Stream States

下图展示了向对端发送数据的流的态机：

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

               Figure 2: States for Sending Parts of Streams
```

应用发起了流的发送部分（客户端类型为0和2，服务端类型为1和3）。“Ready”状态表示流是新创建的，能够从应用接收数据。可以在这个阶段缓存流数据用于后续的发送。

发送第一个STREAM或者STREAM_DATA_BLOCKED frame会使得当前流进入“Send”状态。QUIC实现可以选择在发送第一个STREAM帧并进入"Send"状态之后，才为这条流生成stream ID，以便实现更好的流优先级。

在被动打开的双向流（服务端类型为0，客户端类型为1）中，当它的接收部分完成创建，它的发送部分就会进入到“Ready”状态。

在“Send”状态下，终端会通过STREAM帧来传输和重传流数据。终端需要遵循对端设置的流量控制限制，并继续接受和处理MAX_STREAM_DATA帧来更新流量控制限制。如果处于“Send”状态的终端，达到了流级别的流控限制（第4.1节），它的发送就会被阻塞，并会生成STREAM_DATA_BLOCKED帧。

如果应用层发现所有的stream data都已经被发送完毕，并且FIN标识位已经被发送，这时流的发送部分就会进入”Data Sent”状态。从这个状态开始，终端只能发送需要重传的数据。这个状态下，终端不需要检查流控限制，也不需要发送STREAM_DATA_BLOCKED帧。终端有可能在对端收到最终stream offset之前，收到MAX_STREAM_DATA帧。在这个状态下，终端可以安全地忽视所有从对端收到的MAX_STREAM_DATA帧。

一旦所有的stream data都被确认收到，流的发送部分就进入“Data Recvd”状态，这是个终止状态。

在“Ready”、“Send”、“Data Sent”这些状态中，应用可能希望中断流数据的传输并通知对端。终端有可能从对端收到STOP_SENDING frame。在这两种情况下，终端会发送一个RESET_STREAM帧，这个帧将使得stream进入“Reset Sent”状态。

终端可以（MAY）将RESET_STREAM帧作为一个流上的第一个帧。这将使这条流的发送部分被打开，并立刻进入“Reset Sent”状态。

一旦包含RESET_STREAM的packet被确认收到，流的发送部分就会进入“Reset Recvd”状态，这也是一个终止状态。

## 3.2. Receiving Stream States

图3展示了流的接收部分从对端接收数据时的状态。流的接收部分只对应了对端流的发送部分部分状态。流的接收部分不会追踪流发送部分中那些无法感知的状态，比如“Ready”状态。相反，流的接收部分追踪了递交给应用的数据，并且一些数据无法被发送端觉察到。

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

              Figure 3: States for Receiving Parts of Streams
```

对于对端初始化的流的接收模块，当终端在一个本地还没打开的流中，从对端（客户端类型是1和3，服务端类型是0和2）收到了第一个STREAM、STREAM_DATA_BLOCKED或RESET_STREAM帧，就会创建这条流的接收模块。对于由对端发起的双向流，当在流的发送模块中收到MAX_STREAM_DATA或STOP_SENDING帧时，也会创建流的接收模块。流的接收模块的初始状态是“Recv”。

对于双向流，当终端（客户端类型为0，服务端类型为1）主动打开的发送模块进入“Ready”状态，流的接收模块的就会进入到“Recv”状态。

如果终端在一个本地还未打开的流中，从对端收到了MAX_STREAM_DATA帧或者STOP_SENDING帧，就会打开一个双向流。在本地未打开的流上收到MAX_STREAM_DATA帧表示远端已经打开了流，并且开启了流量控制限制。在一个本地未打开的流上收到STOP_SENDING帧意味着远端不再期望在这个流上接收数据。如果发生了丢包或者乱序，MAX_STREAM_DATA帧或STOP_SENDING帧都可能比STREAM或STREAM_DATA_BLOCKED帧先到。

在创建一条流之前，必须（MUST）创建所有跟这条流类型相同，但流ID更小的流。这保证了两端创建的流都是连续的。

在“Recv”状态下，终端会接收STREAM 和 STREAM_DATA_BLOCKED frame。收到的数据被缓存，并重组成正确的顺序，然后被投递给应用层。应用层消费了这些数据之后，缓存处于空闲状态，可用于后续的数据接收，终端发送MAX_STREAM_DATA 帧来允许对端发送更多的数据。

当收到携带FIN标识位的STREAM帧，终端就可以知晓这条流上最终的数据量；参考4.4节。流的接收模块就会进入“Size Known”状态。在这个状态下，终端不再需要发送MAX_STREAM_DATA frame，它只需要接收重传的数据。

一旦收到了所有的流数据，接收模块就进入了“Data Recvd”状态。这可能是收到相同的带FIN标识位的STREAM帧的结果。在这种状态下，终端已经获取了所有的数据。后续收到的STREAM或STREAM_DATA_BLOCKED frame都可以被丢弃。

“Data Recvd”状态保持到所有的数据被传递给应用层。一旦流数据被传递完毕，这条流就进入了“Data Read”状态，这是个终止状态。

在“Recv”或“Size Known”状态下，接收到“RESET_STREAM”帧会使得流进入“Reset Recvd”状态。这可能中断流数据向应用层的传递。

收到RESET_STREAM帧的时候（在”Data Recvd”状态下收到），有可能已经接收了所有的流数据。类似的情况还有，收到RESET_STREAM帧之后收到剩余的流数据（在”Reset Recvd”状态下）。实现可以按照自己的方案来处理这些情况。

发送RESET_STREAM意味着终端不能保证流数据的传输；这并不表示后续就不传输流数据了。实际实现可以（MAY）中断流数据的传输，丢弃还没被消费的数据，并且立刻发送信号表明收到了RESET_STREAM。如果已经收到了所有的流数据，但还没有被应用读取，RESET_STREAM帧可能会被忽略或抑制。如果忽略了RESET_STREAM帧，流的接收部分保持“Data Recvd”状态。

一旦应用层接收到信号表明当前流被重置，流的接收部分就会进入“Reset Read”状态，这也是个终止状态。

## 3.3. Permitted Frame Types

发送方仅有三种类型的帧会触发发送方或接收方的状态变化：STREAM帧（19.8节）、STREAM_DATA_BLOCKED（19.13节）、RESET_STREAM（19.4节）。

发送方必须不能（MUST NOT）在终止状态（“Data Recvd”或“Reset Recvd”）发送以上这些帧。发送方必须不能（MUST NOT）在处于“Reset Sent”状态（发送了REST_STREAM帧之后）或任何终止状态下，发送STREAM帧或STREAM_DATA_BLOCKED帧。但因为携带者三种帧的包出现延迟，因此接收方可能在任何状态下收到这三种frame。

接收方可以发送MAX_STREAM_DATA帧（19.10节）和STOP_SENDING帧（19.5节）。

接收方只有在“Recv”状态下才会发送MAX_STREAM_DATA帧。只要接收方还没有收到RESET_STREAM帧（也就是在除“Reset Recvd”和“Reset Read”以外的任何状态下），发送STOP_SENDING帧。然而在“Data Recvd”状态下发送STOP_SENDING的意义不大，因为所有的数据已经被接收到了。因为携带MAX_STREAM_DATA或STOP_SENDING帧的包可能出现延迟，发送方可能在任何状态下接收这两种帧。

## 3.4. Bidirectional Stream States

双向流由发送和接收部分组成。实现可以将双向流的状态表示为发送和接收流状态的组合。最简单的模型是当发送或接收部分处于非终止态时，将流表示为"open"状态，当发送和接收流都处于终止态时，将流表示为"closed"状态。

表2列出了更复杂的双向流状态的映射，它与HTTP/2 [HTTP2] 中的流状态大致对应。
这表明，流的发送或接收部分的多个状态被映射到同一个复合状态。
请注意，这只是这种映射的一种可能性，此映射要求在过渡到"closed"或"half-closed"状态之前确认数据。

```
     +======================+======================+=================+
     | Sending Part         | Receiving Part       | Composite State |
     +======================+======================+=================+
     | No Stream/Ready      | No Stream/Recv *1    | idle            |
     +----------------------+----------------------+-----------------+
     | Ready/Send/Data Sent | Recv/Size Known      | open            |
     +----------------------+----------------------+-----------------+
     | Ready/Send/Data Sent | Data Recvd/Data Read | half-closed     |
     |                      |                      | (remote)        |
     +----------------------+----------------------+-----------------+
     | Ready/Send/Data Sent | Reset Recvd/Reset    | half-closed     |
     |                      | Read                 | (remote)        |
     +----------------------+----------------------+-----------------+
     | Data Recvd           | Recv/Size Known      | half-closed     |
     |                      |                      | (local)         |
     +----------------------+----------------------+-----------------+
     | Reset Sent/Reset     | Recv/Size Known      | half-closed     |
     | Recvd                |                      | (local)         |
     +----------------------+----------------------+-----------------+
     | Reset Sent/Reset     | Data Recvd/Data Read | closed          |
     | Recvd                |                      |                 |
     +----------------------+----------------------+-----------------+
     | Reset Sent/Reset     | Reset Recvd/Reset    | closed          |
     | Recvd                | Read                 |                 |
     +----------------------+----------------------+-----------------+
     | Data Recvd           | Data Recvd/Data Read | closed          |
     +----------------------+----------------------+-----------------+
     | Data Recvd           | Reset Recvd/Reset    | closed          |
     |                      | Read                 |                 |
     +----------------------+----------------------+-----------------+

            Table 2: Possible Mapping of Stream States to HTTP/2
```

注意：idle状态指的是一条stream还没被创建、或者作为接收方在”Recv”状态下还没有收到任何数据。

## 3.5. Solicited State Transitions

如果应用对一个流上收到的数据不再感兴趣，它可以停止流的读取并定义一个应用错误码。

如果流处于“Recv”或者“Size Known”状态，传输应当（SHOULD）通过发送一个STOP_SENDING帧来通知对端，并让对端处理流的关闭。这通常表示接收方应用不再读取它从流上接收的数据，但不保证收到的数据会被无视。

在STOP_SENDING之后接收到的STREAM frame仍然会消耗流控资源，尽管这些frame会被丢弃。

STOP_SENDING帧要求接收方终端发送一个RESET_STREAM帧。
如果流处于"Ready"或"Send"状态，收到STOP_SENDING帧的终端必须发送RESET_STREAM帧。
如果流处于"Data Send"状态，终端可以推迟发送RESET_STREAM帧，直到包含未完成数据的数据包被确认或宣布丢失。如果任何未完成的数据被宣布丢失，终端应该发送RESET_STREAM帧，而不是重传数据。

终端应该将错误码从STOP_SENDING帧复制到它发送的RESET_STREAM帧中，但可以使用任何应用程序错误码。发送STOP_SENDING帧的终端可以忽略随后收到的该流的任何RESET_STREAM帧中的错误码。

STOP_SENDING应当（SHOULD）只在stream还没有被reset之前发送。在”Recv”和”Size Known”状态下是有效的。

如果前一个STOP_SENDING丢包了，终端应当重传这个STOP_SENDING。然而如果所有的数据都已经被接收到的情况下，重传就不必要了。

终端想要终止一条双向stream的最好方式是发送RESET_STREAM，可以发到关闭一端的效果，并建议对端关闭另一个方向。

# 4. Flow Control

接收方需要限制它们需要缓冲的数据量，以防止快速发送者不堪重负，或防止恶意发送者消耗大量的内存。
为了使接收方能够限制连接的内存承诺，可以对流进行单独控制，也可以对整个连接进行流控。
QUIC接收方控制发送方随时都可以在一个流及所有流上发送的最大数据量，如第4.1节和第4.2节所述。

同样，为了限制连接内的并发量，QUIC终端会限制其对端可以发起的最大累计stream数量，如第4.6节所述。

以CRYPTO帧发送的数据与流数据的流控方式不同。QUIC依靠加密协议实现来避免数据的过度缓冲，见[QUIC-TLS]。为了避免在多层上过度的缓冲，QUIC实现应该为加密协议实现提供一个接口，以传达其缓冲限制。

## 4.1. Data Flow Control

QUIC采用了一种基于限制的流控方案，在这种方案中，接收方会公布它准备在给定流上或整个连接中能够接收的总字节数限制。这使得QUIC中数据流控分2层：

* Stream级别流控：通过限制每个流上可发送的数据量，防止单个流消耗连接的整个接收缓冲区。
* Connection级别流控：通过限制所有流上STREAM帧中发送的流数据的总字节数，防止发送方超过接收方的连接缓冲区容量。

发送方不能发送超过任何一个限制的数据。

接收方在握手过程中通过传输参数设置所有流的初始限制（第7.4节）。
随后，接收方发送MAX_STREAM_DATA（第19.10节）或MAX_DATA（第19.9节）帧给发送方，通知更大的限制。

接收方可以通过发送一个MAX_STREAM_DATA帧和相应的stream ID，来为流通告更大的限制。
MAX_STREAM_DATA帧指示一个流的最大绝对字节偏移量。
接收方可以基于在该流上消耗的数据的当前偏移量来确定要通告的流控偏移量。

接收方可以通过发送MAX_DATA帧，来通告连接的更大限制。
MAX_DATA帧表示所有流的绝对字节偏移量之和的最大值。
接收方维护所有流上接收到的字节的累积总和，用来检查是否违反了通告中的连接或流数据限制。
接收方可以根据所有流上消耗的字节数总和来决定要通告的最大数据限制。

接收者发布连接或流的限制后，发布较小的限制并不是错误，但是较小的限制无效。

如果发送方违反了公告的连接或流数据限制，接收方必须以FLOW_CONTROL_ERROR错误（第11节）关闭连接。

发送方必须忽略任何不增加流控限制的MAX_STREAM_DATA或MAX_DATA帧。

如果发送方已经发送的数据达到了限制，它将无法发送新的数据，并被视为阻塞。
发送方应该发送一个STREAM_DATA_BLOCKED或DATA_BLOCKED帧来向接收方表明它有数据要写，但被流控限制阻塞了。如果发送方被阻塞的时间超过了空闲超时（idle timeout，10.1节），即使发送方有数据可供传输，接收方也可能关闭连接。
为了防止被连接关闭，当链路上没有发送者发送的可以触发ack的包，发送者应当（SHOULD）周期性的发送STREAM_DATA_BLOCKED/DATA_BLOCKED帧

## 4.2. Increasing Flow Control Limits

由实现决定何时在MAX_STREAM_DATA帧和MAX_DATA帧中通告多大的流控信用，但本节提供了一些注意事项。

为了避免阻塞发送端，一个接收端可以在一个往返中多次发送MAX_STEAM_DATA/MAX_DATA帧，或者足够提前发送MAX_STEAM_DATA/MAX_DATA帧，以便给帧的丢失和后续恢复留出时间。

控制帧会增加连接消耗。因此如果数值本身没有太多变化，不建议频繁发送MAX_STREAM_DATA/MAX_DATA帧。同时，为了防止因为更新不频繁而导致阻塞发送方，接收方有必要使用大一点的增量。因此在通告流控限制大小的时候，需要在资源和流量之间做权衡。

接收方可以使用自动调优机制，根据往返时间估计和接收应用程序消耗数据的速率，来调整通告的额外信用的频率和数量，这与常见的TCP实现类似。作为一种优化，终端可以只在有其他帧要发送时才发送与流控相关的帧，确保流控不会导致额外的数据包被发送。

被阻塞的发送方不需要发送STREAM_DATA_BLOCKED或DATA_BLOCKED帧。因此，接收方不能（MUST NOT）等待STREAM_DATA_BLOCKED or DATA_BLOCKED frame来调整发送MAX_STREAM_DATA or MAX_DATA，这样做可能导致发送者在连接的后续生命周期中一直被阻塞。即使发送者发了这些帧，也会导致发送者至少被阻塞一个RTT。

当一个被阻塞的发送者重新有了窗口，可能能够一下子发送大量数据，从而导致短期的拥塞；7.7节描述了如何来避免这种拥塞。

## 4.3. Flow Control Performance

如果一个终端不能确保其对端在这个连接上的可用流控信用始终大于对端的带宽时延积，则其接收吞吐量将受到流控的限制。

数据包丢失会造成接收缓冲区出现间隙，使应用无法消耗数据并腾出接收缓冲区空间。 

及时发送流控限制的更新可以提高性能。 只发送数据包以提供流控更新会增加网络负载，对性能产生不利影响。 将流控更新与其他帧（如ACK帧）一起发送，可以降低这些更新的成本。  

## 4.4. Handling Stream Cancellation

终端最终需要就每个流上消耗的流控信用量达成一致，才能对连接级流控的所有字节进行核算。

在收到RESET_STREAM帧时，终端将移除匹配流的状态，并忽略该流上到达的其他数据。

RESET_STREAM会突然终止流的一个方向。对于双向流，RESET_STREAM对相反方向的数据流没有影响。
两个终端都必须对未终止方向的数据流保持流控状态，直到该方向进入终止状态。

## 4.5. Stream Final Size

Final size 是指一个流所消耗的流控信用量。
假设流上的每个连续字节都被发送一次，final size 就是发送的字节数。
一般而言，此值比流中发送的具有最大偏移量的字节的偏移量高1；如果未发送任何字节，则为零。

无论流如何终止，发送方始终将流的final size可靠地传达给接收方。Final size是带有FIN标志的STREAM帧的Offset和Length字段的总和，请注意，这些字段可能是隐式的。另外，RESET_STREAM帧的Final Size字段也会携带这个值，这保证了两个终端都同意发送者在该流上消耗了多少流控信用。

当流的接收部分进入 "Size Known" 或 "Reset Recvd" 状态时，终端将知道流的Final size（第3节）。
接收方必须使用流的Final size来说明在其连接级流控制器中发送的所有字节。

终端不得（MUST NOT）在流上以Final size或超出Final size发送数据。

 一旦流的Final size被知道，就不能被修改。如果接收到RESET_STREAM或STREAM帧，表明流的Final size发生了变化，终端应该用FINAL_SIZE_ERROR错误来响应（见第11节）。接收方也应将接收到的Final size或超出Final size的数据视为FINAL_SIZE_ERROR错误，即使在流被关闭后也是如此。产生这些错误并不是强制性的，因为要求终端产生这些错误也意味着终端需要为已关闭的流保持Final size状态，这可能意味着一个重要的状态承诺。

## 4.6. Controlling Concurrency

终端限制对端可以打开的传入流的累计数量。
只有流ID小于（max_stream * 4 + initial_stream_id_for_type）的流才能被打开（见表1）。
初始限制在传输参数中设置（见第18.2节）。随后的限制使用MAX_STREAMS帧进行公告（见第19.11节）。 
单向流和双向流是独立控制的。

如果一个传输参数中的max_streams或者MAX_STREAMS帧中的数值大于2^60，会导致无法用变长整数来表示最大stream ID（见第16节）。如果收到了，连接必须立即关闭。
如果在传输参数中收到了违规值，连接错误类型为 TRANSPORT_PARAMETER_ERROR；
如果在帧中收到了违规值，连接错误类型为 FRAME_ENCODING_ERROR；参见第 10.2 节。

终端不得超过其对端设置的限制。
如终端点收到的帧的流ID超过了它发送的限制，则必须将其视为类型为STREAM_LIMIT_ERROR的连接错误（第11节）。

一旦接收方使用MAX_STREAMS帧通告流限制，再通告较小的限制就没有效果。接收方必须忽略任何不增加流限制的MAX_STREAMS帧。

与流级别和连接级别的流控一样，本文让实现决定什么时候以及应该通过MAX_STREAMS向对端通告多少个流。
实现可能会选择在流被关闭时增加限制，以保持对端可用的流数量大致一致。

由于对端的限制而无法打开新流的终端应该发送一个STREAMS_BLOCKED帧（第19.14节）。这个信号对debug是有用的。 终端绝不能等待收到这个信号后才发布额外的信用，因为这样做意味着对端将被阻塞至少一个RTT，如果对端选择不发送STREAMS_BLOCKED帧，则可能无限期地被阻塞。

# 5. Connections

QUIC连接是客户端和服务端之间的共享状态。

每个连接都从握手阶段开始，在这个阶段，两个终端使用加密握手协议[QUIC-TLS]建立一个共享密钥，并协商应用层协议。握手(第7节)确认两个终端都愿意通信(第8.1节)，并建立连接参数(第7.4节)。

应用层协议可以在握手阶段使用该连接，但有一些限制。
0-RTT允许客户端在收到服务端的响应之前发送应用数据。然而，0-RTT不提供对重放攻击的保护（见[QUIC-TLS]的第9.2节）。
服务端还可以在收到最后的加密握手消息之前向客户端发送应用数据，使其能够确认客户端的身份和活跃度。
这些功能使得应用层协议可以提供以降低延迟来换取一些安全保证的选择。

Connection ID的使用（第5.1节）允许连接迁移到新的网络路径，既可以作为终端的直接选择，也可以在中间件变化的情况下被迫迁移。第9节描述了与迁移相关的安全和隐私问题的缓解措施。

对于不再需要或不需要的连接，客户端和服务端有几种终止连接的方法，如第10章所述。

## 5.1. Connection ID

每条连接有多个connection ID，每一个都可以标识这条连接。
connection ID由两端独立选取，每一个终端为它的对端选择使用的connection ID。

connection ID的基本功能是用来在底层（UDP，IP层）的地址发生变化时，仍能够使得QUIC连接内的packet被送达正确的终端。connection ID除了被用来保证路由的正确性之外，还被接收方终端用来识别packet属于哪条连接。

使用多个connection ID，这样终端就可以发送那些，在没有终端配合的情况下观察者无法识别为同一连接的数据包，见9.5节。

connection ID不能（MUST NOT）包含任何可以被用来关联同一条连接内其他的connection ID的信息。一条连接内，connection ID不能（MUST NOT）被声明多次。

long header packet包含Source Connection ID 和 Destination Connection ID字段（详细见7.2节）。

short header packet只包含Destination Connection ID，且不包含长度字段。长度字段在前面的包里已经声明。终端使用根据connection ID做转发的负载均衡设备(load balancer)，可以约定使用固定的connection ID长度，或者约定一个编码scheme。

服务端在Version Negotiation packet（第17.2.1节）内容里面回应客户端选择的connection IDs，一方面是为了保证应答包被正确地路由到客户端，另一方面是证明该数据包是响应客户端发送的数据包。

长度为0的connection ID是有可能出现的，当connection ID字段不再被需要用来做路由标识，这种情况下可以用地址/端口作为替代的路由标识。然而基于相同IP和端口，且使用了零长CID的多路复用连接，无法在连接迁移、NAT重绑定、客户端端口重用的场景下使用。
终端绝不能（MUST NOT）使用相同的IP地址和端口进行多个零长CID的并发连接，除非确定没有使用这些协议功能。

当一个终端使用非零长的CID时，它需要确保对端具有CID的供应，从中可以选择发送到终端的数据包。
这些CID由终端使用NEW_CONNECTION_ID帧提供（第19.15节）。

### 5.1.1. Issuing Connection IDs

每个CID都有关联的序列号，可以用于检测是否NEW_CONNECTION_ID或RETIRE_CONNECTION_ID帧涉及了同一个值。在握手阶段，终端通过长包头的SCID字段来发行的初始CID。初始CID的序列号是0. 如果发送了preferred_address传输参数，提供的CID的序列号就是1。

NEW_CONNECTION_ID frame用来协商额外的connection ID。每个新声明的connection ID对应的sequence number必须（MUST）每次递增1。客户端为它发送的第一个DCID字段选择的CID和Retry packet提供的任何CID都不分配序列号。

当终端发行了一个connection ID之后，它必须（MUST）接受在整个连接生命周期中所有携带了这个connection ID的包，直到对端使用RETIRE_CONNECTION_ID将这个connection ID废弃。已发行但未回收的的CID是有效的；任何有效的CID都可以在当前连接的任何时刻、任何包类型中使用。包括服务端通过preferred_address传输参数发行的CID。

终端应当（SHOULD）保证它的对端有足够多可用和未使用的CID。终端使用了active_connection_id_limit传输参数来通告他们愿意维护的有效CID的数量。终端提供的CID数量必须不能（MUST NOT）超过对端的限制。如果终端发送的NEW_CONNECTION_ID帧，在Retire Prior To字段中包含一个足够大的值，打算回收了足够多的CID，终端发送的cid可以（MAY）暂时超过对端的限制。

NEW_CONNECTION_ID帧可能触发终端添加更多有效CID，并根据Retire Prior To字段的值回收其他CID。在处理了NEW_CONNECTION_ID帧和添加有效CID之后，如果有效CID超过了终端的active_connection_id_limit传输参数限制，终端必须（MUST）以CONNECTION_ID_LIMIT_ERROR类型的错误关闭连接。

当对端回收一个CID的时候，终端应当（SHOULD）提供一个新的CID。如果终端提供的CID比对端active_connection_id_limit的数量少，当它收到的包携带了一个之前未使用的CID，它可以（MAY）提供一个新的CID。终端可以（MAY）限制每个连接发行的CID的总量，从而来避免CID耗尽的风险；参考10.3.2。终端也可以（MAY）限制CID的发行来减少它维护的每条链路状态的数量，比如路径校验状态，因为它的对端可能在每个CID上建立一条链路和它进行交互。

发起了迁移并要求非零长CID的终端，应当（SHOULD）保证它提供给它对端的CID池允许对端在迁移的时候使用新的CID，否则如果CID池耗尽，对端将无法响应。

在握手过程中选择零长CID的终端无法发出新的CID。在通过任何网络路径向这样的终端发送的所有数据包中，都会使用零长的DCID字段。

### 5.1.2. Consuming and Retiring Connection IDs

终端可以在连接的任意时刻改变它为对端使用的CID。终端在对端迁移的时候消耗CID；详见9.5节。

终端维护了从对端收到的一套CID，当发包的时候，可以使用任意一个。当终端不再想使用某个CID时，它就给对端发送一个RETIRE_CONNECTION_ID帧。这表明不再会使用这个CID，并要求对端通过NEW_CONNECTION_ID帧来发送一个新的CID来替换这个CID。

如9.5节所述，终端限制了一个本地地址到一个目的地址之间发送的包对CID的使用。当CID不再有效使用CID对应的本地地址或目标地址，终端应当（SHOULD）回收CID。

某些特性场景下，终端可能需要停止接受之前发行的CID。终端给对端发送一个NEW_CONNECTION_ID帧，且携带了增长的Retire Prior To字段，就可以让对端回收CID。终端应当（SHOULD）继续接受之前发行的CID，直到它们被对端回收。如果终端不再能够处理指定的CID，它可以（MAY）关闭连接。

一旦收到增长的Retire Prior To字段，对端必须（MUST）停止使用对应的CID，并在将新增的CID添加到有效CID集合中之前，使用RETIRE_CONNECTION_ID帧回收这些将要停止使用的CID。这个顺序使终端可以替换所有有效CID，同时避免没有可用CID、超过对端active_connection_id_limit传输参数限制的情况；参考18.2节。如果停止使用要求的CID失败，由于对端可能不能够在活动的连接上使用CID，所以可能导致连接失败。

终端应当（SHOULD）限制它本地回收且还没有被确认的CID的数量。终端应当（SHOULD）允许发送并追踪active_connection_id限制两倍数量的RETIRE_CONNECTION_ID帧。终端必须不能（MUST NOT）在没有回收一个CID的前提下遗忘一个CID，尽管它可以（MAY）将需要被回收的CID超过这个限制的情况当成CONNECTION_ID_LIMIT_ERROR类型的连接错误。

终端在接收RETIRE_CONNECTION_ID帧之前不应发布 Retire Prior To字段的更新，这些帧将撤销由先前Retire Prior To值指示的所有CID。

## 5.2. Matching Packets to Connections

接收到的数据包会在收到时进行分类。数据包可以与现有的连接相关联，或者，对于服务端来说，可能会创建一个新的连接。 

终端会尝试将数据包与现有的连接关联起来。 如果数据包具有与现有连接相对应的非零长的DCID，QUIC将相应地处理该数据包。请注意，一个连接可以关联多个CID（见第 5.1 节）。

如果DCID为零长，并且数据包中的地址信息与终端用来识别具有零长CID的连接的地址信息相匹配，则QUIC将该数据包作为该连接的一部分进行处理。 终端可以只使用目的IP和端口，也可以同时使用源地址和目的地址进行标识，尽管这样会使连接变得脆弱，如5.1节所述。   

终端可以为任何无法归属于现有连接的数据包发送无状态重置（10.3节）。无状态重置允许对端更快速地识别连接何时变得不可用。   

如果与现有连接匹配的数据包与该连接的状态不一致，则会丢弃这些数据包 例如，如果数据包指示的协议版本与连接的协议版本不同，或者如果期望的密钥可用，移除数据包保护就不成功，那么数据包就会被丢弃。   

缺乏强完整性保护的无效数据包，如Initial、Retry或Version Negotiation，可以丢弃。
如果在发现错误之前处理了这些数据包的内容，终端必须生成一个连接错误，或者完全恢复在处理过程中做出的任何更改。

### 5.2.1. Client Packet Handling

发送给客户端的包永远都携带Destination Connection ID字段（根据client选择的值填写）。同意接收Connection ID长度为0的Client可以使用address/port元组作为连接标识。根据DCID或（如果该值为零长度）本地IP地址和端口，不符合现有连接的数据包将被丢弃。

考虑到丢包和重传，客户端可能收到己方还不能生成的key加密的包。客户端可以（MAY）选择丢弃这些包，或者也可以buffer住它们等待未来可以解析的时候处理。

如果客户端收到了与最初选择版本不同的包，它必须（MUST）丢弃。

### 5.2.2. Server Packet Handling

如果服务端收到表明不支持的版本的数据包，并且如果数据包大到足以为任何支持的版本发起新的连接，服务器应该如第6.1节所述发送一个Version Negotiation packet。服务端可以用Version Negotiation packet来限制它响应的数据包数量。服务端必须（MUST）丢弃指定不支持版本的较小数据包。

不支持版本的第一个数据包可以对任何特定于版本的字段使用不同的语义和编码。特别是，不同版本可能使用不同的数据包保护密钥。不支持特定版本的服务端不太可能能够解密数据包的有效载荷或正确解释结果 只要数据报足够长，服务器应该以Version Negotiation packet来响应。 

具有支持的版本或没有版本字段的数据包将使用CID或本地地址和端口（对于具有零长CID的数据包）与连接匹配。 这些数据包使用选定的连接进行处理；否则，服务端将继续下面的工作。

如果数据包是完全符合规范的Initial包，服务器就进行握手（第7节）。这就使服务端提交到客户端选择的版本。  

如果服务端拒绝接受一个新的连接，它应该（SHOULD）发送一个包含CONNECTION_CLOSE帧的Initial包，错误码为CONNECTION_REFUSED。  

如果数据包是0-RTT数据包，服务器可以（MAY）缓冲一定数量的这些数据包，等待接下来可能收到的Initial包。 

客户端不能在收到服务端响应之前发送Handshake数据包，所以服务端应该忽略任何此类数据包。  

在所有其他情况下，服务端必须丢弃传入的数据包。

### 5.2.3. Considerations for Simple Load Balancers

服务器集群可能只采用源IP地址端口和目标IP地址端口，在服务器之间进行负载均衡。客户端IP地址或者端口改变之后，
可能导致数据包被转发给错误的服务器。这样的集群部署可以使用以下方法中的一种来保证连接的延续性：

* 服务器可以使用一个带外机制，通过CID来将数据包转发至正确的服务器
* 如果服务器可以使用一个专用的IP或者端口，而不是客户端一开始连接的那个，那么它们就可以使用preferred_addrss传输参数来要求客户端连到那个专用的地址。值得注意的是客户端可以选择不用偏好地址。

集群中的服务器如果没有维护连接连续性的主机，在连接迁移的时候应当（SHOULD）使用disable_active_migration传输参数来禁止迁移。

使用了这中简单负载均衡机制的服务集群必须（MUST）避免创建一个无状态的reset oracle（见21.11节）。

## 5.3. Operations on Connections

本文没有定义QUIC的API，而是定义了一套应用层协议可以依赖的QUIC连接功能。应用层协议可以假定QUIC的实现提供了一个包括本节所述操作的接口。为特定应用层协议而设计的实现可能只提供该协议所使用的操作。

当实现客户端的时候，应用层协议可以：

* 可以打开一个连接，并开始第7章中描述的交互；
* 当可以使用的时候，使能Early data；
* Early data被服务端接收或拒绝，都要能够被知会到；

当实现服务端的时候，应用层协议可以：

* 监听连接请，为第7章中描述的交互作准备；
* 如果支持Early data，把受应用控制的数据嵌入到发送给客户端的TLS解密密钥；
* 如果支持Early data，从客户端的恢复密钥中提取出应用控制数据，并根据这个信息来接收或拒绝Early data；

无论什么角色，应用层协议可以：

* 在传输参数交换中，配置每个类型流的最小初始值；
* 通过为流和连接设置流控限制，控制接收缓冲区的资源分配；
* 识别握手是否完成或仍在进行；
* 通过生成PING帧(第19.2节)或要求传输在idle timeout超时之前发送额外的帧(第10.1节)，防止连接悄然关闭；
* 立刻关闭连接。

# 6. Version Negotiation

版本协商允许服务端指示它不支持客户端使用的版本。服务端对每个可能创建新的连接的包都响应一个版本协商包（详细信息见第5.2节）。

客户端发送的第一个数据包的大小将确定服务器是否发送版本协商数据包。
支持多个QUIC版本的客户端应确保，他们发送的第一个UDP数据报的大小应为所支持的所有版本中最小数据报大小的最大值，并在必要时使用PADDING帧（第19.1节）。这将确保服务端可以回复一个互相都支持的版本。
如果服务端接收到的数据报小于其他版本中指定的最小大小，则服务器可能不会发送版本协商包（见14.1节）。

## 6.1. Sending Version Negotiation Packets

如果客户端选择的版本不为服务端所接受，服务器将以版本协商数据包做出响应（参见第17.2.1节）。这包括服务端将接受的版本列表。终端不得发送版本协商数据包来响应接收版本协商数据包。 

该系统允许服务器在不保留状态的情况下处理不支持版本的数据包。虽然作为响应发送的Initial包或版本协商包可能会丢失，但客户端将发送新的数据包，直到成功收到响应或放弃连接尝试。   

服务端可以（MAY）限制己方发送的版本包的数量。例如，能够识别数据包为0-RTT的服务端可能会选择不发送版本协商数据包以响应0-RTT数据包，并期望它最终会收到一个Initial包。

## 6.2. Handling Version Negotiation Packets

版本协商数据包的设计是为了允许将来定义功能，允许 QUIC协商用于连接的QUIC版本。未来的标准规范可能会改变支持多个版本的QUIC的实现对收到的版本协商数据包的反应，以响应使用该版本建立连接的尝试。

一个只支持当前版本QUIC的客户端，在收到版本协商后必须（MUST）放弃连接，并产生两种异常。
一个客户端如果成功接收并处理了其他包，必须（MUST）丢弃任何版本协商包，包括提前的版本协商包。如果一个版本协商包中的版本是客户端选择的，客户端必须（MUST）丢弃这个版本协商包。

如何处理版本协商留作后续QUIC版本的工作。实际上，未来版本需要保证抵御版本降级攻击的鲁棒性。

### 6.2.1. Version Negotiation Between Draft Versions

如果草案的实现收到了一个版本协商包，它可以（MAY）从这个包中多个QUIC版本中选择一个版本，来建立一个新的连接，而不是放弃当前的连接。
客户端必须（MUST）检查DCIS/SCID和它自己发送的包中的SCID/DCID匹配。如果不匹配，必须（MUST）丢弃这个包。
如果版本协商包是有效的，客户端可以选择使用这个版本来创建新的连接。新连接必须（MUST）使用新的随机DCID，并保证与之前发送的DCID不一样。
注意这个机制不能够抵抗降级攻击，必须不能（MUST NOT）在草案实现之外使用。

## 6.3. Using Reserved Versions

为了让服务端将来使用新版本，客户端需要正确处理不支持的版本。一些版本号（如第15章定义的0x?a?a?a?a）被保留在包含版本号的字段中。 

终端可以将保留的版本号添加到任何忽略未知或不支持版本的字段中，以测试对端是否正确地忽略该值。
例如，终端可以在版本协商数据包中包含一个保留版本（见第17.2.1节）。
终端可以发送带有保留版本的数据包，以测试对端是否正确地丢弃该数据包。

# 7. Cryptographic and Transport Handshake

QUIC把加密层和传输层的握手协商结合起来，以此降低握手的延迟。
QUIC使用CRYPTO frame(格式见19.6)来传输加密层的握手包。
本文中定义的QUIC版本标识为 0x00000001，并使 [QUIC-TLS]中描述 TLS. 不同的 QUIC 版本可能表明使用了不同的加密握手协议。

QUIC提供可靠有序的加密握手数据的传递。QUIC packet保护被用来加密尽量多的握手协议内容。加密握手必须（MUST）提供如下信息：

* 经过认证的密钥交换（key exchange）, 包括：
   - 永远需要被认证的服务端
   - 可选被认证的客户端
   - 每条连接独立且互不关联的密钥
   - 用来给0-RTT和1-RTT packet加密的密钥内容
* 两个终端的传输参数值的认证交换，以及服务器传输参数的加密保护（见第7.4节）；
* 应用层协议的认证协商（TLS为此使用ALPN[ALPN]）。

CRYPTO frame可以被放在多个packet number空间中发送。用来确保加密握手数据顺序到达而使用的sequence numbers，在每个packet number空间中是从0下标开始的。

图4显示了一个简化的握手和用于推进握手的数据包和帧的交换。尽可能在握手过程中交换应用程序数据，并以'*'表示。一旦握手完成，终端就可以自由交换应用程序数据。

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

                    Figure 4: Simplified QUIC Handshake
```

终端可以使用握手期间发送的数据包来测试是否支持显式拥塞通知（ECN），见第13.4节。
终端通过观察确认其发送的第一个数据包的ACK帧是否携带ECN计数来验证对ECN的支持，如第13.4.2节所述。 

终端必须（MUST）明确地协商应用层协议，这样可以避免对使用的协议产生分歧的情况。

## 7.1. Example Handshake Flows

关于TLS如何与QUIC集成的细节在[QUIC-TLS]中提供，但这里提供一些例子。
在第8.1.2节中展示了这种交换的扩展，以支持客户端地址验证。   

当版本协商和address校验都做完之后，加密层握手就被用来协商密钥。
加密握手信息由Initial和Handshake packet携带。

图5表示了1-RTT握手协商的交互内容：
每条线的格式packet type[packet number]: frames（包含在这些packet中的）。比如说第一行表示Initial这个packet type的包，packet number是0，并且其中包含一个CRYPTO frame（包含了ClientHello）。

注意多个QUIC packets（甚至不同类型的包）可以被塞进同一个UDP datagram，因此握手流程中最少只需要4个UDP datagram，也可以由更多的UDP datagram组成（受协议固有的限制，如拥塞控制和反放大）。
比如说服务端的第一个datagram中可以同时包含Initial加密等级的包，Handshake等级，以及服务端发送的1-RTT加密等级的”0.5-RTT data”。

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

                     Figure 5: Example 1-RTT Handshake
```

图6是0-RTT握手的一个例子，其中有一个packet包含0-RTT数据。注意到12.3节，服务端在1-RTT包中对0-RTT数据进行确认，并且客户端发送的1-RTT packets是在相同的packet number空间下的。

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

                     Figure 6: Example 0-RTT Handshake
```

## 7.2. Negotiating Connection IDs

Connection ID用于确保数据包路由的一致性，如第5.1节所述。
long header包含两个CID：

* Destination Connection ID由数据包的接收方选择，用于提供一致的路由；
* Source Connection ID用于设置对端使用的Destination Connection ID。

在握手流程中，long header packets被用来协商双方使用的Connection ID。
每个终端使用Source Connection ID字段来指定己方使用的connection ID，同时这个字段会被填入对方回包的Destination Connection ID字段中。在处理完第一个Initial packet后，每个终端用它收到的Source Connection ID来填充它发送的Destination Connection ID。

当客户端发送了一个Initial packet并且它还没有收到服务端的Retry packet，这时它在Destination Connection ID字段中填充的是不可预知的随机值。这个字段必须（MUST）是至少8个字节长度的。直到收到服务端的packet，客户端必须（MUST）使用相同的connection ID，直到它放弃这条连接并开始尝试一条新连接。客户端发送的第一个Initial packet的Destination Connection ID字段用于确定给Initial packet加密的密钥。这些密钥在收到Retry packet后会改变；见[QUIC-TLS]第5.2节。

> 由于最终使用的协议版本和最初Initial packet使用的版本可能不一致，client应当（SHOULD）使用一个足够长的Destination Connection ID，可以兼容它支持的所有版本。

客户端在Source Connection ID字段里面会填充它选择的值，并在SCIL填写对应的长度。

0-RTT数据包的首次传输使用与客户端第一个Initial packet相同的DCID和SCID值。

在第一次收到服务端发送的Initial或Retry packet之后，客户端使用服务端提供的Source Connection ID作为后续报文的Destination Connection ID。这意味着客户端在建连过程中是有可能改变两次Destination Connection ID的，第一次在收到Retry时，第二次在对服务端的第一个Initial packet进行应答时。一旦客户端已经收到了服务端的Initial packet，它必须（MUST）丢弃所有收到的使用不同Source Connection ID的packet。

客户端必须（MUST）在上述2种情况下改变自己发送的Destination Connection ID（收到服务端的Retry或Initial）。服务端必须（MUST）根据收到的Initial packet来设置它自己的Destination Connection ID。只有当值取自NEW_CONNECTION_ID帧时，才允许进一步更改Destination Connection ID；如果随后的Initial packet包含不同的Source Connection ID，则必须丢弃它们。 这就避免了对具有不同SCID的多个Initial packet进行无状态处理可能导致的不可预测的结果。 

终端发送的DCID可以在连接的生命周期内改变，特别是在响应连接迁移时（第9节）；详见第5.1.1节。

## 7.3. Authenticating Connection IDs

终端在握手中的选择的CID通过在传输参数中包含所有值来进行验证。这保证了所有用于握手的CID都会被加密握手认证。

每个终端将它发送的第一个initial包的SCID字段包含在initial_source_connection_id传输参数中；
一个服务端将它收到的第一个initial包的DCID包含在original_destination_connection_id传输参数中；
如果服务端发送了Retry包，它对应的是发送Retry之前收到的第一个Initial包。
如果发送了一个retry包，服务端将把retry包的SCID字段包含在retry_source_connection_id 传输参数中。

对端提供的这些传输参数的值必须（MUST）跟终端在它发送的initial包的DCID、SCID字段的值匹配。将CID包括在传输参数中并进行认证，保证攻击者无法在握手阶段，通过插入带攻击者CID的包，来影响连接选择CID。任意终端的initial_source_connection_id传输参数缺失，或者服务端的original_destination_connection_id传输参数缺失，终端必须（MUST）将其当做是TRANSPORT_PARAMETER_ERROR的连接错误。

一个终端必须（MUST）把以下所有情况都当做TRANSPORT_PARAMETER_ERROR或PROTOCOL_VIOLATION错误：

* 服务端发来的retry包缺少retry_source_connection_id参数；
* 没收到retry包，却在传输参数中出现了retry_source_connection_id ；
* 对端的传输参数和initial包中的DCID/SCID不匹配；

如果选择了零长ID，那么对应的传输参数包含了一个零长值。

图7展示了一个完整的握手过程中CID的使用。展示了initial包的交换，以及后续的、包含了握手期间生成的CID的1-RTT包；

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

               Figure 7: Use of Connection IDs in a Handshake
```

图8展示了使用retry包进行的类似的握手：

```
   Client                                                  Server

   Initial: DCID=S1, SCID=C1 ->
                                       <- Retry: DCID=C1, SCID=S2
   Initial: DCID=S2, SCID=C1 ->
                                     <- Initial: DCID=C1, SCID=S3
                                ...
   1-RTT: DCID=S3 ->
                                                <- 1-RTT: DCID=C1

         Figure 8: Use of Connection IDs in a Handshake with Retry
```

图7和图8中的握手过程，客户端将initial_source_connection_id传输参数的值设置为C1。
在图7中，服务端将original_destination_connection_id 设置为S1，initial_source_connection_id设置为S3，且没有设置retry_source_connection_id。
在图8中，服务端将 original_destination_connection_id 设置为S1，retry_source_connection_id 设置为S2，initial_source_connection_id设置为S3。

## 7.4. Transport Parameters

在建连期间，两个终端都对其transport参数进行经过身份验证的声明。
要求终端遵守每个参数定义的限制；每个参数的描述都包括其处理规则。

这些参数由双方各自单方面宣告自己的。每个终端可以独立于其对端选择的值来决定己方的transport参数的值。
传输参数的编码格式详见第18章。

QUIC在加密层握手中包含了这些加密的传输层参数。一旦握手完成，这些被对端宣告的传输层参数信息就生效了。每个终端都会验证其对端提供的值。

完整参数列表见18.2节。

收到无效传输参数，终端必须（MUST）将其当做是TRANSPORT_PARAMETER_ERROR类型的连接错误。
终端不得（MUST NOT）在给定的传输参数扩展中发送参数超过一次。 
终端应该（SHOULD）把收到重复的传输参数作为类型为 TRANSPORT_PARAMETER_ERROR 的连接错误。 

应用层协议协商（ALPN；见[ALPN]）允许客户端在连接建立期间提供多种应用层协议。客户端在握手期间包含的传输参数适用于客户端提供的所有应用层协议。应用层协议可以为传输参数推荐值，例如初始流控制限制。但是，如果应用层协议对传输参数的值设置了约束条件，如果这些约束条件发生冲突，就会使客户端无法提供多个应用层协议。

### 7.4.1. Values of Transport Parameters for 0-RTT

使用0-RTT取决于客户端和服务端都使用从先前连接中协商的协议参数。
要启用0-RTT，终端要保存服务端传输参数的值，并在后续和同一个对端的连接中，在0-RTT包中使用这些参数。
这些数据包使用在该连接上发出的Session ticket，此信息与应用层协议或加密握手所需的任何信息一起存储；参见[QUIC-TLS]的4.6节。 

记住的传输参数适用于新的连接，直到握手完成，客户端开始发送1-RTT数据包。一旦握手完成，客户端就会使用握手中建立的传输参数。 并不是所有的传输参数都会被记住，因为有些传输参数不适用于未来的连接，或者它们对0-RTT的使用没有影响。

定义新的传输参数（7.4.2小节）必须（MUST）说明它们是否必须（MUST），可以（MAY），或必须不能（MUST NOT）作为0-RTT的参数保存。客户端无需处理它不能处理的传输参数。

客户端必须不能（MUST NOT）使用如下参数的缓存值，相反客户端必须（MUST）使用握手中的新值，而如果服务端缺少新值，则使用默认值：

* ack_delay_exponent
* max_ack_delay
* initial_source_connection_id
* original_destination_connection_id
* preferred_address
* retry_source_connection_id
* stateless_reset_token

尝试发送0-RTT数据的客户端必须（MUST）保存服务端使用的所有其他传输参数。服务端可以缓存住它使用的transport参数，或者把这些参数的加密备份放进ticket里面，用来在接收到0-RTT数据时恢复这些信息。服务端使用transport参数来决定是否接受0-RTT数据。

如果0-RTT数据被服务端接受，那么服务端不能（MUST NOT）在后续参数限制中表示不接受0-RTT数据。
特别注意，接受0-RTT数据的服务端不能（MUST NOT）调小设置以下这些参数（相对缓存值调小）：

* active_connection_id_limit
* initial_max_data
* initial_max_stream_data_bidi_local
* initial_max_stream_data_bidi_remote
* initial_max_stream_data_uni
* initial_max_streams_bidi
* initial_max_streams_uni

删除特定的传输参数，或者将特定的传输参数设置为0，可以使能0-RTT，但并不可用。应当（SHOULD）将那些控制应用数据发送的传输参数的可用子集设置为非0值。这些值包括：
initial_max_data，initial_max_streams_bidi，initial_max_stream_data_bidi_remote
或者：
initial_max_data，initial_max_streams_uni，initial_max_stream_data_uni

服务端可以（MAY）存储并恢复之前发送的 max_idle_timeout，max_udp_payload_size和disable_active_migration 参数的值，如果选择较小的值，则拒绝0-RTT。
降低这些参数的值，同时也接受0-RTT数据，可能会降低连接的性能。
具体来说，降低max_udp_payload_size可能会导致丢包，与直接拒绝0-RTT数据相比，性能更差。 

如果不支持传输参数的恢复值，服务器必须拒绝0-RTT数据。

当使用0-RTT包发送数据时，客户端必须（MUST）只使用保存的传输参数；重点：它必须不能使用从服务端的传输参数更新或1-RTT包中了解到的值。握手的传输参数中更新的值只适用于1-RTT。举个例子，保存传输参数中的流控限制适用于所有的0-RTT包，即使这些值在握手或者1-RTT中包被增加了。一个服务端可以（MAY）把在0-rtt中使用更新的传输参数的行为认为是一种PROTOCOL_VIOLATION类型的连接错误。

### 7.4.2. New Transport Parameters

新的传输参数可以用来协商新的协议行为。终端必须（MUST）忽略它不支持的传输参数。 因此，缺少传输参数会禁用任何使用该参数协商的可选协议特性 如第18.1节所述，为了执行此要求，保留了一些标识符。 

不理解传输参数的客户端可以丢弃该参数，并在后续连接中尝试使用0-RTT。
但如果客户端增加了对被丢弃的传输参数的支持，那么它在尝试0-RTT时就有可能违反传输参数所建立的约束。
新的传输参数可以通过设置一个最保守的默认值来避免这个问题。
客户端可以通过记住所有参数，甚至是当前不支持的参数来避免这个问题。 

新的传输层参数信息注册见22.3节。

## 7.5. Cryptographic Message Buffering

由于CRYPTO帧没有流控，一个终端可能强行让对端缓存无限制的数据，因此实现需要维护一个用于保存乱序CRYPTO数据的缓存。

实现必须支持至少4096个字节大小的乱序CRYPTO帧数据的缓存。终端可以（MAY）选择在握手过程中缓存更多数据。一个更大的限制允许交换更大的key或证书。在连接的生命周期中，一个终端的缓存大小没必要保持不变。

握手过程中无法缓存CRYPTO将导致连接失败。如果握手过程中一个终端的缓存溢出，它可以暂时扩大它的缓存来完成握手。如果一个终端不打算扩大缓存，它必须以一个CRYPTO_BUFFER_EXCEEDED错误码关闭连接。

一旦连接完成，如果一个终端不能缓存CRYPTO帧的所有数据，它可以（MAY）丢弃当前这个和未来将收到的所有CRYPTO帧，也可以（MAY）选择以CRYPTO_BUFFER_EXCEEDED错误码关闭连接。
包含丢弃CRYPTO帧的包必须被ACK确认，因为尽管这个包被丢弃，它也是被收到和处理了。

# 8. Address Validation

地址校验是终端 用来防止被流量放大攻击的一种手段。
在这种攻击中，攻击者给发送到服务端的packet伪造假的来源地址信息，这个地址信息来自于一个受害者。如果服务端给这个地址回复了更多/更大的包，攻击者则可以利用服务端给受害者发送更多的数据（比自己直接发送的更多）。

对放大攻击的主要防御措施是验证对端是否能够在其声明称的传输地址接收数据包。因此，在接收到来自尚未验证的地址的数据包后，终端必须将其向未验证的地址发送的数据量限制为从该地址接收的数据量的三倍。这种对响应大小的限制被称为反放大限制。

地址校验在连接建立期间（见第8.1节）和连接迁移期间（见第8.2节）都要执行。

## 8.1. Address Validation During Connection Establishment

连接建立的过程隐式地给双方终端提供了地址校验。特别是，收到用握手密钥保护的数据包后，可确认对端成功处理了一个Initial包。 一旦终端成功处理了来自对端的Handshake据包，它就可以认为对端的地址已经被验证。

此外，如果对端使用了由该终端选择的CID，并且该CID至少包含64位熵，则终端可以认为对端地址已被验证。

对于客户端来说，其第一个Initial包中Destination Connection ID字段的值允许它验证服务端地址，作为成功处理任何数据包的一部分。来自服务端的Initial包受此值派生的密钥保护（见[QUIC-TLS]的5.2节）。另外，该值由服务端在Version Negotiation包（第6节）中呼应，或包含Retry包的完整性标签中（[QUIC-TLS]第5.8节）。

在校验客户端的地址合法性之前，服务端不能（MUST NOT）回复超过3倍收到的字节数。这限制了放大攻击的系数。为了在地址检验前能够避免放大攻击，服务端必须（MUST）统计一个连接中收到的所有数据载荷字节数。包括了两种数据报：包含了被成功处理的包的数据报；所有包都被丢弃的数据报。

客户端必须（MUST）使用PADDING帧填充只包含Initial packets的UDP datagram，填充到至少1200字节。一旦客户端收到了Handshake packet的ACK，它可以（MAY）发送小于限制的datagram。发送被填充的datagram保证了服务端的字节限制足够大。（提高了攻击成本）

如果服务端发往客户端的Initial或者Handshake包丢失，而客户端如果不发送额外Initial或者Handshake包的话，就会引起死锁。当服务端达到反放大攻击限制，而客户端已经收到了它发送的所有数据的确认信息，就会出现死锁。这种情况下，客户端没有发送额外包的理由，而服务端则因为尚未校验客户端的地址而无法发送更多数据。为了防止出现这种死锁，客户端必须（MUST）在PTO之后发送一个包。更具体的来说，如果客户端没有握手密钥，则必须（MUST）通过UDP数据报发送一个至少1200字节大小的Initial包，如果有握手密钥则发送Handshake包。

服务端可能会希望在开始加密层握手前校验客户端地址。QUIC使用一个在Initial packet中的token来提供地址校验信息。这个token是在Retry packet当中被服务端下发给客户端，或者通过以往连接发送的NEW_TOKEN frame来下发。

除了在地址校验完成之前被限制发送数据量之外，服务端还被拥塞控制器限制了可以发送的内容。客户端只被拥塞控制器限制。

### 8.1.1. Token Construction

Token的创建必须（MUST）要让服务端可以识别token是如何提供给客户端的，是在NEW_TOKEN帧中还是在Retry包中发送的。
这些token都在使用了同一个字段，但是要求服务端区别对待。

### 8.1.2. Address Validation using Retry Packets

在收到客户端的Initial packet之后，服务端可以通过携带有token的Retry packet要求进行地址校验(第17.2.5节)。
客户端在收到Retry packet后，必须（MUST）在所有为该连接发送的后续的Initial packet中携带这个token。

服务端在收到包含Retry packet中提供的token的Initial报文时，不能再发送一个Retry packet，它只能拒绝连接或允许连接继续进行。

由于攻击者不能构造属于自己地址的token，如果客户端能够正常返回这个token并校验通过，表明它确实是能正常收到token的终端（不是伪造的地址）。

一个服务端也可以使用retry包来推迟建立连接的状态和处理消耗。这需要服务端提供一个不同的CID，以及18.2节中定义的original_destination_connection_id传输参数，强迫服务端证明它自己或者它合作的实体收到了客户端的原始initial包。提供一个不同的CID同样保证了服务端对后续包的路由有一些控制。这可以用来将连接指向一个不同的服务端实例。

如果服务端从客户端收到了一个可以解密但包含了无效Retry token的initial包，它就能知道客户端不会接受另外一个retry token。服务端可以丢弃这样的包，并允许客户端握手超时失败。但是那会在客户端上引入一个巨大的延迟。相反，服务端应该（SHOULD）立刻以INVALID_TOKEN错误关闭连接。值得一提的是这节点上服务端还没有确立任何连接的状态，因此也不会进入到closing阶段。

下图是带有Retry报文的握手交互流程：

```
   Client                                                  Server

   Initial[0]: CRYPTO[CH] ->

                                                   <- Retry+Token

   Initial+Token[1]: CRYPTO[CH] ->

                                    Initial[0]: CRYPTO[SH] ACK[1]
                          Handshake[0]: CRYPTO[EE, CERT, CV, FIN]
                                    <- 1-RTT[0]: STREAM[1, "..."]

                   Figure 9: Example Handshake with Retry
```

### 8.1.3. Address Validation for Future Connections

服务端可以（MAY）在连接中下发一个地址校验token给未来新建的连接使用。地址校验在0-RTT流程里面是非常重要的，因为服务端有可能返回一大堆数据作为0-RTT的应答内容（放大攻击）。

服务端使用NEW_TOKEN frame（格式见19.7节）来给客户端下发地址校验token。客户端在后续建连的Initial packet中使用这个token。客户端必须（MUST）在所有的Initial packet中包含这个token，直到收到服务端返回的Retry报文替换了一个新token。客户端必须不能（MUST NOT）将Retry报文里面的token用于未来新建的连接。服务端可以（MAY）丢弃预期携带token但实际没带的Initial packet。

Retry包中的token会立刻被启用，而不同的是，NEW_TOKEN帧中的token可能会在一段时间后才使用。因此一个token应当（SHOULD）具有超时时间，可以是一个显式的超时事件，或者是一个可以用来动态计算超时时间的时间戳。服务端可以保存超时时间，或者将其以加密的格式保存在token中。

通过NEW_TOKEN发布的token必须不能（MUST NOT）包含那些使观察者可以联系到当前连接的信息。比如说，token中不能包含上一个CID或者寻址信息。服务端必须（MUST）保证它发的每一个NEW_TOKEN帧在所有的客户端之间是独一无二的，包括那些丢失重传的NEW_TOKEN帧。除了服务器，其他实体也可以（MAY）访问服务端用来区分token来源（Retry还是NEW_TOKEN）的信息。

两个不同的连接上，不太可能出现相同的客户端端口号；因此校验端口不太可行。

在NEW_TOKEN帧中接收的token适用于该连接认证过的任何服务端（比如证书中的服务端名称）。当客户端拥有一个可用且未用过的token，且将其用于与服务端建立连接，客户端应当（SHOULD）在它的initial包的Token字段包含这个token。

包含一个token可以使服务端校验客户端的地址的时候，节省一个RTT的时间。一个客户端必须不能（MUST NOT）在与一个服务端连接的过程中，将一个不适用于幅度按的token包含进来，除非客户端知晓发布了token的服务端和客户端正在连接的服务端可以对token做联动管理。一个客户端再次连接到一个服务端时，可以（MAY）使用之前和这个服务端连接中用过的token。

token允许服务端将发布token的连接，和任何使用这个token的连接之间的活动联系起来。如果客户端想要打破和服务端连续性和一致性，可以使用NEW_TOKEN帧来丢弃提供的token。在比较的时候，通过Retry包获得的token必须（MUST）在连接期间被立刻使用，并且不能被用于后续的连接。

客户端不应该（SHOULD NOT）在不同连接中复用NEW_TOKEN帧的token。token复用允许网络链路上的所有实体都可以和连接建立联系。

客户端可能从一个连接上收到多个token。除了阻止连通性，任何token都可以在任何连接尝试中使用。服务端发送额外的token来实现多次连接操作的地址校验，或者替换那些可能将要无效的旧token。
对于客户端来说，这种模棱两可的方式意味着，发送最近未使用的token更多的是为了有效，尽管保存和使用旧的token不会有负面的影响，客户端也可以认为在与服务端进行地质校验时，旧的token作用会更少。

如果服务端收到一个带地址校验token的Initial包，如果服务端尚未完成地址校验，它必须（MUST）尝试验证token。如果token无效，那么服务端应当（SHOULD）将这种情况和客户端地址无效的情况同等对待，包括可能发送一个Retry包。用NEW_TOKEN帧和Retry包提供的token可以被服务端区分（见8.1.1节），且后者的校验更严。如果校验成功，服务端应当（SHOULD）允许进行握手。

注意：将客户端当做未校验而不是丢弃包的根本原因是——客户端可能从上个连接的NEW_TOKEN帧，收到了token。如果服务端丢失了状态，它可能无法校验这个token，这时候如果丢包的话，会导致连接错误。

在无状态的设计里面，服务端可以对token的内容进行加密和认证，并在后续收到时恢复内容信息用以校验地址。注意TOKEN字段不是放在加密握手报文里面的，没有经过认证，因此其用途只限于作地址校验。为了避免攻击获知这个属性，服务端可以将它token的内容限制为用于校验客户端地址的信息。

客户端可以（MAY）在所有相同版本的连接中使用同一个token。当选择哪一个token时，客户端不需要考虑当前连接的其他属性，包括可能的应用协议、会话ticket、连接属性等的选择问题。

在DDoS攻击中，攻击者可能会重放服务端下发的token。服务端可以限制Retry下发的token使用周期，并限制NEW_TOKEN下发的token使用频率。

### 8.1.4. Address Validation Token Integrity

地址校验token必须是难以猜测的，在token中包含一个至少128位熵的随机值就足够了，但这取决于服务端是否记得它发送给客户的值。

基于token的方案允许服务端将与验证相关的任何状态卸载到客户端。为了该设计有效，token必须（MUST）有完整性保护，以防止客户端修改或伪造。如果没有完整性保护，恶意客户端可能会生成或猜测将由服务端接受的token的值。仅服务端需要访问token的完整性保护密钥。

Token不需要单一地定义明确的格式，因为生成token的服务端也会使用它。在Retry包中发送的token应该包括允许服务端验证客户端数据包中的源IP地址和端口保持不变的信息。

NEW_TOKEN帧中发送的token必须（MUST）包含能够让服务端校验token发布之后客户端IP和端口是否保持不变的信息。在不想发送retry包的时候，服务端可以使用NEW_TOKEN中的token，即使客户端地址发生了改变。
如果客户端IP地址改变，服务端必须（MUST）继续遵从8.1节提到的反放大攻击限制。值得注意的是，存在NAT的情况下，这个需求可能无法有效保护那些共享了同一个NAT的主机来抵御放大攻击。

攻击者可以重放token，将服务器作为DDoS攻击中的放大器。为了防止这种攻击，服务端必须（MUST）确保阻止或限制token的重放 服务器必须确保在Retry包中发送token只在短时间内被接受，因为它们会立即被客户端返回。 在NEW_TOKEN帧（第19.7节）中提供的token需要有更长的有效期，但不应该被多次接受。鼓励服务器在可能的情况下仅允许使用token一次；token可以（MAY）包含更多的客户端相关的信息，来进一步缩小适用性和重用。

## 8.2. Path Validation

连接迁移期间，两个终端都使用路径校验（请参见第9节）来验证对端地址更改后的可达性。在路径校验中，终端测试特定本地地址和特定对端地址之间的可达性，其中地址是IP地址和端口的两元组。

路径校验测试在路径上发送到对端的数据包是否被该对端接收。路径校验用于确保从迁移对端接收的数据包不携带伪造的源地址。

路径校验并不能验证对端是否可以在返回方向上发送。ACK不能用于返回路径验证，因为它们包含的熵不足且可能是伪造的。终端独立地决定路径的每个方向上的可达性，因此返回的可达性只能由对端建立。

路径校验可以被任何一个终端在任何时候使用。例如，终端可能在经过一段静态时间后会检查对端是否仍拥有其地址。

路径校验未设计为NAT遍历机制。尽管此处描述的机制对于创建支持NAT遍历的NAT绑定可能是有效的，但可以预期的是，一个或其他对端能够接收数据包，而无需先在该路径上发送数据包。有效的NAT遍历需要其他同步机制。但此处未提供。

终端可以在用于路径校验的PATH_CHALLENGE和PATH_RESPONSE帧中包含其他帧。特别是，终端可以在PATH_CHALLENGE帧中包含PADDING帧，用于路径最大传输单元发现（PMTUD；见第14.2.1节）；也可以在PATH_RESPONSE帧中包含自己的PATH_CHALLENGE帧。

终端对从新的本地地址发送的探测使用新的Connection ID；见9.5节。当探测新路径时，终端可以确保其对端体有一个未使用的Connection ID可用于响应。如果对端的active_connection_id_limit允许，则在同一个数据包中发送NEW_CONNECTION_ID和PATH_CHALLENGE帧，可以确保在发送响应时，对端有未使用的Connection ID可用。

终端可以选择同时探测多条路径。用于探测的并发路径数受其对端先前提供的额外Connection ID的数量限制，因为用于探测的每个新本地地址都需要一个以前未使用的Connection ID。

### 8.2.1. Initiating Path Validation

为了发起路径校验，终端会发送一个PATH_CHALLENGE帧，其中包含了待校验路径上不可预测的payload。

终端可以发送多个PATH_CHALLENGE帧以防止丢包，但不应该在一个数据包中发送多个PATH_CHALLENGE帧。

终端不应使用包含PATH_CHALLENGE帧的数据包比发送Initial包更频繁地探测新路径，这样可以确保连接迁移在新路径上的负荷不会比建立新连接的负荷大。

终端必须在每个PATH_CHALLENGE帧中使用不可预知的数据，以便将对端的响应与相应的PATH_CHALLENGE相关联。

终端必须将包含PATH_CHALLENGE帧的数据报至少扩展到所允许的最小的最大数据报大小即1200字节，除非路径的反放大限制不允许发送这个大小的数据报 发送这个大小的UDP数据报可以确保从终端到对端的网络路径可以用于QUIC（见第14节）。

当终端由于反放大限制而无法将数据报大小扩展到1200字节时，将不验证路径MTU。为了确保路径MTU足够大，终端必须通过发送至少1200字节的数据报中的PATH_CHALLENGE帧来执行第二次路径验证。 这种额外的验证可以在成功接收到PATH_RESPONSE之后进行，或者当路径上已经接收到足够多的字节，发送较大的数据报不会导致超过反放大限制。

与其他数据报被扩展的情况不同，当数据报包含PATH_CHALLENGE或PATH_RESPONSE时，终端不得丢弃看起来太小的数据报。

### 8.2.2. Path Validation Responses

在收到PATH_CHALLENGE帧时，终端必须通过在 PATH_RESPONSE 帧中回显PATH_CHALLENGE帧中包含的数据，来作出响应。除非受到拥塞控制的限制，否则终端不得延迟传输包含PATH_RESPONSE帧的数据包。

PATH_RESPONSE帧必须在收到PATH_CHALLENGE的网络路径上发送。这确保了只有当路径在两个方向上都有效时，对端的路径校验才会成功。发起路径校验的终端不得强制执行此要求，因为这将使迁移受到攻击（第9.3.3节）。

终端必须将包含PATH_RESPONSE帧的数据报至少扩展到允许的最小的最大数据报大小即1200 字节。这验证该路径能够在两个方向上携带此大小的数据报。 但是，如果产生的数据超过了反放大限制，终端不得扩展包含PATH_RESPONSE的数据报。 只有当接收到的PATH_CHALLENGE不是在扩展数据报中发送时，才会出现这种情况。

终端不得发送超过一个PATH_RESPONSE帧来响应一个PATH_CHALLENGE帧（见第13.3节）。对端应根据需要发送更多的PATH_CHALLENGE帧，以唤起更多的PATH_RESPONSE帧。

### 8.2.3. Successful Path Validation

当收到PATH_RESPONSE帧，且该帧中包含了之前PATH_CHALLENGE帧中发送的数据时，路径校验成功。在任何网络路径上收到的PATH_RESPONSE帧都会验证在其上发送PATH_CHALLENGE的路径。

如果终端在数据报中发送的PATH_CHALLENGE帧没有扩展到至少1200字节，并且对它的响应验证了对端地址，则路径通过验证，但不验证路径MTU。 因此，终端现在可以发送超过已接收数据量三倍的数据。 然而，终端必须用扩展的数据报发起另一个路径校验，以验证该路径是否支持所需的MTU。

收到包含PATH_CHALLENGE帧的数据包的ACK并不是充分的验证，因为该ACK可能是被恶意的对端伪造的。

### 8.2.4. Failed Path Validation

只有当尝试路径校验的终端放弃尝试时，路径校验才会失败。

终端应该根据定时器放弃路径校验。在设置这个定时器时，要提醒实现注意，新路径的往返时间可能比原始路径的长。 建议使用当前PTO或新路径的PTO(即使用[QUIC-RECOVERY]中定义的kInitialRtt)中较大值的三倍。

这个超时允许多个PTO在路径校验失败之前过期，因此单个PATH_CHALLENGE或PATH_RESPONSE帧的丢失不会导致路径校验失败。

需要注意的是，终端可能会在新路径上收到包含其他帧的数据包，但路径校验成功需要一个包含适当数据的PATH_RESPONSE帧。

当终端放弃路径校验时，它确定该路径无法使用。 这并不一定意味着连接的失败——终端可以根据情况通过其他路径继续发送数据包。如果没有可用的路径，终端可以等待新的路径可用或关闭连接。终端如果没有通往对端的有效网络路径，可以使用NO_VIABLE_PATH连接错误来发出信号，注意只有当网络路径存在但不支持所需的MTU时才有可能这样做（第14节）。 

除了失败之外，路径校验还可能因为其他原因而被放弃。主要是在旧路径上的路径校验正在进行的同时，连接迁移到新路径时，会发生这种情况。

# 9. Connection Migration

connection ID使得连接可以在终端地址发生变化后仍然存在（IP/port发生变化），比如在网络切换的场景下。本节描述这种迁移的场景。

终端不能（MUST NOT）在握手确认之前发起连接迁移，因为QUIC的设计依赖于终端在握手过程中地址不变化（根据[QUIC-TLS]第4.1.2节的定义）。

在对端发送”disable_active_migration”传输层参数时，终端不能（MUST NOT）发起连接迁移。在终端明确表明不支持连接迁移的情况下，如果发现对端发起了迁移，终端必须（MUST）丢弃在那条链路上的包且无需产生一个无状态reset，或者进行地质校验并允许对端进行迁移。产生无状态reset或者关闭连接会使得网络中的第三方可以通过欺骗或者操纵流量来关闭连接。

不是所有的对端地址变化都是连接迁移。对端有可能发生了一次NAT转换。这种情况下如果对端的IP地址发生变化，终端必须（MUST）发起路径校验。

当一个终端没有一条认证过的路径来发送数据包，它可以（MAY）丢弃连接状态。一个有连接迁移能力的终端可以（MAY）在丢弃连接状态之前等待新的链路可用。

本文限制了连接迁移的场景为客户端地址发生变化。只有客户端是迁移的发起方。
如果客户端收到了来自未知地址服务端的包，它必须（MUST）丢弃这些包。

## 9.1. Probing a New Path

终端可能（MAY）探测下路径联通性（见8.2节）再发起到新地址的连接迁移。
新地址的路径探测失败表明新地址是不可用的，地址探测失败的情况下不会触发连接失败，除非所有的路径都不可用。

终端使用新的connection ID填充新地址的探测包。
使用新地址的中断需要确保对端至少有一个新的connection ID是可用的。
可以在探测包中携带NEW_CONNECTION_ID来保证。

收到PATH_CHALLENGE frame表明对端在检查路径可用性，回复PATH_RESPONSE用以表示地址可达。

探测帧包括以下类型：(“probing frames”)

* PATH_CHALLENGE
* PATH_RESPONSE
* NEW_CONNECTION_ID
* PADDING

其他的frame都是非探测帧(“non-probing frames”).
如果一个packet中只包含探测帧，则它是一个探测包”probing packet”.
如果包含了其他帧，则是一个”non-probing packet”.

## 9.2. Initiating Connection Migration

终端可以通过向新的地址发送包含非探测帧“non-probing frames”的packet来实现连接迁移。

每一个终端在建连的过程中都会验证其对端的地址。因此，迁移终端可以在知道对端愿意在对端当前地址处接收消息的情况下，向其对端发送消息。 因此，终端可以迁移到一个新的本地地址，而无需先校验对端的地址。

为了在新路径上建立可达性，终端在新路径上启动路径校验（第8.2节）。终端可以推迟路径校验至对端向其新地址发送下一个非探测帧之后。

在迁移的过程中，新路径可能不支持现在终端的发送速率。因此终端需要重置自己的拥塞控制器（congestion controller）和RTT估计，详细见9.4节。

新路径可能没有相同的ECN容量，因此终端需要检查ECN容量情况，见13.4节。

## 9.3. Responding to Connection Migration

收到来自于一个新的对端地址的”non-probing frame”表明对端发起了地址迁移。

如果接收方允许迁移，它必须向新的对端地址发送后续数据包，并且必须启动路径校验（第8.2节），以验证对端对地址的所有权（如果尚未进行校验）。 

终端仅响应于编号最大的非探测数据包，才更改其向其发送数据包的地址。这样可以确保终端在收到重新排序的数据包的情况下，不会向旧的对端地址发送数据包。

终端可以（MAY）发送数据给新的未被校验的地址，但它必须（MUST）抵御潜在可能的2种攻击（9.3.1和9.3.2）。终端可以（MAY）跳过对端地址的检验，如果这个地址在近期被使用过。实际上，如果一个终端在检测到恶意的迁移的一些行为且回到一条之前校验过的链路上，跳过地址校验并重用丢包探测、拥塞状态可以减少攻击对于性能的影响。

在发送non-probing packet并切换到新地址后，终端可以忽略其他地址的路径校验。

收到新地址的packet也有可能是因为对端NAT地址重新绑定。

在收到新的客户端地址后，服务端应当（SHOULD）发送新的地址校验token给客户端。

### 9.3.1. Peer Address Spoofing

对端有可能欺骗其源地址，使终端向不希望的主机发送过多的数据。如果终端发送的数据量明显多于伪造的对端，则连接迁移可能被用来放大攻击者向受害者发送的数据量。

如第9.3节所述，终端需要校验对端的新地址，以确认对端拥有新地址。在对端的地址被认为有效之前，终端会限制它向该地址发送的数据量（见第8节）。如果没有这个限制，终端就有可能被用来对不知情的受害者进行DoS攻击。

如果终端如上所述跳过了对端地址的校验，它就不需要限制其发送速率。

### 9.3.2. On-Path Address Spoofing

一个on-path攻击者可以触发伪造的连接迁移行为，比如通过拷贝和转发它收到的packet，将地址改为一个虚假地址。来自于假地址的包则看起来像是发生了一次连接迁移，然后原来的包就会被认为是多余的并被丢弃。在这次虚假的迁移之后，对源地址的校验会失败，因为假地址的终端并没有用来读取和处理PATH_CHALLENGE对应的密钥。

为了抵御这种伪造的连接迁移行为，终端必须（MUST）在新地址校验失败之后，回去使用上一次成功校验的对端地址。此外，从合法对端地址接收到包号较高的数据包将触发另一次连接迁移，这将导致放弃对虚假迁移地址的校验，从而包含由攻击者注入单个数据包所发起的迁移。

如果终端没有已经校验成功的地址，它就必须（MUST）关闭连接，并把所有相关连接状态信息丢弃。这将导致连接上的新数据包被一般性地处理。例如，终端可以发送一个无状态的Reset来响应任何进一步的传入数据包。

### 9.3.3. Off-Path Packet Forwarding

一个off-path攻击者可以嗅探并转发packet。
如果这些拷贝的packet比原始的packet先到达对端，它可能会被认为是一次NAT地址转换。这时原始的packet会被丢弃。如果攻击者继续转发packet，对端可能认为是发生了转移到攻击者地址的连接迁移。这就让攻击者地位变成了”on-path”，即给攻击者提供了嗅探或丢弃所有后续包的权利。

这种攻击方式依赖于攻击者使用的路径与终端之间的直接路径具有大致相同的特征。如果发送的数据包相对较少，或者数据包丢失的时间与尝试攻击的时间相吻合，那么这种攻击方式就比较可靠。

在原路径上收到的non-probing packet会增加收包packet number的最大值，并且会使得对端地址迁移回原来地址。在这条路径上诱发数据包会增加攻击不成功的可能性。因此，缓解这种攻击依赖于触发数据包的交换。

为了响应明显的迁移，终端必须使用PATH_CHALLENGE帧来验证之前的活动路径 这将诱导在该路径上发送新的数据包。如果路径不再可行，则校验尝试将超时并失败；如果路径可行但不再需要，则验证将成功，但只导致在该路径上发送探测数据包。

在活动路径上收到PATH_CHALLENGE的终端应该发送一个非探测包作为响应 如果非探测数据包在攻击者进行任何复制之前到达，就会导致连接被迁移回原始路径。任何后续的迁移到另一个路径，都会重新启动这整个过程。

这种防御是不完善的，但这不被认为是一个严重的问题。如果尽管多次尝试使用原始路径，但经过攻击的路径确实比原始路径快，则无法区分攻击和路由改进。

终端也可以使用启发式方法来改进对这种攻击方式的检测。例如，如果数据包是最近在旧路径上收到的，不可能进行NAT重新绑定；同样，在IPv6路径上，重新绑定也很罕见。终端也可以寻找重复的数据包。 相反，Connection ID的变化更有可能表明是有意迁移，而不是攻击。

## 9.4. Loss Detection and Congestion Control

新路径的可用容量跟老路径可能不一致。因此拥塞控制和RTT测量需要从头开始。旧链路上已经发送的包必须不能（MUST NOT）用于新链路的拥塞控制或者RTT计算。

在确认了对端地址合法性之后，终端必须（MUST）立即将新路径的拥塞控制器和RTT测量器重置为初始值（见[QUIC-RECOVERY]中的附录A.3和B.3），除非对端地址的唯一变化是端口号。由于只改变端口通常是NAT重新绑定或其他中间件活动的结果，在这些情况下，终端可以保留其拥塞控制状态和RTT估计，而不是恢复到初始值。在旧路径上保留的拥塞控制状态被用在新路径上，而新路径的特性又大不相同，在拥塞控制器和RTT估计器适应之前，发送者可能会过于激进地传输。 一般来说，建议实现在新路径上使用以前的值时要谨慎。

当端点在迁移期间从/向多个地址发送数据和探测时，可能会在接收方出现明显的重排，因为所产生的两条路径可能有不同的RTT。多条路径上的数据包接收方仍将发送覆盖所有接收数据包的ACK帧。

尽管在连接迁移期间可能使用多个路径，但单个拥塞控制上下文和单个丢失恢复上下文（如[QUIC-RECOVERY]中所述）可能就足够了。例如，终端可能会延迟切换到新的拥塞控制上下文，直到确认不再需要旧路径为止（例如第9.3.3节中的情况）。

发送方可以把探测packet排除在丢包检测机制之外，这样这些包就不会影响发送速率。终端可以为PATH_CHALLENGE的发送设置一个独立的定时器，当收到PATH_RESPONSE时取消这个定时器。如果定时器在收到PATH_RESPONSE之前启动，终端可能会发送一个新的PATH_CHALLENGE，并在更长的时间内重新启动定时器。这个定时器应该按照[QUIC-RECOVERY]第6.2.1节的描述来设置，而且一定不能（MUST NOT）更短。

## 9.5. Privacy Implications of Connection Migration

在多条网络路径上使用固定的Connection ID，将允许被动的观察者将这些路径之间的活动关联起来。在网络之间移动的终端可能不希望他们的活动被除对端以外的任何实体关联起来，因此当从不同的本地地址发送时，会使用不同的Connection ID，如第5.1节所讨论的那样。为了使此方法有效，终端需要确保他们提供的Connection ID不能被任何其他实体链接。

在任何时候，终端都可以将他们传输的DCID改变为一个在其他路径上没有使用过的值。

当从多个本地地址发送消息时，例如，如第9.2节所述启动连接迁移，或如第9.1节所述探测新的网络路径时，终端不得重用Connection ID。

同样，终端向多个目的地址发送时，不得重复使用CID。由于网络变化不在对端的控制范围内，终端可能会从新的源地址收到具有相同DCID的数据包，在这种情况下，终端可以继续使用新的远程地址的当前CID，同时仍然从同一个本地地址发送。

这些关于CID重用的要求只适用于数据包的发送，因为可能会在无意更改CID的情况下意外更改路径。例如，在一段时间的网络空闲后，NAT重新绑定可能会导致客户端恢复发送时数据包被发送到新的路径上，终端会按照第9.3节中的描述来响应这样的事件。

对每个新的网络路径上双向发送的数据包使用不同的CID，可以消除使用CID来链接来自同一连接的数据包跨越不同的网络路径。报头保护确保数据包编号不能用于关联活动，这并不妨碍使用数据包的其他属性（如时间和大小）来关联活动。

终端不应该与请求零长CID的对端发起迁移，因为新路径上的流量可能与旧路径上的流量琐碎地连接起来。如果服务端能够将具有零长CID的数据包关联到正确的连接，这意味着服务端正在使用其他信息来解复用数据包。例如，服务端可能会给每个客户端提供一个唯一的地址，例如使用HTTP替代服务[ALTSVC]。可能允许跨多个网络路径正确路由数据包的信息，还将允许这些路径上的活动由对端实体以外的实体链接。

在一段时间不活动后发送流量时，客户端可能希望通过切换到新的CID，源UDP端口或IP地址（请参阅[RFC4941]）来减少可链接性。同时改变其发送数据包的地址可能会导致服务端检测到连接迁移。这确保了即使对于没有经历NAT重新绑定或真正迁移的客户端，也能行使支持迁移的机制。改变地址可能会导致对端重置其拥塞控制状态（见第9.4节），所以地址不应经常改变。

用尽可用CID的终端不能探测新路径或启动迁移，也不能响应对端的探测或迁移尝试。为了确保迁移是可能的，并且在不同路径上发送的数据包不能相关联，终端应该在对端迁移之前提供新的CID（见第5.1.1节）。如果对端可能已经用尽了可用的CID，迁移的终端可以在新的网络路径上发送的所有数据包中包含一个NEW_CONNECTION_ID帧。

## 9.6. Server's Preferred Address

QUIC允许服务端在一个IP地址接收连接之后，在握手之后不久尝试把这些连接转到另一个地址。当客户端最初连接到一个由多个服务器共享的地址，但希望使用单播地址以确保连接稳定性时，这一点特别有用。 本节描述了将连接迁移到首选服务器地址的协议。

本文档中指定的QUIC版本不支持将连接中途迁移到新的服务器地址。如果客户端收到来自新服务器地址的数据包时，客户端没有发起向该地址的迁移，客户端应该丢弃这些数据包。

### 9.6.1. Communicating a Preferred Address

服务端通过在TLS握手阶段下发传输层参数preferred_address来提供新的地址。

服务端可以传达每个地址族（IPv4和IPv6）的首选地址，让客户选择最适合自己网络附件的地址。

一旦握手确认之后，客户端应当从服务端的两个偏好地址中选择一个，并使用任何之前没使用过且活动的CID开始这个地址的路径校验，而cid要么从preferred_address传输传输，要么从NEW_CONNECTION_ID帧中获得。

如果路径校验成功，客户端应当（SHOULD）立即切换地址，发送所有后续的包给新的服务端地址，并使用新的connection ID。如果路径校验失败，客户端必须（MUST）继续使用服务端原来的IP地址。

### 9.6.2. Migration to a Preferred Address

迁移到首选地址的客户端必须在迁移前校验它所选择的地址；见第21.5.3节。

服务端在接受连接后，可能会在任何时候收到一个指向其首选IP地址的数据包。如果这个数据包包含一个PATH_CHALLENGE帧，服务端就会根据第8.2节发送一个包含PATH_RESPONSE帧的数据包。服务端必须从它的原始地址发送非探测数据包，直到它在它的首选地址收到来自客户端的非探测数据包，且直到服务端验证了新路径。

服务端应当（SHOULD）从新地址发起对客户端的路径校验，这有助于抵御伪造的连接迁移。

一旦服务端完成了路径校验并在新地址收到了一个具有新的最大包号的non-probing packet，服务端就开始通过新地址给客户端发送非探测包了。服务端应当（SHOULD）丢弃老地址收到的包，但可以（MAY）继续处理延迟到达的包。

服务端在preferred_address参数中提供的地址只对这个参数对应的连接有效。客户端必须不能（MUST NOT）在其他连接中使用这些信息，包括从当前连接中恢复的连接。

### 9.6.3. Interaction of Client Migration and Preferred Address

客户端可能会需要在使用服务端的新地址之前，发起一次连接迁移。在这种场景下，客户端应当（SHOULD）从客户端的新地址，对服务端的新/老地址同时发起路径校验。

如果服务端的新地址校验通过，客户端必须（MUST）取消老地址的校验，并使用服务端的新地址。如果服务端的新地址校验失败，且服务端老地址校验成功，则客户端可以（MAY）迁移到客户端的新地址，并继续使用服务端的老地址。

如果在服务端新地址收到的数据包的源地址与握手期间从客户端观察到的不同，服务端必须防止第9.3.1节和第9.3.2节所述的潜在攻击。除了有意的同步迁移外，还可能因为客户端的接入网络对服务器的新地址使用了不同的NAT绑定而发生这种情况。

服务器在收到来自不同地址的探测数据包时，应该启动到客户端新地址的路径校验；参见第8节。

迁移到新地址的客户端应该为服务端使用来自同一地址族的新地址。

在preferred_address传输参数中提供的CID并不限定于提供的地址。这个CID用来保证客户端有一个可以用来迁移的cid，但是客户端可以（MAY）在任意链路上都使用这个CID。

## 9.7. Use of IPv6 Flow-Label and Migration

使用IPv6来发送数据的终端应当（SHOULD）按照[RFC6437]的规定应用IPv6流标签，除非本地API不允许设置IPv6流标签。

流标签的生成必须设计成尽量减少与先前使用的流标签的可连接性，因为固定的流标签将使多条路径上的活动关联，参阅第9.5节。

[RFC6437]建议使用伪随机函数派生值来生成流标签。在生成流标签时，除了源地址和目的地址外，还包括DCID字段，以确保该更改与其他可观察标识符的更改同步。将这些输入与本地密钥结合起来的加密哈希函数是一种可以实现的方式。

# 10. Connection Termination

连接有以下三种关闭情况：

* idle timeout （10.1节）
* immediate close （10.2节）
* stateless reset （10.3节）

如果一个终端没有一条可用于发送数据的验证过的链路，可以（MAY）放弃连接状态。

## 10.1. Idle Timeout

如果对端在它的传输参数中定义了max_idle_timeout，当一个连接空闲事件超过两端max_idle_timeout传输参数中的最小值，且超过了3倍PTO时，连接就悄然关闭了，连接的状态也会被丢弃。

每个终端都通告了max_idle_tieout，但是两个中最小的那个值才是一个端上最终有效的值（如果只有一个终端通告一个非零值，则其为唯一的通告值）。通过宣告max_idle_tieout，如果一个终端根据有效值放弃了连接，需要开始一个立刻关闭的操作。

当收到对端的包并被成功处理，终端重启了空闲定时器。如果上一次收包并处理之后终端没有发送其他触发ACK的包，那么当发送一个触发ACK的包的时候，终端也会重启空闲定时器。在发包的时候重启定时器保证了连接不会再新的活动开始之后被关闭。

为了避免闲超时时间过短，终端必须将空闲超时时间增加到至少是当前PTO的三倍，这允许多个PTO过期，因此在空闲超时之前，可以发送和丢失多个探针。

### 10.1.1. Liveness Testing

在有效空闲时间快超时的时候，一个发送数据的终端面临着被对端丢弃的风险，因为在这些数据包到达之间，对端的空闲时间可能就已经超时。

一个终端可以在对端快超时的时候，发送PING或者其他触发ack的帧来测试连接是否存活，比如在离超时一个PTO之内发送，这种方法在不能安全丢弃任何可用的应用数据的时候特别有用。注意应用决定了什么数据可以安全重试。

### 10.1.2. Deferring Idle Timeout

一个终端期待响应数据，那么可能需要发送触发ACK的包来避免空闲超时，但是没必要也不能够发送应用数据。

QUIC实现可以为应用提供选项来推迟空闲超时。当应用期望避免丢失已开连接的状态，但暂时又不想交换应用数据，可以使用这种方法。有了这种选项，终端可以周期性地发送PING帧（第19.2节）来使对端重启其空闲超时时间。 如果这是自收到数据包后发送的第一个ack-eliciting数据包，发送包含PING帧的数据包也会重启这个终端的空闲超时。发送PING帧会导致对端以ACK的方式进行响应，这也会重启该终端的空闲超时。

使用QUIC的应用协议应当（SHOULD）提供如何适当推迟空闲超时的指导。不必要地发送PING帧会对性能造成副作用。

如果使用max_idle_timeout传输参数协商了空闲超时，且在一段大于max_idle_timeout的时间内没有包收发，连接就会超时；但是，中间设备可能在这个超时发生之前就超时。尽管[RFC4748]中REQ-5建议最小2分钟的超时间隔，但是实践证明15~30秒可以有效防止大多数中间设备丢失UDP流的状态[GATEWAY]。

## 10.2. Immediate Close

终端发送CONNECTION_CLOSE frame来直接关闭一条连接。CONNECTION_CLOSE frame会导致所有的stream立刻进入关闭状态，新建的stream也会被reset处理。

发送CONNECTION_CLOSE帧后，终端立即进入closing状态（见10.2.1节）。
接收到CONNECTION_CLOSE帧后，终端进入draining状态（见10.2.2节）。

违反协议的行为会导致立即关闭。

在应用层协议安排关闭连接后，可以使用立即关闭。这有可能是出现在在应用层协议协商了优雅关闭之后，应用层协议可以交换两个应用程序终端同意关闭连接所需的消息，之后应用请求QUIC关闭连接。当QUIC因此关闭连接时，将使用带有应用程序提供的错误码的connect_close帧来向对端发出关闭信号。

closing和draining连接状态的存在是为了确保连接干净地关闭，延迟或重排的数据包被正确地丢弃。如[QUIC-RECOVERY]中定义，这些状态至少要持续当前PTO间隔的三倍。

在退出closing或draining状态之前处置连接状态，可能会导致终端在收到晚到的数据包时不必要地产生无状态的reset。终端如果有一些替代方法来确保晚到的数据包不会引起ACK，例如那些能够关闭UDP socket的终端，可以提前结束这些状态，以便更快地恢复资源。 保留开放socket以接受新连接的服务端，不应该提前结束closing或draining状态。

一旦closing或draining状态结束，终端应该丢弃所有连接状态。 终端可以发送一个无状态的reset，以响应任何属于这个连接的进一步传入的数据包。

### 10.2.1. Closing Connection State

终端在启动立即关闭后进入关闭状态。

在关闭状态下，终端只保留足够的信息以生成包含CONNECTION_CLOSE帧的数据包，并将其标识为属于连接。 处于关闭状态的终端会发送一个包含CONNECTION_CLOSE帧的数据包，以响应任何它归属于连接的传入数据包。

终端应该限制它在关闭状态下产生数据包的速度。 例如，终端可以在响应收到的数据包之前等待接收数据包数量或时间逐渐增加。

终端选择的CID和QUIC版本足以识别用于关闭连接的数据包，终端可以丢弃所有其他连接状态。正在关闭的终端不需要处理任何收到的帧。 
终端可以为接收到的数据包保留数据包保护密钥，以允许它读取和处理CONNECTION_CLOSE帧。

终端可以在进入关闭状态时放弃数据包保护密钥，并发送包含CONNECTION_CLOSE帧的数据包，以响应收到的任何UDP数据报。但是，丢弃数据包保护密钥的终端不能识别和丢弃无效数据包。为了避免被用于放大攻击，这样的终端必须将其发送的数据包的累计大小限制为已接收并归因于连接的数据包的累积大小的三倍。为了最大限度地减少终端为关闭连接所保持的状态，终端可以发送完全相同的数据包来响应任何接收到的数据包。

注意：在第12.3节中，对于每个数据包都使用一个新的数据包编号，这是允许重新发送最终数据包的一个例外。发送新的数据包号主要是对丢失恢复和拥塞控制有好处，这与关闭的连接无关。重传最终数据包需要的状态较少。

当处于关闭状态时，终端可以从一个新的源地址接收数据包，可能表明连接迁移（见第9节）。处于关闭状态的终端必须丢弃从未验证的地址收到的数据包，或者将它发送到未验证的地址的数据包的累积大小限制为从该地址收到的数据包大小的三倍。

终端在关闭时不应该处理密钥更新（[QUIC-TLS]第6节）。密钥更新可能会阻止终端从关闭状态进入排空状态，因为终端将无法处理随后收到的数据包，但在其他方面没有影响。

### 10.2.2. Draining Connection State

一旦终端收到CONNECTION_CLOSE帧，表示其对端正在关闭或排空，就进入排空状态。虽然在其他方面与关闭状态相同，但处于排空状态的终端必须不发送任何数据包。 一旦连接处于排空状态，就不需要保留数据包保护密钥。

收到CONNECTION_CLOSE帧的终端可以在进入排空状态前发送一个包含CONNECTION_CLOSE帧的数据包，如果合适的话，可以使用NO_ERROR code。 终端不得再发送数据包，这样做可能会导致CONNECTION_CLOSE帧的不断交换，直到其中一个终端退出关闭状态。

如果终端收到CONNECTION_CLOSE帧，表明对端也在关闭或排空，则终端可以从关闭状态进入排空状态。在这种情况下，排空状态会在关闭状态结束时结束。换句话说，终端使用相同的结束时间，但是停止在此连接上传输任何数据包。

### 10.2.3. Immediate Close During the Handshake

当发送CONNECTION_CLOSE的时候，目标是保证对端会处理这个帧。通常，这意味着使用最高等级保护的数据包发送这个帧，从而来避免数据包被丢弃。在握手被确认后，一个终端必须（MUST）在1-RTT数据包中发送任何CONNECTION_CLOSE帧。然而确认握手之前，对端可能无法使用更先进的数据包保护密钥，因此可以（MAY）在一个低加密保护等级的包中来发送CONNECTION_CLOSE帧。

更具体的是：

* 一个客户端总是知道服务端是否有握手密钥，但是服务端可能不知道客户端是否有握手密钥。在这些情况下，一个服务端应当（SHOULD）在handshake和initial包中都发送一个CONNECTION_CLOSE帧，从而来保证至少有一个可以被客户端处理。

* 在0-rtt包中发送CONNECTION_CLOSE的客户端不能保证服务端收到0-RTT，因此通过在initial包中发送一个CONNECTION_CLOSE能够让服务端收到关闭信号的可能性更大，及时应用错误码可能不会被接收。

* 在确认握手之前，对端可能无法处理1-RTT包，因此端点应该（SHOULD）在handshake和1-RTT包中同时发送CONNECTION_CLOSE。服务器还应该（SHOULD）在initial包中发送CONNECTION_CLOSE。

在一个initial或者handshake包中发送一个类型为0x1d的CONNECTION_CLOSE帧可能暴露应用状态，或者被用来改变应用状态。当在initial或者handshake包中发送CONNECTION_CLOSE时，0x1d类型的CONNECTION_CLOSE必须（MUST）被类型为0x1c的CONNECTION_CLOSE替换。否则关于应用状态的信息可能被泄露。终端必须（MUST）清除Reason Phrase字段，并在转换成0x1c状态的CONNECTION_CLOSE时，应该（SHOULD）使用APPLICATION_ERROR错误码。

在多个类型的包中发送的CONNECTION_CLOSE帧可以在一个UDP数据报中合并。

一个终端可能在一个initial包中，发送CONNECTION_CLOSE帧，或者来对initial或者handshake包中未认证的信息进行响应。这样的立刻关闭可能把安全连接暴露成拒绝服务。QUIC没有抵御握手阶段on-path攻击的防御手段；然而，如果终端丢弃了非法数据包而不是使用CONNECTION_CLOSE来关闭连接，就可以以减少关于合法对端的错误反馈为代价，造成攻击者更难使用一些形式的DOS攻击。因为这个原因，终端在处理缺乏认证的报数发现错误，可以（MAY）丢弃数据包而不是立刻关闭连接。

一个尚未建立状态的终端，比如检测到initial包中有错误的服务端，不会进入到closing状态。一个没有连接状态的终端在发送CONNECTION_CLOSE帧之后，不会进入到closing或者draining过程。

## 10.3. Stateless Reset

无状态重置（Stateless Reset）是无法访问连接状态的终端的最后选择。崩溃或中断可能会导致对端继续向无法正确继续连接的终端发送数据，终端可以发送无状态重置以响应收到一个无法与活动连接相关联的数据包。

无状态重置不适合用于指示活动连接中的错误。希望传达致命连接错误的终端，如果可以的话，必须使用CONNECTION_CLOSE帧。

为了支持此过程，终端会发出一个无状态重置token，该token是一个16字节的值，很难猜测。如果对端随后收到一个无状态重置（即以该无状态重置token结束的UDP数据报），对端将立即结束连接。

无状态重置token是特定于Connection ID的。终端通过在NEW_CONNECTION_ID帧的Stateless Reset Token字段中包含该值来发出无状态重置token。服务端也可以在握手过程中发出一个无状态重置token传输参数，该参数适用于它在握手过程中选择的Connection ID。这些交换受加密保护，所以只有客户端和服务端知道它们的值。注意，客户端不能使用stateless_reset_token传输参数，因为它们的传输参数没有机密性保护。

当其关联的Connection ID通过RETIRE_CONNECTION_ID帧（第19.16节）失效时，token就会失效。

接收到它无法处理的数据包的终端会发送一个如下结构的数据包（见1.3节）：

```
   Stateless Reset {
     Fixed Bits (2) = 1,
     Unpredictable Bits (38..),
     Stateless Reset Token (128),
   }

                     Figure 10: Stateless Reset Packet
```

这种设计确保了无状态重置数据包在最大程度上与普通的短包头数据包没有区别。

无状态重置使用整个UDP数据报，从数据包头的前两个位开始。第一个字节的剩余部分及其后任意数量的字节被设置为与随机值无法区分的值。数据报的最后16个字节包含一个无状态重置token。

对于其预期接收者以外的实体，无状态重置将显示为一个带有短包头的数据包。为了使无状态重置显示为有效的 QUIC 数据包，Unpredictable Bits字段需要包含至少 38 位数据（或 5 个字节，减去两个固定位）。

由此产生的最小大小为21个字节，如果接收方需要使用Connection ID，则不能保证无状态重置难以与其他数据包区分开来。为了达到这个目的，终端应该确保它发送的所有数据包至少比它要求对端在其数据包中包含的最小CID长度长22个字节，必要时添加PADDING帧。这确保了对端发送的任何无状态重置与发送到终端的有效数据包无法区分。 终端发送无状态重置以响应一个43字节或更短的数据包时，应该发送比它响应的数据包短一个字节的无状态重置。

这些值假定无状态重置token与包保护AEAD的最小扩展长度相同。如果终端可以协商一个具有更大最的小扩展的数据包保护方案，则需要额外的不可预测字节。

终端绝不能发送比它收到的数据包大三倍或更多的无状态重置，以避免被用于放大，第10.3.3节描述了对无状态重置大小的额外限制。

终端必须丢弃那些太小而不能成为有效QUIC数据包的数据包。举个例子，对于[QUIC-TLS]中定义的AEAD函数集，小于21字节的短报头数据包是绝对无效的。

终端必须发送格式为短包头数据包的无状态重置数据包。 但是，终端必须将任何以有效的无状态重置token结尾的数据包视为无状态重置，因为其他QUIC版本可能允许使用长包头。

终端可以发送无状态重置，以响应具有长包头的数据包。在无状态重置token对于对端可用之前，发送无状态重置是无效的。在这个QUIC版本中，带有长包头的数据包只在连接建立期间使用。因为在连接建立完成或接近完成之前，无状态重置token不可用，因此，忽略具有长包头的未知数据包可能与发送无状态重置一样有效。

终端无法从短包头数据包中确定SCID，因此无法在无状态重置数据包中设置DCID。因此，DCID将与之前数据包中使用的值不同。随机的DCID使CID看起来是移动到使用NEW_CONNECTION_ID帧提供的新CID的结果（第19.15节）。

使用随机的CID会导致两个问题：

* 数据包可能无法到达对端。如果DCID对于向对端路由至关重要，那么这个数据包可能会被错误地路由。这也可能会触发另一个无状态重置作为响应（见第10.3.3节）。没有正确路由的无状态重置是一种无效的错误检测和恢复机制。在这种情况下，终端将需要依靠其他方法（例如定时器）来检测连接是否已经失败。

* 随机生成的CID可以被对端以外的实体用来识别这是一个潜在的无状态重置，偶尔使用不同CID的终端可能会对此带来一些不确定性。

这种无状态重置设计是针对QUIC version 1 的，支持多个版本的QUIC的终端需要生成一个无状态重置，该重置将被支持该终端可能支持的任何版本（或在失去状态之前可能已经支持的版本）的对端所接受。 QUIC新版本的设计者需要意识到这一点，要么重用这种设计，要么使用最后16个字节以外的一部分数据包来携带数据。

### 10.3.1. Detecting a Stateless Reset

一个终端使用udp数据包的最后16个字节来检测一个包是否为无状态reset。一个终端记住了所有它发送的stateless reset token以及它的cid和远端地址。这包含了NEW_CONNECTION_ID帧和服务端传输参数中的stateless reset token，但是不包含那些已经不再使用或者废弃的CID相关的stateless reset token。终端通过对比数据包的最后16字节和收数据报的远端地址相关联所有的stateless reset token，来识别这个数据包是否是stateless reset。

可以在每个达到的数据包进行这样的对比操作。如果所有数据报中的包都被成功处理，终端可以（MAY）跳过这个检查。然而，当到达的数据报中的第一个包无法与一个连接关联起来，或者无法解密，那么必须（MUST）进行对比操作。

终端必须不能（MUST NOT）检查任何它还没有使用或者已经废弃的CID有关联的stateles reset token。
当对数据报和stateless reset token值进行比较是，终端必须（MUST）不能泄露token值有关的信息。比如，在固定时间内进行对比保护了各个stateless reset token的值，防止定时侧通道出现信息泄露。另一种方式是存储和比较stateless reset token的转换值而不是原始的token值，其中转换方法被定义为使用了密钥（如，快密码，HMAC）的加密安全、伪随机函数。终端不需要保护关于包是否成功解密、可用stateless reset token数量的信息。

如果数据报的最后16字节和stateless reset token相同，那么终端必须（MUST）进入到排空状态，并在这种连接中不再发送数据。

### 10.3.2. Calculating a Stateless Reset Token

无状态重置token必须是难以猜测的。为了创建无状态重置token，终端可以为它创建的每个连接随机生成一个secret（[RANDOM]）。然而，当遇到一个集群中有多个实例或一个终端可能失去状态的存储问题时，这会带来协调问题。无状态重置是专门为了处理状态丢失的情况而存在的，所以这种方法是次优的。

通过使用伪随机函数生成证明，使用静态密钥和端点选择的CID（见5.1节）作为输入，可以在所有连接到同一终端的连接中使用单个静态密钥。 终端可以使用HMAC[RFC2104]（例如HMAC(static_key, connection_id)）或HKDF[RFC5869]（例如，使用静态密钥作为input keying material，CID作为salt），该函数的输出被截断为16个字节，以产生该连接的无状态重置token。

失去状态的终端可以使用同样的方法来生成有效的无状态重置token，CID来自于终端收到的数据包。

这种设计依赖于对端总是在其数据包中发送CID，因此终端可以使用数据包中的CID来重置连接。使用这种设计的终端必须对所有连接使用相同的CID长度，或者对CID的长度进行编码，使其可以在没有状态的情况下恢复。此外，它不能提供零长CID。

泄露Stateless Reset Token使任何实体可以终止连接。因此每个token值只能使用一次。
这个选择无状态重置令牌的方法意味着必须不能（MUST NOT）在另外一个连接中使用CID和静态密钥的结合。如果相同的CID被共享静态密钥的实例使用，或者如果攻击者可以导致数据包被路由到一个没有状态但有相同静态密钥的实例，那么就有可能发生拒绝服务攻击（参见第21.11节）。 
一个因泄露无状态重置令牌而被重置的连接的CID必须不能（MUST NOT）在一个共享了静态密钥的新连接中重用

同一个无状态重置令牌必须不能（MUST NOT）跟多个CID一起使用。虽然不要求终端对比新旧值，但是可以（MAY）把值的重复当成一种PROTOCOL_VIOLATION类型的连接错误。

请注意，无状态重置数据包没有任何加密保护。

### 10.3.3. Looping

Stateless State的设计是这样的：如果不知道stateless reset token，就无法和有效包进行区分。比如，如果服务端发送了一个Stateless Reset给另一个服务端，那么发送服务端可能收到另一个Stateless Reset（接收服务端的响应），这就会导致无限循环。

终端必须（MUST）保证它发送的每个Stateless Reset比触发Stateless Reset的包要小，除非终端维护了有效的状态机来防止循环。在循环过程中，这套机制保证最终包会过小，从而不再触发响应。

终端可以记住它已经发送的Stateless Reset包的数量，一旦达到限制后，就不再产生新的Stateless Reset包。对不同远端地址使用单独的限制能够保证，其他连接或对端达到限制后，可以使用Stateless Reset包来关闭连接。

根据对端的词的长度，如果Stateless Reset的大小减到41字节以下，意味着将Stateless Reset暴露给观察者（小于41就肯定是Stateless Reset）。相反，如果拒绝对一个小包发送Stateless Reset，可能导致Stateless Reset无法检测到只能发送很小包的破损连接；这样的场景可能只能由其他方法来检测，比如定时器。

# 11. Error Handling

终端检测到错误时应当（SHOULD）发送信号给对端。传输层和应用的的错误都可能导致连接关闭，但只有应用层的错误可以细化到stream级别。（即传输层错误无法区分哪个stream发生了错误）

通知错误的帧应当（SHOULD）使用最合适的错误码（第20章）。错误条件和错误码是一一对应的。尽管这些条件被列为需求，但是不同的实现策略可能上报不同的错误码。实际上，终端检测到错误后，可以（MAY）使用任意可用的错误码；总是可以使用通过错误码（比如PROTOCOL_VIOLATION或INTERNAL_ERROR）来替代具体的错误码。

在可以使用CONNECTION_CLOSE 或 RESET_STREAM frame的情况下，不应当使用stateless reset（第10.3节）。如果终端已经具备在连接上发送帧的状态，则必须不能（MUST NOT）使用stateless reset。

## 11.1. Connection Errors

各种导致连接不可用的错误，比如协议语义无效，或者影响整个连接的状态崩溃，必须（MUST）以CONNECTION_CLOSE frame的形式通知对端。

特定于应用程序的协议错误使用帧类型为0x1d的CONNECTION_CLOSE帧来指示。
特定于传输的错误（包括本文中描述的所有错误），都在CONNECTION_CLOSE帧中携带，帧类型为0x1c。

CONNECTION_CLOSE帧可能会在丢失的数据包中发送。终端如果在终止的连接上收到更多的数据包，则应该准备好重传包含CONNECTION_CLOSE帧的数据包。限制重传的次数和发送此最终数据包的时间，可以限制在终止的连接上所花费的精力。

选择不重传包含CONNECTION_CLOSE帧的数据包的终端，可能会导致对端丢失第一个此类数据包。对于继续接收终止连接数据的终端来说，唯一可用的机制是尝试stateless reset process（第10.3节）。

由于Initial包上的AEAD不提供强认证，终端可以丢弃无效的Initial包。即使在本规范规定连接错误的情况下，也允许丢弃Initial包。终端只有在不处理数据包中的帧或不恢复任何处理效果的情况下，才能丢弃该数据包。丢弃无效的Initial包可以用来减少DoS的风险（见第21.2节）。

## 11.2. Stream Errors

如果应用层错误影响了单个流，但以其他方式使连接处于可恢复状态，终端可以发送一个带有适当错误码的RESET_STREAM帧（第19.4节），只终止受影响的流。

在没有应用协议参与的情况下，重置一条流可能导致应用协议进入到一个无法恢复的状态。RESET_STREAM必须（MUST）只能被那些使用QUIC的应用协议触发。

应用协议定义了RESET_STREAM中携带的应用错误码的语义。只有应用协议能够终止一条流。一个本地应用协议实例直接调用了API，远端应用协议实例使用了STOP_SENDING帧，就会自动触发RESET_STREAM。

如果一条流被两端过早取消，应用协议应当（SHOULD）为这种情况定义处理规则。

# 12. Packets and Frames

QUIC终端通过交换数据包进行通信。
数据包具有机密性和完整性保护（见第12.1节）。
数据包以UDP数据报的形式传送（见第12.2节）。 

这个版本的 QUIC 在建立连接时使用长包头（见第 17.2 节）。 使用长包头的数据包有Initial（17.2.2节）、0-RTT（17.2.3节）、Handshake（17.2.4节）和Retry（17.2.5节）。 版本协商使用与版本无关的长包头数据包（见第17.2.1节）。

带有短包头的数据包是为最小开销而设计的，并且在建立连接和1-RTT密钥可用之后使用（见第17.3节）。

## 12.1. Protected Packets

QUIC数据包根据数据包的类型有不同级别的加密保护。有关数据包保护的详细内容请参见 [QUIC-TLS]；本节概述了所提供的保护。

Version Negotiation packet 没有加密保护，请参见[QUIC-INVARIANTS]。

Retry packet 使用带有关联数据功能的认证加密（AEAD；[AEAD]）来防止意外修改。

Initial packet 使用AEAD，其密钥是使用线上可见的值导出的。因此，Initial packet 不具有有效的机密性保护，初始保护的存在是为了确保数据包发送方的网络连通性。任何从客户端接收 Initial packet 的实体都可以恢复密钥，这将使他们既能读取数据包的内容，又能生成 Initial packet，在任何一个终端都能成功认证。 AEAD还可以保护 Initial packet 不被意外修改。

所有其他数据包都用从加密握手中获得的密钥保护。加密握手确保只有通信终端收到 Handshake、0-RTT和1-RTT数据包的相应密钥。用0-RTT和1-RTT密钥保护的数据包具有很强的机密性和完整性保护。

出现在某些数据包类型中的数据包序号字段具有替代性的机密性保护，它作为包头保护的一部分被应用；详情请参见[QUIC-TLS]的5.4节。 在给定的包序号空间中，基础包序号会随着每一个包的发送而增加；详见第12.3节。

## 12.2. Coalescing Packets

Initial（第17.2.2节）、0-RTT（第17.2.3节）和Handshake（第17.2.4节）数据包包含一个长度字段，该字段确定数据包的结尾。长度包括包序号和有效载荷字段，二者均受机密性保护，并且初始长度未知。一旦删除了报头保护，就可以了解有效负载字段的长度。

使用长度字段，发送方可以把多个QUIC packet合并到一个UDP datagram里面发送。合并发包，可以减少握手过程中实际发送的UDP datagram数量。这也可以用来构建PMTU探测（参考14.4.1小节）。接收方必须（MUST）能够处理合并的数据包。

packet合并最好以加密等级递增的顺序（Initial、0-RTT、Handshake、1-RTT），这样便于接收方一次处理所有的数据包。short header packet是没有长度字段的，因此它只能是一个UDP datagram中的最后一个包。如果要以相同的加密级别发送多个帧，终端应该在一个数据包中包含多个帧，而不是在相同的加密级别上合并多个数据包。

接收者可以根据UDP datagram中包含的第一个数据包的信息进行路由。发送方不得将具有不同CID的QUIC数据包合并到一个UDP datagram中。接收方应该忽略具有与数据报中第一个数据包不同的DCID的任何后续数据包。

合并为单个UDP datagram中的每个QUIC packet，都是独立且完整的。接收方必须（MUST）独立地处理每个packet，并独立地给每个packet回复ACK，就好像它们是作为不同UDP datagram的有效载荷接收的一样。

例如，如果解密失败（由于密钥不可用或任何其他原因），接收方可以（MAY）丢弃或者buffer住这些包后续处理，并且必须（MUST）尝试处理剩余的其他包。

不能在 Retry / Version Negotiation / 所有short header packet 后续接其他packet。（因为这些packet没有length，无法判断边界）。注意，任何情况下都不会将Retry或Version Negotiation包和其他包合并。

## 12.3. Packet Numbers

packet number是个[0, 2^62-1]范围内整数，在报文封装中是个变长整型格式（16节）。
packet number会用来生成packet加密使用的nonce。
每个终端为发包和收到维护独立的packet number序列。

packet number限制在此范围内，因为它们需要在ACK帧的 Largest Acknowledged 字段中完整表示（第19.3节）。但是，当出现在长包头或短包头中时，packet number 将减少并以1到4个字节进行编码。 请参阅第17.1节。

Version Negotiation / Retry 没有packet number字段。

packet number被拆分为3个空间：

* Initial space：所有的Initial packet使用。
* Handshake space：所有的Handshake packet使用。
* Application data space：所有0-RTT和1-RTT加密packet使用。

如[QUIC-TLS]中所述，每种数据包类型使用不同的保护密钥。

从概念上讲，packet number space是packet被处理和响应(ACK)的上下文空间。

Initial packet只能被Initial等级的密钥加密，其ACK报文也是Initial packet。
Handshake packet只能被Handshake等级的密钥加密，并且ACK报文也是Handshake packet。

这种定义使得不同packet number空间下的报文使用不同加密等级。
每个packet number空间从下标0开始。后续packet必须（MUST）每次至少递增1.

0-RTT和1-RTT数据在相同的packet number空间下，为了使丢包重传算法的实现更简单（注意加密密钥不同）。

QUIC终端不能（MUST NOT）在一条连接内的同一个number空间下，重复使用同一个packet number。如果packet number下标超过2^62-1，发送方必须关闭（MUST）连接，而不发送CONNECTION_CLOSE帧或任何进一步的数据包；终端可以发送一个无状态重置（10.3节）来响应它收到的进一步数据包。

接收者必须丢弃一个新的未受保护的数据包，除非它确信它没有处理来自同一数据包号空间的另一个具有相同数据包号的数据包。 由于[QUIC-TLS]第9.5节中描述的原因，重复抑制必须在取消数据包保护后发生。

除非确定接收方没有处理过来自相同number空间中具有相同packet number的另一个数据包，否则接收方必须丢弃新的未受保护的重复数据包。出于[QUIC-TLS]第9.5节中所述的原因，必须在解密后进行去重。

为了检测冗余而追踪每个包的终端，面临着状态堆积的风险。可以维护一个最小包数量的参数，来限制用于检测重复的数据，小于这个值，就立刻丢弃所有包。任何最小值都需要考虑到往返时间的巨大变化，其中包括对端探测到的网络路径可能具有更大的往返时间; 参见第9章。

发送方的封包格式和接收方的解包格式在第17.1节中描述。

## 12.4. Frames and Frame Types

QUIC packets的payload部分，在解密之后，由一系列frame构成，如图11所示。
Version Negotiaion, Stateless Reset, Retry packet不包含frame.

```
   Packet Payload {
     Frame (8..) ...,
   }

                          Figure 11: QUIC Payload
```

QUIC payload内容必须（MUST）至少包含1个frame，可能（MAY）包含多种类型frame。
终端必须将收到不包含帧的数据包视为PROTOCOL_VIOLATION类型的连接错误。 
frame必须（MUST）被填入一个QUIC packet，不能跨越多个包。

每个frame以Frame Type字段起始，剩余部分由各个frame类型决定：

```
   Frame {
     Frame Type (i),
     Type-Dependent Fields (..),
   }

                      Figure 12: Generic Frame Layout
```

下表列出并总结了本规范中定义的每种frame类型的信息，表后有对该摘要的说明。

```
   +=============+======================+===============+======+======+
   | Type Value  | Frame Type Name      | Definition    | Pkts | Spec |
   +=============+======================+===============+======+======+
   | 0x00        | PADDING              | Section 19.1  | IH01 | NP   |
   +-------------+----------------------+---------------+------+------+
   | 0x01        | PING                 | Section 19.2  | IH01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x02 - 0x03 | ACK                  | Section 19.3  | IH_1 | NC   |
   +-------------+----------------------+---------------+------+------+
   | 0x04        | RESET_STREAM         | Section 19.4  | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x05        | STOP_SENDING         | Section 19.5  | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x06        | CRYPTO               | Section 19.6  | IH_1 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x07        | NEW_TOKEN            | Section 19.7  | ___1 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x08 - 0x0f | STREAM               | Section 19.8  | __01 | F    |
   +-------------+----------------------+---------------+------+------+
   | 0x10        | MAX_DATA             | Section 19.9  | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x11        | MAX_STREAM_DATA      | Section 19.10 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x12 - 0x13 | MAX_STREAMS          | Section 19.11 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x14        | DATA_BLOCKED         | Section 19.12 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x15        | STREAM_DATA_BLOCKED  | Section 19.13 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x16 - 0x17 | STREAMS_BLOCKED      | Section 19.14 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x18        | NEW_CONNECTION_ID    | Section 19.15 | __01 | P    |
   +-------------+----------------------+---------------+------+------+
   | 0x19        | RETIRE_CONNECTION_ID | Section 19.16 | __01 |      |
   +-------------+----------------------+---------------+------+------+
   | 0x1a        | PATH_CHALLENGE       | Section 19.17 | __01 | P    |
   +-------------+----------------------+---------------+------+------+
   | 0x1b        | PATH_RESPONSE        | Section 19.18 | ___1 | P    |
   +-------------+----------------------+---------------+------+------+
   | 0x1c - 0x1d | CONNECTION_CLOSE     | Section 19.19 | ih01 | N    |
   +-------------+----------------------+---------------+------+------+
   | 0x1e        | HANDSHAKE_DONE       | Section 19.20 | ___1 |      |
   +-------------+----------------------+---------------+------+------+

                           Table 3: Frame Types
```

第19章详细解释了每种frame类型的格式和语义，本节的其余部分提供了重要的和一般信息的总结。

ACK、STREAM、MAX_STREAMS、STREAMS_BLOCKED和CONNECTION_CLOSE帧中的帧类型用于携带其他帧特定的标志。对于所有其他帧，帧类型字段只是简单地标识该帧。

上表中的“Pkts”栏罗列了每个帧类型可能出现的包的类型，字符的具体意义如下：

* I：Initial
* H：Handshake
* 0：0-RTT
* 1：1-RTT
* ih：只有类型0x1c的CONNECTION_CLOSE帧才能出现在Initial或Handshake包中

关于这些约束的更多细节，请参阅第12.5节。
请注意，所有帧都可以出现在1-RTT数据包中。
终端必须将收到不允许的数据包类型中的帧视为PROTOCOL_VIOLATION类型的连接错误。

表3中的 "Spec "栏总结了管理帧类型的处理或生成的任何特殊规则，由以下字符表示。

* N：只包含带有此标记的帧的数据包不进行ack- eliciting；见第13.2节
* C：仅包含带有此标记的帧的数据包不计入in-flight的字节，以达到拥塞控制的目的；见[QUIC-RECOVERY]
* P：在连接迁移过程中，仅包含带有此标记的帧的数据包可用于探测新的网络路径；见第9.1节
* F：带有此标记的帧的内容是受到流控的；见第4节

表3中的 "Pkts "和 "Spec "列不构成IANA注册表的一部分；见第22.4节。

收到未知类型的帧，终端必须（MUST）将这种情况当成是FRAME_ENCODING_ERROR类型的连接错误。

在这个版本的QUIC中，所有的QUIC frame都是幂等的：多次收到同一个有效的帧，不应出现额外错误或影响。

Frame Type 字段使用可变长度的整数编码（见第16节），但有一个例外。 为了确保帧解析的简单和高效实现，帧类型必须使用尽可能短的编码。对于本文档中定义的帧类型，这意味着使用单字节编码，即使这些值可以编码为2、4或8字节的可变长度整数。例如，尽管0x4001是一个值为1的可变长度整数的合法的两字节编码，但PING帧始终被编码为一个值为0x01的单字节。 这一规则适用于所有当前和未来的 QUIC 帧类型。 终端可以将收到使用长于必要的编码的帧类型视为PROTOCOL_VIOLATION类型的连接错误。

## 12.5. Frames and Number Spaces

有些帧被禁止出现在不同的包序号空间中。此处的规则适用于TLS的规则，与建立连接相关的帧通常可以出现在任何包序号空间的数据包中，而与传输数据相关的帧只能出现在应用程序数据包序号空间。

* PADDING，PING，CRYPTO帧可以出现在任何包序号空间。
* 表示QUIC层（类型0x1c）错误的CONNECTION_CLOSE帧可能出现在任何包序号号空间中；表示应用程序错误（类型0x1d）的CONNECTION_CLOSE帧必须仅出现在应用程序数据包序号空间中。
* ACK帧可以出现在任何包序号空间，但只能确认出现在该包序号空间的数据包。但是，如下所述，0-RTT数据包不能包含ACK帧。
* 所有其他的帧类型必须只能在应用程序数据包序号空间中发送。

请注意，由于各种原因，不能在0-RTT数据包中发送以下帧：ACK、CRYPTO、HANDSHAKE_DONE、NEW_TOKEN、PATH_RESPONSE和RETIRE_CONNECTION_ID。 服务端可以将0-RTT包中收到的这些帧视为PROTOCOL_VIOLATION类型的连接错误。

# 13. Packetization and Reliability

发送方在一个 QUIC 包中发送一个或多个帧；见第 12.4 节。

发送方可以通过在每个QUIC包中包含尽可能多的帧来最小化每个包的带宽和计算成本。发送方可以在发送一个没有被最大限度地包装的数据包之前，等待一小段时间来收集多个帧，以避免发送大量的小数据包。实现可以使用有关应用程序发送行为的知识或启发式方法来决定是否等待以及等待多长时间。这个等待时间是由实现决定的，实现应该谨慎地延迟，因为任何延迟都可能增加应用程序可见的延迟。

stream多路复用是通过把来自于多个stream的STREAM frame，塞进同一个或多个QUIC packet来实现的。一个QUIC包可以包括来自一个或多个流的多个STREAM frame。

QUIC一大优势是避免多个stream之间的队头阻塞问题。如果一个packet出现丢包，只有这个packet中的stream数据会被block等待重传，其他的stream可以继续处理。
请注意，当来自多个流的数据被包含在一个QUIC包中时，该包的丢失会阻止所有这些流的进展。 建议实现在发出的数据包中尽可能少地包含一些流，而不因数据包填充不足而损失传输效率。

## 13.1. Packet Processing

当packet内容被成功解密，并且所有的frame都被处理完之后，这个packet才能被ACK。
对于STREAM frame来说，这意味着数据已经进入队列等待被返回给应用层，但不要求数据已经被应用层消费完。

一旦packet被完整处理，接收端会使用ACK frames来确认回包，这些frame包含了收包对应的packet number。

如果终端收到了一个它没有发过的包的确认信息，且能够检测到这种情况，应当（SHOULD）将这种情况当成是PROTOCOL_VIOLATION类型的连接错误。关于如何实现这一点的进一步讨论见第21.4节。

## 13.2. Generating Acknowledgments

终端对它们收到和处理的所有包都进行确认。然而，只有那些ack-elicting的包才会使终端在最大ack延迟时间内发送ACK帧。
非ack-eliciting包只有在其他原因的情况下，才会触发ACK包的发送。

无论终端以什么原因发送数据包，应当（SHOULD）尝试绑定一个最近还没发送出去的ACK帧。这样做有助于对端进行实时丢失检测。

通常来说，接收者频繁的反馈有助于改善丢包和拥塞响应，但是需要和接收端为每个ack-elictiong包都发送一个ACK引发的负载增长做一个权衡。
以下提供的信息有助于提供这样的平衡

### 13.2.1. Sending ACK Frames

每个数据包应当（SHOULD）被至少确认一次，并且ack-eliciting包必须（MUST）在最大ACK延迟之内被确认至少一次。终端使用max_ack_delay传输参数来通告自己的最大延迟（见18.2节）。max_ack_delay声明了一个显示的条款：一个终端承诺永远不会故意将ack-eliciting包的确认延迟超过指定的值。 如果它这么做，会带来RTT评估增长，并导致对端伪重传或者超时重传。发送方使用接收方的max_ack_delay值来确定基于定时器的重传的超时，详见[QUIC-RECOVERY]第6.2节。

终端必须立即确认所有ack-eliciting的Initial和Handshake包，以及所有ack-eliciting的0-RTT和1-RTT数据包，并在其通告的max_ack_delay内确认，但有以下例外：在握手确认之前，终端可能没有用于解密Handshake、0-RTT或1-RTT数据包的数据包保护密钥。 因此，可能会对它们进行缓冲，并在必要的密钥可用时对它们进行确认。

由于只包含ACK帧的数据包是不受拥塞控制的，因此终端在收到ack-eliciting的数据包时，不得（MUST NOT）发送一个以上的此类数据包作为回应。

即使在收到数据包之前有包间隔，终端也不得（MUST NOT）发送一个non-ack-eliciting的数据包来响应一个non-ack-eliciting的数据包，这样可以避免无限反馈循环，该循环可能会让连接一直繁忙。non-ack-eliciting数据包最终会在终端响应其他事件而发送ACK帧时被确认。

为了协助发送方的丢包检测，当终端收到ack-eliciting的数据包时，应该无延迟地生成并发送ACK帧，或者：

* 当收到的数据包的数据包号小于另一个已收到的ack-eliciting包时，或者
* 当该数据包的数据包号大于已收到的最高编号的ack-eliciting包，且该数据包与本包之间有缺失的数据包时

同样，在IP头中标有ECN Congestion Experienced（CE）码点的数据包也应该立即被确认，以减对端对拥塞事件的响应时间。

[QUIC-RECOVERY]中的算法可对不遵循上述指导的接收方具有弹性。然而，只有在仔细考虑改变对终端和网络其他用户的连接的性能影响后，实现才可以偏离这些要求。

只发送ACK帧的终端将不会收到来自其对端的确认，除非这些确认包含在带有ACK帧的数据包中。
当有新的ack-eliting数据包需要确认时，终端应该与其他帧一起发送ACK帧。当只有non-ack-eliting数据包需要确认时，终端可以等到收到ack-eliting数据包后才将ACK帧与出站帧一起发送。

接收方不能在所有non-ack-eliting的数据包中发送ack-eliting帧，以避免出现无限的ACK反馈循环

### 13.2.2. Acknowledgment Frequency

接收者决定了用于响应ack-eliciting包的确认信息的发送频率。这个频率又牵涉了权衡。

终端依赖了适时的确认信息来检测丢包；参考[QUIC-RECOVERY]第6章。基于窗口的拥塞控制器，比如[QUIC-RECOVERY]第7张定义的，依赖了确认信息来管理它们的拥塞窗口。无论丢包检测还是拥塞控制，延迟确认都会显著影响性能。

另一方面，减少那些只携带确认信息的包的频率，就能减少两端传输和处理包的成本。这也同样能够改善严重不称连接上的吞吐量，并利用回程路径容量减少确认流量；参考[RFC3449]第3章。

接收端在收到最少两个包之后，应当（SHOULD）发送一个ACK。这个建议本质上是通用的，和TCP终端行为建议[RFC5681]一致。网络条件的认知、对端拥塞控制器的认知，或者未来的研究和实验可能建议其他具有更好性能特征的确认策略。

### 13.2.3. Managing ACK Ranges

一个送出的ACK帧中包含了一个或多个被确认包的范围。包含对旧包的确认可以减少因前一个ACK帧丢失引起的伪重传，但代价是要发送更大的ACK帧。

ACK帧应当（SHOULD）总是确认最近收到的包，并且乱序越严重，就越要快速的发送一个更新后的ACK，从而来防止对端认为数据包丢失并对包中的帧进行伪重传。一个QUIC包一般都能够囊括一个ACK帧。如果不能够，就忽略掉旧的范围（那些具有最小数据包号的范围）。

接收方限制了它记住并发送的ACK范围（第19.3.1节），以限制ACK帧的大小并避免资源耗尽。在接收到一个ACK帧的确认后，接收方应该停止跟踪这些确认的ACK范围。发送方可以期望收到大多数数据包的确认，但是QUIC不能保证接收方处理的每个数据包都会收到确认。

保留许多ACK范围有可能导致一个ACK帧变得过大。接收方可以丢弃未确认的ACK范围以限制ACK帧大小，但代价是发送方的重传增加。如果一个ACK帧太大而无法容纳在一个数据包中，则这是必要的。接收方还可以进一步限制ACK帧的大小，以保留其他帧的空间或限制确认消耗的容量。

接收方必须保留一个ACK范围，除非它能保证以后不接受在这个范围内序号的数据包。保持一个最小的数据包数量，随着范围的丢弃而增加，是以最小的状态实现这一目标的一种方法。 

接收方可以丢弃所有的ACK范围，但是他们必须保留已经成功处理的最大的包号，因为那是用来从后续的包中恢复包号的；见第17.1节。

接收方应该在每个ACK帧中包含一个包含最大接收数据包号的ACK范围。Largest Acknowledged 字段在发送方的ECN验证中使用，其值小于前一个ACK帧中包含的值，可能会导致ECN被不必要地禁用；见第13.4.2节。

13.2.3和13.2.4小节描述了如何来决定每个ack帧中应该确认什么包的可行方法。尽管这些算法的目标是为每个处理过的包都生成一个ACK，但是确认时有可能丢失的。

### 13.2.4. Limiting Ranges by Tracking ACK Frames

当发送了一个包含ack帧的数据包之后，可以保存那个帧中的最大的被确认序号。当一个包含ACK帧的包被确认，接收端可以停止对小于等于最大被确认序号的数据包的确认。

一个只发送non-ack-eliting数据包（例如ACK帧）的接收方，可能在很长一段时间内都不会收到确认。这可能会导致接收方长时间保持大量ACK帧的状态，它发送的ACK帧可能会不必要地变大。在这种情况下，接收方可以偶尔发送一个PING帧或其他小型ack-eliting帧，例如每往返一次，以引起对端的ACK。

在没有ACK帧丢失的情况下，这种算法允许最小1RTT的重排序。 在有ACK帧丢失和重排的情况下，那么这种方法不能保证发送端在确认信息不再包含在ACK帧之前，能够收到每一个确认信息。包可以被乱序接收并且所有后续包含他们的ACK帧可能丢失。在这种情况下，丢包恢复算法可能导致未重传，但是发送方依旧会继续向前处理。

### 13.2.5. Measuring and Reporting Host Delay

终端通过最大包序号的接收时间与ACK发送时间的差值来衡量故意延迟。终端将这个延迟的数值带在ACK帧的Ack Delay字段中（见19.3节）；这使得ACK的接收者来调整故意延迟，从而在确认延迟的时候有助于RTT的计算。

一个数据包在被处理之前可能会被保存在操作系统内核或主机的其他地方。在填写ack的Ack Delay字段时，终端必须不能（MUST NOT）包含不受它控制的延迟。然而，终端应该包含因无法获得解密密钥而造成的缓冲延迟，因为这些延迟可能很大，而且很可能是不重复的。

当测量到的确认延迟大于其max_ack_delay时，终端应该报告测量到的延迟。这个信息在握手过程中特别有用，因为延迟可能很大；见第13.2.1节。

### 13.2.6. ACK Frames and Packet Protection

ACK帧必须只在与被确认的数据包具有相同数据包号空间的数据包中携带；见第12.1节。 例如，用1-RTT密钥保护的数据包必须在同样用1-RTT密钥保护的数据包中进行确认。

客户端发送的0-RTT加密报文必须（MUST）被服务端以1-RTT密钥加密报文ACK。如果服务端的加密握手信息丢包或者延迟了，客户端会解密不了这些ACK。服务端以1-RTT密钥加密的其他数据也可能碰到这个问题。

### 13.2.7. PADDING Frames Consume Congestion Window

处于拥塞控制目的，包含PADDING帧的包会被视为正在传输中[QUIC-RECOVERY]。因此只包含PADDING帧的包会消耗拥塞窗口，但不会生成确认信息来让发送端回收拥塞窗口。为了避免死锁，发送端应当（SHOULD）保证除了PADDING帧之外，还会周期性地发送其他帧来触发接收方的ACK。

## 13.3. Retransmission of Information

被确定为丢失的QUIC数据包不会被完整地重传，丢失数据包中包含的帧同理。 相反，可能在帧中携带的信息会在需要时以新帧的形式再次发送。

新的帧和数据包用来携带确定已经丢失的信息。 一般来说，当确定包含该信息的数据包丢失时，就会再次发送信息，当包含该信息的数据包被确认时，就会停止发送。

* CRYPTO frame：根据[QUIC-RECOVERY]的机制重传，直到所有数据被确认。当丢弃对应数据包编号空间的密钥时，将丢弃CRYPTO帧中用于Initial和Handshake包的数据。
* STREAM frame：应用层数据重传会被塞进新的STREAM frame。如果收到RESET_STREAM会停止重传。
* ACK frame：携带最近的一组ACK和来自最大已确认数据包的ACK延迟。延迟包含ACK的包的发送，或者发送旧的ACK帧，会导致对端的RTT采样不稳定，或不必要地禁用ECN。
* RESET_STREAM frame: 用来终止stream重传，直到被确认或对端确认所有流数据为止（即在流的发送部分达到 "Reset Recvd "或 "Data Recvd "状态）。RESET_STREAM帧的内容在再次发送时不得改变。
* STOP_SENDING frame: 用来要求对方停止重传，直到流的接收部分进入“ Data Recvd”或“ Reset Recvd”状态为止（参阅第3.5节）。
* CONNECTION_CLOSE frame: 在被检测到丢包时不重传，按照第10章的规定发送。
* MAX_DATA frame: 当前连接的最大数据量。如果包含最近发送的MAX_DATA帧的数据包被宣布丢失，或者当终端决定更新限制时，MAX_DATA帧中会发送一个更新值。 需要注意避免过于频繁地发送该帧，因为限值可能会频繁增加，并导致不必要地发送大量的MAX_DATA帧（见4.2节）。
* MAX_STREAM_DATA frame: 当前stream的最大数据量。与MAX_DATA一样，当包含流的最新MAX_STREAM_DATA帧的数据包丢失或更新限制时，会发送一个更新的值，并注意防止帧发送过于频繁。 当流的接收部分进入 "Size Known "或 "Reset Recvd "状态时，终端应停止发送MAX_STREAM_DATA帧。

* MAX_STREAMS frame: 限制某种类型stream的最大数量。与MAX_DATA一样，当包含流类型帧的最新MAX_STREAMS的数据包被宣布丢失或更新限制时，将发送更新值，并注意防止帧发送过于频繁。
* DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED frame: 上面三个限制对应的被block通知，重传时以最新的限制值发送。但只有在终端被阻塞在相应的限制上时才会发送。 这些帧在传输时总是包括导致阻塞的限制。
* PATH_CHALLENGE frame: 定期发送有效性或路径验证检查，重传直到收到匹配的PATH_RESPONSE，或者没必要再校验了。每次重传的随机payload内容不一样。
* PATH_RESPONSE frame: PATH_CHALLENGE的应答内容，不重传。如果丢了发送方会重传PATH_CHALLENGE的。
* NEW_CONNECTION_ID frame: 用来更新connection IDs，丢了会重传，重传frame携带相同的sequence number。同样，retired的CID以RETIRE_CONNECTION_ID帧的形式发送，丢了就重传。
* NEW_TOKEN frame：如果丢包就重传。除了直接比较帧内容，没有什么特别的方法来检测NEW_TOKEN乱序或重复.
* PING / PADDING frame: 没有携带信息，丢了不重传。
* HANDSHAKE_DONE frame：如果一直没被确认，就必须（MUST）一直重传。

除非应用程序指定的优先级另有说明，否则终端应优先重传数据，而不是发送新数据；见第2.3节。

尽管鼓励发送者每次发送数据包时将包含实时信息的帧进行合并，但也不禁止丢包时重传帧的副本。一个重传帧副本的终端需要处理因包序号长度、CID长度、链路MTU的改变的可用负载大小。接收者必须（MUST）接受那些包含过时帧的包，比如比之前最大数据值更小的MAX_DATA帧。

一旦数据包被确认，发送方应避免重传数据包的信息。这包括在宣布丢失后被确认的数据包，这可能发生在网络重排的情况下。 这样做需要发送方保留数据包被宣布丢失后的信息。 发送方可以在经过一段足以允许重排的时间（例如PTO（[QUIC-RECOVERY]的第6.2节））或其他事件（例如达到内存限制）后丢弃此信息。

检测到丢包后，发送方必须采取适当的拥塞控制措施。 丢包检测和拥塞控制的细节在[QUIC-RECOVERY]中描述。

## 13.4. Explicit Congestion Notification

QUIC终端可以使用ECN（Explicit Congestion Notification）来检测和响应网络拥塞情况 [RFC3168]。ECN允许终端在IP头的ECN字段中设置一个ECT codepoint，然后，网络节点可以通过在ECN字段中设置CE codepoint来指示拥塞，而不是直接丢包。终端对报告的拥塞作出反应，降低其发送速率作为响应，如[QUIC-RECOVERY]所述。

要启用ECN，发送的QUIC终端首先要确定路径是否支持ECN标注，以及对端是否在接收到的IP头中报告ECN值；参见第13.4.2节。

### 13.4.1. Reporting ECN Counts

使用ECN需要接收终端从IP包中读取ECN字段，但并非所有平台都能做到这一点。如果一个终端不支持ECN，或者无法访问接收到的ECN字段，它就不会报告它所接收的数据包的ECN计数。

即使终端没有在它发送的数据包上设置ECT字段，终端也必须提供关于它收到的ECN标记的反馈（如果可访问的话）。 如未能报告ECN计数，将导致发送方禁用该连接的ECN。

在收到带有ECT(0)、ECT(1)或CE codepoint的IP包时，启用ECN的终端会访问ECN字段并增加相应的ECT(0)、ECT(1)或CE计数。这些ECN计数包含于随后的ACK帧中（见第13.2节和第19.3节）。

每个包序号空间保持单独的ACK状态和单独的ECN计数。 合并的QUIC报文（见第12.2节）共享相同的IP头，因此每个合并的QUIC报文的ECN计数都会递增一次。

例如，如果Initial、Handshake和1-RTT QUIC报文各一个被合并到一个UDP数据报中，那么所有三个报文号空间的ECN计数将根据单一IP头的ECN字段各增加一。

只有在处理来自接收的IP包的QUIC数据包时，ECN计数才会递增。 因此，重复的QUIC报文不会被处理，也不会增加ECN计数；相关安全问题见第21.10节。

### 13.4.2. ECN Validation

故障的网络设备有可能损坏或错误地丢弃携带非零ECN codepoint的数据包。为了确保在这种设备存在的情况下的连通性，终端会验证每个网络路径的ECN计数，如果检测到错误，就会禁止在该路径上使用ECN。

要对新路径执行ECN校验，需执行以下操作：

* 终端在通过新路径发送到对端的早期传出数据包的IP报头中设置一个ECT(0) codepoint（[RFC8311]）。
* 终端监视通过ECT codepoint发送的所有数据包是否最终都被视为丢失（[QUIC-RECOVERY]的第6节），指示ECN校验失败。

如果终端有理由预判故障的网络元素会丢弃带有ECT codepoint 的IP包，终端可以只为路径上的前10个出站数据包设置ECT codepoint，或者为3个PTO的时间段设置ECT codepoint（见[QUIC-RECOVERY]第6.2节）。如果用非零ECN codepoint 标记的所有数据包随后丢失，它可以在假设标记导致丢失的情况下禁用标记。

因此，当切换到服务器的偏好地址时，以及在将活动连接迁移到新路径时，终端会尝试使用ECN并针对每个新连接对其进行校验。附录A.4描述了一种可能的算法。

其他探测路径是否支持ECN的方法和不同的标记策略也是可能的。实现可以使用RFC中定义的其他方法，参见[RFC8311]。 使用ECT(1) codepoint的实现需要使用报告的ECT(1)计数来执行ECN校验。

#### 13.4.2.1. Receiving ACK Frames with ECN Counts

网络错误地使用CE标记会导致连接性能下降。 因此，接收到带有ECN计数的ACK帧的终端在使用这些计数之前会对其进行校验。它通过将新收到的计数与上一个成功处理的ACK帧的计数进行比较来执行这种校验。 根据应用于ACK帧中新确认的数据包的ECN标记，可以验证任何ECN计数的增加。

当ACK帧新确认了终端用ECT(0)或ECT(1) codepoint 集发送的数据包，如果ACK帧中没有相应的ECN计数，则ECN验证失败。该检查可以检测到将ECN字段归零的网络元素或不报告ECN标记的对端。

如果增加的ECT(0)和ECN-CE计数之和小于最初发送的带有ECT(0)标记的新确认数据包的数量，ECN验证也会失败。 同样，如果增加的ECT(1)和ECN-CE计数之和小于以ECT(1)标记发送的新确认数据包的数量，则ECN验证失败。 这些检查可以检测网络对ECN-CE标记的重标记（remarking）。

当ACK帧丢失时，终端可能会错过一个数据包的确认。 因此，ECT(0)、ECT(1)和ECN-CE计数的总增加量有可能大于被ACK帧新确认的数据包数量。 这就是为什么ECN计数允许大于被确认的数据包总数的原因。

从重排的ACK帧验证ECN计数可能导致失败。终端不得因处理没有增加最大确认数据包数的ACK帧而导致ECN验证失败。

如果ECT(0)或ECT(1)的接收总计数超过了每个相应ECT codepoint发送的数据包总数，ECN验证就会失败。 特别是，当终端收到与它从未应用的ECT codepoint对应的非零ECN计数时，验证将失败。此检查检测何时将数据包标记为网络中的ECT(0)或ECT(1)。

#### 13.4.2.2. ECN Validation Outcomes

如果验证失败，那么终端必须禁用ECN。假设网络路径或对端不支持ECN，它就会停止在它发送的IP数据包中设置ECT codepoint。

即使验证失败，终端也可以在连接中的任何时间对同一路径重新验证ECN。 终端可以继续定期尝试验证。

验证成功后，终端可以继续在随后发送的数据包中设置ECT codepoint，并期望该路径具有ECN功能。然而，网络路由和路径元素可能会在连接过程中发生变化；如果后来验证失败，终端必须禁用ECN。

# 14. Datagram Size

一个UDP数据报可以包括一个或多个QUIC数据包。数据报尺寸指的是携带QUIC数据包的单个UDP数据报的总UDP有效载荷大小。数据报尺寸包括一个或多个QUIC包头和加密的有效载荷，但不包括UDP头和IP头。

最大数据报尺寸定义为使用单个UDP数据报在网络路径上发送的UDP有效载荷的最大尺寸。如果网络路径不能支持至少1200 字节的最大数据报尺寸，则不得使用QUIC。

QUIC假设最小IP数据包尺寸至少为 1280 字节，这是IPv6的最小尺寸[IPv6])，也是大多数现代IPv4网络所支持的。 假设IPv6的最小IP头尺寸为40字节，IPv4为20字节，UDP头尺寸为8字节，那么IPv6的最大数据报尺寸为1232字节，IPv4为1252字节。 因此，现代的IPv4和所有的IPv6网络路径都应该能够支持QUIC。

注意：支持1200字节的UDP有效载荷的要求限制IPv6扩展头的可用空间为32字节，如果路径只支持IPv6最小MTU为1280字节，则IPv4选项的可用空间为52字节。这将影响Initial包和路径校验。

可以通过PMTUD（Path Maximum Transmission Unit Discovery）或DPLPMTUD（Datagram Packetization Layer PMTU Discovery）来发现任何比1200字节大的最大包尺寸。

可以强制使用max_udp_payload_size传输参数（第18.2节）来作为包大小的额外限制。一旦知道了这个数值，就可以避免超过这个限制。然而在知晓这个传输参数的值之前，如果终端发送的包大于1200个字节，终端面临着数据报丢失的风险。

UDP数据包必须不能（MUST NOT）在IP层出现分片。在IPv4中，必须（MUST）设置DF位来防止链路上出现分片。

QUIC有时会要求数据报不小于一定的尺寸，见第8.1节的例子。但是，数据报的尺寸并没有经过认证。 也就是说，如果一个端点收到了一定尺寸的数据报，它无法知晓发送方是否以同样的尺寸发送了数据报。 因此，当终端收到不符合大小限制的数据报时，决不能关闭连接；但终端可以丢弃这些数据报。

## 14.1. Initial Datagram Size

客户端必须（MUST）通过添加PADDING帧到initial包或者合并initial包，将所有包含initial包的udp数据报填充到最大包尺寸的最小值（1200个字节），见第12.2节。Initial包甚至可以与无效数据包合并，接收方将丢弃这些数据包。同样地，服务端必须将所有携带ack-eliciting的Initial包的UDP数据报的有效载荷至少扩展到最小允许的最大数据报尺寸（1200字节）。

发送此尺寸的UDP数据报可以确保网络路径在两个方向上都支持一个合理的链路传输最大单元（PMTU）。 此外，扩大Initial包的客户端有助于减少因服务端向一个未经认证的客户端地址进行响应而引起的放大攻击的幅度（见第8节）。

如果发送方认为网络路径和对端都支持它所选择的大小，包含Initial包的数据报可以（MAY）超过1200字节。

服务端必须（MUST）丢弃一个包含了initial包，但是载荷小于1200字节的UDP数据报。服务端也可以（MAY）通过发送一个带PROTOCOL_VIOLATION错误码的CONNECTION_CLOSE帧立刻关闭连接（见第10.2.3节）。

服务端必须（MUST）在检验完客户端地址之前限制它发送的数据量（见第8章）。

## 14.2. Path Maximum Transmission Unit

PMTU是指整个IP报文的最大长度，包括IP header，UDP header，和UDP payload内容。UDP payload内容则包含了一个或多个QUIC packet header，加密payload。PMTU可以取决于路径特性，因此可以随时间变化。终端在任何给定时间发送的最大UDP有效载荷被称为终端的最大数据报尺寸。

终端应当（SHOULD）使用DPLPMTUD（第14.3节）或PMTUD（第14.2.1节）来确定通向目的地的路径是否能支持所需的最大数据报尺寸而不产生分片。在没有这些机制的情况下，QUIC终端不应发送大于最小允许的最大数据报尺寸的数据报。

DPLPMTUD和PMTUD都会发送大于当前最大数据报尺寸的数据报，称为PMTU探针。所有不在PMTU探针中发送的QUIC数据包，其大小都应在最大数据报尺寸范围内，以避免数据报被分片或丢弃（[RFC8085]）。

如果 QUIC 终端确定任何一对本地和远程IP地址之间的PMTU不能支持最小允许的最大数据报尺寸1200字节，它必须立即停止在受影响的路径上发送QUIC数据包，但PMTU探针中的数据包或包含CONNECTION_CLOSE帧的数据包除外。 如果找不到替代路径，终端可以终止连接。

每一对本地和远程地址可以有不同的PMTU。因此，实现任何类型的PMTU发现的QUIC实现应该为本地和远程IP地址的每种组合保持一个最大的数据报尺寸。

在计算最大数据报尺寸以允许未知的隧道开销或IP头选项/扩展时，QUIC实现可能更为保守。

### 14.2.1. Handling of ICMP Messages by PMTUD

PMTUD（[RFC1191]、[RFC8201]）依赖于接收ICMP报文（如IPv6 Packet Too Big消息），该消息指示IP数据包何时由于其大于本地路由器MTU而被丢弃。DPLPMTUD也可以选择使用这些消息。使用ICMP有可能受到那些不能观察数据包但可能成功猜测路径上使用的地址的实体的攻击，这些攻击可能恶意降低PMTU来降低传输效率。

终端必须忽略声称PMTU已经降低到QUIC的最小允许最大数据报尺寸以下的ICMP报文。

生成ICMP的要求（[RFC1812]、[RFC4443]）规定，引用的数据包应尽可能多地包含原始数据包，而不超过IP版本的最小MTU。引用数据包的尺寸实际上可以更小，或者信息无法理解，如[DPLPMTUD]第1.1节所述。

使用PMTUD的QUIC终端应当（SHOULD）检查ICMP报文来抵御数据包注入攻击，如[RFC8201]和[RFC8085]第5.2节所述。这种检测机制应当（SHOULD）使用由ICMP报文payload提供的quoted packet，将报文与相应的传输连接关联起来（参见[DPLPMTUD]的4.6.1节）。ICMP报文检测必须（MUST）包含IP地址和UDP端口的校验（[RFC8085]），并在可能的情况下，包括与活动QUIC会话的CID。终端应当（SHOULD）忽略所有校验失败的ICMP报文。

终端不能（MUST NOT）增加ICMP报文基础上的PMTU（见[DPLPMTUD]第3节第6条）。在QUIC的丢包检测算法确定引用的数据包实际上已经丢失之前， 响应ICMP报文而对QUIC最大数据报尺寸的任何缩减都可以是暂时的。

## 14.3. Datagram Packetization Layer PMTU Discovery

DPLPMTUD（[DPLPMTUD]）依赖于跟踪PMTU探针中携带的QUIC数据包的丢失或确认。使用PADDING帧的DPLPMTUD的PMTU探针实现了[DPLPMTUD]第4.1节中定义的 "Probing using padding data"。

终端应该设置BASE_PLPMTU的初始值（[DPLPMTUD]的5.1节），使其与QUIC允许的最小的最大数据报尺寸一致。 MIN_PLPMTU与BASE_PLPMTU相同。

实现DPLPMTUD的QUIC终端为本地和远程IP地址的每个组合维护一个DPLPMTUD最大数据包尺寸（MPS，[DPLPMTUD]的第 4.4 节），这对应于最大数据报尺寸。

### 14.3.1. DPLPMTUD and Initial Connectivity

从DPLPMTUD的角度来看，QUIC是一个公认的Packetization Layer（PL）。
因此，当QUIC连接握手完成后，QUIC发送方可以进入DPLPMTUD BASE状态（[DPLPMTUD]的5.2节）。

### 14.3.2. Validating the Network Path with DPLPMTUD

QUIC是一个公认的Packetization Layer（PL），因此QUIC发送方在SEARCH_COMPLETE状态下不会实现DPLPMTUD CONFIRMATION_TIMER（见[DPLPMTUD]的5.2节）。

### 14.3.3. Handling of ICMP Messages by DPLPMTUD

使用DPLPMTUD的终端在使用PTB信息之前，需要验证任何收到的 ICMP Packet Too Big（PTB）消息，如[DPLPMTUD]第4.6节所定义。除了UDP端口验证外，QUIC还通过使用其他PL信息来验证ICMP报文（例如，验证任何收到的ICMP报文的 quoted packet 中的CID）。

如果这些消息被DPLPMTUD使用，第14.2.1节中描述的处理ICMP报文的注意事项也适用。

## 14.4. Sending QUIC PMTU Probes

PMTU探针是ack-eliciting的包。

终端可以将PMTU探针的内容限制为PING和PADDING帧，因为大于当前最大数据报尺寸的数据包更有可能被网络丢弃。因此，PMTU探针中携带的QUIC数据包丢失并不是拥塞的可靠指示，不应该触发拥塞控制反应（参见[DPLPMTUD]第3。7节） 但是，PMTU探针会消耗拥塞窗口，这可能会延迟应用程序的后续传输。

### 14.4.1. PMTU Probes Containing Source Connection ID

依靠DCID来路由传入QUIC报文的终端很可能要求在PMTU探针中包含CID，以便将任何产生的ICMP报文（第14.2.1节）路由回正确的终端。 然而，只有长头包（第17.2节）包含SCID字段，而且一旦握手完成，长头包不会被对端解密或确认。

构造PMTU探针的一种方法是将一个长包头数据包（如Handshake或0-RTT数据包（第17.2节））与一个短包头数据包合并在一个UDP数据报中（见第12.2节）。如果产生的PMTU探针到达终端，长包头的数据包将被忽略，但短包头数据包将被确认。如果PMTU探针导致ICMP报文被发送，该报文中将引用探针的第一部分。如果SCID字段在探针的引用部分内，则该字段可用于ICMP报文的路由或验证。

注意：使用具有长包头的数据包的目的只是为了确保ICMP报文中包含的quoted packet包含SCID字段。这个数据包不需要是一个有效的数据包，即使当前没有使用该类型的数据包，也可以发送。

# 15. Versions

QUIC版本由32-bit unsigned整数表示。

版本0x00000000 被保留用来标识版本协商报文。当前QUIC版本号0x00000001。

其他版本的QUIC可能和这个版本的特性不同。[QUIC-INVARIANTS]中描述了不同版本协议之间QUIC属性的连续性。

0x00000001版本QUIC使用了TLS来作为加密握手协议，详见[QUIC-TLS].

版本号的前16个bit被保留给未来的IETF文档用。同时保留了0x?a?a?a?a格式的版本号来进行强制版本协商（试用）。也就是说，这些版本号二进制的最低4位是1010。客户端或者服务端可以（MAY）通告它们对这些保留版本的支持。

保留版本号不会作为正式协议；客户端可以（MAY）使用这些版本号中的一个来尝试让服务端发起版本协商；服务端可以（MAY）通告对这些版本之一的支持，并可以期望客户端忽略该值。

# 16. Variable-Length Integer Encoding

QUIC数据包和帧通常对非负整数值使用可变长度编码。这种编码确保较小的整数值只需要较少的字节进行编码。

编码保留了2个高位bit来表示编码的总字节长度。
实际值被保存在剩余的bit里面，以网络字节序保存。
实际编码长度取值为1，2，4，8，实际值保存空间为6，14，30，62个bit。

```
          +======+========+=============+=======================+
          | 2Bit | Length | Usable Bits | Range                 |
          +======+========+=============+=======================+
          | 00   | 1      | 6           | 0-63                  |
          +------+--------+-------------+-----------------------+
          | 01   | 2      | 14          | 0-16383               |
          +------+--------+-------------+-----------------------+
          | 10   | 4      | 30          | 0-1073741823          |
          +------+--------+-------------+-----------------------+
          | 11   | 8      | 62          | 0-4611686018427387903 |
          +------+--------+-------------+-----------------------+

                   Table 4: Summary of Integer Encodings
```

例子和示例解码算法样本见附录A.1。

除了帧类型字段，值不需要在所需的最小字节数上进行编码（见第12.4节）。

Version(第15章)、包头中发送的packet numbers(第17.1节)、长包头数据包中CID的长度(第17.2节) 使用整数来描述，但不使用这种编码。

# 17. Packet Formats

所有报文格式描述都是网络字节序（大端序）。
所有的字段大小都是以bit为单位。 
十六进制表示法用于描述字段的值。

## 17.1. Packet Number Encoding and Decoding

包序号号是整数，范围为[0, 2^62 - 1]（第12.3节）。当出现在长包头或短包头中时，它们被编码为1~4个字节。 通过只包括包序号的最小有效位，减小了表示包序号所需的位数。

编码后的包序号被加密保护，如[QUIC-TLS]第5.4节所述。

在收到一个包序号空间的确认之前，必须包括完整的包序号，请勿如下所述将其截断。

在收到一个包号空间的确认后，发送方必须（MUST）使用至少2 * (最大发送下标 - 最大ACKed packet)大小的size空间。 接收到该数据包的对端就会正确地解码该数据包号，除非该数据包在传输过程中被延迟，以至于它在收到许多较高编号的数据包后才到达。终端应该使用足够大的包号编码以允许包号被恢复，即使数据包在随后发送的数据包之后到达。

因此，包序号号编码的大小至少比包括新包在内的连续未被ACK的包序号的log2对数多一位。包序号编码的伪代码和例子可以在附录A.2中找到。

接收方需要先解密packet number部分（header解密），再做解码。然后，根据存在的有效位数、这些位的值和成功认证的数据包中收到的最大数据包号，重建完整的数据包号。解密数据包号是解码数据包的的必要条件。

一旦header被解密，数据包号就会通过找到最接近下一个预期数据包的数据包号值进行解码。下一个预期的数据包是最高的接收数据包号加一。包号解码的伪代码和例子可以在附录A.3中找到。

## 17.2. Long Header Packets

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

                    Figure 13: Long Header Packet Format
```

long header 用于在建立1-RTT密钥之前发送的数据包。一旦有了1-RTT密钥，发送方就转而使用short header发送数据包（第17.3节）。long header允许了特殊的包（比如Version Negotiation 包）可以以这种统一固定长度包的格式来表示。

long header字段详解：

* Header Form: 首字节的最高bit(0x80)为1。

* Fixed Bit：首字节的第二个bit(0x40)为1，除非该数据包是版本协商包。此位为0的数据包在此版本中不是有效数据包，必须丢弃。该位的值为1时，允许QUIC与其他协议共存（参见[RFC7983]）。

* Long Packet Type: 首字节接下来的2个bit(0x30)包含packet type。

* Type-Specific Bits: 第0字节的低4位（第一个字节和0x0f做与操作获得），其语义由数据包类型决定。

* Version: QUIC版本是一个32-bit字段，紧跟在首字节之后。该字段表示正在使用的 QUIC 版本，并决定如何解释其余的协议字段。

* Destination Connection ID Length: version后的字节，表示DCID长度的字节数。这个长度是一个8位的无符号整数。在QUIC版本1中，这个值必须不能（MUST NOT）超过20。在版本1的long header中，如果该值大于20，则必须（MUST）丢弃这个包。为了能够生成一个版本协商包，服务端应当（SHOULD）能够从其他QUIC版本中读取更长的CID。

* Destination Connection ID: 长度为[0, 20]字节。第7.2节更详细地描述了此字段的使用。

* Source Connection ID Length: DCID字段后的一个字节，表示SCID长度的字节数。这个长度是一个8位的无符号整数。在QUIC版本1中，这个值必须不能（MUST NOT）超过20。在版本1的long header中，如果该值大于20，则必须（MUST）丢弃这个包。为了能够生成一个版本协商包，服务端应当（SHOULD）能够从其他QUIC版本中读取更长的CID。

* Source Connection ID: 长度为[0, 20]字节。第7.2节更详细地描述了此字段的使用。

当前QUIC版本中使用long header的包类型：

```
                   +======+===========+================+
                   | Type | Name      | Section        |
                   +======+===========+================+
                   |  0x0 | Initial   | Section 17.2.2 |
                   +------+-----------+----------------+
                   |  0x1 | 0-RTT     | Section 17.2.3 |
                   +------+-----------+----------------+
                   |  0x2 | Handshake | Section 17.2.4 |
                   +------+-----------+----------------+
                   |  0x3 | Retry     | Section 17.2.5 |
                   +------+-----------+----------------+

                     Table 5: Long Header Packet Types
```

Header form bit、Destination and Source Connection ID length、Destination and Source Connection ID、Version 字段与版本无关。 第一个字节中的其他字段是版本特定的。关于如何解释来自不同版本 QUIC的数据包，请参见 [QUIC-INVARIANTS] 。

字段和载荷的解释跟版本和包类型有关。虽然这个版本的特定类型的语义在下面的章节中描述，但当前版本QUIC的一些长头包包含了如下额外的字段：

* Reserved Bits：首字节接下来的2个bit(掩码0x0c)被保留。这两个bit使用header protection（[QUIC-TLS]的5.4节），加密前的值是0。非0情况以PROTOCOL_VIOLATION连接失败处理。在头保护解密之后丢弃这个包，会将终端暴露给攻击者（[QUIC-TLS]第9.3节）。

* Packet Number Length：首字节的最后2个bit(0x03)包含了packet number的长度，编码为无符号2-bit整数；实际packet number字段长度为这个值 + 1。该字段同样使用header protection（[QUIC-TLS]的5.4节）。

* Length: packet剩余部分的长度（包括Packet Number 和 Payload部分），以字节为单位，编码为可变长度整数（见第16章）。

* Packet Number：字段长度是1到4个字节，使用header protection（[QUIC-TLS]的5.4节）。packet number的长度在第0字节的Packet Number Length位中编码，见上文。

### 17.2.1. Version Negotiation Packet

Version Negotiation packet在各个QUIC版本格式一致。
客户端在收到后，通过Version字段全0，将其识别为版本协商包。

Version Negotiation packet，是在服务端发现，客户端使用的QUIC版本服务端不支持的情况下，服务端给客户端回复的协商申请。

版本格式如下：

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

                   Figure 14: Version Negotiation Packet
```

Unused字段内容由服务端随机填写。客户端必须（MUST）忽略这个字段（Unused字段）的值。当 QUIC 可能与其他协议复用时（参见[RFC7983]），服务端应当（SHOULD）将这个字段的最高位设置为1，这样版本协商包就看上去有了固定位字段了。请注意，QUIC的其他版本可能不会提出类似的建议。

Version字段为0x00000000.

服务端必须（MUST）在Destination Connection ID字段填入客户端发送的Source Connection ID。
SCID的值必须从收到的数据包的DCID中复制，该ID最初是由客户端随机选择的。 回显这两个CID可以让客户端在一定程度上确信服务端收到了数据包，并且版本协商数据包不是由一个没有观察到Initial包的实体产生的。

未来版本的QUIC可能对CID的长度有不同的要求。特别是，CID可能具有更小的最小长度或更大的最大长度。因此，CID特定于版本的规则绝不能影响服务端有关是否发送版本协商数据包的决定。

剩余部分是一系列服务端支持的32-bit版本号的列表。

版本协商数据包不会被确认，它只在响应指示不支持的版本的数据包时才被发送（见第5.2.2节）。

Version Negotiation不包含Packet Number和Length字段。
Version Negotiation使用一个完整的UDP datagram发送。

服务端不得向一个UDP数据报发送一个以上的版本协商数据包作为响应。

有关版本协商过程的描述，请参见第6章。

### 17.2.2. Initial Packet

Initial packet：type = 0x0，long header格式。
携带客户端发送的第一个CRYPTO frame，用来和服务端做密钥交换，可以携带ACKs。

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

                         Figure 15: Initial Packet
```

Initial packet包含一个长包头以及"Length"和"Packet Number"字段（见第 17.2 节）。 
第一个字节包含"Reserved"和"Packet Number Length"位（见第 17.2 节）。
在SCID和"Length"字段之间，有两个由Initial packet专用的附加字段。

* Token Length：变长整数，表示Token字段的字节数。如果为0表示没有token。服务端发送的Initial packet Token长度必然是0。客户端收到非0长度Token字段时，必须（MUST）丢弃或返回PROTOCOL_VIOLATION连接错误。
* Token：上一个Retry或者NEW_TOKEN帧中提供的token内容（见8.1节）。
* Packet Payload：数据包的有效载荷。

为了防止 version-unaware middlebox 对数据包的篡改，如[QUIC-TLS]中所述，Initial packet通过版本指定和连接关联的密钥（Initial keys）来进行加密。这部分加密不提供针对on-path攻击者的完整性和加密性校验，但是提供针对off-path攻击者的保护。

客户端和服务端使用Initial packet来进行初始加密握手信息的交换。包含了所有需要创建初始加密消息包的场景，比如在收到Retry包之后发送的包（第17.2.5节）。

服务端发送它的第一个Initial packet来应答客户端的Initial。由于密钥协商可能需要多轮信息交换，或者由于重传原因，服务端可能发送多个Initial。

Initial packet的payload内容包含：

* CRYPTO frames
* PING frames
* ACK frames
* PADDING frames
* CONNECTION_CLOSE frames

检查到其他frame出现则将其视为伪造的数据包丢弃，或视为连接错误。

客户端发起的第一个packet总是包含第一个加密握手信息的CRYPTO frame的开头或者全部。
第一个CRYPTO frame的offset永远是0.

注意，如果服务端发送了TLS HelloRetryRequest（见[QUIC-TLS]第4.7节），客户端会发送另一个系列的Initial packet。这些Initial包会继续握手流程，包中包含的CRYPTO frame的offset，从第一个Initial packet发送的CRYPTO frame对应的size大小开始。

#### 17.2.2.1. Abandoning Initial Packets

客户端在发送第一个Handshake packet之后，停止发送和处理Initial packet。
服务端在收到第一个Handshake packet之后，停止发送和处理Initial packet。

尽管此时可能还有Initial packet在路上或在等待ack，但在这之后不需要再交换Initial packet，丢弃即可。
如[QUIC-RECOVERY]第6.4节所述，初始包保护密钥（及任何丢包恢复和拥塞控制状态）将被丢弃（见[QUIC-TLS]第4.9.1节）。

当初始密钥被丢弃时，CRYPTO frame中的所有数据被丢弃，不再重传。

### 17.2.3. 0-RTT

0-RTT packet：type = 0x1，long header格式，后跟"Length"和"Packet Number"字段（见17.2节）。
第一个字节包含"Reserved"和"Packet Number Length"位（见第 17.2 节）。
0-RTT数据包用于在握手完成之前，作为首次传输的一部分，从客户端向服务器传输 early data。
作为TLS握手的一部分，服务端可以接受或拒绝这些 early data。

有关0-RTT数据及其限制的讨论，请参见[TLS13]的2.3节。

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

                          Figure 16: 0-RTT Packet
```

0-RTT和1-RTT密钥保护的packet使用相同packet number空间。

当客户端收到Retry包后，之前发送的0-RTT包很可能已经丢失或者被服务端丢弃。这时客户端可以（MAY）选择在发送完新的Initial包后尝试重发这个0-RTT包中的数据。新的数据包号必须用于发送的任何新数据包（如第 17.2.5.3 节所述），重复使用数据包号可能会损害数据包保护。

按照[QUIC-TLS]第4.1.1节的定义，客户端只有在握手完成后才会收到0-RTT数据包的确认。

客户端一旦开始处理来自服务端的1-RTT报文，就不得发送0-RTT报文。这意味着0-RTT数据包不能包含对1-RTT数据包内的帧的任何响应。 例如，客户端不能在0-RTT数据包中发送ACK帧，因为它只能确认1-RTT数据包。1-RTT数据包的确认必须在1-RTT数据包中进行。

服务端应该把违反 remembered limits 的行为（第7.4.1节）视为适当类型的连接错误(例如，超过流数据限制的FLOW_CONTROL_ERROR)。

### 17.2.4. Handshake Packet

Handshake packet：type = 0x2，long header格式，后跟"Length"和"Packet Number"字段（见17.2节）。
第一个字节包含"Reserved"和"Packet Number Length"位（见第 17.2 节）。
client和server之间使用这个报文携带ACK和加密握手信息。

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

                   Figure 17: Handshake Protected Packet
```

一旦客户端从服务端接收到一个Handshake packet，它使用Handshake packets来发送后续的加密层握手信息和ACK给服务端。

Handshake packet中的 Destination Connection ID字段包含了对端选择的connection ID。Source Connection ID则是表示发送方选择的connection ID。

第一个服务端发送的Handshake packet其对应的packet number为0. Handshake packets使用它们独立的packet number空间。Packet number同样是递增的。

Handshake packet的payload内容包含CRYPTO frames，可以包含PING、PADDING或者ACK frames. Handshake packets可能（MAY）包含类型为0x1c的CONNECTION_CLOSE frames。终端在收到其他类型frame的情况下必须（MUST）以PROTOCOL_VIOLATION类型的连接错误处理。

类似Initial packets，CRYPTO frame里面的data数据，在Handshake加密密钥被弃用的情况下，这些Handshake加密等级的数据也会被弃用，并且不再重传。

### 17.2.5. Retry Packet

Retry packet：type = 0x3，long header格式，
它携带了一个服务端生成的address validation token。
服务端使用这个packet来进行一个无状态的retry。

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

                          Figure 18: Retry Packet
```

Retry packet（如图18所示）不包含任何加密字段。"Unused"字段被服务端设置为一个任意值，客户端必须忽略这些位。 除了长包头中的字段外，它还包含这些附加字段：

* Retry Token: 服务端用来校验客户端address的token。
* Retry Integrity Tag: 参考[QUIC-TLS]中的 Retry Packet Integrity 章节。

#### 17.2.5.1. Sending a Retry Packet

服务端用客户端在Initial packet中携带的Source Connection ID来填充Destination Connection ID。

服务端在Source Connection ID字段中携带自己选择的cid。这个字段必须不能（MUST NOT）等于客户端发送的Destination Connection ID。客户端但收到了一个Retry包，其DCID和客户端发送的Initial包的SCID不同，则客户端必须（MUST）丢弃Retry包。客户端必须（MUST）把retry包中的SCID作为后续的包中的DCID。

服务端可能（MAY）在回复Initial和0-RTT packet的时机，发送Retry packet。服务端可以选择丢弃或buffer住收到的0-RTT packet。服务端可以发送多个Retry packet作为它收到的Initial 或 0-RTT packets的应答。

#### 17.2.5.2. Handling a Retry Packet

客户端在一条连接内，必须（MUST）接收并处理最多一个Retry packet。在客户端接收并处理服务端发送的Initial 或 Retry packet之后，它必须（MUST）丢弃所有后续收到的Retry packets。

客户端必须（MUST）丢弃包含了无法校验的Retry Integrity Tag的retry包，参考[QUIC-TLS]中Retry Packet Integrity章节。这限制了off-path攻击者注入Retry包的能力，并为Retry包崩溃提供了保护。客户端必须丢弃零长Retry Token字段的retry包。

客户端使用Initial packet来应答Retry packet，其中包含了Retry Token。

客户端用Retry packet携带了Source Connection ID来填充己方发送的Initial packet包含的Destination Connection ID字段。修改Destination Connection ID会导致用来加密Initial packet的密钥发生变化。客户端必须不能（MUST NOT）改变Source Connection ID，因为服务端有可能会在token校验的逻辑中包含connection ID（见8.1.4节）。

Retry包不包含包序号，因此不能被客户端显式确认。

#### 17.2.5.3. Continuing a Handshake After Retry

客户端随后发送的Initial packet使用收到的Retry packet携带的connection ID和token字段。
客户端将Retry包中的Source Connection ID字段复制到Destination Connection ID字段，并使用该值，直到收到具有更新值的Initial包为止（见第7.2节）。 Token字段的值被复制到所有后续的Initial数据包中（见第8.1.2节）。

除了更新DCID和Token字段外，客户端发送的其他Initial包和第一个Initial packet受到的约束一样。客户端必须（MUST）使用它在这个包中包含的加密握手消息。服务端在收到加密握手消息不一样的包之后，可以（MAY）将这种情况当成连接错误，并丢弃这个包。请注意，包含Token字段会减少加密握手消息的可用空间，这可能导致客户端需要发送多个 Initial 包。

客户端可能（MAY）在收到Retry packet之后尝试发送0-RTT packet，使用服务端下发的connection ID。

客户端在处理完Retry包后，不得重置任何数据包号空间的数据包号。 特别是，0-RTT包中包含的加密信息，很可能在收到Retry包时被重新发送。用于保护这些新的0-RTT包的密钥不会因为响应Retry包而改变 但是，这些数据包中发送的数据可能与之前发送的数据不同。用相同的数据包号发送这些新数据包很可能会影响这些数据包的加密保护，因为相同的密钥和nonce可能被用来保护不同的内容。 如果服务端检测到客户端重新设置了数据包号，它可以中止连接。

客户端和服务端之间交换的Initial和Retry数据包所使用的CID将被复制到传输参数中，并按照第 7.3 节的描述进行校验。

## 17.3. Short Header Packets

此版本的QUIC定义了一个使用短包头的单一数据包类型。

### 17.3.1. 1-RTT Packet

1-RTT packet：short header格式，用于版本协商和1-RTT密钥协商都完成之后。

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

                          Figure 19: 1-RTT Packet
```

1-RTT数据包包含以下字段：

* Header Form：首字节最高位(0x80)为0.
* Fixed Bit：首字节第2个bit(0x40)为1。此位为0的数据包在该版本中不是有效数据包，必须丢弃。此位为1允许QUIC与其他协议共存（参见[RFC7983]）。
* Spin Bit：首字节第3个bit(0x20)是Latency Spin Bit（见17.4节）。
* Reserved Bits：首字节第4-5个bit(0x18)为保留位。这些位使用头保护进行了加密；参考[QUIC-TLS]第5.4节。加密前这些位的值必须（MUST）被设为0。头保护解密和包保护解密后，如果这个字段不为0，终端必须(MUST)将这种情况当做是PROTOCOL_VIOLATION类型的连接错误。在只解密头保护后丢弃这样的包会将终端暴露给攻击者；参考[QUIC-TLS]第9.5节。
* Key Phase：首字节第6个bit(0x04)，表示用来加密的密钥等级，它使数据包的接收方可以识别用于加密数据包的数据包保护密钥（详细信息参见[QUIC-TLS]）。该位使用头保护进行了加密（参阅[QUIC-TLS]的5.4节）。
* Packet Number Length：首字节最后2个bit(0x03)，包含了packet number的长度字段，编码为无符号2-bit整数，实际packet number长度 = 字段值+1。使用头保护进行了加密（参阅[QUIC-TLS]的5.4节）。
* Destination Connection ID：DCID是由数据包的预期接收方选择的CID，详细信息参见第5.1节。
* Packet Number：字段长度为1到4个字节，使用头保护进行了加密（参阅[QUIC-TLS]的5.4节）。该字段的长度在"Packet Number Length"字段中进行编码，详见第17.1节。
* Packet Payload: 由1-RTT密钥加密的payload内容。

短头包的Header Form Bit和connection ID字段与版本无关，其余的字段是特定于所选的QUIC版本的。 有关如何解释来自不同版本的QUIC数据包的详细信息，请参见 [QUIC-INVARIANTS]。

## 17.4. Latency Spin Bit

为1-RTT数据包定义的延迟自旋位（第17.3.1节）提供了一种网络链路上的观察点在连接周期内提供被动的延迟监控的功能。服务端反映收到的自旋值，而客户端则在一个RTT后将其进行了旋转。 链路上的观察者可以测量两个自旋位切换时间，从而来评估一个连接端到端的RTT。

自旋位只存在于1-RTT数据包中，因为可以通过观察握手来测量一个连接的初始RTT。因此，版本协商和连接建立之后，自旋位就可用了。将在[QUIC-MANAGEABILITY]中讨论on-path测量和延迟自旋位的使用。

自旋位是此版本QUIC的可选（OPTIONAL）特性。不支持此功能的QUIC终端必须（MUST）禁用它，如下所述：

每个终端单边决定是否在一个连接中使能自旋位。实现必须（MUST）允许客户端和服务端的管理员来全局或者单独禁用自旋位。即使自旋位没有被管理员禁用，终端必须（MUST）在至少1/16的连接中或者每1/16个cid中随机禁用自旋位，以确保QUIC在网络上通常会观察到禁用自旋位的连接。鉴于每个终端都单独关闭自旋位，这保证了自旋位通信大概在1/8的链路中被禁用。

禁用了自旋位之后，终端可以将自旋位设置为任意值，且必须（MUST）忽略所有送入的值。
建议（RECOMMENDED）要么就在每个包中或者每个cid中单独的设置随机自旋位。

如果在连接中启用了自旋位，终端维护了一个自旋值，当终端发送一个1-RTT数据包的时候，将数据包头中的那个自旋位设置为当前存储的自旋位的值。在每个网络路径的终端中，自旋值被初始化为0。每个终端亦保存了连接中它对端发过来的最大包序号。

当一个服务端收到一个比当前最大包序号更大的1-RTT数据包时，服务端将自旋值设置为收到的包的自旋位的值
当一个客户端收到一个比当前最大包序号更大的1-RTT数据包时，客户端将自旋值设置为收到的包的自旋位的相反值

更改该网络路径上使用的CID时，终端重置它的自旋值为0。

# 18. Transport Parameter Encoding

在[QUIC-TLS]中定义的quic_transport_parameters扩展中的“extension_data”字段包含了QUIC传输参数的内容。它们被编码成一系列传输参数序列，如图20所示：

```
   Transport Parameters {
     Transport Parameter (..) ...,
   }

                Figure 20: Sequence of Transport Parameters
```

每个传输参数都以（identifier, length, value）的元组进行了编码，如图21所示：

```
   Transport Parameter {
     Transport Parameter ID (i),
     Transport Parameter Length (i),
     Transport Parameter Value (..),
   }

                  Figure 21: Transport Parameter Encoding
```

Transport Parameter Length字段包含了Transport Parameter Value字段的长度，单位为字节。

QUIC将传输层参数编码进字节序列，编码后的内容被包含在加密层握手中传输。

## 18.1. Reserved Transport Parameters

对于整数N，保留了标记形式为“32 * N+ 27”的传输参数，从而来忽略未知的传输参数。
这些传输参数没有语义，且值可能是随机的。

## 18.2. Transport Parameter Definitions

本节描述transport parameters的详细定义。

注意很多传输层参数使用整数值，这些值使用变长整数编码（参考16章），并且默认值是0（如果没有携带该参数）。特殊情况会被列出来。

**original_destination_connection_id(0x00)**
客户端第一个Initial packet中Destination Connection ID字段的内容，只由服务端发送。

**max_idle_timeout(0x01)**
整数值，单位为毫秒的整数，如果两端都没有这个字段，或字段为0表示idle timeout被disable。

**stateless_reset_token (0x02)**
无状态的reset token（见10.3节），16字节，客户端必须不能（MUST NOT）发送，服务端可以（MAY）发送。没有发送这个参数的服务端，不能在握手过程中协商CID时，使用stateless reset。

**max_udp_payload_size(0x03)**
最大UDP数据报大小，整数，用来表示终端愿意接收的最大UDP数据报的大小。超过这个参数的UDP数据报被处理的可能性较小。
默认值为UDP payload的最大可能尺寸65527，小于1200的值是无效的。
这个限制和链路MTU类似，是数据报尺寸的另一个限制。但它是一个终端的属性而不是链路的属性。这是一个终端来存放送入数据的（存储）空间的期望值。

**initial_max_data (0x04)**
整数，表示连接上能发送的最大数据量初始值。在完成握手之后，这个等同于发送MAX_DATA（第19.9节）。

**initial_max_stream_data_bidi_local (0x05)**
整数，表示初始flow control限制（对己方初始化的双向stream生效）。在客户端参数中，这个限制被用来最后2位为0x0的stream上。在服务端参数中，这个被用在最后2位为0x1的stream上。

**initial_max_stream_data_bidi_remote (0x06)**
整数，表示初始flow control限制（对端初始化的双向stream使用）。这个限制被用在对端启用的双向stream上。在客户端参数中，这个被用在最后2位为0x1的stream上。在服务端参数中，这个被用在最后2位为0x0的stream上。

**initial_max_stream_data_uni (0x07)**
整数，表示单向stream的初始flow control限制。被用在接收方启用的新单向stream上。在客户端参数中，这个被用在最后两位为0x3的stream上；在服务端参数中，这个被用在最后两位为0x2的stream上。

**initial_max_streams_bidi (0x08)**
整数，表示对端可以初始化的双向stream最大值。如果值为空或0，对端不可以启用双向stream，直到收到MAX_STREAMS调大限制。这个参数等效于发送具有相同value的相同类型的MAX_STREAMS（第19.11节）。

**initial_max_streams_uni (0x09)**
整数，表示对端可以初始化的单向stream最大值。如果值为空或0，对端不可以启用单向stream，直到收到MAX_STREAMS调大限制。这个参数等效于发送具有相同value的相同类型的MAX_STREAMS（第19.11节）。

**ack_delay_exponent (0x0a)**
整数，表示用来编码ACK Delay字段的指数（第19.3节）。如果值缺失，默认值为3（表示乘数为2^3=8）。这个默认值也被用在Initial和Handshake packet中的ACK frame。超过20的值认为是非法的。

**max_ack_delay (0x0b)**
整数，单位ms，表示终端发送ACK会delay的时间。这个值应当（SHOULD）包含接收方定时器的唤醒时间。举个栗子，如果接收方设置了一个5ms的定时器，定时器通常有1ms唤醒延迟，那么它应当发送6ms的max_ack_delay参数值。如果值缺失，默认值是25ms。2^14或更大的值无效。

**disable_active_migration(0x0c)**
开关，表示终端是否支持连接迁移（第9章）。收到此传输参数的终端在向握手期间对端使用的地址发送时，不得使用新的本地地址。 在客户端对preferred_address传输参数进行操作后，该传输参数不禁止连接迁移。这个参数是一个长度为0的值。

**preferred_address (0x000d)**
用来在握手结束之后改变服务端地址（9.6节），只由服务端发送。服务端可以（MAY）通过发送全零地址和端口（0.0.0.0:0 or ::.0），来选择只发送一个地址族的偏好地址。IP地址以网络字节序编码。
参数包含了IPv4和IPv6的地址和端口。4 个字节的IPv4地址字段后面是相关的2个字节的 IPv4 端口字段。之后是一个 16 字节的 IPv6 地址字段和两个字节的IPv6端口字段。 在地址和端口对之后，CID Length字段描述了下面CID字段的长度。最后，一个16字节的Stateless Reset Token字段包括与CID相关的Stateless Reset Token。该传输参数的格式如图22所示。
CID字段和Stateless Reset Token字段包含了一个交替的序列号为1的CID；参考5.1.1小节。将这些值与偏好地址绑定，保证了客户端往偏好地址进行连接迁移时，至少有一个未使用的活动CID。
一个偏好地址的cid和Stateless Reset Token字段和NEW_CONNECTION_ID的相关字段在语法和语义上都有区别。选择零长CID的服务端必须不能（MUST NOT）提供偏好地址。类似地，服务端也必须不能（MUST NOT）在这个参数中包含一个零长CID。碰到违反这些规约的情况，客户端必须（MUST）将其当成是TRANSPORT_PARAMETER_ERROR类型的连接错误。

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

                    Figure 22: Preferred Address format
```

**active_connection_id_limit (0x0e)**
活动CID限制是一个整数值，用来说明当前终端原因存储的对端CID的最大数量。
这个值包含了在握手过程中的preferred_address传输参数中以及NEW_CONNECTION_ID帧中收到的CID。
active_connection_id_limit的最小值为2. 终端收到值小于2的参数后必须（MUST）以TRANSPORT_PARAMETER_ERROR类型的错误来关闭连接。
如果缺失了这个参数，则默认是2。如果一个终端发了一个零长CID，它永远不会发送一个NEW_CONNECTION_ID帧，并因此而忽略了从对端收到的active_connection_id_list的值。

**initial_source_connection_id (0x0f)**
指终端在发送的第一个initial包中的SCID字段的值（见第7.3节）。

**retry_source_connection_id (0x10)**
服务端的retry包中的SCID的值（见第7.3节），只有服务端会发送这个传输参数。

这几个参数如果存在，跟后续发送的MAX_STREAM_DATA对应值相同：

* initial_max_stream_data_bidi_local
* initial_max_stream_data_bidi_remote
* initial_max_stream_data_uni

如果上述参数缺失，则对应type的stream从流控限制为0开始。

客户端不能（MUST NOT）包含：

* original_destination_connection_id
* preferred_address
* retry_source_connection_id
* stateless_reset_token

服务端必须（MUST）处理收到的上述参数为TRANSPORT_PARAMETER_ERROR连接错误。

# 19. Frame Types and Formats

packet包含一个或多个frames。本节描述核心QUIC frame类型格式。

## 19.1. PADDING Frames

类型为（type=0x00），没有语义值。
PADDING frames主要被用来填充packet大小。例如可以用来把客户端发送的initial packet填充到要求的最小size，或是提供针对流量分析的攻击抵御。

PADDING frame没有内容。只有一个字节表示这是个PADDING frame。

```
   PADDING Frame {
     Type (i) = 0x00,
   }

                      Figure 23: PADDING Frame Format
```

## 19.2. PING Frames

类型为（type=0x01）。终端使用PING frame来检测对端是否还存在，或者检查对端的可达性。
PING frame没有额外字段。

```
   PING Frame {
     Type (i) = 0x01,
   }

                        Figure 24: PING Frame Format
```

PING frame的接收方使用完全相同的frame内容来应答。
PING frame主要用来保活一条连接，避免超时关闭（见10.1.2节）。

## 19.3. ACK Frames

接收方发送 ACK frames（type=0x02&0x03）来告知发送方报文已经被接收和处理。ACK frame包含一个或多个ACK Ranges。ACK Ranges表示被ACK的报文。如果type是0x03，ACK frames还包含了这条连接上到现在为止，收到的ECN标志关联的QUIC packet之和。QUIC实现必须（MUST）正确地处理两种类型，如果有ECN，应当根据ECN信息来处理拥塞控制状态。

QUIC ACK是不可撤销的。一旦ACK了，一个packet保持被ACK过的状态，即使它在未来的ACK frame中没有再次出现。注意这个机制跟[TCP SACK](https://tools.ietf.org/html/rfc2018)（[RFC2018]）不一样。

发送方在不同的packet number空间中使用相同的packet number。来自不同报序号空间的包可以使用同一个数值来进行区分。一个包的确认信息需要说明包序号和包序号空间。每个ACK帧只确认同一个空间中的包序号。

Version Negotiation 和 Retry packets不能被ACK，因为它们没有packet number。这两种报文由下一个客户端发送的Initial packet来隐式地确认。

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

                        Figure 25: ACK Frame Format
```

ACK frame 包含以下字段：

* Largest Acknowledged：变长整数，表示对端正在ACK的最大packet number；通常是对端在生成当前ACK frame之前收到的最大packet number。与QUIC长或短报头中的数据包编号不同，ACK帧中的值不会被截断。

* ACK Delay：变长整数，以毫秒为单位编码ACK延迟（见13.2.5节）。通过将字段中的值乘上ACK帧发送方发送的2^ack_delay_exponent的倍数来解码（见18.2节）。与仅将延迟表示为整数相比，此编码允许在相同数量的字节内包含更大范围的值，但代价是分辨率较低。

* ACK Range Count：变长整数，表示当前frame中Gap和ACK Range字段的数量。

* First ACK Range：变长整数，表示在Largest Acknowledged之前正在被ACK的连续packet的数量。范围内最小的packet number = Largest Acknowledged - First ACK Range。

* ACK Ranges：包含未确认（Gap）和已确认（ACK Range）的额外数据包范围；见第19.3.1节。

* ECN Counts：包含3个ECN Counts，详见19.3.2节。

#### 19.3.1. ACK Ranges

ACK Range字段由交替的Gap和ACK Range Length组成，以降序的packet number排列。ACK Range可以重复。Gap和ACK Range的数量由ACK Range Count字段来决定。

```
   ACK Range {
     Gap (i),
     ACK Range Length (i),
   }

                           Figure 26: ACK Ranges
```

ACK Range 包含以下字段：

* Gap：变长整数，表示连续的还没有被ACK的packet数量，区间起始从最小的ACK Range - 1开始。
* ACK Range Length：变长整数，表示连续的被ACK的packet数量，区间起始从前一个Gap开始。

Gap和ACK Range使用关联的整数编码形式。尽管编码值是正整数，但是值是被减去的，因此表示的packet区间编号是递减的。

每一个ACK Range用来对一个连续区间的packet进行ACK。value为0的情况表示只有最大的packet number被ACK（区间内只有一个元素）。ACK Range值越大，表示区间越大，区间内最小的数据包编号对应的值越小。因此，给定区间内的最大数据包编号，区间中最小值由以下公式确定：

```
smallest = largest - ack_range
```

一个ACK Range对所有在[最小，最大]区间内的packet进行ACK，两端都是闭区间。
最大值是通过减去所有前面的ACK Range和Gap计算得到的。

每个Gap表示一个没有被ACK的packet区间。实际区间中packet数量为1 + Gap字段编码值。

下一个ACK区间的最大值通过以下公式计算：

```
largest = previous_smallest - gap - 2
```

如果过程中计算出的任何packet number是负数，终端必须（MUST）生成一个FRAME_ENCODING_ERROR的连接错误。

#### 19.3.2. ECN Counts

ACK frame使用最低位（type 0x03）来标识ECN响应，并且上报在IP头中携带关联的ECN codepoints的QUIC packet。数据包的IP头中相关的ECN codepoint为ECT(0)、ECT(1)或CE。 ECN Counts只在ACK frame（type 0x03）中出现。

```
   ECN Counts {
     ECT0 Count (i),
     ECT1 Count (i),
     ECN-CE Count (i),
   }

                        Figure 27: ECN Count Format
```

3个ECN Count为：

* ECT0 Count：变长整数，表示和ACK帧同一个包序号空间中接收到的携带了ECT(0) codepoint的包数量。
* ECT1 Count：变长整数，表示和ACK帧同一个包序号空间中接收到的携带了ECT(1) codepoint的包数量。
* CE Count：变长整数，表示和ACK帧同一个包序号空间中接收到的CE codepoint的包数量。

ECN counts是在每个packet number空间下分别统计的。

## 19.4. RESET_STREAM Frames

终端使用RESET_STREAM frame (type=0x04) 来中途关闭一个stream的发送部分。

在发送完RESET_STREAM之后，终端停止在这条stream上发送和重传STREAM frame。RESET_STREAM的接收方可以丢弃所有该stream上已经收到的数据。

终端如果在仅发送的单向stream上收到了RESET_STREAM，应当以STREAM_STATE_ERROR连接错误处理。

```
   RESET_STREAM Frame {
     Type (i) = 0x04,
     Stream ID (i),
     Application Protocol Error Code (i),
     Final Size (i),
   }

                    Figure 28: RESET_STREAM Frame Format
```

RESET_STREAM Frame 包含以下字段：

* Stream ID：变长整数，表示关闭的流Stream ID。
* Application Protocol Error Code：变长整数应用层协议错误码（见20.1节），表示stream被关闭的原因。
* Final Size：变长整数，stream最终的size，由发送方统计的值，单位为字节。

## 19.5. STOP_SENDING Frames

终端使用STOP_SENDING frame (type=0x05)来告诉对端接下来的数据会被应用层丢弃。

STOP_SENDING frame可以在Recv或者Size Known状态下的stream中发送。
在一条没有被初始化的stream中，收到STOP_SENDING frame，必须（MUST）以STREAM_STATE_ERROR连接错误来处理。终端在仅接收的单向stream中收到STOP_SENDING，以STREAM_STATE_ERROR的连接错误处理。

```
   STOP_SENDING Frame {
     Type (i) = 0x05,
     Stream ID (i),
     Application Protocol Error Code (i),
   }

                    Figure 29: STOP_SENDING Frame Format
```

STOP_SENDING Frame 包含以下字段：

* Stream ID：变长整数，表示被忽略流的Stream ID。
* Application Protocol Error Code：变长整数，表示应用层指定的发送方忽略流的原因（见第20.2节）。

## 19.6. CRYPTO Frames

CRYPTO frame (type=0x06)被用来传输加密层握手信息。可以被放在除0-RTT以外的所有的packet类型中发送。CRYPTO frame给加密层协议提供有序的字节信息。

CRYPTO frame在功能上与STREAM frame相同，但不同点在于：

* CRYPTO frame 没有Stream ID
* CRYPTO frame 不受流控控制
* CRYPTO frame 没有额外的标识位

```
   CRYPTO Frame {
     Type (i) = 0x06,
     Offset (i),
     Length (i),
     Crypto Data (..),
   }

                       Figure 30: CRYPTO Frame Format
```

CRYPTO Frame 包含以下字段：

* Offset：变长整数，表示该frame中数据在整个stream中的字节偏移量。
* Length: 变长整数，表示Crypto Data字段的长度。
* Crypto Data: 加密层的信息内容。

每个加密级别都有一个单独的加密握手数据流，每个加密握手数据都从offset下标0开始。这意味着每个加密层级都被视为单独的CRYPTO数据流。

一个流中传递的最大偏移（offset和数据长度之和）不能超过2^62-1。如果收到的一个包超过了这个限制，那么就认为是一种 FRAME_ENCODING_ERROR 或 CRYPTO_BUFFER_EXCEEDED 类型的错误。

和STREAM frame不一样的是，每个加密层级的数据流由独立的CRYPTO frame来承载，并且没有Stream ID标识。流没有明确的结尾，所以CRYPTO frame没有FIN标识位。

## 19.7. NEW_TOKEN Frames

服务端发送NEW_TOKEN frame (type=0x07)来给客户端提供一个新的token，在未来的连接中携带在Initial packet中。

```
   NEW_TOKEN Frame {
     Type (i) = 0x07,
     Token Length (i),
     Token (..),
   }

                     Figure 31: NEW_TOKEN Frame Format
```

NEW_TOKEN Frame 包含以下字段：

* Token Length：变长整数，表示token长度，单位w为字节。
* Token：token内容的字节流。token必须不能（MUST NOT）是空的。终端必须（MUST）把收到带空token字段的NEW_TOKEN帧的情况当成是FRAME_ENCODING_ERROR类型的连接错误。

如果包含了NEW_TOKEN帧的数据包被误认为丢失了，终端可能收到多个包含了同一个token值的NEW_TOKEN帧
终端负责丢弃冗余值，这些冗余值可能用来将连接联系起来。
客户端必须不能（MUST NOT）发送NEW_TOKEN帧。服务端必须（MUST）在收到NEW_TOKEN帧之后认为发生了PROTOCOL_VIOLATION类型的连接错误。

## 19.8. STREAM Frames

STREAM frames隐式地创建一条stream并携带stream数据。
STREAM frame采用 0b00001XXX 格式（从0x08到0x0f区间）。

type中低三位的值决定了frame中存在的字段：

* The OFF bit (0x04)：表示是否存在Offset字段。设为1时表示会有个Offset字段，设为0时没有。设为0时当前的Stream Data起始offset为0（即帧中包含流的第一个字节，或流的末端不包含数据）。
* The LEN bit (0x02)：表示是否存在Length字段。设为0时没有Length字段，并且Stream Data字段延伸到packet结束位置。设为1时有Length字段。
* The FIN bit (0x01)：stream的结束标识位，stream的最终大小是offset与该帧length之和。

如果终端在仅用于发送的单向流中收到STREAM frame，或者在本地发起但还没有创建的流上收到STREAM帧，必须（MUST）以STREAM_STATE_ERROR 连接错误关闭连接。

```
   STREAM Frame {
     Type (i) = 0x08..0x0f,
     Stream ID (i),
     [Offset (i)],
     [Length (i)],
     Stream Data (..),
   }

                       Figure 32: STREAM Frame Format
```

STREAM Frame 包含以下字段：

* Stream ID：变长整数，表示Stream唯一标识.
* Offset：变长整数，表示当前frame数据在整个stream中的偏移量，是否存在该字段由OFF bit决定。当OFF bit为1时，该字段存在。当Offset字段不存在时，偏移量为0。
* Length: 变长整数，表示当前Stream Data字段的长度，是否存在该字段由LEN bit决定。当LEN bit为0时，该Stream Data的长度为当前packet的所有剩余长度。
* Stream Data：传输的数据字节流。

当Stream Data字段长度为0时，offset为下一个会被发送的字节下标。

Stream中第一个字节offset为0。Stream中最大的offset不能超过2^62-1，因为流控也不可能提供这么大的数据额度。必须（MUST）把收到超过限制的帧的情况当成FRAME_ENCODING_ERROR或FLOW_CONTROL_ERROR类型的连接错误。

## 19.9. MAX_DATA Frames

MAX_DATA frame (type=0x10) 被用在流控中，来告知对方连接中可以发送的最大数据总量。

```
   MAX_DATA Frame {
     Type (i) = 0x10,
     Maximum Data (i),
   }

                      Figure 33: MAX_DATA Frame Format
```

MAX_DATA Frame 包含以下字段：

* Maximum Data：变长整数，表示连接中可以发送的最大数据总量，单位字节。

所有以STREAM frame发送的数据都需要计入这个限制。
所有stream的最大offset之和（包括已经结束的stream），不能（MUST NOT）超过这个接收方声明的限制。
终端在超过限制的情况下必须（MUST）以FLOW_CONTROL_ERROR的错误关闭连接（这包括违反early data中的记忆限制，见7.4.1节）。

## 19.10. MAX_STREAM_DATA Frames

MAX_STREAM_DATA frame (type=0x11) 流控中用来向对端声明单条stream中可以发送的最大数据量。

MAX_STREAM_DATA frame可以在Recv状态下的stream中发送。在还没有初始化的流中接收到MAX_STREAM_DATA，或在仅接收的单向流中收到这个，都以STREAM_STATE_ERROR连接错误处理。

```
   MAX_STREAM_DATA Frame {
     Type (i) = 0x11,
     Stream ID (i),
     Maximum Stream Data (i),
   }

                  Figure 34: MAX_STREAM_DATA Frame Format
```

MAX_STREAM_DATA Frame 包含以下字段：

* Stream ID：变长整数，stream唯一标识。
* Maximum Stream Data：变长整数，表示当前流可以发送的最大数据量，单位字节。

终端统计流中的最大数据offset，来计算是否达到这个限制。
丢包或重传表明最大接收的offset有可能比实际接收到的总数据量大。接收STREAM frame有可能不会增加当前接收到的最大offset。

stream上发送的数据不能（MUST NOT）超过对端声明的最大stream data值。
终端必须（MUST）在收到数据量超过流控限制时，以FLOW_CONTROL_ERROR结束连接（在初始限制阶段有例外，见7.4.1节）。

## 19.11. MAX_STREAMS Frames

MAX_STREAMS frames (type=0x12 and 0x13) 用来告知对端，可以开启的某种类型流的最大累计数量。
type 0x12表示双向流的限制。
type 0x13表示单向流的限制。

```
   MAX_STREAMS Frame {
     Type (i) = 0x12..0x13,
     Maximum Streams (i),
   }

                    Figure 35: MAX_STREAMS Frame Format
```

MAX_STREAMS Frame 包含以下字段：

* Maximum Streams: 对应类型能够启用的最大stream累计数量。Stream ID不能超过2^60，因为不可能编码一个大于2^62-1的Stream ID。收到一个帧打算打开比这个值大的流，必须（MUST）被当成FRAME_ENCODING_ERROR错误。

丢包和重传可能会导致超过这个限制。没有增大上限的MAX_STREAMS必须（MUST）被忽略。

终端不能（MUST NOT）启用超过对端限制的流数量。例如，收到单向流限制为3的服务端允许打开流3、7 和11，但不允许打开流15。 终端在检测到出现超过情况时，以STREAM_LIMIT_ERROR错误关闭连接。（这包括违反early data中的记忆限制，见7.4.1节）。

注意，这些帧（以及相应的传输参数）不是指当前可以打开的并发stream数量。
该限制是包含了已经被关闭的stream和已打开的stream。

## 19.12. DATA_BLOCKED Frames

发送方应当（SHOULD）发送一个DATA_BLOCKED frame (type=0x14)，当发现触达连接级别流控的情况下，仍希望发送数据时（见第4章）。DATA_BLOCKED frame 可用作调整流控算法的输入（见4.2节）。

```
   DATA_BLOCKED Frame {
     Type (i) = 0x14,
     Maximum Data (i),
   }

                    Figure 36: DATA_BLOCKED Frame Format
```

DATA_BLOCKED Frame 包含以下字段：

* Maximum Data: 变长整数，用来表示连接级别的流控被触发导致数据不能发送。

## 19.13. STREAM_DATA_BLOCKED Frames

发送方在触达stream级别流控导致不能发送数据时，应当发送STREAM_DATA_BLOCKED frame (type=0x15) 告知对端。该帧类似于DATA_BLOCKED（第19.12节）。

如果是仅发送的单向流收到了STREAM_DATA_BLOCKED帧，终端必须（MUST）以 STREAM_STATE_ERROR类型的错误终止连接。

```
   STREAM_DATA_BLOCKED Frame {
     Type (i) = 0x15,
     Stream ID (i),
     Maximum Stream Data (i),
   }

                Figure 37: STREAM_DATA_BLOCKED Frame Format
```

STREAM_DATA_BLOCKED Frame 包含以下字段：

* Stream ID：变长整数，表示被流控阻塞流的唯一标识。
* Maximum Stream Data Limit：变长整数，标识在流控阻塞发生的情况下，stream内的offset。

## 19.14. STREAMS_BLOCKED Frames

STREAMS_BLOCKED frame (type=0x16 or 0x17) 由发送方在达到stream最大数量限制的情况下，希望启用一条新的stream时发送。

type 0x16 表示达到双向stream限制。
type 0x17 表示达到单向stream限制。

STREAMS_BLOCKED frame并不是用来启用stream，只是告知对端自己达到了上限限制。

```
   STREAMS_BLOCKED Frame {
     Type (i) = 0x16..0x17,
     Maximum Streams (i),
   }

                  Figure 38: STREAMS_BLOCKED Frame Format
```

STREAMS_BLOCKED Frame 包含以下字段：

* Maximum Streams: 变长整数，表示当前stream限制。Stream ID不能超过2^60，因为不可能编码一个大于2^62-1的Stream ID。超过了就视为STREAM_LIMIT_ERROR错误或者STREAM_ENCODING_ERROR错误。

## 19.15. NEW_CONNECTION_ID Frames

终端发送NEW_CONNECTION_ID frame (type=0x18) 来给对端提供在迁移过程中可选的connection IDs，见第9.5节。

```
   NEW_CONNECTION_ID Frame {
     Type (i) = 0x18,
     Sequence Number (i),
     Retire Prior To (i),
     Length (8),
     Connection ID (8..160),
     Stateless Reset Token (128),
   }

                 Figure 39: NEW_CONNECTION_ID Frame Format
```

NEW_CONNECTION_ID Frame 包含以下字段：

* Sequence Number：变长整数，发送方指定给connection ID的sequence number（见5.1.1节）。
* Retire Prior To：一个用于表示回收哪个CID的变长整数，默认为0，见5.1.2节。
* Length：8-bit长度非负整数，包含了connection ID的长度，长度区间在[1, 20]，区间外的长度以 FRAME_ENCODING_ERROR连接错误处理。
* Connection ID：指定长度的Connection ID字段。
* Stateless Reset Token：128-bit长度的token，将会用在stateless reset当中，当关联的connection ID被使用时，见10.3节。

终端不能（MUST NOT）发送这个frame，当它正在要求对端发送长度为0的Destination Connection ID时。 改变connection ID的长度（从0或者改变成0）会使得终端很难识别出connection ID的值发生变化。正在发送长度为0的Destination Connection ID的终端，必须（MUST）处理以PROTOCOL_VIOLATION连接错误来处理收到的NEW_CONNECTION_ID frame.

传输错误，超时或者重传都可能导致相同的NEW_CONNECTION_ID frame被发送多次。收到相同的多个NEW_CONNECTION_ID frame不能（MUST NOT）被处理为连接错误。接收方可以使用sequence number来识别哪些是新的connection ID。

如果终端接收到的NEW_CONNECTION_ID frame用不同的Stateless Reset Token或不同的Sequence Number重复了之前发出的CID，或者Sequence Number被用于不同的CID，终端可以将其视为PROTOCOL_VIOLATION类型的连接错误。

Retire Prior To字段统计了建连阶段和preferred_address传输参数中发布的CID（见5.1.2节）。该字段必须小于等于Sequence Number字段。收到一个比Sequence Number大的Retire Prior To字段必须被当做FRAME_ENCODING_ERROR类型的连接错误。

一旦一个发送者指定了一个Retire Prior To值，后续的NEW_CONNECTION_ID帧中较小的值是无效的。
接收者必须（MUST）忽略比当前最大的Prior To字段小的值。

收到序列号比之前NEW_CONNECTION_ID帧中的 Retire Prior To值小的NEW_CONNECTION_ID帧之后，终端必须（MUST）发送一个对应的RETIRE_CONNECTION_ID帧来回收最新收到的CID，除非这个序列号对应的CID已经回收了。

## 19.16. RETIRE_CONNECTION_ID Frames

终端发送RETIRE_CONNECTION_ID frame (type=0x19) 来告知它不再会继续使用对端声明的某个connection ID。这有可能包含握手过程中使用的connection ID。发送RETIRE_CONNECTION_ID frame也被作为通知对端需要发送更多新的connection ID来使用。新的connection ID通过NEW_CONNECTION_ID frame来发送。

使一个connection ID过期，会同时使它关联的stateless reset token失效。

```
   RETIRE_CONNECTION_ID Frame {
     Type (i) = 0x19,
     Sequence Number (i),
   }

                Figure 40: RETIRE_CONNECTION_ID Frame Format
```

RETIRE_CONNECTION_ID Frame 包含以下字段：

* Sequence Number：被失效的Connection的下标数字（见5.1.2节）。

收到RETIRE_CONNECTION_ID frame包含了当前未使用到的sequence number，终端必须（MUST）处理为PROTOCOL_VIOLATION连接错误。

RETIRE_CONNECTION_ID帧中阐述的序列号必须不能（MUST NOT）同一个包中的DCID有关联。对端可以（MAY）把这种情况当做是一种FRAME_ENCODING_ERROR的连接错误。

终端不能在使用长度为0的connection ID的情况下发送该frame。违反情况下终端以PROTOCOL_VIOLATION错误关闭连接。

## 19.17. PATH_CHALLENGE Frames

终端可以使用PATH_CHALLENGE frames (type=0x1a) 在连接迁移过程中检查新的路径的可用性。

```
   PATH_CHALLENGE Frame {
     Type (i) = 0x1a,
     Data (64),
   }

                   Figure 41: PATH_CHALLENGE Frame Format
```

PATH_CHALLENGE Frame 包含以下字段：

* Data：8字节随机数。

PATH_CHALLENGE frame包含了64位熵来保证对端回复的内容不容易被预测猜到。

这个frame的接收方必须（MUST）生成Data完全相同的PATH_RESPONSE frame来应答（第19.18节）。

## 19.18. PATH_RESPONSE Frames

PATH_RESPONSE frame (type=0x1b) 是用来应答PATH_CHALLENGE frames的。
格式跟PATH_CHALLENGE frames完全一致，内容完全一致。

```
   PATH_RESPONSE Frame {
     Type (i) = 0x1b,
     Data (64),
   }

                   Figure 42: PATH_RESPONSE Frame Format
```

如果接收方检测到Data内容不一致，以PROTOCOL_VIOLATION连接错误处理。

## 19.19. CONNECTION_CLOSE Frames

终端发送CONNECTION_CLOSE frame (type=0x1c or 0x1d) 来告知对端连接即将被关闭。

type 0x1c 表示出现了QUIC层的错误（或者没有错误正常关闭）。
type 0x1d 表示出现了应用层错误。

如果还有未被关闭的stream，在收到这个帧之后也应当被关闭。

```
   CONNECTION_CLOSE Frame {
     Type (i) = 0x1c..0x1d,
     Error Code (i),
     [Frame Type (i)],
     Reason Phrase Length (i),
     Reason Phrase (..),
   }

                  Figure 43: CONNECTION_CLOSE Frame Format
```

CONNECTION_CLOSE Frame 包含以下字段：

* Error Code: 变长整数错误码，用来标识关闭连接的原因。 类型0x1c的CONNECTION_CLOSE帧使用第20.1节中定义的错误码；类型0x1d的CONNECTION_CLOSE帧使用应用协议错误代码空间中的代码，见第20.2节。
* Frame Type: 变长整数，用来表示出错的帧类型。值为0表示frame type是未知类型。应用层连接错误(type 0x1d)没有这个字段。
* Reason Phrase Length: 变长整数，表示出错原因字段的长度，单位字节。因为CONNECTION_CLOSE frame不能被分拆到多个packet里面，错误原因字段需要遵守packet长度限制。
* Reason Phrase: 人类可读的连接关闭原因。如果发送方选择不提供错误码以外的详细信息，可以长度为0。应当（SHOULD）为UTF-8编码[RFC3629]，尽管该帧不携带诸如语言标签等有助于创建文本以外的任何实体理解的信息。

应用定义的CONNECTION_CLOSE帧只能使用0-RTT或者1-RTT包发送。当应用希望在握手时放弃连接，终端可以通过initial或handshake包发送一个带APPLICATION_ERROR错误码的CONNECTION_CLOSE帧 (type 0x1c)。

## 19.20. HANDSHAKE_DONE Frames

服务端使用HANDSHAKE_DONE帧来将握手确认通知给客户端。HANDSHAKE_DONE帧不包含任何内容。

```
   HANDSHAKE_DONE Frame {
     Type (i) = 0x1e,
   }

                   Figure 44: HANDSHAKE_DONE Frame Format
```

这个帧只能被服务端发送。服务端必须不能（MUST NOT）在完成握手之前发送HANDSHAKE_DONE帧。
服务端如果收到HANDSHAKE_DONE帧，必须（MUST）把这种情况当做一种PROTOCOL_VIOLATION类型的连接错误。

## 19.21. Extension Frames

QUIC不使用自描述编码形式，因此终端必须预先理解所有的帧类型和编码格式，然后才能成功处理数据包。
这样可以对帧进行有效的编码，但是这意味着终端无法发送其对端未知的类型的帧。

扩展帧类型被用在希望扩展新类型的场景下，但必须预先确认对端能够识别。
终端可以使用传输参数来表示它愿意接收扩展帧类型。 一个传输参数可以表示对一个或多个扩展帧类型的支持。

面向协议功能性的不同扩展往往难以合并，除非显式定义合并后的行为。
这样的扩展应当（SHOULD）定义他们和之前定义且修改了同一个协议模块的扩展之间的交互。

扩展帧类型也需要能够被拥塞控制，且必须（MUST）能收到ACK帧回复。例外是替代或补充ACK帧的扩展帧。
除非在扩展帧中指定，扩展帧不在流控统计范围内。

IANA注册表用于管理帧类型的分配；见第22.4节。

# 20. Error Codes

QUIC传输层错误码和应用层错误码是62-bit非负整数。

## 20.1. Transport Error Codes

本节列出了可用于类型为0x1c的CONNECTION_CLOSE帧中的定义的QUIC传输层错误码。
这些错误码适用于整个连接。

NO_ERROR (0x0): 终端将其与CONNECTION_CLOSE一起使用，以表示在没有任何错误的情况下突然关闭了连接。

INTERNAL_ERROR (0x1):
终端遇到内部错误，无法继续连接。

CONNECTION_REFUSED (0x2):
服务端拒绝接收新连接。

FLOW_CONTROL_ERROR (0x3):
终端收到的数据超出其公布的所允许的数据限制；见第4章。

STREAM_LIMIT_ERROR (0x4):
终端收到的流标识符的帧，该帧超过了相应流类型通告的流限制。

STREAM_STATE_ERROR (0x5):
终端收到的流上的帧不在该帧被允许的状态下；参阅第3章。

FINAL_SIZE_ERROR (0x6): 
终端收到一个STREAM帧，其中的数据超过了先前确定的最终大小。
或者终端收到了一个STREAM帧或RESET_STREAM帧，其中包含的最终大小低于已经收到的流数据大小。
或者终端收到了一个STREAM帧或RESET_STREAM帧，其中包含的最终大小与已经建立的最终大小不同。

FRAME_ENCODING_ERROR (0x7):
终端收到一个格式错误的帧。 例如，一个未知类型的帧，或一个确认范围比数据包的其余部分可能携带的ACK帧还要多的ACK帧。

TRANSPORT_PARAMETER_ERROR (0x8):
终端收到的传输参数格式错误：包含了无效值/省略了必需的传输参数/包含了禁止的传输参数/其他错误。

CONNECTION_ID_LIMIT_ERROR (0x9):
对端提供的CID数量超过了通告的active_connection_id_limit。

PROTOCOL_VIOLATION (0xa):
终端检测到一个符合协议的错误，但该错误没有被更多特定的错误代码覆盖。

INVALID_TOKEN (0xb):
服务端收到一个包含无效Token字段的客户端Initial。

APPLICATION_ERROR (0xc):
应用程序或应用程序协议导致连接被关闭。

CRYPTO_BUFFER_EXCEEDED (0xd):
终端收到的CRYPTO帧数据超过了它的缓冲能力。

KEY_UPDATE_ERROR (0xe):
终端在执行密钥更新时检测到错误，参见[QUIC-TLS]第6章。

AEAD_LIMIT_REACHED (0xf):
终端已触达指定连接所使用的AEAD算法的机密性或完整性限制。

NO_VIABLE_PATH (0x10):
终端已经确定网络路径无法支持 QUIC。除非路径不支持足够大的MTU，否则终端不太可能收到携带该错误码的CONNECTION_CLOSE。

CRYPTO_ERROR (0x1XX):
加密握手失败。保留256个值的范围，用于携带特定于加密握手的错误码。在[QUIC-TLS]的4.8节中介绍了将TLS用于加密握手时发生的错误的错误码。

有关注册新错误码的详细信息，请参见第22.5节。

定义错误码的时候，需要遵循一些原则：
1. 那些需要指定接收者行为的错误条件，需要定义为独占码；
2. 代表通常条件的错误，需要定义详细的错误码；
3. 如果不想按照上面的规则来做，错误码用于识别一个协议栈的通用功能，比如流控制或者传输参数处理。
4. 最终，如果实现不能或者不愿使用更加具体的错误码，则需要提供一般错误

## 20.2. Application Protocol Error Codes

应用层协议错误留给应用层协议来组织错误码内容。在RESET_STREAM帧、STOP_SENDING帧、以及0x1d类型的CONNECTION_CLOSE帧中使用应用协议错误码。
