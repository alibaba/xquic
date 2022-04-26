# 1. Introduction

本文描述了如何使用TLS [TLS13]来保证QUIC [QUIC-TRANSPORT]的安全

相对于上一个版本，TLS 1.3在建连连接上提供了极大的延迟改善。抛开丢包，可以在一轮往返中完成大多数建立新连接和相关的安全；在相同客户端和服务端之间的后续连接中，客户端可以使用0-RTT建连机制，来立刻发送应用数据。

本文描述了TLS作为QUIC安全模块的作用。

# 2. Notational Conventions

本文中的关键词"MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", 和"OPTIONAL"，当且只当它们以如上的全大写形式存在时，应当以[BCP 14](https://tools.ietf.org/html/bcp14) [[RFC2119](https://tools.ietf.org/html/rfc2119)] [[RFC8174](https://tools.ietf.org/html/rfc8174)]中描述的方式来解释。

本文使用了[QUIC-TRANSPORT] 中的术语：

方便起见，缩略语TLS用于表示TLS 1.3，尽管可能使用更新的版本（参考4.2节）。

## 2.1. TLS Overview

TLS为两个终端提供了一种通过不受信任的媒介（如互联网）建立通信手段的方法。TLS启用对端的身份验证，并为终端交换的消息提供机密性和完整性保护。

TLS是一个分层协议，其结构如下所示：

```
             +-------------+------------+--------------+---------+
   Content   |             |            |  Application |         |
   Layer     |  Handshake  |   Alerts   |     Data     |   ...   |
             |             |            |              |         |
             +-------------+------------+--------------+---------+
   Record    |                                                   |
   Layer     |                      Records                      |
             |                                                   |
             +---------------------------------------------------+

                            Figure 1: TLS Layers
```

每个Content层消息（例如，Handshake，Alerts，Application Data），在Record层都以一系列有类型的TLS records的形式被承载。Records单独被加密保护并在一个提供排序和可靠传输的协议层上（典型如TCP）上进行传递。

TLS认证密钥在客户端和服务端之间进行交换。客户端发起交换，服务端进行响应。如果密钥交换成功完成，客户端和服务端会协商好一个secret。在有限域或者椭圆形曲线（(EC)DHE）密钥交换的基础上，TLS既支持预共享密钥（PSK），也支持DH算法。PSK是 Early Data (0-RTT) 的基础，当销毁(EC)DHE密钥之后，后者提供了前向保密性（FS）。这两种模式也可以结合起来，以提供前向保密，同时使用PSK进行认证。

在完成TLS握手之后，客户端就知晓并认证了服务端的身份，并且服务端也可以选择知晓并认证客户端的身份。TLS支持X.509 [RFC5280] 基于证书的服务端和客户端认证方式。当使用PSK密钥交换时(如在恢复中)，PSK的认知可用于验证对端的身份。

TLS密钥交换能够抵御攻击者的篡改，并且能够生成不受两端控制的共享secrets。

TLS提供了QUIC感兴趣的两种基本握手模式：

* 在完整的1-RTT握手过程中，经过一个往返，并且服务端立刻对客户端的握手消息响应之后，客户端就能够发送应用数据。
* 在0-RTT中，客户端使用了之前掌握的服务端信息，并且可以立刻发送应用数据。这些应用数据可以被攻击者重放。因此，0-RTT不适合执行可能会引发任何操作的指令，如果重放这些指令，可能会导致不良后果。

一个带0-RTT应用数据的简化版的TLS握手如图2所示：

```
       Client                                             Server

       ClientHello
      (0-RTT Application Data)  -------->
                                                     ServerHello
                                            {EncryptedExtensions}
                                                       {Finished}
                                <--------      [Application Data]
      {Finished}                -------->

      [Application Data]        <------->      [Application Data]

       () Indicates messages protected by Early Data (0-RTT) Keys
       {} Indicates messages protected using Handshake Keys
       [] Indicates messages protected using Application Data
          (1-RTT) Keys

                     Figure 2: TLS Handshake with 0-RTT
```

* ()表示使用Early Data（0-RTT）密钥保护的消息
* {}表示了使用握手密钥保护的消息
* []表示了使用应用数据（1-RTT）密钥保护的消息

图2删除了EndOfEarlyData消息，因为在QUIC中没有用到（参考8.3节）。同样，QUIC也没有使用ChangeCipherSpec 或 KeyUpdata 消息。TLS 1.3中，ChangeCipherSpec是冗余的（参考8.4节）。QUIC自带了密钥更新机制（参考第6章）。

使用了一些加密等级来保护数据：
* Initial Keys
* Early Data (0-RTT) Keys
* Handshake Keys
* Application Data (1-RTT) Keys

应用数据只能出现在Early Data和Application Data等级。Handshake和Alert消息可以出现在任何等级。

如果客户端和服务端以前通信过，可以进行0-RTT握手。在1-RTT握手中，在客户端收到服务端所有握手消息之前，它不能发送受保护的应用数据。

# 3. Protocol Overview

QUIC [QUIC-TRANSPORT] 对包的机密性和完整性保护负责。对此它使用了TLS握手[TLS13]中的密钥，而相较于在QUIC上承载TLS records（如TCP），TLS握手和Alert消息直接在QUIC传输层（替代了TLS record层）上进行传递。具体如图3所示：

```
   +--------------+--------------+ +-------------+
   |     TLS      |     TLS      | |    QUIC     |
   |  Handshake   |    Alerts    | | Applications|
   |              |              | |  (h3, etc.) |
   +--------------+--------------+-+-------------+
   |                                             |
   |                QUIC Transport               |
   |   (streams, reliability, congestion, etc.)  |
   |                                             |
   +---------------------------------------------+
   |                                             |
   |            QUIC Packet Protection           |
   |                                             |
   +---------------------------------------------+

                           Figure 3: QUIC Layers
```

QUIC同样依赖了TLS来进行认证、协商对安全和性能敏感的参数。

相对于严格分层，这两个协议紧密合作：QUIC使用了TLS握手；TLS使用了QUIC提供的可靠性、有序传输、record层。

在高层，TLS和QUIC模块之间有两个主要的交互：

* TLS模块通过QUIC收发消息，QUIC为TLS提供了一条抽象的可靠流。
* TLS模块为QUIC模块提供了一系列更新，包括：（a）设置新的包保护密钥；（b）状态更新，例如握手完成，服务端认证等。

图4展示了这些交互的具体细节，尤其是QUIC包保护。

```
   Figure 4 shows these interactions in more detail, with the QUIC
   packet protection being called out specially.

   +------------+                               +------------+
   |            |<---- Handshake Messages ----->|            |
   |            |<- Validate 0-RTT parameters ->|            |
   |            |<--------- 0-RTT Keys ---------|            |
   |    QUIC    |<------- Handshake Keys -------|    TLS     |
   |            |<--------- 1-RTT Keys ---------|            |
   |            |<------- Handshake Done -------|            |
   +------------+                               +------------+
    |         ^
    | Protect | Protected
    v         | Packet
   +------------+
   |   QUIC     |
   |  Packet    |
   | Protection |
   +------------+

                    Figure 4: QUIC and TLS Interactions
```

不像TLS over TCP，想要发送数据的QUIC应用不会通过TLS “application_data” records 来发送数据。
相反，它们将数据以QUIC STREAM帧或者其他帧类型的形式，通过QUIC包来进行传输。

# 4. Carrying TLS Messages

QUIC在CRYPTO帧中传输了TLS握手数据，每个CRYPTO帧中包含了一连串的握手数据，这些握手数据以offset和length进行区分。这些帧被打包到QUIC包，并在当前加密等级下被加密。如TLS over TCP一样，一旦TLS握手数据被传给QUIC，接下来就是QUIC的责任来保证可靠传输。每个TLS产生的数据块都跟TLS当前使用的密钥集合有关。如果QUIC需要重传这个数据，它必须（MUST）使用相同密钥，即使TLS已经切换到更新的密钥。

TLS产生的每个数据块都与TLS当前使用的密钥集相关联。 如果QUIC需要重新传输该数据，即使TLS已经更新到更新的密钥，它也必须使用相同的密钥。

每个加密级别对应一个序号空间。 使用的包序号空间决定了帧的语义。在不同的包序号空间内禁止使用某些帧，参见[QUIC-TRANSPORT]的12.5节。

因为包可能在网络上发生乱序，QUIC使用了包类型来表示使用哪个密钥来保护一个指定的包，具体如表1所示。
当需要发送不同类型的包时，终端应当（SHOULD）合并这些包，并在同一个UDP数据报中进行发送。

```
       +=====================+=================+==================+
       | Packet Type         | Encryption Keys | PN Space         |
       +=====================+=================+==================+
       | Initial             | Initial secrets | Initial          |
       +---------------------+-----------------+------------------+
       | 0-RTT Protected     | 0-RTT           | Application data |
       +---------------------+-----------------+------------------+
       | Handshake           | Handshake       | Handshake        |
       +---------------------+-----------------+------------------+
       | Retry               | Retry           | N/A              |
       +---------------------+-----------------+------------------+
       | Version Negotiation | N/A             | N/A              |
       +---------------------+-----------------+------------------+
       | Short Header        | 1-RTT           | Application data |
       +---------------------+-----------------+------------------+

                 Table 1: Encryption Keys by Packet Type
```

[QUIC-TRANSPORT]第17章展示了如何将多个加密等级的包嵌入到握手过程。

## 4.1. Interface to TLS

如图4所示，QUIC向TLS提供了4个主要功能接口：

* 收发握手消息
* 从一个恢复的会话处理保存的传输和应用状态，并决定是否可以产生或接收early data
* 密钥更新（包括发送与接收）
* 握手状态更新

可能还需要额外的功能来配置TLS。特别是，QUIC和TLS需要就“由谁负责对端凭证的验证”达成一致，如证书校验（[RFC5280]）。

### 4.1.1. Handshake Complete

本文中，在TLS协议栈报告握手完成时，才认为TLS握手完成。当TLS协议栈发送了Finished消息，并校验了对端的Finished消息，TLS协议栈才会报告握手完成。
校验对端的Finished消息，为终端保证了之前的握手消息没有被篡改。值得注意的是，握手不会在两端同时完成。
因此，任何基于握手完成的需求都取决于相关终端的角度。

### 4.1.2. Handshake Confirmed

在本文档中，认为服务端的TLS握手在握手完成时被确认。
服务器必须在握手完成后立即发送HANDSHAKE_DONE帧。
客户端的握手在收到HANDSHAKE_DONE帧时被确认。

此外，客户端可以（MAY）认为握手在它收到一个1-RTT包的确认消息的时候被确认。记录使用1-RTT密钥加密的最小包序号，并将这个序号与任何在1-RTT ACK帧中收到的最大确认字段做对比：一旦最大ACK序号大于等于最小的发送序号，就认为握手被确认了。

### 4.1.3. Sending and Receiving Handshake Messages

为了驱动握手，TLS依赖于能够发送和接收握手消息。 在这个接口上有两个基本功能：一个是QUIC请求握手消息，一个是QUIC提供组成握手消息的字节。

在开始握手之前，QUIC向TLS提供它希望携带的传输参数（见8.2节）。

QUIC客户端通过向TLS请求TLS握手字节来启动TLS，客户端在发送第一个数据包之前获取握手字节。
QUIC服务端通过向TLS提供客户端的握手字节来启动这个过程。

每个加密等级都和一连串不同的字节相关，这串字节通过CRYPTO帧可靠地传给对端。
当TLS要发送握手的字节时，它们会被追加到当前加密级别的握手字节中。
然后，加密级别决定了产生的CRYPTO帧所承载的数据包类型，见表1。

总共有4个加密等级，分别为Initial、0-RTT、Handshake、1-RTT包提供了密钥。
CRYPTO帧只出现在除了0-RTT等级以外的三种等级中。这4种加密等级映射到了3中包序号空间：
Initial、Handshake、应用数据包序号空间。其中Initial、Handshake加密包使用了各自独立的空间；
0-RTT和1-RTT共享了应用数据包序号空间。

QUIC将 TLS Handshake records的未保护内容作为CRYPTO帧的内容。
QUIC不使用TLS record protection。
QUIC将CRYPTO帧组合成QUIC数据包，并使用QUIC packet protection对其进行保护。

QUIC CRYPTO帧仅携带TLS握手消息，TLS警报被转换为QUIC CONNECTION_CLOSE错误码（第4.8节）。 
QUICK不能以任何加密级别传送TLS application data和其他content类型；如果从TLS协议栈收到了这些数据，就是一种错误。

当终端从网络中接收到包含CRYPTO帧的QUIC包时，它的操作如下。

  * 如果数据包使用的是当前的TLS接收加密级别，则像往常一样将数据排序到输入流中。与STREAM帧一样，使用偏移量来寻找数据序列中的正确位置。 如果这个过程的结果是有新的数据可用，那么它将按顺序传递给TLS。
  * 如果数据包来自于之前的加密级别，则该数据包不得包含超出该流中先前接收的数据末尾的数据。实现必须将任何违反此要求的行为视为PROTOCOL_VIOLATION类型的连接错误。
  * 如果数据包来自一个新的加密级别，那么它将被TLS保存以备以后处理。 一旦TLS转向接收来自这个加密级别的数据，就可以将保存的数据提供给TLS。 当TLS为更高的加密级别提供密钥时，如果有前一个加密级别的数据没有被TLS消耗掉，这必须作为PROTOCOL_VIOLATION类型的连接错误处理。

每次TLS被提供新的数据时，都会向TLS请求新的握手字节。 如果收到的握手信息不完整或者没有数据要发送，TLS可能不会提供任何字节。

CRYPTO帧的内容可能被TLS增量处理，也可能被缓冲，直到有完整的消息或传输为止。TLS负责缓冲已按顺序到达的握手字节，QUIC负责缓冲不按顺序到达的握手字节或尚未准备好的加密级别。QUIC不为CRYPTO帧提供任何流控手段（见[QUIC-TRANSPORT]的7.5节）。

TLS握手完成后，会将其与TLS需要发送的所有最终握手字节一起指示给QUIC。在这个阶段，对端在握手过程中公布的传输参数会被验证，见第8.2节。

握手完成后，TLS就变成了被动状态。TLS仍然可以接收来自对端的数据并做出响应，但是除非有特别的请求，否则它不需要发送更多的数据 —— 无论是应用程序还是QUIC。发送数据的一个原因是，服务器可能希望向客户端提供其他的或更新的会话票据。

握手完成后，QUIC只需要向TLS提供CRYPTO流中到达的任何数据。与握手过程中使用的方式相同，在提供收到的数据后，会向TLS请求新的数据。

### 4.1.4. Encryption Level Changes

当某一加密级别的密钥可供TLS使用时，TLS就会向QUIC表明该加密级别的密钥可被读/写。

新密钥的可用性总是向TLS提供输入的结果。TLS只有在被初始化（由客户端）或提供新的握手数据后才会提供新的密钥。

然而，TLS的实现可以异步地执行一些处理。特别是，验证证书的过程可能需要一些时间。在等待TLS处理完成的过程中，如果收到的数据包可能会使用尚未可用的密钥进行处理，那么终端应该缓冲这些数据包。一旦TLS提供密钥，这些数据包就可以被处理。 终端应该（SHOULD）继续响应这段时间内可以处理的数据包。

在处理输入后，TLS可能会产生握手字节、新加密级别的密钥，或者两者兼而有之。

当新的加密等级可用时，TLS给QUIC提供了三个组件：

* 一个密钥(secret)
* 一个AEAD函数（Authenticated Encryption with Associated Data function）
* 一个密钥生成函数（KDF - Key Derivation Function）

这些组件是基于TLS协商流程得到的，并且会被QUIC用来生成加密packet和header的密钥。

如果0-RTT是可用的，它在客户端发送ClientHello包或者服务端收到这个包之后就已经就绪。在向QUIC客户端提供第一个握手字节后，TLS协议栈可能会发出信号更改为0-RTT密钥。在服务端，在收到包含ClientHello消息的握手字节后，TLS服务端可能会发出0-RTT密钥可用的信号。

虽然TLS一次只使用一个加密级别，但QUIC可以使用多个级别。例如，终端在发送其Finished消息后（使用Handshake加密级别的CRYPTO帧）可以发送STREAM数据（1-RTT加密）。如果Finished消息丢失，终端使用Handshake加密级别重传丢失的消息。重新排序或丢失数据包可能意味着QUIC需要处理多个加密级别的数据包。在握手过程中，这意味着可能要处理比TLS当前使用的加密级别更高和更低的加密级别的数据包。

具体来说，服务端实现需要能同时处理handshake加密等级和0-RTT加密等级的包。客户端给服务端回的ACK frames是被0-RTT加密等级的Handshake key保护的，服务端需要处理这些ack以检测是否有握手包丢包。

QUIC也需要访问那些可能原本对TLS实现无用的密钥。比如说，一个客户端可能需要再它在一个加密等级上可以发送CRYPTO帧之前，确认Handshake包。
TLS因此需要在QUIC生成密钥之前为QUIC提供密钥。

### 4.1.5. TLS Interface Summary

图5总结了客户端和服务器的QUIC和TLS之间的交换。
实心箭头表示携带握手数据的数据包；虚线箭头表示可以发送应用数据的地方。
每个箭头都标有该传输所用的加密级别。

```
   Client                                                    Server
   ======                                                    ======

   Get Handshake
                        Initial ------------->
   Install tx 0-RTT Keys
                        0-RTT - - - - - - - ->

                                                 Handshake Received
                                                      Get Handshake
                        <------------- Initial
                                              Install rx 0-RTT keys
                                             Install Handshake keys
                                                      Get Handshake
                        <----------- Handshake
                                              Install tx 1-RTT keys
                        <- - - - - - - - 1-RTT

   Handshake Received (Initial)
   Install Handshake keys
   Handshake Received (Handshake)
   Get Handshake
                        Handshake ----------->
   Handshake Complete
   Install 1-RTT keys
                        1-RTT - - - - - - - ->

                                                 Handshake Received
                                                 Handshake Complete
                                                Handshake Confirmed
                                              Install rx 1-RTT keys
                        <--------------- 1-RTT
                              (HANDSHAKE_DONE)
   Handshake Confirmed

             Figure 5: Interaction Summary between QUIC and TLS
```

图5展示了一个消息中的多个包如何被单独处理，从而来展示什么样的涌入消息会触发不同的活动。
这显示了多个 "Get Handshake "调用，以检索不同加密级别的握手消息。
在所有包被处理之后，需要新的握手消息。

图5显示了一个简单握手交换的可能结构。具体过程根据终端实现的结构和数据包到达的顺序而变化。各个实现可以使用不同数量的操作，或者以其他顺序执行。

## 4.2. TLS Version

本文描述了如何结合TLS 1.3 [TLS13]和QUIC。

在实践中，TLS握手会协商一个TLS版本。这可能导致协商出一个比1.3版本更新的版本，如果两端都支持这个版本的话。如果新版本能够提供QUIC使用的TLS 1.3版本使用的特性，那么新版本也是可以接收的。

客户端不得（MUST NOT）提供早于1.3的TLS版本。
配置错误的TLS实现可能会协商TLS 1.2或其他较旧的TLS版本。
如果协商的TLS版本早于1.3，则终端必须终止连接。

## 4.3. ClientHello Size

客户端的第一个initial包包含了它第一个加密握手消息的开头或者所有，对于TLS来说就是ClientHello。
服务端可能需要解析整个ClientHello（比如，访问诸如SNI或者SLPN的扩展），从而来决定是否要接受新的QUIC连接请求。如果ClientHello出现在多个Initial包中，那么服务端就需要缓存第一个收到的分片，而如果此时客户端的地址还没有完成校验，这可能需要消耗较多的资源。为了避免这种情况，服务端可以（MAY）使用Retry特性（[QUIC-TRANSPORT]第8.1小节），只缓存经过地址校验的客户端的部分ClientHello消息。

QUIC包和帧需要在ClientHello上增加至少36个字节的额外开销。如果客户端选择了一个大于0字节的CID，会继续增加开销。而如果服务端发送Retry包的时候，可能需要token字段或一个长于8字节的CID，此时也会增加开销。

典型的TLS ClientHello消息可以轻易的嵌入到1200字节的包中。但是，除了QUIC增加的开销，还有几个可能会超过这个限制的变量。过大的session tickets（会话票证），多个或者过大的共享密钥，过长的支持加密列表，签名算法，版本，QUIC传输参数，以及其他可协商的参数和扩展，都可能导致这个消息尺寸增长。

对于服务端，除了CIDs和tokens之外，TLS会话票证的尺寸也会对客户端的连接效率产生影响。
将这些值最小化会增加客户端使用这些值，并将它们的整个ClientHello消息嵌入到它们第一个Initial包中的可能性。

TLS实现不需要保证ClientHello是否足够大以满足QUIC数据包的要求。QUIC PADDING帧会根据需要增加数据包的大小，参见[QUIC-TRANSPORT]第14.1节。

## 4.4. Peer Authentication

认证的要求取决于所使用的应用协议。 TLS提供服务器认证，并允许服务器请求客户端认证。

客户端必须验证服务器的身份。 这通常包括验证服务器的身份是否包含在证书中，以及证书是否由受信任的实体签发（例如[RFC2818]）。

> 注意：当服务器提供证书进行认证时，证书链的大小可能会消耗大量的字节。控制证书链的大小对QUIC的性能至关重要，因为在验证客户端地址之前，服务器每收到一个字节就只能发送3个字节（[QUIC-TRANSPORT]第8.1节）。 证书链的大小可以通过以下方式来管理：限制名称或扩展名的数量；使用像ECDSA这样的小公钥表示的密钥；或者使用证书压缩[COMPRESS]。

服务端可以（MAY）在握手期间请求客户端认证。如果客户端不能在请求时进行认证，则服务器可以拒绝连接。客户端身份验证的要求因应用程序协议和部署而异。

服务端必须不能（MUST NOT）使用握手之后的客户端认证信息，因为QUIC的多路复用功能阻止了客户端将证书请求和触发它的应用等级事件结合起来。

更具体的来说，服务端必须不能（MUST NOT）发送握手之后的TLS CertificateRequest 消息，并且客户端必须（MUST）在收到这个消息之后，把它当做是一种PROTOCOL_VIOLATION类型的连接错误。

服务端必须不能（MUST NOT）使用握手之后的客户端认证信息，因为QUIC的多路复用功能阻止了客户端将证书请求和触发它的应用等级事件结合起来。

## 4.5. Session Resumption

QUIC可以使用TLS 1.3的会话恢复特性。这个特性是这样的：握手完成之后，在CRYPTO帧中携带NewSessionTicket消息。
会话恢复可用于提供0-RTT，也可在禁用0-RTT时使用。

当创建一个恢复的连接，使用会话恢复的终端可能需要保存一些关于当前连接的信息。
TLS要求保存一些信息，参考[TLS13]的4.6.1节。
当恢复连接的时候，QUIC本身不依赖于保存的状态，除非也使用了0-RTT（参考4.6节和 [QUIC-TRANSPORT]的7.3.1节）。
应用协议可以依赖于在恢复的连接间保留的状态。

客户端可以和session ticket一起存储任何恢复需要的状态。服务端可以使用session ticket来携带状态。

会话恢复允许服务端在恢复的连接上关联原始连接的活动，这可能是一个客户端的隐私问题。
客户端可以选择禁用恢复来避免这种关联性。
客户端不应该（SHOULD NOT）重用ticket，因为这允许了实体来关联连接，而不是服务端。

## 4.6. 0-RTT

QUIC中的0-RTT功能允许客户端在握手完成之前发送应用数据。这是通过重用之前连接中协商好的参数来实现的。为了实现这一点，0-RTT依赖于客户端记住关键参数并向服务器提供一个TLS会话票据，允许服务器恢复相同的信息。

这些信息包括 由[TLS13]决定的确定TLS状态的参数、QUIC传输参数、所选的应用协议，以及应用协议可能需要的任何信息；见4.6.3节。这些信息决定了0-RTT数据包及其内容是如何形成的。

为了确保两个终端都能获得相同的信息，所有用于建立0-RTT的信息都来自同一个连接。终端不能选择性地忽略可能改变0-RTT发送或处理的信息。

[TLS13]对原始连接和任何使用0-RTT的尝试之间的时间设置了7天的限制。对0-RTT的使用还有其他限制，特别是那些由潜在的重放攻击引起的限制；见第9.2节。

### 4.6.1. Enabling 0-RTT

NewSessionTicket消息中的TLS "early_data "扩展被定义为（在 "max_early_data_size "参数中）传达服务端愿意接受的TLS 0-RTT数据量。QUIC不使用TLS 0-RTT数据，QUIC使用0-RTT数据包来携带early data。相应地，"max_early_data_size "参数被重新处理为持有一个标志值0xffffffff，以表示服务器愿意接受QUIC 0-RTT数据；为了表示服务器不接受0-RTT数据，NewSessionTicket中省略了 "early_data "扩展。客户端可以在QUIC 0-RTT中发送的数据量，由服务器提供的initial_max_data传输参数控制。

服务器在发送early_data扩展时，不得将max_early_data_size字段设置为0xffffffff以外的任何值。客户端必须将收到包含任何其他值的early_data扩展的NewSessionTicket视为PROTOCOL_VIOLATION类型的连接错误。

希望发送0-RTT数据包的客户端在随后握手的ClientHello消息中使用early_data扩展名（[TLS13]第4.2.10节），然后它在0-RTT数据包中发送应用数据。

如果服务器发送了NEW_TOKEN帧，尝试0-RTT的客户端也可能提供一个地址验证令牌（[QUIC-TRANSPORT]的8.1节）。

### 4.6.2. Accepting and Rejecting 0-RTT

服务端通过发送带early_data扩展的EncryptedExtensions来接受0-RTT（[TLS13]第4.2.10小节），然后服务端就可以处理并确认它收到的0-RTT包了。

服务端通过发送不带early_data扩展的EncryptedExtensions来拒绝0-RTT。
如果服务端发送了TLS HelloRetryRequest，那么它总是会拒绝0-RTT。
当拒绝0-RTT时，服务端必须不能（MUST NOT）处理任何0-RTT包，即使它能够处理。
当0-RTT被决绝，客户端如果收到0-RTT包的确认，应当（SHOULD）把这种情况当做是一种PROTOCOL_VIOLATION的连接错误（如果客户端能够检测出这种条件）。

如果0-RTT被拒绝，这个客户端预先设定的所有连接特性可能都是错误的。这包含了应用协议的选择、传输参数，以及所有应用配置。因此客户端必须（MUST）重置所有流的状态，包括和这些流绑定的应用状态。

如果客户端收到了Retry或者Version Negotiation包，则可以（MAY）尝试再次发送0-RTT。这些包不意味着服务端拒绝了0-RTT。

### 4.6.3. Validating 0-RTT Configuration

当服务端收到带early_data扩展的ClientHello消息，它需要决定是否接受客户端的early data，TLS协议栈参与了部分的决策（比如检查恢复的CH中的加密套件）。
即使TLS协议栈没有拒绝early data的理由，QUIC协议栈或者使用QUIC应用协议也可能因为 和恢复的会话有关的 传输层或者应用的配置，和服务端当前配置不兼容，而拒绝early data。

QUIC要求把更多的传输状态和0-rtt session ticket 结合起来。一种通常的实现是使用stateless session tickets，并在session ticket中开始这个状态。
使用QUIC的应用协议可能会有类似的关联或者保存状态的需求。这个关联的状态用于决定early data是否必须被拒绝。比如说，HTTP/3（[QUIC-HTTP]）配置决定了如何解析客户端的early data。其他使用QUIC的应用在决定接受还是拒绝early data的问题上有不同的需求。

## 4.7. HelloRetryRequest

HelloRetryRequest消息（见[TLS13]第4.1.4节）可以用来请求客户端提供新的信息，如密钥共享，或者验证客户端的某些特性。从QUIC的角度来看，HelloRetryRequest与Initial包中携带的其他加密握手消息没有区别。虽然原则上可以使用这个特性来验证地址，但是QUIC的实现应该使用Retry特性；参见[QUIC-TRANSPORT]的8.1节。

## 4.8. TLS Errors

如果TLS出现错误，它就会按照[TLS13]第6节的定义生成相应的告警。

TLS告警会被转换为QUIC连接错误。AlertDescription的值被加到0x100中，从CRYPTO_ERROR保留的范围中产生一个QUIC错误代码。产生的值在类型为0x1c的QUIC CONNECTION_CLOSE帧中发送。

QUIC只能传达 "fatal "的告警级别。 在TLS 1.3中，"warning"级别的唯一用途是发出连接关闭的信号（[TLS13]第6.1节）。由于QUIC提供了连接终止的替代机制，并且TLS连接只有在遇到错误时才会被关闭，所以QUIC终端必须将 TLS的任何告警视为"fatal"级别。

QUIC允许使用通用码来替换指定的错误码，参考[QUIC-TRANSPORT]的11章。
对于TLS告警，这包括了将所有告警替换成通用告警，比如handshake_failure（QUIC中的0x128）。
终端可以（MAY）使用通用错误码来避免机密信息泄露的可能性。

## 4.9. Discarding Unused Keys

在QUIC迁移到一个新的加密等级之后，就可以丢弃之前加密等级的包保护密钥。握手期间发生多次这种情况，同样密钥更新的时候也会发生多次这样的情况。

当新密钥可用，不会立刻丢弃包保护密钥。如果一个低加密等级中的包包含了CRYPTO帧，那么重传CRYPTO数据的帧必须（MUST）在同一个加密等级中被发送。相似地，终端只能在相同的加密等级对一个包进行确认。因此在新加密等级可用之后，有可能还要将低加密等级的密钥继续保存一小段时间。

终端不能丢弃给定加密级别的密钥，除非它已经收到了该加密级别的对端的所有加密握手信息，而且对端也进行了相同的操作。初始密钥（第 4.9.1 节）和握手密钥（第 4.9.2 节）有不同的方法来确认，这些方法不会因为对端可能没有收到所有必要的确认而阻止该加密级别的数据包被接收或发送。

尽管终端可能保存更老的密钥，新的数据必须（MUST）在当前可用的最高加密等级发送。只有ACK帧和重传的CRYPTO帧在之前的加密等级中发送。这些包也可以（MAY）包括PADDING帧。

### 4.9.1. Discarding Initial Keys

使用initial secrets（5.2节）保护的包没有经过认证，这意味着攻击者可以伪造包来扰乱连接。
为了限制这些攻击，可以更加激进地丢弃initial包保护密钥。

当成功使用Handshake包之后，意味着不再需要交换Initial包，因为handshake的密钥只能在收到所有initial包的CRYPTO帧之后才能生成。因此客户端必须（MUST）在它第一次发送Handshake包的时候丢弃initial密钥，而服务端必须（MUST）在它第一次成功处理一个Handshake包的时候丢弃initial密钥。
终端必须不能（MUST NOT）在这个节点之后再发送initial包。

这导致放弃了initial加密等级的丢包恢复状态，并忽略了所有未完成的initial包。

### 4.9.2. Discarding Handshake Keys

当TLS握手被确认，终端必须（MUST）丢弃它的握手密钥（4.1.2节）。

### 4.9.3. Discarding 0-RTT Keys

0-rtt和1-rtt包共享了同一个包序号空间，并且客户端在发送一个1-RTT包之后不会再发送0-RTT包。

因此，只要设置了1-RTT密钥之后，客户端应当（SHOULD）丢弃0-RTT密钥，因为它们在这以后就没什么用了。

另外，一旦接收到1-RTT包，服务端可以（MAY）丢弃0-RTT密钥。然而，由于包的乱序问题，一个0-RTT包可能在1-RTT包后到达。
服务端可以（MAY）暂时保留0-RTT密钥来允许解密乱序的包，而不用重传带1-RTT密钥的内容。
在接收到1-RTT包之后，服务端必须（MUST）在短时间内丢弃0-RTT密钥；推荐（RECOMMENDED）的时间周期是PTO的3倍。
如果服务端认为它收到了所有0-RTT包，服务端可以（MAY）早一点丢弃0-RTT密钥，这可以通过对丢失的包的序号保持跟踪来实现。

# 5. Packet Protection

正如TLS over TCP，QUIC使用了TLS握手中的密钥（TLS通过AEAD算法 [AEAD] 协商产生）来保护数据包。

QUIC数据包根据其类型有不同的保护措施。
  * Version Negotiation包没有加密保护。
  * Retry包使用AEAD_AES_128_GCM提供保护以防止意外修改，并限制可以产生有效重试的实体（5.8节）。
  * Initial包使用AEAD_AES_128_GCM，其密钥来自客户端发送的第一个初始数据包的Destination Connection ID字段（第5.2节）。
  * 所有其他数据包都有很强的机密性和完整性的加密保护，使用TLS协商的密钥和算法。

本节介绍了如何对握手数据包、0-RTT数据包和1-RTT数据包进行数据包保护。同样的数据包保护过程也适用于Initial包。 然而，由于确定Initial数据包使用的密钥是很简单，所以它不被认为具有机密性或完整性保护。Retry包使用固定的密钥，因此同样缺乏机密性和完整性保护。

## 5.1. Packet Protection Keys

QUIC获取包保护密钥的方式和TLS获取record保护密钥的方式一致。

对于双向传输，每个加密等级都有独立的secret值用来保护包。这些流量的secrets由TLS（[TLS13]第7.1小节）生成，并且被QUIC在除initial加密等级以外的所有加密等级中使用。initial加密等级的secrets根据客户端的初始DCID计算，详见5.2节。

用于保护包的密钥通过使用KDF算法（TLS提供）从TLS secrets计算所得。在TLS 1.3中使用了HKDF-Expand-Label函数（详见[TLS13]的7.1小节），使用了协商出来的加密套件中的哈希函数。
QUIC中对HKDF-Expand-Label的所有使用都使用零长上下文。
请注意，使用字符串描述的标签使用ASCII [ASCII]编码为字节，不带引号或任何尾随的NUL字节。其他版本的TLS必须（MUST）提供类似的函数，从而和QUIC结合使用。

通过输入当前加密等级的secret和“quic key”标签到KDF算法中来产生AEAD密钥；使用“quic iv”标签来获取初始向量IV（参考5.3节）；使用“quic hp”标签来获取头保护密钥（参考5.4节）。通过使用这些标签，为QUIC和TLS之间提供了隔离性（参考9.6节）。

"quic key"和"quic hp"都是用来产生密钥的，所以提供给HKDF-Expand-Label的长度和这些标签一起由AEAD或头保护算法中密钥的大小决定。"quic iv"提供的长度是AEAD随机数的最小长度，如果这个长度小于8字节，则为8个字节；参见[AEAD]。

生成initial secrets使用的KDF算法永远是TLS 1.3的HKDF-Expand-Label函数（参考5.2节）。

## 5.2. Initial Secrets

Initial包应用了数据包加密保护过程，但使用从客户端第一个初始数据包的目标连接ID字段导出的secret。

这个secret是通过HKDF-Extract（[HKDF]第2.2节）确定的，使用了值为0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a的salt和Destination Connection ID字段的IKM。 
这将产生一个中间伪随机密钥(PRK)，可用于派生两个单独的secret以进行发送和接收。

客户端使用PRK和"client in"标签来构建初始数据包，作为TLS [TLS13] 中HKDF-Expand-Label函数的输入，产生一个32字节的secret。由服务器构建的数据包使用相同的过程和标签"server in"。
传输initial secret和密钥时，HKDF使用的哈希函数是SHA-256 [SHA]。

这个过程的伪代码为：

```
   initial_salt = 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
   initial_secret = HKDF-Extract(initial_salt,
                                 client_dst_connection_id)

   client_initial_secret = HKDF-Expand-Label(initial_secret,
                                             "client in", "",
                                             Hash.length)
   server_initial_secret = HKDF-Expand-Label(initial_secret,
                                             "server in", "",
                                             Hash.length)
```

和HKDF-Expand-Label函数一起使用的连接ID是客户端发送的Initial包中的DCID。
在客户端收到Retry包之前，客户端发送的Initial包中的这个值都是随机的，随后这个值会变为服务端选择的DCID。

未来版本的QUIC应当（SHOULD）使用新的盐值，从而来保证QUIC每个版本都使用不同的密钥。
这防止了只支持一个QUIC版本的中间设备查看或修改未来版本QUIC包的内容。

Initial包必须（MUST）使用TLS 1.3中定义的HKDF-Expand-Label函数，即使TLS版本不包含TLS 1.3。

当服务端发送一个Retry包来让客户端使用服务端选择的CID时，用来构建后续initial包的secret会改变。
当客户端改变了DCID时（响应服务端的Initial包时会改变），secret不会改变。

注意：Destination Connection ID字段可以是任何长度，最多20个字节，包括零长度。如果服务器发送一个带有零长Source Connection ID字段的Retry包，在Retry之后，Initial密钥无法向客户端保证服务端收到了它的包，所以客户端必须依赖包含Retry数据包的交换来验证服务器的地址；见[QUIC-TRANSPORT]的8.1节。

附录A载有Initial包样例。

## 5.3. AEAD Usage

QUIC包保护使用的数据相关认证加密（AEAD）[AEAD]函数和TLS连接中协商并使用的AEAD是一样的。
比如说，TLS使用了TLS_AES_128_GCM_SHA256加密套件，那么QUIC使用了AEAD_AES_128_GCM。

QUIC可以使用[TLS13]中定义的除TLS_AES_128_CCM_8_SHA256以外的所有加密套件。
除非为加密套件定义了头保护方案，否则必须不能（MUST NOT）协商加密套件。
本文为[TLS13]中除TLS_AES_128_CCM_8_SHA256以外的所有加密套件定义了一种头保护方案。
这些加密套件有一个16字节的认证标签，并生成一个比输入大16个字节的输出。

注意：如果一个ClientHello消息中提供了一个当前终端不支持的加密套件，当前终端必须不能（MUST NOT）拒绝这个ClientHello消息，否则就不可能部署新的加密套件了。这同样适用于TLS_AES_128_CCM_8_SHA256。

在构造数据包时，在应用报头保护之前先应用AEAD功能（5.4节）。
未受保护的数据包头是相关数据（A）的一部分。在处理数据包时，终端首先删除标头保护。

包的密钥和IV以5.1节中描述的方式进行计算。nonce（N）结合了保护包的IV和包序号。
重新生成的62位网络字节序的QUIC包序号左填0，直至达到IV的大小。
对包序号和IV进行异或操作，生成了AEAD nonce。

```
padded_packet_number = 62bit的packet number（网络字节序）用前导0补齐到IV长度.
AEAD nonce = padded_packet_number XOR IV
```

AEAD的相关数据A，是QUIC头部的内容，从短包头或长包头的首字节开始，直至unprotected packet number的尾部（即包含unprotected packet number）。

AEAD的输入明文P，是QUIC包的载荷，在[QUIC-TRANSPORT]中定义。

AEAD的输出秘文C，替换了P并在网络中进行传输。

一些AEAD函数存在同一个密钥和IV可以加密的包的上限（见6.6节）。
这可能比包序号上限小。终端必须（MUST）在超过AEAD当前正在使用的这个限制之前发起密码月更新（第6章）。

## 5.4. Header Protection

QUIC包头部的Packet Number字段，使用了另一个（和包保护密钥和IV无关的）密钥来进行保护。
（使用了“quic hp”标签来传递的）密钥用来为那些无需暴露给链路上设备的字段提供机密性保护。

这个保护方式旨在加密第一个字节的最低几位，以及包序号字段。
在长头包中，第一个字节的最低4位被加密保护；
在短头包中，第一个字节的最低5位被加密保护。
这种方式都覆盖了这两种头部格式中的保留位和包序号长度字段；短头包中，同样保护了短头包中的密钥相位。

在连接的生命周期中，使用了同一个头保护密钥，密钥更新后值也不会改变。
这使头保护可以用于保护密钥相位。

这种处理方式不适用于Retry或Version Negotiation包，它们的payload、字段不会被加密。

### 5.4.1. Header Protection Application

在使用了包保护之后，才可以使用头保护。包的秘文被采样并被当成加密算法的输入。
使用的算法由协商后的AEAD决定。

算法的输出是一个5字节的掩码，并使用了异或操作，将掩码用于被保护的头部字段。
包的第一个字节的最低几位，被第一个掩码字节的最低几位，通过XOR操作遮掩，
包序号，被剩下的字节，通过XOR操作遮掩。
如果掩码有剩余字节没被使用，可能是因为使用了更短的包序号编码。

图6演示了一个头保护的算法示例。而移除头保护只有决定包序号长度（pn_length）的顺序不一样（这里"^"用于表示异或）。

```
   mask = header_protection(hp_key, sample)

   pn_length = (packet[0] & 0x03) + 1
   if (packet[0] & 0x80) == 0x80:
      # Long header: 4 bits masked
      packet[0] ^= mask[0] & 0x0f
   else:
      # Short header: 5 bits masked
      packet[0] ^= mask[0] & 0x1f

   # pn_offset is the start of the Packet Number field.
   packet[pn_offset:pn_offset+pn_length] ^= mask[1:1+pn_length]

                   Figure 6: Header Protection Pseudocode
```

具体的头保护功能是根据所选的密码套件来定义的，见5.4.3节和5.4.4节。

图7演示了一个长头包（Initial包）和一个短头包（1-RTT包）示例，展示了每个被头保护加密的头部的字段，以及加密后包中被采样的载荷的部分内容。

```
   Initial Packet {
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 0,
     Reserved Bits (2),         # Protected
     Packet Number Length (2),  # Protected
     Version (32),
     DCID Len (8),
     Destination Connection ID (0..160),
     SCID Len (8),
     Source Connection ID (0..160),
     Token Length (i),
     Token (..),
     Length (i),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..)     # Remainder
   }

   1-RTT Packet {
     Header Form (1) = 0,
     Fixed Bit (1) = 1,
     Spin Bit (1),
     Reserved Bits (2),         # Protected
     Key Phase (1),             # Protected
     Packet Number Length (2),  # Protected
     Destination Connection ID (0..160),
     Packet Number (8..32),     # Protected
     Protected Payload (0..24), # Skipped Part
     Protected Payload (128),   # Sampled Part
     Protected Payload (..),    # Remainder
   }

             Figure 7: Header Protection and Ciphertext Sample
```

在QUIC可以使用TLS密码套件之前，必须（MUST）定义AEAD用来生成密码套件的头保护算法。
本文定义了AEAD_AES_128_GCM、AEAD_AES_128_CCM、AEAD_AES_256_GCM（所有这些AES AEAD算法在[AEAD]中定义）、AEAD_CHACHA20_POLY1305（在[CHACHA]中定义）。
在TLS选择密码套件之前，需要使用AES头保护（5.4.3节），与AEAD_AES_128_GCM包保护算法相对应。

### 5.4.2. Header Protection Sample

头保护算法使用了头保护密钥，以及从包载荷字段中秘文采样。

采样的时候，总是会采样一样多的字节，但是终端移除头保护的时候，却不知道Packet Number字段的长度。
密文的采样是从Packet Number字段开始后的4个字节的偏移量开始的。也就是说，在对报头保护的数据包密文进行取样时，假设Packet Number字段长为4个字节（其最大可能的编码长度）。

终端必须（MUST）丢弃长度不够、采样不完整的包

为了保证采样有足够多数据，包如果不够长，可以进行填充，保证被编码的包序号和被保护的载荷的长度之和，比头保护采样所需的字节数至少大4。[TLS13]中定义的加密套件（除了TLS_AES_128_CCM_8_SHA256，本文没有为其定义头保护方案）具有16字节扩展和16字节头保护采样。包序号是单字节编码、2字节包序号编码的2字节的帧，这就导致明文载荷中需要至少3个字节的帧。

采样后的秘文可以由以下伪代码计算得出：

```
   # pn_offset is the start of the Packet Number field.
   sample_offset = pn_offset + 4

   sample = packet[sample_offset..sample_offset+sample_length]
```

其中，短头包的包号偏移量可计算为：

```
   pn_offset = 1 + len(connection_id)
```

长头包的包号偏移可以计算为：

```
   pn_offset = 7 + len(destination_connection_id) +
                   len(source_connection_id) +
                   len(payload_length)
   if packet_type == Initial:
       pn_offset += len(token_length) +
                    len(token)
```

例如，对于一个有短包头、8字节CID、用AEAD_AES_128_GCM算法保护的数据包，sample部分会使用第13字节到第28字节（下标从0开始，包括第13、28字节）。

一个UDP数据报中可能包含多个QUIC数据包。每个数据包都是单独处理的。

### 5.4.3. AES-Based Header Protection

本小节定义了AEAD_AES_128_GCM，AEAD_AES_128_CCM，AEAD_AES_256_GCM三种包保护算法。
其中AEAD_AES_128_GCM、AEAD_AES_128_CCM在ECB模式下使用了128位AES [AES]。
AEAD_AES_256_GCM在ECB模式下使用了256位AES。

这个算法从包的秘文中采样了16个字节。并将其用于AES-ECB的输入。
在伪代码中，头保护函数被定义为：

```
   header_protection(hp_key, sample):
     mask = AES-ECB(hp_key, sample)
```

### 5.4.4. ChaCha20-Based Header Protection

当使用了AEAD_CHACHA20_POLY1305，头保护使用[CHACHA]第2.4节中的原始ChaCha20方法。
这个方法使用了256位密钥和包保护输出的16字节的采样。

被采样秘文的前4个字节是块counter参数。ChaCha20 实现可以使用一个小端顺序32位整数，来替换字节序。

剩余12个字节是nonce。ChaCha20实现可以将三个小端顺序的32位整数，来替换字节序。

加密掩码是通过调用ChaCha20来保护5个'\0'字节产生的。
在伪代码中，头保护函数被定义为：

```
   header_protection(hp_key, sample):
     counter = sample[0..3]
     nonce = sample[4..15]
     mask = ChaCha20(hp_key, counter, nonce, {0,0,0,0,0})
```

## 5.5. Receiving Protected Packets

一旦终端成功收到带指定序号的包，它必须（MUST）丢弃所有在相同包序号空间下，序号更高，且使用当前密钥或者更新后的密钥都无法成功解密的包。类似地，一个触发了密钥更新，但是无法被解密的包也必须（MUST）被丢弃。

包解密失败不意味着对端一定出现了协议错误，或者收到了攻击。如果包延迟严重，那么QUIC使用的被截断的包序号编码方式，可能导致解出来的包序号是错误的。

## 5.6. Use of 0-RTT Keys

如果0-RTT密钥可用，但是又缺乏重放攻击保护，意味着有必要限制0-RTT的使用，从而来避免协议受到重放攻击。

在[QUIC-TRANSPORT]中定义的帧中，STREAM, RESET_STREAM, STOP_SENDING和 CONNECTION_CLOSE帧对于0-RTT的使用是潜在的不安全的，因为它们携带了应用数据。 在0-RTT中接收到的应用数据可能会导致服务器上的应用多次而不是只处理一次数据。服务器因处理重放的应用数据而采取的额外行动可能会产生不必要的后果。因此，除非正在使用的应用程序特别要求，否则客户端不得将0-RTT用于应用程序数据。

使用QUIC的应用协议必须包含定义可接受的0-RTT使用的配置文件；否则，0-RTT只能用于承载不携带应用数据的 QUIC帧。例如，[HTTP-REPLAY]中描述了HTTP的配置文件，该配置文件用于HTTP/3；参见[QUIC-HTTP]的第10.9节。

尽管重放数据包可能会导致额外的连接尝试，但处理不携带应用数据的重放帧的效果仅限于改变受影响连接的状态。 使用重放的数据包无法成功完成TLS握手。

客户端可以（MAY）在它完成TLS握手之前来限制它发送什么数据。否则客户端就会把0-RTT密钥等同于1-RTT密钥，除了它不能用0-RTT密钥发送某些帧（见[QUIC-TRANSPORT]的12.5节）。

客户端收到了服务端接受了它的0-RTT数据的指示，可以在它收到所有服务端握手消息之前发送0-RTT数据。
客户端如果收到了0-RTT数据被拒绝的指示，应当（SHOULD）停止发送0-RTT数据。

服务端必须不能（MUST NOT）使用0-RTT密钥来保护包；它使用1-RTT密钥来保护0-RTT包的确认信息。
客户端必须（MUST）丢弃它收到的0-RTT包，而不是尝试解密他们。

一旦客户端启用了1-RTT密钥，它必须不能（MUST NOT）再发送0-RTT包。

注意：当服务端收到0-RTT数据时可以确认它，但是知道TLS握手完成之前，任何包含0-RTT数据确认信息的包不能被解密。直到客户端收到所有的服务端握手消息，才能获取到用于解密的1-RTT的密钥。

## 5.7. Receiving Out-of-Order Protected Packets

由于重排和丢包，终端可能会在收到最终的TLS握手消息之前接收到受保护的数据包。客户端将无法解密来自服务器的1-RTT数据包，而服务器将能够解密来自客户端的1-RTT数据包。任一个角色的终端在完成握手之前均不得解密来自其对端的1-RTT数据包。

尽管在接收到客户端的第一个握手消息后，服务端就有了1-RTT密钥，但是客户端状态还是缺乏保证：

* 客户端没有认证，除非服务端选择使用预先分享的密钥，并且认证了客户端的pre-shared key binder
* 客户端没有展示活跃度，除非服务端用RETRY包或其他方式验证了客户的地址（见[QUIC-TRANSPORT]第8.1节）。
* 服务端收到并响应的所有0-RTT数据可能是重放攻击数据。

因此，在握手完成之前，服务端对1-RTT密钥的使用仅限于发送数据。 
在TLS握手完成之前，服务端必须不能（MUST NOT）处理涌入的1-RTT受保护的包。
因为发送确认就意味着包中所有的帧都被处理了，服务端不能发送1-RTT包的确认，直到TLS握手完成。
收到的以1-RTT密钥保护的包之后，可以（MAY）将其保存，一旦握手完成，就可以将其解密。

注意：TLS实现可以在握手完成之前提供所有1-RTT加密信息。即使QUIC实现有1-RTT读密钥，这些密钥不能再握手完成之前使用

服务端等待客户端Finished消息的需求，依赖了对于正在传输Finished消息。
客户端可以避免head-of-line阻塞的可能性，只要在CRYPTO帧中带上Finished消息，然后将其包入到handshake包，最后将handshake包和1-RTT包合并并发送，直到其中一个handshake包被确认。
这使服务端立刻处理了这些包。

在收到TLS ClientHello之前，服务端可以收到用0-RTT密钥保护的数据包。
服务端可以保留这些数据包，以便在收到 ClientHello 时进行解密。

客户端一般会在握手完成的同时收到1-RTT密钥。
即使客户端有1-RTT密钥，客户端也不能在TLS握手完成之前处理传入的1-RTT受保护的数据包。

## 5.8. Retry Packet Integrity

携带了Retry Integrity Tag的Retry包提供了两种特性：
1）允许丢弃偶然畸变的包；
2）只有观察到Initial包的实体才能发送有效的Retry包。

Retry Integrity Tag是一个128位长的字段，并根据AEAD_AES_128_GCM [AEAD]算法，输入参数计算所得。
举个例子：

* 密钥(K)：128位长，假设输入为0xbe0c690b9f66575a1d766b54e368c84e。
* nonce(N)：96位长，假设输入为0x461599d35d632bf2239825bb。
* 文本（P）：为空。
* 相关数据（A），Retry伪包的内容，如图8所示：

密钥和nonce通过将0xd9c9943e6101fd200021506bcc02814c73030f25c79d71ce876eca876e6fca8e当做secret，再调用HKDF-expand-Label获得，标签为“quic key”和“quic iv”，

```
   Retry Pseudo-Packet {
     ODCID Length (8),
     Original Destination Connection ID (0..160),
     Header Form (1) = 1,
     Fixed Bit (1) = 1,
     Long Packet Type (2) = 3,
     Unused (4),
     Version (32),
     DCID Len (8),
     Destination Connection ID (0..160),
     SCID Len (8),
     Source Connection ID (0..160),
     Retry Token (..),
   }

                       Figure 8: Retry Pseudo-Packet
```

Retry伪包不会在网络上进行发送。它的计算方式是这样的：取得Retry包、去除Retry Integrity Tag，并预先生成了如下两个字段：

ODCID 长度：ODCID Length（ODCID长度）字段包含其后面的Original Destination Connection ID字段的长度，以字节为单位，编码为8位无符号整数。

ODCID：ODCID包含该Retry包响应的Initial包的OCID的值。此字段的长度在 ODCID Length 中给出。该字段的存在确保有效的Retry包只能由观察Initial包的实体发送。

# 6. Key Update

一旦握手被确认（见4.1.2节），终端可以发起密钥更新。

密钥相位表示使用哪些数据包保护密钥来保护数据包。
对于第一组1-RTT数据包，密钥相位初始设置为0，并切换为每次后续密钥更新的信号。

密钥相位位允许接收者检测建钥资料; 的变化，而不需要接收触发变化的第一个数据包。
注意改变了密钥相位的终端会更新密钥并解密包含改变值的数据包。

启动密钥更新的结果是两个终端都更新密钥。这与TLS不同，在TLS中，终端可以独立更新密钥。

这种机制取代了TLS的密钥更新机制，后者依赖于使用1-RTT加密密钥发送的KeyUpdate消息。
终端不得（MUST NOT）发送TLS KeyUpdate消息。 
终端必须将收到的TLS KeyUpdate消息视为类型为0x10a的连接错误，相当于unexpected_message的"fatal"TLS警报；参见4.8节。

图9显示了一个密钥更新过程，在这个过程中，使用的初始密钥集（用@M标识）被更新后的密钥（用@N标识）所取代。密钥相位的值用括号[]表示。

```
      Initiating Peer                    Responding Peer

   @M [0] QUIC Packets

   ... Update to @N
   @N [1] QUIC Packets
                         -------->
                                            Update to @N ...
                                         QUIC Packets [1] @N
                         <--------
                                         QUIC Packets [1] @N
                                       containing ACK
                         <--------
   ... Key Update Permitted

   @N [1] QUIC Packets
            containing ACK for @N packets
                         -------->
                                    Key Update Permitted ...

                            Figure 9: Key Update
```

## 6.1. Initiating a Key Update

终端维护了独立的读和写secret来保护包。终端开始一个密钥更新时，需要更新包保护写secret并使用它来保护新的包。
[TLS13]的7.2节描述了终端从已有写secret创建了一个新的写secret。这使用了TLS提供的标记位“quic ku”的KDF功能。
相关的密钥和IV根据5.1节定义的secret创建。头部保护密钥没有更新。

比如，使用TLS 1.3来更新写密钥，HKDF-Expand-Label使用如下：

```
   secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku",
                                    "", Hash.length)
```

终端切换了密钥相位的值，并使用了更新后的密钥和IV来保护后续所有的包。

在确认握手之前，终端必须不能（MUST NOT）开始密钥更新。
在终端接收到一个用当前密钥相位的密钥保护的包之前，终端必须不能（MUST NOT）开始后续的密钥更新。
这保证了另一个密钥更新开始之前，当前的密钥对于两端都是可用的。
可以这样实现该功能：跟踪1-RTT空间内，每个密钥相位的最小包序号，和被确认的最大包序号。一旦后者大于等于前者，就可以开始密钥更新。

注意：除了1-RTT包的密钥，其他包的密钥不会更新；他们的密钥从TLS握手状态单独获得。

开始了密钥更新的终端也会更新它收包的密钥。更新密钥之后需要用这些密钥来处理对端发送的数据包。

终端必须（MUST）保留旧的密钥，直到它成功地解除了使用新密钥发送的数据包的保护。
终端应该（SHOULD）在解除使用新密钥发送的数据包的保护后，保留旧密钥一段时间。 
过早的丢弃旧的密钥会导致包延迟并被丢弃。丢弃包最终会被对端判定为网络丢包，并降低性能。

## 6.2. Responding to a Key Update

在当前密钥相位收到一个包的确认之后，才允许对端开始密钥更新。
当处理包的时候，终端发现这个包的密钥相位和终端用来保护它发的上一个包的密钥相位不一致，终端就认为碰到了密钥更新。
终端需要使用下一个包保护密钥和IV来处理这个包。参考6.3节关于密钥生成的注意事项。

如果用下一个密钥和IV可以成功处理这个包，就意味着对端开始了密钥更新。
终端必须（MUST）在响应中将它的发送密钥更新为对应的密钥相位（如6.1节所述）。
在收到一个使用更新后密钥的包，以及发送这个包的确认信息之前，必须（MUST）更新发送密钥。
在对触发密钥更新的包进行确认时，通过使用更新后的密钥来保护带确认信息的包，终端宣告了密钥更新完成。

终端可以根据它正常的发包行为，来推迟包或者确认的发送；因此没有必要立刻生成一个包来响应密钥更新。
终端下一个发送的包会使用更新后的密钥。下一个包含确认的包会完成密钥更新。
对于开始密钥更新的包，如果一个终端还没有使用更新后的密钥来发送一个包含确认的包，却探测到第二次密钥更新，
这意味着对端在没有等待更新确认之前，就更新了两次密钥。
终端可以（MAY）把连续的密钥更新当做是一种KEY_UPDATE_ERROR类型的连接错误。

终端收到了一个携带了确认但使用旧密钥保护的包，其中使用了新密钥来对任何已确认的包进行保护，
那么终端可以（MAY）把这种情况当做是一种KEY_UPDATE_ERROR类型的连接错误。
这意味着对端收到并确认了密钥更新包，但是却没有更新密钥。

## 6.3. Timing of Receive Key Generation

对明确的密钥更新进行响应时，终端必须不能（MUST NOT）生成可能暗示Key Phase bit无效的定时侧通道（有一种 timing side-channel attack）信号。
当还没有允许密钥更新时，终端可以使用假的包保护密钥来替代被丢弃的密钥。
在定时信号（移除包保护时产生）中使用假密钥不会产生任何变化，并导致Key Phase bit无效的包被拒绝。

为收包而创建新的包保护密钥的过程可能暴露了密钥更新已经开始。
终端可以（MAY）生成新的密钥作为数据包处理的一部分，但是这创建了一个定时信号，而攻击者可以用来知晓何时发生了密钥更新，从而从相关包中了解到Key Phase bit的值。
通常期望终端拥有当前和下一个接收数据包保护密钥。 在密钥更新完成后的短时间内，直到PTO，终端都可以推迟生成下一组接收数据包保护密钥。 这允许终端仅保留两组接收密钥。 请参阅第6.5节。

一旦生成下一个包保护密钥集合，就应该（SHOULD）保存这个集合，即使收到的包后续被丢弃。
包含明显密钥更新的包很容易被遗忘——虽然密钥更新也很容易——但攻击者可以触发这个过程来制造DoS攻击。

出于这个原因，终端必须（MUST）能够保存两套包保护密钥来进行收包：
当前密钥集合与下一套密钥集合。除此之外，额外保存之前的密钥集合可能改善性能，但不重要。

## 6.4. Sending with Updated Keys

终端从不发送用旧密钥保护的数据包，只使用当前的密钥。
当切换到更新的密钥之后，当前用于包保护的密钥立刻就可以被丢弃。

相对于低序号的包，拥有更高序号的包必须（MUST）以相同或者更新的包保护密钥来进行保护。
如果终端之前在低序号包中使用了新的密钥，然后使用旧密钥成功移除了保护，必须（MUST）把这种情况当成是一种KEY_UPDATE_ERROR的错误。

## 6.5. Receiving with Different Keys

在密钥更新期间，可能收到因网络延迟，同时使用旧密钥保护的包。
保留旧的包保护密钥可以让这些包被成功处理。

如果使用下一个密钥相位中的密钥来进行保护的包，和那些使用前一个密钥相位中的密钥来进行保护的包，使用了相同的Key Phase值，若要处理用旧密钥保护的数据包，那么就有必要区分这两种包。
这可以通过包序号进行区分。一个解密后的比当前密钥相位中所有包序号都要低的包序号，使用了前一套包保护密钥；一个解密后的比当前密钥相位中所有包序号都要高的包序号，请求了使用下一套包保护密钥；

有必要慎重考虑来保证在之前的、当前的、以及后续的包保护密钥之间选择的时候不会暴露定时侧通道，从而可能进一步泄露当前使用了哪个密钥来移除包保护，

另外，终端可以只保留两套包保护密钥，在一段足够长的允许网络中数据重排序的时间后，将之前的切换为下一套宝保护密钥。
在这种情况下，可以单独使用Key Phase bit来选择密钥。

终端可以（MAY）在将下一组接收密钥推广为当前密钥后，允许一段约为PTO（见[QUIC-RECOVERY]）的时间，再创建下一套包保护密钥。
这些更新的密钥可以（MAY）在那个时间点替换掉之前的密钥。需要特别注意的是，PTO是一个主观的衡量方式，
也就是说，对端可能对RTT有不同的视角，这个时间需要足够长，这样任何乱序的包会被对端宣称为丢失，即使他们被确认了；同时也要足够短，足以让对端发起进一步的密钥更新。

终端需要允许对端在它保留旧密钥期间，可能不能够解密那些开始密钥更新的包（使用了新密钥的包）。
在收到一个确认收到之前密钥更新的确认之后，开始密钥更新之前，终端应当（SHOULD）等待3倍PTO时间。
无法等待有效时间可能导致包被丢弃。

终端在收到使用新密钥保护的数据包后，应当（SHOULD）保留旧密钥超过3倍PTO时间。在这个时间段之后，旧的读密钥和它们相关的secret都应当（SHOULD）被丢弃。

## 6.6. Limits on AEAD Usage

本文规定了AEAD算法的使用限制，以确保在使用QUIC时，过度使用不会使对手在攻击通信的保密性和完整性方面获得不成比例的优势。

TLS 1.3中定义的使用限制，针对机密性相关的攻击提供了保护，并适用于有效使用AEAD保护算法的应用。
认证加密中的完整性保护同样依赖了伪造包的数量限制。
在任何一次认证失败之后，TLS就会关闭连接。相对而言，QUIC忽略了那些无法通过认证的包，这也允许了更多伪造的尝试。

QUIC分别核算AEAD的机密性和完整性限制。机密性限制适用于用给定密钥加密的数据包数量。完整性限制适用于在给定连接中解密的数据包数量。下面将详细介绍如何为每个AEAD算法执行这些限制。

终端必须为每组密钥计算加密数据包的数量。如果使用相同密钥的加密数据包总数超过了所选AEAD的机密性限制，终端必须停止使用这些密钥。终端必须在发送比所选AEAD的机密性限制允许的更多受保护数据包之前启动密钥更新。如果不可能更新密钥，或者达到了完整性限制，终端必须停止使用连接，并且只发送无状态重置以响应接收数据包。建议终端在达到不可能更新密钥的状态之前，立即用类型为AEAD_LIMIT_REACHED的连接错误关闭连接。

对于AEAD_AES_128_GCM和AEAD_AES_256_GCM，机密性限制为2 ^ 23个加密数据包；见附录B.1
对于AEAD_CHACHA20_POLY1305，机密性限制大于可能的数据包数量（2 ^ 62），因此可以忽略。
对于AEAD_AES_128_CCM，机密性限制为2 ^ 21.5个加密数据包；见附录B.2。
施加此限制会降低攻击者可以将使用中的AEAD与随机排列区分开的可能性；参见[AEBounds]，[ROBUST]和[GCM-MU]。

除了对发送的数据包进行计数外，终端还必须计算在连接的生命周期内未能通过认证的接收数据包的数量。如果在所有密钥中，如果在连接内，所有密钥的认证失败的接收数据包总数超过了所选AEAD的完整性限制，则终端必须（MUST）以AEAD_LIMIT_REACHED类型的连接错误立即关闭连接，并且不再处理任何其他数据包。

对于AEAD_AES_128_GCM和AEAD_AES_256_GCM，完整性限制为2 ^ 52个无效数据包；见附录B.1。
对于AEAD_CHACHA20_POLY1305，完整性限制为2 ^ 36个无效数据包；参见[AEBounds]。
对于AEAD_AES_128_CCM，完整性限制为2 ^ 21.5个无效数据包；见附录B.2。
施加此限制会降低攻击者成功伪造数据包的可能性；参见[AEBounds]，[ROBUST]和[GCM-MU]。

限制数据包大小的终端可以使用更高的机密性和完整性限制；详情请参见附录B。
未来的分析和规范可能会放宽AEAD的机密性或完整性限制。

任何被定义为QUIC使用的TLS加密套件必须（MUST）定义相关AEAD函数机密性和完整性保护的使用限制。也就是说，必须说明可以认证的包的数量限制和认证失败的包的数量限制。为所有基于哪个值的分析，以及在分析中使用的所有假设，提供一个参考，允许在不同的使用场景下调整限制。

## 6.7. Key Update Error Code

KEY_UPDATE_ERROR错误码（0xe）用来通知跟密钥更新有关的错误。

# 7. Security of Initial Messages

Initial包不受密钥保护，因此它们可能会被攻击者篡改。
QUIC提供了针对无法读取数据包的攻击者的保护，但并不试图提供额外的保护，以防止攻击者可以观察和注入数据包的攻击。 
有些形式的篡改（如修改TLS消息本身）是可以检测到的，但有些形式的篡改（如修改ACK）是检测不到的。

例如，攻击者可以注入一个包含ACK帧的数据包，使其看起来没有收到数据包，或者对连接状态产生错误的印象（例如，通过修改ACK延迟）。
请注意，这样的数据包可能会导致一个合法的数据包作为重复数据包被丢弃。
实现在依赖Initial包中包含的任何数据时应谨慎，这些数据没有经过其他方式的认证。

攻击者还有可能篡改握手包中携带的数据，但由于这种篡改需要修改TLS握手信息，所以这种篡改会导致TLS握手失败。

# 8. QUIC-Specific Adjustments to the TLS Handshake

当与QUIC一起使用时，TLS握手的某些方面是不同的。
QUIC还需要TLS的附加功能。 除了协商加密参数外，TLS握手还携带和验证QUIC传输参数的值。

## 8.1. Protocol Negotiation

QUIC要求加密握手提供认证的协议协商。TLS使用应用层协议协商（[ALPN]）来选择应用协议。除非使用其他机制来商定应用协议，否则终端必须使用ALPN来实现这一目的。

当使用ALPN时，如果没有协商好应用协议，终端必须立即关闭连接（见[QUIC-TRANSPORT]的10.2节），并发出no_application_protocol TLS告警（QUIC错误代码0x178；见4.8节）。虽然[ALPN]只指定服务器使用这个告警，但当ALPN协商失败时，QUIC客户端必须使用错误0x178来终止连接。

应用协议可以限制它可以操作的QUIC版本。服务端必须选择与客户端选择的QUIC版本兼容的应用协议。服务端必须将无法选择兼容的应用协议视为类型为0x178 (no_application_protocol)的连接错误。同样，客户端必须将服务端选择不兼容的应用协议视为类型为0x178的连接错误。

## 8.2. QUIC Transport Parameters Extension

QUIC传输参数在TLS扩展中携带。不同版本的QUIC可能定义了不同的传输配置协商方法。

在TLS握手中包含传输参数，可以为这些值提供完整性保护。

```
      enum {
         quic_transport_parameters(0x39), (65535)
      } ExtensionType;
```

quic_transport_parameters扩展的extension_data字段包含一个由正在使用的QUIC版本定义的值。

在握手过程中，quic_transport_parameters扩展会在ClientHello和EncryptedExtensions消息中携带。
终端必须（MUST）发送 quic_transport_parameters 扩展；
收到 ClientHello 或 EncryptedExtensions 消息而没有 quic_transport_parameters 扩展的终端必须以 0x16d 类型的错误关闭连接（相当于fatal的TLS missing_extension告警，参见第 4.8 节）。

在握手完成之前，可以使用传输参数。服务器可能会在握手完成之前使用这些值。
然而，传输参数的值在握手完成之前不会被验证，所以对这些参数的使用不能依赖于它们的真实性。
任何篡改传输参数的行为都会导致握手失败。

终端不得（MUST NOT）在不使用QUIC的TLS连接中发送该扩展（如使用 [TLS13] 中定义的基于TCP的TLS）。如果在传输层不是QUIC时收到该扩展，支持该扩展的实现必须发送fatal的unsupported_extensiona告警。

协商quic_transport_parameters扩展会导致EndOfEarlyData被移除；参见第8.3节。

## 8.3. Removing the EndOfEarlyData Message

TLS EndOfEarlyData消息不用于QUIC。QUIC并不依赖该消息来标记0-RTT数据的结束，也不依赖该消息来发出改变握手密钥的信号。

客户端不得（MUST NOT）发送EndOfEarlyData消息。
服务端必须（MUST）将0-RTT数据包中收到的CRYPTO帧视为PROTOCOL_VIOLATION类型的连接错误。

因此，EndOfEarlyData不会出现在TLS握手记录中。

## 8.4. Prohibit TLS Middlebox Compatibility Mode

[TLS13]附录的D.4描述了一种通过修改TLS 1.3的握手来作为一些中间设备BUG的应对方法。
TLS 1.3 中间设备兼容性模式，包括了在ClientHello和ServerHello消息中设置32位长的legacy_session_id字段，
然后发送一个change_cipher_spec记录。两个字段和记录都没有携带语义内容，因此被忽略了。

这个模式在QUIC中没有任何作用，因为它只适用于干涉了TLS over TCP的中间设备。
在QUIC中携带change_cipher_spec记录同样是没有意义的。
客户端必须不能（MUST NOT）请求使用TLS 1.3兼容模式。
如果服务端收到带非空legacy_session_id字段的TLS ClientHello消息，应当（SHOULD）将其当做一个PROTOCOL_VIOLATION类型的连接错误。

# 9. Security Considerations

所有适用于TLS的安全注意事项同样适用于TLS在QUIC中的使用。
熟读[TLS13]的所有内容和它的附录是理解QUIC安全属性的最好方法。

这个章节总结了一些特定于TLS集成的更加重要的安全事项，尽管本文余下篇幅中没有很多安全相关的细节。

## 9.1. Session Linkability

TLS session ticket允许了服务端和其他可能的实体来将同一个客户端建立的连接联系起来。

## 9.2. Replay Attacks with 0-RTT

如[TLS13]的第8章所述，TLS early data暴露给了重放攻击。
在QUIC中使用0-RTT同样容易遭受到重放攻击。

终端必须（MUST）实现并使用[TLS13]中描述的重放保护，然而这些保护措施却不是完美的。
因此，需要额外的针对重放攻击风险的注意事项。

QUIC不易受到重放攻击，除非通过它携带的应用协议信息。
[QUIC-TRANSPORT]定义的根据帧类型的QUIC协议状态的管理，不易受到重放影响。
QUIC帧的处理是幂等的，无论帧是重放、乱序还是丢失，都不会导致无效连接状态无效。
QUIC连接产生的效果不会超过连接生命周期，除了那些QUIC服务的应用协议产生的效果。

注意：在连接之间，使用了TLS会话票证和地址校验令牌来携带QUIC配置信息。
特别是，使服务端能够有效地恢复用于连接建立和地址验证的状态。
这些（字段）必须不能（MUST NOT）用于携带应用语义，客户端必须将它们视为不透明的值。
这些令牌有可能被重用，，这意味着它们需要更强的保护措施来防止重放。

相对于没有0-RTT的连接，在一个连接中接受0-RTT的服务端需要付出更多的处理成本。
这包括了更高的处理和消费成本。服务端需要考虑重放攻击的可能性，以及接受0-RTT时相关的成本。

本质上来说，应用协议需要承担管理0-RTT重放攻击的职责。
使用了QUIC的应用协议必须（MUST）描述协议如何使用0-RTT，以及用来保护重放攻击的手段。
重放风险的分析需要考虑所有携带了应用语义的QUIC协议特征。

完全禁用0-RTT是抵御重放攻击的最有效方法。

QUIC扩展必须（MUST）描述重放攻击如何影响它们的运行，否则就禁止这些扩展在0-RTT中的使用。
应用协议必须（MUST）要么禁用在0-RTT携带了应用语义的扩展，要么提供重放缓解策略。

## 9.3. Packet Reflection Attack Mitigation

一个小的ClientHello，导致服务器发出大块的握手消息，可以在数据包反射攻击中被用来放大攻击者产生的流量。

QUIC包括三种针对这种攻击的防御措施。
首先，包含ClientHello的数据包必须被填充到最小大小。
其次，如果响应一个未经验证的源地址，服务器被禁止发送超过它所收到的字节数三倍的数据包（见[QUIC-TRANSPORT]第8.1节）。
最后，由于Handshake包的确认是经过认证的，所以盲目的攻击者无法伪造它们。
这些防御措施加在一起，限制了放大的程度。

## 9.4. Header Protection Analysis

[NAN]分析了提供非隐秘性的认证加密算法，称为"Hide Nonce"（HN）变换。
本文中的常规头保护构造就是其中的一种算法（HN1）。头保护是在数据包保护AEAD之后应用的，从AEAD输出中采样一组字节("sample")，并使用伪随机函数(PRF)对头字段进行加密，具体如下：

```
   protected_field = field XOR PRF(hp_key, sample)
```

本文件中的头保护变体使用伪随机排列(PRP)代替通用PRF。
然而，由于所有PRP也都是PRF[IMC]，这些变体并没有偏离HN1结构。

由于 "hp_key "与数据包保护密钥不同，因此，头保护实现了[NAN]中定义的AE2安全性，并因此保证了 "field"（受保护的头）的隐私。未来基于这种结构的头保护变体必须使用PRF来确保同等的安全保证。

多次使用相同的密钥和密文样本有可能危及头保护。 用相同的密钥和密文样本保护两个不同的头，会暴露出被保护字段的异或。 假设AEAD作为PRF，如果对L个比特进行采样，则两个密文样本相同的几率接近2^(-L/2)，即生日边界。 对于本文所描述的算法，该概率为1/2^64。

为了防止攻击者修改数据包头，使用数据包保护对数据包头进行转接认证；整个数据包头是认证附加数据的一部分。 受保护的字段如果被伪造或修改，只有在数据包保护被删除后才能被检测到。

## 9.5. Header Protection Timing Side-Channels

攻击者可以猜测包号或密钥相位的值，并让终端通过定时侧通道确认猜测。类似地，可以尝试并公开对数据包编号长度的猜测。如果数据包的接收者在不尝试删除数据包保护的情况下丢弃了具有重复数据包编号的数据包，他们可以通过定时侧信道揭示数据包号与接收的数据包相匹配。 为了使认证不受侧信道的影响，头保护删除、包号恢复和包保护删除的整个过程必须在没有定时测和其他侧信道的情况下一起应用。

对于数据包的发送，数据包有效载荷和数据包号的构造和保护必须不受侧信道的影响，因为侧信道会泄露数据包号或其编码大小。

密钥交换期间，用于生成新密钥的时间可能通过定时侧通道泄露正在更新密钥的信息。
也就是说，攻击者可以在这个侧通道注入包，并通过这些注入的包暴露Key Phase的值。
在接收到密钥更新之后，终端应当（SHOULD）保证并保存下一套收包保护密钥。

通过在密钥更新之前生成新的密钥，收到包之后不会创建泄露Key Phase值的定时信号。

这依赖于在包处理期间不生成密钥，且要求终端维护三套用于接收的包保护密钥：
之前密钥相位、当前密钥相位、后续密钥相位。
此外终端可以选择延迟生成下一套包保护密钥，直到他们丢弃旧的密钥，这样任何终端在任何时候，都只需要维护两套用于接收的密钥。

## 9.6. Key Diversity

在使用TLS时，使用的是TLS的中心密钥表。
由于TLS的握手信息被集成到secret的计算中，因此QUIC传输参数扩展的加入可确保握手和1-RTT密钥与运行基于TCP的TLS的服务端可能产生的握手和1-RTT密钥不同。
为了避免跨协议密钥同步的可能性，提供了额外的措施来提高密钥分离度。

QUIC数据包保护密钥和IV是使用与TLS中的等效密钥不同的标签得出的。

为了保持这种分离，新版本的QUIC应该（SHOULD）定义新的标签，用于数据包保护密钥和IV的密钥推导，加上头保护密钥。这个版本的QUIC使用的是字符串"quic"，其他版本可以使用特定版本的标签来代替该字符串。

initial secret使用协商好的QUIC版本特有的密钥。 新的QUIC版本应该定义一个新的salt值，用于计算initial secret。

## 9.7. Randomness

QUIC依赖于终端能够生成安全随机数，既可以直接生成协议值（如连接ID），也可以通过TLS传递。
参见[RFC4086]，了解安全随机数生成的指导。
