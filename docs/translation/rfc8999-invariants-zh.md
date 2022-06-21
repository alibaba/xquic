# 1. An Extremely Abstract Description of QUIC

QUIC是两个终端之间面向连接的协议。这些终端交换包含QUIC数据包的UDP数据报。
QUIC终端使用QUIC数据包来建立QUIC连接，这是这些终端之间共享的协议状态。

# 2. Fixed Properties of All QUIC Versions

除了提供安全、多路复用传输，QUIC [[QUIC-TRANSPORT](https://tools.ietf.org/html/draft-ietf-quic-invariants-13#ref-QUIC-TRANSPORT)] 还允许选择协商版本，这使得协议可以随着新需求而变化。在不同版本之间，协议的很多特性都会改变。

本文描述了QUIC中那些不会随着新版本开发部署而改变的子集。所有这些不变量都与IP版本无关。

保证新版本QUIC部署的可能性是该文档的主要目标。本文通过记录那些不会改变的特性，来预留改变协议中其他所有特性的能力。因此，这也保证了向终端以外的实体提供的信息量最小。除非本文档中特别禁止，否则协议的任何方面都可以在不同版本之间进行更改。

附录A是一些错误假设的不完全列表，这些假设可能在QUIC第一版的基础上提出的，且不适用于所有QUIC版本。

# 3. Conventions and Definitions

本文中的关键词"MUST"，"MUST NOT"，"REQUIRED"，"SHALL"，"SHALL NOT"，"SHOULD"，"SHOULD NOT"，"RECOMMENDED"，"NOT RECOMMENDED"，"MAY"，以及"OPTIONAL"，只有当他们全部以大写字母出现的时候，需要按 BCP 14[RFC2119][RFC8174]所述的方式进行理解。

本文档定义了对未来QUIC版本的要求，即使是在没有使用规范语言的情况下。

# 4. Notational Conventions

数据包的格式使用本节中定义的符号来描述。 这个符号与[QUIC-TRANSPORT]中使用的符号相同。

定义复合字段时，首先命名它们，接着在一堆括号中列举了字段表。这个列表中的字段以逗号隔开。

描述单个字段时，包括了长度信息，以及固定值、可选性、重复的标记。单个字段使用了一下符号约定，长度以位计算：

x (A)：表示x长度是A位

x (A.. B)：表示x是一个介于A和B之间的长度；如果没有A，则表示最小是0位；如果没有B，则表示没有设置上限；这个格式的值往往以十进制边界结束。

x (L) = C：表示长度由L描述的x，其定值为C。

x (L)...：表示x是多个重复0（且每次重复的长度为L）。

本文中的值都是网络字节序的（big endian）。所有字段都从字节的最高位开始。

图1展示了一个示例结构：

```
   Example Structure {
     One-bit Field (1),
     7-bit Field with Fixed Value (7) = 61,
     Arbitrary-Length Field (..),
     Variable-Length Field (8..24),
     Repeated Field (8) ...,
   }

                          Figure 1: Example Format
```

# 5. QUIC Packets

QUIC终端之间互相交换包含一个或多个QUIC数据包的UDP数据报。 本节描述了QUIC数据包的不变特性。QUIC的一个版本可以允许在一个UDP数据报中包含多个QUIC数据包，但不变性特性只描述数据报中的第一个数据包。

QUIC定义了两种包头：长包头和短包头（long header and short header）。如果一个UDP包的第一个字节的第一位是1，那么它就是long header，否则就是short header。（long header的第一个字节是二进制 1XXX，而short header是二进制 0XXX ）。

QUIC数据包（包括报头）可能是受完整性保护的，但QUIC版本协商包不受完整性保护（见第6节）。

除了这里定义的值，QUIC数据包的载荷是版本特定的，且长度随意。

## 5.1. Long Header

long header的格式如下所示：

```
   Long Header Packet {
     Header Form (1) = 1,
     Version-Specific Bits (7),
     Version (32),
     Destination Connection ID Length (8),
     Destination Connection ID (0..2040),
     Source Connection ID Length (8),
     Source Connection ID (0..2040),
     Version-Specific Data (..),
   }

                         Figure 2: QUIC Long Header
```

一个带long header的QUIC包中，第一个字节的最高位是1，这个字节中剩下的比特位都是版本特定的。

接下来的4个字节是一个32位长度的版本字段（版本说明见第5.4节）。

接下来的一个字节是表示目标连接ID的字节长度，是一个8位unsigned int。DCID Len后的DCID长度在0~255字节之间（连接ID在5.3节中描述）。

接下来的字节包含了源连接ID的字节长度，是一个8位unsigned int。SCID Len后的SCID长度在0~255字节之间。

包剩余部分是版本特定的内容。

## 5.2. Short Header

short header的格式如下所示：

```
   Short Header Packet {
     Header Form (1) = 0,
     Version-Specific Bits (7),
     Destination Connection ID (..),
     Version-Specific Data (..),
   }

                        Figure 3: QUIC Short Header
```

一个带short header的QUIC包中，第一个字节的最高位是0。
short header包第一个字节之后，是目标连接ID。short header中没有connection ID的长度、SCID、版本号。short header包中没有DCID的长度，但不一定完全没有。

包剩余部分包含了版本特定的语义。

## 5.3. 连接ID（Connection ID）

连接ID是一个有任意长度的不透明字段。

连接ID的主要功能是保证底层协议地址发生改变时，一个QUIC连接的数据还能够被送到正确的终端。终端们使用了连接ID，然后中间设备保证了QUIC包被传到正确的终端。在终端上，则使用了连接ID来识别数据包所属的QUIC连接。

终端使用了版本特定的方法来选择连接ID。同一个QUIC连接中的不同包可能使用不同的连接ID值。

## 5.4. 版本

版本字段包含一个4字节的标识符， 此值可被终端用于识别QUIC版本。
值为0x00000000的版本字段为版本协商保留（请参见第6节），所有其他数值都可能有效。

本文中的特性适用于所有QUIC版本。**不符合本文规约的协议 IS NO QUIC! **未来的文档可能增加更多特性的描述，这些特性可能适用于某个特定版本的QUIC，或者一系列QUIC版本。

# 6. 版本协商（version negotiation）

如果一个终端收到一个长头包（packet with long header），但是无法理解或者不支持头部中的version，可能发送一个版本协商包（version negotiation packet）进行答复。短头包不会触发版本协商（packet with short header）。

版本协商包将第一个字节的最高位置为1，从而遵从了5.1节中定义的长头包的格式。如果一个长头包的Version字段值是0x00000000，那么就判定这个长头包为版本协商包。

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

                    Figure 4: Version Negotiation Packet
```

版本协商数据包的第一个字节中只有最高有效位具有定义的值。 剩余的7位（未使用）可以在发送时设置为任何值，并且在接收时必须忽略。

在 Source Connection ID 字段之后，Version Negotiation 数据包包含一个 Supported Version 字段列表，每个字段都标识了发送数据包的终端所支持的版本。版本协商数据包不包含其他字段。终端必须（MUST）忽略不包含Supported Version字段或截断Supported Version字段的数据包。

版本协商包没有完整性和加密保护。特定的QUIC版本可能包括允许终端在支持的版本集中检测修改或损坏的协议元素。

收到包之后，一个终端必须（MUST）将这个包包中的DCID作为（自己将要发送包的）SCID。SCID必须（MUST）拷贝自收到的包的DCID，这是一个客户端随机选择的。对换两个链接ID保证了服务端可以收到客户端的包，并且版本协商包不是由无法观察数据包的攻击者产生的。

进行版本协商之后，一个终端可能想要改变它后续包的版本。终端改变QUIC版本的时机依赖于它选择的QUIC版本。

支持QUIC版本1的终端如何进行版本协商的问题，在[[QUIC-TRANSPORT](https://tools.ietf.org/html/draft-ietf-quic-invariants-13#ref-QUIC-TRANSPORT)]中有更加详尽的阐述。

# 7. Security and Privacy Considerations

网络链路上的中间设备有可能观察到一个特定版本的QUIC的特性，然后假设其他版本的QUIC有类似的特性，那么就有可能出现它们表达了相同底层语义的情况。可能这样的特性还挺多。在QUIC版本1中，做了一些终止或者掩盖这些特性的工作，但还是遗留了很多这样的难问题。另外的QUIC版本可能使用不同的设计思路，从而来解决不同版本间特性-语义的问题。

不是所有的QUIC包都有QUIC版本号，这意味着，如果要正确地根据版本特性来提取信息，需要中间设备保留每个经由它们的连接的状态。

本文中描述的版本协商包不具备完整性保护；它只有最低的防止异常路径攻击的功能。
终端如果尝试不同的QUIC版本，则必须认证版本协商包的语义内容。
