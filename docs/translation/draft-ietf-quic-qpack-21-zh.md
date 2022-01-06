# 1. Introduction

由于QUIC把HTTP2的stream等概念下沉到了传输层，如果在HTTP/3里面使用HPACK，将仍然会导致队头阻塞问题，因为实际上HPACK前提是要求所有stream中的frame按照一个整体顺序排列。

QPACK复用了HPACK的一些理念，但是被设计为能够正确处理乱序到达的情况，同时实现中能够平衡[可靠性、减少队头阻塞和提升压缩效率]。设计目标是为了能够非常接近HPACK的压缩比例，在相同丢包率的场景下尽量减少队头阻塞。

## 1.1. Conventions and Definitions

HTTP字段：以HTTP消息部分发送的元数据。这个术语包括了头部和尾部字段。术语“头部”经常口头上指HTTP头部字段和尾部字段；本文笼统地使用“字段”这个术语。

HTTP字段行：一个名称-值对，并以HTTP字段区的部分而发送，参考[SEMANTICS]第6.3节和6.5节。

HTTP字段值：和字段名称有关的数据，由包含那个区域中那个字段名的所有字段行的值串联组成，并以逗号隔开。

字段区：与HTTP消息有关的HTTP字段行的有序集合。一个字段区可以包含多个相同名称的字段行。它同样可以包含冗余的字段行。
一个HTTP消息可以包含头部字段和尾部字段区。

表示：一个代表了字段行的指令，可能引用了动态和静态表。

编码器：编码字段区的实现。

解码器：解码被编码的字段区的实现。

绝对索引：动态表中每个实体的独一无二的索引。

基：相对指数和基准后指数的参考点。引用动态表项相对于基的表示。

插入数：动态表中插入的入口总数。

## 1.2. Notational Conventions

| 表达式 | 说明 |
| --- | --- |
| x (A) | 表示x是A bit长度 |
| x (A+) | 表示x使用前缀整型编码方式，前缀初始长度A-bit，编码格式参考4.1.1小节 |
| x ... | 表示x是变长长度的，并且延伸到当前区域结束位置 |

# 2. Compression Process Overview

类似HPACK，QPACK使用两张表来关联下标和header内容。
静态表（3.1节）是被预先定义好的，并且包含了公共的header内容（其中一些value值为空，只有name）。
动态表（3.2节）是在连接处理过程中被构建出来的，并且用来给encoder提供索引header内容的功能。

## 2.1. Encoder

encoder将一个头部或尾部字段区，最后压缩成一系列的表示，以索引或字符表示的方式发送。
静态表的引用和文本表示不需要任何动态表支持，并且永远不会有队头阻塞问题。
动态表的引用有队头阻塞的风险，在encoder还没有收到表示当前条目对于decoder已经可用的ack之前，可能有队头阻塞问题。

encoder可能会插入它选择的任意条目到动态表里面；范围不限于当前它在压缩的header内容。

QPACK保留了每个字段区中字段行的有序性。encoder必须（MUST）以输入的字段表示在输入字段区的顺序来发送field representations。

QPACK被设计为encoder包含更复杂的状态追踪，同时decoder实现会相对简单。

### 2.1.1. Limits on Dynamic Table Insertions

如果动态表包含了不能移出的条目，那么可能不能够将条目插入到动态表。

在动态表插入一个条目后，不能立刻移出这个条目，即使它从未没引用过。
一旦确认了动态表条目的插入，并且未确认的表示中也没有这个条目未完成的引用，就可以移出该条目。
值得注意的是，encoder stream上的引用不会影响一个条目的移出，因为保证了在指令弹出条目前，完成那些引用的处理。

如果动态表没有足够空间来插入新的条目（除非移出其他条目），并且还没有可以移出的条目，
encoder必须不能（MUST NOT）将新的条目插入到动态表（包括现有条目的拷贝）。
为了避免这种情况，使用动态表的encoder必须跟踪每个被字段区引用的动态表条目，直到这些表示被decoder确认；（参考4.4.1小节）。

#### 2.1.1.1. Avoiding Prohibited Insertions

为了保证encoder没有在新增条目的时候被阻塞住，encoder可以避免引用临近被淘汰的条目。如果需要引用类似的条目，encoder可以发送一个Duplicate指令（见4.3.3节），并引用复制后的条目。

决定哪些条目临近被淘汰，由encoder的偏好来选择。
一种启发性的方案是，在动态表中标记一段固定可用空间：还没有使用的空间、或通过逐出非阻塞的条目可以回收的空间。为了达到这个目的，encoder可以维护一个排空下标（draining index），这个下标是动态表中会被发送引用的最小绝对值下标。在新的条目被插入时，encoder增加排空下标，来维护动态表中没有被引用的区间。如果encoder不创建新的、对编号绝对值小于排空下标的条目引用，对这些条目进行引用（还未收到ack）的数目最终会变为0，允许这些条目被逐出。

```
                <-- Newer Entries          Older Entries -->
                  (Larger Indicies)      (Smaller Indicies)
      +--------+---------------------------------+----------+
      | Unused |          Referenceable          | Draining |
      | Space  |             Entries             | Entries  |
      +--------+---------------------------------+----------+
               ^                                 ^          ^
               |                                 |          |
         Insertion Point                 Draining Index  Dropping
                                                          Point

                  Figure 1: Draining Dynamic Table Entries
```

### 2.1.2. Blocked Streams

因为QUIC不保证不同stream之间数据的顺序到达，decoder可能会遇到引用了一个动态表中还没有收到的条目的表示。

每个被编码的字段区包含了一个需求插入计数（Required Insert Count），这个需求插入计数表示：当前字段区可以被解码的插入计数最小可能值。
对于使用对动态表的引用进行编码的字段区，插入计数是所有引用的动态表条目中的最大绝对索引再加1。
对于一个没有引用动态表的字段区来说，这个值是0.

当decoder收到一个被编码的字段区，需求插入计数超过其当前动态表收到的条目数量，stream不能立刻被处理，就进入”blocked”状态（见2.2.1小节）。decoder使用参数SETTINGS_QPACK_BLOCKED_STREAMS设置可被阻塞的stream的数量上限（见第5章）。encoder必须（MUST）在任何时候都将可能被阻塞的stream的数量限制在其所承诺的参数SETTINGS_QPACK_BLOCKED_STREAMS的范围之内。如果decoder遇到的阻塞的stream的数量超过了它承诺支持的数量，它必须（MUST）将其视为QPACK_DECOMPRESSION_FAILED类型的连接错误。

请注意，decoder在可能出现阻塞的stream上，并不一定真的会被阻塞。

encoder可以决定是否冒险使得一条stream被阻塞住。
如果SETTINGS_QPACK_BLOCKED_STREAMS参数允许，压缩效率可以通过引用还在传输路上的动态表条目来提升，但如果出现丢包或重排，这个stream就可能被阻塞住。
encoder通过只引用动态表中被ack的条目，来避免阻塞的风险，但是这可能导致更多的文本被发送。由于本文会使得头部编码块变大，这可能会导致encoder被阻塞在拥塞控制或流控限制上。

### 2.1.3. Avoiding Flow Control Deadlocks

流上受流控制限制的写指令可以产生死锁。

decoder可以停止分配 传输了被编码的字段区的stream 上的流控信用，直到在encoder流上收到必要的更新。
如果encoder stream上（或者整个连接）授予的流控信用依赖（传输了被编码的字段区的stream 上的数据的消费和释放，就可能导致死锁。
（一方面接收者在等更新，另一方面发送者因为流控而无法发数据）

说的更通俗点，如果decoder在指令完全收完之前抑制了流控信用，包含了大量指令的流可能发生死锁。

为了避免这些死锁，除非有足够容纳整个指令的流和连接流控信用，否则encoder不应当（SHOULD NOT）写指令。

### 2.1.4. Known Received Count

Known Received Count是指被decoder确认的动态表插入和拷贝条目的总数。
encoder追踪Known Received Count来识别哪个动态表条目可以被引用且又不会阻塞stream。
decoder追踪Known Received Count来发送Insert Count Increment （插入数量增量）指令。

Section Acknowledgement指令表示了decoder收到了所有 必需的用于解码字段区的 动态表状态。
如果已确认的字段区的Required Insert Count比当前Known Received Count要大，Known Received Count更新为Required Insert Count的值。

Insert Count Increment指令通过它的Increment参数增加了Known Received Count。

## 2.2. Decoder

在HPACK中，decoder处理了一系列的表示，并发送了相关的字段区。它同样处理了在编码流上收到的指令。
值得注意的是，被编码的字段区和encoder stream指令通过不同的流进行传输。这跟HPACK不一样，在HPACK中，被编码的字段区（头部区块）可以包含修改动态表的指令，并且没有专门用于HPACK指令传输的流。

decoder必须（MUST）以被编码的字段区中字段行表示的顺序来发射字段行。

### 2.2.1. Blocked Decoding

在收到编码后字段区之后，decoder就会检查Required Insert Count。
当Required Insert Count小于等于decoder的插入数，字段区可以立即被处理。
否则，收到字段区的流就会被阻塞。

被阻塞的同时，被编码的字段区数据应当（SHOULD）保留在被阻塞的流的流控窗口中。
这些数据在流疏通之前是无法使用的，过早地释放流控会使decoder易遭受内存耗尽攻击。
当所有 decoder开始从流中读取的 被编码的字段区的插入数（Insert Count）大于等于要求插入数（Required Insert Count）的时候，流就再次疏通了。

当处理编码字段区的时候，decoder期望要求插入数（Required Insert Count）和可以解码的插入数（Insert Count）的可能最小值相等（详见2.1.2小节）。
如果decoder碰到了要求插入数（Required Insert Count）比期望值大的情况，它可以（MAY）将这种情况当做是QPACK_DECOMPRESSION_FAILED类型的连接错误。

### 2.2.2. State Synchronization

decoder通过在decoder stream上发送decoder指令，来通知以下事件。

#### 2.2.2.1. Completed Processing of a Field Section

在decoder完成（使用了 包含动态表引用的表示的）字段区的解码之后，它必须（MUST）发送一个Section acknowledgement指令（第4.4.1小节）。
流可以在中间响应、尾部、以及推送请求中，携带多个字段区。
encoder将Section Acknowledgement指令理解成（在指定流上发送的）（最早未确认的）（且包含动态表引用的）字段区的确认。

#### 2.2.2.2. Abandonment of a Stream

如果在流结束之前，或者这条流上所有编码字段区处理完成之前，或者它终止了流的读取的时候，终端收到了流重置，它就会产生一个Stream Cancellation指令（流取消）。
最大动态表容量为0的decoder可以（MAY）不发送Stream Cancellation，因为encoder不会持有任何动态表引用。
encoder不能从这个指令推断收到了所有动态表的更新。

Section Acknowledgement 和 Stream Cancellation 指令允许encoder移除动态表中条目的引用。
当一个绝对索引比Known Received Count小的条目不再有任何引用，那么它就是可以移除的。

#### 2.2.2.3 New Table Entries

从encoder stream上接收到新的条目之后，decoder决定了发送Insert Count Increment指令的时机；
在将每一条新的条目插入到动态表之后再发送这个指令是最及时的反馈。如果Insert Count Increment指令被延迟了，decoder可能可以合并多个Insert Count Increment指令，或者以Section Acknowledgments来完全替换掉这个指令；但是，如果延迟太久的话，并且encoder需要某一个条目被确认的信息来使用它，那么就可能导致解压缩效率偏低。

### 2.2.3. Invalid References

如果在字段行表示中，decoder碰到一个引用，且这个引用指向已经被移出、或者绝对索引大于等于要求插入数（Required Insert Count，4.5.1小节）的动态表条目, 
必须将这种情况当成是QPACK_DECOMPRESSION_FAILED类型的连接错误。

如果encoder指令中，decoder碰到一个引用，且这个引用指向已经被移出的动态表条目的情况，
必须将这种情况当成是QPACK_ENCODER_STREAM_ERROR类型的连接错误。

# 3. Header Tables

和HPACK不一样的是，QPACK静态表中的条目和动态表的条目是分开寻址的。
以下章节描述了静态和动态表中条目的寻址方式。

## 3.1. Static Table

静态表由一个预先定义好的静态field lines列表组成，每个条目有一个固定不变的下标。条目定义见附录.

静态表中的所有条目都有一个名称和一个值。但是，值可以是空的（也就是说，值的长度为0）。
条目通过唯一索引进行区分。

注意到QPACK静态表从0下标起始，对比HPACK静态表下标从1开始。

当decoder在一个 line representation中，遇到一个非法的静态表下标索引，它必须（MUST）处理这种情况为stream错误，错误类型“QPACK_DECOMPRESSION_FAILED”。如果这个下标在encoder stream中被接收到，这种情况必须被处理为连接错误”QPACK_ENCODER_STREAM_ERROR”.

## 3.2. Dynamic Table

动态表由一个先进先出顺序的头部列表组成。encoder和decoder共享一个动态表，这个表初始是空的。
encoder将条目添加到动态表，并将条目由encoder stream中的指令发送到decoder。（见4.3节）

动态表可以包含重复的条目（即name和value完全相同的条目）。因此，重复的条目不能（MUST NOT）被decoder处理为错误。

动态表条目的值可以是空的

### 3.2.1. Dynamic Table Size

动态表的大小，是它包含的所有条目长度之和。

```
每个条目的size = name字节长度 + value字节长度 + 32
```

条目长度的计算是用头部name和value未被Huffman编码之前的长度来算的。

### 3.2.2. Dynamic Table Capacity and Eviction

encoder设置动态表的容量大小，这个值为动态表的上限大小。encoder设置了动态表的容量，也就是动态表尺寸的上限。动态表的初始容量是0。encoder发送了非0容量的Set Dynamic Table Capacity（设置动态表容量）指令之后，开始使用动态表。

在一个新的条目被加入到动态表中时，动态表尾部的条目被淘汰出去，直到动态表已使用的空间长度 小于等于 (动态表容量 - 新的条目长度)，或者直到动态表为空。encoder不能（MUST NOT）在条目被decoder ack之前，逐出对应的动态表条目。

如果新条目的大小 小于等于 动态表的容量上限，那么这个条目可以被加入到表中。
如果encoder尝试添加一个超过动态表容量上限的条目，则会出现错误；decoder必须（MUST）处理这种情况为连接错误“QPACK_ENCODER_STREAM_ERROR”。

新条目可以引用一个动态表已有的即将被逐出的条目，如果需要将这个条目重新加回动态表中的话。实现中需要注意避免删除被引用的name/value，如果被引用的条目在被重新添加进来之前、就已经被逐出了动态表。

当动态表容量被encoder调整变小时，条目被从动态表的尾部逐出，直到动态表的大小小于等于新的动态表容量。在动态表大小被设0时，这个机制可以被用来完全清空动态表，同时后续也可以再恢复起来。

### 3.2.3. Maximum Dynamic Table Capacity

为了限制decoder需要使用的内存大小，decoder可以限制encoder能够使用的动态表容量最大值。
在HTTP/3中，这个限制由decoder发送的SETTINGS_QPACK_MAX_TABLE_CAPACITY来决定（第5节）。encoder必须（MUST）不能设置一个超过该最大值的动态表大小，但它可以选择一个小于该值的动态表容量。（见4.3.1节）

HTTP/3中使用0-RTT的客户端，服务端的最大表容量是配置保存的值。如果之前没有设置，这个值就是0。
如果客户端SETTING中的0-RTT值是0，服务端可以（MAY）发送一个带非0值的SETTINGS帧。
如果保存的值非0，服务端的SETTINGS帧中的值必须（MUST）相同。
如果服务端定义了其他值，或者从SETTINGS帧中删除了SETTINGS_QPACK_MAX_TABLE_CAPACITY，encoder就必须（MUST）把这种情况当成是QPACK_DECODER_STREAM_ERROR类型的连接错误。

对于不用或者拒绝0-RTT的HTTP/3服务端和客户端，初始的最大表容量是0，encoder处理一个SETTINGS_QPACK_MAX_TABLE_CAPACITY值非0的SETTINGS帧之后变为非0值。

当最大表容量为0的时候，encoder必须不能（MUST NOT）在动态表中插入条目，且必须不能（MUST NOT）在encoder stream上发送任何encoder指令。

### 3.2.4. Absolute Indexing

每个条目同时拥有一个绝对下标（在条目的生命周期中是固定的）。第一个插入的条目绝对下标为0，随着每次插入下标递增。

### 3.2.5. Relative Indexing

相对下标从0开始，并以绝对下标相反的方向增长。
引用的上下文内容决定哪个条目有0的相对下标。

在encoder stream当中，相对下标为“0”永远表示最新被插入动态表的值。
注意到这意味着被相对下标引用的条目，会在encoder stream收到新指令时发生变化。

```
         +-----+---------------+-------+
         | n-1 |      ...      |   d   |  Absolute Index
         + - - +---------------+ - - - +
         |  0  |      ...      | n-d-1 |  Relative Index
         +-----+---------------+-------+
         ^                             |
         |                             V
   Insertion Point               Dropping Point

   n = count of entries inserted
   d = count of entries dropped

         Figure 2: Example Dynamic Table Indexing - Encoder Stream
```

和在encoder 指令不一样的是，field line representations中相对下标是基于encoded field section起始位置作为基准的（见4.5.1）。这保证了引用是固定的，即使动态表在对被编码的字段区进行解码的过程中被更新了。

在field line representation中，一个值为0的相对索引指向了绝对索引为Base -1 的条目。

```
                  Base
                   |
                   V
       +-----+-----+-----+-----+-------+
       | n-1 | n-2 | n-3 | ... |   d   |  Absolute Index
       +-----+-----+  -  +-----+   -   +
                   |  0  | ... | n-d-3 |  Relative Index
                   +-----+-----+-------+

   n = count of entries inserted
   d = count of entries dropped
   In this example, Base = n - 2

        Figure 3: Example Dynamic Table Indexing - Relative Index in
                               Representation
```

### 3.2.6. Post-Base Indexing

当字段行表示引用那些绝对索引大于等于Base的条目时，可以使用基后索引，从base的位置开始，索引值为0，并和绝对索引增长方向一致。
基后索引允许encoder以一种简单方式处理header block，并且允许引用在处理当前头部压缩块过程中添加的条目。新增条目通过使用Post-Base指令来引用。

Post-Base指令使用的下标和绝对下标增长的方向相同，0表示第一个在Base之后插入的条目。

```
                  Base
                   |
                   V
       +-----+-----+-----+-----+-----+
       | n-1 | n-2 | n-3 | ... |  d  |  Absolute Index
       +-----+-----+-----+-----+-----+
       |  1  |  0  |                    Post-Base Index
       +-----+-----+

   n = count of entries inserted
   d = count of entries dropped
   In this example, Base = n - 2

       Figure 4: Example Dynamic Table Indexing - Post-Base Index in
                               Representation
```

# 4. Wire Format

## 4.1. Primitives

本节描述基础元素。

### 4.1.1. Prefixed Integers

前缀整数编码见[RFC7541 5.1节](https://tools.ietf.org/html/rfc7541#section-5.1)，这种编码格式在本文中被大量使用。编码沿用了RFC7541的格式未变。注意，QPACK使用了一些HPACK中没有用到的前缀大小。

QPACK实现必须（MUST）能够正常解码62-bit及以内长度的整数。

### 4.1.2. String Literals

字符串文本表达形式见[RFC7541 5.2节](https://tools.ietf.org/html/rfc7541#section-5.2)。这种字符串格式包含了可选的Huffman编码。

HPACK定义字符串文本从字节的边界作为起始位置。它们从一个单独的flag起始，本文中以'H'标记，（表示当前字符串是否是Huffman编码），后续紧跟7-bit前缀编码整数作为长度(Length)，最后是Length长度表示的字节内容。如果Huffman编码被使用，Huffman编码表（[RFC7541 附录B](https://tools.ietf.org/html/rfc7541#appendix-B)）被无修改沿用，Length表示编码后字符串的大小。

本文扩展了字符串文本定义，并且允许它们从非字节边缘位置起始。
“N-bit前缀字符串”从字节中间起始，第一个（8-N）位分配给前一个字段。 
字符串使用1个bit作为Huffman标志，紧跟着的长度字段为(N-1)-bit前缀整数编码；
前缀大小，N，是一个[2, 8]之间的值。剩余部分为字符串文本内容，保持不变。

一个字符串文本字段，如果没有前缀长度表示，则默认是8-bit前缀字符串文本，并且遵循[RFC7541](https://tools.ietf.org/html/rfc7541)的定义，不做修改。

## 4.2. Encoder and Decoder Streams

QPACK明确说明两种单向流类型：

* 编码流：流类型0x02，它从encoder将encoder指令以非帧序列的形式传给decoder。
* 解码流：流类型0x03，它从decoder将decoder指令以非帧序列的形式传给encoder。

HTTP/3终端包含了一个QPACKencoder和decoder。每个终端必须（MUST）创建至多一个encoder stream和至多一个decoder stream。
无论在哪个流类型中，如果收到第二个实例，必须（MUST）被当成是H3_STREAM_CREATION_ERROR类型的连接错误。
必须不能（MUST NOT）关闭这些流。任意一个双向流类型被关闭，必须（MUST）被当成H3_CLOSED_CRITICAL_STREAM类型的连接错误。
如果终端不需要使用encoder stream（比如encoder不想用动态表，或者对端允许的动态表最大尺寸是0），终端可以（MAY）不创建encoder stream。
如果终端的decoder将动态表的最大容量设置为0，终端可以（MAY）不创建decoder stream。
即使连接配置不允许使用encoder stream和decoder stream，终端也必须（MUST）允许对端创建这两个流。

## 4.3. Encoder Instructions

encoder在encoder stream上发送编码指令，来设置动态表的容量，并添加动态表条目。
添加新条目的指令，可以使用已有的条目来避免重传重复内容。
name可能被传输为一个静态表中的引用、或一个动态表的引用、或字符串文本。
对于那些已经在动态表中存在的条目，完整条目内容可以通过引用来使用，创建一个重复的条目。

### 4.3.1. Set Dynamic Table Capacity

encoder使用以 "001" 3-bit开头的指令通知decoder动态表容量的变化，随后用5-bit前缀整数表示的新动态表容量（见4.4.1节）。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 0 | 0 | 1 |   Capacity (5+)   |
   +---+---+---+-------------------+

                    Figure 5: Set Dynamic Table Capacity
```

新的容量必须（MUST）小于等于3.2.3小节定义的限制。在HTTP/3中，这个限制是从decoder收到的SETTINGS_QPACK_MAX_TABLE_CAPACITY参数（第5章）。
decoder必须（MUST）把超过SETTINGS_QPACK_MAX_TABLE_CAPACITY参数限制的动态表值当成是QPACK_ENCODER_STREAM_ERROR类型的连接错误。

减少动态表的容量会导致条目被移出（参见3.2.2节），必须不能（MUST NOT）导致不可移出的条目被移出（参见第2.1.1节）。
改变动态表的容量是不被确认的，因为该指令不插入条目。

### 4.3.2. Insert With Name Reference

encoder通过一个以值为"1"的一位模式开始的指令，将条目加到动态表和静态表中字段名和条目字段名匹配的地方。
“T” bit表示这个引用是对静态表（T=1）或者对动态表（T=0）。
6-bit前缀整数紧跟其后，被用来定位这个header name对应的条目位置。当T=1时，这个值表示静态表的下标；当T=0时，这个值表示动态表中的相对下标。

field name引用后面紧跟着field value内容，由字符串文本格式表示。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 1 | T |    Name Index (6+)    |
      +---+---+-----------------------+
      | H |     Value Length (7+)     |
      +---+---------------------------+
      |  Value String (Length bytes)  |
      +-------------------------------+

                Figure 6: Insert Field Line -- Indexed Name
```

### 4.3.3. Insert With Literal Name

如果插入的条目field name和field value都由字符串文本（4.1节）表示，起始两个bit为’01’.
name由6-bit前缀字符串文本格式表示，value由8-bit前缀字符串文本表示。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 0 | 1 | H | Name Length (5+)  |
      +---+---+---+-------------------+
      |  Name String (Length bytes)   |
      +---+---------------------------+
      | H |     Value Length (7+)     |
      +---+---------------------------+
      |  Value String (Length bytes)  |
      +-------------------------------+

                  Figure 7: Insert Field Line -- New Name
```

### 4.3.4. Duplicate

重复插入一个动态表中已经存在条目的指令，起始3个bit为’000’。已存在条目的相对下标由一个5-bit前缀整数表示。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 0 | 0 | 0 |    Index (5+)     |
      +---+---+---+-------------------+

                            Figure 8: Duplicate
```

指令把已经存在的条目重新插入动态表，不用额外传输name/value内容。
这对于即将被逐出的较老的条目，如果被频繁引用的情况下，既可以避免引用条目的内容解析被阻塞，又可以减少重新传输条目内容的成本。

## 4.4. Decoder Instructions

decoder在decoder stream上发送decoder指令来讲字段区和表更新的信息通知给encoder，从而来保证动态表的连续性。

### 4.4.1. Section Acknowledgement

在处理完一个字段区编码块，如果这个压缩块宣告的Required Insert Count不是0，decoder会在decoder stream上发送一个Section Acknowledgement指令。这个指令由一个bit ‘1’位起始，包含了对应的请求stream的stream ID，由一个7-bit前缀整型编码。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 1 |      Stream ID (7+)       |
   +---+---------------------------+

                      Figure 9: Section Acknowledgment
```

如果encoder收到了一个Section Acknowledgement 指令，但是对应的流上每个Required Insert Count非0的字段区压缩块已经被确认，这必须被当成是QPACK_DECODER_STREAM_ERROR类型的连接错误。

Section Acknowledgement指令可能增加Known Received Count；参考2.1.4小节。

### 4.4.2. Stream Cancellation

当流被重置或终止读取，decoder发送一个Stream Cancellation指令。
这条指令从两个bit ’01’起始。后跟一个6位前缀整数形式的stream ID.

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 0 | 1 |     Stream ID (6+)    |
   +---+---+-----------------------+

                       Figure 10: Stream Cancellation
```

### 4.4.3. Insert Count Increment

Insert Count Increment指令由2个bit’00’起始。后跟一个由6-bit前缀整数编码组成的Increment字段。
这个指令表明动态表插入/拷贝条目的总数，从上一次Insert Count Increment / Header Acknowledgement到现在，增加了动态表Known Received Count统计值（见2.1.4节）。
encoder使用这个值来决定表中的哪个条目可能会导致一条stream被阻塞住，见2.2.1描述。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 0 | 0 |     Increment (6+)    |
   +---+---+-----------------------+

                     Figure 11: Insert Count Increment
```


encoder收到一个Increment字段，值等于0 或 增加Known Received Count超过encoder已经发送的最大值，这种情况下必须（MUST）处理为连接错误“HTTP_QPACK_DECODER_STREAM_ERROR”。

## 4.5. Field Line Representations

一个编码字段区由前缀和可能空表示序列组成。每个表示对应一个单独的字段行。这些表示引用了一个实际状态中的静态表或动态表，但不会改变这个状态。

编码字段区通过封闭协议定义的帧和流进行传输。

### 4.5.1. Encoded Field Section Prefix

每个字段区压缩块起始为2个整数。
Required Insert Count是一个8-bit前缀整数编码（4.5.1.1节）。
Base是一个有符号和系数的整型，使用一个单独的符号bit，和一个7-bit的前缀整型（4.5.1.2节）。

这两个值后续紧跟压缩的头部内容指令。
整个压缩块再根据协议格式封装进frame当中。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   |   Required Insert Count (8+)  |
   +---+---------------------------+
   | S |      Delta Base (7+)      |
   +---+---------------------------+
   |      Encoded Field Lines    ...
   +-------------------------------+

                      Figure 12: Encoded Field Section
```

#### 4.5.1.1. Required Insert Count

Required Insert Count标识动态表的状态，在这个状态下才能处理当前字段区压缩块。
被阻塞的decoder使用Required Insert Count来确认它能够安全地处理当前字段区剩余内容。

如果没有动态表的引用，这个值被填0.
可选的，当Required Insert Count是个大于0的值，encoder用以下公式来计算实际值：

```
      if ReqInsertCount == 0:
         EncInsertCount = 0
      else:
         EncInsertCount = (ReqInsertCount mod (2 * MaxEntries)) + 1
```

这里”MaxEntries”是指动态表中能保存的最大条目数量。最小的条目有长度为0的name和value内容，最小长度为32. 因此“MaxEntries”计算公式为：

```
      MaxEntries = floor( MaxTableCapacity / 32 )
```

“MaxTableCapacity”是decoder宣告的动态表最大容量（见3.2.3节）。
这个编码限制了长连接上的前缀长度。

decoder使用如下算法重新计算Required Insert Count，其中TotalNumberOfInserts是指decoder动态表中插入的条目总数：如果decoder碰到了一致encoder不可能生成的EncodedInsertCount，必须（MUST）将其当做是QPACK_DECOMPRESSION_FAILED类型的连接错误。

```
      FullRange = 2 * MaxEntries
      if EncodedInsertCount == 0:
         ReqInsertCount = 0
      else:
         if EncodedInsertCount > FullRange:
            Error
         MaxValue = TotalNumberOfInserts + MaxEntries

         # MaxWrapped is the largest possible value of
         # ReqInsertCount that is 0 mod 2*MaxEntries
         MaxWrapped = floor(MaxValue / FullRange) * FullRange
         ReqInsertCount = MaxWrapped + EncodedInsertCount - 1

         # If ReqInsertCount exceeds MaxValue, the Encoder's value
         # must have wrapped one fewer time
         if ReqInsertCount > MaxValue:
            if ReqInsertCount <= FullRange:
               Error
            ReqInsertCount -= FullRange

         # Value of 0 must be encoded as 0.
         if ReqInsertCount == 0:
            Error

```

这种编码方式限制了长连接上前缀的长度。
举个栗子，如果动态表是100字节，那么Required Insert Count会编码使用6作为模数。如果decoder收到10个插入指令，那么一个编码为3的值表明当前字段区的Required Insert Count值为9.

#### 4.5.1.2. Base

“Base”被用来恢复动态表的引用，用法见3.2.6节。

为了节约空间，Base字段被编码为基于Required Insert Count的相对值，使用1-bit符号位和“Delta Base”值。有
符号位为0表示Base大于等于Required Insert Count值；符号位1表示Base小于Insert Count。计算公式如下：

```
  if S == 0:
     Base = ReqInsertCount + DeltaBase
  else:
     Base = ReqInsertCount - DeltaBase - 1
```

一个单向处理的encoder，在头部块编码前就先决定好了Base值。如果encoder在编码头部块的过程中插入条目在动态表中，Required Insert Count会比Base值大，所以编码的差值会是负值，并且符号位会被设为1. 如果头部压缩块不引用最新插入的条目，并且之前也没有插入任何新的条目，Base值则会比Required Insert Count值大，于是差值就会为正数，并且符号位被设为0.

encoder在编码头部块之前，提供动态表更新时，可能会设置Required Insert Count和Base为相同值。在这种情况下，符号位和Delta Base都为0.

不引用动态表条目的头部压缩块，可以使用任何Base值；设置Delta Base为0是编码最方便的做法。

举个栗子，如果Required Insert Count值为9，decoder收到S符号位为1、Delta Base值为2. 这会计算出Base值为6，并且使得post-base索引到三个条目。在这个栗子中，第5个条目添加了一个下标为1的引用到动态表中；post-base下标为1的引用指向第8个条目。

### 4.5.2. Indexed Field Line

一个被下标索引的字段行表示，指向静态表或动态表中的一个条目，或指向动态表中一个绝对索引小于Base的条目。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 1 | T |      Index (6+)       |
   +---+---+-----------------------+

                       Figure 13: Indexed Field Line
```

如果条目是在静态表中的，或者在动态表中携带了比Base小的绝对下标，编码起始1-bit为’1’，后续紧跟”S”bit表示引用的是静态表（T=1）或动态表（T=0）。最后，对应header内容的相对下标被表示为一个6-bit前缀整型。

### 4.5.3. Indexed Field Line With Post-Base Index

一个有base前有index表示的索引字段行有别于动态表中绝对索引大于等于Base值的条目。

```
     0   1   2   3   4   5   6   7
   +---+---+---+---+---+---+---+---+
   | 0 | 0 | 0 | 1 |  Index (4+)   |
   +---+---+---+---+---------------+

             Figure 14: Indexed Field Line with Post-Base Index
```

编码起始为4-bit ‘0001’，紧跟对应header内容的post-base下标值，由一个4-bit前缀整型编码表示。

### 4.5.4. Literal Field Line With Name Reference

带名称参照表示的字符串字段行，编码了一个字段行，这个字段行的字段名和静态表、或动态表中一个绝对索引比Base小的条目的字段名相同。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 0 | 1 | N | T |Name Index (4+)|
      +---+---+---+---+---------------+
      | H |     Value Length (7+)     |
      +---+---------------------------+
      |  Value String (Length bytes)  |
      +-------------------------------+

             Figure 15: Literal Field Line With Name Reference
```

这个标识以两位“01”开头。接下来的一个bit，“N”，表示是否允许后续节点将这个字段行添加这个header到动态表中。如果‘N’这个bit被设置1，当前编码的字段行必须（MUST）被编码为文本表达形式。特别地，当对端发送了一个字段行内容，它收到了一个包含‘N’标识位被设为1的文本表示字段行，它必须（MUST）使用文本表示来处理这个字段。这个bit被用来保护字段行中的value值，在被压缩可能带来额外风险的情况下避免被压缩（见RFC7451 7.1节讨论）。

第4位（'T'）表示引用静态表还是动态表。后续4位前缀整数用来定位这个字段名的表条目。
T=1：这个数表示静态表索引
T=0：这个数表示动态表中条目的相对索引。

只有字段名是从动态表条目中提取的；字段值被编码为8位前缀字符串文字（参见4.1.2节）。

### 4.5.5. Literal Field Line With Post-Base Name Reference

一个base前有名称参照的字符串字段行，编码了一个字段行，这个字段行的字段名和动态表中一个绝对索引大于等于Base的条目的字段名相同。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 0 | 0 | 0 | 0 | N |NameIdx(3+)|
      +---+---+---+---+---+-----------+
      | H |     Value Length (7+)     |
      +---+---------------------------+
      |  Value String (Length bytes)  |
      +-------------------------------+

        Figure 16: Literal Field Line With Post-Base Name Reference
```

这个标识以四位“0000”开头。接下来的一个bit“N”如4.5.4节所述，之后是动态表项的post-base索引（3.2.6节），编码为3位前缀整数（见4.1.1节）。

只有字段名来自动态表条目，字段值被编码为8位前缀字符串文本（见4.1.2节）。

### 4.5.6. Literal Field Line With Literal name

带有字符串名称的字符串字段行，表示将一个字段名和字段值编码为字符串文本。

```
        0   1   2   3   4   5   6   7
      +---+---+---+---+---+---+---+---+
      | 0 | 0 | 1 | N | H |NameLen(3+)|
      +---+---+---+---+---+-----------+
      |  Name String (Length bytes)   |
      +---+---------------------------+
      | H |     Value Length (7+)     |
      +---+---------------------------+
      |  Value String (Length bytes)  |
      +-------------------------------+

              Figure 17: Literal Field Line With Literal Name
```

这个标识以三位“001”开头。接下来的一个bit“N”如4.5.4节所述，之后是4位前缀字符串文本表示的字段名，其后是8位前缀字符串文本表示的字段值（见4.1.2节）。

# 5. Configuration

QPACK定义了两个setting选项在HTTP/3的SETTING frame中：

SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x1)：默认值是0。用法见3.2节。这个值和HTTP/2中的SETTINGS_HEADER_TABLE_SIZE含义相同。

SETTINGS_QPACK_BLOCKED_STREAMS (0x7): 默认值为0，用法见2.1.3.

# 6. Error Handling

HTTP/3中定义以下错误码来标识QPACK中出现的错误，用来终止连接：

QPACK_DECOMPRESSION_FAILED (0x200): decoder在对请求或推送流中的头部压缩块解码时，处理一条指令失败的情况。

QPACK_ENCODER_STREAM_ERROR (0x201): decoder在处理encoder stream中的一条指令失败的情况。

QPACK_DECODER_STREAM_ERROR (0x202): encoder在处理decoder stream中一条指令失败的情况。

# 7. Security Considerations

本章节描述了QPACK潜在的安全问题：

* 将压缩当成一个基于长度的数据库来验证（被压缩成共享压缩上下文的）密码的猜测
* 耗尽decoder处理或内存容量，从而引起Dos。

## 7.1. Probing Dynamic Table State

QPACK使用了协议（比如HTTP）中的固有冗余，减少了头部字段编码的长度。
其最终的目标是来减少发送HTTP请求或响应所需的数据量。

如果攻击者既可以定义、编码和传输头部字段，也可以侦听这些字段编码后的长度，那么它就可以探测到用于编码头部字段的压缩上下文。
当攻击者可以做到以上两件事的时候，他们可以适当地修改请求，从而来验证他们对动态表状态的试探。
如果试探的压缩长度更短，攻击者一旦发现这个编码后的长度，就可以推断本次试探是正确的。

即使在TLS和QUIC-Transport协议之上，这也是有可能的，因为TLS和QUIC为上下文提供机密性保护的同时，它们也只是为这些内容提供了有限的保护。

注意：面对这样的攻击者的时候，填充方案也只是提供了有限的保护，可能只是增加了试探的数量，让攻击者更难分析出长度。
填充方案同样因为增加了传输的数据量，和压缩的本意形成了对立。

像CRIME [CRIME] 这样的攻击证实了这些常见的攻击方式的存在。
具体的攻击利用了DEFLATE压缩算法 [RFC1951] 根据对比前缀来移除冗余的特性。
这使得攻击者可以在某个时机下验证一个字符的猜想，将指数时间的攻击成本，减少为线性时间。

### 7.1.1. Applicability to QPACK and HTTP

攻击者可以通过强行试探来匹配整个头部字段值（而非单个字符），来模仿CRIME [CRIME]攻击，QPACK减轻了这些攻击，但不能完全阻止。
攻击者只能知晓一次试探是正确还是错误的，因此只能暴力猜测头部字段值。

因此恢复指定头部字段值的可行性就依赖值的熵。因此高熵的值更难以被踩到，低熵的值容易被攻陷。

只要两个不互信的实体在单个HTTP/3连接上发生请求和响应，就有受到收到这种性质的攻击。
如果共享QPACK压缩单元，就会使一个实体在动态表中加入条目，而其他实体在对选定的字段行进行编码时引用这些条目，那么攻击者（第二个实体）可以通过观察编码后输出的长度来了解表的状态。

例如，一个中间媒介如下操作，就会出现互不信任的实体之间进行了请求和响应的情况：

* 在单个连接上发送多个客户端的请求到一个源服务端，
* 或者从多个源服务端发出响应，并通过一个共享连接发给客户端。

Web浏览器同样需要假设同一个连接上的由不同web源发起的请求，是互不信任实体的通信。其他涉及相不信任的实体的情况也是可能发生的。
### 

### 7.1.2. Mitigation

对头部字段有机密性要求的HTTP用户可以使用熵足够高的值，从而让试探不可行。
然而，将这种方法当做通用解决方案是不现实的，因为它强制所有HTTP用户采取措施来抵御攻击。
这会强行引入如何使用HTTP的约束。

相对于强行引入HTTP用户的约束，QPACK的实现可以约束如何压缩，从而来限制探测动态表的可能性。

一种理想的解决方案是：根据创建头部字段的实体，将动态表的访问隔离。
加入到表中的头部字段值只对一个实体开放，且只能是创建了值的实体才能提取这个值。

为了改善这种方法的压缩性能，特定的条目可以被标记为公开。比如，web浏览器可以在所有请求中访问Accept-Encoding头部字段的值。

不清楚头部字段起源的encoder可以对包含很多不同值的头部字段进行惩罚，比如碰到大量猜测头部字段值的尝试，就在未来的消息中不再对比头部字段和动态表条目，从而有效阻止了未来的猜测。

这个响应速度可能与字段值的长度成反比。与较长的值相比，较短的值可能会更快或更有可能禁止对某一字段名的动态表的访问。

这种减缓措施在两个端点之间最为有效。 如果中间人在不知道是哪个实体构建了某一消息的情况下对消息进行重新编码，中间人可能会无意中合并那些被原始encoder特意分开的压缩上下文。

注意：如果攻击者掌握了重新设置头部字段值的方法的话，简单地将和头部字段有关的条目重动态表中移除可能是无效的。
比如一个浏览器上加载图标的请求通常包含了Cookie头部字段（这个字段通常是这种类型攻击的高价值目标），
并且web站点可以轻易地强制加载图片，从而来更新动态表中的条目。

这个响应可能和头部字段值的长度成反比。对于短的值，禁止头部字段的动态表访问可能比长的值更快或更频繁。

### 7.1.3. Never Indexed Literals

实现也可以选择不压缩敏感头部字段，而将它们的值编码成字面值的方式，来保护敏感头部字段。

拒绝将头部字段插入到动态表只有在所有hop上避免这么做时才有效。
可以使用never indexed literal位（4.5.4小节）来告诉中间媒介：一个特定的值故意以字面值的方式发送。

如果一个设置了‘N’位的字面值陈述，中间媒介必须不能（MUST NOT）再将它和另一个将要索引它的陈述进行冲编码。
如果使用了QPACK进行重编码，必须（MUST）使用一个设置了’N’位的字面值陈述。
如果使用了HPACK进行重编码，必须（MUST）使用不索引字面值陈述（参考[RFC7541]第6.2.3小节）。

需要根据多个因素来考虑将一个头部字段标记为不被索引。由于QPACK不提供针对猜测整个头部字段值的保护，
短值或者低熵值更容易被攻击者恢复。因此，encoder可以选择对低熵值不做索引。

encoder也可以选择对那些被认为是高危的或者容易恢复的头部字段（比如cookie或Authorization头部字段）不做索引。

相反，encoder可以选择对值比较小，或者没有值的头部字段建立索引。
比如，一个User-Agent头部字段通常不会因请求而异，并被发给任何服务端。
在这种情况下，确认使用了一个实际的User-Agent值，不会提供太多价值。

注意这些决策使用never indexed literal描述的条款会随着新的攻击出现而逐步变化。

## 7.2. Static Huffman Encoding

目前没有已知的针对静态霍夫曼编码的攻击。一项调查显示使用静态霍夫曼编码表存在信息泄露漏洞，
然而这个调查同样得出结论，攻击者不可能利用这个信息泄露漏洞来获取任何足量有意义的信息。（参考[PETAL]）

## 7.3. Memory Consumption

攻击者可以试图造成终端耗尽内存。QPACK的设计可以限制终端申请的峰值内存和平均内存

QPACK利用动态表最大尺寸和阻塞流最大数量的定义，限制了encoder能使decoder消耗的内存量。
在HTTP/3中，decoder通过配置参数SETTINGS_QPACK_MAX_TABLE_CAPACITY 和 SETTINGS_QPACK_BLOCKED_STREAMS来控制这两个值（见3.2.3小节和2.1.2小节）。
动态表的尺寸限制计算了动态表中存储数据的大小，并允许少量超出。
阻塞流的最大数量限制只是decoder需要的最大内存量的代理，实际最大内存量依赖于decoder跟踪每个阻塞流所需的内存。

decoder可以将动态表的最大尺寸设置为一个合适的值，从而来限制动态表所需的状态内存量。
在HTTP/3中，通过设置SETTINGS_QPACK_MAX_TABLE_CAPACITY参数来实现这一需求。
encoder可以通过选择一个比decoder允许值更小的动态表尺寸并通知decoder，来限制它自己使用的状态内存量。

decoder可以通过设置阻塞流的最大数量来限制阻塞流使用的状态内存量。
在HTTP/3中，通过设置QPACK_BLOCKED_STREAMS参数来实现这一需求。
encoder可以随意决定阻塞流的数量，从而可以自由限制状态内存量，无需设置。

可以通过按序处理头部字段，来限制encoder或decoder临时使用的内存量。
解码头部块的时候，decoder的实现不需要保存整个头部字段列表。
如果encoder使用了单通道算法来编码头部块，encoder实现不需要保存整个头部字段列表。
注意应用可能因为其他原因而需要保存整个头部列表的必要性；即使QPACK不会这样强制要求，应用约束也可能要求必须这么做。

虽然经过协商后的动态表尺寸限制在QPACK实现消费的内存中占了大部分，
但是因流控而不能立刻发送的数据不受这个限制影响。
实现应当限制未发送数据的尺寸，尤其是解码流上，发送内容的灵活性也受到了限制。
对于过量的未发送数据，可能的响应可以包含限制对端创建新的流的能力，只能从encoder stream上读取，或者关闭连接。

## 7.4. Implementation Limits

QPACK实现需要保证大整数、整数长编码、长字符串不会产生安全漏洞。

实现必须对它接受的整数的值和编码长度设置上限。某种方式上，它必须对它接受的字符串设置长度限制。
这些限制应该（SHOULD）足够大，以处理HTTP实现可以配置为接受的最大单个字段。

当一个实现遇到一个比它能够解码的值更大的值，如是请求流，则必须（MUST）作为QPACK_DECOMPRESSION_FAILED类型的流错误处理，如是encoder stream或decoder stream，则必须作为适当类型的连接错误处理。
