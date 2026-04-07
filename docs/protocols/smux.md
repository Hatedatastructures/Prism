# smux 协议交互详解

本文档描述 Prism 服务端与 mihomo/sing-box 客户端之间基于 smux v1 帧协议的完整通信流程。
包括 sing-mux 协商层握手、帧格式、TCP/UDP 流生命周期及数据转发细节。

## 协议栈

```
┌─────────────────────────────────────────┐
│           应用层数据（TCP/UDP）          │
├─────────────────────────────────────────┤
│       StreamRequest / StreamResponse    │
│  （首个 PSH 帧携带地址，服务端回状态字节） │
├─────────────────────────────────────────┤
│         smux v1 帧协议                  │
│  8 字节帧头 + 可变载荷                   │
├─────────────────────────────────────────┤
│         sing-mux 协商层                 │
│  2 字节协议头（选择 smux/yamux）         │
├─────────────────────────────────────────┤
│         底层传输                        │
│  Trojan TLS / WebSocket 等              │
└─────────────────────────────────────────┘
```

## sing-mux 握手

客户端在建立 TLS 连接并通过 Trojan 认证后（cmd=0x7F），发送 sing-mux 协议头。
Prism 的 `bootstrap::negotiate()` 读取此头部确定协议类型。

### 协议头格式

```
+------------+------------+--------------------------------------+
| Version    | Protocol   | [可选] Padding（仅 Version > 0）     |
| (1 字节)   | (1 字节)   |                                      |
+------------+------------+--------------------------------------+

Version > 0 时的 Padding 扩展：
+------------+------------+------------+
| PadLen (2B BE) | Padding (N 字节)  |
+------------+------------+------------+
```

**字段说明**：

| 字段 | 值 | 说明 |
|------|-----|------|
| Version | `0x00` | Version0，无 Padding |
| Version | `0x01` | Version1，支持 Padding |
| Protocol | `0x00` | 选择 smux 协议 |
| Protocol | `0x01` | 选择 yamux 协议 |
| PadLen | 0-65535 | Padding 数据长度（大端序） |
| Padding | 随机字节 | 抗流量特征识别，通常 256-768 字节 |

### mihomo 客户端行为

mihomo（sing-mux 客户端）默认发送 `Version=0`，`Protocol=0`（smux）。
当用户配置 `protocol: smux` 时使用此路径。

握手完成后，连接完全交给 smux 帧协议处理，不再有 sing-mux 层的数据。

## smux 帧格式

所有 smux 帧共享 8 字节固定帧头，多字节字段为小端序（Little-Endian）：

```
+----------+----------+------------------+------------------+
| Version  |   Cmd    |     Length       |    StreamID      |
| (1 字节) | (1 字节) |   (2 字节 LE)    |   (4 字节 LE)    |
+----------+----------+------------------+------------------+
|                   Payload (Length 字节)                   |
+-----------------------------------------------------------+
```

**帧头字段**：

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1B | Version | 协议版本，固定 `0x01` |
| 1 | 1B | Cmd | 命令类型（见下表） |
| 2 | 2B | Length | 载荷长度（小端序），最大 65535 |
| 4 | 4B | StreamID | 流标识符（小端序） |

**命令类型**：

| 命令 | 值 | 说明 |
|------|-----|------|
| SYN | `0x00` | 新建流，无载荷 |
| FIN | `0x01` | 关闭流，无载荷 |
| PSH | `0x02` | 数据推送，携带载荷 |
| NOP | `0x03` | 心跳，无载荷，服务端不回复 |

**流 ID 分配**：客户端使用奇数 ID（1, 3, 5...），服务端使用偶数 ID。
在 sing-mux 模式下，只有客户端创建流，因此所有流 ID 为奇数。

## TCP 流完整生命周期

以下展示一个 TCP 流从创建到关闭的完整帧序列：

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  ──── sing-mux 握手 ────                   │
    │  [Version=0x00][Protocol=0x00]             │
    │  ──────────────────────────────────────────>│  negotiate() 读取协议头
    │                                            │  创建 smux::craft 实例
    │                                            │
    │  ──── 打开流（SYN） ────                   │
    │  SYN 帧 (stream_id=1, 无载荷)              │
    │  ──────────────────────────────────────────>│  handle_syn(1)
    │                                            │  创建 pending_entry
    │                                            │  等待地址数据
    │                                            │
    │  ──── 发送目标地址（首个 PSH）────          │
    │  PSH 帧 (stream_id=1)                      │
    │  载荷: StreamRequest                       │
    │    [Flags 2B][ATYP 1B][Addr][Port 2B]      │
    │    [可选: 后续数据]                          │
    │  ──────────────────────────────────────────>│  dispatch_push(1, payload)
    │                                            │  累积到 pending buffer
    │                                            │  buffer >= 7 字节时
    │                                            │  activate_stream(1)
    │                                            │  parse_mux_address() 解析地址
    │                                            │  router_.async_forward(host, port)
    │                                            │
    │  <──── 连接成功状态 ────                    │
    │  PSH 帧 (stream_id=1)                      │
    │  载荷: [0x00]                               │  send_data(1, {0x00})
    │  <──────────────────────────────────────────│  成功状态
    │                                            │
    │  ──── 双向数据转发 ────                    │
    │  PSH 帧 (stream_id=1, 载荷=data)           │
    │  ──────────────────────────────────────────>│  duct::on_mux_data()
    │                                            │  → write_channel_
    │                                            │  → target_write_loop()
    │                                            │  → 写入目标服务器
    │                                            │
    │  <──── PSH 帧 (stream_id=1, 载荷=data)     │
    │  <──────────────────────────────────────────│  duct::target_read_loop()
    │                                            │  → send_data()
    │                                            │  → push_frame(PSH)
    │                                            │  → send_loop() → transport
    │                                            │
    │  ... 持续双向转发 ...                       │
    │                                            │
    │  ──── 关闭流（FIN） ────                   │
    │  FIN 帧 (stream_id=1)                      │
    │  ──────────────────────────────────────────>│  handle_fin(1)
    │                                            │  duct::on_mux_fin()
    │                                            │  关闭 write_channel_
    │                                            │  target EOF 后
    │                                            │
    │  <──── FIN 帧 (stream_id=1)                │
    │  <──────────────────────────────────────────│  send_fin(1)
    │                                            │  流完全关闭
```

### StreamRequest 地址格式

首个 PSH 帧的载荷为 sing-mux StreamRequest：

```
+--------------+------------+------------------+------------------+
| Flags (2B BE)| ATYP (1B)  | Addr (变长)      | Port (2B BE)     |
+--------------+------------+------------------+------------------+
```

**Flags（2 字节大端序）**：

| 位 | 掩码 | 含义 |
|----|------|------|
| bit 0 | `0x0001` | UDP 流标志 |
| bit 1 | `0x0002` | PacketAddr 模式（每个数据报携带目标地址） |

TCP 流：`Flags = 0x0000`

**ATYP 地址类型**：

| ATYP | 格式 | 长度 |
|------|------|------|
| `0x01` | IPv4：`[4 字节 IP]` | 7 字节总计（含 ATYP+Port） |
| `0x03` | 域名：`[1B 长度][域名][2B 端口]` | 4 + 域名长度 |
| `0x04` | IPv6：`[16 字节 IP]` | 19 字节总计（含 ATYP+Port） |

**示例**：访问 `example.com:443`（TCP）

```
00 00          Flags = 0x0000（TCP 流）
03             ATYP = 域名
0B             域名长度 = 11
65 78 61 6D    "exam"
70 6C 65 2E    "ple."
63 6F 6D       "com"
01 BB          Port = 443（大端序）
```

### StreamResponse 状态字节

服务端通过 PSH 帧发送 1 字节状态响应：

| 值 | 含义 |
|----|------|
| `0x00` | 成功，连接已建立 |
| `0x01` | 失败，地址解析错误或目标不可达 |

客户端收到 `0x00` 后开始双向数据转发。收到 `0x01` 后流将被关闭（服务端会
紧接发送 FIN 帧）。

## UDP 流生命周期

### Plain UDP（单目标）

Plain UDP 模式下，StreamRequest 中 `Flags = 0x0001`，指定固定目标地址。
后续数据使用 2 字节长度前缀格式：

```
+------------------+------------------+
| Length (2B BE)   | Payload (N 字节)  |
+------------------+------------------+
```

**完整流程**：

```
mihomo 客户端                                Prism 服务端
    │  SYN 帧 (stream_id=3)                    │
    │  ──────────────────────────────────────────>│  handle_syn(3)
    │                                            │
    │  PSH 帧 (stream_id=3)                      │
    │  StreamRequest: Flags=0x0001               │
    │  ATYP=0x01, Addr=8.8.8.8, Port=53          │
    │  ──────────────────────────────────────────>│  解析为 UDP 流
    │                                            │  创建 parcel
    │                                            │  set_destination("8.8.8.8", 53)
    │                                            │
    │  <── PSH 帧 (stream_id=3) [0x00]          │  成功状态
    │                                            │
    │  PSH 帧 (stream_id=3)                      │
    │  [Length 2B][DNS Query Payload]             │
    │  ──────────────────────────────────────────>│  parcel::on_mux_data()
    │                                            │  解析 Length+Payload
    │                                            │  发送 UDP 到 8.8.8.8:53
    │                                            │
    │  <── PSH 帧 (stream_id=3)                  │  DNS Response
    │  <── [Length 2B][DNS Response Payload]     │  编码为 Length+Payload
    │                                            │
    │  ... 超时或 FIN 关闭 ...                    │
```

### PacketAddr 模式（多目标）

PacketAddr 模式下，`Flags = 0x0003`（bit 0 + bit 1），每个数据报携带独立目标地址：

```
+--------------+------------+------------------+------------------+
| ATYP (1B)    | Addr (变长) | Port (2B BE)     | Payload          |
+--------------+------------+------------------+------------------+
```

此模式允许一个 UDP 流中继到不同目标地址和端口。

## NOP 心跳

smux 定义 NOP 命令用于保活。但在 sing-mux 客户端中，NOP 心跳默认被禁用
（mihomo 配置 `KeepAliveDisabled = true`）。服务端收到 NOP 帧后直接忽略，
不回复任何帧。

## 帧序列示例

### 完整的 mihomo TCP 连接帧序列

以下为 mihomo 客户端打开一个 TCP 流访问 `example.com:443` 的完整十六进制帧序列：

**1. sing-mux 握手**

```
00 00            Version=0, Protocol=0 (smux)
```

**2. SYN 帧（stream_id=1）**

```
01 00 00 00 01 00 00 00
│  │  └──┘  └──────────┘
│  │  Len=0  StreamID=1 (LE)
│  Cmd=SYN
Version
```

**3. PSH 帧（stream_id=1，携带 StreamRequest）**

```
01 02 0F 00 01 00 00 00   00 00 03 0B 65 78 61 6D
│  │  └──┘  └──────────┘   └─────────────────────...
│  │  Len=15 StreamID=1    Flags=0x0000 ATYP=0x03
│  Cmd=PSH                 域名长度=11 "example.com"
Version                    Port=0x01BB (443)
```

**4. PSH 帧（stream_id=1，服务端响应成功）**

```
01 02 01 00 01 00 00 00   00
│  │  Len=1  StreamID=1   Status=0x00 (成功)
│  Cmd=PSH
Version
```

**5. 双向 PSH 数据帧**（持续转发）

```
01 02 XX XX 01 00 00 00   [data...]
```

**6. FIN 帧（stream_id=1）**

```
01 01 00 00 01 00 00 00
   Cmd=FIN
```

## Prism 实现对应

| 协议行为 | Prism 代码 |
|----------|------------|
| sing-mux 握手 | `bootstrap::negotiate()` in `bootstrap.cpp` |
| SYN 处理 | `smux::craft::handle_syn()` |
| PSH 分发 | `smux::craft::dispatch_push()` |
| 地址解析 | `smux::parse_mux_address()` in `frame.cpp` |
| 状态响应 | `smux::craft::activate_stream()` 中 `send_data({0x00/0x01})` |
| TCP 双向转发 | `duct::target_read_loop()` + `duct::target_write_loop()` |
| UDP 中继 | `parcel::on_mux_data()` → `relay_datagram()` |
| FIN 处理 | `smux::craft::handle_fin()` |
| 帧编码 | `smux::build_header()` in `frame.cpp` |
| 帧解码 | `smux::deserialization()` in `frame.cpp` |
| 发送串行化 | `smux::craft::send_loop()` via `concurrent_channel` |
