# yamux 协议交互详解

本文档描述 Prism 服务端与 mihomo/sing-box 客户端之间基于 yamux 帧协议的完整通信流程。
包括 sing-mux 协商、12 字节大端帧头、流量控制窗口管理、流创建的两种路径及 TCP/UDP 数据转发。

## 协议栈

```
┌─────────────────────────────────────────┐
│           应用层数据（TCP/UDP）          │
├─────────────────────────────────────────┤
│       StreamRequest / StreamResponse    │
│  （首个 Data 帧携带地址，服务端回状态字节）│
├─────────────────────────────────────────┤
│         yamux 帧协议                    │
│  12 字节帧头 + 可变载荷（仅 Data 帧）    │
│  流量控制：WindowUpdate 窗口管理         │
├─────────────────────────────────────────┤
│         sing-mux 协商层                 │
│  2 字节协议头（选择 smux/yamux）         │
├─────────────────────────────────────────┤
│         底层传输                        │
│  Trojan TLS / WebSocket 等              │
└─────────────────────────────────────────┘
```

与 smux 的关键区别：

| 特性 | smux | yamux |
|------|------|-------|
| 帧头大小 | 8 字节 | 12 字节 |
| 字节序 | 小端 | 大端 |
| 流量控制 | 无 | WindowUpdate 窗口机制 |
| 心跳 | NOP（不回复） | Ping/Pong（请求-响应） |
| 半关闭 | FIN = 完全关闭 | FIN 标志 = 半关闭，可单向继续 |
| 流创建 | SYN 命令 | Data(SYN) 或 WindowUpdate(SYN) |
| 初始窗口 | 无 | 256 KB |

## sing-mux 握手

与 smux 共享相同的 sing-mux 协商层。客户端发送协议头时 Protocol 字段选择 yamux：

```
+------------+------------+
| Version    | Protocol   |
| (1 字节)   | (1 字节)   |
+------------+------------+
             0x01 = yamux
```

mihomo 客户端配置 `protocol: yamux` 时发送 `[0x00][0x01]`。

## yamux 帧格式

所有 yamux 帧共享 12 字节固定帧头，多字节字段为大端序（Big-Endian / 网络字节序）：

```
+----------+----------+----------+------------------+------------------+
| Version  |   Type   |  Flags   |    StreamID      |     Length       |
| (1 字节) | (1 字节) | (2B BE)  |    (4B BE)       |    (4B BE)       |
+----------+----------+----------+------------------+------------------+
|                   Payload（仅 Data 帧有，Length 字节）              |
+---------------------------------------------------------------------+
```

**帧头字段**：

| 偏移 | 大小 | 字段 | 说明 |
|------|------|------|------|
| 0 | 1B | Version | 协议版本，固定 `0x00` |
| 1 | 1B | Type | 消息类型（见下表） |
| 2 | 2B | Flags | 标志位（大端序，可组合） |
| 4 | 4B | StreamID | 流标识符（大端序），0 = 会话级 |
| 8 | 4B | Length | 含义取决于 Type（大端序） |

### 消息类型

| Type | 值 | Length 含义 | 载荷 |
|------|-----|-------------|------|
| Data | `0x00` | 载荷字节数 | 有 |
| WindowUpdate | `0x01` | 窗口增量值 | 无 |
| Ping | `0x02` | Ping ID | 无 |
| GoAway | `0x03` | 终止原因码 | 无 |

### 标志位

标志位为 2 字节大端序，支持按位组合：

| 标志 | 值 | 说明 |
|------|-----|------|
| none | `0x0000` | 无标志 |
| SYN | `0x0001` | 同步：新建流或发起 Ping |
| ACK | `0x0002` | 确认：确认流创建或 Ping 响应 |
| FIN | `0x0004` | 半关闭：发送方不再发送数据 |
| RST | `0x0008` | 重置：强制终止流 |

### GoAway 原因码

| 原因码 | 值 | 说明 |
|--------|-----|------|
| normal | `0x00000000` | 正常关闭 |
| protocol_error | `0x00000001` | 协议错误 |
| internal_error | `0x00000002` | 内部错误 |

## TCP 流完整生命周期

yamux 有两种打开流的方式。Prism 服务端同时支持这两种路径。

### 路径 A：WindowUpdate(SYN)（标准 yamux 方式）

客户端通过 WindowUpdate 帧的 SYN 标志打开新流，后续通过 Data 帧发送地址数据。

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  ──── sing-mux 握手 ────                   │
    │  [Version=0x00][Protocol=0x01]             │
    │  ──────────────────────────────────────────>│  negotiate() → yamux
    │                                            │  创建 yamux::craft
    │                                            │
    │  ──── WindowUpdate(SYN) 打开流 ────        │
    │  Type=WindowUpdate, Flags=SYN              │
    │  StreamID=1, Length=262144                 │
    │  ──────────────────────────────────────────>│  handle_window_update()
    │                                            │  检测 SYN（无 ACK）
    │                                            │  创建 pending_entry
    │                                            │  初始化 stream_window
    │                                            │
    │  <── WindowUpdate(ACK) 确认 ────           │
    │  Type=WindowUpdate, Flags=ACK              │
    │  StreamID=1, Length=262144                 │  初始窗口 256KB
    │  <──────────────────────────────────────────│
    │                                            │
    │  ──── Data 帧携带目标地址 ────             │
    │  Type=Data, Flags=none                     │
    │  StreamID=1, Length=N                      │
    │  Payload: StreamRequest                    │
    │    [Flags 2B][ATYP 1B][Addr][Port 2B]      │
    │  ──────────────────────────────────────────>│  handle_data() → dispatch_data()
    │                                            │  累积到 pending buffer
    │                                            │  activate_stream()
    │                                            │  parse_mux_address()
    │                                            │  router_.async_forward()
    │                                            │
    │  <── Data 帧（成功状态）────               │
    │  Type=Data, Flags=none                     │
    │  StreamID=1, Length=1                      │
    │  Payload: [0x00]                           │  send_data(1, {0x00})
    │  <──────────────────────────────────────────│
    │                                            │
    │  ──── 双向 Data 转发 ────                  │
    │  ... 与下方路径 B 相同 ...                  │
```

### 路径 B：Data(SYN)（sing-mux 兼容方式）

客户端通过 Data 帧的 SYN 标志同时打开流并携带地址数据。这是 mihomo 实际使用的方式。

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  ──── Data(SYN) 打开流 + 携带地址 ────    │
    │  Type=Data, Flags=SYN                      │
    │  StreamID=1, Length=N                      │
    │  Payload: StreamRequest + 数据             │
    │  ──────────────────────────────────────────>│  handle_data() → handle_syn()
    │                                            │  创建 pending_entry
    │                                            │  累积 payload
    │                                            │  初始化 stream_window
    │                                            │
    │  <── WindowUpdate(ACK) 确认 ────           │
    │  Type=WindowUpdate, Flags=ACK              │
    │  StreamID=1, Length=262144                 │
    │  <──────────────────────────────────────────│
    │                                            │
    │  ... 激活流后同路径 A ...                   │
```

### 双向数据转发与窗口管理

流激活后进入双向数据转发阶段，yamux 的窗口机制控制发送速率：

```
mihomo 客户端                                Prism 服务端              目标服务器
    │                                            │                        │
    │  ──── Data(none, 上行数据) ────            │                        │
    │  Type=Data, StreamID=1                     │                        │
    │  Payload=data                              │                        │
    │  ──────────────────────────────────────────>│                        │
    │                                            │  dispatch_data()       │
    │                                            │  update_recv_window()  │
    │                                            │  duct::on_mux_data()   │
    │                                            │  ──────────────────────>│
    │                                            │         写入 target    │
    │                                            │                        │
    │  <── WindowUpdate（接收窗口更新）────       │                        │
    │  Type=WindowUpdate, StreamID=1             │                        │
    │  Length=累计消费量                          │                        │
    │  <──────────────────────────────────────────│                        │
    │                                            │                        │
    │                                            │  duct::target_read_loop│
    │                                            │  <──────────────────────│
    │                                            │      target 响应数据    │
    │  <── Data(none, 下行数据) ────             │                        │
    │  Type=Data, StreamID=1                     │                        │
    │  Payload=response                          │                        │
    │  <──────────────────────────────────────────│                        │
    │                                            │                        │
    │  ──── WindowUpdate（客户端确认窗口）────    │                        │
    │  Type=WindowUpdate, StreamID=1             │                        │
    │  Length=delta                              │                        │
    │  ──────────────────────────────────────────>│                        │
    │                                            │  send_window += delta  │
```

### 窗口管理详解

每个流维护三个原子变量（`stream_window` 结构）：

| 变量 | 初始值 | 作用 |
|------|--------|------|
| `send_window` | 256 KB | 对端允许本端发送的剩余字节数 |
| `recv_window` | 256 KB | 本端允许对端发送的剩余字节数 |
| `recv_consumed` | 0 | 已消费的接收数据累计量 |

**接收窗口更新策略**：
1. 每次收到 Data 帧并消费 `N` 字节后，`recv_consumed += N`
2. 当 `recv_consumed >= 128 KB`（初始窗口的一半）时：
   - 发送 `WindowUpdate(none, stream_id, delta=recv_consumed)`
   - 重置 `recv_consumed = 0`
3. 此策略避免频繁发送 WindowUpdate，同时防止对端发送窗口耗尽

**发送窗口增长**：
- 收到 `WindowUpdate(none, stream_id, delta)` 时，`send_window += delta`
- 使用 CAS 循环保证原子性，溢出时钳制到 `uint32_max`

### 半关闭（FIN）

yamux 支持真正的半关闭：一端发送 FIN 后，该方向数据流关闭，但反方向可继续传输。

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  ──── Data(FIN) 客户端不再发送 ────        │
    │  Type=Data, Flags=FIN                      │
    │  StreamID=1, Length=0                      │
    │  ──────────────────────────────────────────>│  handle_data() → handle_fin()
    │                                            │  duct::on_mux_fin()
    │                                            │  关闭 write_channel_
    │                                            │  target_read_loop 继续
    │                                            │
    │  <── Data(none, 服务端剩余数据) ────       │
    │  <──────────────────────────────────────────│  直到 target EOF
    │                                            │
    │  <── Data(FIN) 服务端也关闭 ────           │
    │  Type=Data, Flags=FIN                      │
    │  StreamID=1, Length=0                      │  send_fin()
    │  <──────────────────────────────────────────│
```

## UDP 流生命周期

UDP 流的创建流程与 TCP 相同（使用 StreamRequest 中的 Flags bit 0 标识）。
数据转发格式与 smux 相同（Plain UDP 使用 Length 前缀，PacketAddr 使用 SOCKS5 地址格式）。

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  Data(SYN, stream_id=3)                    │
    │  Payload: [Flags=0x0001][ATYP][Addr][Port] │
    │  ──────────────────────────────────────────>│  handle_syn(3)
    │                                            │  解析为 UDP 流
    │                                            │
    │  <── WindowUpdate(ACK, stream_id=3)        │
    │  <──────────────────────────────────────────│  Length=262144
    │                                            │
    │  <── Data(none, stream_id=3) [0x00]        │
    │  <──────────────────────────────────────────│  成功状态
    │                                            │  创建 parcel
    │                                            │
    │  Data(none, stream_id=3)                   │
    │  Payload: [Length 2B][UDP Data]             │
    │  ──────────────────────────────────────────>│  parcel::on_mux_data()
    │                                            │  解析并转发 UDP
    │                                            │
    │  <── Data(none, stream_id=3)               │
    │  <── [Length 2B][UDP Response]             │  parcel 回传响应
```

### 接收窗口与 UDP

UDP 数据同样触发 `update_recv_window()`，每消费半窗口数据后发送 WindowUpdate。
这确保客户端知道服务端已处理数据，可以继续发送。

## Ping 心跳

yamux 使用 Ping 帧实现心跳和 RTT 测量：

```
mihomo 客户端                                Prism 服务端
    │                                            │
    │  ──── Ping(SYN) 心跳请求 ────             │
    │  Type=Ping, Flags=SYN                      │
    │  StreamID=0, Length=<ping_id>              │
    │  ──────────────────────────────────────────>│  handle_ping()
    │                                            │
    │  <── Ping(ACK) 心跳响应 ────               │
    │  Type=Ping, Flags=ACK                      │
    │  StreamID=0, Length=<相同 ping_id>          │
    │  <──────────────────────────────────────────│
```

- StreamID 固定为 0（会话级操作）
- Length 为 Ping ID（4 字节随机数），响应必须携带相同 ID
- 客户端通过 Ping 测量 RTT 和检测连接存活

**mihomo 默认配置**：Ping 心跳由 sing-mux 客户端管理，默认间隔约 30 秒。

## GoAway 会话终止

任一方可发送 GoAway 帧关闭整个会话：

```
    Type=GoAway, Flags=none
    StreamID=0, Length=<reason_code>
```

Prism 收到 GoAway 后调用 `close()` 关闭所有流和传输层连接。

## 帧序列示例

### 完整的 Data(SYN) 打开 TCP 流的帧序列

**1. sing-mux 握手**

```
00 01            Version=0, Protocol=1 (yamux)
```

**2. Data(SYN) 打开流 + 携带 StreamRequest**

```
00 00 00 01 00 00 00 01 00 00 00 0F
│  │  └──┬──┘ └────┬────┘ └────┬────┘
│  Type  Flags=SYN StreamID=1  Length=15
Version  (BE)      (BE)        (BE)

Payload (15 字节):
00 00 03 0B 65 78 61 6D 70 6C 65 2E 63 6F 6D 01 BB
│     │  │  └──────────────────────────────────┘ └──┘
Flags=0  ATYP=3  "example.com" (11字节)           Port=443
```

**3. WindowUpdate(ACK) 服务端确认**

```
00 01 00 02 00 00 00 01 00 04 00 00
│  │  └──┬──┘ └────┬────┘ └────┬────┘
│  Type  Flags=ACK StreamID=1  Length=262144
Version WU     (BE)      (BE)  (0x00040000=256KB)
```

**4. Data(none) 服务端成功状态**

```
00 00 00 00 00 00 00 01 00 00 00 01
│  │  Flags=none StreamID=1  Length=1
│  Data
Version

Payload:
00
└── Status=0x00 (成功)
```

**5. 双向 Data 数据帧**

```
上行: 00 00 00 00 00 00 00 01 00 00 XX XX [data...]
下行: 00 00 00 00 00 00 00 01 00 00 YY YY [data...]
```

**6. WindowUpdate 窗口更新**

```
00 01 00 00 00 00 00 01 00 00 80 00
                          └── delta=32768 (32KB)
```

**7. Data(FIN) 关闭流**

```
00 00 00 04 00 00 00 01 00 00 00 00
      Flags=FIN              Length=0
```

## 与 smux 的帧序列对比

### smux 打开 TCP 流

```
客户端 → 服务端: SYN 帧 (8 字节, 无载荷)
客户端 → 服务端: PSH 帧 (8 字节头 + StreamRequest 载荷)
服务端 → 客户端: PSH 帧 (8 字节头 + 1 字节状态)
```

### yamux 打开 TCP 流（Data(SYN) 路径）

```
客户端 → 服务端: Data(SYN) 帧 (12 字节头 + StreamRequest 载荷)
服务端 → 客户端: WindowUpdate(ACK) 帧 (12 字节, 无载荷)
服务端 → 客户端: Data(none) 帧 (12 字节头 + 1 字节状态)
```

yamux 多了一步 WindowUpdate(ACK)，用于建立流量控制窗口。

## Prism 实现对应

| 协议行为 | Prism 代码 |
|----------|------------|
| sing-mux 握手 | `bootstrap::negotiate()` in `bootstrap.cpp` |
| Data(SYN) 处理 | `yamux::craft::handle_syn()` |
| WindowUpdate(SYN) 处理 | `yamux::craft::handle_window_update()` |
| WindowUpdate(ACK) 响应 | `handle_syn()` / `handle_window_update()` 中发送 |
| Data 分发 | `yamux::craft::dispatch_data()` |
| 地址解析 | `smux::parse_mux_address()` (复用 smux 的地址格式) |
| 状态响应 | `yamux::craft::activate_stream()` 中 `send_data({0x00/0x01})` |
| 窗口初始化 | `yamux::craft::get_or_create_window()` |
| 接收窗口更新 | `yamux::craft::update_recv_window()` |
| 发送窗口增长 | `yamux::craft::handle_window_update()` 中 CAS 循环 |
| TCP 双向转发 | `duct::target_read_loop()` + `duct::target_write_loop()` |
| UDP 中继 | `parcel::on_mux_data()` |
| Ping 响应 | `yamux::craft::handle_ping()` |
| GoAway 处理 | `yamux::craft::handle_go_away()` → `close()` |
| FIN 处理 | `yamux::craft::handle_fin()` |
| RST 处理 | `yamux::craft::handle_rst()` |
| 帧编码 | `yamux::build_header()` in `frame.cpp` |
| 帧解码 | `yamux::parse_header()` in `frame.cpp` |
| 发送串行化 | `yamux::craft::send_loop()` via `concurrent_channel` |
