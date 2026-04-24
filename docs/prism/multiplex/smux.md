# smux 协议 — 多路复用模块

## 1. 模块概述

smux 是 Prism 实现的简单多路复用协议，兼容 Mihomo/xtaci/smux v1 并通过 sing-mux 协议协商接入。它在单个 TCP 连接上承载多个独立的双向字节流，每个流对应一个目标连接（TCP duct 或 UDP parcel）。smux 由 Trojan 协议的 `cmd=0x7F` 触发，是 Prism 多路复用体系的核心协议之一。

### 协议栈

```
Application (HTTP/SOCKS5)
   │
   ├─ smux::duct / smux::parcel   // TCP 流管道 / UDP 数据报管道
   │
   ├─ smux::craft                 // 帧编解码 + 流调度
   │    8-byte header: [Ver][Cmd][Len][SID]
   │
   ├─ multiplex::core             // 协议无关抽象基类
   │    pending_ / ducts_ / parcels_ 流状态管理
   │
   ├─ sing-mux 协商               // [Ver 1B][Proto 1B]
   │    Proto=0x00 → smux
   │
   ├─ transport                   // TLS 隧道 / 明文
   │
   └─ TCP Socket
```

### 文件结构

```
include/prism/multiplex/
├── bootstrap.hpp               # 多路复用会话引导（sing-mux 协商 + 协议分流）
├── core.hpp                    # 协议无关抽象基类（流状态管理）
├── config.hpp                  # 多路复用配置（smux/yamux 子配置）
├── duct.hpp                    # TCP 流管道（协议无关）
├── parcel.hpp                  # UDP 数据报管道（协议无关）
├── smux/
│   ├── craft.hpp               # smux 会话实现（帧读写 + 流调度）
│   ├── frame.hpp               # smux 帧格式定义 + 编解码函数
│   └── config.hpp              # smux 子配置
└── yamux/
    ├── craft.hpp               # yamux 会话实现
    ├── frame.hpp               # yamux 帧格式
    └── config.hpp              # yamux 子配置

src/prism/multiplex/
├── core.cpp                    # core 基类实现
├── duct.cpp                    # duct TCP 管道实现
├── parcel.cpp                  # parcel UDP 管道实现
├── smux/
│   ├── craft.cpp               # smux 会话实现
│   └── frame.cpp               # smux 帧编解码实现
└── yamux/
    ├── craft.cpp               # yamux 会话实现
    └── frame.cpp               # yamux 帧编解码实现
```

---

## 2. 核心类型与类

### 2.1 smux 帧格式

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/smux/frame.hpp` |
| 实现文件 | `src/prism/multiplex/smux/frame.cpp` |
| 命名空间 | `psm::multiplex::smux` |

**8 字节定长帧头（小端序）:**

```
+--------+-------+--------+----------+
| Byte 0 | Byte 1| Byte2-3| Byte4-7  |
+--------+-------+--------+----------+
| Version| Cmd   | Length | StreamID |
|  1B    |  1B   |  2B LE |  4B LE   |
+--------+-------+--------+----------+

Version  = 0x01
Length   = uint16 LE, 最大 65535
StreamID = uint32 LE, 0 表示会话级帧
```

**命令类型:**

| 命令 | 值 | 说明 |
|------|-----|------|
| `syn` | 0x00 | 新建流 |
| `fin` | 0x01 | 半关闭流 |
| `push` | 0x02 | 数据推送 |
| `nop` | 0x03 | 心跳（不回复） |

### 2.2 地址解析结构体

```
struct parsed_address                     // 从首个 PSH 帧解析的目标地址
├── host                  : memory::string  // 目标主机（IPv4/IPv6/域名）
├── port                  : uint16          // 目标端口
├── offset                : size_t          // 地址结束位置
├── is_udp                : bool            // Flags bit0: UDP 流
└── packet_addr           : bool            // Flags bit1: PacketAddr 模式

struct udp_datagram                         // UDP 数据报（SOCKS5 格式）
├── host                  : memory::string  // 目标主机
├── port                  : uint16          // 目标端口
├── payload               : span<const byte>// 数据部分
└── consumed              : size_t          // 解析消耗字节数

struct udp_length_prefixed                  // Length-prefixed UDP 数据报
├── payload               : span<const byte>// 数据部分
└── consumed              : size_t          // 解析消耗字节数
```

**sing-mux StreamRequest 格式:**

```
+-------+-----+---------+------+
|Flags 2B|ATYP | Addr   |Port 2B|
+-------+-----+---------+------+

Flags (BE):
  bit0 = 1 → UDP 流
  bit1 = 1 → PacketAddr 模式（每帧携带目标地址）

ATYP:
  0x01 → IPv4 (4 bytes)
  0x03 → 域名 (1 byte len + domain)
  0x04 → IPv6 (16 bytes)
```

**UDP 数据报格式 (PacketAddr 模式):**

```
+-----+---------+------+--------+
|ATYP | Addr    |Port 2B| Data  |
+-----+---------+------+--------+
```

**UDP 数据报格式 (无 PacketAddr 模式):**

```
+--------+--------+
|Len 2B  | Payload|
|  BE    |        |
+--------+--------+
```

### 2.3 smux::craft (smux 会话)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/smux/craft.hpp` |
| 实现文件 | `src/prism/multiplex/smux/craft.cpp` |
| 命名空间 | `psm::multiplex::smux` |

```
struct outbound_frame                     // 出站帧（header 与 payload 分离）
├── header                : array<byte, 8>  // 编码后的 8 字节帧头
└── payload               : memory::vector<byte>  // 帧载荷（move 传递）

class craft : core                          // smux 会话
├── channel_              : concurrent_channel<outbound_frame>  // 发送通道
├── run()                 : awaitable<void>  // 协议主循环
├── frame_loop()          : awaitable<void>  // 帧读取 + 分发
├── send_loop()           : awaitable<void>  // 帧发送循环
├── keepalive_loop()      : awaitable<void>  // NOP 心跳循环
├── handle_syn(stream_id) : awaitable<void>  // 处理 SYN 帧
├── dispatch_push(sid, payload): void       // 三路分发 PSH 帧
├── handle_fin(stream_id) : void            // 处理 FIN 帧
├── activate_stream(sid)  : awaitable<void>  // 解析地址 + 连接目标
├── push_frame(cmd, sid, payload): awaitable<void>  // 推送帧到通道
├── send_data(sid, payload): awaitable<void> // 发送 PSH 帧
├── send_fin(sid)         : void            // 异步发送 FIN 帧
└── executor()            : any_io_executor  // 获取执行器
```

### 2.4 multiplex::core (抽象基类)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/core.hpp` |
| 实现文件 | `src/prism/multiplex/core.cpp` |
| 命名空间 | `psm::multiplex` |

```
class core : enable_shared_from_this<core>
├── transport_            : shared_transmission  // 底层传输连接
├── router_               : resolve::router&     // 路由器引用
├── config_               : const config&        // mux 配置
├── mr_                   : memory::resource_pointer
├── active_               : atomic<bool>         // 会话活跃标志
├── pending_              : unordered_map<uint32, pending_entry>  // 待连接流
├── ducts_                : unordered_map<uint32, shared_ptr<duct>>   // TCP 管道
├── parcels_              : unordered_map<uint32, shared_ptr<parcel>> // UDP 管道
├── start()               : void                 // 启动 mux 会话
├── close()               : void                 // 幂等关闭
├── is_active()           : bool                 // 检查活跃状态
├── send_data(sid, payload): awaitable<void>     // 纯虚：发送数据帧
├── send_fin(sid)         : void                 // 纯虚：发送 FIN 帧
├── executor()            : any_io_executor       // 纯虚：获取执行器
├── run()                 : awaitable<void>       // 纯虚：协议主循环
├── remove_duct(sid)      : void                 // 移除 TCP 管道
└── remove_parcel(sid)    : void                 // 移除 UDP 管道

struct pending_entry                        // 待连接流条目
├── buffer                : memory::vector<byte>  // 累积地址+数据
└── connecting            : bool             // 是否已发起连接
```

### 2.5 multiplex::bootstrap (会话引导)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/bootstrap.hpp` |
| 命名空间 | `psm::multiplex` |

```
bootstrap(transport, router, cfg, mr) → shared_ptr<core>
    │
    ├── 读取 sing-mux 协商头: [Version 1B][Protocol 1B]
    │   Version > 0 时: + [PaddingLen 2B BE][Padding N bytes]
    │
    ├── Protocol = 0x00 → 创建 smux::craft
    └── Protocol = 0x01 → 创建 yamux::craft
```

---

## 3. 架构与组件交互

### 3.1 整体架构图

```
multiplex::core  // 协议无关抽象基类
   pending_       // SYN 后等待地址
   ducts_         // TCP 流双向转发
   parcels_       // UDP 数据报中继
   纯虚接口:      send_data / send_fin / executor / run
   │
   ├─ smux::craft
   │    8B 小端帧头 [Ver][Cmd][Len LE][SID LE]
   │    channel_ → send_loop → transport (scatter-gather)
   │    NOP keepalive_loop
   │
   └─ yamux::craft
        12B 大端帧头 [Ver][Type][Flags BE][SID][Len BE]
        WindowUpdate 流量控制
        Ping 心跳
   │
   ├─ multiplex::duct        // TCP 管道
   │    target_read_loop
   │    target_write_loop
   │    write_channel_
   │    → 目标 TCP 连接
   │
   └─ multiplex::parcel      // UDP 管道
        on_mux_data
        downlink_loop
        egress_socket_
        → 目标 UDP socket
```

### 3.2 发送路径架构

```
// 发送路径: duct → craft → transport
duct::target_read_loop / parcel::relay_datagram
   → owner_->send_data(stream_id, move(payload))
   → smux::craft::send_data()
        → push_frame(command::push, stream_id, move(payload))
           → build_header(cmd, sid, len)      // 8B 帧头
           → outbound_frame { header, payload }
           → channel_.async_send(frame)
        → smux::craft::send_loop()
           → co_await channel_.async_receive()
           → async_write_scatter(header, payload)  // 零拷贝
   → transport (TLS 隧道 / 明文 TCP)
```

---

## 4. 完整生命周期流程

### 4.1 完整 TCP 流生命周期（含 hex 帧示例）

**场景: 客户端通过 smux 创建一条到 example.com:80 的 TCP 流**

```
// 阶段 1: sing-mux 协商
客户端 → Server: [sing-mux header]
   00 00    // Version=0, Protocol=0x00 (smux)

// 阶段 2: 客户端发送 SYN 帧创建新流
客户端 → Server: [smux frame: SYN, StreamID=1]
   01 00 00 00 01 00 00 00
   // Version=0x01, Cmd=0x00 (SYN), Length=0x0000, StreamID=0x00000001 (LE, 奇数)

Server: 创建 pending_entry[1], 等待地址数据

// 阶段 3: 客户端发送目标地址 (StreamRequest)
客户端 → Server: [smux frame: PSH, StreamID=1, payload=StreamRequest]
   01 02 0E 00 01 00 00 00  [payload: 14 bytes]
   // Version=0x01, Cmd=0x02 (PSH), Length=0x000E (14), StreamID=1
   // StreamRequest:
   //   Flags = 00 00  (TCP, 无 PacketAddr)
   //   ATYP  = 03     (域名)
   //   Addr  = "example.com" (11 bytes)
   //   Port  = 00 50  (80 BE)

Server:
   1. parse_mux_address → host="example.com", port=80
   2. router.async_forward("example.com", "80")
   3. 连接成功 → send_data(sid, {0x00})
   4. 创建 duct[1] 绑定目标连接
   5. duct.start() 启动双向转发

Server → 客户端: [smux frame: PSH, StreamID=1, payload=0x00]
   01 02 01 00 01 00 00 00  00
   // Length=1, payload=0x00 (成功状态)

// 阶段 4: 双向数据转发
客户端 → Server: [PSH, SID=1] HTTP GET / HTTP/1.1...
   01 02 xx xx 01 00 00 00  [HTTP GET 载荷]
   → 转发到目标 TCP 连接

Server → 客户端: [PSH, SID=1] HTTP/1.1 200 OK...
   01 02 xx xx 01 00 00 00  [HTTP 200 载荷]
   ← 从目标 TCP 连接读取

// 阶段 5: 客户端关闭流 (FIN)
客户端 → Server: [smux frame: FIN, StreamID=1]
   01 01 00 00 01 00 00 00
   // Version=0x01, Cmd=0x01 (FIN), Length=0, StreamID=1

Server:
   1. handle_fin(1) → duct.on_mux_fin()  // 半关闭
   2. duct target_read_loop 继续读取剩余数据
   3. target EOF → send_fin(1) → 通知客户端

// 阶段 6: 服务端回复 FIN
Server → 客户端: [smux frame: FIN, StreamID=1]
   01 01 00 00 01 00 00 00

Server: ducts_.erase(1), remove_duct(1)
```

### 4.2 完整 UDP 流生命周期

**场景: 客户端通过 smux 创建 DNS 查询 UDP 流 (PacketAddr 模式)**

```
// 阶段 1: SYN + 地址数据 (PacketAddr 模式)
客户端 → Server: [smux frame: SYN, StreamID=3]
   01 00 00 00 03 00 00 00

客户端 → Server: [smux frame: PSH, StreamID=3, payload]
   01 02 0D 00 03 00 00 00  [Payload: Flags=00 03 (UDP+PacketAddr)]
   // ATYP=0x01 (IPv4), Addr=8.8.8.8, Port=00 35 (53)

Server:
   1. 解析: is_udp=true, packet_addr=true
   2. send_data(sid, {0x00})  // 成功状态
   3. 创建 parcel[3], packet_addr=true
   4. parcel.start() 启动空闲超时监控

// 阶段 2: DNS 查询 (每帧携带目标地址)
客户端 → Server: [smux frame: PSH, StreamID=3, payload]
   01 02 xx xx 03 00 00 00  [ATYP=0x01][8.8.8.8][Port=53][DNS Query]

Server:
   1. parcel.on_mux_data() → parse_udp_datagram()
   2. 通过 egress_socket_ 发送 DNS 查询到 8.8.8.8:53
   3. downlink_loop 接收响应
   4. 编码为 [ATYP][Addr][Port][Response] 发送回客户端

Server → 客户端: [smux frame: PSH, StreamID=3, payload]
   01 02 xx xx 03 00 00 00  [ATYP=0x01][8.8.8.8][Port=53][DNS Response]

// 阶段 3: 空闲超时
超过 config.udp_idle_timeout_ms 无数据活动
   → parcel.close() → parcels_.erase(3)
```

### 4.3 帧循环主协程序列图

```
// 帧循环主协程 (craft::frame_loop)
transport → craft::frame_loop: async_read 8B header
craft::frame_loop → craft: deserialization → frame_header

if hdr.length > 0:
   transport → craft::frame_loop: async_read payload

switch hdr.cmd:
   case SYN:
      → handle_syn(sid)
      → pending_.emplace(sid, pending_entry)

   case PSH:
      → dispatch_push(sid, payload)
           if sid in pending_:
               entry.buffer += payload
               if entry.buffer.size >= 7 && !entry.connecting:
                   entry.connecting = true
                   co_spawn activate_stream(sid)
                      → parse_mux_address → connect target
                      → create duct / parcel
           elif sid in ducts_:
               co_spawn duct.on_mux_data(payload)
           elif sid in parcels_:
               co_spawn parcel.on_mux_data(payload)

   case FIN:
      → handle_fin(sid)
           if sid in pending_:  pending_.erase(sid)
           elif sid in ducts_:  duct.on_mux_fin()  // 半关闭
           elif sid in parcels_: parcel.close()

   case NOP:
      忽略  // 心跳帧无需回复
```

### 4.4 激活流 (activate_stream) 流程

```
activate_stream(stream_id)
    │
    ├── 查找 pending_[stream_id]
    │
    ├── parse_mux_address(buffer) → parsed_address
    │   //  Flags 2B: bit0=UDP, bit1=PacketAddr
    │   //  ATYP 1B: 0x01=IPv4, 0x03=域名, 0x04=IPv6
    │   //  Addr(var)
    │   //  Port 2B BE
    │
    ├── 提取 offset 之后的剩余数据
    │
    ├── if is_udp:
    │   │
    │   ├── send_data(sid, {0x00})  // 成功状态
    │   ├── pending_.erase(sid)
    │   ├── parcel = make_parcel(sid, owner, router, timeout, max_dg, mr, packet_addr)
    │   ├── if !packet_addr: parcel.set_destination(host, port)
    │   ├── parcels_[sid] = parcel
    │   ├── parcel.start()
    │   └── if remaining_data: parcel.on_mux_data(remaining_data)
    │
    └── else (TCP):
        │
        ├── router.async_forward(host, port)
        │
        ├── if connect failed:
        │   ├── send_data(sid, {0x01})  // 错误状态
        │   ├── pending_.erase(sid)
        │   └── send_fin(sid)
        │
        └── else (connect success):
            ├── send_data(sid, {0x00})  // 成功状态
            ├── pending_.erase(sid)
            ├── target = make_reliable(conn)
            ├── duct = make_duct(sid, owner, target, buffer_size, mr)
            ├── ducts_[sid] = duct
            ├── duct.start()
            └── if remaining_data: duct.on_mux_data(remaining_data)
```

---

## 5. 关键算法

### 5.1 帧头编解码

```
// 编码: 8 字节小端序
build_header(cmd, stream_id, length) → array<byte, 8>:
    [0] = protocol_version (0x01)
    [1] = cmd
    [2] = length & 0xFF           // Length LO byte
    [3] = length >> 8             // Length HI byte
    [4] = stream_id & 0xFF        // StreamID byte 0
    [5] = stream_id >> 8          // StreamID byte 1
    [6] = stream_id >> 16         // StreamID byte 2
    [7] = stream_id >> 24         // StreamID byte 3

// 解码: 8 字节小端序解析
deserialization(span) → optional<frame_header>:
    if span.size < 8: return nullopt
    hdr.version = span[0]
    hdr.cmd = span[1]
    hdr.length = span[2] | (span[3] << 8)
    hdr.stream_id = span[4] | (span[5] << 8) | (span[6] << 16) | (span[7] << 24)
    if hdr.version != protocol_version: return nullopt
    if hdr.length > max_frame_length (65535): return nullopt
    return hdr
```

### 5.2 三路分发 (dispatch_push)

```
dispatch_push(stream_id, payload):
    // 1. Pending 流: 累积地址数据，触发激活
    if stream_id in pending_:
        entry.buffer += payload
        if !entry.connecting and entry.buffer.size >= 7:
            entry.connecting = true
            co_spawn(activate_stream(stream_id))  // detached

    // 2. 已连接的 TCP 流: 非阻塞 dispatch
    elif stream_id in ducts_:
        co_spawn(duct.on_mux_data(move(payload)))  // detached

    // 3. UDP 流: 非阻塞 dispatch
    elif stream_id in parcels_:
        co_spawn(parcel.on_mux_data(move(payload)))  // detached
```

### 5.3 StreamID 分配约定

| 端 | StreamID 规则 | 说明 |
|----|--------------|------|
| 客户端 (smux) | 奇数 (1, 3, 5, ...) | 客户端创建的流使用奇数 ID |
| 服务端 | 无需分配 | 服务端只响应客户端发起的流 |

注意: 在 sing-mux 模式下，只有客户端创建流，所有 StreamID 均为奇数。

---

## 6. 依赖关系

### 6.1 smux 模块向外依赖

```
smux 模块
├── multiplex::core (抽象基类)
├── multiplex::duct / parcel (流管道)
├── channel::transport (传输层接口)
├── resolve::router (地址解析)
├── memory (PMR 分配器)
├── trace (日志)
└── boost::asio::experimental::concurrent_channel (发送通道)
```

### 6.2 外部模块对 smux 的依赖

```
multiplex::bootstrap ──► smux::craft (Protocol=0x00 时创建)
pipeline::primitives ──► multiplex::core (通过 bootstrap 接入)
```

---

## 7. 配置参数

### 7.1 smux 子配置

```json
{
  "mux": {
    "smux": {
      "max_streams": 32,
      "keepalive_interval_ms": 30000,
      "buffer_size": 4096,
      "udp_idle_timeout_ms": 60000,
      "udp_max_datagram": 65535
    }
  }
}
```

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `max_streams` | 32 | 单会话最大流数 |
| `keepalive_interval_ms` | 30000 | NOP 心跳间隔（毫秒），0 则禁用 |
| `buffer_size` | 4096 | 每流读取缓冲区大小（字节） |
| `udp_idle_timeout_ms` | 60000 | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | 65535 | UDP 数据报最大长度（字节） |