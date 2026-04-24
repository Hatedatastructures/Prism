# yamux 协议 — 多路复用模块

## 1. 模块概述

yamux 是 Prism 实现的 Hashicorp/yamux 兼容多路复用协议，通过 sing-mux 协商接入（Protocol=0x01）。与 smux 相比，yamux 提供更完善的流量控制机制（256KB 初始流窗口）、标志位系统和 Ping 心跳探测。它在单个 TCP 连接上承载多个独立的双向字节流，适用于高并发、大数据量的代理场景。

### 协议栈

```
Application (HTTP/SOCKS5)
   │
   ├─ yamux::duct / yamux::parcel   // TCP 流管道 / UDP 数据报管道
   │
   ├─ yamux::craft                  // 帧编解码 + 窗口管理
   │    12-byte header: [Ver][Type][Flags][StreamID][Length]
   │
   ├─ multiplex::core               // 协议无关抽象基类
   │    pending_ / ducts_ / parcels_ 流状态管理
   │
   ├─ sing-mux 协商                 // [Ver 1B][Proto 1B]
   │    Proto=0x01 → yamux
   │
   ├─ transport                     // TLS 隧道 / 明文
   │
   └─ TCP Socket
```

### 文件结构

```
include/prism/multiplex/
├── bootstrap.hpp               # 多路复用会话引导（sing-mux 协商 + 协议分流）
├── core.hpp                    # 协议无关抽象基类
├── config.hpp                  # 多路复用配置
├── duct.hpp                    # TCP 流管道
├── parcel.hpp                  # UDP 数据报管道
└── yamux/
    ├── craft.hpp               # yamux 会话实现（帧读写 + 窗口管理 + 心跳）
    ├── frame.hpp               # yamux 帧格式定义 + 编解码函数
    └── config.hpp              # yamux 子配置

src/prism/multiplex/
├── core.cpp                    # core 基类实现
├── duct.cpp                    # duct TCP 管道实现
├── parcel.cpp                  # parcel UDP 管道实现
└── yamux/
    ├── craft.cpp               # yamux 会话实现
    └── frame.cpp               # yamux 帧编解码实现
```

---

## 2. 核心类型与类

### 2.1 yamux 帧格式

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/yamux/frame.hpp` |
| 实现文件 | `src/prism/multiplex/yamux/frame.cpp` |
| 命名空间 | `psm::multiplex::yamux` |

**12 字节定长帧头（大端序）:**

```
+--------+--------+--------+--------+
| Byte 0 | Byte 1 | Byte2-3| Byte4-7|
+--------+--------+--------+--------+
| Version| Type   | Flags  | Stream |
|  1B    |  1B    |  2B BE |  4B BE |
+--------+--------+--------+--------+
|          Length (4B BE)           |
+-----------------------------------+

Version  = 0x00 (yamux 规范固定值)
Type     = 消息类型
Flags    = 标志位组合（可叠加）
StreamID = uint32 BE, 0 表示会话级帧
Length   = uint32 BE, 含义因消息类型而异
```

**消息类型 (Type 字段):**

| 类型 | 值 | 含义 | Length 字段含义 |
|------|-----|------|----------------|
| `data` | 0x00 | 数据帧 | 载荷字节数 |
| `window_update` | 0x01 | 窗口更新帧 | 窗口增量 |
| `ping` | 0x02 | 心跳帧 | ping 标识符 |
| `go_away` | 0x03 | 会话终止帧 | 错误码 |

**标志位 (Flags 字段):**

| 标志 | 值 | 说明 |
|------|-----|------|
| `none` | 0x0000 | 无标志 |
| `syn` | 0x0001 | SYN 同步（打开流 / 心跳请求） |
| `ack` | 0x0002 | ACK 确认（确认流创建 / 心跳响应） |
| `fin` | 0x0004 | FIN 半关闭（发送端不再发送数据） |
| `rst` | 0x0008 | RST 重置（强制关闭流） |

**标志位与消息类型的组合语义:**

| Type + Flags | 语义 |
|-------------|------|
| `Data + SYN` | 携带地址数据的新流创建（sing-mux 兼容） |
| `Data + FIN` | 半关闭流 |
| `Data + RST` | 强制重置流 |
| `Data + none` | 纯数据传输 |
| `WindowUpdate + SYN` | 客户端打开新流（Length = 初始窗口） |
| `WindowUpdate + ACK` | 确认流创建（Length = 服务端初始窗口） |
| `WindowUpdate + none` | 普通窗口更新（Length = 窗口增量） |
| `WindowUpdate + RST` | 重置流 |
| `Ping + SYN` | 心跳请求（Length = ping ID） |
| `Ping + ACK` | 心跳响应（Length = 相同 ping ID） |
| `GoAway + none` | 会话终止（Length = 错误码） |

### 2.2 流窗口结构体

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/yamux/craft.hpp` |

```
struct stream_window                      // 流窗口状态（流量控制）
├── send_window           : atomic<uint32>  // 发送窗口（对端允许发送的数据量）
├── recv_consumed         : atomic<uint32>  // 已消费的接收数据量
└── window_signal         : shared_ptr<steady_timer>  // 窗口更新信号定时器

初始值:
    send_window = initial_stream_window (256KB = 262144)
    recv_consumed = 0
    window_signal = 永不超时定时器
```

### 2.3 yamux::craft (yamux 会话)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/multiplex/yamux/craft.hpp` |
| 实现文件 | `src/prism/multiplex/yamux/craft.cpp` |
| 命名空间 | `psm::multiplex::yamux` |

```
struct outbound_frame                     // 出站帧（12B header 与 payload 分离）
├── header                : array<byte, 12>  // 编码后的 12 字节帧头
└── payload               : memory::vector<byte>  // 帧载荷（move 传递）

class craft : core                          // yamux 会话
├── channel_              : concurrent_channel<outbound_frame>  // 发送通道
├── windows_              : unordered_map<uint32, unique_ptr<stream_window>>
├── pending_timers_       : unordered_map<uint32, shared_ptr<steady_timer>>
├── ping_id_              : atomic<uint32>
├── recv_buffer_          : array<byte, 12>   // 帧头读取缓冲
├── run()                 : awaitable<void>   // 协议主循环
├── frame_loop()          : awaitable<void>   // 帧读取 + 分发
├── send_loop()           : awaitable<void>   // 帧发送循环
├── ping_loop()           : awaitable<void>   // 主动 Ping 心跳循环
├── handle_data(hdr, payload): awaitable<void>  // Data 帧分发
├── handle_syn(sid, payload): awaitable<void>   // Data(SYN) 处理
├── handle_rst(sid)       : void              // RST 处理
├── handle_fin(sid)       : void              // FIN 处理
├── dispatch_data(sid, payload): awaitable<void>  // 三路分发
├── try_activate_pending(sid): void           // 尝试激活 pending 流
├── handle_window_update(hdr): awaitable<void>  // 窗口更新处理
├── handle_ping(hdr)      : awaitable<void>   // Ping 处理
├── handle_go_away(hdr)   : awaitable<void>   // GoAway 处理
├── activate_stream(sid)  : awaitable<void>   // 解析地址 + 连接目标
├── update_recv_window(sid, consumed): awaitable<void>  // 接收窗口更新
├── start_pending_timeout(sid): void          // pending 流超时定时器
├── get_or_create_window(sid): stream_window* // 获取或创建窗口
├── get_window(sid)       : stream_window*    // 查找窗口（不创建）
├── push_frame(type, flags, sid, len, payload): awaitable<void>
├── send_data(sid, payload): awaitable<void>  // 发送 Data 帧（含窗口检查）
├── send_fin(sid)         : void              // 异步发送 FIN
├── executor()            : any_io_executor
├── remove_duct(sid)      : void              // 清理 duct 窗口状态
├── remove_parcel(sid)    : void              // 清理 parcel 窗口状态
└── close()               : void              // 关闭会话（含窗口清理）
```

---

## 3. 架构与组件交互

### 3.1 与 smux 的关键差异

| 维度 | smux | yamux |
|------|------|-------|
| 帧头大小 | 8 字节 | 12 字节 |
| 字节序 | 小端 (LE) | 大端 (BE) |
| 版本号 | 0x01 | 0x00 |
| 流量控制 | 无 | 有（256KB 初始窗口） |
| 流创建 | SYN 帧 (Cmd=0x00) | Data(SYN) 或 WindowUpdate(SYN) |
| 心跳 | NOP 帧（单向，不回复） | Ping(SYN/ACK)（双向请求-响应） |
| 流重置 | 无 | RST 标志 + GoAway 帧 |
| 窗口管理 | 无 | stream_window 映射 |
| 帧载荷限制 | 65535 (uint16) | 65535 (代码中限制，uint32 字段) |

### 3.2 流量控制架构

```
// 发送路径: duct → yamux → transport
duct::target_read_loop
   → owner_->send_data(sid, move(payload))
   → yamux::craft::send_data()
        1. 检查 send_window (CAS 原子操作)
           if window < payload_size:
               window_signal->wait()  // 阻塞等待
           else:
               send_window -= payload_size  // 扣减
        2. push_frame(Data, none, sid, size, data)
   → channel_ → send_loop → transport

// 接收路径: transport → yamux → duct
transport → frame_loop → handle_data
   1. dispatch_data → duct.on_mux_data(data)
   2. update_recv_window(sid, consumed_size)
      recv_consumed += consumed
      if recv_consumed >= initial_window / 2:
          send WindowUpdate(none, delta)
          recv_consumed = 0
   → 窗口更新帧 → 对端 send_window 增加
```

### 3.3 窗口更新信号机制

```
// 发送方窗口不足时的挂起/唤醒机制
send_data()
   if send_window < payload_size:
       signal = window_signal  // copy shared_ptr
       signal->expires_at(max)
       co_await signal->async_wait()  // 挂起等待

       // 接收方收到数据，消费后:
       update_recv_window()
          → push_frame(WindowUpdate, delta)

       // 发送方收到 WindowUpdate:
       handle_window_update()
          → send_window += delta
          → window_signal->cancel()  // 唤醒发送方

   // 唤醒后重新获取窗口指针 → 重试扣减
```

---

## 4. 完整生命周期流程

### 4.1 完整 TCP 流生命周期（含 hex 帧示例）

**场景: 客户端通过 yamux 创建一条到 example.com:80 的 TCP 流**

```
// 阶段 1: sing-mux 协商
客户端 → Server: [sing-mux header]
   00 01    // Version=0, Protocol=0x01 (yamux)

// 阶段 2: 客户端通过 Data(SYN) 创建新流

// 方式 A — Data(SYN) 携带地址数据（sing-mux 兼容）:
客户端 → Server: [yamux frame: Data+SYN, StreamID=1]
   00 00 00 01 00 00 00 01 00 00 00 0E  [payload: 14 bytes]
   // Version=0x00, Type=0x00 (Data), Flags=0x0001 (SYN)
   // StreamID=1, Length=14
   // StreamRequest (同 smux):
   //   Flags = 00 00, ATYP = 03 (域名), Addr = "example.com", Port = 00 50 (80 BE)

// 方式 B — WindowUpdate(SYN) 打开流 + Data(none) 发送地址:
客户端 → Server: [yamux frame: WindowUpdate+SYN, StreamID=1]
   00 01 00 01 00 00 00 01 00 04 00 00
   // Type=0x01 (WindowUpdate), Flags=0x0001 (SYN), StreamID=1, Length=262144 (初始窗口)

客户端 → Server: [Data(none), StreamID=1, payload=14 bytes]
   00 00 00 00 00 00 00 01 00 00 00 0E  [StreamRequest...]

// Server 响应 (以方式 A 为例):
Server:
   1. handle_data(hdr) → has_flag(SYN) → handle_syn(1, payload)
   2. pending_.emplace(1)
   3. get_or_create_window(1)
   4. start_pending_timeout(1)
   5. 回复 WindowUpdate(ACK):

Server → 客户端: [yamux frame: WindowUpdate+ACK, StreamID=1]
   00 01 00 02 00 00 00 01 00 04 00 00
   // Type=0x01, Flags=0x0002 (ACK), StreamID=1, Length=262144 (服务端初始窗口)

   6. try_activate_pending(1)
      → activate_stream(1): parse address → connect → create duct[1]
   7. 发送 0x00 成功状态:

Server → 客户端: [yamux frame: Data(none), StreamID=1, payload=0x00]
   00 00 00 00 00 00 00 01 00 00 00 01  00
   // Length=1, payload=0x00 (成功状态)

// 阶段 3: 双向数据转发（含窗口跟踪）
// 初始: Server send_window[1]=262144, Client send_window[1]=262144

客户端 → Server: [Data(none), SID=1] HTTP GET / HTTP/1.1...
   00 00 00 00 00 00 00 01 00 00 00 xx  [HTTP GET 载荷]
Server:
   send_window[1] -= payload_size  // 扣减窗口
   → 转发到目标 TCP

Server → 客户端: [Data(none), SID=1] HTTP/1.1 200 OK...
   00 00 00 00 00 00 00 01 00 00 00 xx  [HTTP 200 载荷]

Server:
   消费数据 → update_recv_window(1, consumed)
   if recv_consumed >= 131072 (256KB/2):
       发送 WindowUpdate(none, delta=recv_consumed)
       recv_consumed = 0

Server → 客户端: [WindowUpdate(none), SID=1, delta=131072]
   00 01 00 00 00 00 00 01 00 02 00 00
   // Type=0x01, Flags=0x0000, StreamID=1, Length=131072
客户端: send_window[1] += 131072  // 恢复发送窗口

// 阶段 4: 流关闭 (FIN)
客户端 → Server: [Data+FIN, StreamID=1]
   00 00 00 04 00 00 00 01 00 00 00 00
   // Flags=0x0004 (FIN), Length=0

Server:
   handle_data → has_flag(FIN) → handle_fin(1)
   → duct.on_mux_fin()  // 半关闭

// 阶段 5: 服务端回复 FIN + 清理
Server → 客户端: [Data+FIN, StreamID=1]
   00 00 00 04 00 00 00 01 00 00 00 00

Server: remove_duct(1) → windows_.erase(1)
```

### 4.2 窗口流量控制详解

```
// 发送窗口状态机
send_window = 262144 (初始)

// 发送数据:
if send_window >= payload_size:
    CAS(send_window, send_window - size)
    发送成功
else:
    window_signal->wait()  // 挂起
    // 被 WindowUpdate 唤醒后重新获取窗口 → 重试

// 收到 WindowUpdate(delta):
send_window += delta
// 溢出检查: 钳制到 uint32_max
window_signal->cancel()  // 唤醒等待方

// 接收窗口管理:
recv_consumed += consumed_size
if recv_consumed >= 131072:
    send WindowUpdate(none, recv_consumed)
    recv_consumed = 0
```

### 4.3 Ping 心跳机制

```
// 主动 Ping (ping_loop):
while is_active():
    timer.expires_after(ping_interval)
    co_await timer.wait()
    id = ping_id_.fetch_add(1) + 1
    push_frame(Ping+SYN, sid=0, len=id)
    // 等待 Ping+ACK 回复

// 被动 Ping (handle_ping):
if has_flag(SYN):
    push_frame(Ping+ACK, sid=0, len=id)  // 回复相同的 ping ID
if has_flag(ACK):
    // Ping 响应，忽略
```

### 4.4 帧循环主协程序列图

```
// 帧循环主协程 (craft::frame_loop)
transport → craft::frame_loop: async_read 12B header
craft::frame_loop → craft: parse_header → frame_header

if hdr.type == Data && hdr.length > 0:
   transport → craft::frame_loop: async_read payload

switch hdr.type:
   case Data:
      → handle_data(hdr, payload)
           if has_flag(SYN):
               → handle_syn(sid, payload)
                    pending_.emplace(sid)
                    get_or_create_window(sid)   // → windows_.create
                    push_frame(WU+ACK, ...)
                    try_activate_pending(sid)
           elif has_flag(RST):
               → handle_rst(sid)
                    erase from pending_ / ducts_ / parcels_
                    windows_.erase(sid)
           elif has_flag(FIN):
               → handle_fin(sid)
                    duct.on_mux_fin() / parcel.close()
           else:
               → dispatch_data(sid, payload)
                    if sid in pending_:  累积 buffer → try_activate
                    elif sid in ducts_:   co_spawn duct.on_mux_data(payload)
                    elif sid in parcels_: co_spawn parcel.on_mux_data(payload)

   case WindowUpdate:
      → handle_window_update(hdr)
           if SYN && !ACK:   打开新流 → windows_.create
           elif SYN && ACK:   确认流创建
           elif RST:           重置流 → windows_.erase
           elif FIN:           半关闭
           else:              send_window += delta (CAS)
                              window_signal->cancel()  // 唤醒等待方

   case Ping:
      → handle_ping(hdr)
           if SYN: push_frame(Ping+ACK, sid=0, len=id)
           if ACK: 忽略

   case GoAway:
      → handle_go_away(hdr)
           close()
```

---

## 5. 关键算法

### 5.1 帧头编解码

```
// 编码: 12 字节大端序
build_header(hdr) → array<byte, 12>:
    [0]  = protocol_version (0x00)
    [1]  = hdr.type
    [2]  = hdr.flag >> 8             // Flags HI byte
    [3]  = hdr.flag & 0xFF           // Flags LO byte
    [4]  = hdr.stream_id >> 24       // StreamID byte 0
    [5]  = hdr.stream_id >> 16       // StreamID byte 1
    [6]  = hdr.stream_id >> 8        // StreamID byte 2
    [7]  = hdr.stream_id & 0xFF      // StreamID byte 3
    [8]  = hdr.length >> 24          // Length byte 0
    [9]  = hdr.length >> 16          // Length byte 1
    [10] = hdr.length >> 8           // Length byte 2
    [11] = hdr.length & 0xFF         // Length byte 3

// 解码: 12 字节大端序解析
parse_header(span) → optional<frame_header>:
    if span.size < 12: return nullopt
    hdr.version = span[0]
    hdr.type = span[1]
    hdr.flag = (span[2] << 8) | span[3]
    hdr.stream_id = (span[4]<<24)|(span[5]<<16)|(span[6]<<8)|span[7]
    hdr.length = (span[8]<<24)|(span[9]<<16)|(span[10]<<8)|span[11]
    if hdr.version != 0x00: return nullopt
    if hdr.type not in {0,1,2,3}: return nullopt
    return hdr
```

### 5.2 发送窗口扣减 (CAS 原子操作)

```
send_data(stream_id, payload):
    payload_size = payload.size()
    window = get_window(stream_id)
    if not window: return

    window_acquired = false
    while !window_acquired and is_active():
        old_val = window->send_window.load(acquire)
        while old_val >= payload_size:
            if CAS(old_val, old_val - payload_size, acq_rel):
                window_acquired = true
                break
        if window_acquired: break

        // 窗口不足，等待
        signal = window->window_signal  // 拷贝 shared_ptr 防析构
        signal->expires_at(max)
        co_await signal->async_wait()
        if wait_ec != operation_aborted:
            if !is_active(): return
            continue

        // 唤醒后重新获取窗口指针（可能在等待期间被移除）
        window = get_window(stream_id)
        if !window: return

    if !window_acquired: return  // 会话关闭或窗口移除

    push_frame(Data, none, stream_id, payload_size, move(payload))
```

### 5.3 接收窗口更新（阈值触发）

```
update_recv_window(stream_id, consumed):
    window = get_or_create_window(stream_id)
    total_consumed = recv_consumed.fetch_add(consumed, acq_rel) + consumed

    if total_consumed >= initial_window / 2 (131072):
        recv_consumed.store(0, release)
        push_frame(WindowUpdate, none, stream_id, total_consumed, {})
        // 对端收到后将 send_window += total_consumed
```

### 5.4 WindowUpdate 处理（多种标志位组合）

```
handle_window_update(hdr):
    stream_id = hdr.stream_id
    delta = hdr.length

    if stream_id == 0: return  // 会话级窗口更新，忽略

    if has_flag(RST):
        // 强制重置流
        erase from pending_/ducts_/parcels_
        cancel window_signal
        windows_.erase(stream_id)
        return

    if has_flag(FIN):
        // 半关闭
        erase from pending_ (含窗口)
        duct.on_mux_fin() if exists
        return

    if has_flag(SYN) and !has_flag(ACK):
        // 客户端打开新流 (WindowUpdate+SYN)
        if max_streams reached: reply RST; return
        pending_.emplace(stream_id)
        window = get_or_create_window(stream_id)
        client_window = (delta > 0) ? delta : config.initial_window
        window->send_window = client_window
        reply WindowUpdate(ACK, server_initial_window)
        start_pending_timeout(stream_id)
        return

    if has_flag(SYN) and has_flag(ACK):
        // 服务端发起流的确认（本实现不支持服务端发起）
        return

    // 普通窗口更新
    window = get_window(stream_id)
    if window and delta > 0:
        CAS(send_window, send_window + delta)  // 含溢出钳制
        window_signal->cancel()  // 唤醒等待的发送方
```

---

## 6. 依赖关系

### 6.1 yamux 模块向外依赖

```
yamux 模块
├── multiplex::core (抽象基类)
├── multiplex::duct / parcel (流管道)
├── multiplex::smux::frame (复用 parse_mux_address 地址解析)
├── channel::transport (传输层接口)
├── resolve::router (地址解析)
├── memory (PMR 分配器)
├── trace (日志)
└── boost::asio::experimental::concurrent_channel (发送通道)
```

### 6.2 外部模块对 yamux 的依赖

```
multiplex::bootstrap ──► yamux::craft (Protocol=0x01 时创建)
pipeline::primitives ──► multiplex::core (通过 bootstrap 接入)
```

---

## 7. 配置参数

### 7.1 yamux 子配置

```json
{
  "mux": {
    "yamux": {
      "max_streams": 32,
      "initial_window": 262144,
      "enable_ping": true,
      "ping_interval_ms": 30000,
      "buffer_size": 4096,
      "udp_idle_timeout_ms": 60000,
      "udp_max_datagram": 65535,
      "stream_open_timeout_ms": 30000,
      "stream_close_timeout_ms": 30000
    }
  }
}
```

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `max_streams` | 32 | 单会话最大流数 |
| `initial_window` | 262144 | 初始流窗口（256KB） |
| `enable_ping` | true | 心跳开关 |
| `ping_interval_ms` | 30000 | 主动 Ping 间隔（毫秒） |
| `buffer_size` | 4096 | 每流读取缓冲区大小（字节） |
| `udp_idle_timeout_ms` | 60000 | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | 65535 | UDP 数据报最大长度（字节） |
| `stream_open_timeout_ms` | 30000 | pending 流超时（毫秒），超时自动 RST |
| `stream_close_timeout_ms` | 30000 | 流关闭超时（毫秒），超时强制清理 |
