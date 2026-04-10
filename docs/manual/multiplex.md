# 多路复用模块设计

位置：`include/prism/multiplex/`、`src/prism/multiplex/`

命名空间：`psm::multiplex`

## 概述

多路复用模块实现 smux 和 yamux 两种多路复用协议的服务端，通过 sing-mux 协商层
在运行时选择具体协议。smux 兼容 xtaci/smux v1 帧协议，yamux 兼容 Hashicorp/yamux
帧协议，均提供完整的流量控制能力。通过在单个 TCP/TLS 连接上承载多个独立流，
减少连接开销，提升传输效率。

### 核心价值

- **连接复用**：单个 TCP/TLS 连接承载多个并发流
- **降低延迟**：避免重复 TCP/TLS 握手开销
- **资源节约**：减少文件描述符和内核连接跟踪表占用
- **协议无关**：core 层抽象，支持扩展其他 mux 协议
- **多协议支持**：smux（轻量）和 yamux（流量控制），通过 sing-mux 协商选择

## 模块架构

```
  bootstrap (sing-mux 协商 + 协议分发)
  negotiate(): 读取协议头，选择 smux 或 yamux
  根据协商结果创建对应的 craft 实例
       │
       ├─ smux::craft (smux 协议)
       │   8 字节小端帧头, SYN/PSH/FIN/NOP 命令, 无流量控制
       │
       └─ yamux::craft (yamux 协议)
           12 字节大端帧头, Data/WindowUpdate/Ping/GoAway, 窗口流量控制
              │
              ▼
       core (抽象基类)
       流生命周期管理、发送串行化、pending/duct/parcel 状态跟踪
       send_data()/send_fin(): 纯虚，由子类实现帧发送
              │
              ├─ duct (TCP 流管道)
              │   target_read_loop: 下载方向
              │   target_write_loop: 上传方向
              │   write_channel_: 反压解耦
              │
              └─ parcel (UDP 数据报管道)
                  relay_datagram: 请求-响应模型
                  idle_timer: 空闲超时管理
                  egress_socket_: 按需创建
                     │
                     ▼
       smux::frame / yamux::frame
       帧编解码、地址解析、UDP 数据报构建
       outbound_frame: header + payload 分离结构
```

### 设计原则

1. **协议无关抽象**：core 层提供通用流管理，duct/parcel 通过虚函数发送帧
2. **单线程执行**：每个 mux 会话绑定一个 executor，避免锁竞争
3. **协程原生**：所有 IO 操作使用 `co_await`，无回调
4. **PMR 内存**：所有容器使用 PMR 分配器，热路径零堆分配
5. **非阻塞分发**：PSH 帧通过带异常回调的 `co_spawn` 分发，消除队头阻塞，异常时关闭对应流

## 核心组件

### core

位置：[core.hpp](../../include/prism/multiplex/core.hpp)、[core.cpp](../../src/prism/multiplex/core.cpp)

抽象基类，管理流生命周期和发送串行化。

#### 流状态管理

```cpp
memory::unordered_map<std::uint32_t, pending_entry> pending_;           // 等待地址
memory::unordered_map<std::uint32_t, std::shared_ptr<duct>> ducts_;     // TCP 流
memory::unordered_map<std::uint32_t, std::shared_ptr<parcel>> parcels_; // UDP 流
```

#### 关键方法

| 方法 | 说明 |
|------|------|
| `start()` | 通过 `co_spawn` 启动 `run()` 协程，设置异常处理 |
| `close()` | 原子标记非活跃，`std::move` 取出管道后逐一关闭 |
| `send_data(stream_id, vector<byte>)` | 纯虚，发送 PSH 帧，payload 通过 move 传递 |
| `send_fin(stream_id)` | 纯虚，异步发送 FIN 帧，不阻塞调用者 |
| `executor()` | 纯虚，返回 transport 的 executor |
| `remove_duct(stream_id)` | 虚函数，从 ducts_ 移除，子类可 override 清理协议特定资源 |
| `remove_parcel(stream_id)` | 虚函数，从 parcels_ 移除，子类可 override 清理协议特定资源 |
| `run()` | 纯虚，协议主循环 |

#### pending_entry 结构

```cpp
struct pending_entry
{
    memory::vector<std::byte> buffer; // 累积的地址+数据
    bool connecting = false;          // 是否已发起连接

    explicit pending_entry(memory::resource_pointer mr);
};
```

累积首 PSH 帧数据，数据足够（>=7 字节）时解析地址并发起连接。

### duct

位置：[duct.hpp](../../include/prism/multiplex/duct.hpp)、[duct.cpp](../../src/prism/multiplex/duct.cpp)

TCP 流双向转发管道，构造时已持有已连接的 target。

#### 数据流

```
  mux 客户端 ◄── duct ──► target 服务器
                    │
       send_data() ◄── target_read_loop()
       (通过 core 虚函数)  读 target → 发回 mux
                    │
                    ▼
       on_mux_data()
                    │
                    ▼
       write_channel_ ──► target_write_loop()
       (有界通道，反压)     (独立协程写入)
```

#### 双向路径

| 方向 | 客户端视角 | 方法 | 说明 |
|------|-----------|------|------|
| 下载 | target → mux | `target_read_loop()` | 独立协程，读 target 后通过 `send_data()` 发回 |
| 上传 | mux → target | `on_mux_data()` → `write_channel_` → `target_write_loop()` | 解耦帧循环与 target 写入 |

#### 关键实现

- **零拷贝上行**：`target_read_loop()` 直接读入 PMR vector，move 传递给 `send_data()`
- **反压解耦**：`write_channel_` 有界容量（32），防止快生产者淹没慢 target
- **半关闭处理**：`on_mux_fin()` 仅关闭 `write_channel_`，等待 target 端关闭后才完全关闭
- **读取上限**：`read_size_ = min(buffer_size, 65535)`，防止 uint16_t 溢出

#### 半关闭状态机

```
           on_mux_fin()                    target EOF
               │                               │
               ▼                               ▼
       mux_closed_ = true              target_closed_ = true
               │                               │
               └───────────────┬───────────────┘
                               │
                       两端均关闭后
                               │
                               ▼
                          close()
```

### parcel

位置：[parcel.hpp](../../include/prism/multiplex/parcel.hpp)、[parcel.cpp](../../src/prism/multiplex/parcel.cpp)

UDP 数据报中继管道，每个 PSH 帧承载一个 SOCKS5 UDP relay 格式数据报。

#### 工作流程

```
  mux 客户端 ──► parcel ──► 目标服务器
                   │
  on_mux_data()    │    relay_datagram()
  (非阻塞 co_spawn)│    解析 → DNS → 发送 → 等待 → 编码
                   │         │      ▲
                   │         ▼      │
                   │   async_send_to()  async_receive_from()
                   │
                   └─ idle_timer_
                      (每次活动重置，超时关闭)
```

#### 关键实现

- **请求-响应模型**：`relay_datagram()` 串行处理单次 DNS → 发送 → 等待响应 → 编码回传
- **空闲超时**：`idle_timer_` 管理生命周期，每次收到数据重置，超时自动关闭
- **Socket 按需创建**：`ensure_socket()` 根据目标协议类型创建 UDP socket，支持 IPv4/IPv6 切换
- **IP 字面量优化**：`router_.resolve_datagram_target()` 直接识别 IP 地址，跳过 DNS 解析

## smux 协议实现

### craft

位置：[craft.hpp](../../include/prism/multiplex/smux/craft.hpp)、[craft.cpp](../../src/prism/multiplex/smux/craft.cpp)

smux 多路复用会话服务端，兼容 xtaci/smux v1 帧协议 + sing-mux 协商层。

#### 协程入口

```cpp
auto craft::run() -> net::awaitable<void>
{
    // 1. 启动独立发送循环
    net::co_spawn(executor(), send_loop(), net::detached);

    // 2. 协议协商
    if (const auto ec = co_await negotiate_protocol())
        co_return;

    // 3. 帧循环
    co_await frame_loop();
}
```

#### 协议协商

sing-mux 协议头格式：

```
+----------------+----------------+----------------------------------+
| VERSION (1B)   | PROTOCOL (1B)  | [可选] PADDING (Version > 0)     |
+----------------+----------------+----------------------------------+
                                │
                     Version > 0 时:
                +----------------+----------------+
                | PadLen (2B BE) | Padding (N B)  |
                +----------------+----------------+
```

#### 帧循环与三路分发

```cpp
auto craft::frame_loop() -> net::awaitable<void>
{
    while (active_)
    {
        // 1. 读取 8 字节帧头
        co_await transport_->async_read(frame_buffer, ec);
        auto hdr = deserialization(frame_buffer);

        // 2. 读取载荷
        co_await transport_->async_read(payload, ec);

        // 3. 按命令分发
        switch (hdr.cmd)
        {
        case command::syn:  co_await handle_syn(hdr.stream_id); break;
        case command::push: dispatch_push(hdr.stream_id, payload); break;
        case command::fin:  handle_fin(hdr.stream_id); break;
        case command::nop:  break;
        }
    }
}
```

#### PSH 非阻塞三路分发

```cpp
void craft::dispatch_push(stream_id, payload)
{
    // 1. Pending 流：累积数据，可能触发连接
    if (pending_.contains(stream_id))
    {
        entry.buffer.append(payload);
        if (数据足够 && !entry.connecting)
            co_spawn(activate_stream(stream_id));
        return;
    }

    // 2. TCP 流：非阻塞分发，带异常回调
    if (ducts_.contains(stream_id))
    {
        co_spawn(executor(), [dp, p] { co_await dp->on_mux_data(p); },
                 [](ep) { dp->close(); });
        return;
    }

    // 3. UDP 流：非阻塞分发，带异常回调
    if (parcels_.contains(stream_id))
    {
        co_spawn(executor(), [dp, p] { co_await dp->on_mux_data(p); },
                 [](ep) { dp->close(); });
    }
}
```

#### 发送路径：scatter-gather 零拷贝

```cpp
// outbound_frame: header 与 payload 分离
struct outbound_frame
{
    std::array<std::byte, 8> header;   // 编码后的帧头
    memory::vector<std::byte> payload; // 载荷（move 传递）
};

// push_frame: 构建分离帧，推入通道
auto craft::push_frame(cmd, stream_id, payload) -> net::awaitable<void>
{
    outbound_frame frame;
    frame.header = build_header(cmd, stream_id, payload.size());
    frame.payload = std::move(payload);  // 零拷贝
    co_await channel_.async_send({}, std::move(frame));
}

// send_loop: scatter-gather 写入
auto craft::send_loop() -> net::awaitable<void>
{
    while (is_active())
    {
        auto frame = co_await channel_.async_receive();

        co_await transport_->async_write(frame.header);   // 写帧头
        if (!frame.payload.empty())
            co_await transport_->async_write(frame.payload); // 写载荷
    }
}
```

### frame

位置：[frame.hpp](../../include/prism/multiplex/smux/frame.hpp)、[frame.cpp](../../src/prism/multiplex/smux/frame.cpp)

smux 帧协议编解码。

#### 帧格式

```
+----------------+----------------+----------------+------------------+
| VERSION (1B)   | CMD (1B)       | LENGTH (2B LE) | STREAMID (4B LE) |
+----------------+----------------+----------------+------------------+
|                     PAYLOAD (最大 65535 字节)                       |
+---------------------------------------------------------------------+
```

#### 命令类型

| 命令 | 值 | 说明 |
|------|-----|------|
| SYN | 0x00 | 新建流，服务端创建 pending_entry |
| FIN | 0x01 | 半关闭流，通知对端不再发送 |
| PSH | 0x02 | 数据推送，携带负载数据 |
| NOP | 0x03 | 心跳，服务端不回复 |

#### 地址格式

**sing-mux StreamRequest（首 PSH 帧）**：

```
+----------------+----------------+----------------+------------------+
| FLAGS (2B BE)  | ATYP (1B)      | Addr Variable  | PORT (2B BE)     |
+----------------+----------------+----------------+------------------+
```

- FLAGS bit0：标识 UDP 流
- ATYP：0x01 IPv4、0x03 域名、0x04 IPv6

**SOCKS5 UDP Relay**：

```
+----------------+----------------+----------------+------------------+
| ATYP (1B)      | Addr Variable  | PORT (2B BE)   | Payload          |
+----------------+----------------+----------------+------------------+
```

#### 关键函数

| 函数 | 说明 |
|------|------|
| `build_header()` | 构建 8 字节帧头为数组（零拷贝） |
| `deserialization()` | 解析帧头，校验版本和命令有效性 |
| `parse_mux_address()` | 解析 sing-mux StreamRequest 地址 |
| `parse_udp_datagram()` | 解析 SOCKS5 UDP relay 数据报 |
| `build_udp_datagram()` | 构建 UDP 数据报响应 |

## yamux 协议实现

### craft

位置：[craft.hpp](../../include/prism/multiplex/yamux/craft.hpp)、[craft.cpp](../../src/prism/multiplex/yamux/craft.cpp)

yamux 多路复用会话服务端，兼容 Hashicorp/yamux 帧协议 + sing-mux 协商层。
与 smux 相比，yamux 提供完整的流量控制（256KB 初始窗口）、标志位系统和 Ping 心跳。

#### 协程入口

```cpp
auto craft::run() -> net::awaitable<void>
{
    // 1. 启动独立发送循环
    const auto self = std::static_pointer_cast<craft>(shared_from_this());
    net::co_spawn(executor(), self->send_loop(), net::detached);

    // 2. 帧循环（协议协商由 bootstrap 在外部完成）
    co_await frame_loop();
    channel_.cancel();
}
```

#### 帧循环与消息分发

```cpp
auto craft::frame_loop() -> net::awaitable<void>
{
    while (active_)
    {
        // 1. 读取 12 字节帧头
        co_await transport_->async_read(recv_buffer_, ec);
        auto hdr = parse_header(recv_buffer_);

        // 2. Data 帧读取载荷，其他类型帧只有 12 字节头
        if (hdr.type == message_type::data && hdr.length > 0)
        {
            // 载荷长度校验，防止恶意大帧导致 OOM
            if (hdr.length > 65535)
            {
                co_await push_frame(GoAway, protocol_error);
                break;
            }
            co_await transport_->async_read(payload, ec);
        }

        // 3. 按消息类型分发
        switch (hdr.type)
        {
        case message_type::data:           co_await handle_data(hdr, payload); break;
        case message_type::window_update:  co_await handle_window_update(hdr); break;
        case message_type::ping:           co_await handle_ping(hdr); break;
        case message_type::go_away:        co_await handle_go_away(hdr); break;
        }
    }
}
```

#### Data 帧标志位处理

```cpp
auto craft::handle_data(hdr, payload)
{
    if (has_flag(hdr.flag, flags::syn))    co_await handle_syn(stream_id, payload);  // 新建流
    if (has_flag(hdr.flag, flags::rst))    handle_rst(stream_id);                    // 强制重置
    if (has_flag(hdr.flag, flags::fin))    handle_fin(stream_id);                    // 半关闭
    // 无标志：纯数据分发
    co_await dispatch_data(stream_id, payload);
}
```

#### 窗口管理

- 每个流维护独立的 `stream_window`，包含 `send_window`、`recv_window`、`recv_consumed`
- SYN 后回复 `WindowUpdate(ACK)` 携带服务端初始窗口大小（256KB）
- 接收数据后累积 `recv_consumed`，达到窗口一半时发送 `WindowUpdate(none)`
- 发送窗口由对端的 `WindowUpdate` 原子增加，支持并发访问
- `send_data()` 窗口不足时等待重试（最多 4 次，每次 30ms），超时后丢弃并记录警告
- 普通窗口更新仅查找已有窗口（`get_window`），不为未知流创建窗口对象
- 窗口状态随 duct/parcel 关闭自动清理（通过 override `remove_duct`/`remove_parcel`）

#### Ping 心跳

- 收到 `Ping(SYN)` 回复 `Ping(ACK)` 携带相同 ID
- 收到 `Ping(ACK)` 记录日志，不做额外处理

### frame

位置：[frame.hpp](../../include/prism/multiplex/yamux/frame.hpp)、[frame.cpp](../../src/prism/multiplex/yamux/frame.cpp)

yamux 帧协议编解码。

#### 帧格式

```
+----------+----------+----------+----------+----------+----------+
| Version  |  Type    |  Flags   |  StreamID (4B BE)  |  Length (4B BE)  |
| (1B)     |  (1B)    |  (2B BE) |                    |                  |
+----------+----------+----------+----------+----------+----------+
|                    PAYLOAD (Length 字节)                        |
+---------------------------------------------------------------+
```

#### 消息类型

| 类型 | 值 | 说明 |
|------|-----|------|
| Data | 0x00 | 数据传输，可携带 SYN/FIN/RST 标志 |
| WindowUpdate | 0x01 | 窗口更新，Length 为增量值 |
| Ping | 0x02 | 心跳探测，Length 为 Ping ID |
| GoAway | 0x03 | 关闭会话，Length 为终止原因码 |

#### 标志位

| 标志 | 值 | 说明 |
|------|-----|------|
| none | 0x0000 | 无标志，普通数据帧 |
| SYN | 0x0001 | 同步，用于新建流或发起 Ping |
| ACK | 0x0002 | 确认，用于确认流创建或 Ping 响应 |
| FIN | 0x0004 | 半关闭，通知对端不再发送 |
| RST | 0x0008 | 重置，强制终止流 |

#### GoAway 原因码

| 原因码 | 值 | 说明 |
|--------|-----|------|
| normal | 0x00000000 | 正常关闭 |
| protocol_error | 0x00000001 | 协议错误 |
| internal_error | 0x00000002 | 内部错误 |

#### 关键函数

| 函数 | 说明 |
|------|------|
| `build_header()` | 构建 12 字节帧头为数组（零拷贝） |
| `parse_header()` | 解析帧头，校验版本和类型有效性 |
| `build_data_frame()` | 构建 Data 帧（12 字节头 + payload） |
| `build_window_update_frame()` | 构建 WindowUpdate 帧 |
| `build_ping_frame()` | 构建 Ping 帧 |
| `build_go_away_frame()` | 构建 GoAway 帧 |

## 配置

位置：[config.hpp](../../include/prism/multiplex/config.hpp)

各协议拥有独立的配置结构，顶层 config 仅负责协议选择和全局开关：

```cpp
// 顶层配置
struct config
{
    protocol_type protocol = protocol_type::smux; // 协议类型
    bool enabled = false;                          // 是否启用
    smux::config smux;                             // smux 协议配置
    yamux::config yamux;                           // yamux 协议配置
};

// smux 协议配置（独立）
struct smux::config
{
    std::uint32_t max_streams = 32;              // 单会话最大并发流数
    std::uint32_t buffer_size = 4096;            // 每流读取缓冲区大小
    std::uint32_t keepalive_interval_ms = 30000; // 心跳间隔（毫秒）
    std::uint32_t udp_idle_timeout_ms = 60000;   // UDP 管道空闲超时（毫秒）
    std::uint32_t udp_max_datagram = 65535;      // UDP 数据报最大长度
};

// yamux 协议配置（独立）
struct yamux::config
{
    std::uint32_t max_streams = 32;                // 单会话最大并发流数
    std::uint32_t buffer_size = 4096;              // 每流读取缓冲区大小
    std::uint32_t initial_window = 256 * 1024;     // 初始流窗口大小
    bool enable_ping = true;                       // 是否启用心跳
    std::uint32_t ping_interval_ms = 30000;        // 心跳间隔（毫秒）
    std::uint32_t stream_open_timeout_ms = 30000;  // 流打开超时（毫秒）
    std::uint32_t stream_close_timeout_ms = 30000; // 流关闭超时（毫秒）
    std::uint32_t udp_idle_timeout_ms = 60000;     // UDP 管道空闲超时（毫秒）
    std::uint32_t udp_max_datagram = 65535;        // UDP 数据报最大长度
};
```

位置：[config.hpp](../../include/prism/multiplex/config.hpp)

```cpp
struct config
{
    bool enabled = false;                   // 是否启用多路复用
    std::uint32_t max_streams = 32;         // 单会话最大并发流数
    std::uint32_t buffer_size = 4096;       // 每流读取缓冲区大小，实际限制 min(buffer_size, 65535)
    std::uint32_t keepalive_interval_ms = 30000; // 心跳间隔（毫秒），0 表示禁用
    std::uint32_t udp_idle_timeout_ms = 60000;   // UDP 管道空闲超时（毫秒）
    std::uint32_t udp_max_datagram = 65535;      // UDP 数据报最大长度
};
```

### 配置示例

```json
{
    "agent": {
        "mux": {
            "enabled": true,
            "smux": {
                "max_streams": 512,
                "buffer_size": 65535,
                "keepalive_interval_ms": 30000,
                "udp_idle_timeout_ms": 60000,
                "udp_max_datagram": 65535
            },
            "yamux": {
                "max_streams": 32,
                "buffer_size": 4096,
                "initial_window": 262144,
                "enable_ping": true,
                "ping_interval_ms": 30000,
                "stream_open_timeout_ms": 30000,
                "stream_close_timeout_ms": 30000,
                "udp_idle_timeout_ms": 60000,
                "udp_max_datagram": 65535
            }
        }
    }
}
```

## 与 Trojan 协议的集成

Trojan 原生 mux 通过 cmd=0x7F 触发，由 bootstrap 完成 sing-mux 协商后
根据客户端选择的协议创建对应的 craft 实例：

```
  Trojan 握手流程
       │
       ├─ 1. TLS 握手
       └─ 2. 读取 Trojan 头部
            ├─ 凭据验证
            └─ cmd 字段检测
                 │
                 ├─ cmd = 0x01 (CONNECT)
                 │   └─► 建立 TCP 隧道
                 │
                 ├─ cmd = 0x03 (UDP_ASSOCIATE)
                 │   └─► 建立 UDP 中继
                 │
                 └─ cmd = 0x7F (MUX)
                     └─► bootstrap 执行 sing-mux 协商
                         ├─ 读取协议头 [Version 1B][Protocol 1B]
                         ├─ Protocol = 0 → smux::craft（smux v1 帧协议）
                         ├─ Protocol = 1 → yamux::craft（yamux 帧协议）
                         ├─ 帧循环处理多流
                         └─ 每个 SYN/WindowUpdate(SYN) 创建新流
```

详见 [Trojan 协议文档](../protocols/trojan.md)。

## 数据流图

```
  craft.frame_loop()
       │
       ├────────────────┼────────────────┐
       │                │                │
       ▼                ▼                ▼
  SYN 帧           PSH 帧           FIN 帧
       │                │                │
       ▼                ▼                ▼
  创建 pending    dispatch_push()    handle_fin()
  等待首 PSH 帧   非阻塞三路分发：   按序检查关闭：
                  ├─ pending: 累积   ├─ pending: 删除
                  ├─ duct: co_spawn  ├─ duct: on_mux_fin()
                  └─ parcel: co_spawn└─ parcel: close()
                        │                │
                        ▼                ▼
                   duct               parcel
                   target_read_loop() relay_datagram()
                   target_write_loop()
                        │                │
                        ▼                ▼
                   target TCP 连接    UDP socket

  流激活 (activate_stream): 解析地址 → 连接目标 → 创建管道
```

## 性能考量

### 内存分配

- 所有容器使用 PMR 分配器，从 `memory::resource` 分配
- `target_read_loop()` 每次读取直接分配 vector，PMR 池复用同大小块
- `outbound_frame` 的 header 是栈上数组，payload 通过 move 传递
- scatter-gather 写入消除 header + payload 拼接的 memcpy

### 并发模型

- 每个 mux 会话绑定单个 executor，无锁设计
- 发送通过 `concurrent_channel` 串行化，容量 = `max_streams`
- PSH 分发使用带异常回调的 `co_spawn`，不阻塞帧循环
- duct 的 `write_channel_` 容量 32，提供反压

### 反压机制

- **上传方向**：`on_mux_data()` 推入 `write_channel_`，满时挂起调用者
- **下载方向**：`target_read_loop()` 直接 move 数据到 `send_data()`
- **发送方向**：`channel_` 满时 `push_frame()` 挂起，自然反压所有流

## 注意事项

1. **发送串行化**：所有帧发送必须通过 `channel_`，否则帧会交错
2. **非阻塞 PSH**：`dispatch_push()` 对已连接流使用 `co_spawn(detached)`，避免队头阻塞
3. **半关闭处理**：`on_mux_fin()` 仅关闭 `write_channel_`，等待对端关闭
4. **UDP 空闲超时**：UDP 管道无数据时自动清理，避免资源泄漏
5. **流 ID 复用**：FIN 后流 ID 可被复用，需确保旧流完全关闭
6. **buffer_size 上限**：实际读取量限制为 `min(buffer_size, 65535)`
7. **PMR 内存**：所有容器必须传入 PMR 分配器

## 兼容性

| 客户端 | 协议 | 兼容性 |
|--------|------|--------|
| mihomo-Meta | smux v1 + sing-mux | 完全兼容 |
| mihomo-Meta | yamux + sing-mux | 完全兼容 |
| sing-box | smux v1 + sing-mux | 完全兼容 |
| sing-box | yamux + sing-mux | 完全兼容 |
| Clash Meta | smux v1 + sing-mux | 完全兼容 |
| Clash Meta | yamux + sing-mux | 完全兼容 |
| v2ray-plugin | yamux（无 sing-mux 协商） | 不兼容 |
| xtaci/smux v2 | smux v2 (UPD) | 不兼容 |

## 测试

### 基准测试

位置：`benchmarks/mux_bench.cpp`

使用 Google Benchmark 框架测量帧编解码性能。覆盖所有公共纯函数，无 I/O 依赖。

**运行方式**：

```bash
build_release/benchmarks/mux_bench.exe
```

**覆盖范围**：

| 类别 | 基准函数 | 说明 |
|------|----------|------|
| smux 帧头 | `BM_SmuxFrameDeserialize_*` | SYN/FIN/PSH/NOP 四种命令的帧头解析 |
| smux 地址 | `BM_SmuxParseMuxAddress_*` | IPv4/域名/变长域名地址解析 |
| smux UDP | `BM_SmuxParseUdpDatagram_*` | SOCKS5 UDP 数据报解析 |
| smux UDP | `BM_SmuxBuildUdpDatagram_*` | UDP 数据报编码（IPv4/域名），参数化 payload 大小 |
| smux LP | `BM_SmuxBuildUdpLengthPrefixed` | Length-prefixed UDP 编码 |
| yamux 帧头 | `BM_YamuxBuildHeader` / `BM_YamuxParseHeader` | 12 字节帧头编解码 |
| yamux 特化 | `BM_YamuxBuild*Frame` | WindowUpdate/Ping/GoAway 帧构建 |
| 跨协议对比 | `BM_MuxFrameDecode_*` | smux vs yamux 帧解码吞吐量，参数化 payload 大小 |

### 压力测试

位置：`stresses/mux_stress.cpp`

验证帧编解码在高并发和大量数据下的正确性与稳定性。

**运行方式**：

```bash
build_release/stresses/mux_stress.exe
```

**测试场景**：

| 场景 | 说明 | 验证点 |
|------|------|--------|
| 帧解码风暴 | 单线程高频解码混合 smux/yamux 帧 | 解析成功率、内存峰值 |
| 并发编解码 | 多线程同时编解码 + 地址解析 + UDP 构建 | 线程安全、counting_resource 内存跟踪 |
| 地址解析覆盖 | IPv4/域名(短+长)/IPv6 全格式覆盖 | 解析结果正确性（host、port 一致） |
| UDP 往返验证 | build → parse 往返验证 IPv4/域名/LP 三种格式 | 数据完整性（payload 字节一致） |
