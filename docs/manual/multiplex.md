# 多路复用模块设计

位置：`include/prism/multiplex/`、`src/prism/multiplex/`

命名空间：`psm::multiplex`

## 概述

多路复用模块实现 smux 协议服务端，兼容 xtaci/smux v1 帧协议和 sing-mux 协商层。通过在单个 TCP/TLS 连接上承载多个独立流，减少连接开销，提升传输效率。

### 核心价值

- **连接复用**：单个 TCP/TLS 连接承载多个并发流
- **降低延迟**：避免重复 TCP/TLS 握手开销
- **资源节约**：减少文件描述符和内核连接跟踪表占用
- **协议无关**：core 层抽象，支持扩展其他 mux 协议

## 模块架构

```
┌──────────────────────────────────────────────────────────────────────┐
│                        craft (smux 协议实现)                          │
│  继承 core，实现 smux v1 帧协议 + sing-mux 协议协商                     │
│  - negotiate_protocol(): sing-mux 协商层                              │
│  - frame_loop(): 帧读取与三路分发                                      │
│  - send_loop(): scatter-gather 发送协程                               │
├──────────────────────────────────────────────────────────────────────┤
│                         core (抽象基类)                               │
│  流生命周期管理、发送串行化、pending/duct/parcel 状态跟踪               │
│  - send_data()/send_fin(): 纯虚，由子类实现帧发送                      │
├───────────────────────────────┬──────────────────────────────────────┤
│       duct (TCP 流管道)       │       parcel (UDP 数据报管道)         │
│  target_read_loop: 下载方向   │  relay_datagram: 请求-响应模型        │
│  target_write_loop: 上传方向  │  idle_timer: 空闲超时管理              │
│  write_channel_: 反压解耦     │  egress_socket_: 按需创建             │
├───────────────────────────────┴──────────────────────────────────────┤
│                       smux::frame                                    │
│  帧编解码、地址解析、UDP 数据报构建                                    │
│  - build_header(): 8 字节帧头构建（零拷贝）                            │
│  - outbound_frame: header + payload 分离结构                         │
└──────────────────────────────────────────────────────────────────────┘
```

### 设计原则

1. **协议无关抽象**：core 层提供通用流管理，duct/parcel 通过虚函数发送帧
2. **单线程执行**：每个 mux 会话绑定一个 executor，避免锁竞争
3. **协程原生**：所有 IO 操作使用 `co_await`，无回调
4. **PMR 内存**：所有容器使用 PMR 分配器，热路径零堆分配
5. **非阻塞分发**：PSH 帧通过 `co_spawn(detached)` 分发，消除队头阻塞

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
                         ┌────────────────────────────────────┐
         mux 客户端 ◄────│              duct                  │────► target 服务器
                         │                                    │
    send_data() ◄────────│  target_read_loop()               │
    (通过 core 虚函数)    │  读 target → 发回 mux              │
                         │                                    │
                         │  on_mux_data()                     │
                         │      │                             │
                         │      ▼                             │
                         │  write_channel_ ──────► target_write_loop()
                         │  (有界通道，反压)         (独立协程写入)
                         └────────────────────────────────────┘
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
                         ┌────────────────────────────────────┐
         mux 客户端 ─────►│             parcel                 │────► 目标服务器
                         │                                    │
        on_mux_data()    │  relay_datagram()                  │    async_send_to()
        (非阻塞 co_spawn) │  解析 → DNS → 发送 → 等待 → 编码   │◄─── async_receive_from()
                         │                                    │
                         │  idle_timer_                       │
                         │  (每次活动重置，超时关闭)            │
                         └────────────────────────────────────┘
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

    // 2. TCP 流：非阻塞 dispatch
    if (ducts_.contains(stream_id))
    {
        co_spawn(executor(), [dp, p] { co_await dp->on_mux_data(p); }, detached);
        return;
    }

    // 3. UDP 流：非阻塞 dispatch
    if (parcels_.contains(stream_id))
    {
        co_spawn(executor(), [dp, p] { co_await dp->on_mux_data(p); }, detached);
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

## 配置

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
            "max_streams": 32,
            "buffer_size": 65535,
            "keepalive_interval_ms": 30000,
            "udp_idle_timeout_ms": 60000
        }
    }
}
```

## 与 Trojan 协议的集成

Trojan 原生 mux 通过 cmd=0x7F 触发：

```
+---------------------------------------------------------------------+
|                     Trojan 握手流程                                  |
+---------------------------------------------------------------------+
| 1. TLS 握手                                                         |
| 2. 读取 Trojan 头部                                                 |
|    - 凭据验证                                                       |
|    - cmd 字段检测                                                   |
+---------------------------------------------------------------------+
| cmd = 0x01 (CONNECT)                                                |
|   └─► 建立 TCP 隧道                                                 |
|                                                                     |
| cmd = 0x03 (UDP_ASSOCIATE)                                          |
|   └─► 建立 UDP 中继                                                 |
|                                                                     |
| cmd = 0x7F (MUX)                                                    |
|   └─► 创建 smux::craft 实例                                         |
|       - sing-mux 协议协商                                           |
|       - 帧循环处理多流                                               |
|       - 每个 SYN 创建新流                                            |
+---------------------------------------------------------------------+
```

详见 [Trojan 协议文档](../protocols/trojan.md)。

## 数据流图

```
                              ┌─────────────────────────────────────┐
                              │             craft                   │
                              │           frame_loop()              │
                              └──────────────┬──────────────────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
              ▼                              ▼                              ▼
        ┌───────────┐                  ┌───────────┐                  ┌───────────┐
        │  SYN 帧   │                  │  PSH 帧   │                  │  FIN 帧   │
        └─────┬─────┘                  └─────┬─────┘                  └─────┬─────┘
              │                              │                              │
              ▼                              ▼                              ▼
     创建 pending_entry              dispatch_push()                   handle_fin()
     等待首 PSH 帧                   非阻塞三路分发：                   按序检查关闭：
                                    - pending: 累积数据               - pending: 删除
                                    - duct: co_spawn                  - duct: on_mux_fin()
                                    - parcel: co_spawn                - parcel: close()
              │                              │
              │            ┌─────────────────┴─────────────────┐
              │            │                                   │
              │            ▼                                   ▼
              │      ┌───────────┐                      ┌───────────┐
              │      │   duct    │                      │  parcel   │
              │      │target_read│                      │ relay_    │
              │      │ _loop()   │                      │ datagram()│
              │      │target_write│                     │           │
              │      │ _loop()   │                      │           │
              │      └─────┬─────┘                      └─────┬─────┘
              │            │                                   │
              │            ▼                                   ▼
              │      ┌───────────┐                      ┌───────────┐
              │      │  target   │                      │UDP socket │
              │      │  TCP 连接  │                      │           │
              │      └───────────┘                      └───────────┘
              │
              └──────────────────────────────────────────────────►
                              流激活 (activate_stream)
                              解析地址 → 连接目标 → 创建管道
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
- PSH 分发使用 `co_spawn(detached)`，不阻塞帧循环
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
| sing-box | smux v1 + sing-mux | 完全兼容 |
| Clash Meta | smux v1 + sing-mux | 完全兼容 |
| v2ray-plugin | yamux | 不兼容 |
| xtaci/smux v2 | smux v2 (UPD) | 不兼容 |
