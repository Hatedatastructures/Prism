# 多路复用模块设计

位置：`include/prism/multiplex/`、`src/prism/multiplex/`

命名空间：`psm::multiplex`

## 概述

多路复用模块实现 smux 协议服务端，兼容 Mihomo/xtaci/smux v1 和 sing-mux 协商。通过在单个 TCP 连接上承载多个独立流，减少连接开销，提升传输效率。

### 核心价值

- **连接复用**：单个 TCP/TLS 连接承载多个并发流
- **降低延迟**：避免重复 TCP/TLS 握手开销
- **资源节约**：减少文件描述符和内核连接跟踪表占用
- **协议无关**：core 层抽象，支持扩展其他 mux 协议

## 模块架构

```
┌──────────────────────────────────────────────────────────────┐
│                        craft (smux 协议实现)                   │
│  继承 core，实现 smux v1 帧协议 + sing-mux 协议协商              │
├──────────────────────────────────────────────────────────────┤
│                         core (抽象基类)                        │
│  流生命周期管理、发送串行化、pending/duct/parcel 状态跟踪         │
├────────────────────────┬─────────────────────────────────────┤
│      duct (TCP 流)     │         parcel (UDP 数据报)          │
│  双向 TCP 转发管道      │    UDP 中继管道，空闲超时管理          │
├────────────────────────┴─────────────────────────────────────┤
│                       smux::frame                            │
│  帧编解码、地址解析、UDP 数据报构建                              │
└──────────────────────────────────────────────────────────────┘
```

### 设计原则

1. **协议无关抽象**：core 层提供通用流管理，duct/parcel 通过虚函数发送帧
2. **单线程执行**：每个 mux 会话绑定一个 executor，避免锁竞争
3. **协程原生**：所有 IO 操作使用 `co_await`，无回调
4. **PMR 内存**：所有容器使用 PMR 分配器，热路径零堆分配

## 核心组件

### core

位置：[core.hpp](../../include/prism/multiplex/core.hpp)、[core.cpp](../../src/prism/multiplex/core.cpp)

抽象基类，管理流生命周期和发送串行化。

#### 流状态管理

```cpp
memory::unordered_map<std::uint32_t, pending_entry> pending_;   // 等待地址
memory::unordered_map<std::uint32_t, std::shared_ptr<duct>> ducts_;     // TCP 流
memory::unordered_map<std::uint32_t, std::shared_ptr<parcel>> parcels_; // UDP 流
```

#### 关键方法

| 方法 | 说明 |
|------|------|
| `start()` | 通过 `co_spawn` 启动 `run()` 协程，设置异常处理 |
| `close()` | 原子标记非活跃，`std::move` 取出管道后逐一关闭 |
| `send_data()` | 纯虚，由子类实现帧发送 |
| `send_fin()` | 纯虚，由子类实现 FIN 帧发送 |
| `executor()` | 纯虚，返回 transport 的 executor |

#### pending_entry 结构

```cpp
struct pending_entry
{
    memory::vector<std::byte> buffer; // 累积的地址+数据
    bool connecting = false;          // 是否已发起连接
};
```

累积首 PSH 帧数据，数据足够（>=7字节）时解析地址并发起连接。

### duct

位置：[duct.hpp](../../include/prism/multiplex/duct.hpp)、[duct.cpp](../../src/prism/multiplex/duct.cpp)

TCP 流双向转发管道，构造时已持有已连接的 target。

#### 数据流

```
                    ┌─────────────────┐
     mux 客户端 ◄───│     duct        │───► target 服务器
                    │                 │
    on_mux_data()   │  uplink_loop()  │
    (帧循环调用)     │  (独立协程)      │
                    └─────────────────┘
```

#### 关键实现

- **上行（target → mux）**：`uplink_loop()` 独立协程循环读取 target 数据，通过 `owner_->send_data()` 发送到 mux
- **下行（mux → target）**：`on_mux_data()` 由帧循环直接 `co_await` 写入 target，天然反压
- **半关闭处理**：`on_mux_fin()` 仅 `shutdown_write()` 发送方向，等待 target 端关闭后才完全关闭

#### 半关闭状态机

```
           mux_fin              target_closed
              │                      │
              ▼                      ▼
┌─────────┬─────────┐        ┌─────────┬─────────┐
│mux_closed│target_closed│ → │mux_closed│target_closed│
│  false  │  false  │        │  true   │  true   │
└─────────┴─────────┘        └─────────┴─────────┘
              │                      │
              └──────────────────────┘
                        │
                        ▼
                   close()
```

### parcel

位置：[parcel.hpp](../../include/prism/multiplex/parcel.hpp)、[parcel.cpp](../../src/prism/multiplex/parcel.cpp)

UDP 数据报中继管道，每个 PSH 帧承载一个 SOCKS5 UDP relay 格式数据报。

#### 工作流程

```
                    ┌─────────────────┐
     mux 客户端 ────►│    parcel       │────► 目标服务器
                    │                 │
    on_mux_data()   │ ensure_socket() │    async_send_to()
                    │                 │◄─── async_receive_from()
                    │ relay_datagram()│
                    └─────────────────┘
                           │
                     idle_timer_
                    (空闲超时关闭)
```

#### 关键实现

- **空闲超时**：`idle_timer_` 管理生命周期，每次收到数据重置，超时自动关闭
- **Socket 按需创建**：`ensure_socket()` 根据目标协议类型创建 UDP socket，支持 IPv4/IPv6 切换
- **DNS 解析**：通过 `router_.resolve_datagram_target()` 解析域名目标
- **数据报编解码**：使用 `smux::parse_udp_datagram()` 和 `smux::build_udp_datagram()`

## smux 协议实现

### craft

位置：[craft.hpp](../../include/prism/multiplex/smux/craft.hpp)、[craft.cpp](../../src/prism/multiplex/smux/craft.cpp)

smux 多路复用会话服务端，兼容 Mihomo/xtaci/smux v1 + sing-mux 协商。

#### 协程入口

```cpp
auto craft::run() -> net::awaitable<void>
{
    if (const auto ec = co_await negotiate_protocol())
        co_return;
    co_await frame_loop();
}
```

#### 协议协商

sing-mux 协议头格式：

```
┌────────────┬────────────┬─────────────────┬──────────────┐
│ Version 1B │ Protocol 1B│ PaddingLen 2B BE│ Padding N B  │
└────────────┴────────────┴─────────────────┴──────────────┘
```

- Version = 0：无 padding
- Version > 0：读取 PaddingLen 和 Padding

#### 帧循环

```cpp
auto craft::frame_loop() -> net::awaitable<void>
{
    while (active_)
    {
        // 1. 读取 8 字节帧头
        co_await transport_->async_read(frame_buffer, ec);

        // 2. 解析帧头
        auto hdr = deserialization(frame_buffer);

        // 3. 读取负载
        co_await transport_->async_read(payload, ec);

        // 4. 分发处理
        switch (hdr.cmd)
        {
        case command::syn:  co_await handle_syn(hdr.stream_id); break;
        case command::push: co_await handle_data(hdr.stream_id, payload); break;
        case command::fin:  handle_fin(hdr.stream_id); break;
        case command::nop:  break; // 心跳，忽略
        }
    }
}
```

#### PSH 三路分发

```cpp
auto craft::handle_data(stream_id, payload) -> net::awaitable<void>
{
    // 1. pending 流：累积数据，异步发起连接
    if (pending_.contains(stream_id))
    {
        entry.buffer.append(payload);
        if (数据足够 && !entry.connecting)
            co_spawn(activate_stream(stream_id));
        co_return;
    }

    // 2. TCP 流：直接转发
    if (ducts_.contains(stream_id))
        co_await duct->on_mux_data(payload);

    // 3. UDP 流：转发数据报
    if (parcels_.contains(stream_id))
        co_await parcel->on_mux_data(payload);
}
```

#### 流激活流程

```cpp
auto craft::activate_stream(stream_id) -> net::awaitable<void>
{
    // 1. 解析地址
    auto addr = parse_mux_address(entry.buffer);

    // 2. UDP 流
    if (addr.is_udp)
    {
        send_data(成功状态);
        auto dp = make_shared<parcel>(...);
        dp->start();
        parcels_[stream_id] = dp;
        co_return;
    }

    // 3. TCP 流
    auto [code, conn] = co_await router_.async_forward(host, port);
    send_data(成功状态);
    auto p = make_shared<duct>(...);
    p->start();
    ducts_[stream_id] = p;
}
```

### frame

位置：[frame.hpp](../../include/prism/multiplex/smux/frame.hpp)、[frame.cpp](../../src/prism/multiplex/smux/frame.cpp)

smux 帧协议编解码。

#### 帧格式

```
┌────────────┬──────────┬───────────────┬──────────────────┐
│ Version 1B │ Cmd 1B   │ Length 2B LE  │ StreamID 4B LE   │
└────────────┴──────────┴───────────────┴──────────────────┘
│                      Payload (Length bytes)                  │
└──────────────────────────────────────────────────────────────┘
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
┌─────────────┬──────────┬──────────────┬───────────────┐
│ Flags 2B BE │ ATYP 1B  │ Addr Variable│ Port 2B BE    │
└─────────────┴──────────┴──────────────┴───────────────┘
```

- Flags bit0：标识 UDP 流
- ATYP：0x01 IPv4、0x03 域名、0x04 IPv6

**SOCKS5 UDP Relay**：

```
┌──────────┬──────────────┬───────────────┬──────────────┐
│ ATYP 1B  │ Addr Variable│ Port 2B BE    │ Payload      │
└──────────┴──────────────┴───────────────┴──────────────┘
```

#### 关键函数

| 函数 | 说明 |
|------|------|
| `serialize()` | 序列化帧头 + 负载为字节向量 |
| `deserialization()` | 解析帧头，校验版本和命令有效性 |
| `parse_mux_address()` | 解析 sing-mux StreamRequest 地址 |
| `parse_udp_datagram()` | 解析 SOCKS5 UDP relay 数据报 |
| `build_udp_datagram()` | 构建 UDP 数据报响应 |
| `make_push_frame()` | 创建 PSH 帧 |
| `make_syn_frame()` | 创建 SYN 帧 |
| `make_fin_frame()` | 创建 FIN 帧 |

## 配置

位置：[config.hpp](../../include/prism/multiplex/config.hpp)

```cpp
struct config
{
    bool enabled = false;               // 是否启用多路复用
    std::uint32_t max_streams = 32;     // 单会话最大并发流数
    std::uint32_t buffer_size = 4096;   // 每流缓冲区大小
    std::uint32_t keepalive_interval_ms = 30000; // 心跳间隔
    std::uint32_t udp_idle_timeout_ms = 60000;   // UDP 管道空闲超时
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
            "buffer_size": 4096,
            "keepalive_interval_ms": 30000,
            "udp_idle_timeout_ms": 60000
        }
    }
}
```

## 与 Trojan 协议的集成

Trojan 原生 mux 通过 cmd=0x7F 触发：

```
┌─────────────────────────────────────────────────────────────┐
│                     Trojan 握手流程                          │
├─────────────────────────────────────────────────────────────┤
│ 1. TLS 握手                                                  │
│ 2. 读取 Trojan 头部                                          │
│    - 凭据验证                                                │
│    - cmd 字段检测                                            │
├─────────────────────────────────────────────────────────────┤
│ cmd = 0x01 (CONNECT)                                         │
│   └─► 建立 TCP 隧道                                          │
│                                                              │
│ cmd = 0x03 (UDP_ASSOCIATE)                                   │
│   └─► 建立 UDP 中继                                          │
│                                                              │
│ cmd = 0x7F (MUX)                                             │
│   └─► 创建 smux::craft 实例                                  │
│       - sing-mux 协议协商                                    │
│       - 帧循环处理多流                                        │
│       - 每个 SYN 创建新流                                     │
└─────────────────────────────────────────────────────────────┘
```

详见 [Trojan 协议文档](../protocols/trojan.md)。

## 数据流图

```
                              ┌─────────────────────────────────┐
                              │           craft                 │
                              │         frame_loop()            │
                              └──────────────┬──────────────────┘
                                             │
              ┌──────────────────────────────┼──────────────────────────────┐
              │                              │                              │
              ▼                              ▼                              ▼
        ┌───────────┐                  ┌───────────┐                  ┌───────────┐
        │  SYN 帧   │                  │  PSH 帧   │                  │  FIN 帧   │
        └─────┬─────┘                  └─────┬─────┘                  └─────┬─────┘
              │                              │                              │
              ▼                              ▼                              ▼
     创建 pending_entry              三路分发：                        处理半关闭：
     等待首 PSH 帧                  - pending: 累积数据               - pending: 删除
                                   - duct: 转发到 target            - duct: on_mux_fin()
                                   - parcel: 中继 UDP              - parcel: close()
              │                              │
              │            ┌─────────────────┴─────────────────┐
              │            │                                   │
              │            ▼                                   ▼
              │      ┌───────────┐                      ┌───────────┐
              │      │   duct    │                      │  parcel   │
              │      │ uplink_   │                      │ relay_    │
              │      │ loop()    │                      │ datagram()│
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

## 协程设计

### 发送串行化

```cpp
auto craft::send_frame(const frame_header &hdr, span<const std::byte> payload) const
    -> net::awaitable<void>
{
    // strand 保证帧不会被交错写入
    co_await net::post(send_strand_, net::use_awaitable);
    auto frame = serialize(hdr, payload, mr_);
    co_await transport_->async_write(frame, ec);
}
```

### FIN 异步发送

```cpp
void craft::send_fin(std::uint32_t stream_id)
{
    // FIN 发送不阻塞帧循环，异步执行
    net::co_spawn(executor(), [self, hdr]() -> net::awaitable<void> {
        co_await self->send_frame(hdr, {});
    }, on_exception);
}
```

### duct 上行循环

```cpp
auto duct::uplink_loop() -> net::awaitable<void>
{
    while (!closed_)
    {
        const auto n = co_await target_->async_read_some(recv_buffer_, ec);
        if (ec || n == 0) break;

        if (!owner_->is_active()) break;

        // 直接 co_await，不经过缓冲
        co_await owner_->send_data(id_, span(recv_buffer_.data(), n));
    }

    target_closed_ = true;
    if (!mux_closed_ && owner_->is_active())
        owner_->send_fin(id_);
}
```

### parcel 空闲超时

```cpp
auto parcel::uplink_loop() -> net::awaitable<void>
{
    while (!closed_)
    {
        co_await idle_timer_.async_wait(token);
        // operation_aborted 表示 touch_idle_timer() 重置了定时器
        if (ec != net::error::operation_aborted)
            break;
    }
    // 超时退出，on_done 回调调用 close()
}
```

## 性能考量

### 内存分配

- 所有容器使用 PMR 分配器，从 `memory::resource` 分配
- `recv_buffer_` 在构造时预分配，避免热路径分配
- 帧序列化使用 `memory::vector`，零拷贝传递

### 并发模型

- 每个 mux 会话绑定单个 executor，无锁设计
- 发送通过 strand 串行化，接收由帧循环串行处理
- duct 上行使用独立协程，与帧循环并行

### 反压机制

- 下行方向直接 `co_await` 写入，不缓冲
- 如果 target 写入阻塞，帧循环自然等待
- 不会出现内存无限增长

## 注意事项

1. **发送串行化**：所有帧发送必须通过 `send_strand_`，否则帧会交错
2. **半关闭处理**：`on_mux_fin()` 仅 shutdown 发送方向，等待对端关闭
3. **UDP 空闲超时**：UDP 管道无数据时自动清理，避免资源泄漏
4. **流 ID 复用**：FIN 后流 ID 可被复用，需确保旧流完全关闭
5. **PMR 内存**：所有容器必须传入 PMR 分配器