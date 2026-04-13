# 配置与上下文结构

本文档详细说明 `prism` 的配置结构体与上下文结构体，涵盖各字段职责、生命周期及所有权模型。

---

## config 结构体

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

`config` 是代理服务的全局配置入口，聚合所有子模块配置。该结构用于初始化 worker、`account::directory` 和 `resolve::router`。

### 字段说明

#### limit

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
struct limit limit;
```

连接限制配置，控制并发数和黑名单策略。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `concurrences` | `std::uint32_t` | `20` | 最大并发连接数，0 表示无限制 |
| `blacklist` | `bool` | `true` | 是否启用黑名单过滤 |

**注意事项**:
- 并发限制作用于全局所有工作线程
- 设置过小的并发数可能导致服务拒绝合法连接

---

#### positive

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
endpoint positive;
```

正向代理端点，定义上游代理服务器。

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `host` | `memory::string` | 上游代理主机名（域名或 IP） |
| `port` | `std::uint16_t` | 上游代理端口，0 表示未设置 |

**用途**: 配置后，正向代理请求将转发到该端点而非直接连接目标。

---

#### addressable

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
endpoint addressable;
```

监听端点，定义服务监听的地址和端口。

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `host` | `memory::string` | 监听主机名 |
| `port` | `std::uint16_t` | 监听端口 |

**重要说明**: 当前 `listener` 只使用 `addressable.port`，绑定 IPv4 地址（`0.0.0.0`）。`host` 字段暂未使用。

---

#### certificate

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
struct certificate certificate;
```

SSL/TLS 证书配置，用于配置 SSL 上下文以支持 HTTPS 和 TLS 协议。

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `key` | `memory::string` | 私钥文件路径（PEM 格式） |
| `cert` | `memory::string` | 证书文件路径（PEM 格式） |

**注意事项**:
- 文件格式要求为 PEM
- 文件路径必须可读，否则 SSL 上下文初始化会失败

---

#### authentication

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
struct authentication authentication;
```

统一身份认证配置，管理客户端身份验证的凭据和用户限制。每个用户可同时配置
密码（用于 Trojan/HTTP/SOCKS5）和 UUID（用于 VLESS），两种凭证共享连接数配额。

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `users` | `memory::vector<user>` | 统一用户列表 |

**user 结构体** ([config.hpp](../../include/prism/agent/config.hpp)):

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `password` | `memory::string` | 密码认证（明文或 56 字符 SHA224 hex），用于 Trojan/HTTP/SOCKS5 |
| `uuid` | `memory::string` | VLESS UUID 字符串，标准格式 `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` |
| `max_connections` | `std::uint32_t` | 最大并发连接数，0 表示无限制 |

**注意事项**:
- `password` 和 `uuid` 均为可选字段，但至少一个非空才有效
- 密码启动时自动转换为 SHA224 哈希注册到 `account::directory`
- UUID 直接注册到 `account::directory`，两种凭证指向同一个 `entry` 共享配额
- 用户仅配置 `uuid` 时无法通过密码认证协议连接；仅配置 `password` 时无法通过 VLESS 连接

---

#### camouflage

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
memory::string camouflage;
```

伪装路径，用于抗探测。当探测请求访问该路径时，返回伪装响应以隐藏代理服务特征。

---

#### clash

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
bool clash{false};
```

启用 Clash API 兼容模式。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `clash` | `bool` | `false` | 启用 Clash API 兼容模式 |

---

#### reverse_map

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
memory::map<memory::string, endpoint> reverse_map;
```

反向代理路由表，键为主机名，值为后端端点。用于将特定域名的请求路由到指定的后端服务器。

---

#### pool

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
struct pool_config pool;
```

连接池配置，控制连接缓存、超时、缓冲区等参数。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `max_cache_per_endpoint` | `std::uint32_t` | `32` | 单个目标端点最大缓存连接数 |
| `connect_timeout_ms` | `std::uint64_t` | `300` | 连接超时（毫秒） |
| `max_idle_seconds` | `std::uint64_t` | `30` | 空闲连接最大存活时间（秒） |
| `cleanup_interval_sec` | `std::uint64_t` | `10` | 后台清理间隔（秒） |
| `recv_buffer_size` | `std::uint32_t` | `65536` | 接收缓冲区大小（字节） |
| `send_buffer_size` | `std::uint32_t` | `65536` | 发送缓冲区大小（字节） |
| `tcp_nodelay` | `bool` | `true` | 是否启用 TCP_NODELAY |
| `keep_alive` | `bool` | `true` | 是否启用 SO_KEEPALIVE |
| `cache_ipv6` | `bool` | `false` | 是否缓存 IPv6 连接 |

**用途**: 连接池缓存 TCP 连接，避免频繁的三次握手，提升性能。

---

#### buffer

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

```cpp
struct buffer buffer;
```

缓冲区配置，控制数据转发缓冲区大小。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `size` | `std::uint32_t` | `262144` (256KB) | 传输缓冲区大小（字节） |

**调优建议**:
- 高延迟高带宽环境：增大此值
- 内存受限环境：减小此值

---

#### socks5

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

**协议配置定义**: [protocol/socks5/config.hpp](../../include/prism/protocol/socks5/config.hpp)

```cpp
protocol::socks5::config socks5;
```

SOCKS5 协议配置，控制能力开关和 UDP relay 参数。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_auth` | `bool` | `false` | 是否启用用户名密码认证 |
| `enable_tcp` | `bool` | `true` | 是否允许 CONNECT 命令（TCP 隧道） |
| `enable_udp` | `bool` | `true` | 是否允许 UDP_ASSOCIATE 命令 |
| `enable_bind` | `bool` | `false` | 是否允许 BIND 命令 |
| `udp_bind_port` | `std::uint16_t` | `0` | UDP relay 绑定端口，0 表示自动分配 |
| `udp_idle_timeout` | `std::uint32_t` | `60` | UDP 会话空闲超时（秒） |
| `udp_max_datagram` | `std::uint32_t` | `65535` | UDP 数据报最大长度 |

---

#### trojan

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

**协议配置定义**: [protocol/trojan/config.hpp](../../include/prism/protocol/trojan/config.hpp)

```cpp
protocol::trojan::config trojan;
```

Trojan 协议配置，控制能力开关和 UDP 参数。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_tcp` | `bool` | `true` | 是否允许 CONNECT 命令（TCP 隧道） |
| `enable_udp` | `bool` | `false` | 是否允许 UDP_ASSOCIATE 命令 |
| `udp_idle_timeout` | `std::uint32_t` | `60` | UDP 会话空闲超时（秒） |
| `udp_max_datagram` | `std::uint32_t` | `65535` | UDP 数据报最大长度 |

**说明**: Trojan 协议已集成到分发逻辑中，`register_handlers()` 注册了 `Trojan` handler。

---

#### vless

**源码位置**: [config.hpp](../../include/prism/protocol/vless/config.hpp)

```cpp
protocol::vless::config vless;
```

VLESS 协议配置。当前配置结构为空，用户认证已统一到 `authentication.users[].uuid` 字段，
启动时由 `loader::build_account_directory()` 自动注册到 `account::directory`。

**说明**: VLESS 协议已集成到分发逻辑中，`register_handlers()` 注册了 `Vless` handler。

---

#### shadowsocks

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

**协议配置定义**: [protocol/shadowsocks/config.hpp](../../include/prism/protocol/shadowsocks/config.hpp)

```cpp
protocol::shadowsocks::config shadowsocks;
```

Shadowsocks 2022 (SIP022) 协议配置，控制 AEAD 加密参数。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `psk` | `memory::string` | `""` | Base64 编码的预共享密钥（16 字节 = AES-128-GCM，32 字节 = AES-256-GCM） |
| `enable_tcp` | `bool` | `true` | 是否允许 TCP 代理 |
| `timestamp_window` | `std::int64_t` | `30` | 时间戳验证窗口（秒），用于防重放 |

**说明**: Shadowsocks 2022 协议已集成到分发逻辑中，`register_handlers()` 注册了 `Shadowsocks` handler。协议检测采用排除法：不匹配其他协议时 fallback 到 `protocol_type::shadowsocks`。

---

#### mux

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

**协议配置定义**: [multiplex/config.hpp](../../include/prism/multiplex/config.hpp)

```cpp
multiplex::config mux;
```

多路复用配置，控制 smux/yamux 多路复用服务端行为。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enabled` | `bool` | `false` | 是否启用多路复用服务端 |
| `smux` | `smux::config` | (见下文) | smux 协议配置 |
| `yamux` | `yamux::config` | (见下文) | yamux 协议配置 |

**smux 子配置**:

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `max_streams` | `std::uint32_t` | `32` | 单会话最大并发流数 |
| `buffer_size` | `std::uint32_t` | `4096` | 每流读取缓冲区大小 |
| `keepalive_interval_ms` | `std::uint32_t` | `30000` | 心跳间隔（毫秒），0 禁用 |
| `udp_idle_timeout_ms` | `std::uint32_t` | `60000` | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | `std::uint32_t` | `65535` | UDP 数据报最大长度 |

**yamux 子配置**:

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `max_streams` | `std::uint32_t` | `32` | 单会话最大并发流数 |
| `buffer_size` | `std::uint32_t` | `4096` | 每流读取缓冲区大小 |
| `initial_window` | `std::uint32_t` | `262144` | 初始流窗口大小（256KB） |
| `enable_ping` | `bool` | `true` | 是否启用心跳 |
| `ping_interval_ms` | `std::uint32_t` | `30000` | 心跳间隔（毫秒） |
| `stream_open_timeout_ms` | `std::uint32_t` | `30000` | 流打开超时（毫秒） |
| `stream_close_timeout_ms` | `std::uint32_t` | `30000` | 流关闭超时（毫秒） |
| `udp_idle_timeout_ms` | `std::uint32_t` | `60000` | UDP 管道空闲超时（毫秒） |
| `udp_max_datagram` | `std::uint32_t` | `65535` | UDP 数据报最大长度 |

**详细说明**: 详见 [多路复用模块文档](../multiplex/overview.md)。

---

#### dns

**源码位置**: [config.hpp](../../include/prism/agent/config.hpp)

**协议配置定义**: [resolve/config.hpp](../../include/prism/resolve/config.hpp)

```cpp
resolve::config dns;
```

DNS 解析器配置，控制上游 DNS 服务器、缓存策略、规则匹配等。

---

## server_context 结构体

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

`server_context` 聚合服务器级别的共享资源，在服务器启动时创建，被所有工作线程共享。

### 字段说明

#### cfg

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
const config &cfg;
```

配置对象的常量引用，包含所有运行时参数。

**生命周期**: 配置对象的生命周期必须长于 `server_context`。

---

#### ssl_ctx

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::shared_ptr<ssl::context> ssl_ctx;
```

SSL 上下文，用于 TLS 握手和加密通信。

**所有权**: 使用 `shared_ptr` 管理，确保跨线程共享安全。

---

#### account_store

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::shared_ptr<account::directory> account_store;
```

账户注册表，管理用户凭据和连接配额。

**所有权**: 使用 `shared_ptr` 管理，确保跨线程共享安全。

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | `main()` 函数中创建 |
| 共享 | 被所有 worker 共享 |
| 销毁 | 服务关闭时销毁 |

---

## worker_context 结构体

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

`worker_context` 封装单个工作线程的独立资源，实现线程间的资源隔离和避免锁竞争。

### 字段说明

#### io_context

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
net::io_context &io_context;
```

I/O 上下文引用，驱动该线程的异步操作。

**生命周期**: 由工作线程管理。

---

#### router

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
resolve::router &router;
```

路由器引用，负责请求分发和后端选择。

**定义位置**: [resolve/router.hpp](../../include/prism/resolve/router.hpp)

---

#### memory_pool

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
memory::resource_pointer memory_pool;
```

内存池资源指针，用于 PMR 内存分配。

**定义位置**: [memory/pool.hpp](../../include/prism/memory/pool.hpp)

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | worker 构造时创建 |
| 持有 | 每个 worker 独立持有 |
| 销毁 | 随 worker 销毁 |

---

## session_context 结构体

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

`session_context` 聚合单个连接会话所需的所有资源和状态，是请求处理流程的核心数据结构。

### 字段说明

| 字段 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `session_id` | `std::uint64_t` | `0` | 会话唯一标识符 |

---

#### server

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
const server_context &server;
```

服务器上下文的常量引用，提供全局资源访问。

---

#### worker

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
worker_context &worker;
```

工作线程上下文引用，提供线程级资源访问。

---

#### frame_arena

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
memory::frame_arena &frame_arena;
```

帧内存池引用，用于会话期间的临时内存分配。

**定义位置**: [memory/pool.hpp](../../include/prism/memory/pool.hpp)

**特性**:
- 使用栈上缓冲区（128 字节）和单调增长资源
- 提供极高的分配性能
- 适用于短生命周期、高频分配的场景

---

#### credential_verifier

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::function<bool(std::string_view)> credential_verifier;
```

凭据验证函数，用于校验客户端身份。

**注意事项**: 可能为空，使用前应检查有效性。

---

#### account_directory_ptr

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
account::directory *account_directory_ptr{nullptr};
```

账户注册表指针，用于配额检查和流量统计。

**默认值**: `nullptr`

---

#### buffer_size

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::uint32_t buffer_size;
```

数据传输缓冲区大小（字节）。

---

#### inbound

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
psm::channel::transport::shared_transmission inbound;
```

入站传输对象，处理来自客户端的数据。

**类型定义**: [channel/transport/transmission.hpp](../../include/prism/channel/transport/transmission.hpp)

```cpp
using shared_transmission = std::shared_ptr<transmission>;
```

---

#### outbound

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
psm::channel::transport::shared_transmission outbound;
```

出站传输对象，处理发往目标服务器的数据。

---

#### account_lease

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
account::lease account_lease;
```

RAII 凭证持有，控制并发连接数。会话期间持有租约，会话结束时自动释放。

---

#### active_stream_cancel

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::function<void()> active_stream_cancel;
```

TLS 活跃流取消回调。当 `inbound` 被 move 后，仍能正确取消底层流的异步操作。

---

#### active_stream_close

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

```cpp
std::function<void()> active_stream_close;
```

TLS 活跃流关闭回调。当 `inbound` 被 move 后，仍能正确关闭底层流连接。

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | 随会话创建初始化 |
| 持有 | session 持有 inbound/outbound |
| 销毁 | 随会话生命周期销毁 |

---

## 所有权模型总结

| 上下文 | 资源 | 所有权类型 |
|--------|------|------------|
| `server_context` | `cfg` | 常量引用（外部持有） |
| `server_context` | `ssl_ctx` | `shared_ptr`（共享） |
| `server_context` | `account_store` | `shared_ptr`（共享） |
| `worker_context` | `io_context` | 引用（worker 持有） |
| `worker_context` | `router` | 引用（worker 持有） |
| `worker_context` | `memory_pool` | 值（worker 独占） |
| `session_context` | `server` | 常量引用 |
| `session_context` | `worker` | 引用 |
| `session_context` | `frame_arena` | 引用（session 持有） |
| `session_context` | `inbound` | `shared_ptr`（session 独占） |
| `session_context` | `outbound` | `shared_ptr`（session 独占） |
