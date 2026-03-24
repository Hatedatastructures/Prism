# 配置与上下文结构

本文档详细说明 `forward-engine` 的配置结构体与上下文结构体，涵盖各字段职责、生命周期及所有权模型。

---

## config 结构体

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

`config` 是代理服务的全局配置入口，聚合所有子模块配置。该结构用于初始化 worker、`account::directory` 和 `resolve::router`。

### 字段说明

#### limit

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

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

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

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

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

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

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

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

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

```cpp
struct authentication authentication;
```

身份认证配置，管理客户端身份验证的凭据和用户限制。

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `credentials` | `memory::vector<memory::string>` | 凭据列表（SHA224 密码哈希） |
| `users` | `memory::vector<user>` | 用户列表，支持独立限制 |

**user 结构体** ([config.hpp](../../include/forward-engine/agent/config.hpp)):

| 子字段 | 类型 | 说明 |
|--------|------|------|
| `credential` | `memory::string` | 用户凭据（SHA224 哈希） |
| `max_connections` | `std::uint32_t` | 最大并发连接数，0 表示无限制 |

**注意事项**:
- 凭据通常是密码的 SHA224 哈希
- 如果同时配置 `credentials` 和 `users`，`account::directory` 优先检查 `users` 列表

---

#### camouflage

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

```cpp
memory::string camouflage;
```

伪装路径，用于抗探测。当探测请求访问该路径时，返回伪装响应以隐藏代理服务特征。

---

#### reverse_map

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

```cpp
memory::map<memory::string, endpoint> reverse_map;
```

反向代理路由表，键为主机名，值为后端端点。用于将特定域名的请求路由到指定的后端服务器。

---

#### pool

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

```cpp
struct pool_config pool;
```

连接池配置，控制连接缓存和空闲超时。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `max_cache_per_endpoint` | `std::uint32_t` | `32` | 单个目标端点最大缓存连接数 |
| `max_idle_seconds` | `std::uint64_t` | `30` | 空闲连接最大存活时间（秒） |

**用途**: 连接池缓存 TCP 连接，避免频繁的三次握手，提升性能。

---

#### buffer

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

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

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

**协议配置定义**: [protocol/socks5/config.hpp](../../include/forward-engine/protocol/socks5/config.hpp)

```cpp
protocol::socks5::config socks5;
```

SOCKS5 协议配置，控制能力开关和 UDP relay 参数。

| 子字段 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_tcp` | `bool` | `true` | 是否允许 CONNECT 命令（TCP 隧道） |
| `enable_udp` | `bool` | `true` | 是否允许 UDP_ASSOCIATE 命令 |
| `enable_bind` | `bool` | `false` | 是否允许 BIND 命令 |
| `udp_bind_port` | `std::uint16_t` | `0` | UDP relay 绑定端口，0 表示自动分配 |
| `udp_idle_timeout` | `std::uint32_t` | `60` | UDP 会话空闲超时（秒） |
| `udp_max_datagram` | `std::uint32_t` | `65535` | UDP 数据报最大长度 |

---

#### trojan

**源码位置**: [config.hpp](../../include/forward-engine/agent/config.hpp)

**协议配置定义**: [protocol/trojan/config.hpp](../../include/forward-engine/protocol/trojan/config.hpp)

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

**重要说明**: `config` 有此字段但 `dispatch` 未注册 Trojan handler。当前 Trojan 协议配置已定义但未集成到分发逻辑中。

---

## server_context 结构体

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

`server_context` 聚合服务器级别的共享资源，在服务器启动时创建，被所有工作线程共享。

### 字段说明

#### cfg

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
const config &cfg;
```

配置对象的常量引用，包含所有运行时参数。

**生命周期**: 配置对象的生命周期必须长于 `server_context`。

---

#### ssl_ctx

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
std::shared_ptr<ssl::context> ssl_ctx;
```

SSL 上下文，用于 TLS 握手和加密通信。

**所有权**: 使用 `shared_ptr` 管理，确保跨线程共享安全。

---

#### account_store

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

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

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

`worker_context` 封装单个工作线程的独立资源，实现线程间的资源隔离和避免锁竞争。

### 字段说明

#### io_context

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
net::io_context &io_context;
```

I/O 上下文引用，驱动该线程的异步操作。

**生命周期**: 由工作线程管理。

---

#### router

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
resolve::router &router;
```

路由器引用，负责请求分发和后端选择。

**定义位置**: [resolve/router.hpp](../../include/forward-engine/resolve/router.hpp)

---

#### memory_pool

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
memory::resource_pointer memory_pool;
```

内存池资源指针，用于 PMR 内存分配。

**定义位置**: [memory/pool.hpp](../../include/forward-engine/memory/pool.hpp)

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | worker 构造时创建 |
| 持有 | 每个 worker 独立持有 |
| 销毁 | 随 worker 销毁 |

---

## session_context 结构体

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

`session_context` 聚合单个连接会话所需的所有资源和状态，是请求处理流程的核心数据结构。

### 字段说明

#### server

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
const server_context &server;
```

服务器上下文的常量引用，提供全局资源访问。

---

#### worker

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
worker_context &worker;
```

工作线程上下文引用，提供线程级资源访问。

---

#### frame_arena

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
memory::frame_arena &frame_arena;
```

帧内存池引用，用于会话期间的临时内存分配。

**定义位置**: [memory/pool.hpp](../../include/forward-engine/memory/pool.hpp)

**特性**:
- 使用栈上缓冲区（128 字节）和单调增长资源
- 提供极高的分配性能
- 适用于短生命周期、高频分配的场景

---

#### credential_verifier

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
std::function<bool(std::string_view)> credential_verifier;
```

凭据验证函数，用于校验客户端身份。

**注意事项**: 可能为空，使用前应检查有效性。

---

#### account_directory_ptr

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
account::directory *account_directory_ptr{nullptr};
```

账户注册表指针，用于配额检查和流量统计。

**默认值**: `nullptr`

---

#### buffer_size

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
std::uint32_t buffer_size;
```

数据传输缓冲区大小（字节）。

---

#### inbound

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
ngx::channel::transport::transmission_pointer inbound;
```

入站传输对象，处理来自客户端的数据。

**类型定义**: [channel/transport/transmission.hpp](../../include/forward-engine/channel/transport/transmission.hpp)

```cpp
using transmission_pointer = std::unique_ptr<transmission>;
```

---

#### outbound

**源码位置**: [context.hpp](../../include/forward-engine/agent/context.hpp)

```cpp
ngx::channel::transport::transmission_pointer outbound;
```

出站传输对象，处理发往目标服务器的数据。

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
| `session_context` | `inbound` | `unique_ptr`（session 独占） |
| `session_context` | `outbound` | `unique_ptr`（session 独占） |
