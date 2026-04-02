# 上下文结构体详解

本文档详细说明 Prism 中的上下文结构体，涵盖各字段职责、生命周期及所有权模型。

---

## server_context 结构体

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

`server_context` 聚合服务器级别的共享资源，在服务器启动时创建，被所有工作线程共享。

### 字段说明

#### cfg

```cpp
const config &cfg;
```

配置对象的常量引用，包含所有运行时参数。

**生命周期**: 配置对象的生命周期必须长于 `server_context`。

---

#### ssl_ctx

```cpp
std::shared_ptr<ssl::context> ssl_ctx;
```

SSL 上下文，用于 TLS 握手和加密通信。

**所有权**: 使用 `shared_ptr` 管理，确保跨线程共享安全。

**创建时机**: Worker 构造时，通过 `tls::create_ssl_context()` 创建。

---

#### account_store

```cpp
std::shared_ptr<account::directory> account_store;
```

账户注册表，管理用户凭据和连接配额。

**所有权**: 使用 `shared_ptr` 管理，确保跨线程共享安全。

**创建时机**: `main()` 函数中创建，传入 Worker 构造函数。

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

```cpp
net::io_context &io_context;
```

I/O 上下文引用，驱动该线程的异步操作。

**生命周期**: 由工作线程管理，每个 Worker 拥有独立的 `io_context`。

---

#### router

```cpp
resolve::router &router;
```

路由器引用，负责请求分发和后端选择。

**定义位置**: [router.hpp](../../include/prism/resolve/router.hpp)

**所有权**: Worker 独占，每个 Worker 拥有独立的路由器实例。

---

#### memory_pool

```cpp
memory::resource_pointer memory_pool;
```

内存池资源指针，用于 PMR 内存分配。

**定义位置**: [pool.hpp](../../include/prism/memory/pool.hpp)

**特性**:
- 每个 Worker 独立的内存池
- 避免跨线程内存分配竞争
- 支持高效的内存复用

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | Worker 构造时创建 |
| 持有 | 每个 Worker 独立持有 |
| 销毁 | 随 Worker 销毁 |

---

## session_context 结构体

**源码位置**: [context.hpp](../../include/prism/agent/context.hpp)

`session_context` 聚合单个连接会话所需的所有资源和状态，是请求处理流程的核心数据结构。

### 字段说明

#### server

```cpp
const server_context &server;
```

服务器上下文的常量引用，提供全局资源访问。

---

#### worker

```cpp
worker_context &worker;
```

工作线程上下文引用，提供线程级资源访问。

---

#### frame_arena

```cpp
memory::frame_arena &frame_arena;
```

帧内存池引用，用于会话期间的临时内存分配。

**定义位置**: [pool.hpp](../../include/prism/memory/pool.hpp)

**特性**:
- 使用栈上缓冲区（128 字节）和单调增长资源
- 提供极高的分配性能
- 适用于短生命周期、高频分配的场景
- 会话处理过程中可重置复用

---

#### credential_verifier

```cpp
std::function<bool(std::string_view)> credential_verifier;
```

凭据验证函数，用于校验客户端身份。

**注意事项**: 可能为空，使用前应检查有效性。

---

#### account_directory_ptr

```cpp
account::directory *account_directory_ptr{nullptr};
```

账户注册表指针，用于配额检查和流量统计。

**默认值**: `nullptr`

---

#### buffer_size

```cpp
std::uint32_t buffer_size;
```

数据传输缓冲区大小（字节）。

**默认值**: 从配置读取，默认 262144（256KB）

---

#### inbound

```cpp
psm::channel::transport::transmission_pointer inbound;
```

入站传输对象，处理来自客户端的数据。

**类型定义**: [transmission.hpp](../../include/prism/channel/transport/transmission.hpp)

```cpp
using transmission_pointer = std::unique_ptr<transmission>;
```

---

#### outbound

```cpp
psm::channel::transport::transmission_pointer outbound;
```

出站传输对象，处理发往目标服务器的数据。

---

#### account_lease

```cpp
account::lease account_lease;
```

账户连接租约，持有期间保持连接计数，会话结束时自动释放。

**用途**: 用于 Trojan 等需要账户验证的协议，验证成功后持有租约，确保连接限制生效。

---

#### active_stream_cancel

```cpp
std::function<void()> active_stream_cancel;
```

活跃流取消回调，由 TLS 等加密协议处理器设置。

**用途**: 当 `ctx.inbound` 被 move 后，仍能正确取消底层流的异步操作。

**调用时机**: `session::close()` 中调用。

---

#### active_stream_close

```cpp
std::function<void()> active_stream_close;
```

活跃流关闭回调，由 TLS 等加密协议处理器设置。

**用途**: 当 `ctx.inbound` 被 move 后，仍能正确关闭底层流连接。

**调用时机**: `session::release_resources()` 中调用。

### 生命周期总结

| 阶段 | 说明 |
|------|------|
| 创建 | 随会话创建初始化 |
| 持有 | Session 持有 inbound/outbound |
| 销毁 | 随会话生命周期销毁 |

---

## 所有权模型总结

| 上下文 | 资源 | 所有权类型 |
|--------|------|------------|
| `server_context` | `cfg` | 常量引用（外部持有） |
| `server_context` | `ssl_ctx` | `shared_ptr`（共享） |
| `server_context` | `account_store` | `shared_ptr`（共享） |
| `worker_context` | `io_context` | 引用（Worker 持有） |
| `worker_context` | `router` | 引用（Worker 持有） |
| `worker_context` | `memory_pool` | 值（Worker 独占） |
| `session_context` | `server` | 常量引用 |
| `session_context` | `worker` | 引用 |
| `session_context` | `frame_arena` | 引用（Session 持有） |
| `session_context` | `inbound` | `unique_ptr`（Session 独占） |
| `session_context` | `outbound` | `unique_ptr`（Session 独占） |
| `session_context` | `account_lease` | 值（RAII 自动释放） |
| `session_context` | `active_stream_*` | `function`（回调） |

---

## 线程安全说明

| 组件 | 线程安全 | 说明 |
|------|----------|------|
| `server_context` | ✅ | 只读访问，跨线程共享安全 |
| `worker_context` | ❌ | 仅在所属 Worker 线程内访问 |
| `session_context` | ❌ | 仅在所属 Worker 线程内访问 |
| `account::directory` | ✅ | 使用原子操作和写时复制 |
| `router` | ❌ | 仅在所属 Worker 线程内访问 |

---

## 使用示例

### 创建 session_context

```cpp
session_context ctx{
    .server = server_ctx,
    .worker = worker_ctx,
    .frame_arena = frame_arena,
    .buffer_size = server_ctx.cfg.buffer.size,
    .inbound = psm::channel::transport::make_reliable(std::move(socket))
};
```

### 访问全局资源

```cpp
// 访问 SSL 上下文
auto ssl_ctx = ctx.server.ssl_ctx;

// 访问账户目录
if (ctx.account_directory_ptr)
{
    auto entry = ctx.account_directory_ptr->find(credential);
}
```

### 访问线程级资源

```cpp
// 投递任务到 IO 上下文
net::post(ctx.worker.io_context, []() {
    // 异步任务
});

// 使用路由器
auto [ec, socket] = co_await ctx.worker.router.async_forward(host, port);
```
