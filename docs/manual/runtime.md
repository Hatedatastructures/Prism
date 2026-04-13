# 运行时流程

本文档详细描述 prism 的运行时流程，涵盖 Session 创建、协议检测、隧道转发和连接关闭四个核心阶段。

---

## Session 创建流程

Session 创建流程负责接收新连接并初始化会话上下文。该流程由 `launch` 命名空间驱动，将连接从主线程安全地移交到工作线程。

### 流程步骤

#### 1. launch::dispatch() 投递到 worker 事件循环

**源码位置**: [launch.cpp](../../src/prism/agent/worker/launch.cpp)

```cpp
void dispatch(net::io_context &ioc, server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
{
    metrics.handoff_push();

    auto start_session = [&server, &worker, &metrics, sock = std::move(socket), &ioc]() mutable
    {
        metrics.handoff_pop();

        // 将 socket 从 listener 的 io_context 迁移到 worker 的 io_context
        auto migrated = migrate_executor(sock, ioc);
        if (!migrated)
        {
            return;
        }

        prime(*migrated, server.cfg.buffer.size);
        try
        {
            start(server, worker, metrics, std::move(*migrated));
        }
        catch (const std::exception &e)
        {
            trace::error("session launch failed: {}", e.what());
        }
    };
    net::post(ioc, std::move(start_session));
}
```

**关键操作**:
- 调用 `metrics.handoff_push()` 记录连接移交开始
- 使用 `net::post()` 将连接投递到 worker 的 `io_context`
- 在 worker 线程中调用 `metrics.handoff_pop()` 记录移交完成
- 调用 `migrate_executor()` 将 socket 从 listener 的 `io_context` 迁移到 worker 的 `io_context`
- 迁移失败时直接返回，不创建会话

#### 2. launch::prime() 预配置 socket 参数

**源码位置**: [launch.cpp](../../src/prism/agent/worker/launch.cpp)

```cpp
void prime(tcp::socket &socket, std::uint32_t buffer_size) noexcept
{
    boost::system::error_code ec;
    socket.set_option(tcp::no_delay(true), ec);
    socket.set_option(net::socket_base::receive_buffer_size(buffer_size), ec);
    socket.set_option(net::socket_base::send_buffer_size(buffer_size), ec);
}
```

**关键配置**:
- `tcp::no_delay(true)`: 禁用 Nagle 算法，减少小包延迟
- `receive_buffer_size`: 设置接收缓冲区大小
- `send_buffer_size`: 设置发送缓冲区大小

#### 3. launch::start() 创建 session

**源码位置**: [launch.cpp](../../src/prism/agent/worker/launch.cpp)

```cpp
void start(server_context &server, worker_context &worker, stats::state &metrics, tcp::socket socket)
{
    auto active_sessions = metrics.session_counter();
    auto on_closed = [active_sessions]() noexcept
    {
        active_sessions->fetch_sub(1U, std::memory_order_relaxed);
    };

    auto inbound = psm::channel::transport::make_reliable(std::move(socket));
    session::session_params params{server, worker, std::move(inbound)};
    const auto shared_session = psm::agent::session::make_session(std::move(params));

    metrics.session_open();
    try
    {
        shared_session->set_on_closed(std::move(on_closed));

        const bool auth_enabled = !server.cfg.authentication.users.empty();
        auto account_store = server.account_store;
        shared_session->set_account_directory(auth_enabled ? account_store.get() : nullptr);
        shared_session->set_credential_verifier(
            [auth_enabled, account_store](std::string_view credential) -> bool
            {
                if (!auth_enabled)
                {
                    return true;
                }
                if (!account_store)
                {
                    return false;
                }
                return account::contains(*account_store, credential);
            });
        shared_session->start();
    }
    catch (...)
    {
        metrics.session_close();
        throw;
    }
}
```

**关键操作**:

| 步骤 | 操作 | 说明 |
|------|------|------|
| 3.1 | 获取 active_sessions 计数器 | 通过 `metrics.session_counter()` 获取原子计数器 |
| 3.2 | 设置 on_closed 回调 | 回调中递减活跃会话计数 |
| 3.3 | 创建 reliable transmission | 将 socket 包装为可靠传输对象 |
| 3.4 | 创建 session_params | 封装 server、worker、inbound 参数 |
| 3.5 | 调用 make_session() | 创建 session 共享指针 |
| 3.6 | 设置 credential_verifier | 配置凭证验证器 |
| 3.7 | 调用 session->start() | 启动会话协程 |

---

## 协议检测流程

协议检测流程在会话启动后执行，通过预读少量数据识别协议类型，然后分发给对应的处理器。

### 流程步骤

#### 1. session::start() 启动协程

**源码位置**: [session.cpp](../../src/prism/agent/session/session.cpp)

```cpp
void session::start()
{
    trace::debug("[Session] [{}] Session started.", id_);

    // 主处理协程：执行协议分流和数据转发
    auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
    {
        try
        {
            co_await self->diversion();
        }
        catch (const std::exception &e)
        {
            trace::error("[Session] [{}] Unhandled exception in diversion: {}", self->id_, e.what());
        }
        catch (...)
        {
            trace::error("[Session] [{}] Unknown exception in diversion", self->id_);
        }

        // 处理完成后释放资源
        self->release_resources();
    };

    // 异常完成回调：捕获并记录协程异常
    auto completion = [self = this->shared_from_this()](const std::exception_ptr &ep) noexcept
    {
        if (!ep)
        {
            return;
        }

        try
        {
            std::rethrow_exception(ep);
        }
        catch (const ::psm::exception::deviant &e)
        {
            // 项目自定义异常，输出完整诊断信息
            trace::error("[Session] [{}] Abnormal exception: {}", self->id_, e.dump());
        }
        catch (const std::exception &e)
        {
            // 标准异常，输出 what() 消息
            trace::error("[Session] [{}] Standard exception: {}", self->id_, e.what());
        }
        catch (...)
        {
            // 未知异常类型
            trace::error("[Session] [{}] Unknown exception type", self->id_);
        }

        self->release_resources();
    };

    // 在 worker 的 io_context 上启动协程
    net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
}
```

**关键操作**:
- 使用 `shared_from_this()` 保活 session
- process lambda 包含 try/catch 和 `release_resources()` 调用
- completion 回调区分 `exception::deviant` / `std::exception` / 未知异常
- completion 回调中同样调用 `release_resources()` 确保异常路径也释放资源

#### 2. session::diversion() 协程

**源码位置**: [session.cpp](../../src/prism/agent/session/session.cpp)

```cpp
auto session::diversion() -> net::awaitable<void>
{
    // 检查入站传输层是否有效
    if (!ctx_.inbound)
    {
        trace::warn("[Session] [{}] diversion aborted: missing inbound transmission.", id_);
        co_return;
    }

    // 1：外层探测
    auto detect_result = co_await protocol::probe(*ctx_.inbound, 24);
    if (fault::failed(detect_result.ec))
    {
        trace::warn("[Session] [{}] Protocol detection failed: {}.", id_, fault::describe(detect_result.ec));
        co_return;
    }

    auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);

    // 2：TLS 剥离（如果外层是 TLS）
    if (detect_result.type == protocol::protocol_type::tls)
    {
        // TLS 握手（复用 ssl_handshake，它会 move ctx_.inbound）
        auto [ssl_ec, ssl_stream] = co_await pipeline::primitives::ssl_handshake(ctx_, span);
        if (fault::failed(ssl_ec) || !ssl_stream)
        {
            trace::warn("[Session] [{}] TLS handshake failed: {}", id_, fault::describe(ssl_ec));
            co_return;
        }

        // 创建加密传输层
        auto encrypted_trans = std::make_shared<channel::transport::encrypted>(ssl_stream);

        // 注册 TLS 流清理回调
        ctx_.active_stream_cancel = [ssl_stream]() noexcept
        {
            ssl_stream->lowest_layer().transmission().cancel();
        };
        ctx_.active_stream_close = [ssl_stream]() noexcept
        {
            ssl_stream->lowest_layer().transmission().close();
        };

        // 增量读取内层数据并逐次探测协议
        constexpr std::size_t trojan_min = 60;
        std::array<std::byte, 64> inner_buf{};
        std::size_t inner_n = 0;

        while (inner_n < trojan_min)
        {
            std::error_code ec;
            auto buf_span = std::span<std::byte>(inner_buf.data() + inner_n, inner_buf.size() - inner_n);
            const auto n = co_await encrypted_trans->async_read_some(std::move(buf_span), ec);
            if (ec)
            {
                trace::warn("[Session] [{}] Inner probe read failed: {}", id_, ec.message());
                co_return;
            }
            inner_n += n;

            const auto inner_view = std::string_view(reinterpret_cast<const char *>(inner_buf.data()), inner_n);
            detect_result.type = protocol::analysis::detect_inner(inner_view);
            if (detect_result.type != protocol::protocol_type::unknown)
            {
                break;
            }
        }

        if (detect_result.type == protocol::protocol_type::unknown)
        {
            trace::warn("[Session] [{}] Cannot determine inner protocol", id_);
            co_return;
        }

        trace::debug("[Session] [{}] TLS inner protocol: {}", id_, protocol::to_string_view(detect_result.type));

        // 更新 ctx_.inbound 为加密传输层
        ctx_.inbound = std::move(encrypted_trans);

        // 更新 span 为内层预读数据
        span = std::span<const std::byte>(inner_buf.data(), inner_n);
    }

    // 3：分发到 handler
    auto handler = dispatch::registry::global().create(detect_result.type);
    if (!handler)
    {
        handler = dispatch::registry::global().create(protocol::protocol_type::unknown);
        if (!handler)
        {
            trace::warn("[Session] [{}] No handler available for protocol.", id_);
            co_return;
        }
    }

    trace::debug("[Session] [{}] Dispatching to handler: {}", id_, handler->name());
    co_await handler->process(ctx_, span);
    trace::debug("[Session] [{}] Handler {} completed.", id_, handler->name());
}
```

#### 3. protocol::probe() 预读 24 字节

**源码位置**: [probe.hpp](../../include/prism/protocol/probe.hpp)

```cpp
inline auto probe(psm::channel::transport::transmission &trans, std::size_t max_peek_size = 24)
    -> net::awaitable<detection_result>
{
    detection_result result;

    const std::size_t peek_size = (std::min)(max_peek_size, result.pre_read_data.size());
    auto span = std::span<std::byte>(result.pre_read_data.data(), peek_size);

    std::error_code sys_ec;
    std::size_t n = co_await trans.async_read_some(span, sys_ec);
    if (sys_ec)
    {
        result.ec = fault::to_code(sys_ec);
        co_return result;
    }
    if (n == 0)
    {
        result.ec = fault::code::eof;
        co_return result;
    }

    std::string_view peek_view(reinterpret_cast<const char *>(result.pre_read_data.data()), n);
    result.type = protocol::analysis::detect(peek_view);

    result.pre_read_size = n;
    result.ec = fault::code::success;

    co_return result;
}
```

**检测逻辑**:
- 预读最多 24 字节数据
- 调用 `protocol::analysis::detect()` 识别协议类型
- 返回 `detection_result` 包含协议类型和预读数据

#### 4. dispatch::registry::global().create() 获取 handler

**源码位置**: [handler.hpp](../../include/prism/agent/dispatch/handler.hpp)

```cpp
auto create(const protocol::protocol_type type) const -> shared_handler
{
    if (const auto it = registry_.find(type); it != registry_.end())
    {
        return it->second();
    }
    trace::warn("Handler NOT found for type {}", protocol::to_string_view(type));
    return nullptr;
}
```

**处理器映射**:

| 协议类型 | 处理器类 | 处理函数 |
|----------|----------|----------|
| `http` | `dispatch::Http` | `pipeline::http()` |
| `socks5` | `dispatch::Socks5` | `pipeline::socks5()` |
| `trojan` | `dispatch::Trojan` | `pipeline::trojan()` |
| `vless` | `dispatch::Vless` | `pipeline::vless()` |
| `shadowsocks` | `dispatch::Shadowsocks` | `pipeline::shadowsocks()` |
| `unknown` | `dispatch::Unknown` | `primitives::tunnel()` |

#### 5. 调用 handler->process(ctx, pre_read_data)

处理器获取预读数据，避免重复读取，直接进入协议处理流程。

---

## 隧道转发流程

隧道转发流程根据协议类型执行不同的处理逻辑，最终建立双向数据隧道。

### HTTP 路径

**源码位置**: [http.cpp](../../src/prism/pipeline/protocols/http.cpp)

#### 流程步骤

```
  HTTP 处理流程
       │
       ├─ 1. 重置帧内存池 (frame_arena)
       ├─ 2. 使用 preview 装饰器包装 inbound（如有预读数据则重放）
       ├─ 3. 创建 http::relay 并调用 handshake()（读取+解析+认证）
       ├─ 4. 调用 analysis::resolve() 提取目标地址
       ├─ 5. 调用 primitives::dial() 建立上游连接
       └─ 6. 判断请求类型
            ├─ CONNECT: 返回 200 → tunnel
            └─ 其他: 重写 URI 分段转发 → tunnel
```

**关键代码**:

```cpp
auto http(session_context &ctx, std::span<const std::byte> data)
    -> net::awaitable<void>
{
    ctx.frame_arena.reset();

    // 包装入站传输（如有预读数据则用 preview 装饰器重放）
    auto inbound = std::move(ctx.inbound);
    if (!data.empty())
    {
        inbound = std::make_shared<primitives::preview>(std::move(inbound), data, ctx.frame_arena.get());
    }

    // 创建 HTTP 中继并握手（读取请求头 + 解析 + 认证）
    auto relay = protocol::http::make_relay(std::move(inbound), ctx.account_directory_ptr);
    auto [ec, req] = co_await relay->handshake();
    if (fault::failed(ec))
    {
        co_return;
    }

    // 解析目标地址并拨号
    const auto target = protocol::analysis::resolve(req);
    auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
    if (fault::failed(fst) || !snd)
    {
        co_await relay->write_bad_gateway();
        co_return;
    }

    // 按方法分发
    if (req.method == "CONNECT")
    {
        co_await relay->write_connect_success();
        co_await primitives::tunnel(relay->release(), std::move(snd), ctx);
    }
    else
    {
        co_await relay->forward(req, snd, ctx.frame_arena.get());
        co_await primitives::tunnel(relay->release(), std::move(snd), ctx);
    }
}
```

### SOCKS5 路径

**源码位置**: [socks5.cpp](../../src/prism/pipeline/protocols/socks5.cpp)

#### 流程步骤

```
  SOCKS5 处理流程
       │
       ├─ 1. 创建 preview 包装器（如有预读数据）
       ├─ 2. 创建 socks5::stream 并调用 handshake()
       └─ 3. 解析命令类型
            ├─ CONNECT:
            │   ├─ 提取目标地址
            │   ├─ dial() 建立上游连接
            │   ├─ 返回成功响应
            │   └─ tunnel 双向转发
            ├─ UDP_ASSOCIATE:
            │   └─ 调用 async_associate() 建立 UDP 转发
            └─ BIND: 返回命令不支持错误
```

### TLS 路径

**源码位置**: [session.cpp](../../src/prism/agent/session/session.cpp)

TLS 握手在 Session 层完成，不在 Pipeline 层。Session 检测到 `protocol_type::tls` 后执行握手，探测内层协议后分发到对应 handler。

#### 流程步骤

```
  TLS 处理流程
       │
       ├─ 1. Session 层探测到 protocol_type::tls
       ├─ 2. 调用 ssl_handshake() 执行 TLS 握手
       ├─ 3. 创建 encrypted 传输层包装已握手的 SSL 流
       ├─ 4. 增量读取内层数据，调用 detect_inner() 探测内层协议
       ├─ 5. 更新 ctx_.inbound 为 encrypted 传输层
       └─ 6. 分发到内层协议 handler（Http/Trojan）并传入预读数据
```

### 原语函数

#### primitives::dial() - 建立上游连接

**源码位置**: [primitives.cpp](../../src/prism/pipeline/primitives.cpp)

```cpp
auto dial(std::shared_ptr<resolve::router> router, std::string_view label,
          const protocol::analysis::target &target, const bool allow_reverse, const bool require_open)
    -> net::awaitable<std::pair<fault::code, shared_transmission>>
{
    // 拒绝 IPv6 地址字面量（仅在禁用 IPv6 时）
    if (router->ipv6_disabled() && is_ipv6_literal(target.host))
    {
        co_return std::make_pair(fault::code::ipv6_disabled, nullptr);
    }

    // 路由到目标
    fault::code ec;
    channel::pooled_connection conn;
    if (allow_reverse && !target.positive)
    {
        auto result = co_await router->async_reverse(target.host);
        ec = result.first;
        conn = std::move(result.second);
    }
    else
    {
        auto result = co_await router->async_forward(target.host, target.port);
        ec = result.first;
        conn = std::move(result.second);
    }

    if (fault::failed(ec))
    {
        co_return std::make_pair(ec, nullptr);
    }

    if (require_open && !conn.valid())
    {
        co_return std::make_pair(fault::code::connection_refused, nullptr);
    }

    co_return std::make_pair(ec, channel::transport::make_reliable(std::move(conn)));
}
```

#### primitives::tunnel() - 双向隧道转发

**源码位置**: [primitives.hpp](../../include/prism/pipeline/primitives.hpp)

**设计要点**:
- 使用单个缓冲区分割为两个半缓冲区
- 使用 `||` 操作符并行运行两个方向的转发协程
- 任一方向断开即终止整个隧道
- 使用 PMR 内存资源分配缓冲区

---

## 连接关闭流程

连接关闭流程确保资源正确释放，避免内存泄漏和悬空引用。

### 流程步骤

**源码位置**: [session.cpp](../../src/prism/agent/session/session.cpp)

```cpp
void session::close()
{
    if (state_ != state::active)
    {
        return;
    }
    state_ = state::closing;
    trace::debug("[Session] [{}] Session closing.", id_);

    // 先取消活跃流（TLS 等），因为 ctx_.inbound 可能已被 move
    if (ctx_.active_stream_cancel)
    {
        ctx_.active_stream_cancel();
    }
    if (ctx_.inbound)
    {
        ctx_.inbound->cancel();
    }
    if (ctx_.outbound)
    {
        ctx_.outbound->cancel();
    }
}
```

### 关闭流程图

```
  连接关闭流程
       │
       ├─ 1. session::close() 幂等关闭
       │   ├─ 检查 state_ != active，若非活跃则直接返回
       │   ├─ 设置 state_ = closing
       │   └─ 取消 active_stream_cancel（TLS 流等）
       │
       ├─ 2. 取消 inbound transmission
       │   └─ 调用 ctx_.inbound->cancel()
       │
       ├─ 3. 取消 outbound transmission
       │   └─ 调用 ctx_.outbound->cancel()
       │
       ├─ 4. release_resources() 由协程退出或析构触发
       │   ├─ 设置 state_ = closed
       │   ├─ 关闭 active_stream_close（TLS 流等）
       │   ├─ 关闭并 reset inbound/outbound
       │   └─ 触发 on_closed 回调（递减 active_sessions 计数）
       │
       └─ 5. 析构函数调用 release_resources()（兜底）
           └─ 确保资源最终释放
```

### 回调链

**源码位置**: [launch.cpp](../../src/prism/agent/worker/launch.cpp)

```cpp
auto on_closed = [active_sessions]() noexcept
{
    active_sessions->fetch_sub(1U, std::memory_order_relaxed);
};
```

**回调职责**:
- 递减 `active_sessions` 原子计数器
- 使用 `memory_order_relaxed` 避免不必要的内存屏障

---

## 流程总览

```
  Prism 运行时总览
       │
       ▼
  Accept (主线程)
       │
       ▼
  Dispatch (投递到 IO)
       │
       ▼
  Prime (配置 Socket)
       │
       ▼
  Start (创建会话)
       │
       ▼
  Session 生命周期
       │
       ├─ Start (启动协程)
       │     │
       │     ▼
       │   Diversion (协议检测)
       │     │
       │     ▼
       │   Protocol Handler
       │     ├─ HTTP
       │     ├─ SOCKS5
       │     ├─ Trojan
       │     ├─ VLESS
       │     ├─ Shadowsocks
       │     └─ Unknown
       │           │
       │           ▼
       │     tunnel() 双向隧道转发
       │           │
       │           ▼
       │     Close (资源释放+回调)
```

---

## 性能考量

基于项目性能准则，运行时流程遵循以下优化策略：

| 准则 | 实践 |
|------|------|
| **零拷贝** | 预读数据直接传递给处理器，避免重复读取 |
| **内存池** | 使用 `frame_arena` 和 PMR 分配隧道缓冲区 |
| **协程保活** | 使用 `shared_from_this()` 延长 session 生命周期 |
| **原子操作** | `active_sessions` 使用 `fetch_sub` 无锁递减 |
| **幂等关闭** | `state_` 状态机确保资源仅释放一次 |
