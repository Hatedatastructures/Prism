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
    net::post(ioc, [&server, &worker, &metrics, sock = std::move(socket)]() mutable
              {
        metrics.handoff_pop();
        if (!sock.is_open())
        {
            return;
        }

        prime(sock, server.cfg.buffer.size);
        try
        {
            start(server, worker, metrics, std::move(sock));
        }
        catch (const std::exception &e)
        {
            trace::error("session launch failed: {}", e.what());
        } });
}
```

**关键操作**:
- 调用 `metrics.handoff_push()` 记录连接移交开始
- 使用 `net::post()` 将连接投递到 worker 的 `io_context`
- 在 worker 线程中调用 `metrics.handoff_pop()` 记录移交完成
- 检查 socket 是否仍然打开

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

    auto inbound = ngx::channel::transport::make_reliable(std::move(socket));
        session::session_params params{server, worker, std::move(inbound)};
    const auto shared_session = ngx::agent::session::make_session(std::move(params));

    metrics.session_open();
    try
    {
        shared_session->set_on_closed(std::move(on_closed));

        const bool auth_enabled = !server.cfg.authentication.credentials.empty() || !server.cfg.authentication.users.empty();
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
    trace::debug("[Session] Session started.");

    auto process = [self = this->shared_from_this()]() -> net::awaitable<void>
    {
        co_await self->diversion();
    };

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
        catch (const exception::deviant &e)
        {
            trace::error(e.dump());
        }
        catch (const std::exception &e)
        {
            trace::error(e.what());
        }

        self->close();
    };

    net::co_spawn(ctx_.worker.io_context, std::move(process), std::move(completion));
}
```

**关键操作**:
- 使用 `shared_from_this()` 保活 session
- 创建 `diversion()` 协程处理协议分流
- 设置异常处理完成回调

#### 2. session::diversion() 协程

**源码位置**: [session.cpp](../../src/prism/agent/session/session.cpp)

```cpp
auto session::diversion() -> net::awaitable<void>
{
    if (!ctx_.inbound)
    {   //检测入站指针是否有效
        trace::warn("[Session] diversion aborted: missing inbound transmission.");
        co_return;
    }
    // 预读检测协议类型
    auto detect_result = co_await protocol::probe::probe(*ctx_.inbound, 24);
    if (fault::failed(detect_result.ec))
    {
        trace::warn("[Session] Protocol detection failed: {}.", fault::describe(detect_result.ec));
        co_return;
    }

    auto handler = dispatch::registry::global().create(detect_result.type);
    if (!handler)
    {
        handler = dispatch::registry::global().create(protocol::protocol_type::unknown);
        if (!handler)
        {
            trace::warn("[Session] No handler available for protocol.");
            co_return;
        }
    }
    // 预读的24字节数据
    auto span = std::span<const std::byte>(detect_result.pre_read_data.data(), detect_result.pre_read_size);
    co_await handler->process(ctx_, span);
}
```

#### 3. protocol::probe::probe() 预读 24 字节

**源码位置**: [probe.hpp](../../include/prism/protocol/probe.hpp)

```cpp
inline auto probe(ngx::channel::transport::transmission &trans, std::size_t max_peek_size = 24)
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
| `unknown` | `dispatch::Unknown` | `primitives::tunnel()` |

#### 5. 调用 handler->process(ctx, pre_read_data)

处理器获取预读数据，避免重复读取，直接进入协议处理流程。

---

## 隧道转发流程

隧道转发流程根据协议类型执行不同的处理逻辑，最终建立双向数据隧道。

### HTTP 路径

**源码位置**: [protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

#### 流程步骤

```
┌─────────────────────────────────────────────────────────────────┐
│                        HTTP 处理流程                             │
├─────────────────────────────────────────────────────────────────┤
│  1. 创建 connector 包装 inbound                                        │
│  2. 将预读数据写入 read_buffer                                   │
│  3. 调用 http::async_read() 解析 HTTP 请求                       │
│  4. 调用 analysis::resolve() 提取目标地址                        │
│  5. 调用 primitives::dial() 建立上游连接                         │
│  6. 判断请求类型:                                                │
│     ├─ CONNECT: 返回 200 → tunnel                      │
│     └─ 其他: 序列化请求转发 → tunnel                    │
└─────────────────────────────────────────────────────────────────┘
```

**关键代码**:

```cpp
auto http(session_context &ctx, std::span<const std::byte> data)
    -> net::awaitable<void>
{
    ngx::channel::connector stream(std::move(ctx.inbound));
    ngx::channel::transport::transmission_pointer outbound;

    ctx.frame_arena.reset();
    auto mr = ctx.frame_arena.get();
    beast::basic_flat_buffer read_buffer(protocol::http::network_allocator{mr});

    // 写入预读数据
    if (!data.empty())
    {
        auto dest = read_buffer.prepare(data.size());
        std::memcpy(dest.data(), data.data(), data.size());
        read_buffer.commit(data.size());
    }

    protocol::http::request req(mr);
    {
        const auto ec = co_await protocol::http::async_read(stream, req, read_buffer, mr);
        if (fault::failed(ec))
            co_return;

        const auto target = protocol::analysis::resolve(req);
        trace::info("[Pipeline] Http analysis target = [host: {}, port: {}, positive: {}]",
                    target.host, target.port, target.positive);

        std::shared_ptr<resolve::router> router_ptr(&ctx.worker.router, [](resolve::router *) {});
        auto [fst, snd] = co_await primitives::dial(router_ptr, "HTTP", target, true, false);
        if (fault::failed(fst) || !snd)
            co_return;
        outbound = std::move(snd);
    }

    // CONNECT 方法处理
    if (req.method() == protocol::http::verb::connect)
    {
        boost::system::error_code ec;
        constexpr std::string_view resp = {"HTTP/1.1 200 Connection Established\r\n\r\n"};
        co_await stream.async_write_some(net::buffer(resp), net::redirect_error(net::use_awaitable, ec));
        if (!ec)
        {
            co_await primitives::tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
        }
        co_return;
    }

    // 普通请求处理
    std::error_code ec;
    const auto req_data = protocol::http::serialize(req, mr);
    co_await outbound->async_write_some(
        std::span(reinterpret_cast<const std::byte *>(req_data.data()), req_data.size()), ec);
    
    if (read_buffer.size() > 0)
    {
        auto buf = read_buffer.data();
        std::span span(static_cast<const std::byte *>(buf.data()), buf.size());
        co_await outbound->async_write_some(span, ec);
    }

    co_await primitives::tunnel(stream.release(), std::move(outbound), mr, ctx.buffer_size);
}
```

### SOCKS5 路径

**源码位置**: [protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

#### 流程步骤

```
┌─────────────────────────────────────────────────────────────────┐
│                       SOCKS5 处理流程                            │
├─────────────────────────────────────────────────────────────────┤
│  1. 创建 preview 包装器（如有预读数据）                           │
│  2. 创建 socks5::stream 并调用 handshake()                       │
│  3. 解析命令类型:                                                │
│     ├─ CONNECT:                                                 │
│     │   ├─ 提取目标地址                                         │
│     │   ├─ dial() 建立上游连接                                  │
│     │   ├─ 返回成功响应                                         │
│     │   └─ tunnel 双向转发                             │
│     ├─ UDP_ASSOCIATE:                                           │
│     │   └─ 调用 async_associate() 建立 UDP 转发                 │
│     └─ BIND: 返回命令不支持错误                                 │
└─────────────────────────────────────────────────────────────────┘
```

### TLS 路径

**源码位置**: [protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

#### 流程步骤

```
┌─────────────────────────────────────────────────────────────────┐
│                        TLS 处理流程                              │
├─────────────────────────────────────────────────────────────────┤
│  1. 创建 connector 包装 inbound                                        │
│  2. 创建 ssl::stream 并执行 TLS 握手                             │
│  3. 调用 http::async_read() 解析内部 HTTP 请求                   │
│  4. 调用 analysis::resolve() 提取目标地址                        │
│  5. 调用 primitives::dial() 建立上游连接                         │
│  6. 判断请求类型:                                                │
│     ├─ CONNECT: 返回 200 → tunnel                      │
│     └─ 其他: 序列化请求转发 → tunnel                    │
└─────────────────────────────────────────────────────────────────┘
```

### 原语函数

#### primitives::dial() - 建立上游连接

**源码位置**: [primitives.cpp](../../src/prism/agent/pipeline/primitives.cpp)

```cpp
auto dial(std::shared_ptr<resolve::router> router, std::string_view label,
          const protocol::analysis::target &target, const bool allow_reverse,
          const bool require_open)
    -> net::awaitable<std::pair<fault::code, ngx::channel::transport::transmission_pointer>>
{
    auto ec = fault::code::success;
    ngx::channel::unique_sock socket;

    if (allow_reverse && !target.positive)
    {
        auto [route_ec, routed] = co_await router->async_reverse(target.host);
        ec = route_ec;
        socket = std::move(routed);
    }
    else
    {
        auto [route_ec, routed] = co_await router->async_forward(target.host, target.port);
        ec = route_ec;
        socket = std::move(routed);
    }

    if (fault::failed(ec))
    {
        trace::warn("[Pipeline] {} route failed: {}", label, fault::describe(ec));
        co_return std::make_pair(ec, nullptr);
    }

    if (require_open && (!socket || !socket->is_open()))
    {
        trace::error("[Pipeline] {} route to upstream failed (connection invalid).", label);
        co_return std::make_pair(fault::code::connection_refused, nullptr);
    }

    trace::debug("[Pipeline] {} upstream connected.", label);
    co_return std::make_pair(ec, ngx::channel::transport::make_reliable(std::move(*socket)));
}
```

#### primitives::tunnel() - 双向隧道转发

**源码位置**: [primitives.hpp](../../include/prism/agent/pipeline/primitives.hpp)

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
    auto close_and_reset = [](auto &ptr) noexcept
    {   // 关闭并重置指针
        if (ptr)
        {
            ptr->close();
            ptr.reset();
        }
    };

    if (closed_)
    {
        return;
    }
    closed_ = true;
    trace::debug("[Session] Session closing.");
    
    close_and_reset(ctx_.inbound);
    close_and_reset(ctx_.outbound);
    if (on_closed_)
    {
        auto callback = std::move(on_closed_);
        on_closed_ = nullptr;
        callback();
    }
}
```

### 关闭流程图

```
┌─────────────────────────────────────────────────────────────────┐
│                       连接关闭流程                               │
├─────────────────────────────────────────────────────────────────┤
│  1. session::close() 幂等关闭                                    │
│     ├─ 检查 closed_ 标志，若已关闭则直接返回                     │
│     └─ 设置 closed_ = true                                      │
│                                                                 │
│  2. 关闭 inbound transmission                                   │
│     ├─ 调用 ptr->close()                                        │
│     └─ 调用 ptr.reset() 释放所有权                              │
│                                                                 │
│  3. 关闭 outbound transmission                                  │
│     ├─ 调用 ptr->close()                                        │
│     └─ 调用 ptr.reset() 释放所有权                              │
│                                                                 │
│  4. 触发 on_closed 回调                                         │
│     ├─ 移动回调到局部变量                                       │
│     ├─ 清空 on_closed_ 成员                                     │
│     └─ 执行回调（递减 active_sessions 计数）                    │
└─────────────────────────────────────────────────────────────────┘
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
┌─────────────────────────────────────────────────────────────────────────────┐
│                           prism 运行时总览                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌───────────┐ │
│  │   Accept     │───▶│   Dispatch   │───▶│    Prime     │───▶│   Start   │ │
│  │  (主线程)    │    │  (投递到IO)  │    │ (配置Socket) │    │(创建会话) │ │
│  └──────────────┘    └──────────────┘    └──────────────┘    └───────────┘ │
│                                                                     │       │
│                                                                     ▼       │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        Session 生命周期                               │  │
│  │  ┌────────────┐    ┌─────────────┐    ┌───────────────────────────┐ │  │
│  │  │   Start    │───▶│  Diversion  │───▶│    Protocol Handler       │ │  │
│  │  │ (启动协程) │    │ (协议检测)  │    │  ┌─────────┬─────────┐    │ │  │
│  │  └────────────┘    └─────────────┘    │  │   HTTP  │ SOCKS5  │    │ │  │
│  │                                        │  ├─────────┼─────────┤    │ │  │
│  │                                        │  │   TLS   │ Unknown │    │ │  │
│  │                                        │  └─────────┴─────────┘    │ │  │
│  │                                        └───────────────────────────┘ │  │
│  │                                                     │                │  │
│  │                                                     ▼                │  │
│  │                                        ┌───────────────────────────┐ │  │
│  │                                        │    tunnel()      │ │  │
│  │                                        │    (双向隧道转发)         │ │  │
│  │                                        └───────────────────────────┘ │  │
│  │                                                     │                │  │
│  │                                                     ▼                │  │
│  │                                        ┌───────────────────────────┐ │  │
│  │                                        │       Close               │ │  │
│  │                                        │   (资源释放+回调)         │ │  │
│  │                                        └───────────────────────────┘ │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
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
| **幂等关闭** | `closed_` 标志确保资源仅释放一次 |
