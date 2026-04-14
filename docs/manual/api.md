# Prism API 参考文档

Prism 代理服务器完整 API 参考，涵盖启动、会话、管道、通道、DNS、内存等全部公开接口。

---

## 目录

- [公开头文件总入口](#公开头文件总入口)
- [核心 API 总览](#核心-api-总览)
- [Agent 启动 API](#agent-启动-api)
- [配置结构体映射](#配置结构体映射)
- [Session API](#session-api)
- [Pipeline 原语](#pipeline-原语)
- [Handler / Registry API](#handler--registry-api)
- [Channel API](#channel-api)
- [Resolve API](#resolve-api)
- [Memory API](#memory-api)
- [协程使用约定](#协程使用约定)

---

## 公开头文件总入口

`include/prism/agent.hpp` 是 agent 模块公开 API 总入口：

```cpp
#pragma once

#include <prism/agent/account/directory.hpp>
#include <prism/agent/account/entry.hpp>
#include <prism/agent/config.hpp>
#include <prism/agent/session/session.hpp>
#include <prism/agent/context.hpp>
#include <prism/agent/dispatch/handler.hpp>
#include <prism/agent/dispatch/handlers.hpp>
#include <prism/resolve/router.hpp>
#include <prism/resolve/transparent.hpp>
#include <prism/agent/front/balancer.hpp>
#include <prism/agent/front/listener.hpp>
#include <prism/pipeline/primitives.hpp>
#include <prism/pipeline/protocols.hpp>
#include <prism/agent/worker/launch.hpp>
#include <prism/agent/worker/stats.hpp>
#include <prism/agent/worker/tls.hpp>
#include <prism/agent/worker/worker.hpp>
```

### 配置与上下文

```cpp
#include <prism/agent/config.hpp>       // config 结构体
#include <prism/agent/context.hpp>      // server_context, worker_context, session_context
```

### 账户管理

```cpp
#include <prism/agent/account/directory.hpp>  // directory 类
#include <prism/agent/account/entry.hpp>      // entry 结构体, lease 类
```

### 连接管理

```cpp
#include <prism/agent/session/session.hpp> // session 类, make_session()
```

### 协议分发

```cpp
#include <prism/agent/dispatch/handler.hpp>   // handler 基类, registry 类
#include <prism/agent/dispatch/handlers.hpp>  // Http, Socks5, Trojan, Vless, Shadowsocks, Unknown 处理器, register_handlers()
```

### 分发路由

```cpp
#include <prism/resolve/router.hpp>     // router 类
#include <prism/resolve/cache.hpp>   // cache 类
#include <prism/resolve/coalescer.hpp>  // coalescer 类
#include <prism/resolve/transparent.hpp> // transparent_hash, transparent_equal
```

### 前端监听

```cpp
#include <prism/agent/front/balancer.hpp>  // balancer 类, worker_load_snapshot
#include <prism/agent/front/listener.hpp>  // listener 类
```

### 协议管道

```cpp
#include <prism/pipeline/primitives.hpp>  // dial(), preview, tunnel()
#include <prism/pipeline/protocols.hpp>   // 聚合头文件，引入 http.hpp, socks5.hpp, trojan.hpp, vless.hpp, shadowsocks.hpp
#include <prism/pipeline/protocols/http.hpp>   // http()
#include <prism/pipeline/protocols/socks5.hpp> // socks5()
#include <prism/pipeline/protocols/trojan.hpp> // trojan()
#include <prism/pipeline/protocols/vless.hpp>  // vless()
#include <prism/pipeline/protocols/shadowsocks.hpp> // shadowsocks()
```

### 工作线程

```cpp
#include <prism/agent/worker/launch.hpp>  // launch 命名空间
#include <prism/agent/worker/stats.hpp>   // stats::state 类
#include <prism/agent/worker/tls.hpp>     // tls 命名空间
#include <prism/agent/worker/worker.hpp>  // worker 类
```

---

## 核心 API 总览

| 模块 | 关键类型/函数 | 头文件 | 命名空间 |
|------|--------------|--------|----------|
| 配置加载 | `loader::load()` | `include/prism/loader/load.hpp` | `psm::loader` |
| 账户构建 | `loader::build_account_directory()` | `include/prism/loader/load.hpp` | `psm::loader` |
| 内存初始化 | `memory::system::enable_global_pooling()` | `include/prism/memory/pool.hpp` | `psm::memory::system` |
| 处理器注册 | `dispatch::register_handlers()` | `include/prism/agent/dispatch/handlers.hpp` | `psm::agent::dispatch` |
| 会话管理 | `session::session`, `session::make_session()` | `include/prism/agent/session/session.hpp` | `psm::agent::session` |
| 上游拨号 | `primitives::dial()` | `include/prism/pipeline/primitives.hpp` | `psm::pipeline::primitives` |
| 双向转发 | `primitives::tunnel()` | `include/prism/pipeline/primitives.hpp` | `psm::pipeline::primitives` |
| 预读回放 | `primitives::preview` | `include/prism/pipeline/primitives.hpp` | `psm::pipeline::primitives` |
| 处理器工厂 | `dispatch::registry::global()` | `include/prism/agent/dispatch/handler.hpp` | `psm::agent::dispatch` |
| 传输抽象 | `transport::transmission` | `include/prism/channel/transport/transmission.hpp` | `psm::channel::transport` |
| 连接池 | `channel::connection_pool` | `include/prism/channel/connection/pool.hpp` | `psm::channel` |
| DNS 路由 | `resolve::router` | `include/prism/resolve/router.hpp` | `psm::resolve` |
| DNS 门面 | `resolve::recursor` | `include/prism/resolve/recursor.hpp` | `psm::resolve` |
| 错误码 | `fault::code` | `include/prism/fault/code.hpp` | `psm::fault` |
| 内存容器 | `memory::string`, `memory::vector` | `include/prism/memory/container.hpp` | `psm::memory` |
| 账户目录 | `account::directory` | `include/prism/agent/account/directory.hpp` | `psm::agent::account` |

---

## Agent 启动 API

### 启动流程

```
enable_global_pooling()
       |
       v
loader::load() + trace::init()
       |
       v
register_handlers()
       |
       v
build_account_directory()
       |
       v
创建 worker 线程池 (CPU-1 个)
       |
       v
绑定 balancer + 启动 listener
```

### loader::load()

从 JSON 文件加载全局配置。

```cpp
// include/prism/loader/load.hpp
namespace psm::loader {
    auto load(std::string_view path) -> psm::config;
}
```

- **返回**: `psm::config` 聚合配置对象，包含 `agent` 和 `trace` 两个子配置
- **异常**: 文件打开失败时抛出 `exception::security`

```cpp
auto [agent_cfg, trace_cfg] = psm::loader::load("config.json");
psm::trace::init(trace_cfg);
```

### loader::build_account_directory()

从认证配置构建运行时账户目录。每个 user 的 `password` 经 SHA224 规范化后注册，`uuid` 直接注册，两种凭证共享同一个 `entry`。

```cpp
// include/prism/loader/load.hpp
namespace psm::loader {
    auto build_account_directory(const agent::authentication &auth)
        -> std::shared_ptr<agent::account::directory>;
}
```

### memory::system::enable_global_pooling()

设置 C++ 标准库默认内存资源为全局内存池，必须在所有 PMR 容器使用前调用。

```cpp
// include/prism/memory/pool.hpp
namespace psm::memory::system {
    static void enable_global_pooling();
    static synchronized_pool *global_pool();
    static unsynchronized_pool *thread_local_pool();
    static unsynchronized_pool *hot_path_pool();
}
```

### dispatch::register_handlers()

注册所有协议处理器到全局工厂，必须在所有工作线程启动前调用。

```cpp
// include/prism/agent/dispatch/handlers.hpp
namespace psm::agent::dispatch {
    void register_handlers();
}
```

注册的处理器：`Http`、`Socks5`、`Trojan`、`Vless`、`Shadowsocks`、`Unknown`。

---

## 配置结构体映射

### JSON 到 C++ 结构体对应关系

配置文件 `src/configuration.json` 通过 Glaze 库映射到以下 C++ 类型：

| JSON 路径 | C++ 类型 | 头文件 |
|-----------|---------|--------|
| `agent` | `psm::agent::config` | `include/prism/agent/config.hpp` |
| `agent.addressable` | `agent::endpoint { host, port }` | `include/prism/agent/config.hpp` |
| `agent.positive` | `agent::endpoint { host, port }` | `include/prism/agent/config.hpp` |
| `agent.limit` | `agent::limit { concurrences, blacklist }` | `include/prism/agent/config.hpp` |
| `agent.certificate` | `agent::certificate { key, cert }` | `include/prism/agent/config.hpp` |
| `agent.authentication` | `agent::authentication { users }` | `include/prism/agent/config.hpp` |
| `agent.authentication.users[]` | `authentication::user { password, uuid, max_connections }` | `include/prism/agent/config.hpp` |
| `agent.camouflage` | `memory::string` | `include/prism/agent/config.hpp` |
| `agent.reverse_map` | `memory::map<memory::string, endpoint>` | `include/prism/agent/config.hpp` |
| `agent.pool` | `channel::config` | `include/prism/channel/connection/pool.hpp` |
| `agent.buffer` | `agent::buffer { size }` | `include/prism/agent/config.hpp` |
| `agent.socks5` | `protocol::socks5::config` | `include/prism/protocol/socks5/config.hpp` |
| `agent.trojan` | `protocol::trojan::config` | `include/prism/protocol/trojan/config.hpp` |
| `agent.vless` | `protocol::vless::config` | `include/prism/protocol/vless/config.hpp` |
| `agent.shadowsocks` | `protocol::shadowsocks::config` | `include/prism/protocol/shadowsocks/config.hpp` |
| `agent.reality` | `protocol::reality::config` | `include/prism/protocol/reality/config.hpp` |
| `agent.mux` | `multiplex::config` | `include/prism/multiplex/config.hpp` |
| `agent.dns` | `resolve::config` | `include/prism/resolve/config.hpp` |
| `trace` | `psm::trace::config` | `include/prism/trace/config.hpp` |

### 上下文结构体

三个上下文贯穿请求处理全生命周期：

| 结构体 | 作用域 | 头文件 |
|--------|--------|--------|
| `server_context` | 全局，所有 worker 共享 | `include/prism/agent/context.hpp` |
| `worker_context` | 线程局部，每 worker 独有 | `include/prism/agent/context.hpp` |
| `session_context` | 会话局部，每连接独有 | `include/prism/agent/context.hpp` |

```cpp
struct server_context {
    const config &cfg;
    std::shared_ptr<ssl::context> ssl_ctx;
    std::shared_ptr<account::directory> account_store;
};

struct worker_context {
    net::io_context &io_context;
    resolve::router &router;
    memory::resource_pointer memory_pool;
};

struct session_context {
    std::uint64_t session_id{0};
    const server_context &server;
    worker_context &worker;
    memory::frame_arena &frame_arena;
    std::function<bool(std::string_view)> credential_verifier;
    account::directory *account_directory_ptr;
    std::uint32_t buffer_size;
    transport::shared_transmission inbound;
    transport::shared_transmission outbound;
    account::lease account_lease;
    std::function<void()> active_stream_cancel;
    std::function<void()> active_stream_close;
};
```

---

## Session API

会话管理单个入站连接的完整生命周期，定义在 `include/prism/agent/session/session.hpp` 中。

### session::session

```cpp
namespace psm::agent::session {
    struct session_params {
        server_context &server;
        worker_context &worker;
        transport::shared_transmission inbound;
    };

    enum class state : std::uint8_t {
        active,    // 活跃状态
        closing,   // 正在关闭
        closed     // 已关闭
    };

    class session : public std::enable_shared_from_this<session> {
    public:
        explicit session(session_params params);
        ~session();

        void start();                                               // 启动异步处理（只能调用一次）
        void close();                                               // 关闭会话（幂等）
        void set_credential_verifier(std::function<bool(std::string_view)> verifier);
        void set_account_directory(account::directory *dir) noexcept;
        void set_on_closed(std::function<void()> callback) noexcept;
        [[nodiscard]] std::uint64_t id() const noexcept;
    };
}
```

### make_session()

会话工厂函数，确保对象始终通过 `shared_ptr` 管理。

```cpp
namespace psm::agent::session {
    [[nodiscard]] std::shared_ptr<session> make_session(session_params &&params) noexcept;
}
```

```cpp
// 由 launch::start 内部调用
auto params = session::session_params{server_ctx, worker_ctx, std::move(inbound)};
auto sess = session::make_session(std::move(params));
sess->set_credential_verifier([&dir](std::string_view cred) { return account::contains(dir, cred); });
sess->set_account_directory(&dir);
sess->set_on_closed([&counter]() { --counter; });
sess->start();
```

---

## Pipeline 原语

管道原语定义在 `include/prism/pipeline/primitives.hpp` 中，提供连接建立、数据预读和双向转发能力。

### dial() -- 建立上游连接

```cpp
namespace psm::pipeline::primitives {
    auto dial(
        std::shared_ptr<resolve::router> router,
        std::string_view label,
        const protocol::analysis::target &target,
        bool allow_reverse,
        bool require_open
    ) -> net::awaitable<std::pair<fault::code, shared_transmission>>;
}
```

- **co_await 返回**: `std::pair<fault::code, shared_transmission>` -- 根据 `target.positive` 选择正向/反向路由，连接成功后包装为 `reliable` 传输

### preview -- 预读数据回放

```cpp
namespace psm::pipeline::primitives {
    class preview final : public channel::transport::transmission {
    public:
        explicit preview(
            shared_transmission inner,
            std::span<const std::byte> preread,
            memory::resource_pointer mr = memory::current_resource()
        );

        [[nodiscard]] bool is_reliable() const noexcept override;
        [[nodiscard]] executor_type executor() const override;
        auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;
        auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> override;
        void close() override;
        void cancel() override;
    };
}
```

优先返回预读缓冲区内容，耗尽后委托给内部传输。

### tunnel() -- 双向转发

```cpp
namespace psm::pipeline::primitives {
    auto tunnel(
        shared_transmission inbound,
        shared_transmission outbound,
        const session_context &ctx,
        bool complete_write = true
    ) -> net::awaitable<void>;
}
```

任一方向断开即终止整个隧道，结束后自动关闭两端连接。

### ssl_handshake() -- TLS 服务端握手

```cpp
namespace psm::pipeline::primitives {
    auto ssl_handshake(
        session_context &ctx,
        std::span<const std::byte> data
    ) -> net::awaitable<std::pair<fault::code, shared_ssl_stream>>;
}
```

将入站传输层包装为 connector，执行 TLS 服务端握手。

### shut_close() -- 安全关闭辅助

```cpp
namespace psm::pipeline::primitives {
    inline void shut_close(channel::transport::transmission *trans) noexcept;
    inline void shut_close(shared_transmission &trans) noexcept;
}
```

---

## Handler / Registry API

协议处理器和注册表定义在 `include/prism/agent/dispatch/handler.hpp` 和 `handlers.hpp` 中，header-only 实现。

### handler 基类

```cpp
namespace psm::agent::dispatch {
    class handler {
    public:
        virtual ~handler() = default;
        virtual auto process(session_context &ctx, std::span<const std::byte> data)
            -> net::awaitable<void> = 0;
        [[nodiscard]] virtual auto type() const -> protocol::protocol_type = 0;
        [[nodiscard]] virtual auto name() const -> std::string_view = 0;
    };
}
```

### registry 处理器注册表

```cpp
namespace psm::agent::dispatch {
    class registry {
    public:
        static auto global() -> registry &;
        static auto instantiation() -> registry &;

        template <typename Handler, typename... Args>
        void register_handler(protocol::protocol_type type, Args &&...args);

        [[nodiscard]] auto create(protocol::protocol_type type) const -> shared_handler;
        [[nodiscard]] auto registered(protocol::protocol_type type) const -> bool;
        [[nodiscard]] auto registered_types() const -> std::vector<protocol::protocol_type>;
    };
}
```

### 已注册处理器列表

| 处理器类 | 协议类型 | 管道委托 |
|----------|---------|---------|
| `Http` | `protocol_type::http` | `pipeline::http(ctx, data)` |
| `Socks5` | `protocol_type::socks5` | `pipeline::socks5(ctx, data)` |
| `Trojan` | `protocol_type::trojan` | `pipeline::trojan(ctx, data)` |
| `Vless` | `protocol_type::vless` | `pipeline::vless(ctx, data)` |
| `Shadowsocks` | `protocol_type::shadowsocks` | `pipeline::shadowsocks(ctx, data)` |
| `Unknown` | `protocol_type::unknown` | `primitives::tunnel(inbound, outbound, ctx)` |

---

## Channel API

### transmission -- 传输层抽象接口

定义在 `include/prism/channel/transport/transmission.hpp` 中。

```cpp
namespace psm::channel::transport {
    class transmission {
    public:
        using executor_type = net::any_io_executor;
        virtual ~transmission() = default;

        [[nodiscard]] virtual bool is_reliable() const noexcept;
        [[nodiscard]] virtual executor_type executor() const = 0;
        [[nodiscard]] executor_type get_executor() const;

        virtual auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;
        virtual auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t> = 0;
        virtual auto async_write(std::span<const std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>;
        virtual auto async_read(std::span<std::byte> buffer, std::error_code &ec)
            -> net::awaitable<std::size_t>;
        virtual auto async_write_scatter(
            const std::span<const std::byte> *buffers, std::size_t count, std::error_code &ec)
            -> net::awaitable<std::size_t>;

        virtual void shutdown_write();
        virtual void close() = 0;
        virtual void cancel() = 0;
    };

    using shared_transmission = std::shared_ptr<transmission>;
}
```

### connection_pool -- TCP 连接池

定义在 `include/prism/channel/connection/pool.hpp` 中，每个 worker 持有独立实例。

```cpp
namespace psm::channel {
    struct config {
        std::uint32_t max_cache_per_endpoint = 32;
        std::uint64_t connect_timeout_ms = 300;
        std::uint64_t max_idle_seconds = 30;
        std::uint64_t cleanup_interval_sec = 10;
        std::uint32_t recv_buffer_size = 65536;
        std::uint32_t send_buffer_size = 65536;
        bool tcp_nodelay = true;
        bool keep_alive = true;
        bool cache_ipv6 = false;
    };

    class connection_pool {
    public:
        explicit connection_pool(net::io_context &ioc,
            memory::resource_pointer resource = memory::current_resource(),
            const config &config = {});

        [[nodiscard]] auto async_acquire(tcp::endpoint endpoint)
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;
        void start();
        [[nodiscard]] auto stats() const -> pool_stats;
    };
}
```

### pooled_connection -- 连接 RAII 包装器

```cpp
namespace psm::channel {
    class pooled_connection {
    public:
        pooled_connection() = default;
        ~pooled_connection();  // 自动归还连接到池

        pooled_connection(pooled_connection &&) noexcept;
        pooled_connection &operator=(pooled_connection &&) noexcept;

        [[nodiscard]] tcp::socket *get() const noexcept;
        [[nodiscard]] tcp::socket &operator*() const noexcept;
        [[nodiscard]] tcp::socket *operator->() const noexcept;
        [[nodiscard]] bool valid() const noexcept;
        [[nodiscard]] explicit operator bool() const noexcept;
        [[nodiscard]] tcp::socket *release() noexcept;
        void reset();
    };
}
```

---

## Resolve API

### router -- 分发层路由器

定义在 `include/prism/resolve/router.hpp` 中，整合 DNS 解析器、反向路由表和连接池。

```cpp
namespace psm::resolve {
    class router {
    public:
        explicit router(connection_pool &pool, net::io_context &ioc,
                        config dns_cfg,
                        memory::resource_pointer mr = memory::current_resource());

        void set_positive_endpoint(std::string_view host, std::uint16_t port);
        void add_reverse_route(std::string_view host, const tcp::endpoint &ep);

        [[nodiscard]] auto async_reverse(std::string_view host) const
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;
        [[nodiscard]] auto async_direct(tcp::endpoint ep) const
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;
        [[nodiscard]] auto async_forward(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, pooled_connection>>;
        [[nodiscard]] auto async_datagram(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;
        [[nodiscard]] auto resolve_datagram_target(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, net::ip::udp::endpoint>>;
        [[nodiscard]] auto ipv6_disabled() const noexcept -> bool;
    };
}
```

### recursor -- DNS 解析器门面

定义在 `include/prism/resolve/recursor.hpp` 中，实现六阶段查询管道（规则匹配 -> 缓存 -> 合并 -> 上游查询 -> IP 过滤 -> TTL 钳制）。

```cpp
namespace psm::resolve {
    class recursor {
    public:
        explicit recursor(net::io_context &ioc, config cfg,
                          memory::resource_pointer mr = memory::current_resource());

        [[nodiscard]] auto resolve(std::string_view host)
            -> net::awaitable<std::pair<fault::code, memory::vector<net::ip::address>>>;
        [[nodiscard]] auto resolve_tcp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, memory::vector<tcp::endpoint>>>;
        [[nodiscard]] auto resolve_udp(std::string_view host, std::string_view port)
            -> net::awaitable<std::pair<fault::code, udp::endpoint>>;
    };
}
```

---

## Memory API

Prism 采用 PMR (多态内存资源) 实现热路径零堆分配，API 定义在 `include/prism/memory/` 下。

### PMR 容器别名

定义在 `include/prism/memory/container.hpp` 中。

| 别名 | 底层类型 |
|------|---------|
| `memory::resource` | `std::pmr::memory_resource` |
| `memory::resource_pointer` | `memory_resource*` |
| `memory::allocator<T>` | `std::pmr::polymorphic_allocator<T>` |
| `memory::synchronized_pool` | `std::pmr::synchronized_pool_resource` |
| `memory::unsynchronized_pool` | `std::pmr::unsynchronized_pool_resource` |
| `memory::monotonic_buffer` | `std::pmr::monotonic_buffer_resource` |
| `memory::string` | `std::pmr::string` |
| `memory::vector<T>` | `std::pmr::vector<T>` |
| `memory::list<T>` | `std::pmr::list<T>` |
| `memory::map<K, V>` | `std::pmr::map<K, V>` |
| `memory::unordered_map<K, V>` | `std::pmr::unordered_map<K, V>` |
| `memory::unordered_set<K>` | `std::pmr::unordered_set<K>` |

### 内存池初始化

定义在 `include/prism/memory/pool.hpp` 中。

```cpp
namespace psm::memory {
    struct policy {
        static constexpr std::size_t max_blocks = 256;
        static constexpr std::size_t max_pool_size = 16384;
        static constexpr std::size_t small_buffer_size = 8192;
    };

    class system {
    public:
        static synchronized_pool *global_pool();
        static unsynchronized_pool *thread_local_pool();
        static unsynchronized_pool *hot_path_pool();
        static void enable_global_pooling();
    };

    template <typename T>
    class pooled_object {
    public:
        void *operator new(std::size_t count);
        void operator delete(void *ptr, std::size_t count);
    };

    class frame_arena {
    public:
        frame_arena();
        resource_pointer get();
        void reset();
    };
}
```

---

## 协程使用约定

### 基本规则

1. 所有异步操作返回 `net::awaitable<T>`（`namespace net = boost::asio`）
2. 使用 `co_await` 执行顺序异步操作
3. 使用 `net::co_spawn` 启动独立协程
4. 协程中禁止阻塞（`sleep`、`mutex`、`condition_variable` 等）
5. 热路径通过 `fault::code` 返回错误，严禁抛异常
6. 异常仅用于启动阶段致命错误

### 线程模型约束

| 组件 | 线程安全 | 备注 |
|------|---------|------|
| `session` | 单 io_context 线程 | 内部无锁 |
| `worker` | 仅 `dispatch_socket()` / `load_snapshot()` | 其余方法在 worker 线程内调用 |
| `router` | 单 io_context 线程 | per-worker 实例 |
| `recursor` | 单 io_context 线程 | per-worker 实例 |
| `connection_pool` | 单 io_context 线程 | 线程局部使用 |
| `account::directory` | 线程安全 | 原子共享指针 + 写时复制 |
| `dispatch::registry` | 注册阶段单线程，查询线程安全 | 单例 |

### co_await 结果处理模式

```cpp
// 模式一: pair<fault::code, T> 返回值
auto [ec, result] = co_await async_operation();
if (psm::fault::failed(ec)) { co_return; }

// 模式二: std::error_code& 输出参数
std::error_code ec;
auto n = co_await trans->async_read_some(buffer, ec);
if (ec) { /* 错误处理 */ }

// 模式三: void 返回
co_await primitives::tunnel(inbound, outbound, ctx);
```

---

## 稳定 API vs 内部实现

- 以上头文件为稳定 API，外部代码应通过 `#include <prism/agent.hpp>` 访问
- `.cpp` 文件中的实现细节不属于稳定 API
- dispatch 模块是 header-only，所有内容都在头文件中
