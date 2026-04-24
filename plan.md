# Prism vs mihomo 深度对比分析与开发路线

> 本文档基于对 Prism (C++23 纯协程代理服务器) 和 mihomo-Meta (Go Clash.Meta 代理服务器, E:\mihomo-Meta) 的全面源码分析，给出架构差距评估、层级优化方案和分阶段开发路线。

---

## 一、Prism 优势分析（相对 mihomo 的技术领先点）

### 1.1 协程 vs Goroutine — 内存与延迟优势

| 维度 | Prism (C++23) | mihomo (Go) |
|------|---------------|-------------|
| 异步模型 | `co_await` 编译为状态机，每连接 ~512B 协程帧 | goroutine-per-connection，每连接 2-8KB 栈 |
| GC | 无 GC，PMR 线性分配器直接 reset | Go GC 引发 STW 暂停，高负载下延迟抖动 |
| 调度 | 每 worker 一个 `io_context`，无锁数据路径 | M:N 调度 + channel 通信，锁竞争不可避免 |
| 上下文切换 | 零开销（编译器生成状态机跳转） | goroutine 切换涉及栈保存/恢复 |

**结论**: Prism 在高并发场景下内存占用更低、延迟更稳定，这是 C++ 协程架构的核心优势。

### 1.2 PMR 三级内存体系 — 热路径零堆分配

```
Tier 1: 全局同步池 (synchronized_pool_resource)
         → 跨线程对象: account::directory 条目、config 共享数据
Tier 2: 线程本地无锁池 (unsynchronized_pool_resource)
         → 每 worker 热路径: frame_arena、临时 vector/string
Tier 3: 帧竞技场 (monotonic_buffer_resource, 512B 栈缓冲)
         → 每会话短生命周期: 协议帧解析、地址缓冲
```

mihomo 完全依赖 Go 堆分配 + GC，无分层内存策略。Prism 的 `pooled_object<T>` CRTP 基类自动路由分配到正确的池层级。

### 1.3 传输抽象层 — 更干净的分层设计

Prism 的 `transmission` 虚接口 + 装饰器模式：
```
transmission (虚接口: async_read_some / async_write_some / close / cancel)
├── reliable    — TCP socket, 支持 pooled_connection RAII
├── encrypted   — ssl::stream<connector>, scatter-gather TLS
├── unreliable  — UDP socket, 数据报语义
├── preview     — 预读数据回放装饰器
└── [协议 relay] — SS2022 relay 自身也是 transmission 装饰器, 持续 AEAD
```

mihomo 用 `net.Conn` + `bufio.Reader` 层层包装，缺乏统一的虚接口。Prism 扩展新传输类型（QUIC、WebSocket、gRPC）只需实现 `transmission` 接口。

### 1.4 连接池设计 — 更精细的资源管理

| 特性 | Prism | mihomo |
|------|-------|--------|
| 池化策略 | LIFO 栈 + 每 endpoint 分桶 | 无显式连接池 |
| 回收机制 | RAII `pooled_connection` 自动归还 | 无 |
| 僵尸检测 | `healthy_fast()` 探活 + 空闲超时 | 无 |
| 线程安全 | 每 worker 独立池，无锁 | 无 |
| 清理 | 后台协程定期驱逐 | 无 |

### 1.5 单端口多协议探测 — 更优雅的设计

Prism 的双阶段探测：
1. **外层**: 读取 24 字节，检测 HTTP(方法关键字) / SOCKS5(0x05) / TLS(0x16)
2. **内层**: TLS 剥离后，通过 hex 凭据启发式检测 Trojan/HTTP，排除法 fallback 到 SS2022

mihomo 需要为每个协议创建独立的监听器（`http-port`, `socks-port`, `mixed-port` 等）。

---

## 二、架构差距分析（核心缺失，非功能层面）

### 2.1 缺少中央流量调度器

**现状**: `session::diversion()` 直接调用 handler → pipeline → `primitives::dial()` → `router`

**mihomo 对应**: `tunnel.HandleTCPConn()` / `tunnel.HandleUDPPacket()` 作为中央调度器

**影响**: 无法在 "知道目标地址" 和 "连接上游" 之间插入：
- 规则匹配（决定走哪个出站代理）
- 代理组选择（URLTest/Fallback/LoadBalance）
- 统计收集（每连接字节计数）
- 级联代理链（多跳代理）

**关键代码位置**:
```
src/prism/agent/session/session.cpp         — diversion() 直接调 handler
include/prism/pipeline/primitives.hpp:84    — dial() 直接调 router
include/prism/pipeline/primitives.hpp:244   — forward() = dial + tunnel
```

**数据流对比**:
```
Prism (当前):
  session::diversion() → handler::handle() → pipeline::xxx() → primitives::dial() → router

mihomo:
  listener → tunnel.HandleTCPConn()
            → fixMetadata()              // 地址规范化
            → preHandleMetadata()         // fake-IP 反查
            → sniffer.Detect()            // 协议嗅探
            → resolveMetadata()           // 规则匹配 + 代理选择
            → proxy.DialContext()          // 出站连接
            → statistic.NewTCPTracker()    // 统计包装
            → handleSocket()              // 双向转发
```

### 2.2 缺少出站代理抽象

**现状**:
- `primitives::dial()` 硬编码为直连（通过 `router` + `connection_pool`）
- `agent::config::positive` 为唯一上游代理配置，但 `async_positive()` 已 stub 为 `not_supported`
- 无 `outbound` 概念 — 入站协议处理完后直接拨号直连

**mihomo 对应**: `C.ProxyAdapter` 接口统一 22 种出站协议：
```go
type ProxyAdapter interface {
    Name() string
    Type() AdapterType
    DialContext(ctx, metadata) (net.Conn, error)
    ListenPacketContext(ctx, metadata) (net.PacketConn, error)
}
```

**关键代码位置**:
```
include/prism/resolve/router.hpp:166  — async_forward() 直接 DNS 解析 + 连接
src/prism/resolve/router.cpp:47       — async_positive() 返回 not_supported
```

### 2.3 session_context 是 God Object

**现状**: `session_context` 持有 10 个成员：
```cpp
struct session_context {
    std::uint64_t session_id{0};
    const server_context &server;                      // 服务器上下文
    worker_context &worker;                             // worker 上下文
    memory::frame_arena &frame_arena;                   // 帧内存池
    std::function<bool(std::string_view)> credential_verifier;  // 凭据验证
    account::directory *account_directory_ptr{nullptr};  // 账户目录
    std::uint32_t buffer_size;                           // 缓冲区大小
    shared_transmission inbound;                         // 入站传输
    shared_transmission outbound;                        // 出站传输
    account::lease account_lease;                        // 账户租约
    std::function<void()> active_stream_cancel;          // 取消回调
    std::function<void()> active_stream_close;           // 关闭回调
};
```

**问题**: 添加路由上下文、统计上下文、代理组选择结果等新横切关注点会进一步膨胀。这些成员的生命周期和用途各不相同，不应该平铺在一个结构体中。

**关键文件**: `include/prism/agent/context.hpp:81-107`

### 2.4 配置不可变 — 无法热加载

**现状**:
- `server_context` 持有 `const config &cfg`（常量引用）
- `main.cpp` 一次性加载配置，传入 worker/listener 后无法修改
- mihomo 通过 SIGHUP 触发 `hub.Parse()` → `executor.ApplyConfig()` 原子交换配置

**关键代码位置**:
```
include/prism/agent/context.hpp:45  — const config &cfg
src/main.cpp:55-56                  — auto [agent, trace] = psm::loader::load(...)
src/main.cpp:66                     — const agent::config &agent_config = agent
```

### 2.5 缺少统计基础设施

**现状**:
- `worker::stats::state` — 仅记录事件循环延迟
- `connection_pool::pool_stats` — 仅记录连接池容量/空闲数
- 无每连接、每用户、每规则的带宽统计

**mihomo 对应**: `Tracker` 包装每个连接，追踪：
```go
type TrackerInfo struct {
    UUID          uuid.UUID
    Metadata      *C.Metadata
    UploadTotal   atomic.Int64
    DownloadTotal atomic.Int64
    Start         time.Time
    Chain         C.Chain           // 经过的代理链
    Rule          string            // 匹配的规则
    RulePayload   string            // 规则的具体模式
}
```

### 2.6 resolve::router 职责过重

**现状**: `router` 类混杂了三种不同职责：
1. **DNS 解析**: `async_forward()` → `recursor::resolve()` → DNS 查询
2. **反向代理**: `async_reverse()` → 查 hostname-to-endpoint 映射表
3. **连接管理**: 所有路径最终通过 `connection_pool` 建立 TCP 连接

**mihomo 对应**: DNS 解析、规则路由、代理选择、连接建立是四个独立阶段。

### 2.7 缺少 UDP NAT 表

**现状**: UDP 处理分散在各协议中：
- Trojan: UDP over TLS + SOCKS5 framing (`protocol/trojan/relay.cpp`)
- VLESS: UDP over TLS + VLESS framing (`protocol/vless/relay.cpp`)
- SS2022: AEAD encrypted UDP relay (`protocol/shadowsocks/relay.cpp`)

**mihomo 对应**: 统一的 `natTable`（基于 `xsync.Map` 的无锁并发映射）管理所有 UDP 会话。

### 2.8 Pipeline 函数是单体的

**现状**: 每个协议的 pipeline 函数（`pipeline::http`, `pipeline::socks5` 等）直接调用 `primitives::dial()`。无法在不修改每个 pipeline 函数的情况下插入路由决策。

**mihomo 对应**: `tunnel.HandleTCPConn()` 在 handler 之外统一执行路由，handler 只负责协议握手。

---

## 三、层级优化方案（逐层详细设计）

### 3.1 Agent 层重构

#### 3.1.1 拆分 session_context

将扁平的 `session_context` 拆分为多个子结构，每个子结构有明确的生命周期和职责：

```cpp
// 新增: 路由上下文 — 每请求创建
struct routing_context {
    rule::match_result rule_match;       // 规则匹配结果
    outbound::proxy *selected_outbound;  // 选中的出站代理
    routing_mode mode;                   // direct / global / rule
};

// 新增: 统计上下文 — 每会话创建
struct stats_context {
    std::uint64_t upload_bytes{0};
    std::uint64_t download_bytes{0};
    std::chrono::steady_clock::time_point start_time;
    std::string_view matched_rule;
    std::string_view matched_rule_payload;
    memory::string chain;  // 代理链描述
};

// 瘦身后的 session_context
struct session_context {
    // 不变的核心成员
    std::uint64_t session_id{0};
    const server_context &server;
    worker_context &worker;
    memory::frame_arena &frame_arena;
    std::uint32_t buffer_size;
    shared_transmission inbound;
    shared_transmission outbound;

    // 新增子结构指针（按需创建，不增加不使用时的开销）
    std::unique_ptr<routing_context> routing;
    std::unique_ptr<stats_context> stats;

    // 账户相关（保持不变）
    std::function<bool(std::string_view)> credential_verifier;
    account::directory *account_directory_ptr{nullptr};
    account::lease account_lease;
    std::function<void()> active_stream_cancel;
    std::function<void()> active_stream_close;
};
```

**修改文件**: `include/prism/agent/context.hpp`

#### 3.1.2 新增 traffic_controller（mihomo `tunnel.Tunnel` 等价物）

```cpp
namespace psm::agent::controller {

/// 流量调度器 — 所有协议 handler 的统一入口
/// 等价于 mihomo 的 tunnel.HandleTCPConn() / tunnel.HandleUDPPacket()
class traffic_controller {
public:
    explicit traffic_controller(
        std::shared_ptr<const config> cfg,
        std::shared_ptr<rule::engine> rules,
        std::shared_ptr<stats::tracker> tracker);

    /// 处理 TCP 连接 — 协议握手完成后调用
    /// @param target  目标地址 (host + port)
    /// @param ctx     会话上下文
    /// @return        出站传输对象
    auto route_tcp(const protocol::analysis::target &target,
                   session_context &ctx)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>;

    /// 处理 UDP 关联
    auto route_udp(const protocol::analysis::target &target,
                   session_context &ctx)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>>;

private:
    /// 规则匹配 → 选择出站代理
    auto resolve_outbound(const protocol::analysis::target &target,
                          session_context &ctx)
        -> outbound::proxy &;

    std::shared_ptr<const config> cfg_;
    std::shared_ptr<rule::engine> rules_;
    std::shared_ptr<stats::tracker> tracker_;
    memory::unordered_map<memory::string, std::unique_ptr<outbound::proxy>> outbounds_;
    memory::unordered_map<memory::string, std::unique_ptr<group::base>> groups_;
};

} // namespace psm::agent::controller
```

**数据流重构后**:
```
session::diversion()
  → protocol detection
  → handler::handle()
    → pipeline::xxx()  // 只做协议握手，获取 target 地址
      → traffic_controller::route_tcp(target, ctx)
        → rule matching
        → proxy group selection
        → stats registration
        → outbound::proxy::async_connect()
      → primitives::tunnel()  // 双向转发
```

**新增文件**: `include/prism/agent/controller.hpp`, `src/prism/agent/controller.cpp`

#### 3.1.3 可变配置基础设施

```cpp
struct server_context {
    // 从 const config &cfg 改为 shared_ptr，支持原子交换
    std::shared_ptr<const config> cfg;

    std::shared_ptr<ssl::context> ssl_ctx;
    std::shared_ptr<account::directory> account_store;

    /// 原子交换配置 — 热加载时调用
    void swap_config(std::shared_ptr<const config> new_cfg) {
        std::atomic_store(&cfg, std::move(new_cfg));
        // 重建 SSL 上下文（证书可能变化）
        // 重建账户目录（用户可能变化）
    }

    /// 获取当前配置 — 热路径调用，无锁读取
    auto current_config() const -> const config & {
        return *std::atomic_load(&cfg);
    }
};
```

**修改文件**: `include/prism/agent/context.hpp`, `src/main.cpp`

### 3.2 新增 Outbound 层

#### 3.2.1 出站代理抽象接口

```cpp
namespace psm::outbound {

/// 出站代理抽象 — 所有出站协议实现此接口
/// 等价于 mihomo 的 C.ProxyAdapter
class proxy {
public:
    virtual ~proxy() = default;

    /// 建立 TCP 连接到目标
    virtual auto async_connect(std::string_view host, std::uint16_t port,
                                const net::any_io_executor &executor)
        -> net::awaitable<std::pair<fault::code, shared_transmission>> = 0;

    /// 建立 UDP 关联
    virtual auto async_connect_udp(std::string_view host, std::uint16_t port,
                                    const net::any_io_executor &executor)
        -> net::awaitable<std::pair<fault::code, net::ip::udp::socket>> = 0;

    /// 代理名称
    [[nodiscard]] virtual auto name() const -> std::string_view = 0;

    /// 代理类型
    [[nodiscard]] virtual auto type() const -> protocol_type = 0;

    /// 是否支持 UDP
    [[nodiscard]] virtual auto supports_udp() const -> bool { return false; }
};

} // namespace psm::outbound
```

#### 3.2.2 具体出站实现

```cpp
/// 直连出站 — 包装当前 router + connection_pool 行为
class direct : public proxy {
    // async_connect() 调用 router.async_forward() + connection_pool
};

/// 级联代理出站 — 通过上游代理连接目标
/// 解决当前 async_positive() 的 stub
class relay : public proxy {
    // async_connect() 连接到 upstream endpoint, 然后通过 upstream 协议连接 target
};

/// SOCKS5 出站
class socks5_out : public proxy {
    // SOCKS5 CONNECT 握手
};

/// HTTP 出站
class http_out : public proxy {
    // HTTP CONNECT 握手
};

/// Shadowsocks 出站
class ss_out : public proxy {
    // SS2022 AEAD 加密连接
};

/// Trojan 出站
class trojan_out : public proxy {
    // Trojan 握手 + 可选 TLS
};

/// VLESS 出站
class vless_out : public proxy {
    // VLESS 握手 + 可选 XTLS Vision
};
```

**新增目录**: `include/prism/outbound/`, `src/prism/outbound/`

#### 3.2.3 代理组（组合模式）

```cpp
namespace psm::group {

/// 代理组基类 — 也是 outbound::proxy（组合模式）
/// 等价于 mihomo 的 adapter/outboundgroup/
class base : public outbound::proxy {
public:
    /// 选择一个出站代理
    virtual auto select() -> std::shared_ptr<outbound::proxy> = 0;

    /// 当前使用的代理
    virtual auto current() const -> std::shared_ptr<outbound::proxy> = 0;

    /// 所有候选代理
    virtual auto all() const -> memory::vector<std::shared_ptr<outbound::proxy>> = 0;

    /// 执行健康检查 / 延迟测试
    virtual auto url_test() -> net::awaitable<void> = 0;

    // async_connect 委托给 select() 返回的代理
    auto async_connect(...) -> net::awaitable<...> override {
        return select()->async_connect(...);
    }
};

/// 自动选择最快代理
class url_test : public base {
    // 定期延迟测试（HTTP GET 到 test URL）
    // 选择延迟最低的代理
    // tolerance 参数防止频繁切换
    //
    // 数据成员:
    //   net::steady_timer test_timer_;
    //   memory::vector<std::shared_ptr<outbound::proxy>> providers_;
    //   std::atomic<std::size_t> best_index_{0};
    //   std::uint32_t tolerance_ms_;
    //   std::uint32_t interval_ms_;
};

/// 故障转移
class fallback : public base {
    // 按顺序尝试，返回第一个可用的
    // 支持手动选择，选中代理挂了自动切回
};

/// 负载均衡
class load_balance : public base {
    // 三种策略:
    // 1. consistent-hashing: Jump hash + 5 次重试 + 线性扫描兜底
    // 2. round-robin: 原子计数器轮转，跳过死代理
    // 3. sticky-sessions: LRU 缓存 (1000 条, 10 分钟 TTL), 按 src+dst 哈希

    enum class strategy { consistent_hash, round_robin, sticky_session };
    strategy strategy_;
};

/// 手动选择
class selector : public base {
    // 通过 REST API 手动切换
    // 默认选择第一个
    std::atomic<std::size_t> selected_index_{0};
};

/// 代理链（Relay）
class relay_chain : public base {
    // 按顺序串联多个代理: proxy1 → proxy2 → target
    // 每跳都是一个完整的代理握手
};

} // namespace psm::group
```

**新增目录**: `include/prism/group/`, `src/prism/group/`

### 3.3 Pipeline 层重构

#### 3.3.1 解耦 dial 决策

当前 `primitives::forward()` 直接调用 `dial()` → `router`：

```cpp
// 当前签名:
auto forward(session_context &ctx, std::string_view label,
             const protocol::analysis::target &target,
             shared_transmission inbound) -> net::awaitable<void>;

// 重构后签名:
auto forward(session_context &ctx, std::string_view label,
             const protocol::analysis::target &target,
             shared_transmission inbound,
             outbound::proxy &outbound_proxy) -> net::awaitable<void>;
```

**影响范围**: 所有协议 pipeline 函数需要适配：
- `src/prism/pipeline/protocols/http.cpp`
- `src/prism/pipeline/protocols/socks5.cpp`
- `src/prism/pipeline/protocols/trojan.cpp`
- `src/prism/pipeline/protocols/vless.cpp`
- `src/prism/pipeline/protocols/shadowsocks.cpp`

每个 pipeline 函数内部从 `primitives::forward(ctx, label, target, inbound)` 改为：
```cpp
auto &outbound = ctx.routing->selected_outbound
    ? *ctx.routing->selected_outbound
    : default_direct_outbound;
co_await primitives::forward(ctx, label, target, inbound, outbound);
```

#### 3.3.2 统一 UDP Relay 抽象

当前各协议各自实现 UDP 转发：
- `protocol/trojan/relay.cpp` — Trojan UDP over TLS + SOCKS5 地址格式
- `protocol/vless/relay.cpp` — VLESS UDP + VLESS 地址格式（95%，未完成）
- `protocol/shadowsocks/relay.cpp` — SS2022 AEAD UDP

创建共享抽象：
```cpp
namespace psm::protocol::common {

/// UDP relay 会话 — 统一各协议的 UDP 转发逻辑
class udp_relay_session {
public:
    /// 从客户端读取 UDP 数据包的回调类型
    using packet_reader = std::function<net::awaitable<std::optional<memory::vector<std::byte>>>()>;

    /// 向客户端写入 UDP 数据包的回调类型
    using packet_writer = std::function<net::awaitable<void>(std::span<const std::byte>)>;

    /// 运行 UDP relay
    static auto relay(packet_reader reader, packet_writer writer,
                      outbound::proxy &outbound,
                      const net::any_io_executor &executor,
                      std::uint32_t buffer_size) -> net::awaitable<void>;
};

} // namespace psm::protocol::common
```

**新增文件**: `include/prism/protocol/common/udp_session.hpp`, `src/prism/protocol/common/udp_session.cpp`

### 3.4 Channel 层扩展

#### 3.4.1 QUIC 传输（最重要的一项传输层扩展）

```cpp
namespace psm::channel::quic {

/// QUIC 连接管理
class connection : public std::enable_shared_from_this<connection> {
public:
    /// 建立出站 QUIC 连接
    static auto connect(const net::any_io_executor &executor,
                        const net::ip::udp::endpoint &remote,
                        const std::string &sni,
                        std::chrono::milliseconds timeout = std::chrono::seconds(10))
        -> net::awaitable<std::shared_ptr<connection>>;

    /// 接收入站 QUIC 连接
    static auto accept(const net::any_io_executor &executor,
                       const net::ip::udp::endpoint &local,
                       const std::string &cert_path,
                       const std::string &key_path)
        -> net::awaitable<std::shared_ptr<connection>>;

    /// 打开一个双向流
    auto open_stream() -> net::awaitable<std::shared_ptr<stream>>;

    /// 获取数据报接口
    auto datagram() -> std::shared_ptr<datagram>;

    void close();

private:
    // QUIC 库内部状态 (quiche 或 lsquic)
};

/// QUIC 流 — 实现 transmission 接口
class stream : public channel::transport::transmission {
public:
    [[nodiscard]] bool is_reliable() const noexcept override { return true; }
    [[nodiscard]] executor_type executor() const override;

    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;

    void close() override;
    void cancel() override;

private:
    std::shared_ptr<connection> conn_;
    uint64_t stream_id_;
};

/// QUIC 数据报 — UDP-over-QUIC
class datagram {
public:
    auto send(std::span<const std::byte> data) -> net::awaitable<void>;
    auto receive(std::span<std::byte> buffer) -> net::awaitable<std::size_t>;
};

} // namespace psm::channel::quic
```

**QUIC 库选型**:
- **quiche** (Cloudflare): C 库，API 简洁，BSD 许可，成熟稳定。推荐选型。
- **lsquic** (LiteSpeed): C 库，性能极高但 API 复杂。
- 两者均通过 FetchContent 拉取，编译为静态库。

**新增目录**: `include/prism/channel/quic/`, `src/prism/channel/quic/`

#### 3.4.2 WebSocket 传输

```cpp
namespace psm::channel::transport {

/// WebSocket 传输 — 实现 transmission 接口
class websocket : public transmission {
public:
    /// 客户端模式: HTTP/1.1 Upgrade 握手
    static auto connect(const net::any_io_executor &executor,
                        const std::string &host, std::uint16_t port,
                        const std::string &path,
                        const std::vector<std::pair<std::string, std::string>> &headers = {})
        -> net::awaitable<std::shared_ptr<websocket>>;

    /// 服务端模式: 从 HTTP 升级请求接受
    static auto accept(shared_transmission tcp_transport,
                       const std::string &path = "/")
        -> net::awaitable<std::shared_ptr<websocket>>;

    // transmission 接口实现...
    auto async_read_some(std::span<std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;
    auto async_write_some(std::span<const std::byte> buffer, std::error_code &ec)
        -> net::awaitable<std::size_t> override;

private:
    shared_transmission underlying_;  // TCP 或 TLS 传输
    // WebSocket 帧解析状态
};

} // namespace psm::channel::transport
```

**新增文件**: `include/prism/channel/transport/websocket.hpp`, `src/prism/channel/transport/websocket.cpp`

#### 3.4.3 gRPC 传输

```cpp
namespace psm::channel::transport {

/// gRPC 传输 (gun 协议) — 实现 transmission 接口
/// 用于 VLESS/VMess 的 gRPC 传输模式
class grpc : public transmission {
public:
    /// 建立 gRPC 连接
    static auto connect(const net::any_io_executor &executor,
                        const std::string &host, std::uint16_t port,
                        const std::string &service_name)
        -> net::awaitable<std::shared_ptr<grpc>>;

    // transmission 接口实现...
    // gRPC 帧格式: 5 字节头 (1B 压缩标志 + 4B 长度) + payload
    // HTTP/2 帧格式: 9 字节头 (3B 长度 + 1B 类型 + 1B flags + 4B stream ID)

private:
    shared_transmission underlying_;
    std::string service_name_;
    // HTTP/2 帧解析状态
};

} // namespace psm::channel::transport
```

**依赖**: nghttp2 库（通过 FetchContent）或自实现最小 HTTP/2 帧（参考 mihomo 的 gun 实现）

**新增文件**: `include/prism/channel/transport/grpc.hpp`, `src/prism/channel/transport/grpc.cpp`

### 3.5 新增 Rule 引擎

```cpp
namespace psm::rule {

/// 规则匹配器抽象
class matcher {
public:
    virtual ~matcher() = default;

    /// 判断是否匹配
    /// @param host  目标域名 (可能为空, 如 IP 直连)
    /// @param port  目标端口
    /// @param ip    已解析的 IP (可能为空, 延迟解析)
    virtual auto match(std::string_view host, std::uint16_t port,
                       const std::optional<net::ip::address> &ip) const
        -> bool = 0;

    /// 规则类型名 (如 "DOMAIN-SUFFIX", "IP-CIDR")
    [[nodiscard]] virtual auto type() const -> std::string_view = 0;

    /// 规则匹配模式 (如 "google.com", "10.0.0.0/8")
    [[nodiscard]] virtual auto payload() const -> std::string_view = 0;
};

/// 规则匹配结果
struct match_result {
    std::string_view outbound_name;    // 代理或代理组名称 (如 "DIRECT", "proxy-group-1")
    std::string_view rule_type;        // 规则类型 (如 "DOMAIN-SUFFIX")
    std::string_view rule_payload;     // 规则模式 (如 "google.com")
};

/// 规则引擎 — 首匹配胜出
class engine {
public:
    explicit engine(memory::resource_pointer mr = {});

    /// 匹配规则 — 遍历规则列表，返回第一个匹配的结果
    auto match(std::string_view host, std::uint16_t port,
               std::optional<net::ip::address> ip) const
        -> std::optional<match_result>;

    /// 添加规则
    void add_rule(std::unique_ptr<matcher> rule, std::string_view outbound_name);

    /// 加载规则集
    void load_rules_from_config(const config::rules_config &cfg);

    /// 规则数量
    [[nodiscard]] auto size() const -> std::size_t;

private:
    memory::vector<std::pair<std::unique_ptr<matcher>, memory::string>> rules_;
};

// ===== 具体匹配器实现 =====

/// DOMAIN — 精确域名匹配
/// 复用 resolve::domain_trie 进行高效匹配
class domain_matcher : public matcher { /* ... */ };

/// DOMAIN-SUFFIX — 域名后缀匹配 (如 ".google.com")
/// 复用 resolve::domain_trie (反向存储)
class domain_suffix_matcher : public matcher { /* ... */ };

/// DOMAIN-KEYWORD — 域名包含关键字
class domain_keyword_matcher : public matcher { /* ... */ };

/// DOMAIN-REGEX — 域名正则匹配
class domain_regex_matcher : public matcher { /* ... */ };

/// IP-CIDR — IPv4/IPv6 CIDR 匹配
/// 使用自定义 CIDR trie 或 boost::asio::ip::network
class ip_cidr_matcher : public matcher { /* ... */ };

/// GEOIP — GeoIP 数据库匹配 (MaxMindDB)
/// 需要 libmaxminddb 依赖
class geoip_matcher : public matcher { /* ... */ };

/// GEOSITE — GeoSite 数据库匹配 (domain list)
class geosite_matcher : public matcher { /* ... */ };

/// SRC-PORT / DST-PORT — 端口范围匹配
class port_matcher : public matcher { /* ... */ };

/// NETWORK — 网络类型匹配 (tcp / udp)
class network_matcher : public matcher { /* ... */ };

/// RULE-SET — 外部规则集引用
/// 支持从 HTTP URL 或本地文件加载规则列表
class rule_set_matcher : public matcher { /* ... */ };

/// AND / OR / NOT — 逻辑组合规则
class logic_and : public matcher { /* ... */ };
class logic_or : public matcher { /* ... */ };
class logic_not : public matcher { /* ... */ };

/// SUB-RULE — 嵌套子规则集
class sub_rule : public matcher { /* ... */ };

/// MATCH — 兜底规则，匹配所有
class match_all : public matcher { /* ... */ };

} // namespace psm::rule
```

**新增目录**: `include/prism/rule/`, `src/prism/rule/`

**复用现有代码**:
- `resolve::domain_trie` — 域名规则匹配
- `resolve::rules_engine` — 静态规则匹配
- `channel::eyeball::address_racer` — IP 相关的连接竞速

### 3.6 新增 API 层

```cpp
namespace psm::api {

/// REST API 服务器 — 兼容 Clash Dashboard
class server {
public:
    explicit server(std::shared_ptr<const config> cfg,
                    std::shared_ptr<stats::tracker> tracker,
                    std::shared_ptr<rule::engine> rules,
                    std::shared_ptr<agent::controller::traffic_controller> controller);

    void start();  // 启动独立 io_context 线程
    void stop();

private:
    // === 端点处理函数 ===

    /// GET / — Hello
    auto handle_hello(const request &req) -> response;

    /// GET /proxies — 列出所有代理和代理组
    auto handle_get_proxies(const request &req) -> response;

    /// GET /proxies/:name — 代理详情
    auto handle_get_proxy(const request &req) -> response;

    /// PUT /proxies/:name — 在 Selector 组中选择代理
    auto handle_put_proxy(const request &req) -> response;

    /// GET /proxies/:name/delay — URL 测试
    auto handle_get_proxy_delay(const request &req) -> response;

    /// GET /rules — 规则列表
    auto handle_get_rules(const request &req) -> response;

    /// GET /connections — 活跃连接列表
    auto handle_get_connections(const request &req) -> response;

    /// DELETE /connections — 关闭所有连接
    auto handle_delete_connections(const request &req) -> response;

    /// GET /traffic — SSE 实时流量流 (每秒推送)
    auto handle_get_traffic(const request &req) -> response;

    /// GET /configs — 当前配置
    auto handle_get_configs(const request &req) -> response;

    /// PUT /configs — 热加载新配置
    auto handle_put_configs(const request &req) -> response;

    /// PATCH /configs — 部分更新配置
    auto handle_patch_configs(const request &req) -> response;

    /// POST /configs?force=true — 强制重载配置
    auto handle_post_configs(const request &req) -> response;

    /// GET /version — 版本信息
    auto handle_get_version(const request &req) -> response;

    net::io_context ioc_;
    std::shared_ptr<const config> cfg_;
    std::shared_ptr<stats::tracker> tracker_;
    std::shared_ptr<rule::engine> rules_;
    std::shared_ptr<agent::controller::traffic_controller> controller_;
};

} // namespace psm::api
```

**API 端点与 mihomo 对照表**:

| 端点 | 方法 | mihomo 等价 | 说明 |
|------|------|-------------|------|
| `/` | GET | `/` | Hello |
| `/proxies` | GET | `/proxies` | 代理列表 |
| `/proxies/:name` | GET | `/proxies/:name` | 代理详情 |
| `/proxies/:name` | PUT | `/proxies/:name` | 选择代理 |
| `/proxies/:name/delay` | GET | `/proxies/:name/delay` | 延迟测试 |
| `/rules` | GET | `/rules` | 规则列表 |
| `/connections` | GET | `/connections` | 连接列表 |
| `/connections` | DELETE | `/connections` | 关闭连接 |
| `/traffic` | GET | `/traffic` | SSE 流量 |
| `/configs` | GET/PUT/PATCH | `/configs` | 配置管理 |
| `/version` | GET | `/version` | 版本 |

**新增目录**: `include/prism/api/`, `src/prism/api/`

### 3.7 新增 Statistics 层

```cpp
namespace psm::stats {

/// 连接元数据 — 每连接一个
struct connection_info {
    std::uint64_t id;
    memory::string host;
    std::uint16_t port;
    memory::string network;          // "tcp" / "udp"
    memory::string rule;             // 匹配的规则类型
    memory::string rule_payload;     // 规则模式
    memory::string chains;           // 代理链 (如 "proxy1 -> proxy2")
    memory::string inbound_type;     // 入站协议 (如 "trojan")
    std::chrono::steady_clock::time_point start;

    /// 上传字节 (原子, 可从任意线程读取)
    std::atomic<std::uint64_t> upload{0};
    /// 下载字节 (原子)
    std::atomic<std::uint64_t> download{0};
};

/// 统计追踪器 — 全局单例
class tracker {
public:
    explicit tracker(memory::resource_pointer mr = {});

    /// 注册新连接 — 返回共享指针, 连接结束前持有
    auto register_connection(const connection_info &info)
        -> std::shared_ptr<connection_info>;

    /// 注销连接
    void unregister_connection(std::uint64_t id);

    /// 快照 — 返回所有活跃连接的拷贝 (供 API 使用)
    auto snapshot() const -> memory::vector<std::shared_ptr<connection_info>>;

    /// 总上传字节
    [[nodiscard]] auto total_upload() const -> std::uint64_t;

    /// 总下载字节
    [[nodiscard]] auto total_download() const -> std::uint64_t;

    /// 活跃连接数
    [[nodiscard]] auto active_count() const -> std::size_t;

private:
    mutable std::shared_mutex mutex_;
    memory::unordered_map<std::uint64_t, std::shared_ptr<connection_info>> active_;
    std::atomic<std::uint64_t> total_upload_{0};
    std::atomic<std::uint64_t> total_download_{0};
};

} // namespace psm::stats
```

**集成点**:
- `session::start()` — 创建 `connection_info` 并注册到 tracker
- `primitives::tunnel()` — 每次读/写更新 upload/download 计数
- `session::release_resources()` — 从 tracker 注销

**新增目录**: `include/prism/stats/`

### 3.8 Resolve 层扩展

#### 3.8.1 Fake-IP DNS

```cpp
namespace psm::resolve {

/// Fake-IP 池 — 返回假 IP 并维护双向映射
class fakeip_pool {
public:
    /// 配置假 IP 范围
    explicit fakeip_pool(const std::string &ip_range,   // 如 "198.18.0.0/16"
                         const std::string &ip6_range,   // 如 "fc00::/18"
                         memory::resource_pointer mr = {});

    /// 为域名分配假 IP (如不存在则创建)
    auto allocate(std::string_view domain) -> net::ip::address;

    /// 从假 IP 反查域名
    auto lookup(const net::ip::address &fake_ip) const -> std::optional<std::string_view>;

    /// 持久化映射到文件
    auto save(const std::filesystem::path &path) const -> bool;

    /// 从文件加载映射
    auto load(const std::filesystem::path &path) -> bool;

private:
    memory::unordered_map<memory::string, net::ip::address> domain_to_ip_;
    memory::unordered_map<net::ip::address, memory::string> ip_to_domain_;
    // IP 分配器 (顺序或随机)
};

} // namespace psm::resolve
```

**新增文件**: `include/prism/resolve/fakeip.hpp`, `src/prism/resolve/fakeip.cpp`

### 3.9 Stealth 层扩展

#### 3.9.1 ShadowTLS v3

```cpp
namespace psm::stealth::shadowtls {

/// ShadowTLS v3 服务端
/// TLS-in-TLS 包装: 模拟到真实目标的 TLS 握手, 然后切换到代理数据
class shadowtls_server {
public:
    explicit shadowtls_server(const config &cfg);

    /// 处理连接 — 与客户端完成 ShadowTLS 握手
    auto handshake(shared_transmission client)
        -> net::awaitable<std::pair<fault::code, shared_transmission>>;

private:
    // TLS 配置
    // 认证用户列表
    // 通配符 SNI 配置
};

} // namespace psm::stealth::shadowtls
```

**新增文件**: `include/prism/stealth/shadowtls/server.hpp`, `src/prism/stealth/shadowtls/server.cpp`

#### 3.9.2 VLESS Vision (XTLS)

```cpp
namespace psm::stealth::vision {

/// VLESS Vision — XTLS 直接转发模式
/// 检测到 TLS 流量后, 跳过不必要的二次加密, 直接转发
class vision_stream : public channel::transport::transmission {
public:
    explicit vision_stream(shared_transmission inner);

    // 实现 transmission 接口...
    // 内部状态机:
    //   1. 初始: 透传所有数据
    //   2. 检测到 TLS ClientHello/ServerHello: 过滤 UUID 字节
    //   3. TLS 握手完成: 切换到直接复制模式 (splice)
    //   4. 非 TLS 数据: 继续正常转发

private:
    shared_transmission inner_;
    enum class state { copy, filter, splice } state_{state::copy};
};

} // namespace psm::stealth::vision
```

**新增文件**: `include/prism/stealth/vision/stream.hpp`, `src/prism/stealth/vision/stream.cpp`

### 3.10 Fault 层扩展

```cpp
// 新增错误码范围:
namespace psm::fault {
    // 60-69: QUIC 传输错误
    code::quic_handshake_failed = 60,
    code::quic_stream_reset = 61,
    code::quic_idle_timeout = 62,
    code::quic_datagram_too_large = 63,

    // 70-79: 规则引擎错误
    code::rule_not_found = 70,
    code::rule_provider_unavailable = 71,
    code::rule_parse_error = 72,

    // 80-89: REST API 错误
    code::api_auth_failed = 80,
    code::api_route_not_found = 81,
    code::api_bad_request = 82,

    // 90-99: 代理组错误
    code::group_no_available_proxy = 90,
    code::group_health_check_failed = 91,
    code::group_proxy_not_found = 92,
}
```

**修改文件**: `include/prism/fault/code.hpp`

---

## 四、分阶段开发路线

### Phase 1: 架构基础重构 (4-6 周)

**目标**: 建立支撑规则路由和代理组的内部抽象，不改变现有功能行为。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 1.1 | 出站代理抽象 | 定义 `outbound::proxy` 接口 + `direct` 实现 | `include/prism/outbound/proxy.hpp` | 中 |
| 1.2 | 直连出站 | `outbound::direct` 包装现有 router+pool 行为 | `src/prism/outbound/direct.cpp` | 低 |
| 1.3 | 级联出站 | `outbound::relay` 通过上游代理连接 (解决 positive stub) | `src/prism/outbound/relay.cpp` | 中 |
| 1.4 | traffic_controller | 中央调度器，session 和 handler 之间的拦截层 | `include/prism/agent/controller.hpp` | 中 |
| 1.5 | session_context 瘦身 | 提取 routing_context、stats_context 子结构 | `include/prism/agent/context.hpp` | 中 |
| 1.6 | 可变配置 | `shared_ptr<const config>` + 原子交换 | `include/prism/agent/context.hpp` | 低 |
| 1.7 | dial 策略解耦 | `forward()` 接受 `outbound::proxy&` 参数 | `include/prism/pipeline/primitives.hpp` | 中 |
| 1.8 | 全部 pipeline 适配 | http/socks5/trojan/vless/ss 适配新 forward 签名 | `src/prism/pipeline/protocols/*.cpp` | 中 |
| 1.9 | YAML 配置解析 | 兼容 mihomo 的 YAML 格式 (如需) | `include/prism/loader/yaml.hpp` | 低 |

**验证**:
- 所有 25 个现有单元测试通过
- 出站抽象单元测试（direct 模拟连接）
- traffic_controller 路由模式切换测试
- 行为与重构前完全一致

---

### Phase 2: 规则引擎 + 代理组 (4-5 周)

**目标**: 实现规则路由和代理组选择，达到 mihomo 核心流量管理能力。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 2.1 | 规则引擎核心 | `rule::engine` + 首匹配胜出语义 | `include/prism/rule/engine.hpp` | 中 |
| 2.2 | 域名规则 | DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, DOMAIN-REGEX | 复用 `resolve::rules_engine` 的 trie | 中 |
| 2.3 | IP 规则 | IP-CIDR, IP-CIDR6, SRC-IP-CIDR | `include/prism/rule/ip_matcher.hpp` | 中 |
| 2.4 | GeoIP | MaxMindDB 集成 (libmaxminddb FetchContent) | `include/prism/rule/geoip_matcher.hpp` | 中高 |
| 2.5 | 端口/网络规则 | SRC-PORT, DST-PORT, NETWORK | `include/prism/rule/port_matcher.hpp` | 低 |
| 2.6 | 逻辑规则 | AND, OR, NOT, SUB-RULE | `include/prism/rule/logic_matcher.hpp` | 中 |
| 2.7 | 规则集 | RULE-SET 外部规则集加载 (HTTP/文件) | `include/prism/rule/rule_set.hpp` | 中 |
| 2.8 | URLTest 组 | 自动选择最低延迟代理 | `include/prism/group/url_test.hpp` | 中高 |
| 2.9 | Fallback 组 | 故障转移 | `include/prism/group/fallback.hpp` | 中 |
| 2.10 | LoadBalance 组 | 一致性哈希 / 轮转 / 粘性会话 | `include/prism/group/load_balance.hpp` | 中高 |
| 2.11 | Selector 组 | 手动选择 | `include/prism/group/selector.hpp` | 低 |
| 2.12 | 健康检查 | 定期 HTTP GET 到测试 URL + 延迟测量 | 各 group 文件 | 中 |
| 2.13 | 路由模式 | Direct / Global / Rule 三种模式 | `include/prism/agent/controller.hpp` | 低 |
| 2.14 | 出站协议实现 | socks5_out, http_out, ss_out, trojan_out, vless_out | `src/prism/outbound/*.cpp` | 中高 |

**验证**:
- 规则匹配单元测试（每种规则类型 3-5 个用例）
- 代理组健康检查测试（模拟延迟、失败、切换）
- 路由模式切换测试（Direct → Rule → Global）
- 与 mihomo YAML 配置文件兼容测试

**依赖**: Phase 1（出站抽象、traffic_controller）

---

### Phase 3: QUIC 传输 + Hysteria2 + TUIC (6-8 周)

**目标**: 添加 QUIC 传输支持，实现 Hysteria2 和 TUIC 协议。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 3.1 | QUIC 库集成 | quiche FetchContent + CMake 配置 | `CMakeLists.txt` | 中 |
| 3.2 | QUIC 连接管理 | `channel::quic::connection` 客户端+服务端 | `include/prism/channel/quic/connection.hpp` | 极高 |
| 3.3 | QUIC 流 | 实现 `transmission` 接口 | `include/prism/channel/quic/stream.hpp` | 高 |
| 3.4 | QUIC 数据报 | UDP-over-QUIC | `include/prism/channel/quic/datagram.hpp` | 高 |
| 3.5 | QUIC 连接池 | 复用 QUIC session (多 stream 共享连接) | 扩展 `connection_pool` | 中 |
| 3.6 | Hysteria2 协议 | QUIC 代理 + BBR 拥塞 + 认证 + 带宽控制 | `include/prism/protocol/hysteria2/` | 极高 |
| 3.7 | Hysteria2 入站 | 服务端 listener + salamander 混淆 | `include/prism/protocol/hysteria2/server.hpp` | 高 |
| 3.8 | Hysteria2 出站 | 客户端 dialer | `src/prism/outbound/hysteria2.cpp` | 高 |
| 3.9 | TUIC 协议 | QUIC 代理 + v4/v5 认证 | `include/prism/protocol/tuic/` | 高 |
| 3.10 | TUIC 入站 | 服务端 (QUIC streams + datagrams) | `include/prism/protocol/tuic/server.hpp` | 高 |
| 3.11 | TUIC 出站 | 客户端 | `src/prism/outbound/tuic.cpp` | 高 |
| 3.12 | DoQ DNS | DNS-over-QUIC 解析器 | 扩展 `resolve/resolver` | 中 |

**验证**:
- QUIC 连接建立/关闭测试
- QUIC 流读写测试
- Hysteria2 帧解析测试
- TUIC 帧解析测试
- 与 mihomo Hysteria2/TUIC 客户端互操作测试

**依赖**: Phase 1（出站抽象用于协议集成）

> **可并行**: Phase 3 可与 Phase 2 同时开发

---

### Phase 4: WebSocket + gRPC + ShadowTLS + Vision (3-4 周)

**目标**: 添加传输层选项，兼容 mihomo 的传输配置。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 4.1 | WebSocket 传输 | HTTP/1.1 升级 + 二进制帧 + ping/pong | `include/prism/channel/transport/websocket.hpp` | 中 |
| 4.2 | WebSocket 入站 | 服务端 accept 升级 | 同上 | 中 |
| 4.3 | WebSocket 出站 | 客户端 connect 升级 | 同上 | 中 |
| 4.4 | gRPC 传输 | HTTP/2 帧 + gun 协议头 | `include/prism/channel/transport/grpc.hpp` | 中高 |
| 4.5 | nghttp2 集成 | FetchContent 拉取 nghttp2 | `CMakeLists.txt` | 中 |
| 4.6 | ShadowTLS v3 | TLS-in-TLS 包装 + 认证 + 通配 SNI | `include/prism/stealth/shadowtls/` | 中 |
| 4.7 | VLESS Vision | XTLS 直接转发模式 + TLS 记录检测 | `include/prism/stealth/vision/` | 中高 |
| 4.8 | VLESS UDP 补全 | 95% → 100%, 完成并测试 UDP relay | `src/prism/pipeline/protocols/vless.cpp` | 低 |
| 4.9 | 传输组合测试 | Trojan-WS, VLESS-gRPC, SS-ShadowTLS 等组合 | 测试文件 | 中 |

**验证**:
- WebSocket/gRPC 帧解析单元测试
- ShadowTLS 握手测试
- VLESS Vision 状态机测试
- 与 mihomo 客户端各种传输组合的互操作测试

**依赖**: Phase 1（transmission 接口）

> **可并行**: Phase 4 可与 Phase 3 同时开发

---

### Phase 5: REST API + 可观测性 + 配置热加载 (3-4 周)

**目标**: 管理接口、统计追踪、配置热加载。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 5.1 | HTTP API 框架 | Boost.Beast 或轻量 HTTP 库 + Chi 风格路由 | `include/prism/api/server.hpp` | 中 |
| 5.2 | 认证中间件 | Bearer token 认证 | `include/prism/api/auth.hpp` | 低 |
| 5.3 | 代理管理端点 | GET/PUT /proxies, GET /proxies/:name/delay | `include/prism/api/handler.hpp` | 中 |
| 5.4 | 连接管理端点 | GET/DELETE /connections | `include/prism/api/handler.hpp` | 中 |
| 5.5 | SSE 流量流 | GET /traffic 每秒推送流量统计 | `include/prism/api/sse.hpp` | 中 |
| 5.6 | 配置管理端点 | GET/PUT/PATCH /configs | `include/prism/api/handler.hpp` | 中 |
| 5.7 | 统计 tracker | 每连接字节计数 + 代理链 + 规则命中 | `include/prism/stats/tracker.hpp` | 中 |
| 5.8 | 统计集成 | tunnel() 中更新计数, session 注册/注销 | 修改 `primitives.cpp`, `session.cpp` | 低 |
| 5.9 | 配置热加载 | 文件监视 + 原子配置交换 + 监听器重启 | `include/prism/loader/watcher.hpp` | 中 |
| 5.10 | 优雅重启 | 新配置加载时排空旧连接 | `src/main.cpp` 重构 | 中 |
| 5.11 | Fake-IP DNS | 假 IP 池 + 域名双向映射 | `include/prism/resolve/fakeip.hpp` | 中 |
| 5.12 | Fake-IP 集成 | 与规则引擎配合, DNS 查询返回假 IP | 修改 `recursor` | 中 |

**验证**:
- API 端点集成测试（每个端点 3+ 用例）
- Clash Dashboard (yacd/metacubexd) 连接测试
- 配置热加载测试（改配置文件 → 自动生效 → 不丢连接）
- Fake-IP DNS 测试

**依赖**: Phase 2（规则引擎、代理组用于 API 操作）

---

### Phase 6: 高级协议 + 平台功能 (4-5 周)

**目标**: 完善协议支持和平台集成。

| # | 任务 | 详情 | 关键文件 | 复杂度 |
|---|------|------|----------|--------|
| 6.1 | VMess 协议 | AEAD 加密 + UUID 认证 + legacy 兼容 | `include/prism/protocol/vmess/` | 高 |
| 6.2 | VMess 入站 | 服务端 (sing-vmess 兼容) | `include/prism/protocol/vmess/server.hpp` | 高 |
| 6.3 | VMess 出站 | 客户端 | `src/prism/outbound/vmess.cpp` | 高 |
| 6.4 | WireGuard | 用户态 Noise 协议 (X25519 + ChaCha20) | `include/prism/protocol/wireguard/` | 极高 |
| 6.5 | TUN 设备 | Wintun (Windows) / /dev/net/tun (Linux) | `include/prism/tun/` | 极高 |
| 6.6 | 透明代理 | iptables/nftables 重定向 | `include/prism/tun/redirect.hpp` | 极高 |
| 6.7 | Snell 协议 | v3 协议支持 | `include/prism/protocol/snell/` | 中 |
| 6.8 | AnyTLS | TLS 填充变体 | `include/prism/stealth/anytls/` | 中 |
| 6.9 | NTP 同步 | SS2022 时间戳校验 | `include/prism/utils/ntp.hpp` | 低 |
| 6.10 | smux v2 | 带流控的 smux 升级版 | `include/prism/multiplex/smux/` | 低 |
| 6.11 | 进程检测 | 进程名/路径匹配规则 (Windows/Linux) | `include/prism/rule/process_matcher.hpp` | 中高 |

**验证**:
- VMess 帧解析 + 加密测试
- WireGuard Noise 握手测试
- TUN 包收发测试（平台特定）
- 与 mihomo VMess/WireGuard 客户端互操作测试

**依赖**: Phase 2（规则引擎用于 TUN 路由）, Phase 3（QUIC 可能用于 WireGuard-over-QUIC）

---

## 五、功能优先级矩阵

| 优先级 | 功能 | 用户影响 | C++ 难度 | 架构依赖 | mihomo 兼容 | Phase |
|--------|------|----------|----------|----------|-------------|-------|
| **P0** | 出站代理抽象 | 基础 | 中 | 无 | 基础 | 1 |
| **P0** | traffic_controller | 基础 | 中 | 出站抽象 | 基础 | 1 |
| **P0** | 可变配置 | 基础 | 低 | 无 | 基础 | 1 |
| **P0** | dial 策略解耦 | 基础 | 中 | 出站抽象 | 基础 | 1 |
| **P1** | 规则引擎 | 关键 | 中 | Phase 1 | 关键 | 2 |
| **P1** | 代理组 | 关键 | 中高 | Phase 1 | 关键 | 2 |
| **P1** | 出站协议(socks5/http/ss/trojan/vless) | 关键 | 中高 | 出站抽象 | 关键 | 2 |
| **P1** | 级联代理 | 中 | 低 | 出站抽象 | 中 | 1 |
| **P2** | QUIC 传输 | 很高 | 极高 | 独立 | 关键 | 3 |
| **P2** | Hysteria2 | 很高 | 高 | QUIC | 关键 | 3 |
| **P2** | WebSocket | 高 | 中 | transmission | 高 | 4 |
| **P2** | REST API | 高 | 中 | stats | 高 | 5 |
| **P2** | 配置热加载 | 高 | 中 | 可变配置 | 高 | 5 |
| **P3** | Fake-IP DNS | 高 | 中 | 规则引擎 | 高 | 5 |
| **P3** | 统计 tracker | 中高 | 中 | session | 高 | 5 |
| **P3** | gRPC 传输 | 中 | 中高 | transmission | 中 | 4 |
| **P3** | ShadowTLS | 中 | 中 | stealth | 中 | 4 |
| **P3** | VLESS Vision | 中 | 中高 | transmission | 中 | 4 |
| **P3** | TUIC | 中 | 高 | QUIC | 中 | 3 |
| **P4** | VMess | 中 | 高 | 独立 | 中 | 6 |
| **P4** | WireGuard | 中低 | 极高 | 独立 | 中 | 6 |
| **P4** | TUN 设备 | 中 | 极高 | 平台相关 | 中 | 6 |
| **P4** | Snell | 低中 | 中 | 独立 | 低 | 6 |
| **P4** | AnyTLS | 低 | 中 | stealth | 低 | 6 |
| **P4** | DoQ DNS | 低中 | 中 | QUIC | 低 | 6 |

---

## 六、核心修改文件清单

### 必须修改的现有文件

| 文件路径 | 修改内容 | Phase |
|----------|----------|-------|
| `include/prism/agent/context.hpp` | 拆分 session_context，server_context 改 `shared_ptr<const config>` | 1 |
| `include/prism/pipeline/primitives.hpp` | `forward()` 接受 `outbound::proxy&` 参数 | 1 |
| `src/prism/pipeline/primitives.cpp` | 对应实现修改 | 1 |
| `src/prism/pipeline/protocols/http.cpp` | 适配新 forward 签名 | 1 |
| `src/prism/pipeline/protocols/socks5.cpp` | 适配新 forward 签名 | 1 |
| `src/prism/pipeline/protocols/trojan.cpp` | 适配新 forward 签名 | 1 |
| `src/prism/pipeline/protocols/vless.cpp` | 适配新 forward 签名 + UDP 补全 | 1, 4 |
| `src/prism/pipeline/protocols/shadowsocks.cpp` | 适配新 forward 签名 | 1 |
| `src/prism/agent/session/session.cpp` | `diversion()` 通过 controller 分发 | 1 |
| `src/main.cpp` | 重构: API 线程、配置监视、优雅关机 | 1, 5 |
| `include/prism/fault/code.hpp` | 新增 QUIC/规则/API/代理组错误码 | 2-6 |
| `CMakeLists.txt` | 新依赖 (quiche/nghttp2/libmaxminddb) | 3, 4 |

### 新增模块目录

| 目录路径 | 模块 | Phase |
|----------|------|-------|
| `include/prism/outbound/` + `src/prism/outbound/` | 出站代理抽象 + 各协议出站 | 1-2 |
| `include/prism/group/` + `src/prism/group/` | 代理组 (URLTest/Fallback/LB/Selector) | 2 |
| `include/prism/rule/` + `src/prism/rule/` | 规则引擎 | 2 |
| `include/prism/channel/quic/` + `src/prism/channel/quic/` | QUIC 传输 | 3 |
| `include/prism/channel/transport/websocket.hpp` + `.cpp` | WebSocket 传输 | 4 |
| `include/prism/channel/transport/grpc.hpp` + `.cpp` | gRPC 传输 | 4 |
| `include/prism/protocol/hysteria2/` + `src/prism/protocol/hysteria2/` | Hysteria2 协议 | 3 |
| `include/prism/protocol/tuic/` + `src/prism/protocol/tuic/` | TUIC 协议 | 3 |
| `include/prism/protocol/vmess/` + `src/prism/protocol/vmess/` | VMess 协议 | 6 |
| `include/prism/protocol/snell/` + `src/prism/protocol/snell/` | Snell 协议 | 6 |
| `include/prism/protocol/wireguard/` + `src/prism/protocol/wireguard/` | WireGuard | 6 |
| `include/prism/stealth/shadowtls/` + `src/prism/stealth/shadowtls/` | ShadowTLS v3 | 4 |
| `include/prism/stealth/vision/` + `src/prism/stealth/vision/` | VLESS Vision | 4 |
| `include/prism/stealth/anytls/` + `src/prism/stealth/anytls/` | AnyTLS | 6 |
| `include/prism/api/` + `src/prism/api/` | REST API | 5 |
| `include/prism/stats/` | 统计追踪 | 5 |
| `include/prism/agent/controller.hpp` + `.cpp` | traffic_controller | 1 |
| `include/prism/resolve/fakeip.hpp` + `.cpp` | Fake-IP DNS | 5 |
| `include/prism/loader/watcher.hpp` + `.cpp` | 配置热加载 | 5 |
| `include/prism/loader/yaml.hpp` | YAML 配置解析 | 1 |
| `include/prism/utils/ntp.hpp` | NTP 同步 | 6 |
| `include/prism/tun/` + `src/prism/tun/` | TUN 设备 | 6 |
| `include/prism/protocol/common/udp_session.hpp` + `.cpp` | 统一 UDP relay | 1 |

---

## 七、依赖关系图

```
Phase 1: 架构基础
  ├── outbound::proxy 抽象
  ├── traffic_controller
  ├── session_context 瘦身
  ├── 可变配置
  └── dial 策略解耦
        │
        ├─────────────────────────┐
        ▼                         ▼
Phase 2: 规则+代理组     Phase 3: QUIC+协议
  ├── rule::engine           ├── QUIC 传输
  ├── group::url_test等      ├── Hysteria2
  ├── 各出站协议实现         └── TUIC
  └── 路由模式                     │
        │                          │ (独立)
        ▼                          ▼
Phase 4: 传输扩展        (Phase 3 可与 Phase 2 并行)
  ├── WebSocket
  ├── gRPC
  ├── ShadowTLS
  └── VLESS Vision
        │
        ▼
Phase 5: API+可观测性
  ├── REST API
  ├── 统计 tracker
  ├── 配置热加载
  └── Fake-IP DNS
        │
        ▼
Phase 6: 高级功能
  ├── VMess
  ├── WireGuard
  ├── TUN
  ├── Snell/AnyTLS
  └── NTP/DoQ/smux v2
```

---

## 八、验证策略

### 每阶段验证清单

| Phase | 验证项 |
|-------|--------|
| **1** | 所有 25 个现有单元测试通过 + 出站抽象测试 + dial 策略测试 + traffic_controller 路由模式测试 |
| **2** | 规则匹配测试 (每种规则 3+ 用例) + 代理组健康检查测试 + 路由模式切换 + mihomo YAML 配置兼容 |
| **3** | QUIC 连接/流读写测试 + Hysteria2/TUIC 帧解析 + 与 mihomo 客户端互操作 |
| **4** | WebSocket/gRPC 帧测试 + ShadowTLS 握手 + Vision 状态机 + 传输组合互操作 |
| **5** | API 端点集成测试 + Clash Dashboard 连接 + 热加载不丢连接 + Fake-IP DNS |
| **6** | VMess 帧解析 + WireGuard Noise 握手 + TUN 包收发 + 各协议互操作 |

### 互操作测试环境

```
测试矩阵:
┌─────────────┬──────────────────┬─────────────────────────┐
│ 客户端      │ Prism 服务端     │ 验证内容                │
├─────────────┼──────────────────┼─────────────────────────┤
│ mihomo      │ Prism            │ Trojan/VLESS/SS/H2 入站 │
│ sing-box    │ Prism            │ mux 协议兼容性          │
│ Clash Dash  │ Prism API        │ 管理面板功能            │
│ curl/wget   │ Prism            │ HTTP/SOCKS5 基础代理    │
│ v2rayN      │ Prism            │ VMess/VLESS+WS/gRPC    │
│ Hysteria2 CLI│ Prism           │ Hysteria2 协议          │
└─────────────┴──────────────────┴─────────────────────────┘
```
