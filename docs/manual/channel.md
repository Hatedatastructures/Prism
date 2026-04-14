# Channel 模块设计

## 模块概述

位置：`include/prism/channel/`、`src/prism/channel/`

Channel 模块是 Prism 的传输抽象层，位于 Pipeline 层和操作系统网络 API 之间，为上层协议处理提供统一的异步读写接口。模块的核心设计目标是：

- **传输抽象**：通过 `transmission` 基类将 TCP、UDP、TLS 等异构传输统一为协程读写接口，上层协议无需感知底层传输类型
- **连接复用**：通过 `connection_pool` 维护 TCP 连接池，减少握手开销，降低端到端延迟
- **快速连接**：通过 `eyeball::address_racer` 实现 RFC 8305 Happy Eyeballs 竞速算法，在多候选地址场景下优先选择最快路径
- **健康检测**：在连接池 checkout/checkin 时执行无侵入的 socket 状态检测，避免复用已失效的连接
- **Asio 适配**：通过 `connector` 适配器将 `transmission` 接口桥接到 Boost.Asio 概念体系，使 SSL 等库能直接工作在传输抽象之上

### 模块架构概览

```
  Pipeline 层
  primitives::dial() ─ primitives::tunnel() ─ primitives::ssl_handshake()
       │                      │                        │
       ▼                      ▼                        ▼
  Resolve 层                 Channel 层                Channel 层
  router::async_forward()    transport::reliable       adapter::connector
  router::connect_with_retry()    │                        │
       │                          │                        ▼
       ▼                          │                  transport::encrypted
  Channel 层                      │
  eyeball::address_racer          │
       │                          │
       ▼                          ▼
  connection::pool ────────── transport::transmission（抽象基类）
       │                          │
       │                     ┌────┼────────────┐
       │                     │    │             │
       │                     ▼    ▼             ▼
       │              reliable  unreliable   encrypted
       │              (TCP)     (UDP)        (TLS)
       │
       ▼
  health（僵尸检测）
```

## 1. transport 传输接口

位置：`include/prism/channel/transport/`

### transmission 基类

`transmission` 是所有传输实现的抽象基类，定义了协程语义的异步读写接口。所有异步方法返回 `net::awaitable<T>`，错误通过 `std::error_code&` 输出参数返回，避免异常开销。

**核心接口**：

| 方法 | 返回类型 | 说明 |
|------|----------|------|
| `is_reliable()` | `bool` | 标识传输是否可靠（TCP 返回 `true`） |
| `executor()` | `executor_type` | 返回关联的执行器 |
| `async_read_some(buffer, ec)` | `awaitable<size_t>` | 异步读取，可能返回部分数据 |
| `async_write_some(buffer, ec)` | `awaitable<size_t>` | 异步写入，可能写入部分数据 |
| `async_read(buffer, ec)` | `awaitable<size_t>` | 完整读取，循环调用 `async_read_some` 直到填满 |
| `async_write(buffer, ec)` | `awaitable<size_t>` | 完整写入，循环调用 `async_write_some` 直到发完 |
| `async_write_scatter(buffers, count, ec)` | `awaitable<size_t>` | Scatter-gather 写入，合并多个缓冲区减少系统调用 |
| `shutdown_write()` | `void` | 半关闭（关闭写端） |
| `close()` | `void` | 关闭传输层 |
| `cancel()` | `void` | 取消所有未完成的异步操作 |

**设计特点**：

- **协程优先**：所有异步操作返回 `net::awaitable`，上层通过 `co_await` 调用，无回调地狱
- **错误码返回**：通过 `ec` 参数返回错误，自动映射 Boost.System 错误码到项目 `fault::code`
- **智能指针管理**：`shared_transmission = std::shared_ptr<transmission>` 自动管理生命周期
- **Asio 概念兼容**：`get_executor()` 方法使传输对象兼容 Boost.Asio 执行器概念

此外，`transmission.hpp` 还提供了两个自由函数模板 `async_read_some()` 和 `async_write_some()`，将 `shared_ptr<transmission>` 适配为 Boost.Asio 的 `AsyncReadStream`/`AsyncWriteStream` 概念，支持任意完成令牌（协程、回调等）。

- 源码：[transmission.hpp](../../../include/prism/channel/transport/transmission.hpp)

### reliable — TCP 可靠传输

`reliable` 封装 `boost::asio::ip::tcp::socket`，提供基于 TCP 的可靠流式传输。这是最常用的传输实现，所有基于 TCP 的协议都使用此类。

**构造方式**：

| 构造函数 | 场景 |
|----------|------|
| `reliable(executor)` | 使用执行器创建，后续需要 `connect` 或 `accept` |
| `reliable(socket)` | 从已连接的 TCP socket 创建 |
| `reliable(pooled_connection)` | 从连接池获取的连接创建，`close()` 时归还连接池 |

**关键实现细节**：

- `async_read_some`/`async_write_some`：委托给底层 TCP socket，自动映射错误码
- `async_write_scatter`：当缓冲区数量为 2（最常见场景）时，使用 `net::async_write` + `std::array<net::const_buffer, 2>` 实现单次 `WSASend`/`writev` 系统调用，避免帧头与载荷分两次写入的额外开销
- 连接池复用：通过 `pooled_connection` 构造的实例在 `close()` 时归还连接池而非直接关闭 socket，实现连接复用
- `shutdown_write()`：支持 TCP 半关闭，通知对端不再发送数据
- 工厂函数：`make_reliable()` 提供三种重载简化创建

- 源码：[reliable.hpp](../../../include/prism/channel/transport/reliable.hpp)

### unreliable — UDP 不可靠传输

`unreliable` 封装 `boost::asio::ip::udp::socket`，提供基于 UDP 的数据报传输。内部维护远程端点实现"连接式"操作语义。

**设计特点**：

- **连接模拟**：通过记录 `remote_endpoint_`，所有发送操作指向该端点
- **来源过滤**：接收时验证来源是否匹配远程端点，不匹配则丢弃并继续等待
- **首次接收自动绑定**：若未设置远程端点，首次接收到的数据报来源将被自动设为远程端点
- **数据报语义**：`async_write` 直接委托给 `async_write_some`，因为 UDP 数据报一次发送完成，无需循环
- **写入前检查**：若未设置远程端点，写入操作返回 `io_error` 错误

- 源码：[unreliable.hpp](../../../include/prism/channel/transport/unreliable.hpp)

### encrypted — TLS 加密传输

`encrypted` 将 `ssl::stream<connector>` 适配为 `transmission` 接口，使协议装饰器能够透明地工作在 TLS 加密流之上。

**关键实现细节**：

- **底层类型**：`ssl::stream<connector>`，其中 `connector` 是 transmission 到 Asio 概念的适配器
- **Scatter-gather 优化**：当缓冲区数量为 2 时，使用 `net::async_write` 将多个缓冲区合并为单次 `SSL_write` 调用，使帧头和载荷合并为一条 TLS 记录，避免两次加密操作和额外的 TLS 帧头开销
- **优雅关闭**：`close()` 时执行 best-effort `SSL_shutdown` 发送 `close_notify`，非阻塞模式下立即返回
- **流访问**：提供 `stream()` 和 `release()` 方法访问底层 TLS 流

**创建方式**：通常由 `primitives::ssl_handshake()` 创建，该函数将 `transmission` 包装为 `connector`，在其上叠加 SSL 层，执行握手后返回 `encrypted` 传输。

- 源码：[encrypted.hpp](../../../include/prism/channel/transport/encrypted.hpp)

## 2. connection/pool — 连接池

位置：`include/prism/channel/connection/`、`src/prism/channel/connection/`

### 设计目标

TCP 连接建立涉及三次握手，延迟通常在 0.1-1ms 量级（局域网）到数十毫秒（广域网）。连接池通过复用已建立的 TCP 连接，消除重复握手开销，显著降低代理转发的端到端延迟。

### 核心类型

#### config — 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `max_cache_per_endpoint` | 32 | 单个目标端点最大缓存连接数 |
| `connect_timeout_ms` | 300 | 连接超时（毫秒） |
| `max_idle_seconds` | 30 | 空闲连接最大存活时间（秒） |
| `cleanup_interval_sec` | 10 | 后台清理间隔（秒） |
| `recv_buffer_size` | 65536 | 接收缓冲区大小（字节） |
| `send_buffer_size` | 65536 | 发送缓冲区大小（字节） |
| `tcp_nodelay` | true | 是否启用 TCP_NODELAY |
| `keep_alive` | true | 是否启用 SO_KEEPALIVE |
| `cache_ipv6` | false | 是否缓存 IPv6 连接 |

#### pooled_connection — RAII 连接包装器

`pooled_connection` 是连接池连接的 RAII 包装器，内联存储 pool 指针、socket 指针和 endpoint，零堆分配。关键行为：

- **析构自动归还**：析构函数调用 `reset()`，将连接归还到连接池进行健康检测和可能的复用
- **移动语义**：支持移动构造和移动赋值，移动后源对象变为无效状态（`valid()` 返回 `false`）
- **释放所有权**：`release()` 放弃所有权，调用方接管 socket 并负责关闭
- **手动归还**：`reset()` 主动触发归还或关闭

#### pool_stats — 统计信息

| 指标 | 说明 |
|------|------|
| `idle_count` | 当前空闲连接数 |
| `endpoint_count` | 有缓存的端点数 |
| `total_acquires` | 总获取次数 |
| `total_hits` | 缓存命中次数 |
| `total_creates` | 新建连接次数 |
| `total_recycles` | 归还次数 |
| `total_evictions` | 驱逐次数（容量满/不健康/过期） |

### 连接获取流程

```
  async_acquire(endpoint)
       │
       ├─ 1. 查找 endpoint_key → idle stack
       │     │
       │     ├─ LIFO 弹出栈顶连接
       │     │   ├─ 过期？→ 驱逐，继续弹出
       │     │   ├─ 健康检测失败？→ 驱逐，继续弹出
       │     │   └─ 健康 → 缓存命中，返回 pooled_connection
       │     │
       │     └─ 栈空 → 移除端点条目
       │
       ├─ 2. 缓存未命中：创建新连接
       │     │
       │     ├─ new tcp::socket + async_connect
       │     ├─ 并发启动超时定时器（awaitable_operators ||）
       │     ├─ 超时 → 返回 fault::code::timeout
       │     ├─ 连接失败 → 返回 fault::code::bad_gateway
       │     └─ 成功 → 设置 socket 选项，返回 pooled_connection
       │
       └─ 返回 pair<fault::code, pooled_connection>
```

### 连接归还流程

```
  recycle(socket, endpoint)
       │
       ├─ 无效/已关闭 → 直接销毁
       ├─ IPv6 且 cache_ipv6=false → 直接销毁
       ├─ 健康检测失败 → 直接销毁
       ├─ 缓存容量满 → 直接销毁
       └─ 满足条件 → push_back 到 LIFO 栈，记录 last_used
```

### 后台清理

`start()` 启动后台清理协程，按 `cleanup_interval_sec` 间隔周期性执行 `cleanup()`：

- 遍历所有端点的连接栈
- 使用**原地压缩算法**移除超过 `max_idle_seconds` 的过期连接，避免额外内存分配
- 空栈的端点条目被移除
- 通过 `shutdown_flag_` 共享标志安全退出，避免析构时 UAF

### 设计约束

- **线程隔离**：每个 worker 线程独享一个连接池实例，无锁设计
- **LIFO 策略**：后归还的连接最先被复用，热点数据更可能在缓存中
- **统计原子性**：计数器使用 `memory_order_relaxed`，不保证与其他操作的严格原子性
- **endpoint_key**：使用 FNV-1a 变体哈希，按 `port + family + address` 唯一标识端点

- 源码：[pool.hpp](../../../include/prism/channel/connection/pool.hpp)、[pool.cpp](../../../src/prism/channel/connection/pool.cpp)

## 3. adapter/connector — Socket 适配器

位置：`include/prism/channel/adapter/`

### 设计意图

`connector` 是传输层和上层协议处理之间的关键桥梁。它的核心职责是将 `transmission` 接口适配为 Boost.Asio 的 `AsyncReadStream`/`AsyncWriteStream` 概念，使 Boost.Asio.SSL 等库能直接工作在传输抽象之上。

### 关键能力

**预读数据注入**：

在协议嗅探阶段，session 会预读 24 字节数据用于协议检测。这些数据不能丢失。`connector` 在构造时可注入预读数据切片，首次 `async_read_some` 调用时优先返回预读数据，耗尽后委托给内部 `transmission`。

```
  connector(transmission, preread_data)
       │
       async_read_some()
       ├─ preread 未耗尽 → 从 preread_buffer_ 复制返回（同步完成）
       └─ preread 已耗尽 → 委托给 transmission::async_read_some()
```

**Asio 概念适配**：

- `get_executor()` → 委托给 `transmission::executor()`
- `async_read_some(buffers, token)` → 支持 Boost.Asio 完成令牌
- `async_write_some(buffers, token)` → 委托给自由函数 `transport::async_write_some()`
- `lowest_layer_type` 和 `lowest_layer()` → 满足 `ssl::stream` 的最低层类型要求

**所有权管理**：

- 内部通过 `shared_ptr` 持有 `transmission`，确保 `co_spawn(detached)` 异步操作期间传输对象不会被提前释放
- `release()` 转移 `transmission` 所有权

### 使用场景

`connector` 的主要使用场景是 TLS 握手：

1. `primitives::ssl_handshake()` 将入站 `transmission` 包装为 `connector`
2. `ssl::stream<connector>` 在 connector 之上叠加 SSL 层
3. 执行 `async_handshake` 完成 TLS 协商
4. 握手成功后创建 `encrypted` 传输层供后续协议处理

- 源码：[connector.hpp](../../../include/prism/channel/adapter/connector.hpp)

## 4. eyeball/racer — Happy Eyeballs 竞速

位置：`include/prism/channel/eyeball/`、`src/prism/channel/eyeball/`

### 算法原理

Happy Eyeballs (RFC 8305) 解决了以下问题：

- IPv6 连接可能存在"黑洞"（路由配置错误导致连接挂起）
- 单地址连接失败时需等待超时才能尝试下一个地址
- 用户感知的连接延迟过长

### 竞速时间线

假设 DNS 返回 3 个端点 `[IPv6_A, IPv4_B, IPv4_C]`：

```
  时间   |  IPv6_A  |  IPv4_B  |  IPv4_C
  -------|----------|----------|----------
  0ms    |  开始    |          |
  250ms  |  ...     |  开始    |
  500ms  |  ...     |  ...     |  开始
```

如果 IPv6_A 在 100ms 成功：
- IPv4_B 的定时器被取消，连接不会开始
- IPv4_C 的定时器被取消，连接不会开始
- 返回 IPv6_A 的连接

### 实现架构

```
  race(endpoints)
       │
       ├─ endpoints.size() == 0 → 返回空连接
       ├─ endpoints.size() == 1 → 直接 async_acquire，无并发开销
       │
       └─ endpoints.size() > 1
            │
            ├─ 创建 race_context（共享状态）
            │   ├─ winner: atomic<bool> 获胜标志
            │   ├─ result: pooled_connection 获胜连接
            │   ├─ pending: atomic<size_t> 未完成计数
            │   └─ signal: steady_timer 完成信号
            │
            ├─ 为每个端点 co_spawn 子协程
            │   │
            │   └─ race_endpoint(ep, delay, ctx)
            │       ├─ 等待 staggered delay（0ms / 250ms / 500ms / ...）
            │       ├─ 检查 winner（延迟期间可能已有获胜者）
            │       ├─ pool_.async_acquire(ep)
            │       ├─ winner.exchange(true) 原子竞争
            │       │   ├─ 获胜：保存连接，取消 signal 唤醒主协程
            │       │   └─ 落败：归还连接到池中供复用
            │       └─ ctx->complete() 递减 pending
            │
            └─ 主协程等待 signal.async_wait()
                └─ 返回 ctx->result
```

### 线程安全

`address_racer` 设计为单线程 `io_context` 上使用：

- `winner` 使用 `atomic<bool>` 的 `exchange` 操作保证只有一个获胜者
- 在单线程 `io_context` 上，`winner` 写入与 `signal.cancel()` 之间无 `co_await` 挂起点，主协程不可能在写入前读取
- 子协程直接捕获连接池引用（而非 `this`），因为 `address_racer` 可能是调用方的局部变量，主协程返回后 racer 即被销毁

### 延迟参数

| 参数 | 值 | 说明 |
|------|----|------|
| `secondary_delay` | 250ms | RFC 8305 建议值（推荐范围 100-500ms） |
| 第 1 个端点 | 0ms | 立即连接 |
| 第 N 个端点 | (N-1) * 250ms | 递增延迟 |

### 集成方式

`router::connect_with_retry()` 是 `address_racer` 的调用方：

```
  router::async_forward(host, port)
       │
       ├─ IP 字面量 → pool_.async_acquire(endpoint)
       │
       └─ 域名 → dns_.resolve_tcp() → endpoints
            │
            └─ connect_with_retry(endpoints)
                 │
                 └─ eyeball::address_racer(pool_).race(endpoints)
```

- 源码：[racer.hpp](../../../include/prism/channel/eyeball/racer.hpp)、[racer.cpp](../../../src/prism/channel/eyeball/racer.cpp)

## 5. health — Socket 健康检测

位置：`include/prism/channel/health.hpp`、`src/prism/channel/health.cpp`

### 设计目标

连接池复用连接前必须验证 socket 仍然健康可用，避免将已关闭或错误的连接提供给上层使用。健康检测是无侵入的，不会消费 socket 数据。

### 健康状态

| 状态 | 说明 |
|------|------|
| `healthy` | 连接健康，可安全复用 |
| `has_data` | 有待读数据（可能残留上一轮脏数据） |
| `fin` | 对端已发送 FIN，不可复用 |
| `error` | socket 错误，不可复用 |
| `invalid` | socket 无效（未打开或已关闭） |

### 检测接口

#### health() — 完整检测

依次检查三个维度，返回精确的 `socket_state`：

1. **SO_ERROR**：通过 `getsockopt(SOL_SOCKET, SO_ERROR)` 获取 socket 待处理错误码
2. **available**：检查是否有待读取数据
3. **peek**：当 `available == 0` 时，通过非阻塞 `recv(MSG_PEEK)` 检测对端 FIN

#### healthy_fast() — 快速检测

返回 `bool`，专用于连接池的高频检测场景。逻辑：

1. 检查 `is_open()` — socket 是否有效
2. 检查 `SO_ERROR` — 是否有待处理错误
3. 检查 `available` — 有待读数据则返回 `false`（可能残留脏数据，不适合复用）
4. 非阻塞 `recv(MSG_PEEK)` — 检测 FIN（`available` 为 0 时 FIN 无法被检测到，必须 peek）

**关键细节**：FIN 不产生"可用数据"，`available()` 返回 0，因此必须通过 `MSG_PEEK` 才能检测到对端已关闭的情况。

### 检测时机

健康检测在两个关键时机被调用：

- **checkout（async_acquire）**：从缓存弹出连接后执行 `healthy_fast()`，不健康的连接被驱逐
- **checkin（recycle）**：连接归还到池时执行 `healthy_fast()`，不健康的连接被直接关闭

- 源码：[health.hpp](../../../include/prism/channel/health.hpp)、[health.cpp](../../../src/prism/channel/health.cpp)

## 6. 与 Pipeline 层的集成

Channel 模块通过 `pipeline::primitives` 命名空间的原语与上层协议处理器集成。以下是两条核心数据路径：

### dial — 上游拨号

`primitives::dial()` 是所有协议处理器建立上游连接的统一入口：

```
  协议 handler (HTTP/Socks5/Trojan/Vless/SS)
       │
       ▼
  primitives::dial(router, label, target, ...)
       │
       ├─ target.positive == false && allow_reverse
       │   └─ router::async_reverse(host)
       │       └─ reverse_map 查找 → pool_.async_acquire(endpoint)
       │
       └─ target.positive == true (正向路由)
           └─ router::async_forward(host, port)
               ├─ IP 字面量 → pool_.async_acquire(endpoint)
               └─ 域名 → dns_.resolve_tcp() → eyeball::address_racer.race()
       │
       ▼
  channel::transport::make_reliable(pooled_connection)
       │
       ▼
  返回 shared_transmission（reliable 传输）
```

**关键转换**：`dial()` 将 `pooled_connection`（连接池的 RAII 包装）转换为 `shared_transmission`（传输层抽象的智能指针），通过 `make_reliable()` 工厂函数完成。`reliable` 在 `close()` 时自动归还连接到连接池。

### ssl_handshake — TLS 握手

`primitives::ssl_handshake()` 为所有需要 TLS 的协议提供统一的握手入口：

```
  session (入站 connection)
       │
       ▼
  primitives::ssl_handshake(ctx, preread_data)
       │
       ├─ 创建 connector(ctx.inbound, preread_data)
       │   └─ 注入协议检测时的预读数据
       │
       ├─ 创建 ssl::stream<connector>(connector, ssl_context)
       │   └─ 在 connector 之上叠加 SSL 层
       │
       ├─ async_handshake(server)
       │   └─ BoringSSL 通过 connector 读写传输层数据
       │
       └─ 握手成功 → 返回 shared_ssl_stream
           └─ 可进一步包装为 encrypted 传输
```

### tunnel — 双向隧道

`primitives::tunnel()` 在两个 `transmission` 之间建立全双工隧道：

```
  inbound ──────► outbound
     │               │
     │ read      write│
     │               │
     ◄───────────────┘
  outbound ────► inbound
     │               │
     │ read      write│
     │               │
```

**实现要点**：

- 分配单个 PMR 缓冲区，切割为两半分别用于两个方向
- 使用 `awaitable_operators::||` 并行启动两个转发协程
- 任一方向断开即终止整个隧道
- `complete_write` 参数控制写入语义（完整写入 vs 单次写入）
- 隧道结束后自动关闭两端传输

## 7. 完整数据流示例

以下是一个完整的 HTTP 代理请求从入站到出站的数据流：

```
  Client → Listener → Balancer → Worker → Session
                                            │
                                   protocol::probe() 预读 24B
                                            │
                                   registry → Http handler
                                            │
                                   ┌── Pipeline ──┐
                                   │               │
                                   │ http::process()
                                   │  ├─ 解析 HTTP 请求
                                   │  ├─ 提取目标地址 (target)
                                   │  ├─ primitives::dial()
                                   │  │   ├─ router::async_forward()
                                   │  │   │   ├─ dns_.resolve_tcp()
                                   │  │   │   └─ eyeball::address_racer.race()
                                   │  │   │       └─ pool_.async_acquire()
                                   │  │   └─ make_reliable(pooled_connection)
                                   │  ├─ 发送 200 Connection Established
                                   │  └─ primitives::tunnel(inbound, outbound)
                                   │       └─ 双向转发直到断开
                                   │               │
                                   └───────────────┘
                                            │
                                   reliable::close()
                                   └─ pooled_connection 析构
                                       └─ pool_.recycle() → healthy_fast() → 归还/销毁
```
