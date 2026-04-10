# Prism 架构设计

本文档详细描述 Prism 的架构设计，包括能力边界、时序链和关键实现细节。

---

## 一、架构能力分析

### 1.1 源码已实现的能力

基于运行链确认已实现的功能，所有结论均有源码位置引用。

#### HTTP/HTTPS 代理

**CONNECT 方法（隧道代理）**：
- 实现位置：[http.cpp](../../src/prism/pipeline/protocols/http.cpp)
- 处理流程：解析 HTTP 请求后，对 CONNECT 方法返回 `HTTP/1.1 200 Connection Established`，随后建立双向隧道

**普通 HTTP 请求转发**：
- 实现位置：[http.cpp](../../src/prism/pipeline/protocols/http.cpp)
- 处理流程：序列化请求并转发到上游，同时转发预读缓冲区中的剩余数据

**HTTP 代理认证**：
- 实现位置：[http.cpp](../../src/prism/pipeline/protocols/http.cpp)
- 认证方式：Proxy-Authorization: Basic（Base64 解码使用 [base64.hpp](../../include/prism/crypto/base64.hpp)）
- 未认证请求返回 `407 Proxy Authentication Required`，认证失败返回 `403 Forbidden`

#### SOCKS5 代理

**CONNECT 命令**：
- 实现位置：[socks5.cpp](../../src/prism/pipeline/protocols/socks5.cpp)
- 处理流程：握手协商 → 目标解析 → 建立上游连接 → 返回成功响应 → 双向隧道

**UDP_ASSOCIATE 命令**：
- 实现位置：[socks5.cpp](../../src/prism/pipeline/protocols/socks5.cpp)
- 处理流程：调用 `async_associate()` 建立 UDP 中继

#### TLS 终止

**TLS 握手**：
- 实现位置：[session.cpp](../../src/prism/agent/session/session.cpp)
- Session 层检测到 `protocol_type::tls` 后执行 TLS 握手，探测内层协议后分发到对应 handler

#### 反向代理

**reverse_map 路由**：
- 配置定义：[config.hpp](../../include/prism/agent/config.hpp)
- 路由初始化：[worker.cpp](../../src/prism/agent/worker/worker.cpp)
- 路由查询：[router.hpp](../../include/prism/resolve/router.hpp)

#### 正向代理 Fallback

**直连失败后转发**：
- 实现位置：[router.cpp](../../src/prism/resolve/router.cpp)
- 处理流程：先检查黑名单 → 尝试直连 → 失败后转发到 positive endpoint

#### 负载均衡

**基于评分的 Worker 选择**：
- 实现位置：[balancer.hpp](../../include/prism/agent/front/balancer.hpp)
- 评分公式：`score = weight_session * (sessions/capacity) + weight_pending * (pending/capacity) + weight_lag * (lag/capacity)`
- 默认权重：session 60%、pending 10%、lag 30%
- 过载检测：采用滞后机制（进入阈值 90%，退出阈值 80%）

#### 连接池

**TCP 连接复用**：
- 实现位置：[pool.hpp](../../include/prism/channel/connection/pool.hpp)
- 核心特性：栈式缓存（LIFO）、僵尸检测、线程隔离、空闲超时

#### DNS 缓存

- **cache**：[cache.hpp](../../include/prism/resolve/cache.hpp)，支持正向缓存和负缓存，默认 TTL 120 秒，最大条目 10000，serve-stale 模式
- **请求合并**：[coalescer.hpp](../../include/prism/resolve/coalescer.hpp)，避免重复 DNS 查询
- **域名规则**：[rules.hpp](../../include/prism/resolve/rules.hpp)，基于反转 Trie 的规则引擎，支持静态 IP、广告屏蔽、CNAME 重定向

#### 账户认证与配额控制

- 实现位置：[directory.hpp](../../include/prism/agent/account/directory.hpp)
- 特性：写时复制、无锁读取、透明查找、CAS 原子递增
- 租约管理：[entry.hpp](../../include/prism/agent/account/entry.hpp)，RAII 自动管理连接计数

### 1.2 运行链完整度

| 能力 | 配置 | 实现 | 接入 | 状态 |
|------|------|------|------|------|
| HTTP 代理 | ✅ | ✅ | ✅ | 完整 |
| HTTPS 代理 | ✅ | ✅ | ✅ | 完整 |
| SOCKS5 TCP | ✅ | ✅ | ✅ | 完整 |
| SOCKS5 UDP | ✅ | ✅ | ✅ | 完整 |
| TLS 终止 | ✅ | ✅ | ✅ | 完整 |
| 反向代理 | ✅ | ✅ | ✅ | 完整 |
| 正向 Fallback | ✅ | ✅ | ✅ | 完整 |
| 负载均衡 | ✅ | ✅ | ✅ | 完整 |
| 连接池 | ✅ | ✅ | ✅ | 完整 |
| DNS 缓存 | ✅ | ✅ | ✅ | 完整 |
| 账户认证 | ✅ | ✅ | ✅ | 完整 |
| Trojan 协议 | ✅ | ✅ | ✅ | 完整 |

---

## 二、进程启动流程

### 2.1 初始化阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 1 | `enable_global_pooling()` | `src/main.cpp` | 初始化全局内存池 |
| 2 | `register_handlers()` | `src/main.cpp` | 注册协议处理器到全局工厂 |

### 2.2 配置加载阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 3 | `loader::load(configuration_path)` | `src/main.cpp` | 从配置文件加载 agent 配置 |
| 4 | `trace::init(trace)` | `src/main.cpp` | 初始化日志追踪系统 |

### 2.3 账户存储初始化

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 5 | 创建 `account_store` | `src/main.cpp` | 使用全局内存池创建账户目录 |
| 6 | 填充 `credentials` | `src/main.cpp` | 遍历并插入凭据数据 |
| 7 | 填充 `users` | `src/main.cpp` | 遍历并插入用户数据（含连接数限制） |

### 2.4 Worker 创建阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 8 | 计算 `workers_count` | `src/main.cpp` | 根据 CPU 核心数计算工作线程数 |
| 9 | 创建 `workers` 向量 | `src/main.cpp` | 创建并填充 worker 实例 |

### 2.5 负载均衡器绑定

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 10 | 创建 `bindings` 列表 | `src/main.cpp` | 为每个 worker 创建分发函数和快照函数 |
| 11 | 创建 `balancer` | `src/main.cpp` | 使用绑定列表创建负载均衡器 |
| 12 | 创建 `listener` | `src/main.cpp` | 创建监听器实例 |

### 2.6 线程启动阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 13 | 启动 worker 线程 | `src/main.cpp` | 为每个 worker 启动独立线程运行 `worker.run()` |
| 14 | 启动监听线程 | `src/main.cpp` | 启动独立线程运行 `listener.listen()` |

---

## 三、连接处理流程

### 3.1 连接接受阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 1 | `listener.listen()` | `src/main.cpp` | 监听线程入口 |
| 2 | `net::co_spawn(accept_loop())` | `src/prism/agent/front/listener.cpp` | 启动接受连接协程 |
| 3 | `acceptor_.async_accept()` | `src/prism/agent/front/listener.cpp` | 异步接受新连接 |

### 3.2 负载均衡阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 4 | `make_affinity()` | `src/prism/agent/front/listener.cpp` | 根据客户端 IP 计算亲和性哈希 |
| 5 | `balancer.select(affinity)` | `src/prism/agent/front/listener.cpp` | 选择目标 worker |
| 6 | 检查 `backpressure` | `src/prism/agent/front/listener.cpp` | 若过载则延迟 |
| 7 | `balancer.dispatch()` | `src/prism/agent/front/listener.cpp` | 分发 socket 到选定 worker |

### 3.3 Worker 分发阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 8 | `worker.dispatch_socket()` | `src/prism/agent/worker/worker.cpp` | Worker 接收分发请求 |
| 9 | `launch::dispatch()` | `src/prism/agent/worker/launch.cpp` | 投递到 worker 事件循环 |
| 10 | `net::post(ioc, ...)` | `src/prism/agent/worker/launch.cpp` | 跨线程投递到 IO 上下文 |

### 3.4 会话创建阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 11 | `launch::start()` | `src/prism/agent/worker/launch.cpp` | 启动会话 |
| 12 | 创建 `inbound` 传输 | `src/prism/agent/worker/launch.cpp` | 包装 socket 为可靠传输 |
| 13 | `make_session()` | `src/prism/agent/worker/launch.cpp` | 创建 session 实例 |
| 14 | `session.start()` | `src/prism/agent/worker/launch.cpp` | 启动会话处理 |

### 3.5 协议检测阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 15 | `session.diversion()` | `src/prism/agent/session/session.cpp` | 协议分流入口 |
| 16 | `protocol::probe::probe()` | `src/prism/agent/session/session.cpp` | 嗅探检测协议类型（预读 24 字节） |
| 17 | `registry::global().create()` | `src/prism/agent/session/session.cpp` | 根据协议类型获取处理器 |

### 3.6 协议处理阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 18 | `handler->process()` | `src/prism/agent/session/session.cpp` | 调用处理器处理协议 |
| 19 | 协议管道处理 | 见下表 | 根据协议类型调用对应管道 |

**协议管道映射表：**

| 协议类型 | 处理器类 | 管道函数 | 源码位置 |
|----------|----------|----------|----------|
| HTTP | `dispatch::Http` | `psm::pipeline::http()` | `include/prism/agent/dispatch/handlers.hpp` |
| SOCKS5 | `dispatch::Socks5` | `psm::pipeline::socks5()` | `include/prism/agent/dispatch/handlers.hpp` |
| Trojan | `dispatch::Trojan` | `psm::pipeline::trojan()` | `include/prism/agent/dispatch/handlers.hpp` |
| Unknown | `dispatch::Unknown` | `primitives::tunnel()` | `include/prism/agent/dispatch/handlers.hpp` |

### 3.7 上游连接阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 20 | `protocol::analysis::resolve()` | `src/prism/pipeline/protocols/` | 解析请求获取目标地址 |
| 21 | `primitives::dial()` | `src/prism/pipeline/primitives.cpp` | 建立上游连接 |
| 22 | `router->async_reverse()` 或 `router->async_forward()` | `src/prism/resolve/router.cpp` | 路由选择 |
| 23 | `psm::channel::transport::make_reliable()` | `src/prism/pipeline/primitives.cpp` | 包装为可靠传输 |

### 3.8 双向转发阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 24 | `primitives::tunnel()` | `include/prism/pipeline/primitives.hpp` | 建立全双工隧道 |
| 25 | 双向数据转发 | `include/prism/pipeline/primitives.hpp` | 并发转发双向数据流 |
| 26 | 连接关闭 | `include/prism/pipeline/primitives.hpp` | 任一方向断开后关闭两端 |

---

## 四、协议处理器注册

当前 `register_handlers()` 函数注册以下四种协议处理器：

| 协议类型 | 枚举值 | 处理器类 | 注册位置 |
|----------|--------|----------|----------|
| HTTP | `protocol_type::http` | `dispatch::Http` | `include/prism/agent/dispatch/handlers.hpp` |
| SOCKS5 | `protocol_type::socks5` | `dispatch::Socks5` | `include/prism/agent/dispatch/handlers.hpp` |
| Trojan | `protocol_type::trojan` | `dispatch::Trojan` | `include/prism/agent/dispatch/handlers.hpp` |
| Unknown | `protocol_type::unknown` | `dispatch::Unknown` | `include/prism/agent/dispatch/handlers.hpp` |

**注册函数定义：**

```cpp
inline void register_handlers()
{
    auto &factory = registry::global();
    factory.register_handler<Http>(protocol::protocol_type::http);
    factory.register_handler<Socks5>(protocol::protocol_type::socks5);
    factory.register_handler<Trojan>(protocol::protocol_type::trojan);
    factory.register_handler<Unknown>(protocol::protocol_type::unknown);
}
```

源码位置：`include/prism/agent/dispatch/handlers.hpp`

---

## 五、关键实现细节

### 5.1 Listener 绑定 IPv4 而非 addressable.host

**问题位置**：[listener.cpp](../../src/prism/agent/front/listener.cpp)

```cpp
const tcp::endpoint endpoint(tcp::v4(), cfg.addressable.port);
```

**影响**：
- 无法绑定到特定 IP 地址
- 无法支持 IPv6 监听
- 多网卡环境下无法指定监听接口

**待优化**：支持 `addressable.host` 绑定和 IPv6

### 5.2 async_forward 先直连后 Fallback

**实现位置**：[router.cpp](../../src/prism/resolve/router.cpp)

**处理流程**：
1. IPv6 字面量检测（若 `dns.disable_ipv6` 为 true，直接拒绝 IPv6 地址）
2. DNS 解析目标域名（通过 recursor 的查询管道，已内置 IPv6 过滤）
3. 带重试连接（最多尝试 3 个端点）
4. 通过连接池获取已建立的 socket

**设计意图**：DNS 解析由 recursor 整合规则、缓存、请求合并，减少实际上游查询次数。

### 5.3 reverse_map 目标更偏向 IP Literal

**实现位置**：[worker.cpp](../../src/prism/agent/worker/worker.cpp)

**影响**：
- `reverse_map` 的目标地址应为 IP Literal
- 域名格式目标需要额外 DNS 解析逻辑
- 配置错误时仅打印警告，不影响其他路由

---

## 六、关键数据结构

### 6.1 session_context

会话上下文，贯穿整个连接处理流程：

| 字段 | 类型 | 说明 |
|------|------|------|
| `server` | `server_context&` | 服务器配置上下文 |
| `worker` | `worker_context&` | Worker 运行时上下文 |
| `frame_arena` | `memory::frame_arena&` | 帧内存竞技场 |
| `inbound` | `psm::channel::transport::transmission_pointer` | 入站传输层 |
| `outbound` | `psm::channel::transport::transmission_pointer` | 出站传输层 |
| `buffer_size` | `std::uint32_t` | 缓冲区大小 |

详细说明请参阅 [上下文结构体](../reference/context.md)。

### 6.2 worker_binding

Worker 绑定结构，用于负载均衡器与 Worker 通信：

| 字段 | 类型 | 说明 |
|------|------|------|
| `dispatch` | `std::function<void(tcp::socket)>` | 分发 socket 的函数 |
| `snapshot` | `std::function<worker_load_snapshot()>` | 获取负载快照的函数 |

---

## 七、时序图

```
  main              listener          balancer          worker            session
    │                   │                 │                 │                 │
    ├─ enable_global_pooling() ──────────────────────────────────────────────→
    │                   │                 │                 │                 │
    ├─ register_handlers() ──────────────────────────────────────────────────→
    │                   │                 │                 │                 │
    ├─ load(config) ─────────────────────────────────────────────────────────→
    │                   │                 │                 │                 │
    ├─ create workers   │                 │                 │                 │
    ├─ create balancer  │                 │                 │                 │
    ├─ create listener  │                 │                 │                 │
    ├─ spawn threads    │                 │                 │                 │
    │                   │                 │                 │                 │
    │              accept_loop()          │                 │                 │
    │              async_accept()         │                 │                 │
    │                   │                 │                 │                 │
    │              select(affinity) ──→   │                 │                 │
    │                   │ ←─────────────  │                 │                 │
    │                   │                 │                 │                 │
    │              dispatch(socket) ──→   │                 │                 │
    │                   │                 │                 │                 │
    │                   │            dispatch_socket() ──→  │                 │
    │                   │                 │                 │                 │
    │                   │                 │            launch::dispatch() ──→│
    │                   │                 │                 │                 │
    │                   │                 │                 │  start()
    │                   │                 │                 │  diversion()
    │                   │                 │                 │  probe()
    │                   │                 │                 │  create()
    │                   │                 │                 │  process()
    │                   │                 │                 │  dial()
    │                   │                 │                 │  tunnel()
    │                   │                 │                 │       │
    │                   │                 │                 │ ←─────┘
    │                   │                 │ ←───────────────┘
    │                   │ ←───────────────┘
    │ ←─────────────────┘
```

---

## 八、待完善项

### 高优先级

当前无高优先级待完善项。

### 中优先级

| 任务 | 说明 | 状态 |
|------|------|------|
| Listener 绑定优化 | 支持 `addressable.host` 绑定和 IPv6 | 📋 计划中 |
| reverse_map 域名支持 | 增加 DNS 解析逻辑支持域名目标 | 📋 计划中 |
| SOCKS5 认证 | 支持用户名密码认证 | 📋 计划中 |

### 低优先级

| 任务 | 说明 | 状态 |
|------|------|------|
| 配置热更新 | 修改配置后无需重启 | 📋 计划中 |
| 性能监控接口 | 暴露连接数、流量、性能指标 | 📋 计划中 |
