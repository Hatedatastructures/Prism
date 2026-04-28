# Agent 模块 — 代理服务核心

## 1. 模块概述

Agent 模块是 Prism 代理服务器的核心调度引擎，负责从连接入站到会话分派的完整生命周期管理。它实现了前端连接监听、工作线程负载均衡、会话编排、协议分发和账户管理五大功能域。

### 文件结构

```
include/prism/agent/
├── config.hpp                  # Agent 配置类型（limit、endpoint、certificate、authentication）
├── context.hpp                 # 上下文结构体（server/worker/session_context）
├── front/
│   ├── listener.hpp            # TCP 监听器 + 反压 + 亲和性哈希
│   └── balancer.hpp            # 加权评分负载均衡器
├── worker/
│   ├── worker.hpp              # 工作线程核心（io_context/连接池/路由器）
│   ├── launch.hpp              # 会话启动（socket 投递、认证设置）
│   ├── stats.hpp               # 统计指标采集（EMA 延迟、活跃计数）
│   └── tls.hpp                 # TLS 上下文管理
├── session/
│   └── session.hpp             # 会话生命周期管理
├── dispatch/
│   ├── handler.hpp             # 处理器抽象基类（header-only）
│   ├── registry.hpp            # 处理器注册表（header-only）
│   └── table.hpp               # 编译期协议处理函数表（header-only）
└── account/
    ├── directory.hpp           # 写时复制账户存储 + 无锁读取
    └── entry.hpp               # 账户条目 + 租约 RAII + 流量统计

src/prism/agent/
├── front/
│   ├── listener.cpp            # 监听器实现
│   └── balancer.cpp            # 负载均衡器实现
├── worker/
│   ├── worker.cpp              # 工作线程实现
│   ├── launch.cpp              # 会话启动实现
│   ├── stats.cpp               # 统计采集实现
│   └── tls.cpp                 # TLS 证书加载实现
├── session/
│   └── session.cpp             # 会话实现
└── account/
    └── directory.cpp           # 账户目录实现（entry.hpp 是 header-only）
```

### 数据流概览

```
// 数据流概览
外部客户端
   │
   ▼
listener (接受连接)
   → affinity value → balancer (选择 worker)
   → dispatch()
   → worker (io_context + 池)
   → launch
   → session
   → recognition::recognize() (协议探测 + TLS 伪装识别)
   → dispatch (http/socks5/...)
```

---

## 2. 核心类型与类

### 2.1 listener (前端监听器)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/front/listener.hpp` |
| 实现文件 | `src/prism/agent/front/listener.cpp` |
| 命名空间 | `psm::agent::front` |

**核心成员:**

```
class listener
├── ioc_                        : net::io_context          // 独立 IO 上下文，与 worker 隔离
├── acceptor_                   : tcp::acceptor             // TCP 接受器
├── dispatcher_                 : balancer&                 // 负载均衡器引用
├── buffer_size_                : uint32_t                  // socket 缓冲区大小
├── backpressure_delay_         : milliseconds              // 反压延迟时间
├── make_affinity(endpoint)     : uint64_t                  // 亲和性哈希计算
└── accept_loop()               : awaitable<void>           // 异步接受循环协程
```

### 2.2 balancer (负载均衡器)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/front/balancer.hpp` |
| 实现文件 | `src/prism/agent/front/balancer.cpp` |
| 命名空间 | `psm::agent::front` |

**核心结构体:**

```
struct worker_load_snapshot         // 工作线程负载快照
├── active_sessions       : uint32  // 当前活跃会话数
├── pending_handoffs      : uint32  // 等待处理的移交任务数
└── event_loop_lag_us     : uint64  // 事件循环延迟（微秒）

struct distribute_config            // 分发策略配置
├── enter_overload        : double (0.90)  // 进入过载阈值
├── exit_overload         : double (0.80)  // 退出过载阈值
├── global_backpressure_threshold : double (0.95)
├── weight_session        : double (0.60)  // 会话数权重
├── weight_pending        : double (0.10)  // 待处理数权重
├── weight_lag            : double (0.30)  // 延迟权重
├── session_capacity      : uint32 (1024)  // 会话容量基准
├── pending_capacity      : uint32 (256)   // 待处理容量基准
└── lag_capacity_us       : uint64 (5000)  // 延迟容量基准

struct select_result                // 选择结果
├── worker_index          : size_t  // 选中线程索引
├── overflowed            : bool    // 是否已过载
└── backpressure          : bool    // 是否触发全局反压

class balancer
├── bindings_              : vector<worker_binding>  // 工作线程绑定列表
├── overload_state_        : vector<uint8_t>         // 过载状态标记
├── config_                : distribute_config       // 分发配置
├── select(affinity)       : select_result           // 选择最优 worker
├── dispatch(idx, socket)  : void                    // 分发连接到 worker
├── score(snapshot)        : double                  // 计算负载评分
├── mix_hash(value)        : uint64                  // MurmurHash3 混合
└── refresh_state(idx, score): void                  // 刷新过载状态
```

### 2.3 worker (工作线程)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/worker/worker.hpp` |
| 实现文件 | `src/prism/agent/worker/worker.cpp` |
| 命名空间 | `psm::agent::worker` |

```
class worker
├── ioc_                  : net::io_context          // 单线程事件循环
├── pool_                 : connection_pool          // TCP 连接池
├── router_               : resolve::router          // DNS 路由器
├── ssl_ctx_              : shared_ptr<ssl::context> // TLS 上下文
├── outbound_direct_      : unique_ptr<outbound::direct>
├── metrics_              : stats::state             // 统计状态
├── server_ctx_           : server_context           // 服务器全局上下文
├── worker_ctx_           : worker_context           // 线程局部上下文
├── dispatch_socket(sock) : void                     // 接收分发来的 socket
├── load_snapshot()       : worker_load_snapshot     // 报告负载快照
└── run()                 : void                     // 启动事件循环
```

### 2.4 session (会话)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/session/session.hpp` |
| 实现文件 | `src/prism/agent/session/session.cpp` |
| 命名空间 | `psm::agent::session` |

```
class session : enable_shared_from_this<session>
├── state (enum)          : active / closing / closed
├── id_                   : uint64                   // 全局唯一会话 ID
├── frame_arena_          : memory::frame_arena      // 帧内存池
├── state_                : state                    // 生命周期状态
├── ctx_                  : session_context          // 会话上下文
├── on_closed_            : function<void()>         // 关闭回调
├── start()               : void                     // 启动处理协程
├── close()               : void                     // 幂等关闭
├── diversion()           : awaitable<void>          // 协议检测 + 分流
├── release_resources()   : void                     // 释放所有资源
└── set_*()               : 各类回调设置器
```

### 2.5 dispatch::handler_table (协议处理函数表)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/dispatch/table.hpp` |
| 命名空间 | `psm::agent::dispatch` |

```
using handler_func = awaitable<void>(session_context&, span<const byte>);

inline constexpr array<handler_func*, N> handler_table {
    handle_unknown,       // unknown     → 原始 TCP 透传
    pipeline::http,       // http        → HTTP 代理管道
    pipeline::socks5,     // socks5      → SOCKS5 代理管道
    pipeline::trojan,     // trojan      → Trojan 协议管道
    pipeline::vless,      // vless       → VLESS 协议管道
    pipeline::shadowsocks,// shadowsocks → SS2022 协议管道
    handle_unknown,       // tls         → 由 stage chain 处理
};

dispatch(ctx, type, data) → awaitable<void>  // 按类型索引分派
```

### 2.6 account::directory + entry + lease

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/account/directory.hpp`, `entry.hpp` |
| 实现文件 | `src/prism/agent/account/directory.cpp`, `entry.cpp` |
| 命名空间 | `psm::agent::account` |

```
struct entry                        // 账户运行时状态
├── max_connections       : uint32  // 最大连接数 (0=无限制)
├── uplink_bytes          : atomic_uint64  // 上行流量
├── downlink_bytes        : atomic_uint64  // 下行流量
└── active_connections    : atomic_uint32  // 活跃连接数

class lease                         // RAII 连接租约
├── state_                : shared_ptr<entry>
├── release()             : void    // 析构时递减 active_connections
└── 仅移动语义，不可拷贝

class directory                     // 写时复制账户存储
├── allocator_            : memory::allocator<byte>
├── entries_ptr_          : atomic<shared_ptr<unordered_map>>
├── transparent_hash      : 支持 string_view 和 memory::string
├── transparent_equal     : 混合比较器
├── upsert(cred, max_conn): void    // 插入或更新
├── insert(cred, entry)   : void    // 复用已有条目注册新凭证
├── find(cred)            : shared_ptr<entry>  // 无锁查找
├── reserve(n)            : void
├── clear()               : void
└── update_entries(fn)    : void    // CAS 写时复制模板方法

try_acquire(directory, cred) → lease  // 获取连接租约（原子递增）
contains(directory, cred)  → bool     // 检查账户是否存在
```

### 2.7 上下文结构体

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/agent/context.hpp` |
| 命名空间 | `psm::agent` |

```
struct server_context             // 服务器全局（所有 worker 共享）
├── cfg                   : atomic<shared_ptr<const config>>  // 可热加载
├── ssl_ctx               : shared_ptr<ssl::context>
└── account_store         : shared_ptr<account::directory>

struct worker_context             // 每工作线程独立
├── io_context            : net::io_context&
├── router                : resolve::router&
├── memory_pool           : memory::resource_pointer
└── outbound              : outbound::proxy*

struct session_context            // 每会话独立（不可拷贝，仅移动）
├── session_id            : uint64
├── server                : const server_context&
├── worker                : worker_context&
├── frame_arena           : memory::frame_arena&
├── credential_verifier   : function<bool(string_view)>
├── account_directory_ptr : account::directory*
├── buffer_size           : uint32
├── inbound               : shared_transmission
├── outbound              : shared_transmission
├── outbound_proxy        : outbound::proxy*
├── account_lease         : account::lease
├── active_stream_cancel  : function<void()>
└── active_stream_close   : function<void()>
```

---

## 3. 架构与组件交互

### 3.1 分层架构图

```
// 分层架构
Front Layer:
   listener (accept + backpressure)
      → affinity value → balancer (weighted scoring + hysteresis overload + MurmurHash affinity)
   → dispatch()

Worker Layer:
   worker
      io_context (per thread)
      pool (connection reuse)
      router (DNS facade)
      ssl_ctx (optional)
   → dispatch_socket()

Session Layer:
   session (lifecycle + shared_ptr)
      → recognition::recognize() (probe + arrival + handshake)
      → dispatch::table (compile-time handler array)

Pipeline Layer:
   pipeline::http / pipeline::socks5 / pipeline::trojan
   pipeline::vless / pipeline::shadowsocks
```

### 3.2 组件交互矩阵

| 组件 | 依赖 | 被依赖 |
|------|------|--------|
| listener | balancer, config | 无（入口点） |
| balancer | memory::container | listener, worker |
| worker | connection_pool, router, ssl::context, account::directory | balancer, launch |
| session | server_context, worker_context, transmission, dispatch::table | launch |
| dispatch::table | protocol::protocol_type, pipeline | session |
| directory | memory::pool, entry | worker, session, account::lease |
| entry | 无（纯数据） | directory, lease |
| lease | entry | session_context |

### 3.3 线程模型

```
// 线程模型
Listener Thread:
   listener.ioc_
      accept_loop()
         → balancer.select()
         → balancer.dispatch()
   │ (cross-thread post)
   ▼

Worker Thread 0:
   worker_0.ioc_
      session_1 → handler → tunnel
      session_3 → handler → tunnel
      session_7 → handler → tunnel
   connection_pool_0 (thread-local)
   router_0 (thread-local)

Worker Thread 1:
   worker_1.ioc_
      session_2 → handler → tunnel
      session_5 → handler → tunnel
   connection_pool_1 (thread-local)
   router_1 (thread-local)
```

---

## 4. 完整生命周期流程

### 4.1 连接入站到会话分派序列图

```
// 连接入站到会话分派
Client → listener: SYN
listener: accept() → make_affinity(ep)
listener → balancer: select(affinity)
   → 评分计算 → 滞后过载检测 → 反压判断 → 返回 worker_index
balancer → worker: dispatch(idx, socket)
worker: post(ioc_) → launch → prime(sock) → make_session
worker → session: start()
session: diversion()
   → pread(24B) → detect_protocol
   → dispatch(ctx, type, data) → handler_table[type](ctx, data)
   → co_await handler

Client ◄── 数据转发 ──► session
Client → session: EOF
session: close() → release_resources() → 析构
```

### 4.2 负载均衡评分算法流程

```
// 负载均衡评分算法
affinity_value → mix_hash(affinity)  // MurmurHash3 混合
   candidate = hash % N              // N = worker 数量

收集所有 worker 的 load_snapshot()
   score = w_session * (sessions / C)
         + w_pending * (pending / P)
         + w_lag     * (lag / L)
   // C=1024, P=256, L=5000us

refresh_state(idx, score)
   if score > enter_overload (0.90):  state[idx] = OVERLOADED
   elif score < exit_overload (0.80): state[idx] = NORMAL
   // 滞后机制，避免抖动

选择最低评分的健康 worker
   若全部过载 → 选最低评分 + overflowed=true
   若所有 > global_backpressure (0.95) → backpressure=true

→ select_result { worker_index, overflowed, backpressure }
```

### 4.3 会话协议检测序列图

```
// 会话协议检测
session.start()
   → async_forward()
       1. recognition::recognize(ctx)
            ├─ probe::probe(inbound, 24)
            │    → detect(data)
            │         HTTP?    → protocol_type::http
            │         SOCKS5?  → protocol_type::socks5
            │         TLS?     → protocol_type::tls
            │         SS?      → protocol_type::shadowsocks
            │         else     → protocol_type::unknown
            ├─ (仅当 TLS)
            │    → identify(ctx)
            │         ├─ read_arrival()
            │         ├─ parse_arrival() → features
            │         ├─ analyzer_registry::analyze(features, cfg)
            │         │    → analysis_result{candidates, confidence}
            │         └─ scheme_executor::execute_by_analysis()
            │              → stealth::scheme::execute()
            │              → execution_result{transport, detected}
            └─ 返回 recognize_result{transport, detected, preread}
       2. dispatch::dispatch(ctx, detected, preread)
            → handler_table[detected](ctx, preread)
       3. co_await handler

handler 执行:
   HTTP:     解析请求 → router.async_forward → tunnel
   SOCKS5:   认证协商 → 解析目标 → tunnel
   Trojan:   认证 → 解析目标 → tunnel (可触发 smux)
   VLESS:    UUID 验证 → 解析目标 → tunnel
   SS2022:   解密 → 解析目标 → tunnel
   Unknown:  原始 TCP 双向透传
```

### 4.4 账户租约生命周期

```
新连接到达
    │
    ▼
try_acquire(directory, credential)
    │
    ├── find(credential) ── nullptr ──► 返回空租约 (拒绝)
    │
    ├── entry.max_connections == 0 ────► CAS fetch_add(1) ──► 返回 lease(entry)
    │
    └── entry.max_connections > 0
         │
         ├── current >= max ──────────► 返回空租约 (配额满)
         │
         └── CAS(current, current+1) ──► 成功 ──► 返回 lease(entry)
                                       失败 ──► 重试 CAS 循环

连接关闭 (lease 析构)
    │
    ▼
lease.release()
    │
    ├── fetch_sub(1, relaxed)    // 原子递减活跃连接数
    └── state_.reset()           // 释放 shared_ptr
```

---

## 5. 关键算法

### 5.1 MurmurHash3 亲和性混合

```
// balancer::mix_hash — 64-bit MurmurHash3 混合
static constexpr mix_hash(uint64_t value) → uint64:
    value ^= value >> 33
    value *= 0xFF51AFD7ED558CCD
    value ^= value >> 33
    value *= 0xC4CEB9FE1A85EC53
    value ^= value >> 33
    return value
```

该混合函数提供均匀的哈希分布，减少同一客户端连接的聚集效应。

### 5.2 加权评分归一化

```
score(snapshot) =
    weight_session * min(active_sessions / session_capacity, 1.0)
  + weight_pending * min(pending_handoffs / pending_capacity, 1.0)
  + weight_lag     * min(event_loop_lag_us / lag_capacity_us, 1.0)

默认权重: 0.60 + 0.10 + 0.30 = 1.00
评分范围: [0.0, 1.0]
```

### 5.3 滞后过载检测

```
当前状态 = NORMAL:
    if score > 0.90 → 切换到 OVERLOADED

当前状态 = OVERLOADED:
    if score < 0.80 → 切换到 NORMAL
    (即使 score 从 0.91 降到 0.85，仍保持 OVERLOADED)

全局反压:
    if (所有 worker 的 score > 0.95) → backpressure = true
    listener 收到 backpressure 后延迟 backpressure_delay 再 accept
```

### 5.4 写时复制 (Copy-on-Write) CAS 更新

```
update_entries(update_fn):
    current = entries_ptr_.load(acquire)
    if current is null:
        current = allocate_shared<map>(allocator_, 0)
    while true:
        next = allocate_shared<map>(allocator_, *current)  // 完整复制
        update_fn(*next)                                    // 修改副本
        if CAS(current, next, release, acquire):
            return                                          // 成功
        // CAS 失败: current 已被其他线程更新，重新复制并重试
```

### 5.5 租约原子连接计数

```
try_acquire(directory, credential) → lease:
    entry_ptr = directory.find(credential)
    if entry_ptr is null:
        return empty_lease

    if entry_ptr.max_connections == 0:
        // 无限制: 直接递增
        entry_ptr.active_connections.fetch_add(1, relaxed)
        return lease(entry_ptr)

    // 有限制: CAS 循环递增
    current = entry_ptr.active_connections.load(relaxed)
    while true:
        if current >= entry_ptr.max_connections:
            return empty_lease  // 配额已满
        if CAS(current, current+1, relaxed, relaxed):
            return lease(entry_ptr)  // 成功
        // CAS 失败: current 已更新，重试循环
```

---

## 6. 依赖关系

### 6.1 Agent 模块向外依赖

```
agent 模块
├── memory (PMR 分配器, frame_arena, container)
├── resolve::router (DNS 解析门面)
├── channel::connection_pool (TCP 连接池)
├── protocol::protocol_type (协议枚举)
├── pipeline (协议处理函数)
├── config (全局配置)
├── fault::code (错误码)
├── trace (日志)
└── outbound::proxy (出站代理接口)
```

### 6.2 外部模块对 Agent 的依赖

```
main() ──────────────────────► listener, worker
pipeline ────────────────────► session_context (通过 ctx 访问资源)
multiplex::bootstrap ────────► resolve::router (经由 worker)
protocol handlers ───────────► session_context, dispatch::table
```

---

## 7. 配置参数

### 7.1 Agent 相关配置项

```json
{
  "addressable": { "host": "0.0.0.0", "port": 1080 },
  "limit": { "blacklist": true },
  "positive": { "host": "", "port": 0 },
  "certificate": { "key": "", "cert": "" },
  "authentication": {
    "users": [
      {
        "password": "secret",
        "uuid": "xxx-xxx-xxx",
        "max_connections": 0
      }
    ]
  },
  "camouflage": "",
  "reverse_map": {}
}
```

`pool`、`buffer`、`protocol`、`multiplex`、`stealth`、`dns`、`trace` 为全局配置顶层键，与 `agent` 平级，见 `src/configuration.json`。

### 7.2 Balancer 分发配置 (硬编码默认值)

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `enter_overload` | 0.90 | 进入过载状态的负载阈值 |
| `exit_overload` | 0.80 | 退出过载状态的负载阈值 |
| `global_backpressure_threshold` | 0.95 | 全局反压触发阈值 |
| `weight_session` | 0.60 | 活跃会话数权重 |
| `weight_pending` | 0.10 | 待处理移交数权重 |
| `weight_lag` | 0.30 | 事件循环延迟权重 |
| `session_capacity` | 1024 | 会话容量基准值（归一化分母） |
| `pending_capacity` | 256 | 待处理容量基准值 |
| `lag_capacity_us` | 5000 | 延迟容量基准值（微秒） |
