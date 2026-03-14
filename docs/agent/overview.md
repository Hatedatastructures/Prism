# Agent 时序链概述

本文档记录 agent 从进程启动到连接转发完成的完整时序链。

## 一、进程启动流程

### 1.1 初始化阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 1 | `enable_global_pooling()` | `src/main.cpp:22` | 初始化全局内存池 |
| 2 | `register_handlers()` | `src/main.cpp:23` | 注册协议处理器到全局工厂 |

### 1.2 配置加载阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 3 | `adapter::load(configuration_path)` | `src/main.cpp:31` | 从配置文件加载 agent 配置 |
| 4 | `trace::init(trace)` | `src/main.cpp:32` | 初始化日志追踪系统 |

### 1.3 账户存储初始化

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 5 | 创建 `account_store` | `src/main.cpp:34` | 使用全局内存池创建账户目录 |
| 6 | 填充 `credentials` | `src/main.cpp:37-40` | 遍历并插入凭据数据 |
| 7 | 填充 `users` | `src/main.cpp:41-44` | 遍历并插入用户数据（含连接数限制） |

### 1.4 Worker 创建阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 8 | 计算 `workers_count` | `src/main.cpp:46` | 根据 CPU 核心数计算工作线程数 |
| 9 | 创建 `workers` 向量 | `src/main.cpp:49-54` | 创建并填充 worker 实例 |

### 1.5 负载均衡器绑定

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 10 | 创建 `bindings` 列表 | `src/main.cpp:56-70` | 为每个 worker 创建分发函数和快照函数 |
| 11 | 创建 `balancer` | `src/main.cpp:72` | 使用绑定列表创建负载均衡器 |
| 12 | 创建 `listener` | `src/main.cpp:73` | 创建监听器实例 |

### 1.6 线程启动阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 13 | 启动 worker 线程 | `src/main.cpp:78-97` | 为每个 worker 启动独立线程运行 `worker.run()` |
| 14 | 启动监听线程 | `src/main.cpp:99-114` | 启动独立线程运行 `listener.listen()` |

---

## 二、连接处理流程

### 2.1 连接接受阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 1 | `listener.listen()` | `src/main.cpp:103` | 监听线程入口 |
| 2 | `net::co_spawn(accept_loop())` | `src/forward-engine/agent/front/listener.cpp:25` | 启动接受连接协程 |
| 3 | `acceptor_.async_accept()` | `src/forward-engine/agent/front/listener.cpp:54` | 异步接受新连接 |

### 2.2 负载均衡阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 4 | `make_affinity()` | `src/forward-engine/agent/front/listener.cpp:29-45` | 根据客户端 IP 计算亲和性哈希 |
| 5 | `balancer.select(affinity)` | `src/forward-engine/agent/front/listener.cpp:65` | 选择目标 worker |
| 6 | 检查 `backpressure` | `src/forward-engine/agent/front/listener.cpp:66-70` | 若过载则延迟 |
| 7 | `balancer.dispatch()` | `src/forward-engine/agent/front/listener.cpp:76` | 分发 socket 到选定 worker |

### 2.3 Worker 分发阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 8 | `worker.dispatch_socket()` | `src/forward-engine/agent/reactor/worker.cpp:41-44` | Worker 接收分发请求 |
| 9 | `launch::dispatch()` | `src/forward-engine/agent/reactor/launch.cpp:55-75` | 投递到 worker 事件循环 |
| 10 | `net::post(ioc, ...)` | `src/forward-engine/agent/reactor/launch.cpp:58` | 跨线程投递到 IO 上下文 |

### 2.4 会话创建阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 11 | `launch::start()` | `src/forward-engine/agent/reactor/launch.cpp:13-53` | 启动会话 |
| 12 | 创建 `inbound` 传输 | `src/forward-engine/agent/reactor/launch.cpp:21` | 包装 socket 为可靠传输 |
| 13 | `make_session()` | `src/forward-engine/agent/reactor/launch.cpp:23` | 创建 session 实例 |
| 14 | `session.start()` | `src/forward-engine/agent/reactor/launch.cpp:46` | 启动会话处理 |

### 2.5 协议检测阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 15 | `session.diversion()` | `src/forward-engine/agent/connection/session.cpp:81-109` | 协议分流入口 |
| 16 | `protocol::sniff::probe()` | `src/forward-engine/agent/connection/session.cpp:89` | 嗅探检测协议类型（预读 24 字节） |
| 17 | `registry::global().create()` | `src/forward-engine/agent/connection/session.cpp:96` | 根据协议类型获取处理器 |

### 2.6 协议处理阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 18 | `handler->process()` | `src/forward-engine/agent/connection/session.cpp:108` | 调用处理器处理协议 |
| 19 | 协议管道处理 | 见下表 | 根据协议类型调用对应管道 |

**协议管道映射表：**

| 协议类型 | 处理器类 | 管道函数 | 源码位置 |
|----------|----------|----------|----------|
| HTTP | `dispatch::Http` | `pipeline::http()` | `include/forward-engine/agent/dispatch/handlers.hpp:82` |
| SOCKS5 | `dispatch::Socks5` | `pipeline::socks5()` | `include/forward-engine/agent/dispatch/handlers.hpp:142` |
| TLS | `dispatch::Tls` | `pipeline::tls()` | `include/forward-engine/agent/dispatch/handlers.hpp:201` |
| Unknown | `dispatch::Unknown` | `primitives::original_tunnel()` | `include/forward-engine/agent/dispatch/handlers.hpp:267` |

### 2.7 上游连接阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 20 | `protocol::analysis::resolve()` | `src/forward-engine/agent/pipeline/protocols.cpp:28` | 解析请求获取目标地址 |
| 21 | `primitives::dial()` | `src/forward-engine/agent/pipeline/primitives.cpp:6-41` | 建立上游连接 |
| 22 | `router->async_reverse()` 或 `router->async_forward()` | `src/forward-engine/agent/pipeline/primitives.cpp:16,22` | 路由选择 |
| 23 | `transport::make_reliable()` | `src/forward-engine/agent/pipeline/primitives.cpp:40` | 包装为可靠传输 |

### 2.8 双向转发阶段

| 步骤 | 操作 | 源码位置 | 说明 |
|------|------|----------|------|
| 24 | `primitives::original_tunnel()` | `include/forward-engine/agent/pipeline/primitives.hpp:170-238` | 建立全双工隧道 |
| 25 | 双向数据转发 | `include/forward-engine/agent/pipeline/primitives.hpp:180-225` | 并发转发双向数据流 |
| 26 | 连接关闭 | `include/forward-engine/agent/pipeline/primitives.hpp:230-237` | 任一方向断开后关闭两端 |

---

## 三、协议处理器注册

当前 `register_handlers()` 函数注册以下四种协议处理器：

| 协议类型 | 枚举值 | 处理器类 | 注册位置 |
|----------|--------|----------|----------|
| HTTP | `protocol_type::http` | `dispatch::Http` | `include/forward-engine/agent/dispatch/handlers.hpp:290` |
| SOCKS5 | `protocol_type::socks5` | `dispatch::Socks5` | `include/forward-engine/agent/dispatch/handlers.hpp:291` |
| TLS | `protocol_type::tls` | `dispatch::Tls` | `include/forward-engine/agent/dispatch/handlers.hpp:292` |
| Unknown | `protocol_type::unknown` | `dispatch::Unknown` | `include/forward-engine/agent/dispatch/handlers.hpp:293` |

**注册函数定义：**
```cpp
inline void register_handlers()
{
    auto &factory = registry::global();
    factory.register_handler<Http>(protocol::protocol_type::http);
    factory.register_handler<Socks5>(protocol::protocol_type::socks5);
    factory.register_handler<Tls>(protocol::protocol_type::tls);
    factory.register_handler<Unknown>(protocol::protocol_type::unknown);
}
```

源码位置：`include/forward-engine/agent/dispatch/handlers.hpp:287-294`

---

## 四、关键数据结构

### 4.1 session_context

会话上下文，贯穿整个连接处理流程：

| 字段 | 类型 | 说明 |
|------|------|------|
| `server` | `server_context&` | 服务器配置上下文 |
| `worker` | `worker_context&` | Worker 运行时上下文 |
| `frame_arena` | `memory::frame_arena&` | 帧内存竞技场 |
| `inbound` | `transport::transmission_pointer` | 入站传输层 |
| `outbound` | `transport::transmission_pointer` | 出站传输层 |
| `buffer_size` | `std::uint32_t` | 缓冲区大小 |

### 4.2 worker_binding

Worker 绑定结构，用于负载均衡器与 Worker 通信：

| 字段 | 类型 | 说明 |
|------|------|------|
| `dispatch` | `std::function<void(tcp::socket)>` | 分发 socket 的函数 |
| `snapshot` | `std::function<worker_load_snapshot()>` | 获取负载快照的函数 |

---

## 五、时序图

```
┌─────────┐     ┌──────────┐     ┌─────────┐     ┌─────────┐     ┌──────────┐
│  main   │     │ listener │     │ balancer│     │ worker  │     │ session  │
└────┬────┘     └────┬─────┘     └────┬────┘     └────┬────┘     └────┬─────┘
     │               │                │               │               │
     │ enable_global_pooling()        │               │               │
     │──────────────────────────────────────────────────────────────────>
     │               │                │               │               │
     │ register_handlers()            │               │               │
     │──────────────────────────────────────────────────────────────────>
     │               │                │               │               │
     │ load(config)  │                │               │               │
     │──────────────────────────────────────────────────────────────────>
     │               │                │               │               │
     │ create workers│                │               │               │
     │               │                │               │               │
     │ create balancer                │               │               │
     │               │                │               │               │
     │ create listener                │               │               │
     │               │                │               │               │
     │ spawn threads │                │               │               │
     │               │                │               │               │
     │               │  accept_loop() │               │               │
     │               │  async_accept()│               │               │
     │               │       │        │               │               │
     │               │       │ select(affinity)       │               │
     │               │       │───────>│               │               │
     │               │       │<───────│               │               │
     │               │       │        │               │               │
     │               │       │ dispatch(socket)       │               │
     │               │       │───────>│               │               │
     │               │       │        │               │               │
     │               │       │        │ dispatch_socket()              │
     │               │       │        │──────────────>│               │
     │               │       │        │               │               │
     │               │       │        │               │ launch::dispatch()
     │               │       │        │               │──────────────>│
     │               │       │        │               │               │
     │               │       │        │               │  start()      │
     │               │       │        │               │  diversion()  │
     │               │       │        │               │  probe()      │
     │               │       │        │               │  create()     │
     │               │       │        │               │  process()    │
     │               │       │        │               │  dial()       │
     │               │       │        │               │  tunnel()     │
     │               │       │        │               │       │       │
     │               │       │        │               │<──────────────│
     │               │       │        │<──────────────│               │
     │               │       │<───────│               │               │
     │               │<──────│        │               │               │
```

---

## 六、备注

1. **内存管理**：所有内存分配均通过内存池进行，避免热路径中的动态分配
2. **协程模型**：整个连接处理流程基于 Boost.Asio 协程实现
3. **线程安全**：Worker 之间通过 `net::post` 进行跨线程通信
4. **负载均衡**：支持基于 IP 亲和性的负载均衡和过载保护
