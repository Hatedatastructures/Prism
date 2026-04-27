# Channel 模块 — 传输层抽象

## 1. 模块概述

Channel 模块是 Prism 的传输层抽象基础设施，提供统一的流式传输接口、连接复用池和 Happy Eyeballs 并发竞速。它将具体的传输介质（TCP、UDP、TLS）统一为 `transmission` 抽象，使上层代码（pipeline、multiplex）无需感知底层传输细节。

### 文件结构

```
include/prism/channel/
├── transport/
│   ├── transmission.hpp        # 传输抽象接口（纯虚基类）
│   ├── reliable.hpp            # 可靠传输（TCP socket 包装，header-only）
│   ├── encrypted.hpp           # 加密传输（TLS stream 装饰器，header-only）
│   └── unreliable.hpp          # 不可靠传输（UDP socket 包装，header-only）
├── connection/
│   └── pool.hpp                # TCP 连接池（含 config 结构体定义）
├── adapter/
│   └── connector.hpp           # Socket 适配器（支持预读数据注入）
├── health.hpp                  # 健康检测接口
└── eyeball/
    └── racer.hpp               # Happy Eyeballs RFC 8305 竞速器

src/prism/channel/
├── connection/
│   └── pool.cpp                # 连接池实现
├── health.cpp                  # 健康检测实现
└── eyeball/
    └── racer.cpp               # 竞速器实现
```

**注意**：`transport/` 下的三个传输实现（reliable/encrypted/unreliable）均为 header-only，无对应 `.cpp` 文件。连接池配置结构体 `config` 定义在 `pool.hpp` 中，而非独立的 `config.hpp`。

### 设计哲学

```
transmission（抽象接口）
    │
    ├── reliable（TCP 流 — 有序、可靠）
    ├── encrypted（TLS 装饰 — 加密、有序）
    └── unreliable（UDP 数据报 — 无序、不可靠）
```

所有具体实现均继承 `transmission` 纯虚基类，通过 `shared_transmission`（即 `shared_ptr<transmission>`）管理生命周期，支持装饰器模式嵌套。隧道转发由 `pipeline::primitives::tunnel()` 实现。

---

## 2. 核心类型与类

### 2.1 transmission (传输抽象接口)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/channel/transport/transmission.hpp` |
| 命名空间 | `psm::channel::transport` |

```
class transmission                          // 纯虚基类
├── executor_type         : any_io_executor  // 关联执行器类型
├── is_reliable()         : bool             // 标识是否可靠传输（TCP 返回 true）
├── executor()            : executor_type    // 获取关联执行器（纯虚）
├── get_executor()        : executor_type    // executor() 别名，兼容 Asio Concept
├── async_read_some(buf, ec) : awaitable<size_t>  // 异步读取（纯虚）
├── async_write_some(buf, ec): awaitable<size_t>  // 异步写入（纯虚）
├── shutdown_write()      : void             // 半关闭写端（默认空实现）
├── close()               : void             // 关闭传输层（纯虚）
├── cancel()              : void             // 取消所有挂起操作（纯虚）
├── async_write(buf, ec)  : awaitable<size_t>  // 完整写入（循环调用 write_some）
├── async_write_scatter(bufs, count, ec): awaitable<size_t>  // scatter-gather 写入
└── async_read(buf, ec)   : awaitable<size_t>  // 完整读取（循环调用 read_some）

using shared_transmission = shared_ptr<transmission>
```

**默认实现行为:**

| 方法 | 默认行为 | 子类覆盖情况 |
|------|----------|-------------|
| `is_reliable()` | 返回 `false` | reliable/encrypted 覆盖为 `true` |
| `shutdown_write()` | 空操作 | reliable 覆盖以调用 socket shutdown |
| `async_write()` | 循环 `async_write_some` 直到完成 | unreliable 覆盖（单次写入） |
| `async_write_scatter()` | 逐个写入每个缓冲区 | 可被原生 scatter-gather I/O 优化 |
| `async_read()` | 循环 `async_read_some` 直到填满 | 可被子类优化 |

### 2.2 pooled_connection (连接池 RAII 包装)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/channel/connection/pool.hpp` |
| 实现文件 | `src/prism/channel/connection/pool.cpp` |
| 命名空间 | `psm::channel` |

```
struct endpoint_key                       // 端点键（缓存 Key）
├── port                : uint16          // 端口号
├── family              : uint8           // 协议族：4=IPv4, 6=IPv6
├── address             : array<uchar,16> // IP 地址（IPv4 使用前 4 字节）
└── operator==          : default         // 默认比较

struct endpoint_hash                      // FNV-1a 变体哈希
└── operator()(key)     : size_t

struct config                             // 连接池配置
├── max_cache_per_endpoint : 32           // 单端点最大缓存连接数
├── connect_timeout_ms     : 300          // 连接超时（毫秒）
├── max_idle_seconds       : 30           // 空闲连接最大存活时间（秒）
├── cleanup_interval_sec   : 10           // 后台清理间隔（秒）
├── recv_buffer_size       : 65536        // 接收缓冲区大小
├── send_buffer_size       : 65536        // 发送缓冲区大小
├── tcp_nodelay            : true         // 启用 TCP_NODELAY
├── keep_alive             : true         // 启用 SO_KEEPALIVE
└── cache_ipv6             : false        // 是否缓存 IPv6 连接

class pooled_connection                   // RAII 连接包装（内联存储，零堆分配）
├── pool_                 : connection_pool*  // 关联连接池
├── socket_               : tcp::socket*      // 持有的 socket 指针
├── endpoint_             : tcp::endpoint     // 目标端点
├── get()                 : socket*           // 获取 socket 指针
├── operator* / ->        : socket& / *       // 解引用操作符
├── valid() / operator bool : bool            // 有效性检查
├── release()             : socket*           // 释放所有权（不归还）
├── reset()               : void              // 归还或关闭连接
└── 析构函数              : 自动调用 reset()

class connection_pool                     // TCP 连接池
├── ioc_                  : io_context&     // IO 上下文
├── cache_                : unordered_map<endpoint_key, vector<idle_item>>
├── config_               : config          // 连接池配置
├── cleanup_timer_        : optional<steady_timer>
├── shutdown_flag_        : shared_ptr<atomic<bool>>
├── async_acquire(ep)     : pair<fault::code, pooled_connection>
├── recycle(sock, ep)     : void            // 归还连接（内部接口）
├── start()               : void            // 启动后台清理
├── stats()               : pool_stats      // 统计快照
├── config()              : const config&   // 获取配置
├── clear()               : void            // 清理所有缓存
└── cleanup()             : void            // 移除过期连接
```

### 2.3 address_racer (Happy Eyeballs 竞速器)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/channel/eyeball/racer.hpp` |
| 实现文件 | `src/prism/channel/eyeball/racer.cpp` |
| 命名空间 | `psm::channel::eyeball` |

```
class address_racer
├── pool_                 : connection_pool&  // 连接池引用（不拥有）
├── secondary_delay       : 250ms             // RFC 8305 建议值
├── race(endpoints)       : pooled_connection // 并发竞速连接
└── race_endpoint(ep, delay, ctx): void      // 单端点竞速协程
```

---

## 3. 架构与组件交互

### 3.1 传输层装饰器模式

```
// 传输层装饰器模式
encrypted::transmission (TLS 装饰器)
   → 包装 ssl::stream<...>
   → 包装 reliable::transmission (TCP socket)
        → 包装 tcp::socket

// 外部通过 shared_transmission 接口访问，无需关心嵌套层级:
// shared_transmission → 可能是 plain TCP / TLS-wrapped / 其他
```

### 3.2 连接池架构

```
connection_pool (每 worker 一个，线程局部)
    │
    ├── cache_ (unordered_map<endpoint_key, LIFO stack>)
    │   ├── endpoint_key("1.2.3.4:443") → [idle_item3, idle_item2, idle_item1]
    │   ├── endpoint_key("5.6.7.8:80")  → [idle_item2, idle_item1]
    │   └── ...
    │
    ├── cleanup_timer_ (周期性定时器)
    │   └── cleanup() → 移除超过 max_idle_seconds 的连接
    │
    └── 统计计数器 (acquires / hits / creates / recycles / evictions)

acquire(endpoint) 流程:
    1. 查找 cache_[endpoint]
    2. LIFO 弹栈 → 检查过期 → 健康检测
    3. 若复用失败或缓存为空 → 新建连接（co_spawn + timer 超时）
    4. 新建连接设置 TCP_NODELAY / SO_KEEPALIVE

pooled_connection 析构:
    1. reset() → recycle(socket, endpoint)
    2. recycle: IPv6 过滤 → 健康检测 → 容量检查
    3. 满足条件则入栈，否则关闭
```

### 3.3 Happy Eyeballs (RFC 8305)

```
// Happy Eyeballs (RFC 8305)
DNS 返回多个 IP 地址: [IPv6-1, IPv6-2, IPv4-1, IPv4-2]
   │
   ▼
race() 核心算法:
   endpoint[0] ──────────────────► 立即连接
   endpoint[1] ── 250ms delay ──► 连接
   endpoint[2] ── 500ms delay ──► 连接
   endpoint[3] ── 750ms delay ──► 连接

   第一个成功的连接 wins
   其余连接被取消
   单端点时直接连接（无延迟）
```

---

## 4. 完整生命周期流程

### 4.1 连接获取到归还序列图

```
// 连接获取到归还
上层代码 → connection_pool: async_acquire(ep)
connection_pool: 查找 cache_[ep]
   if hit:
       LIFO 弹栈 → 过期检查 → 健康检测 (发送小数据测活)
       返回 pooled_conn
   else:
       co_spawn + timer → connect → SYN/ACK → TCP_NODELAY / SO_KEEPALIVE
       返回 pooled_conn

上层代码: 使用 conn.get() 进行 I/O 操作
上层代码: 析构 / 显式 reset()
   → recycle(socket, endpoint)
   → 健康检测 → 容量检查 → 入栈到 cache_[ep]
```

### 4.2 Happy Eyeballs 竞速序列图

```
// Happy Eyeballs 竞速
上层代码 → address_racer: race([ep0, ep1])
address_racer → connection_pool: co_spawn race_endpoint(ep0, delay=0ms)
   → connect(ep0)
address_racer: 定时器 250ms
address_racer → connection_pool: co_spawn race_endpoint(ep1, delay=250ms)
   → connect(ep1)

// 假设 ep1 先成功:
address_racer ◄── winner (ep1) ──── connection_pool
address_racer: cancel all other endpoints
   → cancel(ep0)
上层代码 ◄── pooled_conn
```

### 4.3 tunnel 双向透明转发

```
// tunnel 双向透明转发
// 两端独立协程，互不阻塞
// 任一端 EOF → 两端关闭

协程 A (inbound → outbound):
   inbound.async_read_some → 数据 → outbound.async_write_some

协程 B (outbound → inbound):
   outbound.async_read_some → 数据 → inbound.async_write_some
```

### 4.4 后台清理循环

```
// 后台清理循环
connection_pool.start()
   → cleanup_loop()
        while active:
            timer.expires_after(cleanup_interval)
            co_await timer.wait()
            cleanup()
                for each (endpoint, idle_stack):
                    原地压缩: 移除过期 idle_item
                    if stack empty: erase endpoint
```

---

## 5. 关键算法

### 5.1 传输层 async_write 完整写入

```
async_write(buffer, ec) → awaitable<size_t>:
    total_written = 0
    while total_written < buffer.size():
        remaining = buffer.subspan(total_written)
        n = co_await async_write_some(remaining, ec)
        if ec or n == 0:
            return total_written  // 部分写入
        total_written += n
    return total_written
```

### 5.2 连接池 acquire 流程

```
async_acquire(endpoint) → pair<fault::code, pooled_connection>:
    key = make_endpoint_key(endpoint)

    // 1. 缓存复用
    if stack = cache_[key] and stack not empty:
        while stack not empty:
            item = stack.pop_back()  // LIFO 弹栈
            if item.last_used + max_idle_seconds < now:
                close(item.socket)   // 过期，关闭
                stat_evictions++
                continue
            if not health_check(item.socket):
                close(item.socket)   // 不健康，关闭
                stat_evictions++
                continue
            stat_hits++
            return pooled_connection(this, item.socket, endpoint)

    // 2. 新建连接
    stat_creates++
    socket = create_new_socket(endpoint, connect_timeout_ms)
    if socket failed:
        return (fault::code::bad_gateway, empty)
    set TCP_NODELAY, SO_KEEPALIVE, buffer sizes
    return pooled_connection(this, socket, endpoint)
```

### 5.3 recycle 回收流程

```
recycle(socket, endpoint):
    stat_recycles++

    if config.cache_ipv6 == false:
        if endpoint.address.is_v6():
            close(socket)  // 不缓存 IPv6
            return

    if not health_check(socket):
        close(socket)
        stat_evictions++
        return

    key = make_endpoint_key(endpoint)
    stack = cache_[key]
    if stack.size >= max_cache_per_endpoint:
        close(socket)      // 容量已满
        stat_evictions++
        return

    stack.push_back({socket, now()})  // 入栈复用
    stat_idle++
```

### 5.4 Happy Eyeballs 核心算法

```
race(endpoints[]) → pooled_connection:
    if endpoints.size == 1:
        return pool.async_acquire(endpoints[0])  // 直接连接

    ctx = shared race_context  // 共享竞速状态
    winner = null (atomic)

    for i = 0 to endpoints.size - 1:
        delay = 250ms * i
        co_spawn(race_endpoint(endpoints[i], delay, ctx))

    // 等待 winner 产生或全部失败
    co_await wait_for_winner_or_all_done(ctx)
    return ctx.winner
```

---

## 6. 依赖关系

### 6.1 Channel 模块向外依赖

```
channel 模块
├── memory (PMR 分配器, container, pool)
├── fault::code / fault::compatible (错误码体系)
└── boost::asio (网络异步原语)
```

### 6.2 外部模块对 Channel 的依赖

```
agent::worker ───────────────► connection_pool (每 worker 一个)
agent::session ──────────────► shared_transmission (入站/出站)
resolve::router ─────────────► connection_pool (async_direct/async_forward)
pipeline::primitives::tunnel ─► transmission (双向转发)
multiplex::duct ─────────────► transmission (target 传输层)
multiplex::parcel ───────────► shared_transmission (不直接依赖，通过 router)
```

---

## 7. 配置参数

### 7.1 连接池配置

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `max_cache_per_endpoint` | 32 | 单个目标端点最大缓存连接数 |
| `connect_timeout_ms` | 300 | 新建连接超时（毫秒） |
| `max_idle_seconds` | 30 | 空闲连接最大存活时间（秒） |
| `cleanup_interval_sec` | 10 | 后台清理间隔（秒） |
| `recv_buffer_size` | 65536 | 接收缓冲区大小（字节） |
| `send_buffer_size` | 65536 | 发送缓冲区大小（字节） |
| `tcp_nodelay` | true | 是否启用 TCP_NODELAY（禁用 Nagle） |
| `keep_alive` | true | 是否启用 SO_KEEPALIVE |
| `cache_ipv6` | false | 是否缓存 IPv6 连接 |

### 7.2 Happy Eyeballs 参数

| 参数 | 值 | 含义 |
|------|-----|------|
| `secondary_delay` | 250ms | 后续端点启动延迟（RFC 8305 建议值） |
