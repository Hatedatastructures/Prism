# Agent 模块设计

## 1. front 模块
位置：`include/forward-engine/agent/front/`、`src/forward-engine/agent/front/`

### listener
- 职责：监听 TCP 端口、接受入站连接、计算亲和性、分发连接
- 关键实现：
  - 使用独立 `io_context` 运行监听循环
  - `accept_loop()` 协程持续接受连接
  - `make_affinity()` 计算客户端亲和性哈希（IPv4 直接取地址值，IPv6 取高低 64 位异或）
  - 当前绑定 IPv4 + `addressable.port`（不使用 `addressable.host`）
  - 反压机制：当负载均衡器返回反压标志时，延迟 2ms 后继续接受
- 源码：[listener.hpp](../../include/forward-engine/agent/front/listener.hpp)、[listener.cpp](../../src/forward-engine/agent/front/listener.cpp)

### balancer
- 职责：负载均衡、选择最优 worker、反压机制
- 关键实现：
  - 基于评分选择 worker（会话数 60%、待处理数 10%、延迟 30% 三维度加权）
  - 过载检测采用滞后机制（进入阈值 90%，退出阈值 80%）
  - 使用 MurmurHash3 混合函数计算亲和性候选
  - 不直接依赖 `worker::worker` 类型，而是依赖 `worker_binding` 回调绑定
  - 全局反压触发条件：所有 worker 过载 或 最低评分 >= 95%
- 源码：[balancer.hpp](../../include/forward-engine/agent/front/balancer.hpp)、[balancer.cpp](../../src/forward-engine/agent/front/balancer.cpp)

## 2. worker 模块
位置：`include/forward-engine/agent/worker/`、`src/forward-engine/agent/worker/`

### worker
- 职责：工作线程核心，管理事件循环和资源
- 内部资源组合：
  - `io_context`：单线程事件循环
  - `ngx::channel::tcpool`：TCP 连接池
  - `resolve::router`：路由表
  - `ssl::context`：TLS 上下文（可选）
  - `stats::state`：负载统计
  - `server_context`：服务端全局上下文
  - `worker_context`：worker 线程局部上下文
- 关键实现：
  - `run()` 启动事件循环，同时启动延迟监控协程
  - `dispatch_socket()` 跨线程接收连接，投递到 `io_context`
  - `load_snapshot()` 导出负载快照供负载均衡器使用
  - 构造时解析反向路由规则并设置正向代理端点
- 源码：[worker.hpp](../../include/forward-engine/agent/worker/worker.hpp)、[worker.cpp](../../src/forward-engine/agent/worker/worker.cpp)

### launch
- 职责：会话启动与连接分发
- 关键函数：
  - `prime()`：配置 socket 参数（TCP_NODELAY、缓冲区大小）
  - `start()`：创建会话对象、设置认证回调、启动会话
  - `dispatch()`：跨线程投递 socket 到 worker 事件循环
- 关键实现：
  - 使用 `handoff_push/pop` 跟踪待处理连接数
  - 会话关闭时通过回调递减活跃会话计数
- 源码：[launch.hpp](../../include/forward-engine/agent/worker/launch.hpp)、[launch.cpp](../../src/forward-engine/agent/worker/launch.cpp)

### stats
- 职责：负载统计、EMA 平滑延迟测量
- 关键实现：
  - 活跃会话数：使用 `shared_ptr<atomic<uint32_t>>` 支持跨线程共享
  - 待处理连接数：原子计数器
  - 事件循环延迟：每 250ms 采样一次，预热 16 次后计算抖动基线
  - EMA 平滑：`smoothed = (smoothed * 7 + effective) / 8`
  - 延迟上限 20ms，过滤 1ms 以内的小抖动
- 源码：[stats.hpp](../../include/forward-engine/agent/worker/stats.hpp)、[stats.cpp](../../src/forward-engine/agent/worker/stats.cpp)

### tls
- 职责：TLS 证书配置、SSL 上下文创建
- 关键实现：
  - 加载证书链和私钥文件
  - 启用 GREASE 扩展增加 TLS 指纹随机性
  - 设置 ALPN 协议列表（h2、http/1.1）
  - 若未配置证书则返回空指针，运行明文模式
- 源码：[tls.hpp](../../include/forward-engine/agent/worker/tls.hpp)、[tls.cpp](../../src/forward-engine/agent/worker/tls.cpp)

## 3. session 模块
位置：`include/forward-engine/agent/session/`、`src/forward-engine/agent/session/`

### session
- 职责：单个连接的完整生命周期管理
- 关键实现：
  - 持有 `inbound`/`outbound` transmission
  - 通过 `protocol::probe::probe` 检测协议（预读 24 字节）
  - 从 `dispatch::registry` 获取 handler
  - 通过 `shared_from_this` 实现异步生命周期保活
  - 支持设置凭证验证器和账户目录
  - 关闭时触发 `on_closed` 回调
- 源码：[session.hpp](../../include/forward-engine/agent/session/session.hpp)、[session.cpp](../../src/forward-engine/agent/session/session.cpp)

## 4. dispatch 模块
位置：`include/forward-engine/agent/dispatch/`

**重要：dispatch 是 header-only 层，无 .cpp 文件**

### handler
- 职责：协议处理器抽象基类
- 接口：
  - `process()`：处理协议连接的核心协程方法
  - `type()`：返回支持的协议类型枚举
  - `name()`：返回协议名称字符串
- 源码：[handler.hpp](../../include/forward-engine/agent/dispatch/handler.hpp)

### registry
- 职责：处理器注册表、工厂模式
- 关键实现：
  - 单例模式：通过 `registry::global()` 访问全局实例
  - 模板工厂：`register_handler<Handler>(type, args...)`
  - 处理器单例：工厂内部使用 `static shared_handler` 确保单例
  - 透明查找：支持 `string_view` 异构键查找
- 源码：[handler.hpp](../../include/forward-engine/agent/dispatch/handler.hpp)

### handlers
- 当前已注册的处理器：
  - `Http`：处理 HTTP/1.1 请求，委托给 `pipeline::http`
  - `Socks5`：处理 SOCKS5 协议，委托给 `pipeline::socks5`
  - `Tls`：处理 TLS 握手，委托给 `pipeline::tls`
  - `Unknown`：原始 TCP 透传，调用 `primitives::original_tunnel`
- 注册函数：`register_handlers()` 在程序启动时调用
- 源码：[handlers.hpp](../../include/forward-engine/agent/dispatch/handlers.hpp)

## 5. pipeline 模块
位置：`include/forward-engine/agent/pipeline/`、`src/forward-engine/agent/pipeline/`

### protocols
- HTTP 处理路径：
  1. 解析 HTTP 请求（使用 `beast::basic_flat_buffer` + 内存池分配器）
  2. 通过 `protocol::analysis::resolve` 提取目标
  3. 调用 `primitives::dial` 连接上游
  4. CONNECT 方法：发送 `200 Connection Established` 后进入 `original_tunnel`
  5. 普通请求：序列化请求转发后进入 `original_tunnel`
- SOCKS5 处理路径：
  1. 握手协商（支持认证方法选择）
  2. 请求解析（支持 CONNECT、UDP_ASSOCIATE 命令）
  3. CONNECT：连接上游后发送成功响应，进入 `original_tunnel`
  4. UDP_ASSOCIATE：创建 UDP 中继
- TLS 处理路径：
  1. 执行 TLS 握手（服务器端）
  2. 解密后作为 HTTP 请求解析
  3. 后续流程同 HTTP 处理路径
- 源码：[protocols.hpp](../../include/forward-engine/agent/pipeline/protocols.hpp)、[protocols.cpp](../../src/forward-engine/agent/pipeline/protocols.cpp)

### primitives
- `dial()`：拨号连接上游
  - 根据 `target.positive` 标志选择反向路由或正向路由
  - 连接成功后包装为 `reliable` 传输
- `preview`：预读数据回放包装器
  - 继承 `transmission` 接口
  - 优先返回预读数据，耗尽后委托给内部传输
- `original_tunnel()`：全双工隧道转发
  - 模板函数，支持任意传输类型
  - 使用双缓冲区实现双向转发
  - 任一方向断开即终止隧道
- 源码：[primitives.hpp](../../include/forward-engine/agent/pipeline/primitives.hpp)、[primitives.cpp](../../src/forward-engine/agent/pipeline/primitives.cpp)

## 6. resolve 模块
位置：`include/forward-engine/agent/resolve/`、`src/forward-engine/agent/resolve/`

### router
- 职责：统一路由入口，整合子组件
- 关键方法：
  - `async_reverse()`：反向代理路由，通过 arbiter 查找路由表
  - `async_direct()`：直连端点路由，直接通过连接池获取
  - `async_forward()`：正向代理路由，**先直连后 fallback 到 positive endpoint**
  - `async_datagram()`：数据报路由，通过 arbiter 解析目标
  - `resolve_datagram_target()`：仅解析 UDP 端点，不创建套接字
- 关键实现：
  - 黑名单过滤在 `async_forward` 入口处检查
  - `async_positive` 发送 CONNECT 请求到上游代理
- 源码：[router.hpp](../../include/forward-engine/agent/resolve/router.hpp)、[router.cpp](../../src/forward-engine/agent/resolve/router.cpp)

### arbiter
- 职责：反向路由、直连路由、数据报路由
- 关键实现：
  - 无状态协调器，所有依赖通过引用注入
  - 使用透明哈希和相等比较器支持异构键查找
  - `reverse_map` 类型：`unordered_map<string, tcp::endpoint, transparent_hash, transparent_equal>`
- 源码：[arbiter.hpp](../../include/forward-engine/agent/resolve/arbiter.hpp)

### tcpcache
- 职责：TCP DNS 解析、缓存、请求合并
- 关键实现：
  - 两级优化：缓存命中 -> 请求合并 -> 发起 DNS 解析
  - 缓存 TTL 默认 120 秒，最大条目 10000
  - FIFO 淘汰策略
  - 连接失败时清除对应缓存记录
- 源码：[tcpcache.hpp](../../include/forward-engine/agent/resolve/tcpcache.hpp)、[tcpcache.cpp](../../src/forward-engine/agent/resolve/tcpcache.cpp)

### udpcache
- 职责：UDP DNS 解析、缓存
- 关键实现：
  - 与 `tcpcache` 类似的缓存和请求合并机制
  - 仅存储单个端点（UDP 场景通常不需要尝试多个地址）
  - 缓存 TTL 默认 120 秒，最大条目 4096
- 源码：[udpcache.hpp](../../include/forward-engine/agent/resolve/udpcache.hpp)、[udpcache.cpp](../../src/forward-engine/agent/resolve/udpcache.cpp)

### coalescer
- 职责：请求合并机制
- 关键实现：
  - `flight` 结构体：跟踪正在进行的请求
  - 使用永不超时的定时器挂起等待协程
  - 延迟清理：通过 `pending_cleanup` 标记避免迭代器失效
  - `flush_cleanup()` 在下一次请求开始前执行实际删除
- 源码：[coalescer.hpp](../../include/forward-engine/agent/resolve/coalescer.hpp)

## 7. account 模块
位置：`include/forward-engine/agent/account/`、`src/forward-engine/agent/account/`

### directory
- 职责：账户目录管理
- 关键设计：
  - Copy-on-Write + atomic `shared_ptr` 实现无锁读取
  - 写操作复制整个映射表，CAS 原子替换
  - 透明查找：支持 `string_view` 异构键查找
  - 适用于读多写少的账户配置场景
- 关键函数：
  - `upsert()`：插入或更新账户条目
  - `find()`：无锁查找，返回 `shared_ptr<entry>`
  - `try_acquire()`：尝试获取连接租约
- 源码：[directory.hpp](../../include/forward-engine/agent/account/directory.hpp)、[directory.cpp](../../src/forward-engine/agent/account/directory.cpp)

### entry
- 职责：账户运行时状态
- 字段：
  - `max_connections`：最大连接数限制（0 表示无限制）
  - `uplink_bytes`：上行流量统计
  - `downlink_bytes`：下行流量统计
  - `active_connections`：活跃连接数
- 所有统计字段使用原子操作保证线程安全
- 源码：[entry.hpp](../../include/forward-engine/agent/account/entry.hpp)

### lease
- 职责：RAII 连接数管理
- 关键实现：
  - 构造时已递增活跃连接数（由 `try_acquire` 完成）
  - 析构时自动递减活跃连接数
  - 不可拷贝，仅支持移动语义
  - 空租约表示获取失败或已达连接上限
- 源码：[entry.hpp](../../include/forward-engine/agent/account/entry.hpp)
