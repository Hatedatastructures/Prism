# Agent 模块设计

## 1. front 模块
位置：`include/prism/agent/front/`、`src/prism/agent/front/`

### listener
- 职责：监听 TCP 端口、接受入站连接、计算亲和性、分发连接
- 关键实现：
  - 使用独立 `io_context` 运行监听循环
  - `accept_loop()` 协程持续接受连接
  - `make_affinity()` 计算客户端亲和性哈希（IPv4 直接取地址值，IPv6 取高低 64 位异或）
  - 当前绑定 IPv4 + `addressable.port`（不使用 `addressable.host`）
  - 反压机制：当负载均衡器返回反压标志时，延迟 2ms 后继续接受
- 源码：[listener.hpp](../../include/prism/agent/front/listener.hpp)、[listener.cpp](../../src/prism/agent/front/listener.cpp)

### balancer
- 职责：负载均衡、选择最优 worker、反压机制
- 关键实现：
  - 基于评分选择 worker（会话数 60%、待处理数 10%、延迟 30% 三维度加权）
  - 过载检测采用滞后机制（进入阈值 90%，退出阈值 80%）
  - 使用 MurmurHash3 混合函数计算亲和性候选
  - 不直接依赖 `worker::worker` 类型，而是依赖 `worker_binding` 回调绑定
  - 全局反压触发条件：所有 worker 过载 或 最低评分 >= 95%
- 源码：[balancer.hpp](../../include/prism/agent/front/balancer.hpp)、[balancer.cpp](../../src/prism/agent/front/balancer.cpp)

## 2. worker 模块
位置：`include/prism/agent/worker/`、`src/prism/agent/worker/`

### worker
- 职责：工作线程核心，管理事件循环和资源
- 内部资源组合：
  - `io_context`：单线程事件循环
  - `ngx::channel::tcpool`：TCP 连接池
  - `resolve::router`：路由表（来自顶层 `resolve` 模块）
  - `ssl::context`：TLS 上下文（可选）
  - `stats::state`：负载统计
  - `server_context`：服务端全局上下文
  - `worker_context`：worker 线程局部上下文
- 关键实现：
  - `run()` 启动事件循环，同时启动延迟监控协程
  - `dispatch_socket()` 跨线程接收连接，投递到 `io_context`
  - `load_snapshot()` 导出负载快照供负载均衡器使用
  - 构造时解析反向路由规则并设置正向代理端点
- 源码：[worker.hpp](../../include/prism/agent/worker/worker.hpp)、[worker.cpp](../../src/prism/agent/worker/worker.cpp)

### launch
- 职责：会话启动与连接分发
- 关键函数：
  - `prime()`：配置 socket 参数（TCP_NODELAY、缓冲区大小）
  - `start()`：创建会话对象、设置认证回调、启动会话
  - `dispatch()`：跨线程投递 socket 到 worker 事件循环
- 关键实现：
  - 使用 `handoff_push/pop` 跟踪待处理连接数
  - 会话关闭时通过回调递减活跃会话计数
- 源码：[launch.hpp](../../include/prism/agent/worker/launch.hpp)、[launch.cpp](../../src/prism/agent/worker/launch.cpp)

### stats
- 职责：负载统计、EMA 平滑延迟测量
- 关键实现：
  - 活跃会话数：使用 `shared_ptr<atomic<uint32_t>>` 支持跨线程共享
  - 待处理连接数：原子计数器
  - 事件循环延迟：每 250ms 采样一次，预热 16 次后计算抖动基线
  - EMA 平滑：`smoothed = (smoothed * 7 + effective) / 8`
  - 延迟上限 20ms，过滤 1ms 以内的小抖动
- 源码：[stats.hpp](../../include/prism/agent/worker/stats.hpp)、[stats.cpp](../../src/prism/agent/worker/stats.cpp)

### tls
- 职责：TLS 证书配置、SSL 上下文创建
- 关键实现：
  - 加载证书链和私钥文件
  - 启用 GREASE 扩展增加 TLS 指纹随机性
  - 设置 ALPN 协议列表（h2、http/1.1）
  - 若未配置证书则返回空指针，运行明文模式
- 源码：[tls.hpp](../../include/prism/agent/worker/tls.hpp)、[tls.cpp](../../src/prism/agent/worker/tls.cpp)

## 3. session 模块
位置：`include/prism/agent/session/`、`src/prism/agent/session/`

### session
- 职责：单个连接的完整生命周期管理
- 关键实现：
  - 持有 `inbound`/`outbound` transmission
  - 通过 `protocol::probe::probe` 检测协议（预读 24 字节）
  - 从 `dispatch::registry` 获取 handler
  - 通过 `shared_from_this` 实现异步生命周期保活
  - 支持设置凭证验证器和账户目录
  - 关闭时触发 `on_closed` 回调
- 源码：[session.hpp](../../include/prism/agent/session/session.hpp)、[session.cpp](../../src/prism/agent/session/session.cpp)

## 4. dispatch 模块
位置：`include/prism/agent/dispatch/`

**重要：dispatch 是 header-only 层，无 .cpp 文件**

### handler
- 职责：协议处理器抽象基类
- 接口：
  - `process()`：处理协议连接的核心协程方法
  - `type()`：返回支持的协议类型枚举
  - `name()`：返回协议名称字符串
- 源码：[handler.hpp](../../include/prism/agent/dispatch/handler.hpp)

### registry
- 职责：处理器注册表、工厂模式
- 关键实现：
  - 单例模式：通过 `registry::global()` 访问全局实例
  - 模板工厂：`register_handler<Handler>(type, args...)`
  - 处理器单例：工厂内部使用 `static shared_handler` 确保单例
  - 透明查找：支持 `string_view` 异构键查找
- 源码：[handler.hpp](../../include/prism/agent/dispatch/handler.hpp)

### handlers
- 当前已注册的处理器：
  - `Http`：处理 HTTP/1.1 请求，委托给 `pipeline::http`
  - `Socks5`：处理 SOCKS5 协议，委托给 `pipeline::socks5`
  - `Trojan`：处理 Trojan over TLS，委托给 `pipeline::trojan`（内部完成 TLS 握手）
  - `Unknown`：原始 TCP 透传，调用 `primitives::tunnel`
- 注册函数：`register_handlers()` 在程序启动时调用
- 源码：[handlers.hpp](../../include/prism/agent/dispatch/handlers.hpp)

## 5. pipeline 模块
位置：`include/prism/agent/pipeline/`、`src/prism/agent/pipeline/`

### protocols
- HTTP 处理路径：
  1. 解析 HTTP 请求（使用 `beast::basic_flat_buffer` + 内存池分配器）
  2. 通过 `protocol::analysis::resolve` 提取目标
  3. 调用 `primitives::dial` 连接上游
  4. CONNECT 方法：发送 `200 Connection Established` 后进入 `tunnel`
  5. 普通请求：序列化请求转发后进入 `tunnel`
- SOCKS5 处理路径：
  1. 握手协商（支持认证方法选择）
  2. 请求解析（支持 CONNECT、UDP_ASSOCIATE 命令）
  3. CONNECT：连接上游后发送成功响应，进入 `tunnel`
  4. UDP_ASSOCIATE：创建 UDP 中继
- Trojan 处理路径：
  1. 执行 TLS 握手（服务器端）
  2. 解析 Trojan 协议头，验证凭据
  3. 提取目标地址，建立上游连接
  4. 进入 `tunnel` 双向转发
- 源码：[protocols.hpp](../../include/prism/agent/pipeline/protocols.hpp)、[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

### primitives
- `dial()`：拨号连接上游
  - 根据 `target.positive` 标志选择反向路由或正向路由
  - 连接成功后包装为 `reliable` 传输
- `preview`：预读数据回放包装器
  - 继承 `transmission` 接口
  - 优先返回预读数据，耗尽后委托给内部传输
- `tunnel()`：全双工隧道转发
  - 模板函数，支持任意传输类型
  - 使用双缓冲区实现双向转发
  - 任一方向断开即终止隧道
- 源码：[primitives.hpp](../../include/prism/agent/pipeline/primitives.hpp)、[primitives.cpp](../../src/prism/agent/pipeline/primitives.cpp)

## 6. resolve 模块
位置：`include/prism/resolve/`、`src/prism/resolve/`

> **重要**：resolve 已从 `agent/resolve/` 提升为顶层独立模块，命名空间为 `ngx::resolve`。
> Agent 层通过 `worker` 持有 `resolve::router` 成员来使用该模块。

### 模块架构概览

```
┌─────────────────────────────────────────────────────────┐
│                      router                             │  ← 分发层门面（反向/正向/直连/数据报路由）
│  整合 recursor + 反向路由表 + 连接池                      │
├─────────────────────────────────────────────────────────┤
│                     recursor                             │  ← 解析器门面（六阶段查询管道）
│  规则匹配 → 缓存查找 → 请求合并 → 上游查询 → IP过滤 → 存储 │
├──────────┬──────────┬──────────┬────────────────────────┤
│ resolver │  cache   │  rules   │ coalescer              │
│ 四协议查询 │ 正/负缓存 │ 域名规则   │ 请求合并               │
├──────────┴──────────┴──────────┴────────────────────────┤
│                      packet                             │  ← DNS 报文编解码（RFC 1035）
├─────────────────────────────────────────────────────────┤
│                    transparent                           │  ← 透明哈希与相等比较器（FNV-1a）
├─────────────────────────────────────────────────────────┤
│                      config                             │  ← 配置类型（header-only）
└─────────────────────────────────────────────────────────┘
```

### config
- 职责：DNS 解析器全部配置类型，header-only 实现
- 核心类型：
  - `dns_protocol` 枚举：`udp`、`tcp`、`tls`（DoT）、`https`（DoH）
  - `dns_remote` 结构体：上游服务器配置（地址、协议、端口、超时、TLS 选项、DoH 路径）
  - `resolve_mode` 枚举：`fastest`（并发选最快）、`first`（并发选首个成功）、`fallback`（顺序尝试）
  - `address_rule` 结构体：域名 → 静态 IP 映射（支持通配符 `*.xxx.com`）、广告屏蔽标记
  - `cname_rule` 结构体：域名 CNAME 重定向
  - `config` 结构体：聚合以上所有配置，包含缓存参数（容量、TTL、serve-stale）、TTL 钳制范围（ttl_min/ttl_max）、IPv4/IPv6 黑名单
- 地址解析规则：无 scheme 默认 UDP（端口 53）；`tcp://` 端口 53；`tls://` 端口 853；`https://` 端口 443
- 通过 Glaze 库提供 JSON 序列化能力
- 源码：[config.hpp](../../include/prism/resolve/config.hpp)

### packet
- 职责：DNS 报文编解码，完全不依赖系统 resolver（RFC 1035）
- 核心类型：
  - `qtype` 枚举：A(1)、NS(2)、CNAME(5)、SOA(6)、MX(15)、TXT(16)、AAAA(28)、OPT(41)
  - `question` 结构体：DNS 查询段（域名 + 查询类型 + 类别）
  - `record` 结构体：DNS 资源记录（域名 + 类型 + 类别 + TTL + RDATA）
  - `message` 类：完整的 DNS 报文
- 关键方法：
  - `message::pack()`：序列化为 wire format，实现域名压缩指针减少报文体积
  - `message::unpack()`：反序列化 wire format，检测压缩指针循环防止恶意报文
  - `message::make_query()`：构造标准递归查询报文
  - `message::extract_ips()`：从 answer/authority/additional 段提取所有 A/AAAA 记录的 IP
  - `message::min_ttl()`：取所有记录中的最小 TTL，用于缓存 TTL 钳制
- TCP 帧封装：`pack_tcp()` / `unpack_tcp()`，2 字节大端长度前缀 + DNS 报文（RFC 1035 §4.2.2）
- 源码：[packet.hpp](../../include/prism/resolve/packet.hpp)、[packet.cpp](../../src/prism/resolve/packet.cpp)

### resolver
- 职责：异步 DNS 查询客户端，支持四种传输协议
- 核心类型：
  - `resolve_result` 结构体：封装 DNS 响应报文、IP 列表、RTT、来源服务器、错误码
  - `resolver` 类：异步 DNS 解析器
- 关键方法：
  - `resolve(domain, qtype)`：异步解析域名，返回 `awaitable<resolve_result>`
  - `set_servers()` / `set_mode()` / `set_timeout()`：配置上游服务器、查询策略、超时
- 四种查询协议的实现：
  - **UDP**（`query_udp`）：512 字节缓冲区，检测 TC 标志自动回退 TCP（RFC 1035 §4.2.1）
  - **TCP**（`query_tcp`）：2 字节大端长度前缀 + DNS 报文帧格式
  - **DoT**（`query_tls`）：TCP + TLS 层，支持 SNI 设置和证书验证控制（BoringSSL）
  - **DoH**（`query_https`）：TLS + HTTP/1.1 POST（RFC 8484），手动解析 HTTP 响应头提取 Content-Length
- 查询调度策略（`resolve()` 方法）：
  - `fallback`：按顺序逐一尝试上游，首个成功即返回
  - `first`：并发查询所有上游，第一个成功响应即返回
  - `fastest`：并发查询所有上游，选 RTT 最低的成功响应
- 超时机制：每个 I/O 操作使用 `steady_timer` + `||`（Asio awaitable 并行组合）实现超时取消
- 源码：[resolver.hpp](../../include/prism/resolve/resolver.hpp)、[resolver.cpp](../../src/prism/resolve/resolver.cpp)

### recursor
- 职责：高性能 DNS 解析器门面（Facade），替代系统 `getaddrinfo`
- 设计为 per-worker 实例，非线程安全
- 六阶段查询管道（`query_pipeline`）：
  1. **规则匹配**：查域名规则引擎（blocked / negative / 静态 IP / CNAME）
  2. **缓存查找**：命中缓存直接返回（含负缓存和 serve-stale 判断）
  3. **请求合并**：相同查询挂起等待，仅发送一次上游请求（coalescer）
  4. **上游查询**：调用 `resolver` 向上游发请求
  5. **IP 黑名单过滤**：遍历结果列表移除黑名单网段内的 IP
  6. **TTL 钳制 + 缓存存储**：取 min TTL 并 clamp 到 `[ttl_min, ttl_max]` 后写入缓存；查询失败写入负缓存
- 公开接口：
  - `resolve(host)`：并发解析 A + AAAA，合并 IP 列表返回
  - `resolve_tcp(host, port)`：解析到 TCP 端点列表
  - `resolve_udp(host, port)`：解析到 UDP 端点（优先 A 记录，回退 AAAA）
- 源码：[recursor.hpp](../../include/prism/resolve/recursor.hpp)、[recursor.cpp](../../src/prism/resolve/recursor.cpp)

### cache
- 职责：DNS 结果缓存，支持正向缓存和负缓存
- 关键实现：
  - 缓存键格式：`"domain:qtype_num"`（如 `example.com:1`）
  - `get()` 多级判断：未过期正向缓存 → 未过期负缓存 → 过期 + serve-stale → 过期删除
  - `put()` 写入正向缓存，FIFO 淘汰（超过 `max_entries` 时删除最早插入的条目）
  - `put_negative()` 写入负缓存（独立 negative_ttl，默认 30 秒）
  - `evict_expired()` 清理所有过期条目
  - 使用 `transparent_hash` / `transparent_equal` 实现异构键查找
- 非线程安全，设计为 per-worker 实例
- 源码：[cache.hpp](../../include/prism/resolve/cache.hpp)、[cache.cpp](../../src/prism/resolve/cache.cpp)

### rules
- 职责：域名规则引擎，基于反转域名基数树（Trie）实现高效匹配
- 核心类型：
  - `rule_result` 结构体：规则匹配结果（静态 IP 列表、CNAME 目标、广告屏蔽标记、拦截标记）
  - `domain_trie` 类：反转域名基数树
  - `rules_engine` 类：整合地址规则和 CNAME 规则两棵 Trie
- 关键实现：
  - **反转存储**：`www.example.com` 存储为 `com → example → www`，将后缀匹配等价于 Trie 前缀遍历
  - **通配符处理**：`*.example.com` 在 `example` 节点标记 `wildcard`，查询域名至少比通配符多一级标签才匹配
  - **规则优先级**：地址规则优先于 CNAME 规则
- 源码：[rules.hpp](../../include/prism/resolve/rules.hpp)、[rules.cpp](../../src/prism/resolve/rules.cpp)

### coalescer
- 职责：请求合并（Request Coalescing），将同一目标的并发请求合并为单次操作
- 关键实现：
  - `flight` 结构体：跟踪正在进行的请求（键、定时器、等待者计数、完成状态）
  - 使用永不超时的 `steady_timer` 挂起等待协程
  - `find_or_create()`：查找或创建 flight 记录，返回是否为新建
  - 延迟清理：通过 `pending_cleanup` 标记避免迭代器失效，`flush_cleanup()` 在下次请求前执行实际删除
- 非线程安全
- 源码：[coalescer.hpp](../../include/prism/resolve/coalescer.hpp)

### transparent
- 职责：透明哈希与相等比较器，允许 `unordered_map` 中混合使用 `string_view` 和 `memory::string` 查找
- 核心类型：
  - `transparent_hash`：FNV-1a 哈希算法
  - `transparent_equal`：四种混合比较重载（view↔view、string↔view、view↔string、string↔string）
- 被 `cache`、`coalescer`、`router` 广泛复用
- 源码：[transparent.hpp](../../include/prism/resolve/transparent.hpp)

### router
- 职责：分发层路由器顶层门面，整合 DNS 解析器、反向路由表和连接池
- 关键方法：
  - `async_reverse(host)`：反向代理路由，通过反向路由表查找目标端点，从连接池获取
  - `async_direct(ep)`：直连路由，已知端点直接从连接池获取
  - `async_forward(host, port)`：正向转发，DNS 解析后带重试连接（最多 3 次）
  - `async_datagram(host, port)`：UDP 数据报路由，解析目标后创建 UDP socket
  - `resolve_datagram_target(host, port)`：仅解析 UDP 端点，不创建套接字
- 关键实现：
  - 内部持有 `recursor dns_` 成员进行 DNS 解析
  - `reverse_map` 类型：`unordered_map<string, tcp::endpoint>` 支持透明异构查找
  - IPv6 过滤：由 DNS 层统一处理，配置 `dns.disable_ipv6` 后跳过 AAAA 查询
  - `connect_with_retry()`：遍历端点列表最多尝试 3 次，通过连接池获取已建立的 socket
- 源码：[router.hpp](../../include/prism/resolve/router.hpp)、[router.cpp](../../src/prism/resolve/router.cpp)

## 7. multiplex 模块
位置：`include/prism/multiplex/`、src/prism/multiplex/`

> **重要**：multiplex 是多路复用模块，支持 smux 协议（兼容 Mihomo/xtaci/smux v1），
> 通过 Trojan cmd=0x7F 触发。详细文档见 [multiplex.md](multiplex.md)。

### 模块架构概览

```
┌──────────────────────────────────────────────────────────────┐
│                        craft (smux 协议实现)                   │
├──────────────────────────────────────────────────────────────┤
│                         core (抽象基类)                        │
├────────────────────────┬─────────────────────────────────────┤
│      duct (TCP 流)     │         parcel (UDP 数据报)          │
├────────────────────────┴─────────────────────────────────────┤
│                       smux::frame                            │
└──────────────────────────────────────────────────────────────┘
```

### core
- 职责：多路复用核心抽象基类，管理流生命周期和发送串行化
- 流状态：pending（等待地址）、duct（TCP 流）、parcel（UDP 数据报）
- 发送串行化：通过 `send_strand_` 确保帧不会交错写入
- 源码：[core.hpp](../../include/prism/multiplex/core.hpp)、[core.cpp](../../src/prism/multiplex/core.cpp)

### duct
- 职责：TCP 流双向转发管道
- 上行：独立协程 `uplink_loop()` 读 target → mux
- 下行：帧循环直接 `co_await` 写 target，天然反压
- 源码：[duct.hpp](../../include/prism/multiplex/duct.hpp)、[duct.cpp](../../src/prism/multiplex/duct.cpp)

### parcel
- 职责：UDP 数据报中继管道
- 每个 PSH 帧承载 SOCKS5 UDP relay 格式数据报
- 空闲超时自动关闭
- 源码：[parcel.hpp](../../include/prism/multiplex/parcel.hpp)、[parcel.cpp](../../src/prism/multiplex/parcel.cpp)

### smux::craft
- 职责：smux 多路复用会话服务端（兼容 Mihomo/xtaci/smux v1 + sing-mux 协商）
- 帧格式：8 字节定长帧头 [Version][Cmd][Length LE][StreamID LE]
- 协议协商：sing-mux 协议头解析
- 源码：[craft.hpp](../../include/prism/multiplex/smux/craft.hpp)、[craft.cpp](../../src/prism/multiplex/smux/craft.cpp)

### smux::frame
- 职责：smux 帧编解码、地址解析、UDP 数据报构建
- 命令类型：SYN(0x00)、FIN(0x01)、PSH(0x02)、NOP(0x03)
- 源码：[frame.hpp](../../include/prism/multiplex/smux/frame.hpp)、[frame.cpp](../../src/prism/multiplex/smux/frame.cpp)

## 8. account 模块
位置：`include/prism/agent/account/`、`src/prism/agent/account/`

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
- 源码：[directory.hpp](../../include/prism/agent/account/directory.hpp)、[directory.cpp](../../src/prism/agent/account/directory.cpp)

### entry
- 职责：账户运行时状态
- 字段：
  - `max_connections`：最大连接数限制（0 表示无限制）
  - `uplink_bytes`：上行流量统计
  - `downlink_bytes`：下行流量统计
  - `active_connections`：活跃连接数
- 所有统计字段使用原子操作保证线程安全
- 源码：[entry.hpp](../../include/prism/agent/account/entry.hpp)

### lease
- 职责：RAII 连接数管理
- 关键实现：
  - 构造时已递增活跃连接数（由 `try_acquire` 完成）
  - 析构时自动递减活跃连接数
  - 不可拷贝，仅支持移动语义
  - 空租约表示获取失败或已达连接上限
- 源码：[entry.hpp](../../include/prism/agent/account/entry.hpp)
