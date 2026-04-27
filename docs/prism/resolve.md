# Resolve 模块 — DNS 解析门面

## 1. 模块概述

Resolve 模块是 Prism 的 DNS 解析门面，提供完整的七阶段查询管道：域名规范化、规则匹配、缓存查找、请求合并、上游查询、IP 黑名单过滤、TTL 钳制加缓存存储。它将 DNS 解析的复杂性封装为简洁的 `router` 接口，供上层模块通过 `async_forward()` / `async_reverse()` / `async_datagram()` 调用。

### 文件结构

```
include/prism/resolve/
├── router.hpp                # 分发层路由器（顶层门面）
├── dns/
│   ├── dns.hpp               # DNS 解析器抽象接口 + 工厂函数
│   ├── config.hpp            # DNS 配置（servers、mode、cache、rules）
│   ├── upstream.hpp          # 底层 DNS 查询客户端（UDP/TCP/DoT/DoH）
│   └── detail/               # 内部实现（不对外暴露）
│       ├── cache.hpp         # DNS 缓存（正向/负向、serve-stale、LRU）
│       ├── coalescer.hpp     # 请求合并器（并发查询去重）
│       ├── format.hpp        # DNS 报文编解码（RFC 1035）
│       ├── rules.hpp         # 域名规则引擎（反转 Trie）
│       ├── transparent.hpp   # 透明哈希/相等比较器
│       └── utility.hpp       # 工具函数（parse_port 等）

src/prism/resolve/
├── router.cpp                # 路由器实现
└── dns/
    ├── resolver.cpp          # resolver 实现（make_resolver）
    ├── upstream.cpp          # 上游查询客户端实现
    └── detail/
        ├── cache.cpp         # 缓存实现
        ├── format.cpp        # 报文编解码实现
        └── rules.cpp         # 规则引擎实现
```

### 七阶段查询管道

```
// 七阶段查询管道
请求输入
   │
   ▼
阶段 1: 域名规范化
   转小写 + 去末尾点号 (.)
   "WWW.Example.COM." → "www.example.com"

阶段 2: 规则匹配
   反转 Trie 查找
   精确匹配 / 通配符 (*.example.com) / 后缀
   → 命中: 静态地址 / CNAME / 否定规则

阶段 3: 缓存查找 (未命中则继续)
   正向缓存: key="domain:qtype"
   负向缓存: 解析失败标记 (TTL=30s)
   Serve-Stale: 过期数据仍可用 (异步刷新)

阶段 4: 请求合并 (未命中则继续)
   相同 key 的并发查询合并为单次上游请求
   flight.waiters++ → 等待 → 复用结果

阶段 5: 上游查询
   UDP / TCP / DoT / DoH
   策略: fastest / first / fallback
   并发查询多上游 → 选择最佳响应

阶段 6: IP 黑名单过滤
   过滤 IPv4/IPv6 黑名单网段中的结果
   若全部过滤 → 视为解析失败

阶段 7: TTL 钳制 + 缓存存储
   TTL 钳制到 [ttl_min, ttl_max]
   put(key, ips, ttl) 写入缓存
   返回 IP 地址列表
```

---

## 2. 核心类型与类

### 2.1 router (分发层路由器)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/router.hpp` |
| 实现文件 | `src/prism/resolve/router.cpp` |
| 命名空间 | `psm::resolve` |

```
class router
├── pool_                 : connection_pool&        // 共享 TCP 传输源
├── dns_                  : unique_ptr<dns::resolver> // DNS 解析器
├── reverse_map_          : hash_map<tcp::endpoint>   // 反向路由表
├── executor_             : any_io_executor           // 执行器（UDP socket）
├── positive_host_        : optional<memory::string>  // 正向代理主机名
├── positive_port_        : uint16                    // 正向代理端口
├── mr_                   : memory::resource_pointer
├── async_reverse(host)   : pair<fault::code, pooled_connection>  // 反向代理
├── async_direct(ep)      : pair<fault::code, pooled_connection>  // 直连
├── async_forward(host,port): pair<fault::code, pooled_connection>// 正向代理
├── async_datagram(host,port): pair<fault::code, udp::socket>     // 数据报
├── resolve_datagram_target(host,port): pair<fault::code, udp::endpoint>
├── add_reverse_route(host, ep): void               // 添加反向路由
├── set_positive_endpoint(host, port): void          // 设置正向代理端点
├── ipv6_disabled()       : bool                     // 是否禁用 IPv6
├── connect_with_retry(endpoints): pooled_connection // 最多尝试 3 个端点
├── async_positive(host,port): pair<fault::code, pooled_connection>
└── string_hash / string_equal  // 透明哈希/相等比较器
```

### 2.2 dns::resolver (DNS 解析器接口)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/dns.hpp` |
| 实现文件 | `src/prism/resolve/dns/dns.cpp` |
| 命名空间 | `psm::resolve::dns` |

```
class resolver                          // 纯虚抽象接口
├── ~resolver()         : virtual default
├── resolve(host)       : pair<fault::code, vector<ip::address>>
├── resolve_tcp(host,port): pair<fault::code, vector<tcp::endpoint>>
├── resolve_udp(host,port): pair<fault::code, udp::endpoint>
└── ipv6_disabled()     : bool

make_resolver(ioc, cfg, mr) → unique_ptr<resolver>  // 工厂函数
```

### 2.3 dns::upstream (上游查询客户端)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/upstream.hpp` |
| 实现文件 | `src/prism/resolve/dns/upstream.cpp` |
| 命名空间 | `psm::resolve::dns` |

```
struct query_result                       // 单次 DNS 查询结果
├── response              : message       // DNS 响应报文
├── ips                   : vector<ip::address>  // 提取的 IP 列表
├── rtt_ms                : uint64        // 往返时间（毫秒）
├── server_addr           : memory::string       // 响应来源上游标识
└── error                 : fault::code   // 错误码

class upstream
├── ioc_                  : io_context&
├── servers_              : vector<dns_remote>   // 上游服务器列表
├── mode_                 : resolve_mode         // 解析策略
├── timeout_ms_           : uint32               // 默认超时
├── ssl_cache_            : unordered_map<ssl_cache_key, ssl::context>
├── set_servers(servers)  : void
├── set_mode(mode)        : void
├── set_timeout(ms)       : void
├── resolve(domain, qtype): query_result
├── query_udp(server, query): query_result
├── query_tcp(server, query): query_result
├── query_tls(server, query): query_result
├── query_https(server, query): query_result
└── get_ssl_context(server): shared_ptr<ssl::context>
```

### 2.4 detail::cache (DNS 缓存)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/detail/cache.hpp` |
| 实现文件 | `src/prism/resolve/dns/detail/cache.cpp` |
| 命名空间 | `psm::resolve::dns::detail` |

```
struct cache_entry                        // DNS 缓存条目
├── ips                   : vector<ip::address>  // 解析结果
├── ttl                   : uint32        // 原始 TTL（秒）
├── expire                : time_point    // 过期时间
├── inserted              : time_point    // 插入时间（FIFO 淘汰）
└── failed                : bool          // 负缓存标记

class cache
├── mr_                   : memory::resource_pointer
├── default_ttl_          : seconds
├── max_entries_          : size_t
├── serve_stale_          : bool
├── lru_order_            : list<string>  // LRU 访问顺序链表
├── entries_              : unordered_map<string, pair<cache_entry, list::iterator>>
├── get(domain, qtype)    : optional<vector<ip::address>>  // 查找
├── put(domain, qtype, ips, ttl): void    // 写入正向缓存
├── put_negative(domain, qtype, ttl): void // 写入负缓存
├── evict_expired()       : void           // 清理过期条目
├── make_key(domain, qtype): memory::string  // "domain:qtype_number"
└── make_key_view(domain, qtype, buf): string_view  // 零分配键构造
```

### 2.5 detail::coalescer (请求合并器)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/detail/coalescer.hpp` |
| 命名空间 | `psm::resolve::dns::detail` |

```
struct flight                             // 请求合并记录
├── key                   : memory::string   // 查找键
├── timer                 : steady_timer     // 等待定时器（永不超时初始值）
├── waiters               : size_t           // 等待者计数
├── ready                 : bool             // 是否已完成
└── pending_cleanup       : bool             // 是否待清理

class coalescer
├── flights_              : list<flight>     // 请求合并列表
├── flight_map_           : unordered_map<string_view, list::iterator>
├── make_key(host, port)  : memory::string   // "host:port" 格式
├── find_or_create(key, executor): pair<iterator, bool>
├── cleanup_flight(it)    : void             // 标记待清理
└── flush_cleanup()       : void             // 执行延迟清理
```

### 2.6 detail::rules_engine (规则引擎)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/detail/rules.hpp` |
| 实现文件 | `src/prism/resolve/dns/detail/rules.cpp` |
| 命名空间 | `psm::resolve::dns::detail` |

```
struct rule_result                          // 规则匹配结果
├── addresses             : vector<ip::address>  // 静态地址列表
├── cname                 : memory::string       // CNAME 目标域名
├── negative              : bool                 // 否定规则（广告屏蔽）
├── no_cache              : bool                 // 跳过缓存
└── blocked               : bool                 // 被拦截

class domain_trie                           // 反转域名基数树
├── root_                 : unique_ptr<node>
├── mr_                   : memory::resource_pointer
├── insert(domain, value) : void             // 插入规则
├── search(domain)        : optional<any>    // 精确 + 通配符匹配
└── match(domain)         : bool             // 检查是否命中

struct node                                 // Trie 节点
├── children              : unordered_map<string, unique_ptr<node>>
├── value                 : any              // 规则关联值
├── is_end                : bool             // 规则终点标记
└── wildcard              : bool             // 通配符标记

class rules_engine                          // 统一规则引擎
├── address_trie_         : domain_trie      // 地址规则树
├── cname_trie_           : domain_trie      // CNAME 规则树
├── mr_                   : memory::resource_pointer
├── add_address_rule(domain, ips): void
├── add_negative_rule(domain): void
├── add_cname_rule(domain, target): void
└── match(domain)         : optional<rule_result>
```

### 2.7 detail::format (DNS 报文编解码)

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/detail/format.hpp` |
| 实现文件 | `src/prism/resolve/dns/detail/format.cpp` |
| 命名空间 | `psm::resolve::dns::detail` |

```
enum class qtype : uint16                   // DNS 查询类型
├── a = 1                                   // IPv4 地址
├── ns = 2                                  // 名称服务器
├── cname = 5                               // 规范名称
├── soa = 6                                 // 区域起始授权
├── mx = 15                                 // 邮件交换
├── txt = 16                                // 文本记录
├── aaaa = 28                               // IPv6 地址
└── opt = 41                                // EDNS0 选项

struct question                             // DNS 查询段
├── name                  : memory::string  // 域名（小写，无末尾点号）
├── qtype                 : qtype
└── qclass                : uint16 (1 = IN)

struct record                               // DNS 资源记录
├── name                  : memory::string  // 拥有者名称
├── type                  : qtype
├── rclass                : uint16
├── ttl                   : uint32
└── rdata                 : vector<uint8_t> // 原始 RDATA

class message                               // DNS 报文（RFC 1035）
├── id                    : uint16          // 报文标识
├── qr                    : bool            // 0=查询, 1=响应
├── opcode                : uint8           // 操作码
├── aa / tc / rd / ra     : bool            // 标志位
├── rcode                 : uint8           // 响应码
├── questions             : vector<question>
├── answers               : vector<record>
├── authority             : vector<record>
├── additional            : vector<record>
├── pack()                : vector<uint8_t>       // 序列化
├── unpack(data, mr)      : optional<message>     // 反序列化
├── make_query(domain, qtype, mr): message        // 创建查询报文
├── extract_ips()         : vector<ip::address>   // 提取所有 IP
└── min_ttl()             : uint32                // 最小 TTL

pack_tcp(msg) → vector<uint8_t>           // TCP 帧格式（2B 长度前缀）
unpack_tcp(data, mr) → optional<message>  // 从 TCP 帧解析
extract_ipv4(record) → optional<address_v4>
extract_ipv6(record) → optional<address_v6>
```

### 2.8 DNS 配置

| 项目 | 详情 |
|------|------|
| 头文件 | `include/prism/resolve/dns/config.hpp` |
| 命名空间 | `psm::resolve::dns` |

```
enum class dns_protocol : uint8             // 上游协议类型
├── udp                                     // 纯 UDP
├── tcp                                     // TCP
├── tls                                     // DoT (端口 853)
└── https                                   // DoH (端口 443)

struct dns_remote                           // 上游服务器配置
├── address               : memory::string  // 地址字符串
├── protocol              : dns_protocol
├── hostname              : memory::string  // TLS SNI / HTTP Host
├── port                  : uint16
├── timeout_ms            : uint32
├── http_path             : memory::string  // DoH 路径（默认 /dns-query）
└── no_check_certificate  : bool

enum class resolve_mode : uint8             // 解析策略
├── fastest                                 // 并发查询，选 RTT 最低
├── first                                   // 并发查询，返回首个成功
└── fallback                                // 顺序尝试，前一个失败才试下一个

struct address_rule                         // 地址映射规则
├── domain                : memory::string  // 匹配域名（支持 *. 通配符）
├── addresses             : vector<ip::address>
└── negative              : bool            // 否定应答（NXDOMAIN）

struct cname_rule                           // CNAME 重定向规则
├── domain                : memory::string  // 源域名
└── target                : memory::string  // 目标域名

struct config                               // DNS 主配置
├── servers               : vector<dns_remote>
├── mode                  : resolve_mode
├── timeout_ms            : uint32
├── cache_enabled         : bool
├── cache_size            : size_t
├── cache_ttl             : seconds
├── serve_stale           : bool
├── negative_ttl          : seconds
├── ttl_min               : uint32
├── ttl_max               : uint32
├── address_rules         : vector<address_rule>
├── cname_rules           : vector<cname_rule>
├── disable_ipv6          : bool
├── blacklist_v4          : vector<network_v4>
└── blacklist_v6          : vector<network_v6>
```

---

## 3. 架构与组件交互

### 3.1 模块内部架构图

```
// 模块内部架构
router (门面)
   reverse_map_ (主机→端点映射)
   pool_ (connection_pool 共享引用)
   dns::resolver
      rules_engine (反转 Trie)
      │
      cache (LRU + 负缓存)
      │
      coalescer (请求合并)
      │
      upstream (UDP/TCP/DoT/DoH)
```

### 3.2 路由模式

```
// 路由模式
router 接口
   │
   ├─ async_reverse (反向代理)
   │    → reverse_map_ 查找 → pool.acquire
   │
   ├─ async_forward (正向代理)
   │    → dns_.resolve → pool.acquire (需 DNS 解析)
   │
   └─ async_datagram (UDP 数据报)
        → dns_.resolve_udp → open_udp_socket (需 DNS 解析)
```

---

## 4. 完整生命周期流程

### 4.1 async_forward 完整流程序列图

```
// async_forward 完整流程
上层代码 → router: async_forward(host, port)
router → dns::resolver: resolve(host)
   → normalize(host): 转小写 + 去末尾点号
   → rules.match(host): 命中? → 直接返回
   → cache.get(host): 命中 (含 serve-stale)? → 返回
   → coalescer.find(key): 已有请求? → timer.wait() → 复用结果
   → upstream.resolve(): fastest / first / fallback
   → 黑名单过滤 + TTL 钳制
   → cache.put(host, ips, ttl)
   → coalescer.notify_waiters()
router ◄── ips
router: connect_with_retry(ips) → pool.async_acquire(ep)
上层代码 ◄── connection
```

### 4.2 上游查询策略 (fastest / first / fallback)

```
// fastest 模式:
co_await upstream[0], upstream[1], upstream[2]  // 并发所有上游
→ select min(rtt_ms) where success              // 选 RTT 最低的成功响应

// first 模式:
co_await upstream[0], upstream[1], upstream[2]  // 并发所有上游
→ select first where success                    // 返回首个成功响应

// fallback 模式:
upstream[0] → 失败? → upstream[1] → 失败? → upstream[2]  // 顺序逐一尝试
              成功? ✓ 返回
```

### 4.3 请求合并 (Coalescer) 序列图

```
// 请求合并 (Coalescer)
协程 A → coalescer: find_or_create(key)
   → 新创建 → 发起上游查询
协程 B → coalescer: find_or_create(key)
   → 已有请求，waiters++ → timer.wait() (挂起，等待完成)

upstream → 协程 A: result
协程 A → coalescer: notify_waiters() + timer.cancel()
coalescer → 协程 B: 唤醒 → 复用相同结果
coalescer: flush_cleanup()  // 延迟清理
```

---

## 5. 关键算法

### 5.1 反转域名 Trie 匹配

```
// 域名 "www.example.com" 拆分为 ["com", "example", "www"]
// 沿树从根节点逐级查找

search(domain):
    labels = split_and_reverse(domain)  // ["com", "example", "www"]
    node = root
    wildcard_result = null

    for label in labels:
        if node.children[label] exists:
            node = node.children[label]
            if node.wildcard:
                wildcard_result = node.value  // 记录沿途通配符
        else:
            break

    if node.is_end:
        return node.value  // 精确匹配优先
    if wildcard_result:
        return wildcard_result  // 回溯通配符匹配
    return null
```

### 5.2 DNS 缓存 get 逻辑

```
get(domain, qtype):
    key = make_key(domain, qtype)  // "domain:qtype_number"
    if key not in entries_:
        return nullopt

    entry = entries_[key].first
    now = steady_clock::now()

    if entry.expire > now:
        // 未过期
        if entry.failed:
            return empty_vector  // 负缓存命中
        return entry.ips          // 正向缓存命中

    // 已过期
    if serve_stale_:
        return entry.ips  // 返回旧数据，调用方应触发刷新
    else:
        erase(key)
        return nullopt
```

### 5.3 DNS 报文 TCP 帧格式

```
TCP 帧: [Length 2B BE][DNS Message N bytes]

         0                   1                   2                   3
         0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |            Length             |                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         DNS Message           |
        |                                                               |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 5.4 上游查询 (UDP) 流程

```
query_udp(server, query):
    start_timer = now()
    socket = udp::socket(ioc_)
    query_msg = query.pack()
    socket.send_to(query_msg, server.endpoint)

    response = co_await socket.receive(timeout=server.timeout_ms)
    rtt = now() - start_timer

    msg = message.unpack(response)
    if not msg:
        return {error: decode_error}

    result.ips = msg.extract_ips()
    result.rtt_ms = rtt
    result.response = msg
    return result
```

---

## 6. 依赖关系

### 6.1 Resolve 模块向外依赖

```
resolve 模块
├── memory (PMR 分配器, container, pool)
├── fault::code (错误码体系)
├── channel::connection_pool (TCP 连接池，用于 router)
└── boost::asio (网络异步原语, SSL)
```

### 6.2 外部模块对 Resolve 的依赖

```
agent::worker ───────────────► router (构造时传入)
agent::session ──────────────► 通过 session_context.worker.router 访问
pipeline::primitives ────────► router (通过 ctx.worker.router)
multiplex::bootstrap ────────► router (地址解析)
multiplex::duct/parcel ──────► 通过 core::router_ 访问
```

---

## 7. 配置参数

### 7.1 DNS 配置项 (JSON)

```json
{
  "dns": {
    "servers": [
      {
        "address": "8.8.8.8",
        "protocol": "udp",
        "port": 53,
        "timeout_ms": 5000
      },
      {
        "address": "1.1.1.1",
        "protocol": "udp",
        "port": 53
      },
      {
        "address": "dns.google",
        "protocol": "https",
        "hostname": "dns.google",
        "http_path": "/dns-query",
        "port": 443
      }
    ],
    "mode": "fastest",
    "timeout_ms": 5000,
    "cache_enabled": true,
    "cache_size": 10000,
    "cache_ttl": 120,
    "serve_stale": true,
    "negative_ttl": 300,
    "ttl_min": 60,
    "ttl_max": 86400,
    "address_rules": [
      {
        "domain": "blocked.example.com",
        "negative": true
      }
    ],
    "cname_rules": [],
    "disable_ipv6": false
  }
}
```

### 7.2 参数详解

| 参数 | 默认值 | 含义 |
|------|--------|------|
| `servers` | `[]` | 上游 DNS 服务器列表 |
| `mode` | `fastest` | 解析策略（fastest/first/fallback） |
| `timeout_ms` | 5000 | 全局超时（毫秒） |
| `cache_enabled` | `true` | 是否启用 DNS 缓存 |
| `cache_size` | 10000 | 缓存最大条目数 |
| `cache_ttl` | 120 | 默认缓存 TTL（秒） |
| `serve_stale` | `true` | 过期后是否仍返回旧数据 |
| `negative_ttl` | 300 | 负缓存 TTL（秒） |
| `ttl_min` | 60 | 最小 TTL（秒） |
| `ttl_max` | 86400 | 最大 TTL（秒） |
| `disable_ipv6` | `false` | 是否禁用 IPv6 |
