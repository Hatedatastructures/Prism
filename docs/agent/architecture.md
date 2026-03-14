# Forward-Engine 架构能力分析

本文档明确区分三类能力：源码已实现的能力、仅配置声明但未接入的能力、源码声明但运行链未接入的能力。

---

## 一、源码已实现的能力

基于运行链确认已实现的功能，所有结论均有源码位置引用。

### 1. HTTP/HTTPS 代理

**CONNECT 方法（隧道代理）**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 处理流程：解析 HTTP 请求后，对 CONNECT 方法返回 `HTTP/1.1 200 Connection Established`，随后建立双向隧道

**普通 HTTP 请求转发**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 处理流程：序列化请求并转发到上游，同时转发预读缓冲区中的剩余数据

**Handler 注册**：
- 注册位置：[handlers.hpp](include/forward-engine/agent/dispatch/handlers.hpp)
- `register_handlers()` 中注册 `Http` 处理器到 `protocol_type::http`

### 2. SOCKS5 代理

**CONNECT 命令**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 处理流程：握手协商 → 目标解析 → 建立上游连接 → 返回成功响应 → 双向隧道

**UDP_ASSOCIATE 命令**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 处理流程：调用 `async_associate()` 建立 UDP 中继

**Handler 注册**：
- 注册位置：[handlers.hpp](include/forward-engine/agent/dispatch/handlers.hpp)
- `register_handlers()` 中注册 `Socks5` 处理器到 `protocol_type::socks5`

### 3. TLS 终止

**TLS 握手**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 握手后作为 HTTPS 处理，执行服务器端 TLS 握手

**HTTPS 处理**：
- 实现位置：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
- 解密后的流量按 HTTP 协议处理，支持 CONNECT 和普通请求

**Handler 注册**：
- 注册位置：[handlers.hpp](include/forward-engine/agent/dispatch/handlers.hpp)
- `register_handlers()` 中注册 `Tls` 处理器到 `protocol_type::tls`

### 4. 反向代理

**reverse_map 路由**：
- 配置定义：[config.hpp](include/forward-engine/agent/config.hpp)
- 路由初始化：[worker.cpp](src/forward-engine/agent/reactor/worker.cpp)
- 路由查询：[arbiter.hpp](include/forward-engine/agent/distribution/arbiter.hpp)

**处理流程**：
1. Worker 构造时遍历 `reverse_map` 配置
2. 使用 `net::ip::make_address()` 解析目标地址
3. 调用 `router_.add_reverse_route()` 注册路由
4. 请求时通过 `arbiter::route_reverse()` 查找并连接

### 5. 正向代理 Fallback

**直连失败后转发**：
- 实现位置：[router.cpp](src/forward-engine/agent/distribution/router.cpp)
- 处理流程：
  1. 先检查黑名单 `blacklist_.domain(host)`
  2. 尝试 `stream_dns_.resolve()` 直连
  3. 失败后调用 `async_positive()` 转发到 positive endpoint

**async_positive 实现**：
- 实现位置：[router.cpp](src/forward-engine/agent/distribution/router.cpp)
- 发送 HTTP CONNECT 请求到上游代理，解析响应状态码

### 6. 负载均衡

**基于评分的 Worker 选择**：
- 实现位置：[balancer.hpp](include/forward-engine/agent/front/balancer.hpp)
- 评分公式：`score = weight_session * (sessions/capacity) + weight_pending * (pending/capacity) + weight_lag * (lag/capacity)`
- 默认权重：session 60%、pending 10%、lag 30%

**过载检测与反压**：
- 实现位置：[balancer.hpp](include/forward-engine/agent/front/balancer.hpp)
- 滞后机制：进入过载阈值 90%，退出阈值 80%

### 7. 连接池

**TCP 连接复用**：
- 实现位置：[source.hpp](include/forward-engine/transport/source.hpp)
- 核心特性：
  - 栈式缓存（LIFO），优先复用最近使用的连接
  - 僵尸检测，复用前检查连接有效性
  - 线程隔离，每个 Worker 独享连接池

**配置参数**：
- `max_cache_per_endpoint`：单个端点最大缓存连接数，默认 32
- `max_idle_seconds`：空闲连接最大存活时间，默认 60 秒

### 8. DNS 缓存

**reliable_resolver（TCP）**：
- 实现位置：[reliable.hpp](include/forward-engine/agent/distribution/reliable.hpp)
- 特性：缓存端点列表、请求合并、FIFO 淘汰
- 默认 TTL：120 秒，最大条目：10000

**datagram_resolver（UDP）**：
- 实现位置：[datagram.hpp](include/forward-engine/agent/distribution/datagram.hpp)
- 特性：缓存单个端点、请求合并
- 默认 TTL：120 秒，最大条目：4096

### 9. 账户认证与配额控制

**账户目录**：
- 实现位置：[directory.hpp](include/forward-engine/agent/account/directory.hpp)
- 特性：写时复制、无锁读取、透明查找

**连接配额**：
- 实现位置：[directory.hpp](include/forward-engine/agent/account/directory.hpp)
- `try_acquire()` 函数实现 CAS 原子递增，支持最大连接数限制

---

## 二、仅配置声明但未接入的能力

### Trojan 协议

**配置声明**：
- 配置字段：[config.hpp](include/forward-engine/agent/config.hpp)
  ```cpp
  protocol::trojan::config trojan;
  ```

- 协议配置：[trojan/config.hpp](include/forward-engine/protocol/trojan/config.hpp)
  ```cpp
  struct config 
  {
      bool enable_tcp = true;
      bool enable_udp = false;
      std::uint32_t udp_idle_timeout = 60;
      std::uint32_t udp_max_datagram = 65535;
  };
  ```

**协议实现存在**：
- 流实现：[trojan/stream.hpp](include/forward-engine/protocol/trojan/stream.hpp)
- 完整的握手、凭据验证、数据转发功能已实现

**未接入运行链**：
- Handler 注册：[handlers.hpp](include/forward-engine/agent/dispatch/handlers.hpp)
  ```cpp
  inline void register_handlers() 
  {
      auto &factory = registry::global();
      factory.register_handler<Http>(protocol::protocol_type::http);
      factory.register_handler<Socks5>(protocol::protocol_type::socks5);
      factory.register_handler<Tls>(protocol::protocol_type::tls);
      factory.register_handler<Unknown>(protocol::protocol_type::unknown);
      // 注意：没有 Trojan handler 注册
  }
  ```

- TLS Pipeline 未调用 Trojan：[protocols.cpp](src/forward-engine/agent/pipeline/protocols.cpp)
  - `pipeline::tls()` 仅执行 TLS 握手后按 HTTP/HTTPS 处理
  - 未检测 Trojan 协议特征（56 字节凭据 + CRLF）

- `config.trojan` 字段存在但未被使用
- `protocol::trojan::stream` 实现完整但未接入
- 当前运行链无法处理 Trojan 协议

---

## 三、源码声明但运行链未接入的能力

暂未发现其他类似情况。所有已实现的功能均已在运行链中正确接入。

---

## 四、关键实现细节

### 1. Listener 绑定 IPv4 而非 addressable.host

**问题位置**：[listener.cpp](src/forward-engine/agent/front/listener.cpp)

```cpp
const tcp::endpoint endpoint(tcp::v4(), cfg.addressable.port);
```

**分析**：
- 使用 `tcp::v4()` 硬编码 IPv4 协议
- `cfg.addressable.host` 当前未用于 bind
- 仅使用 `cfg.addressable.port` 作为监听端口

**影响**：
- 无法绑定到特定 IP 地址
- 无法支持 IPv6 监听
- 多网卡环境下无法指定监听接口

### 2. async_forward 先直连后 Fallback

**实现位置**：[router.cpp](src/forward-engine/agent/distribution/router.cpp)

```cpp
auto router::async_forward(const std::string_view host, const std::string_view port)
    -> net::awaitable<std::pair<gist::code, unique_sock>>
{
    if (blacklist_.domain(host))
    {
        co_return std::make_pair(gist::code::blocked, nullptr);
    }

    auto [ec, socket] = co_await stream_dns_.resolve(host, port);
    if (!gist::failed(ec) && socket && socket->is_open())
    {
        co_return std::make_pair(ec, std::move(socket));
    }

    co_return co_await async_positive(host, port);
}
```

**处理流程**：
1. 先检查黑名单
2. 尝试 DNS 解析并直连目标
3. 直连失败后才调用 `async_positive()` 转发到 positive endpoint

**设计意图**：
- 优先直连，减少延迟
- 仅在直连不可达时使用上游代理
- 适用于需要"智能分流"的场景

### 3. reverse_map 目标更偏向 IP Literal

**实现位置**：[worker.cpp](src/forward-engine/agent/reactor/worker.cpp)

```cpp
for (const auto &[host, endpoint_config] : server_ctx_.cfg.reverse_map)
{
    boost::system::error_code ec;
    const auto addr = net::ip::make_address(endpoint_config.host, ec);
    if (!ec && endpoint_config.port != 0)
    {
        router_.add_reverse_route(host, tcp::endpoint(addr, endpoint_config.port));
    }
    else
    {
        trace::warn("Invalid reverse route config for host: {}", host);
    }
}
```

**分析**：
- 使用 `net::ip::make_address()` 解析目标地址
- 该函数优先识别 IP 地址格式（IPv4/IPv6）
- 对于域名格式会返回错误，导致路由注册失败

**影响**：
- `reverse_map` 的目标地址应为 IP Literal
- 域名格式目标需要额外 DNS 解析逻辑
- 配置错误时仅打印警告，不影响其他路由

---

## 五、架构总结

### 运行链完整度

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
| Trojan 协议 | ✅ | ✅ | ❌ | 未接入 |

### 待完善项

1. **Trojan 协议接入**：需要创建 Trojan Handler 并注册到 `register_handlers()`
2. **Listener 绑定优化**：支持 `addressable.host` 绑定和 IPv6
3. **reverse_map 域名支持**：增加 DNS 解析逻辑支持域名目标
