# Prism 中的 HTTP/1.1 代理协议

## 1. 协议背景

### 1.1 规范参考

| 规范 | 描述 |
|---|---|
| RFC 7230 | HTTP/1.1 消息语法与路由 |
| RFC 7231 | HTTP/1.1 语义与内容 |
| RFC 2817 | HTTP/1.1 内升级至 TLS（CONNECT 方法） |
| RFC 7235 | HTTP/1.1 认证（Basic 认证方案） |
| RFC 7617 | Basic HTTP 认证方案 |

### 1.2 为什么存在 HTTP 代理

HTTP 代理是最古老且部署最广泛的应用层代理协议。它主要服务于两个目的：

- **正向代理**：客户端配置 HTTP 代理以访问更广泛的互联网。代理接收带有绝对 URI 或 CONNECT 隧道的请求，并将其转发到源服务器。这使得内容过滤、缓存和访问控制成为可能。
- **透明/反向代理**：代理接收带有相对路径的请求，并使用 `Host` 头（RFC 7230 第 5.4 节）来确定源服务器。这在负载均衡器和反向代理部署中很常见。

### 1.3 协议特征

- **基于文本的协议**：人类可读的请求和状态行，CRLF 分隔
- **每请求无状态**：每个请求相互独立（与维持会话状态的 SOCKS5 不同）
- **三种请求形式**：CONNECT 隧道、绝对 URI、相对路径
- **端口 80（HTTP）/ 443（HTTPS）**：根据方案推断的默认端口
- **HTTP/1.1 持久连接**：连接可以处理多个请求，但 Prism 为简化起见将每个连接视为单个会话
- **无协议版本协商**：客户端在请求行中声明版本，服务器以相同版本响应

### 1.4 Prism 架构中的 HTTP 代理

Prism 将 HTTP/1.1 代理实现为**管道协议**，意味着它在初始探测阶段被检测并通过编译期处理器表直接分派。与 Trojan 或 Shadowsocks 不同，HTTP 在传输层不需要加密或认证——认证通过应用层的 Basic Auth 处理。

HTTP 实现刻意保持**精简**：它仅提取代理路由所需的字段（方法、目标、Host 头、Proxy-Authorization 头），不解析完整的 HTTP 消息体。这使得热路径快速且内存高效。

---

## 2. 协议规范

### 2.1 HTTP 请求行格式

```
请求行 = 方法 SP 请求URI SP HTTP版本 CRLF

方法       = "GET" | "POST" | "PUT" | "DELETE" | "HEAD"
           | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
SP           = " "（单个空格，0x20）
HTTP版本     = "HTTP/" 1*数字 "." 1*数字
CRLF         = CR LF（0x0D 0x0A）
```

### 2.2 三种请求 URI 形式

#### 形式 A：CONNECT 隧道（RFC 2817）

用于 HTTPS 连接。客户端请求代理建立到目标主机的 TCP 隧道。

```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
\r\n
```

- `请求URI` = `主机:端口` 格式
- 无前缀方案
- 代理响应 `200 Connection Established`，然后透明转发所有后续数据

#### 形式 B：绝对 URI（正向代理）

当客户端配置为使用显式 HTTP 代理时使用。

```
GET http://example.com:8080/path?query=1 HTTP/1.1
Host: example.com:8080
\r\n
```

- `请求URI` = `方案://主机:端口/路径?查询`
- 代理必须解析 URI、提取目标，并在转发到源服务器之前将请求重写为相对形式

#### 形式 C：相对路径（反向代理）

当代理作为反向代理或透明代理运行时使用。

```
GET /path?query=1 HTTP/1.1
Host: example.com:80
\r\n
```

- `请求URI` 以 `/` 开头
- 目标由 `Host` 头确定
- 如果缺少 `Host` 头，代理无法确定目标，必须返回 `400 Bad Request`

### 2.3 HTTP 响应格式

#### 200 连接已建立（CONNECT 成功）

```
HTTP/1.1 200 Connection Established\r\n
\r\n
```

最小响应——无需任何头部。此后连接成为透明 TCP 隧道。

#### 407 需要代理认证

```
HTTP/1.1 407 Proxy Authentication Required\r\n
Proxy-Authenticate: Basic\r\n
Content-Length: 0\r\n
\r\n
```

当客户端未提供有效的 Basic 认证凭据时发送。

#### 403 禁止访问

```
HTTP/1.1 403 Forbidden\r\n
Content-Length: 0\r\n
\r\n
```

当客户端提供无效的认证凭据时发送。

#### 502 网关错误

```
HTTP/1.1 502 Bad Gateway\r\n
Content-Length: 0\r\n
\r\n
```

当上游连接失败时发送（拨号错误、连接被拒绝等）。

### 2.4 Basic 认证（RFC 7617）

`Proxy-Authorization` 头格式：

```
Proxy-Authorization: Basic <base64(用户名:密码)>
```

示例：
```
Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==
```

其中 `dXNlcjpwYXNzd29yZA==` 是 `user:password` 的 Base64 编码。

在 Prism 中，认证流程为：
1. 提取 `Basic ` 前缀后的值（不区分大小写）
2. Base64 解码得到 `用户名:密码`
3. 提取冒号后的密码部分
4. 计算密码的 SHA224 哈希
5. 在 `account::directory` 中查找该哈希
6. 如果找到，获取连接租约；否则返回 403

### 2.5 HTTP 消息结构

```
HTTP 消息 = 请求行 / 状态行
           *头部字段
           CRLF
           [消息体]
```

头部字段是 `名称: 值` 对，每行一个，以空行（`\r\n\r\n`）终止。

---

## 3. Prism 架构

### 3.2 协议检测

检测发生在 `psm::protocol::analysis::detect()`（analysis.cpp 第 98-129 行）。算法按以下顺序检查预读数据：

1. **SOCKS5 检查**：首字节 == `0x05` -> `protocol_type::socks5`
2. **TLS 检查**：前两字节 == `0x16 0x03` -> `protocol_type::tls`
3. **HTTP 检查**：前缀匹配 9 个已知 HTTP 方法之一 -> `protocol_type::http`
4. **Shadowsocks 回退**：其他所有情况 -> `protocol_type::shadowsocks`

检查的 HTTP 方法前缀（analysis.cpp 第 8-11 行）：

```cpp
static constexpr std::array<std::string_view, 9> http_methods = {
    "GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
    "CONNECT ", "OPTIONS ", "TRACE ", "PATCH "};
```

检测是简单的前缀匹配——窥视数据必须至少与方法字符串加上尾部空格的长度相同。例如，"GET " 至少需要 4 字节。

### 3.3 处理器分派

分派通过**编译期处理器表**完成（table.hpp 第 48-57 行）：

```cpp
inline constexpr std::array<handler_func *, ...> handler_table{
    /* 未知        */ handle_unknown,
    /* http        */ pipeline::http,
    /* socks5      */ pipeline::socks5,
    /* trojan      */ pipeline::trojan,
    /* vless       */ pipeline::vless,
    /* shadowsocks */ pipeline::shadowsocks,
    /* tls         */ handle_unknown,
};
```

`protocol_type::http` 枚举值（索引 1）直接映射到 `pipeline::http`。没有虚函数，没有运行时工厂——只有直接的数组查找和函数调用。

### 3.4 预读重放机制

会话通过 `probe()` 预读 24 字节（probe.hpp 第 97-125 行）。这些字节随后被包装在 `preview` 传输层装饰器中（primitives.hpp）。`preview` 装饰器在第一次调用 `async_read_some()` 时重放预读数据，确保 HTTP 中继器能够看到检测期间已消费的初始字节。

```
会话预读（24 字节）
    |
    v
+--------+    +------------------+    +--------------+
| probe()| -> | preview 包装器   | -> | http::中继器 |
+--------+    +------------------+    +--------------+
                    |                      |
              首次读取时             如同直接从
              重放数据               socket 读取
```

### 3.5 目标解析

`analysis::resolve()` 函数（analysis.cpp 第 196-234 行）处理三种情况：

| 情况 | 条件 | positive 标志 | 目标提取 |
|---|---|---|---|
| CONNECT | `req.method == "CONNECT"` | `true` | 从 `req.target` 解析 `主机:端口` |
| 绝对 URI | `target` 以 `http://` 或 `https://` 开头 | `true` | 解析方案、权威、路径 |
| 相对路径 | 以上都不是 | `false` | 从 `Host` 头解析 |

对于不带显式端口的 CONNECT，默认端口为 `443`（HTTPS）。对于绝对 URI，HTTP 默认为 `80`，HTTPS 默认为 `443`。

---

## 4. 调用层次结构

### 4.1 完整调用链（自上而下）

```
listener (io_context::accept)
  |
  v
balancer::select_worker (基于负载的亲和性)
  |
  v
worker::launch (在 worker io_context 上 co_spawn)
  |
  v
session::start()
  |
  v
session::diversion()
  |
  +-- 步骤 1: protocol::probe(inbound, 24)
  |       |
  |       +-- async_read_some (24 字节)
  |       +-- analysis::detect(peek_view)
  |           +-- is_http_request() -> 前缀匹配
  |           返回: protocol_type::http
  |
  +-- 步骤 2: 伪装管道（HTTP 跳过——类型 != tls）
  |
  +-- 步骤 3: dispatch::dispatch(ctx, protocol_type::http, span)
              |
              +-- handler_table[1] -> pipeline::http(ctx, span)
                  |
                  +-- ctx.frame_arena.reset()
                  +-- wrap_with_preview(ctx, span) -> inbound
                  +-- protocol::http::make_relay(inbound, account_dir)
                  +-- relay->handshake()
                  |   |
                  |   +-- read_until_header_end()
                  |   |   +-- 循环: async_read_some 直到找到 "\r\n\r\n"
                  |   |   +-- 缓冲区扩容: 4096 -> 8192 -> ... -> 最大 65536
                  |   |
                  |   +-- parse_proxy_request(raw, req)
                  |   |   +-- 查找第一个 "\r\n" -> 请求行
                  |   |   +-- 按空格分割 -> 方法、目标、版本
                  |   |   +-- 查找 "\r\n\r\n" -> 头部结束
                  |   |   +-- 遍历头部 -> 提取 Host、Proxy-Authorization
                  |   |
                  |   +-- authenticate_proxy_request(auth, directory) [如果 account_dir != nullptr]
                  |       +-- 验证 "Basic " 前缀（不区分大小写）
                  |       +-- base64_decode(凭据)
                  |       +-- 提取密码（冒号后）
                  |       +-- sha224(密码) -> 凭据哈希
                  |       +-- account::try_acquire(directory, credential)
                  |       +-- 失败时: 写入 407 或 403 响应
                  |
                  +-- protocol::analysis::resolve(req) -> target {主机, 端口, positive}
                  |
                  +-- primitives::dial(router, "HTTP", target, ...)
                  |   |
                  |   +-- router.async_forward(target) 或直接 TCP 连接
                  |   返回: [错误码, outbound_transmission]
                  |
                  +-- [根据 req.method 分支]
                      |
                      +-- "CONNECT" -> relay->write_connect_success() [200 响应]
                      |              primitives::tunnel(inbound, outbound, ctx)
                      |
                      +-- 其他     -> relay->forward(req, outbound, mr)
                                     |
                                     +-- build_forward_request_line() -> 相对路径
                                     +-- 将新请求行写入上游
                                     +-- 将其余头部 + 消息体写入上游
                                     primitives::tunnel(inbound, outbound, ctx)
```

### 4.2 关键函数签名

```cpp
// 管道入口点
auto pipeline::http(session_context &ctx, std::span<const std::byte> data)
    -> net::awaitable<void>;

// 中继器工厂
auto protocol::http::make_relay(
    transport::shared_transmission transport,
    agent::account::directory *account_directory = nullptr)
    -> std::shared_ptr<relay>;

// 中继器握手
auto relay::handshake()
    -> net::awaitable<std::pair<fault::code, proxy_request>>;

// HTTP 解析器
auto protocol::http::parse_proxy_request(
    std::string_view raw_data,
    proxy_request &out) -> fault::code;

// 认证
auto protocol::http::authenticate_proxy_request(
    std::string_view authorization,
    agent::account::directory &directory) -> auth_result;

// URI 重写
auto protocol::http::extract_relative_path(
    std::string_view target) -> std::string_view;

auto protocol::http::build_forward_request_line(
    const proxy_request &req,
    std::pmr::memory_resource *mr) -> memory::string;

// 目标解析
auto protocol::analysis::resolve(
    const http::proxy_request &req,
    memory::resource_pointer mr = nullptr) -> analysis::target;
```

---

## 5. 完整生命周期

### 5.1 CONNECT 隧道生命周期

```
  客户端                    Prism 代理                    源服务器
    |                            |                              |
    |  SYN                       |                              |
    |--------------------------->|                              |
    |                            |  session::diversion()        |
    |                            |  probe(24 字节)              |
    |                            |  detect -> protocol_type::http
    |                            |                              |
    |  "CONNECT example.com:443  |                              |
    |   HTTP/1.1\r\n             |                              |
    |   Host: example.com:443\r\n|                              |
    |   \r\n"                    |                              |
    |--------------------------->|                              |
    |                            |  relay::handshake()          |
    |                            |  read_until_header_end()     |
    |                            |  parse_proxy_request()       |
    |                            |  [可选: 认证]                |
    |                            |  analysis::resolve()         |
    |                            |  -> 主机="example.com"       |
    |                            |     端口="443"               |
    |                            |     positive=true            |
    |                            |                              |
    |                            |  primitives::dial()          |
    |                            |  TCP 连接 example.com:443    |
    |                            |------------------------------|>
    |                            |         SYN-ACK              |
    |                            |<------------------------------|
    |                            |                              |
    |  "HTTP/1.1 200             |                              |
    |   连接已建立\r\n            |                              |
    |   \r\n"                    |                              |
    |<---------------------------|                              |
    |                            |                              |
    |  TLS 客户端问候             |                              |
    |   (加密隧道开始)            |                              |
    |--------------------------->|                              |
    |                            |  primitives::tunnel()        |
    |                            |  双向拷贝                    |
    |                            |------------------------------|>
    |                            |         TLS 客户端问候        |
    |                            |<-----------------------------|
    |                            |         TLS 服务器问候        |
    |                            |         ... 应用数据          |
    |<---------------------------|                              |
    |                            |                              |
    |  ... 应用数据 ...           |                              |
    |<=========================================================>|
    |                            |                              |
    |  FIN                       |                              |
    |--------------------------->|  FIN                         |
    |                            |----------------------------->|
    |                            |                         FIN-ACK
    |                            |<-----------------------------|
    |  FIN-ACK                   |                              |
    |<---------------------------|                              |
    |                            |  session::release_resources()|
    |                            |  关闭 inbound/outbound       |
```

### 5.2 绝对 URI 请求生命周期

```
  客户端                    Prism 代理                    源服务器
    |                            |                              |
    |  "GET http://example.com/  |                              |
    |   HTTP/1.1\r\n             |                              |
    |   Host: example.com\r\n    |                              |
    |   \r\n"                    |                              |
    |--------------------------->|                              |
    |                            |  relay::handshake()          |
    |                            |  parse_proxy_request()       |
    |                            |  -> 方法="GET"               |
    |                            |     目标="http://..."        |
    |                            |     主机="example.com"       |
    |                            |                              |
    |                            |  analysis::resolve()         |
    |                            |  -> 主机="example.com"       |
    |                            |     端口="80"                |
    |                            |     positive=true            |
    |                            |                              |
    |                            |  primitives::dial()          |
    |                            |  TCP 连接 example.com:80     |
    |                            |------------------------------|>
    |                            |         SYN-ACK              |
    |                            |<------------------------------|
    |                            |                              |
    |                            |  relay::forward()            |
    |                            |  build_forward_request_line() |
    |                            |  -> "GET / HTTP/1.1\r\n"     |
    |                            |  写入新请求行                 |
    |                            |  写入头部 + 消息体            |
    |                            |------------------------------|>
    |                            |    "GET / HTTP/1.1\r\n       |
    |                            |     Host: example.com\r\n    |
    |                            |     \r\n"                    |
    |                            |                              |
    |                            |    HTTP 响应                 |
    |                            |<-----------------------------|
    |                            |                              |
    |  HTTP 响应                 |                              |
    |<---------------------------|                              |
    |                            |  primitives::tunnel()        |
    |                            |  (剩余数据双向)               |
    |<=========================================================>|
```

### 5.3 相对路径请求生命周期

```
  客户端                    Prism 代理                    源服务器
    |                            |                              |
    |  "GET /api/data HTTP/1.1\r\n                              |
    |   Host: api.example.com\r\n|                              |
    |   \r\n"                    |                              |
    |--------------------------->|                              |
    |                            |  relay::handshake()          |
    |                            |  parse_proxy_request()       |
    |                            |  -> 方法="GET"               |
    |                            |     目标="/api/data"         |
    |                            |     主机="api.example.com"   |
    |                            |                              |
    |                            |  analysis::resolve()         |
    |                            |  -> 主机="api.example.com"   |
    |                            |     端口="80"                |
    |                            |     positive=false           |
    |                            |                              |
    |                            |  primitives::dial()          |
    |                            |  TCP 连接 api.example.com    |
    |                            |------------------------------|>
    |                            |         SYN-ACK              |
    |                            |<------------------------------|
    |                            |                              |
    |                            |  relay::forward()            |
    |                            |  (目标已为相对形式，          |
    |                            |   无需重写)                   |
    |                            |  写入原始数据                 |
    |                            |------------------------------|>
    |                            |    "GET /api/data HTTP/1.1\r\n
    |                            |     Host: api.example.com\r\n|
    |                            |     \r\n"                    |
    |                            |                              |
    |                            |    HTTP 响应                 |
    |                            |<-----------------------------|
    |                            |                              |
    |  HTTP 响应                 |                              |
    |<---------------------------|                              |
    |                            |  primitives::tunnel()        |
    |<=========================================================>|
```

### 5.4 认证失败生命周期

```
  客户端                    Prism 代理
    |                            |
    |  "GET http://example.com/  |
    |   HTTP/1.1\r\n             |
    |   \r\n"                    |
    |--------------------------->|
    |                            |  relay::handshake()
    |                            |  parse_proxy_request()
    |                            |  -> 授权 = ""（空）
    |                            |
    |                            |  authenticate_proxy_request()
    |                            |  -> 无 "Basic " 前缀
    |                            |  -> 返回 {false, resp407, {}}
    |                            |
    |  "HTTP/1.1 407             |
    |   需要代理认证\r\n           |
    |   Proxy-Authenticate: Basic|
    |   Content-Length: 0\r\n    |
    |   \r\n"                    |
    |<---------------------------|
    |                            |  handshake 返回 auth_failed
    |                            |  pipeline::http co_returns
    |                            |  session 释放资源
```

---

## 6. 二进制格式示例

### 6.1 CONNECT 请求（十六进制转储）

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  43 4F 4E 4E 45 43 54 20 65 78 61 6D 70 6C 65 2E   CONNECT example.
000010  63 6F 6D 3A 34 34 33 20 48 54 54 50 2F 31 2E 31   com:443 HTTP/1.1
000020  0D 0A 48 6F 73 74 3A 20 65 78 61 6D 70 6C 65 2E   ..Host: example.
000030  63 6F 6D 3A 34 34 33 0D 0A 55 73 65 72 2D 41 67   com:443..User-Ag
000040  65 6E 74 3A 20 6D 6F 7A 69 6C 6C 61 2F 35 2E 30   ent: mozilla/5.0
000050  0D 0A 0D 0A                                       ....
```

关键字段：
- 字节 0-6：`CONNECT`（方法，7 字节）
- 字节 7：`0x20`（空格分隔符）
- 字节 8-21：`example.com:443`（目标）
- 字节 22：`0x20`（空格分隔符）
- 字节 23-31：`HTTP/1.1`（版本）
- 字节 32-33：`0x0D 0x0A`（CRLF，请求行结束）
- 字节 34-51：`Host: example.com:443`（头部）
- 字节 52-53：`0x0D 0x0A`（CRLF，头部结束）
- 字节 76-79：`0x0D 0x0A 0x0D 0x0A`（双 CRLF，头部结束）

### 6.2 200 连接已建立响应

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  48 54 54 50 2F 31 2E 31 20 32 30 30 20 43 6F 6E   HTTP/1.1 200 Con
000010  6E 65 63 74 69 6F 6E 20 45 73 74 61 62 6C 69 73   nection Establis
000020  68 65 64 0D 0A 0D 0A                              hed....
```

这是 relay.cpp 中的 `resp200` 常量：
```cpp
constexpr std::string_view resp200 = "HTTP/1.1 200 Connection Established\r\n\r\n";
```
总计：38 字节。

### 6.3 绝对 URI GET 请求

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  47 45 54 20 68 74 74 70 3A 2F 2F 65 78 61 6D 70   GET http://examp
000010  6C 65 2E 63 6F 6D 2F 70 61 74 68 3F 71 3D 31 20   le.com/path?q=1
000020  48 54 54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20   HTTP/1.1..Host:
000030  65 78 61 6D 70 6C 65 2E 63 6F 6D 0D 0A 0D 0A     example.com....
```

### 6.4 重写后的请求（转发到源服务器）

经过 `build_forward_request_line()` 处理后，发送到源服务器的请求变为：

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  47 45 54 20 2F 70 61 74 68 3F 71 3D 31 20 48 54   GET /path?q=1 HT
000010  54 50 2F 31 2E 31 0D 0A 48 6F 73 74 3A 20 65 78   TP/1.1..Host: ex
000020  61 6D 70 6C 65 2E 63 6F 6D 0D 0A 0D 0A            ample.com....
```

注意 `http://example.com` 已从请求行中剥离。剩余数据（原始文件中从偏移 0x1E 开始的头部）按原样转发。

### 6.5 Basic 认证头

```
Proxy-Authorization: Basic dXNlcjpwYXNzd29yZA==
```

头部行的十六进制转储：
```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  50 72 6F 78 79 2D 41 75 74 68 6F 72 69 7A 61 74   Proxy-Authorizat
000010  69 6F 6E 3A 20 42 61 73 69 63 20 64 58 4E 6C 63   ion: Basic dXNlc
000020  33 70 77 61 6E 64 47 56 73 62 47 38 67 5A 57 35   3pwnadGVsbG8gZW5
000030  6A 61 3D 3D 0D 0A                                 ja==..
```

Base64 解码：`user:password`
- `dXNlcg==` = `user`
- `cGFzc3dvcmQ=` = `password`

### 6.6 407 需要认证响应

```
偏移    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
000000  48 54 54 50 2F 31 2E 31 20 34 30 37 20 50 72 6F   HTTP/1.1 407 Pro
000010  78 79 20 41 75 74 68 65 6E 74 69 63 61 74 69 6F   xy Authenticatio
000020  6E 20 52 65 71 75 69 72 65 64 0D 0A 50 72 6F 78   n Required..Prox
000030  79 2D 41 75 74 68 65 6E 74 69 63 61 74 65 3A 20   y-Authenticate:
000040  42 61 73 69 63 0D 0A 43 6F 6E 74 65 6E 74 2D 4C   Basic..Content-L
000050  65 6E 67 74 68 3A 20 30 0D 0A 0D 0A               ength: 0....
```

这是 parser.cpp 中的 `resp407` 常量：
```cpp
constexpr std::string_view resp407 = "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                     "Proxy-Authenticate: Basic\r\n"
                                     "Content-Length: 0\r\n"
                                     "\r\n";
```
总计：89 字节。

---

## 7. 配置参数

### 7.1 HTTP 专用配置

Prism 中的 HTTP 代理在 JSON 配置中没有专用配置参数。其行为通过以下方式控制：

| 参数 | 配置中的位置 | 默认值 | 效果 |
|---|---|---|---|
| `authentication.users` | 根级别 | `[]` | HTTP Basic 认证凭据。每个用户有一个 `password` 字段。密码的 SHA224 哈希与 `Proxy-Authorization` 头进行匹配。 |
| `addressable` | 根级别 | 必填 | 监听端点。到达这些端点的 HTTP 连接在检测到时由 HTTP 管道处理。 |
| `buffer.size` | 根级别 | `32768` | 隧道缓冲区大小，用于 HTTP 握手后的双向转发。 |
| `limit.concurrences` | 根级别 | `0`（无限制） | 最大并发连接数。在会话级别强制执行。 |
| `positive` | 根级别 | `[]` | 上游代理列表。如果配置，HTTP 请求将通过指定的上游代理转发，而不是直接连接到目标。 |

### 7.2 认证配置示例

```json
{
    "addressable": ["0.0.0.0:8080"],
    "authentication": {
        "users": [
            { "password": "mysecretpassword" }
        ]
    },
    "buffer": { "size": 32768 }
}
```

配置认证后：
- 所有 HTTP 请求必须包含有效的 `Proxy-Authorization: Basic ...` 头
- 缺少或错误的凭据将导致 407 或 403 响应
- 密码以其 SHA224 哈希形式存储在 `account::directory` 中

### 7.3 隐式配置默认值

| 参数 | 默认值 | 源 |
|---|---|---|
| 初始读取缓冲区 | 4096 字节 | `src/prism/protocol/http/relay.cpp` 第 22 行 |
| 最大头部大小 | 65536 字节 | `src/prism/protocol/http/relay.cpp` 第 16 行 |
| 缓冲区增长因子 | 2 倍 | `src/prism/protocol/http/relay.cpp` 第 110 行 |
| 预读大小 | 24 字节 | `include/prism/protocol/probe.hpp` 第 97 行 |
| CONNECT 默认端口 | 443 | `src/prism/protocol/analysis.cpp` 第 215 行 |
| HTTP 默认端口 | 80 | `src/prism/protocol/analysis.cpp` 第 80-81 行 |
| HTTPS 默认端口 | 443 | `src/prism/protocol/analysis.cpp` 第 76-77 行 |

---

## 8. 边缘情况与错误处理

### 8.1 错误码映射

| 场景 | 错误码 | 客户端响应 | 源 |
|---|---|---|---|
| 头部读取期间读取错误 | `fault::code::io_error` | 无（静默关闭） | `relay.cpp` 第 30 行 |
| 解析错误（格式错误的请求） | `fault::code::parse_error` | 无（静默关闭） | `relay.cpp` 第 38 行 |
| 认证失败（无凭据） | `fault::code::auth_failed` | `407 需要代理认证` | `relay.cpp` 第 48 行 |
| 认证失败（密码错误） | `fault::code::auth_failed` | `403 禁止访问` | `relay.cpp` 第 48 行 |
| 上游拨号失败 | `fault::code::*` | `502 网关错误` | `http.cpp` 第 42 行 |
| 响应写入错误 | `fault::code::io_error` | 无（连接已断开） | `relay.cpp` 各处 |

### 8.2 Slowloris 防护

`max_header_size` 常量（65536 字节，位于 `relay.cpp` 第 16 行）防止慢速 HTTP 头部攻击：

```cpp
if (used_ >= buffer_.size())
{
    if (buffer_.size() >= max_header_size)
    {
        co_return false;  // 头部过大，中止
    }
    buffer_.resize(buffer_.size() * 2);  // 缓冲区翻倍
}
```

增长序列：4096 -> 8192 -> 16384 -> 32768 -> 65536（停止）

### 8.3 缺少 Host 头

当相对路径请求没有 `Host` 头时：
- `parse_proxy_request()` 将 `out.host` 留空
- `analysis::resolve()` 调用 `parse("", t.host, t.port)` 立即返回
- 结果目标的 `host` 字符串为空
- `primitives::dial()` 将无法解析空主机名
- 向客户端发送 `502 网关错误` 响应

### 8.4 CONNECT 不带端口

```
CONNECT example.com HTTP/1.1
```

`analysis::resolve()` 函数检测到此情况（analysis.cpp 第 209-216 行）：
- 检查目标是否包含冒号（针对 IPv4/主机名）或 `]:`（针对 IPv6）
- 如果未找到显式端口，默认为 `443`
- 这是正确的行为，因为 CONNECT 通常用于 HTTPS

### 8.5 CONNECT 目标中的 IPv6

```
CONNECT [2001:db8::1]:443 HTTP/1.1
```

`analysis::parse()` 函数处理 IPv6 括号语法（analysis.cpp 第 252-270 行）：
- 检测 `[` 前缀
- 查找闭合的 `]`
- 提取括号之间的地址
- 检查 `]:` 以找到端口

### 8.6 不带路径的绝对 URI

```
GET http://example.com HTTP/1.1
```

`extract_relative_path()` 函数（parser.cpp 第 236-239 行）：
- 剥离 `http://` 得到 `example.com`
- 在剩余字符串中找不到 `/`
- 返回 `"/"` 作为默认路径

### 8.7 格式错误的请求行

| 格式错误的输入 | 错误 | 源 |
|---|---|---|
| 请求行中无 `\r\n` | `fault::code::parse_error` | `parser.cpp` 第 151 行 |
| 方法后无空格 | `fault::code::parse_error` | `parser.cpp` 第 158 行 |
| 目标后无空格 | `fault::code::parse_error` | `parser.cpp` 第 164 行 |
| 无 `\r\n\r\n` 头部终止符 | `fault::code::parse_error` | `parser.cpp` 第 177 行 |
| 方法过短（< 4 字节） | 未被检测为 HTTP | `analysis.cpp` - 探测返回 `shadowsocks` |

### 8.8 头部解析边缘情况

| 场景 | 行为 | 源 |
|---|---|---|
| 空头部行 | `continue`（跳过） | `parser.cpp` 第 191-193 行 |
| 无冒号的头部 | `continue`（跳过） | `parser.cpp` 第 196-198 行 |
| 重复的 `Host` 头 | 最后一个值生效 | `parser.cpp` 第 204-206 行 |
| 重复的 `Proxy-Authorization` | 最后一个值生效 | `parser.cpp` 第 208-210 行 |
| 头部值中的前导/尾部空白 | 被修剪 | `parser.cpp` 第 201-202 行（`trim()`） |
| 混合大小写头部名称 | 不区分大小写匹配 | `parser.cpp` 第 204 行（`iequals()`） |
| 头部名称 `host`（小写） | 正确匹配 | `iequals("host", "Host")` = true |

### 8.9 认证边缘情况

| 场景 | 行为 | 源 |
|---|---|---|
| 空的 `Proxy-Authorization` | 视为未提供认证 | `authenticate_proxy_request()` 检查前缀 |
| `Proxy-Authorization: Bearer token` | 无法识别，返回 407 | 前缀检查失败（不是 "Basic "） |
| `Proxy-Authorization: Basic`（无凭据） | 空字符串的 Base64 解码 -> 无冒号 -> 403 | `parser.cpp` 第 109-126 行 |
| `Proxy-Authorization: Basic dXNlcg==`（`user` 无冒号） | 未找到冒号 -> 403 | `parser.cpp` 第 111 行 |
| `Proxy-Authorization: Basic dXNlcjo=`（`user:` 空密码） | 冒号在末尾，密码为空，计算 "" 的哈希 | 在目录中查找 SHA224("") |
| 有效凭据但连接数已达上限 | `try_acquire` 返回空租约 -> 403 | `parser.cpp` 第 116-123 行 |

### 8.10 网络错误处理

| 错误 | 检测 | 响应 |
|---|---|---|
| 上游连接被拒绝 | `primitives::dial()` 返回的 `dial_ec` | `502 网关错误` |
| DNS 解析失败 | 路由器返回的 `dial_ec` | `502 网关错误` |
| 隧道期间上游连接重置 | `tunnel()` 检测到 EOF/错误 | 会话关闭，无响应（CONNECT 已返回 200） |
| 头部读取期间客户端断开 | `async_read_some` 返回错误 | `relay::handshake()` 返回 `io_error`，会话关闭 |
| 响应之前上游断开 | `tunnel()` 处理 EOF | 会话正常关闭 |

### 8.11 出站代理模式

当设置 `ctx.outbound_proxy` 时（configuration.json 的 `positive` 部分）：
- HTTP 请求通过上游代理转发，而不是直接连接
- 使用 `primitives::dial(*ctx.outbound_proxy, target, ...)` 而非路由器
- 对于非 CONNECT 请求，请求仍被重写为相对形式
- 上游代理处理到源服务器的实际连接

### 8.12 协议检测误判

HTTP 检测使用前缀匹配 9 个已知方法。这可能会产生误判：

| 场景 | 风险 | 缓解措施 |
|---|---|---|
| 随机二进制数据以 "GET " 开头 | 低 | 后续解析将失败（无 `\r\n\r\n`） |
| 非 HTTP 协议以 "GET " 开头 | 极低 | 其他协议很少以可打印 ASCII 开头 |
| 来自非代理客户端的 CONNECT 请求 | 无 | 这是有效的 HTTP 代理行为 |

回退链确保即使检测错误，解析失败也会导致干净的断开连接，而不是未定义行为。
