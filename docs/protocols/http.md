# HTTP 请求在 Prism 内的调用流程

本文说明 HTTP 请求进入代理后的完整调用链，以及不同类型 HTTP 请求（`CONNECT`、绝对 `URI`、相对路径）在项目内的分支与路由决策。所有流程均基于协程模型运行。

## 1. 总体入口链路

1. **连接接收**：`listener` 监听端口并接受连接，`balancer` 选择 worker 分发 socket，worker 调用 `dispatch_socket` 创建 `session`
   入口位置：[listener.hpp](../../include/prism/agent/front/listener.hpp)，类 `psm::agent::front::listener` 的 accept 逻辑。

2. **协议识别**：`session::diversion` 预读并识别协议，然后分流到 HTTP 处理器
   位置：[session.hpp](../../include/prism/agent/session/session.hpp)，类 `psm::agent::session` 的 `diversion`。通过检查请求行前几个字节判断是否为 HTTP 协议（`GET `、`POST `、`CONNECT ` 等）。

3. **HTTP 处理器调用**：`dispatch::Http` handler 类读取并解析 HTTP 请求，确定目标与路由方向
   位置：[handlers.hpp](../../include/prism/agent/dispatch/handlers.hpp)，命名空间 `psm::agent::dispatch` 的 `Http` handler 类。

4. **目标解析**：`protocol::analysis::resolve` 判断"正向/反向"并解析目标地址
   位置：[analysis.cpp](../../src/prism/protocol/analysis.cpp)，类 `psm::protocol::analysis` 的 `resolve`。

5. **上游连接建立**：`primitives::dial` 根据 `target.positive` 选择路由
   位置：[primitives.cpp](../../src/prism/pipeline/primitives.cpp)，命名空间 `psm::pipeline::primitives` 的 `dial`。

6. **路由决策与连接**：`router` 建立上游连接（直连或回退）
   位置：[router.cpp](../../src/prism/resolve/router.cpp)，类 `psm::resolve::router` 的 `async_forward` 与 `async_reverse`。

7. **隧道转发**：根据请求类型进入隧道（`tunnel`）转发。

## 2. HTTP 请求解析与目标判定详解

### 2.1 请求读取与解析

`pipeline::http` 使用 `primitives::preview` 装饰器重放预读数据，然后通过 `protocol::http::relay` 中继器完成握手（读取请求头 + 解析 + 认证），整个过程将协议逻辑与 pipeline 编排层分离：

```cpp
// 包装入站传输（如有预读数据则用 preview 装饰器重放）
auto inbound = std::move(ctx.inbound);
if (!data.empty())
    inbound = std::make_shared<primitives::preview>(std::move(inbound), data, ctx.frame_arena.get());

// 创建 HTTP 中继并握手（读取请求头 + 解析 + 认证）
auto relay = protocol::http::make_relay(std::move(inbound), ctx.account_directory_ptr);
auto [ec, req] = co_await relay->handshake();
```

**解析流程**（[relay.hpp](../../include/prism/protocol/http/relay.hpp) → [parser.hpp](../../include/prism/protocol/http/parser.hpp)）：
1. **手动读取**：`relay` 内部通过 `read_until_header_end()` 循环读取，直到找到 `\r\n\r\n`。
2. **请求行解析**：提取 `method`、`target`、`version`（均为 `string_view`，零拷贝）。
3. **头字段提取**：遍历头字段，仅提取代理所需字段：`Host` 和 `Proxy-Authorization`（大小写不敏感）。
4. **结果结构体**：`proxy_request` 包含 `method`、`target`、`host`、`authorization`、`version` 等字段，全部为 `string_view`。

### 2.2 目标解析与正反向判定

`protocol::analysis::resolve` 根据请求内容判断代理方向并解析目标地址：

**判定逻辑**：
- **CONNECT 请求**（`req.method == "CONNECT"`）：
  正向代理，目标地址从 `req.target` 解析（格式：`host:port`），端口默认为 443。

- **绝对 URI 请求**（`req.target.starts_with("http://")` 或 `req.target.starts_with("https://")`）：
  正向代理，调用 `parse_absolute_uri` 解析 URI，提取主机、端口和路径。
  默认端口：HTTP 为 80，HTTPS 为 443。

- **相对路径请求**（其他情况）：
  反向代理，目标从 `req.host` 解析，端口默认为 80。

**关键代码位置**：[analysis.cpp](../../src/prism/protocol/analysis.cpp)。

### 2.3 三种请求类型的处理分支

#### 2.3.1 `CONNECT` 请求（HTTPS 正向代理）

**示例请求**：
```
CONNECT example.com:443 HTTP/1.1
Host: example.com:443
```

**调用流程**：
1. `analysis::resolve` 将其判定为正向代理，解析 `host:port`。
2. `connect_upstream` 调用 `resolve::router::async_forward`（直连优先，失败回退上游代理）。
3. 连接成功后，返回 `200 Connection Established` 给客户端。
4. 进入原始 TCP 隧道透传（`tunnel`）。

**关键点**：
- `CONNECT` 请求完成后不再解析 HTTP 报文，而是纯 TCP 双向转发。
- 响应固定为：`HTTP/1.1 200 Connection Established\r\n\r\n`

#### 2.3.2 绝对 `URI` 请求（HTTP 正向代理）

**示例请求**：
```
GET http://example.com/path HTTP/1.1
Host: example.com
```

**调用流程**：
1. `analysis::resolve` 识别为正向代理并解析绝对 `URI`。
2. `connect_upstream` 调用 `resolve::router::async_forward`，建立上游连接。
3. 通过 `extract_relative_path` 将绝对 URI 转换为相对路径。
4. 构建新请求行（`METHOD /path HTTP/1.1\r\n`），分段写入上游：
   - 先写新请求行
   - 再写原始数据中请求行之后的部分（剩余 headers + `\r\n\r\n` + body data）
5. 进入隧道转发（`tunnel`），支持持续双向流量。

#### 2.3.3 相对路径请求（反向代理）

**示例请求**：
```
GET /index.html HTTP/1.1
Host: myservice.com
```

**调用流程**：
1. `analysis::resolve` 判定为反向代理，目标从 `Host` 头解析。
2. `connect_upstream` 调用 `resolve::router::async_reverse`，根据路由表获取后端连接。
3. 请求原始数据直接转发给后端（无需 URI 重写）。
4. 进入隧道转发（`tunnel`）。

## 3. HTTP 代理认证

Prism 支持标准 HTTP 代理认证机制（RFC 7235），用于对正向代理请求进行身份验证。

### 3.1 Proxy-Authorization 头解析

当配置了认证凭据时，HTTP 处理器会检查请求中的 `Proxy-Authorization` 头部字段。当前支持 Basic 认证方案：

```
Proxy-Authorization: Basic <base64-encoded-credentials>
```

Base64 解码使用 [base64.hpp](../../include/prism/crypto/base64.hpp) 实现，解码后格式为 `username:password`。

### 3.2 认证流程

1. 检查配置中是否启用了认证（存在凭据列表）。
2. 若未启用认证，直接放行请求。
3. 若启用了认证，从 `proxy_request::authorization` 字段获取 `Proxy-Authorization` 值。
4. 解码并验证凭据（SHA224 哈希比对）。
5. 验证通过则继续处理请求，否则返回相应错误响应。

### 3.3 认证失败响应

- **407 Proxy Authentication Required**：请求缺少 `Proxy-Authorization` 头或凭据验证失败。
- **403 Forbidden**：认证格式错误或解码失败。

## 4. 路由与连接建立的关键细节

### 4.1 正向路由 `async_forward`

路由优先级（[router.cpp](../../src/prism/resolve/router.cpp)）：
1. **黑名单拦截**：检查目标地址是否在黑名单中（直接返回 `blocked`）。
2. **DNS 解析并直连**：解析目标主机名，通过连接池 `acquire_tcp` 获取或创建连接。
3. **直连失败回退**：如果直连失败，回退到配置的上游代理（通过 `CONNECT` 命令）。

### 4.2 反向路由 `async_reverse`

从 `reverse_map_` 取目标后端 `endpoint`，通过连接池复用连接。
对应实现：[router.cpp](../../src/prism/resolve/router.cpp) 的 `psm::resolve::router::async_reverse`。

### 4.3 上游代理回退 `async_positive`

当直连失败时，走 `CONNECT` 回退路径：
1. 解析上游代理地址。
2. 连接代理服务器。
3. 发送 `CONNECT host:port` 请求。
4. 解析响应行状态码（仅接受 `200`）。

对应实现：[router.cpp](../../src/prism/resolve/router.cpp) 的 `psm::resolve::router::async_positive`。

## 5. 隧道转发机制

### 5.1 双向隧道转发

`primitives::tunnel` 用于建立双向数据隧道：

```cpp
auto tunnel(shared_transmission inbound, shared_transmission outbound,
            const session_context &ctx, const bool complete_write = true) -> net::awaitable<void>
{
  // 使用双缓冲区实现双向转发
  // 任一方向断开即终止隧道
}
```

**特点**：
- 纯字节流转发，不进行协议升级。
- 使用 PMR 内存资源分配缓冲区。
- 转发完成后关闭两端连接。

### 5.2 预读数据处理

在 HTTP 请求读取过程中，可能已经读取了部分请求体数据（位于 `\r\n\r\n` 之后）。这些数据与请求行之后的所有字节一起直接转发给上游，然后进入隧道处理后续数据流。

### 5.3 核心转发逻辑 `primitives::tunnel`

`primitives::tunnel` 是通用的双向转发函数：
- 在客户端和上游连接之间建立双向数据流。
- 使用协程实现高效的并发转发。
- 处理连接关闭和错误情况。

## 6. 关键日志与排查点

以下日志有助于确认 HTTP 请求走向：

- `[Pipeline.Http] {method} {target} -> {host}:{port}`
  位置：[http.cpp](../../src/prism/pipeline/protocols/http.cpp) 的 `psm::pipeline::http`。

## 7. 简化调用图（文字版）

```
listener.accept -> balancer.dispatch -> worker.dispatch_socket -> session::diversion
  -> pipeline::http
      -> primitives::preview (预读数据重放装饰器)
      -> protocol::http::relay::handshake (读取请求头 + 解析 + 认证)
      -> analysis::resolve (目标解析与正反向判定)
      -> primitives::dial
          -> router::async_forward | async_reverse (路由决策与连接建立)
      -> if CONNECT:
          -> relay::write_connect_success
          -> primitives::tunnel (纯 TCP 透传)
      -> else:
          -> relay::forward (绝对 URI 重写为相对路径 + 写入上游)
          -> primitives::tunnel (持续双向转发)
```

## 8. 轻量解析器

HTTP 代理解析模块定义在 [parser.hpp](../../include/prism/protocol/http/parser.hpp)：

### 8.1 `proxy_request` 结构体

解析结果结构体，所有字段为 `string_view`（零分配，指向原始缓冲区）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `method` | `string_view` | 请求方法，如 `"CONNECT"`、`"GET"` |
| `target` | `string_view` | 请求目标（URI 或 host:port） |
| `host` | `string_view` | Host 头字段值 |
| `authorization` | `string_view` | Proxy-Authorization 头字段值 |
| `version` | `string_view` | HTTP 版本，如 `"HTTP/1.1"` |
| `req_line_end` | `size_t` | 请求行之后 `\r\n` 的偏移量 |
| `header_end` | `size_t` | `\r\n\r\n` 之后的偏移量 |

### 8.2 `parse_proxy_request`

从原始字节中提取代理转发所需信息。仅提取 `method`、`target`、`host`、`authorization`、`version`，不构建完整 HTTP 消息对象。

### 8.3 `extract_relative_path`

将绝对 URI（如 `http://example.com/path?q=1`）转换为源站所需的相对路径（如 `/path?q=1`），用于正向代理请求转发。

## 9. 错误处理与状态码映射

HTTP 协议错误到 `fault::code` 的映射：

- `parse_error`：HTTP 报文解析失败（格式不合法、字段缺失等）
- `generic_error`：一般性 I/O 错误
- `eof`：连接关闭

**错误处理原则**：
1. **热路径无异常**：网络 I/O、协议解析、数据转发等热路径严禁抛异常，必须使用 `fault::code` 返回值。
2. **异常仅用于启动阶段**：配置加载失败、内存耗尽等致命错误可使用异常。
3. **错误码轻量**：`fault::code` 是 4 字节的轻量值对象，无动态分配。

**典型错误场景**：
- **头部读取失败**：记录日志并关闭连接。
- **请求解析失败**：记录日志并关闭连接。
- **连接建立失败**：返回 `502 Bad Gateway` 给客户端。
- **隧道转发错误**：记录错误日志，优雅关闭两端连接。

所有错误都会在相应位置记录详细日志，便于问题排查和系统监控。
