# HTTP 请求在 Prism 内的调用流程

本文说明 HTTP 请求进入代理后的完整调用链，以及不同类型 HTTP 请求（`CONNECT`、绝对 `URI`、相对路径）在项目内的分支与路由决策。所有流程均基于协程模型运行。

## 1. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接，创建 `session`  
   入口位置：[worker.hpp](../../include/prism/agent/worker/worker.hpp)，类 `psm::agent::worker` 的 `do_accept`。

2. **协议识别**：`session::diversion` 预读并识别协议，然后分流到 HTTP 处理器  
   位置：[session.hpp](../../include/prism/agent/session/session.hpp)，类 `psm::agent::session` 的 `diversion`。通过检查请求行前几个字节判断是否为 HTTP 协议（`GET `、`POST `、`CONNECT ` 等）。

3. **HTTP 处理器调用**：`handler::http` 读取并解析 HTTP 请求，确定目标与路由方向  
   位置：[handlers.hpp](../../include/prism/agent/dispatch/handlers.hpp)，命名空间 `psm::agent::handler` 的 `http` 模板函数。

4. **目标解析**：`protocol::analysis::resolve` 判断"正向/反向"并解析目标地址  
   位置：[analysis.cpp](../../src/prism/protocol/analysis.cpp)，类 `psm::protocol::analysis` 的 `resolve`。

5. **上游连接建立**：`primitives::dial` 根据 `target.positive` 选择路由  
   位置：[primitives.cpp](../../src/prism/agent/pipeline/primitives.cpp)，命名空间 `psm::agent::pipeline::primitives` 的 `dial`。

6. **路由决策与连接**：`router` 建立上游连接（直连或回退）  
   位置：[router.cpp](../../src/prism/resolve/router.cpp)，类 `psm::resolve::router` 的 `async_forward` 与 `async_reverse`。

7. **隧道转发**：根据请求类型进入隧道（`tunnel`）转发。

## 2. HTTP 请求解析与目标判定详解

### 2.1 请求读取与解析

`handler::http` 使用 `protocol::http::async_read` 异步读取并解析 HTTP 请求：

```cpp
// 创建请求对象和缓冲区
beast::basic_flat_buffer read_buffer(protocol_http::network_allocator{mr});
protocol_http::request req(mr);

// 异步读取并解析
const auto ec = co_await protocol_http::async_read(ctx.client_socket, req, read_buffer, mr);
```

**解析流程**（[deserialization.hpp](../../include/prism/protocol/http/deserialization.hpp)）：
1. **创建解析器**：使用 `beast::http::request_parser<http_body>`，设置头部限制（16KB）和正文限制（10MB）。
2. **异步读取**：调用 `beast::http::async_read` 读取完整 HTTP 请求。
3. **数据提取**：从解析器提取方法、目标、版本、头部字段和正文。
4. **错误处理**：如果读取失败，返回相应的 `fault::code`：
   - `eof`：连接关闭
   - `generic_error`：其他错误

### 2.2 目标解析与正反向判定

`protocol::analysis::resolve` 根据请求内容判断代理方向并解析目标地址：

**判定逻辑**：
- **CONNECT 请求**（`req.method() == http::verb::connect`）：  
  正向代理，目标地址从 `req.target()` 解析（格式：`host:port`），端口默认为 443。
  
- **绝对 URI 请求**（`req.target().starts_with("http://")` 或 `req.target().starts_with("https://")`）：  
  正向代理，调用 `parse_absolute_uri` 解析 URI，提取主机、端口和路径。  
  默认端口：HTTP 为 80，HTTPS 为 443。

- **相对路径请求**（其他情况）：  
  反向代理，目标从 `Host` 头解析，端口默认为 80。

**关键代码位置**：[analysis.cpp](../../src/prism/protocol/analysis.cpp) 第 118-147 行。

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
3. 将解析后的 `req` 通过 `protocol::http::serialize` 序列化并转发给上游。
4. 若 `read_buffer` 内还有预读数据，继续转发。
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
3. 请求序列化并转发给后端。
4. 继续转发预读数据并进入隧道转发（`tunnel`）。

## 3. 路由与连接建立的关键细节

### 3.1 正向路由 `async_forward`

路由优先级（[router.cpp](../../src/prism/resolve/router.cpp)）：
1. **黑名单拦截**：检查目标地址是否在黑名单中（直接返回 `blocked`）。
2. **DNS 解析并直连**：解析目标主机名，通过连接池 `acquire_tcp` 获取或创建连接。
3. **直连失败回退**：如果直连失败，回退到配置的上游代理（通过 `CONNECT` 命令）。

### 3.2 反向路由 `async_reverse`

从 `reverse_map_` 取目标后端 `endpoint`，通过连接池复用连接。
对应实现：[router.cpp](../../src/prism/resolve/router.cpp) 的 `psm::resolve::router::async_reverse`。

### 3.3 上游代理回退 `async_positive`

当直连失败时，走 `CONNECT` 回退路径：
1. 解析上游代理地址。
2. 连接代理服务器。
3. 发送 `CONNECT host:port` 请求。
4. 解析响应行状态码（仅接受 `200`）。

对应实现：[router.cpp](../../src/prism/resolve/router.cpp) 的 `psm::resolve::router::async_positive`。

## 4. 隧道转发机制

### 4.1 双向隧道转发

`primitives::tunnel` 用于建立双向数据隧道：

```cpp
auto tunnel(transmission_pointer inbound, transmission_pointer outbound,
            session_context &ctx) -> net::awaitable<void>
{
  // 使用双缓冲区实现双向转发
  // 任一方向断开即终止隧道
}
```

**特点**：
- 纯字节流转发，不进行协议升级。
- 使用 PMR 内存资源分配缓冲区。
- 转发完成后关闭两端连接。

### 4.2 预读数据处理

在 HTTP 请求解析过程中，可能已经预读了一些数据（如请求正文的开始部分）。这些数据需要转发给上游：

```cpp
if (read_buffer.size() != 0)
{
  trace::debug("[Handler] Forwarding {} bytes of prefetched data.", read_buffer.size());
  co_await psm::channel::loader::async_write(*ctx.server_socket, read_buffer.data(), redirect_error);
  read_buffer.consume(read_buffer.size());
}
```

**关键点**：
- 使用 `psm::channel::loader::async_write` 保证完整写入。
- 写入后调用 `consume` 清空缓冲区。

### 4.3 核心转发逻辑 `primitives::tunnel`

`primitives::tunnel` 是通用的双向转发函数：
- 在客户端和上游连接之间建立双向数据流。
- 使用协程实现高效的并发转发。
- 处理连接关闭和错误情况。

## 5. 关键日志与排查点

以下日志有助于确认 HTTP 请求走向：

- `[Session] Detected protocol: http.`
  位置：[session.hpp](../../include/prism/agent/session/session.hpp) 的 `psm::agent::session::session::diversion`。

- `[Pipeline] HTTP request received: {method} {target}`
  位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp) 的 `psm::agent::pipeline::http`。

- `[Pipeline] HTTP analysis target = [host: {}, port: {}, positive: {}]`
  位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp) 的 `psm::agent::pipeline::http`。

- `[Pipeline] HTTP upstream connected`
  位置：[primitives.cpp](../../src/prism/agent/pipeline/primitives.cpp) 的 `psm::agent::pipeline::primitives::dial`。

## 6. 简化调用图（文字版）

```
worker.accept -> session::diversion
  -> pipeline::http
      -> protocol::http::async_read (请求解析)
      -> analysis::resolve (目标解析与正反向判定)
      -> primitives::dial
          -> router::async_forward | async_reverse (路由决策与连接建立)
      -> if CONNECT:
          -> send "200 Connection Established"
          -> primitives::tunnel (纯 TCP 透传)
      -> else:
          -> protocol::http::serialize (请求序列化)
          -> psm::channel::adapter::async_write (转发请求头与正文)
          -> forward prefetched buffer (read_buffer.data) (预读数据转发)
          -> primitives::tunnel (持续双向转发)
```

## 7. 协议常量与枚举

关键枚举定义在 [constants.hpp](../../include/prism/protocol/http/constants.hpp)：

### 7.1 HTTP 请求方法（`verb`）
- `connect`：建立隧道（HTTPS 代理）
- `get`：获取资源
- `post`：提交数据
- `put`：更新资源
- `delete_`：删除资源
- `head`：获取响应头
- `options`：查询服务器能力
- 以及其他 WebDAV、UPnP 等方法

### 7.2 HTTP 状态码（`status`）
- `ok` (`200`)：请求成功
- `bad_request` (`400`)：请求语法错误
- `unauthorized` (`401`)：需要认证
- `forbidden` (`403`)：禁止访问
- `not_found` (`404`)：资源不存在
- `internal_server_error` (`500`)：服务器内部错误
- 以及其他标准状态码

### 7.3 HTTP 头部字段（`field`）
- `host`：请求目标主机
- `content_length`：内容长度
- `content_type`：内容类型
- `connection`：连接管理
- `proxy_connection`：代理连接
- 以及其他标准和非标准头部字段

## 8. 错误处理与状态码映射

HTTP 协议错误到 `fault::code` 的映射：

- `parse_error`：HTTP 报文解析失败（格式不合法、字段缺失等）
- `bad_message`：消息格式错误（长度不足、字段越界等）
- `protocol_error`：协议违反（非法状态机、约束违反等）
- `io_error`：网络 I/O 错误（socket 读写失败）
- `timeout`：操作超时
- `eof`：连接关闭
- `generic_error`：一般性错误

**错误处理原则**：
1. **热路径无异常**：网络 I/O、协议解析、数据转发等热路径严禁抛异常，必须使用 `fault::code` 返回值。
2. **异常仅用于启动阶段**：配置加载失败、内存耗尽等致命错误可使用异常。
3. **错误码轻量**：`fault::code` 是 4 字节的轻量值对象，无动态分配。

**典型错误场景**：
- **连接建立失败**：返回 `fault::code::io_error`，记录日志并关闭连接。
- **请求解析失败**：返回 `fault::code::parse_error`，发送 `400 Bad Request`（如适用）。
- **目标解析失败**：返回 `fault::code::invalid_argument`，记录日志并关闭连接。
- **隧道转发错误**：记录错误日志，优雅关闭两端连接。

所有错误都会在相应位置记录详细日志，便于问题排查和系统监控。