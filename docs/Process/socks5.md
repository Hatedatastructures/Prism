# SOCKS5 请求在 ForwardEngine 内的调用流程

本文说明 SOCKS5 请求进入代理后的完整调用链，以及 SOCKS5 协议握手、地址解析、连接建立的全过程。所有流程均基于协程模型运行。

## 1. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接，创建 `session`  
   入口位置：[worker.hpp](../../include/forward-engine/agent/worker.hpp)，类 `ngx::agent::worker` 的 `do_accept`。

2. **协议识别**：`session::diversion` 预读并识别协议，然后分流到 SOCKS5 处理器  
   位置：[session.hpp](../../include/forward-engine/agent/session.hpp)，类 `ngx::agent::session` 的 `diversion`。通过检查前几个字节判断是否为 SOCKS5 协议（版本号为 `0x05`）。

3. **SOCKS5 处理器调用**：`handler::socks5` 创建 SOCKS5 流对象并执行握手  
   位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp)，命名空间 `ngx::agent::handler` 的 `socks5` 模板函数。

4. **协议握手执行**：`protocol::socks5::stream::handshake` 执行完整的 SOCKS5 握手流程  
   位置：[stream.hpp](../../include/forward-engine/protocol/socks5/stream.hpp)，类 `ngx::protocol::socks5::stream` 的 `handshake`。

5. **上游连接建立**：`handler::connect_upstream` 根据解析的目标地址建立连接  
   位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp)，命名空间 `ngx::agent::handler` 的 `connect_upstream`。

6. **路由决策与连接**：`distributor` 建立上游连接（直连或回退）  
   位置：[distributor.cpp](../../src/forward-engine/agent/conduit.cpp)，类 `ngx::agent::distributor` 的 `route_forward`。

7. **响应发送与隧道切换**：连接成功后发送成功响应，进入原始 TCP 隧道转发。

## 2. SOCKS5 握手详解

SOCKS5 握手遵循 RFC 1928 标准，分为两个阶段：**方法协商阶段**和**请求读取阶段**。

### 2.1 方法协商阶段

`protocol::socks5::stream::negotiate_method` 处理客户端认证方法协商：

**客户端请求格式**：
```
+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+
```

**协商流程**：
1. **读取客户端请求**：异步读取 2 字节头部（VER + NMETHODS），然后读取 NMETHODS 字节的方法列表。
2. **协议版本验证**：检查 VER 字段是否为 `0x05`（只支持 SOCKS5）。
3. **方法检查**：遍历 METHODS 列表，查找支持的方法。当前实现仅支持 `NO AUTHENTICATION REQUIRED` (`0x00`)。
4. **响应发送**：
   - 如果支持 `0x00`：发送 `[0x05, 0x00]`
   - 如果不支持：发送 `[0x05, 0xFF]`

**关键代码位置**：[stream.hpp](../../include/forward-engine/protocol/socks5/stream.hpp) 第 190-258 行。

### 2.2 请求读取阶段

`protocol::socks5::stream::read_request_header` 读取客户端请求：

**请求头部格式**：
```
+----+-----+-------+------+
|VER | CMD |  RSV  | ATYP |
+----+-----+-------+------+
| 1  |  1  | X'00' |  1   |
+----+-----+-------+------+
```

**解析流程**：
1. **读取 4 字节头部**：异步读取 VER、CMD、RSV、ATYP 字段。
2. **头部解码**：调用 `wire::decode_header` 解码头部，验证版本号（必须为 `0x05`）和保留字段（必须为 `0x00`）。
3. **地址解析分支**：根据 ATYP 字段选择不同的地址解析函数。

### 2.3 地址解析分支

根据 `atyp` 字段的不同，调用相应的解析函数：

#### 2.3.1 IPv4 地址（`atyp == address_type::ipv4`）

调用 `read_ip_address_and_port<4>`：
- **数据格式**：4 字节 IPv4 地址 + 2 字节端口
- **解析函数**：`wire::decode_ipv4` 解析 IPv4 地址，`wire::decode_port` 解析端口
- **最大长度**：6 字节

#### 2.3.2 IPv6 地址（`atyp == address_type::ipv6`）

调用 `read_ip_address_and_port<16>`：
- **数据格式**：16 字节 IPv6 地址 + 2 字节端口
- **解析函数**：`wire::decode_ipv6` 解析 IPv6 地址，`wire::decode_port` 解析端口
- **最大长度**：18 字节

#### 2.3.3 域名地址（`atyp == address_type::domain`）

调用 `read_domain_address_and_port`：
- **数据格式**：1 字节域名长度 + N 字节域名 + 2 字节端口
- **解析函数**：`wire::decode_domain` 解析域名，`wire::decode_port` 解析端口
- **最大长度**：1 + 255 + 2 = 258 字节

**关键代码位置**：[stream.hpp](../../include/forward-engine/protocol/socks5/stream.hpp) 第 291-359 行。

### 2.4 完整握手流程

`protocol::socks5::stream::handshake` 整合所有步骤：
1. 调用 `negotiate_method` 完成方法协商。
2. 调用 `read_request_header` 读取请求头部。
3. 根据 ATYP 字段调用对应的地址解析函数。
4. 验证命令类型（只支持 `command::connect`）。
5. 返回解析后的请求信息。

## 3. 命令处理与响应

### 3.1 CONNECT 命令（TCP 代理）

当前实现仅支持 `CONNECT` 命令（`command::connect`，`0x01`）。

**握手成功后的响应流程**：
1. **方法协商**：客户端发送 `[0x05, 0x01, 0x00]`，服务端返回 `[0x05, 0x00]`。
2. **请求解析**：解析客户端请求，获取目标地址和端口。
3. **连接建立**：通过 `connect_upstream` 建立到目标服务器的连接。
4. **成功响应**：发送 `[0x05, 0x00, 0x00, ATYP, BND.ADDR, BND.PORT]` 给客户端。
5. **隧道转发**：进入原始 TCP 隧道透传模式。

**成功响应构建**（`build_success_response` 函数）：
- **固定头部**：VER (`0x05`)、REP (`0x00`)、RSV (`0x00`)、ATYP
- **地址编码**：根据地址类型编码 IPv4、IPv6 或域名地址
- **端口编码**：大端序编码端口号

### 3.2 不支持的命令处理

如果接收到 `BIND` (`0x02`) 或 `UDP ASSOCIATE` (`0x03`) 命令，流程如下：

1. **命令检查**：`handshake` 函数中检查命令是否为 `command::connect`。
2. **错误响应**：调用 `send_error` 发送 `reply_code::command_not_supported` (`0x07`)。
3. **错误返回**：返回 `gist::code::unsupported_command` 错误码。
4. **连接关闭**：握手失败，连接终止。

**错误响应格式**：
```
+----+-----+-------+------+
|VER | REP |  RSV  | ATYP |
+----+-----+-------+------+
|0x05|0x07 | 0x00  | 0x01 |
+----+-----+-------+------+
|       IPv4:0.0.0.0       |
+-------------+------------+
|    PORT(2)  |
+-------------+
```

## 4. 目标解析与路由决策

### 4.1 目标对象构造

握手成功后，`handler::socks5` 构造 `protocol::analysis::target` 对象：

```cpp
protocol::analysis::target target(ctx.frame_arena.get());
auto host_str = protocol::socks5::to_string(request.destination_address, ctx.frame_arena.get());
target.host = std::move(host_str);
target.port.assign(std::to_string(request.destination_port));
target.forward_proxy = true;  // SOCKS5 始终是正向代理
```

**关键点**：
- `protocol::socks5::to_string` 将地址转换为字符串表示。
- SOCKS5 协议**始终使用正向代理模式**（`forward_proxy = true`）。

### 4.2 路由决策

SOCKS5 协议使用正向代理模式，路由决策流程如下：

1. **黑名单检查**：检查目标地址是否在黑名单中。
2. **DNS 解析**：解析目标主机名。
3. **直连尝试**：尝试直接连接到目标服务器。
4. **上游代理回退**：如果直连失败，回退到配置的上游代理（通过 `CONNECT` 命令）。

对应实现：[distributor.cpp](../../src/forward-engine/agent/conduit.cpp) 的 `ngx::agent::distributor::route_forward`。

## 5. 连接建立与隧道转发

### 5.1 上游连接建立

`connect_upstream` 函数根据 `target` 对象建立上游连接：
- 调用 `distributor::route_forward` 获取上游连接。
- 如果连接成功，返回 `true`；否则返回 `false`。

### 5.2 响应发送与隧道切换

**连接成功的情况**：
1. **发送成功响应**：`co_await agent->send_success(request)`
2. **恢复客户端 socket**：`ctx.client_socket = std::move(agent->socket())`
3. **进入原始隧道转发**：`co_await original_tunnel(ctx)`

**连接失败的情况**：
1. **发送错误响应**：`co_await agent->send_error(protocol::socks5::reply_code::host_unreachable)`
2. **连接关闭**：SOCKS5 流析构时自动关闭底层 socket

### 5.3 原始隧道转发

SOCKS5 使用 `original_tunnel` 进行纯 TCP 隧道转发：

```cpp
template <typename Context>
auto original_tunnel(Context &ctx) -> net::awaitable<void>
{
  if (!ctx.server_socket) 
  {
    trace::warn("[Handler] raw tunnel: no upstream connection.");
    co_return;
  }
    
  auto tunnel_ctx = detail::make_tunnel_context(&*ctx.server_socket, &ctx.client_socket);
  co_await detail::tunnel::stream(tunnel_ctx, ctx.buffer.data(), ctx.buffer.size());
  shut_close(ctx.server_socket);
}
```

**特点**：
- 不进行协议升级，纯字节流转发。
- 使用 `detail::tunnel::stream` 核心转发逻辑。
- 转发完成后关闭上游连接。

**核心转发逻辑**：
- `detail::tunnel::stream` 在客户端和上游连接之间建立双向数据流。
- 使用协程实现高效的并发转发。
- 处理连接关闭和错误情况。

## 6. 预读数据处理

SOCKS5 协议在 `session::diversion` 阶段进行协议识别时，可能已经预读了一些数据。由于 SOCKS5 握手需要精确的报文长度，预读数据量很小（通常为 2-3 字节用于协议识别）。这些预读数据在 SOCKS5 流创建时已经消耗，因此无需特殊处理。

**与 HTTP 的区别**：
- HTTP 可能预读完整请求头甚至部分正文，需要转发。
- SOCKS5 协议识别只需少量字节，握手阶段重新读取完整报文。

## 7. 关键日志与排查点

以下日志有助于确认 SOCKS5 请求走向：

- `[Session] Detected protocol: socks5.`  
  位置：[session.hpp](../../include/forward-engine/agent/session.hpp) 的 `ngx::agent::session::diversion`。

- `[SOCKS5] Handshake failed: {error}`  
  位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp) 的 `ngx::agent::handler::socks5`。

- `[SOCKS5] {host}:{port}`  
  位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp) 的 `ngx::agent::handler::socks5`（握手成功后记录目标地址）。

- `[Handler] Upstream connect success/failed for SOCKS5`  
  位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp) 的 `ngx::agent::handler::connect_upstream`。

- `[Handler] raw tunnel: no upstream connection.`  
  位置：[handler.hpp](../../include/forward-engine/agent/handler.hpp) 的 `ngx::agent::handler::original_tunnel`。

## 8. 简化调用图（文字版）

```
worker.accept -> session::diversion
  -> handler::socks5
      -> protocol::socks5::stream::handshake
          -> negotiate_method (方法协商)
              -> 读取客户端方法列表
              -> 检查是否支持 0x00 (NO AUTH)
              -> 发送协商响应
          -> read_request_header (读取请求头)
              -> wire::decode_header (解析头部)
          -> 根据 ATYP 解析地址：
              -> read_ip_address_and_port (IPv4/IPv6)
              -> read_domain_address_and_port (域名)
          -> 验证命令类型 (仅支持 CONNECT)
      -> 构造 target 对象
      -> handler::connect_upstream
          -> distributor::route_forward (正向路由)
              -> 黑名单检查
              -> DNS 解析
              -> 直连尝试
              -> 上游代理回退 (可选)
      -> if 连接成功:
          -> send_success (发送成功响应)
          -> original_tunnel (纯 TCP 透传)
              -> detail::tunnel::stream (核心转发逻辑)
      -> else:
          -> send_error (发送错误响应)
          -> 连接关闭
```

## 9. 协议常量与枚举

关键枚举定义在 [constants.hpp](../../include/forward-engine/protocol/socks5/constants.hpp)：

### 9.1 命令类型（`command`）
- `connect` (`0x01`)：建立 TCP 连接（唯一支持的命令）
- `bind` (`0x02`)：绑定端口（暂不支持）
- `udp_associate` (`0x03`)：UDP 关联（暂不支持）

### 9.2 地址类型（`address_type`）
- `ipv4` (`0x01`)：IPv4 地址
- `domain` (`0x03`)：域名地址
- `ipv6` (`0x04`)：IPv6 地址

### 9.3 认证方法（`auth_method`）
- `no_auth` (`0x00`)：无需认证（唯一支持的方法）
- `gssapi` (`0x01`)：GSSAPI 认证（暂不支持）
- `password` (`0x02`)：用户名/密码认证（暂不支持）
- `no_acceptable_methods` (`0xFF`)：无可接受的方法

### 9.4 响应码（`reply_code`）
- `succeeded` (`0x00`)：成功
- `server_failure` (`0x01`)：服务器失败
- `connection_not_allowed` (`0x02`)：连接不允许
- `network_unreachable` (`0x03`)：网络不可达
- `host_unreachable` (`0x04`)：主机不可达
- `connection_refused` (`0x05`)：连接被拒绝
- `ttl_expired` (`0x06`)：TTL 过期
- `command_not_supported` (`0x07`)：命令不支持
- `address_type_not_supported` (`0x08`)：地址类型不支持

## 10. 错误处理与状态码映射

SOCKS5 协议错误到 `gist::code` 的映射：

- `unsupported_command`：命令不支持（收到 `BIND` 或 `UDP ASSOCIATE`）
- `unsupported_address`：地址类型不支持（收到不支持的 ATYP 值）
- `parse_error`：协议解析失败（报文格式错误、字段值非法等）
- `generic_error`：一般性错误（方法协商失败、I/O 错误等）
- `protocol_error`：协议违反（版本号错误、保留字段非零等）
- `not_supported`：不支持的功能（无可用认证方法）
- `io_error`：网络 I/O 错误（socket 读写失败）
- `auth_failed`：认证失败（虽然当前不支持认证，但预留）

**错误处理原则**：
1. **协议级错误**：通过 SOCKS5 响应码通知客户端（如 `command_not_supported`）。
2. **系统级错误**：直接关闭连接，记录详细日志。
3. **优雅降级**：对于暂时性错误（如网络不可达），返回相应的 SOCKS5 错误码而非直接断开。

**典型错误场景**：
- **客户端发送 BIND 命令**：返回 `reply_code::command_not_supported` (`0x07`)。
- **客户端使用不支持的认证方法**：返回 `auth_method::no_acceptable_methods` (`0xFF`)。
- **地址解析失败**：返回 `reply_code::address_type_not_supported` (`0x08`) 或 `host_unreachable` (`0x04`)。
- **网络连接失败**：返回 `reply_code::network_unreachable` (`0x03`) 或 `host_unreachable` (`0x04`)。

所有错误都会在相应位置记录详细日志，便于问题排查和系统监控。