# Trojan 请求在 ForwardEngine 内的调用流程

本文说明 Trojan 请求进入代理后的完整调用链，包括 SSL 握手、Trojan 协议头解析、用户凭据验证、目标地址解析和双向隧道建立的全过程。所有流程均基于协程模型运行。

## 1. 总体入口链路

Trojan 协议的特殊之处在于它建立在 TLS/SSL 连接之上，因此入口点与其他协议略有不同：

1. **TLS 连接建立**：客户端首先建立 TLS 连接，该连接可能由 `session::diversion` 通过 SNI 或其他方式识别为 Trojan 协议。
   
2. **Trojan 处理器调用**：已建立的 SSL 流被传递给 `handler::trojan` 函数进行处理。
   入口位置：`include/forward-engine/agent/handler.hpp`，命名空间 `ngx::agent::handler` 的 `trojan` 模板函数。

3. **Trojan 流对象创建**：创建 `protocol::trojan::stream` 对象，封装 SSL 流和协议处理逻辑。
   位置：`include/forward-engine/protocol/trojan/stream.hpp`，类 `ngx::protocol::trojan::stream`。

4. **Trojan 握手执行**：调用 `stream::handshake_preread` 执行 Trojan 协议握手（包括凭据验证和请求解析）。
   
5. **用户流量验证**：通过 `account_validator` 验证用户凭据并获取流量统计对象。
   
6. **目标解析与路由**：解析目标地址，通过 `connect_upstream` 建立上游连接。
   
7. **双向隧道转发**：在 SSL 流和上游 TCP 连接之间建立双向数据转发隧道。

## 2. Trojan 协议握手详解

Trojan 协议握手分为两个阶段：**SSL 握手**和 **Trojan 协议头握手**。

### 2.1 SSL 握手

Trojan 协议建立在 TLS/SSL 加密通道之上。SSL 握手由 Boost.Asio 的 `ssl::stream` 处理：
```cpp
// SSL 握手（stream::handshake 函数）
boost::system::error_code ec;
co_await stream_ptr_->async_handshake(ssl::stream_base::server, net::redirect_error(net::use_awaitable, ec));
if (ec) 
{
    co_return std::pair{gist::code::tls_handshake_failed, request{}};
}
```

如果 SSL 握手失败，返回 `tls_handshake_failed` 错误码，连接终止。

### 2.2 Trojan 协议头握手

SSL 握手成功后，读取并解析 Trojan 协议头。Trojan 协议头格式如下：

```
+-------------------+-----+------+------------+----------+----------+
|   Credential      |CRLF | CMD  |    ATYP    | DST.ADDR | DST.PORT  |
|   (56 bytes)      |(\r\n)|(1 byte)| (1 byte) | Variable |  2 bytes |
+-------------------+-----+------+------------+----------+----------+
```

**头部解析流程**（`stream::read_header` 函数）：

1. **读取 60 字节头部**：56 字节凭据 + 2 字节 CRLF + 1 字节 CMD + 1 字节 ATYP
2. **解析凭据**：使用 `wire::decode_credential` 验证 56 字节十六进制字符串
3. **验证 CRLF**：使用 `wire::decode_crlf` 验证 `\r\n` 分隔符
4. **解析命令和地址类型**：使用 `wire::decode_cmd_atyp` 解析 CMD 和 ATYP
5. **凭据验证**：如果提供了 `verifier_` 回调，验证用户凭据有效性

**关键代码位置**：`include/forward-engine/protocol/trojan/stream.hpp` 第 291-331 行。

### 2.3 地址解析

根据 ATYP 字段的不同，调用相应的地址解析函数：

- **IPv4 地址**（`atyp == address_type::ipv4`）：  
  调用 `read_ip_address<4>`，使用 `wire::decode_ipv4` 解析 4 字节 IPv4 地址。
  
- **IPv6 地址**（`atyp == address_type::ipv6`）：  
  调用 `read_ip_address<16>`，使用 `wire::decode_ipv6` 解析 16 字节 IPv6 地址。
  
- **域名地址**（`atyp == address_type::domain`）：  
  调用 `read_domain_address`，先读取 1 字节域名长度，再读取对应长度的域名数据。

所有地址解析完成后，端口信息从后续 2 字节读取。

## 3. 用户凭据验证与流量统计

Trojan 协议支持基于用户凭据的验证和流量统计：

### 3.1 凭据验证

`stream` 构造函数可以接受一个 `credential_verifier` 回调函数：
```cpp
stream(Transport socket, std::shared_ptr<ssl::context> ctx,std::function<bool(std::string_view)> credential_verifier = nullptr)
```

在 `read_header` 过程中，如果提供了验证器，会调用它验证用户凭据：
```cpp
if (verifier_) 
{
    if (!verifier_(std::string_view(credential.data(), 56))) 
    {
        co_return std::pair<gist::code, header_information>{gist::code::auth_failed, header_information{}};
    }
}
```

### 3.2 流量统计

在 `handler::trojan` 中，如果配置了 `account_validator_ptr`，会为每个用户会话创建流量统计：
```cpp
if (ctx.account_validator_ptr) 
{
    const std::string_view credential_view(info.credential.data(), info.credential.size());
    validator::protector user_session = ctx.account_validator_ptr->try_acquire(credential_view);
    if (!user_session) 
    {
        trace::warn("[Trojan] Connection rejected by account validator.");
        co_return;
    }
    user_state_ptr = user_session.state();
}
```

流量统计在双向转发过程中实时更新：
- **上行流量**（客户端 → 服务器）：`validator_ptr->accumulate_uplink(user_state_ptr, n)`
- **下行流量**（服务器 → 客户端）：`validator_ptr->accumulate_downlink(user_state_ptr, n)`

## 4. 命令处理

Trojan 协议支持两种命令（定义在 `include/forward-engine/protocol/trojan/constants.hpp`）：

- `command::connect` (`0x01`)：建立 TCP 连接
- `command::udp_associate` (`0x03`)：建立 UDP 关联

当前实现支持两种命令，在 `handshake_internal` 中检查：
```cpp
if (req.cmd != command::connect && req.cmd != command::udp_associate) 
{
    co_return std::pair{gist::code::unsupported_command, request{}};
}
```

## 5. 目标解析与路由决策

### 5.1 目标对象构造

握手成功后，`handler::trojan` 构造 `protocol::analysis::target` 对象：
```cpp
protocol::analysis::target target(ctx.frame_arena.get());
auto host_str = protocol::trojan::to_string(info.destination_address, ctx.frame_arena.get());
target.host = std::move(host_str);
target.port.assign(std::to_string(info.port));
target.forward_proxy = true;  // Trojan 始终是正向代理
```

### 5.2 路由决策

Trojan 协议**始终使用正向代理模式**，路由决策流程如下：

1. **黑名单检查**：检查目标地址是否在黑名单中。
2. **DNS 解析**：解析目标主机名。
3. **直连尝试**：尝试直接连接到目标服务器。
4. **上游代理回退**：如果直连失败，回退到配置的上游代理。

对应实现：`src/forward-engine/agent/distributor.cpp` 的 `ngx::agent::distributor::route_forward`。

## 6. 双向隧道转发

Trojan 协议的核心是加密的隧道转发。连接建立成功后，在 SSL 流和上游 TCP 连接之间建立双向转发：

### 6.1 转发 Lambda 函数

`handler::trojan` 定义了一个通用的转发 Lambda：
```cpp
auto forward = [validator_ptr, user_state_ptr](auto &read_stream, auto &write_stream, const bool uplink) -> net::awaitable<void>
{
    std::array<char, ngx::memory::policy::small_buffer_size> buf{};
    boost::system::error_code ec;
    auto token = net::redirect_error(net::use_awaitable, ec);
    while (true) 
    {
        ec.clear();
        const auto n = co_await read_stream.async_read_some(net::buffer(buf), token);
        if (ec || n == 0) 
        {
            co_return;
        }
        
        // 流量统计
        if (validator_ptr && user_state_ptr) 
        {
            if (uplink) 
            {
                validator_ptr->accumulate_uplink(user_state_ptr, n);
            } 
            else 
            {
                validator_ptr->accumulate_downlink(user_state_ptr, n);
            }
        }
        
        ec.clear();
        co_await net::async_write(write_stream, net::buffer(buf, n), token);
        if (ec) 
        {
            co_return;
        }
    }
};
```

### 6.2 并行双向转发

使用 Boost.Asio 的 `awaitable_operators` 实现并行双向转发：
```cpp
using namespace boost::asio::experimental::awaitable_operators;
co_await (forward(client_stream, server_socket, true) || forward(server_socket, client_stream, false));
```

这创建了两个并发的转发协程：
1. **客户端 → 服务器**：从 SSL 流读取，向上游 TCP 连接写入（上行流量）
2. **服务器 → 客户端**：从上游 TCP 连接读取，向 SSL 流写入（下行流量）

## 7. 预读数据处理

Trojan 协议支持预读数据处理，用于在协议识别阶段已经读取的数据：

```cpp
auto handshake_preread(const std::string_view pre_read_data)
    -> net::awaitable<std::pair<gist::code, request>>
{
    // 继续握手，优先消耗预读数据
    co_return co_await handshake_internal(pre_read_data);
}
```

预读数据通过 `read_specified_bytes` 函数优先消耗，避免重复读取。

## 8. 关键日志与排查点

以下日志有助于确认 Trojan 请求走向：
- `[Trojan] Handshake failed: {error}`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::trojan`。
- `[Trojan] {host}:{port}`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::trojan`。
- `[Trojan] Connection rejected by account validator.`  
  位置：`include/forward-engine/agent/handler.hpp` 的 `ngx::agent::handler::trojan`。

## 9. 简化调用图（文字版）

```
TLS 连接建立 -> handler::trojan
  -> protocol::trojan::stream 创建
  -> handshake_preread (Trojan 握手)
      -> SSL 握手 (如果未完成)
      -> read_header (读取协议头)
          -> wire::decode_credential (解析凭据)
          -> wire::decode_crlf (验证 CRLF)
          -> wire::decode_cmd_atyp (解析命令和地址类型)
          -> 凭据验证 (如果有验证器)
      -> 根据 ATYP 解析地址：
          -> read_ip_address (IPv4/IPv6)
          -> read_domain_address (域名)
      -> 解析端口
  -> 用户流量验证 (account_validator)
  -> 构造 target 对象
  -> handler::connect_upstream
      -> distributor::route_forward (正向路由)
  -> 双向隧道转发
      -> forward(client_stream, server_socket, true)  // 上行
      -> forward(server_socket, client_stream, false) // 下行
```

## 10. 协议常量与枚举

关键枚举定义在 `include/forward-engine/protocol/trojan/constants.hpp`：

- `command`：`connect` (`0x01`), `udp_associate` (`0x03`)
- `address_type`：`ipv4` (`0x01`), `domain` (`0x03`), `ipv6` (`0x04`)

## 11. 错误处理与状态码映射

Trojan 协议错误码到 `gist::code` 的映射：

- `tls_handshake_failed`：SSL/TLS 握手失败
- `auth_failed`：用户凭据验证失败
- `unsupported_command`：命令不支持
- `unsupported_address`：地址类型不支持
- `protocol_error`：协议格式错误（CRLF 验证失败等）
- `bad_message`：消息格式错误（长度不足等）
- `parse_error`：协议解析失败

所有错误都会导致连接终止，客户端会收到相应的 SSL 层或 TCP 层错误。