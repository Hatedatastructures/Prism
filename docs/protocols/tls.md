# TLS 协议在 Prism 内的调用流程

本文说明 TLS 连接在 Prism 内的处理流程。TLS 处理已整合到 Trojan 处理器中，Trojan over TLS 是主要的 TLS 入口。

## 1. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接，创建 `session`
   入口位置：[worker.hpp](../../include/prism/agent/worker/worker.hpp)

2. **协议识别**：`session::diversion` 预读并识别协议，检测到 TLS 握手特征
   位置：[session.cpp](../../src/prism/agent/session/session.cpp)
   TLS 协议通过检查首字节是否为 `0x16`（Handshake）来识别。

3. **Trojan 处理器调用**：`handler::Trojan` 执行 TLS 握手并处理后续请求
   位置：[handlers.hpp](../../include/prism/agent/dispatch/handlers.hpp)

4. **TLS 握手**：执行服务器端 TLS 握手
   位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)，函数 `pipeline::trojan`

5. **内部协议处理**：握手成功后，解析 Trojan 协议或 HTTP 请求

## 2. TLS 协议检测

### 2.1 检测逻辑

TLS 协议通过以下特征识别：

```
TLS 记录层格式：
+--------+--------+--------+----------------+
|  Type  | Version| Length |     Payload    |
| 1 byte | 2 bytes| 2 bytes|    Variable    |
+--------+--------+--------+----------------+

Type = 0x16 (Handshake) 表示 TLS 握手
```

**检测代码位置**：[probe.hpp](../../include/prism/protocol/probe.hpp)

### 2.2 协议类型枚举

```cpp
enum class protocol_type
{
    unknown = 0,
    http = 1,
    socks5 = 2,
    trojan = 3  // TLS 流量路由到 Trojan 处理器
};
```

## 3. TLS 握手流程

### 3.1 SSL 上下文配置

SSL 上下文在 Worker 构造时创建：

**位置**：[tls.cpp](../../src/prism/agent/worker/tls.cpp)

**配置项**：
- 加载证书链和私钥
- 启用 GREASE 扩展增加 TLS 指纹随机性
- 设置 ALPN 协议列表（h2、http/1.1）
- 配置密码套件和协议版本

### 3.2 握手执行

TLS 握手在 `pipeline::trojan` 函数内部执行：

```cpp
auto trojan(session_context &ctx, std::span<const std::byte> data)
    -> net::awaitable<void>
{
    // 创建 SSL 流
    auto ssl_stream = std::make_unique<ssl::stream<tcp::socket>>(
        std::move(socket), *ssl_ctx);

    // 执行 TLS 握手
    boost::system::error_code ec;
    co_await ssl_stream->async_handshake(
        ssl::stream_base::server,
        net::redirect_error(net::use_awaitable, ec));

    if (ec)
    {
        trace::error("[Trojan] TLS handshake failed: {}", ec.message());
        co_return;
    }

    // 握手成功，继续 Trojan 协议处理
    // ...
}
```

**位置**：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

## 4. 握手后处理

### 4.1 Trojan 协议处理

TLS 握手成功后，首先尝试解析 Trojan 协议：

**Trojan 协议格式**：
- 56 字节十六进制凭据（SHA224 哈希）
- 2 字节 CRLF 分隔符（`\r\n`）
- 1 字节命令类型（0x01=CONNECT, 0x03=UDP）
- 1 字节地址类型
- 变长目标地址
- 2 字节目标端口

**处理流程**：
1. 读取并验证凭据
2. 解析命令和目标地址
3. 验证通过则建立上游连接并转发

详细流程请参阅 [Trojan 协议文档](trojan.md)。

## 5. 证书配置

### 5.1 证书文件

配置位置：`configuration.json`

```json
{
  "agent": {
    "certificate": {
      "cert": "./cert.pem",
      "key": "./key.pem"
    }
  }
}
```

### 5.2 证书要求

- **格式**：PEM 格式
- **类型**：X.509 证书
- **密钥**：RSA 或 ECDSA 私钥
- **权限**：文件必须可读

### 5.3 生成自签名证书

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"
```

## 6. 关键日志与排查点

以下日志有助于确认 TLS 请求走向：

- `[Trojan] TLS handshake started`
  位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

- `[Trojan] TLS handshake failed: {error}`
  位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

- `[Trojan] handshake completed, ALPN: {protocol}`
  位置：[protocols.cpp](../../src/prism/agent/pipeline/protocols.cpp)

## 7. 简化调用图

```
worker.accept -> session::diversion
  -> protocol::probe::probe (检测 TLS)
  -> handler::Trojan
      -> pipeline::trojan
          -> 创建 ssl::stream
          -> async_handshake (TLS 握手)
          -> if 握手成功:
              -> 解析 Trojan 协议头
              -> 验证凭据
              -> 解析目标地址
              -> primitives::dial (建立上游连接)
              -> primitives::tunnel (双向转发)
          -> else:
              -> 记录错误日志
              -> 关闭连接
```

## 8. 错误处理

### 8.1 常见错误

| 错误类型 | 错误码 | 处理方式 |
|---------|--------|---------|
| 证书加载失败 | `ssl::error::stream_truncated` | 记录日志，终止启动 |
| 握手失败 | `ssl::error::stream_truncated` | 记录日志，关闭连接 |
| 证书验证失败 | `ssl::error::certificate_verify_failed` | 记录日志，关闭连接 |
| 协议版本不匹配 | `ssl::error::unsupported_version` | 记录日志，关闭连接 |

### 8.2 错误处理原则

1. **证书错误**：启动阶段失败，阻止服务启动
2. **握手错误**：运行时错误，记录日志并关闭单个连接
3. **无证书配置**：返回空 SSL 上下文，运行明文模式
