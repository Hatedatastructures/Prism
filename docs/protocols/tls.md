# TLS 协议在 Prism 内的调用流程

本文说明 TLS 连接在 Prism 内的处理流程。Session 层负责 TLS 握手和内层协议探测，
之后将已解密的传输层分发给对应的 handler（HTTP 或 Trojan）。

## 1. 总体入口链路

1. **连接接收**：`worker` 监听端口并接收连接，创建 `session`
   入口位置：[worker.hpp](../../include/prism/agent/worker/worker.hpp)

2. **外层协议识别**：`session::diversion` 预读 24 字节，检测到 TLS 握手特征（首字节 `0x16`）
   位置：[session.cpp](../../src/prism/agent/session/session.cpp)

3. **TLS 握手**：Session 层调用 `primitives::ssl_handshake` 执行服务器端 TLS 握手
   位置：[session.cpp](../../src/prism/agent/session/session.cpp)

4. **内层协议探测**：Session 层增量读取内层数据，调用 `analysis::detect_inner` 判断协议类型（HTTP 或 Trojan）
   位置：[session.cpp](../../src/prism/agent/session/session.cpp)

5. **分发到 Handler**：将已解密的传输层分发给对应的处理器
   位置：[handlers.hpp](../../include/prism/agent/dispatch/handlers.hpp)

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
    trojan = 3,
    tls = 4  // 外层 TLS，Session 层剥离后探测内层协议
};
```

## 3. TLS 握手流程

### 3.1 SSL 上下文配置

SSL 上下文在 Worker 构造时创建：

**位置**：[tls.cpp](../../src/prism/agent/worker/tls.cpp)

**配置项**：
- 加载证书链和私钥
- 启用 ALPN 协议协商（h2、http/1.1）
- 配置密码套件和协议版本

### 3.2 握手执行

TLS 握手在 `session::diversion` 中执行，握手完成后探测内层协议并分发：

```cpp
// session.cpp - diversion()
// 1. 检测到 protocol_type::tls 后执行 TLS 握手
auto [ssl_ec, ssl_stream] = co_await primitives::ssl_handshake(ctx_, span);

// 2. 创建加密传输层
auto encrypted_trans = std::make_shared<transport::encrypted>(ssl_stream);

// 3. 增量读取内层数据并探测协议
auto inner_type = protocol::analysis::detect_inner(inner_view);

// 4. 更新 ctx_.inbound 为加密传输层，分发到对应 handler
ctx_.inbound = std::move(encrypted_trans);
```

**位置**：[session.cpp](../../src/prism/agent/session/session.cpp)

## 4. 握手后处理

### 4.1 Trojan 协议处理

TLS 握手成功后，Session 层探测内层协议类型（HTTP 或 Trojan）：

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
  位置：[protocols.cpp](../../src/prism/pipeline/protocols/trojan.cpp)

- `[Trojan] TLS handshake failed: {error}`
  位置：[protocols.cpp](../../src/prism/pipeline/protocols/trojan.cpp)

- `[Trojan] handshake completed, ALPN: {protocol}`
  位置：[protocols.cpp](../../src/prism/pipeline/protocols/trojan.cpp)

## 7. 简化调用图

```
worker.accept -> session::diversion
  -> protocol::probe::probe (检测外层协议)
  -> if protocol_type::tls:
      -> primitives::ssl_handshake (TLS 握手)
      -> 创建 encrypted 传输层
      -> analysis::detect_inner (增量读取并探测内层协议)
      -> 更新 ctx_.inbound 为加密传输层
  -> registry::create(内层协议类型) -> handler
  -> handler->process(ctx, inner_data)
      -> HTTP/Trojan handler 处理已解密流量
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
