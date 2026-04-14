# TLS 协议在 Prism 内的调用流程

本文说明 TLS 连接在 Prism 内的处理流程。Session 层负责 TLS 握手和内层协议探测，
之后将已解密的传输层分发给对应的 handler（HTTP、Trojan 或 VLESS）。

核心思想：**handler 不感知 TLS，只看到解密后的 transport + 预读数据。**

## 1. TLS 协议检测

TLS 通过首字节 `0x16`（Handshake）识别：

```
TLS 记录层格式：
+--------+--------+--------+----------------+
|  Type  | Version| Length |     Payload    |
| 1 byte | 2 bytes| 2 bytes|    Variable    |
+--------+--------+--------+----------------+

Type = 0x16 (Handshake) 表示 TLS 握手
```

检测位置：[probe.hpp](../../include/prism/protocol/probe.hpp)

## 2. 握手与内层探测

SSL 上下文在 Worker 构造时创建（[tls.cpp](../../src/prism/agent/worker/tls.cpp)），配置证书链、私钥和 ALPN。

Session 层在 `diversion()` 中执行：

```
probe(24B) → detect() → protocol_type::tls
                          ↓
              primitives::ssl_handshake (TLS 握手)
                          ↓
              创建 encrypted 传输层
                          ↓
              增量读取内层数据，detect_inner() 探测协议
                - HTTP：最早 4 字节可识别（匹配方法前缀）
                - Trojan：至少 60 字节（56 凭据 + CRLF + CMD + ATYP）
                - VLESS：至少 22 字节（Version + UUID + AddnlLen + CMD + Port + ATYP + 最小地址）
                          ↓
              分发到对应 handler（handler 收到解密 transport）
```

> Trojan 协议格式详见 [Trojan 协议文档](trojan.md)，VLESS 协议格式详见 [VLESS 协议文档](vless.md)。

## 3. 证书配置

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

生成自签名证书：

```bash
openssl req -x509 -newkey rsa:4096 \
    -keyout key.pem -out cert.pem \
    -days 365 -nodes \
    -subj "/CN=localhost"
```

## 4. 错误处理

| 场景 | 处理方式 |
|------|---------|
| 证书加载失败 | 记录日志，阻止服务启动 |
| 握手失败 | 记录日志，关闭单个连接 |
| 无证书配置 | 运行明文模式（HTTP/SOCKS5） |

## 5. 关键日志

- `[Primitives.SSL] TLS handshake failed: {error} ({value})` — [primitives.cpp](../../src/prism/pipeline/primitives.cpp)
- `[Session] [{}] TLS inner protocol: {}` — [session.cpp](../../src/prism/agent/session/session.cpp)

## 6. Reality 协议

Reality 是一种基于 TLS 1.3 的协议伪装方案，通过在标准 TLS 握手中嵌入认证信息，
使代理流量看起来像访问正常网站的 TLS 连接。Prism 实现了完整的 Reality 服务端。

### 6.1 握手流程

```
客户端                                    Prism 服务端
  |                                          |
  |  TLS ClientHello (含加密 session_id)     |
  |  ──────────────────────────────────────> |
  |                                          |  解析 ClientHello
  |                                          |  X25519/X25519MLKEM768 key_share 提取
  |                                          |  Reality 认证（解密 session_id）
  |                                          |
  |                        ┌─ 认证失败 ──> 透传到 dest（伪装真实站点）
  |                        │
  |                        └─ 认证成功 ──> TLS 1.3 握手
  |                                          |
  |  <────────────────────────────────────── |
  |  ServerHello + CCS + 加密握手消息         |
  |      (EncryptedExtensions                |
  |     + Certificate (Ed25519 自签名)       |
  |     + CertificateVerify (Ed25519 签名)   |
  |     + Finished)                          |
  |                                          |
  |  CCS + 加密 ClientFinished               |
  |  ──────────────────────────────────────> |
  |                                          |  验证 ClientFinished
  |                                          |  切换到应用密钥
  |  <────────── 双向数据传输 ──────────────> |
```

### 6.2 认证机制

Reality 认证通过 ClientHello 的 session_id 字段传递：

- 客户端用服务端长期公钥 + X25519 ECDH 共享密钥派生 auth_key
- auth_key 用于加密包含 short_id 和时间戳的 session_id
- 服务端用长期私钥还原 auth_key 并解密验证

### 6.3 密钥交换

支持两种 key_share 类型：

| 类型 | Named Group | 说明 |
|------|-------------|------|
| X25519 | `0x001D` | 纯 X25519，32 字节公钥 |
| X25519MLKEM768 | `0x11EC` | 混合密钥交换，提取末尾 32 字节 X25519 公钥 |

### 6.4 TLS 1.3 密钥调度

严格遵循 RFC 8446 Section 7 实现：

```
early_secret = HKDF-Extract(0^32, 0^32)
derived_secret = Derive-Secret(early_secret, "derived", "")
handshake_secret = HKDF-Extract(derived_secret, shared_secret)
hello_hash = SHA-256(ClientHello || ServerHello)
c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", hello_hash)
s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", hello_hash)
```

### 6.5 证书与签名

Reality 不使用真实 CA 证书，而是生成临时 Ed25519 自签名证书：

- 密钥对：每次握手随机生成 Ed25519 密钥对
- 证书签名：`HMAC-SHA512(auth_key, ed25519_public_key)`
- CertificateVerify：使用 Ed25519 私钥对 transcript hash 签名
- 签名算法：`ed25519 (0x0807)`

### 6.6 配置

```json
{
  "agent": {
    "reality": {
      "private_key": "Base64 编码的 X25519 私钥",
      "short_id": ["Base64 编码的 short ID"],
      "dest": "www.microsoft.com:443",
      "server_names": ["www.microsoft.com"]
    }
  }
}
```

### 6.7 相关源码

| 文件 | 职责 |
|------|------|
| [request.cpp](../../src/prism/protocol/reality/request.cpp) | ClientHello 解析 |
| [auth.cpp](../../src/prism/protocol/reality/auth.cpp) | Reality 认证 |
| [response.cpp](../../src/prism/protocol/reality/response.cpp) | ServerHello + 加密握手生成 |
| [handshake.cpp](../../src/prism/protocol/reality/handshake.cpp) | 握手状态机 |
| [keygen.cpp](../../src/prism/protocol/reality/keygen.cpp) | TLS 1.3 密钥调度 |
| [session.cpp](../../src/prism/protocol/reality/session.cpp) | Reality 会话处理 |
