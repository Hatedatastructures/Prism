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
