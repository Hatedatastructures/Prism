# TrustTunnel 伪装方案文档

## 1. 模块概述

### 1.1 协议背景

TrustTunnel 是一种基于 HTTP/2 CONNECT 的 TLS 伪装代理协议。它利用 HTTP/2 原生的 stream 多路复用机制，将每个代理连接映射为一个 HTTP/2 CONNECT 请求，通过标准的 HTTP/2 流控和帧格式实现高效的多连接复用。

TrustTunnel 的核心优势在于完全复用 HTTP/2 标准协议栈：从被动检测器的角度看，TrustTunnel 流量与任何正常的 HTTP/2 连接（如 gRPC、REST API）完全一致。认证使用 HTTP 标准的 Basic Auth 机制，进一步增强了协议的"合法性"。

Prism 中的 TrustTunnel 实现参考了以下规范：

- **TrustTunnel 协议规范** -- https://github.com/trusttunnel/trusttunnel
- **RFC 7540** -- Hypertext Transfer Protocol Version 2 (HTTP/2)
- **RFC 7235** -- Hypertext Authentication (Basic Auth)
- **RFC 8446** -- TLS 1.3 协议

### 1.2 核心设计思想

TrustTunnel 采用 **Path A TLS 终结模式** + **HTTP/2 CONNECT 多路复用** 的组合架构：

1. **TLS + ALPN h2**：服务端使用真实 TLS 证书完成握手，协商 ALPN 为 `h2`
2. **HTTP/2 CONNECT**：每个代理连接通过 HTTP/2 CONNECT 请求创建，`Host` 头指定目标地址
3. **Basic Auth 认证**：通过 `Proxy-Authorization` 头进行 HTTP Basic Auth 认证
4. **stream 类型路由**：通过 `Host` 头的特殊后缀区分 TCP/UDP/ICMP/健康检查
5. **nghttp2 帧编解码**：利用 nghttp2 库处理 HTTP/2 帧的编解码和流控

### 1.3 与其他伪装方案的对比

| 特性 | AnyTLS | TrustTunnel |
|------|--------|-------------|
| TLS 握手 | 标准证书 | 标准证书 + ALPN h2 |
| 认证机制 | SHA-256(password) | HTTP Basic Auth |
| 多路复用协议 | 自定义帧格式 | HTTP/2 CONNECT（标准） |
| 帧格式 | 7B header | HTTP/2 二进制帧 |
| 流控 | 无（应用层） | HTTP/2 标准流控 |
| 外部依赖 | 无 | nghttp2 |
| TCP 支持 | 有 | 有（duct） |
| UDP 支持 | 无 | 有（parcel） |
| 健康检查 | 无 | 有（`_check` 后缀） |
| 拥塞控制 | 无 | BBR/Cubic/NewReno |

### 1.4 检测层级

TrustTunnel 作为 **Tier 2** 方案，无 ClientHello 独占特征，依赖 SNI 匹配触发。

## 2. 架构设计

### 2.1 文件结构

```
include/prism/stealth/trusttunnel/
├── config.hpp      # TrustTunnel 配置（证书、SNI、用户、网络类型）
└── scheme.hpp      # stealth_scheme 子类（方案注册与握手入口）

src/prism/stealth/trusttunnel/
└── scheme.cpp      # scheme 实现（TLS 握手 + h2mux 会话创建 + Basic Auth）
```

TrustTunnel 的核心多路复用逻辑位于 `multiplex/h2mux/` 模块，TrustTunnel scheme 负责 TLS 握手和认证，然后将 HTTP/2 连接交给 `h2mux::craft` 管理。

### 2.2 组件关系

```
  scheme (stealth_scheme 入口)
    │
    ├── handshake() ──────────────── TLS 握手 + h2mux 创建
    │     ├── peel_to_raw()               剥离传输层到原始 TCP
    │     ├── SSL_CTX_set_alpn_protos()   设置 ALPN=h2
    │     ├── ssl_handshake()             标准 TLS 握手
    │     ├── 验证 ALPN=h2               确保 HTTP/2 协商成功
    │     │
    │     ├── trusttunnel_resolver        CONNECT 请求地址解析回调
    │     │     ├── :authority → host:port
    │     │     └── Host → stream_type 路由
    │     │
    │     ├── h2mux::craft 创建          注入 resolver + router
    │     ├── craft->start()             nghttp2 初始化 + frame_loop
    │     ├── craft->wait_first_connect() 等待首个 CONNECT
    │     │
    │     ├── verify_basic_auth()         HTTP Basic Auth 验证
    │     │     ├── Base64 解码
    │     │     └── username:password 比对
    │     │
    │     ├── craft->respond_connect(200)  回复 200 OK
    │     └── craft->activate_stream()     激活首个 stream
    │
    └── h2mux::craft ──────────────── HTTP/2 多路复用
          │                               （详见 h2mux 模块文档）
          ├── frame_loop()              接收 HTTP/2 帧
          ├── send_loop()               发送 HTTP/2 帧
          ├── activate_stream()         创建 duct/parcel
          └── address_resolver 回调      TrustTunnel 模式
```

## 3. 核心组件说明

### 3.1 scheme（方案入口）

`scheme` 类继承 `stealth_scheme`，是 TrustTunnel 在 Prism 伪装方案管道中的入口。

- `name()` 返回 `"trusttunnel"`
- `tier()` 返回 `2`
- `unique()` 返回 `false`
- `guess()` 返回固定 score=100
- `handshake()` 执行完整流程：TLS 握手 -> 创建 h2mux craft -> 等待 CONNECT -> Basic Auth -> 激活 stream

**关键设计**：TrustTunnel 在 stealth 层内部完成所有 stream 的处理。`h2mux::craft` 持有 TLS 传输层的 `shared_ptr`，`frame_loop` 自动处理后续 CONNECT stream，不经过 `session::diversion()` 分发。

### 3.2 认证流程

TrustTunnel 使用 HTTP Basic Auth 进行客户端认证：

```
客户端                              Prism Server
  │                                      │
  │═══ TLS Handshake (ALPN=h2) ════════>│
  │                                      │
  │── HTTP/2 SETTINGS ──────────────────>│
  │                                      │
  │── HTTP/2 CONNECT ──────────────────>│
  │     :authority: target.com:443       │
  │     Host: target.com                 │
  │     Proxy-Authorization: Basic XXX   │
  │                                      │
  │                                      ├── verify_basic_auth()
  │                                      │     ├── 提取 "Basic " 后的 Base64
  │                                      │     ├── 对每个用户计算 Base64(username:password)
  │                                      │     └── 比对
  │                                      │
  │                                      ├── 认证成功 → 200 OK
  │                                      └── 认证失败 → 407 Proxy Auth Required
```

**安全措施**：

- 凭据长度超过 192 字节时跳过比对，防止栈缓冲区溢出（`EVP_EncodeBlock` 使用 256 字节栈缓冲区）
- Base64 编码使用 OpenSSL 的 `EVP_EncodeBlock`，确保标准 Base64 编码
- 逐用户比对而非预先构建查找表（因为 Basic Auth 的 Base64 编码包含用户名和密码的组合）

### 3.3 trusttunnel_resolver（地址解析回调）

TrustTunnel 通过 `address_resolver` 回调从 HTTP/2 CONNECT 请求头提取目标地址：

```cpp
auto trusttunnel_resolver = [](int32_t, const h2_headers &headers)
    -> h2_stream_info
{
    // 1. 从 Host 头判断 stream 类型
    if (host.find("_check") != npos) → stream_type::check
    if (host.find("_udp2") != npos)  → stream_type::udp
    if (host.find("_icmp") != npos)  → stream_type::icmp
    else                             → stream_type::tcp

    // 2. 从 :authority 解析 host:port
    auto colon = authority.rfind(':');
    info.host = authority.substr(0, colon);
    info.port = parse_uint16(authority.substr(colon + 1));
    info.valid = true;
};
```

**stream 类型路由规则**：

| Host 后缀 | stream 类型 | 行为 |
|-----------|-------------|------|
| `_check` | `check` | 健康检查：回复 200 后关闭 stream |
| `_udp2` | `udp` | UDP 代理：创建 parcel 数据报管道 |
| `_icmp` | `icmp` | ICMP 代理（后续迭代，暂按 TCP 处理） |
| 无特殊后缀 | `tcp` | TCP 代理：创建 duct 双向转发 |

### 3.4 网络类型与拥塞控制

| 配置 | 选项 | 说明 |
|------|------|------|
| `network` | `tcp` / `udp` / `both` | 传输网络类型（HTTP/2 或 HTTP/3） |
| `congestion` | `cubic` / `bbr` / `new_reno` | 拥塞控制算法（默认 BBR） |

注：当前实现仅支持 TCP（HTTP/2）模式。UDP（HTTP/3/QUIC）模式为后续迭代计划。

## 4. 数据流图

### 4.1 完整连接生命周期

```
Client                          Prism Server                    Upstream
  │                                  │                              │
  │═══ TLS Handshake (ALPN=h2) ════>│                              │
  │                                  │                              │
  │── HTTP/2 SETTINGS ─────────────>│── HTTP/2 SETTINGS ──────────>│
  │                                  │                              │
  │── CONNECT target.com:443 ──────>│                              │
  │   Proxy-Auth: Basic dXNlcjpwYXNz│                              │
  │                                  │                              │
  │                                  ├── verify_basic_auth()        │
  │                                  │   auth OK                    │
  │                                  │                              │
  │<── HTTP/2 200 OK ───────────────│                              │
  │                                  │                              │
  │                                  │── connect ──────────────────>│
  │                                  │<── established ──────────────│
  │                                  │                              │
  │═══ DATA (HTTP/2 frames) ═══════>│═══ duct forward ════════════>│
  │<══ DATA (HTTP/2 frames) ════════│<═══ duct forward ════════════│
  │                                  │                              │
  │── CONNECT udp2.target.com:443 ─>│                              │
  │                                  │                              │
  │<── 200 OK ──────────────────────│── parcel ───────────────────>│
  │═══ DATA ═══════════════════════>│═══ parcel relay ════════════>│
  │                                  │                              │
  │── CONNECT check.health:443 ────>│                              │
  │<── 200 OK + RST_STREAM ─────────│                              │
  │                                  │                              │
  │── RST_STREAM (close stream) ───>│── close upstream ───────────>│
```

### 4.2 craft 内部数据流

```
                   ┌─────────────────────────────────────────┐
                   │           h2mux::craft                   │
                   │                                          │
 TLS Transport ───>│  frame_loop()                           │
 (encrypted)       │    │                                     │
                   │    ├── async_read_some() → raw bytes     │
                   │    ├── nghttp2_session_mem_recv()        │
                   │    │       │                              │
                   │    │       ├── on_begin_headers()        │
                   │    │       │     └── detect CONNECT      │
                   │    │       │        → create h2_pending  │
                   │    │       │                              │
                   │    │       ├── on_header()               │
                   │    │       │     └── collect :authority  │
                   │    │       │        Host, Proxy-Auth     │
                   │    │       │                              │
                   │    │       ├── on_frame_recv()           │
                   │    │       │     └── HEADERS complete    │
                   │    │       │        → handle_connect()   │
                   │    │       │           → resolver_()     │
                   │    │       │                              │
                   │    │       ├── on_data()                 │
                   │    │       │     ├── ducts_[id]          │
                   │    │       │     │   → duct.on_mux_data  │
                   │    │       │     └── parcels_[id]        │
                   │    │       │         → parcel.on_mux_data│
                   │    │       │                              │
                   │    │       └── on_stream_close()         │
                   │    │             → duct.on_mux_fin()     │
                   │    │             → parcel.close()        │
                   │    │                                     │
                   │    └── send_pending() → async_write()    │
                   │                                          │
                   │  send_loop()                             │
                   │    └── send_channel_ → nghttp2_submit    │
                   │         → send_pending() → async_write() │
                   │                                          │
                   │  ┌─── duct (TCP stream) ────┐            │
                   │  │  upstream ↔ on_mux_data   │            │
                   │  └───────────────────────────┘            │
                   │  ┌─── parcel (UDP stream) ──┐            │
                   │  │  upstream ↔ on_mux_data   │            │
                   │  └───────────────────────────┘            │
                   └─────────────────────────────────────────┘
```

## 5. 配置选项

### 5.1 JSON 配置结构

```json
{
  "stealth": {
    "trusttunnel": {
      "server_names": ["www.example.com"],
      "certificate": "/path/to/cert.pem",
      "private_key": "/path/to/key.pem",
      "users": [
        { "username": "user1", "password": "password1" }
      ],
      "network": "both",
      "congestion": "bbr",
      "handshake_timeout_ms": 5000,
      "idle_timeout_ms": 30000
    }
  }
}
```

### 5.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `server_names` | string[] | 必填 | SNI 白名单，只有匹配的 ClientHello 才会执行 TrustTunnel 认证 |
| `certificate` | string | 必填 | TLS 证书文件路径（PEM 格式） |
| `private_key` | string | 必填 | TLS 私钥文件路径（PEM 格式） |
| `users` | object[] | 必填 | 用户认证列表，每个条目包含 `username` 和 `password` |
| `network` | string | `"both"` | 传输网络类型：`"tcp"`（HTTP/2）、`"udp"`（HTTP/3）、`"both"` |
| `congestion` | string | `"bbr"` | 拥塞控制算法：`"cubic"`、`"bbr"`、`"new_reno"` |
| `handshake_timeout_ms` | uint32 | `5000` | TLS 握手超时（毫秒） |
| `idle_timeout_ms` | uint32 | `30000` | 空闲连接超时（毫秒） |

## 6. 与其他模块的交互

### 6.1 与 h2mux 多路复用模块的关系

TrustTunnel 是 `h2mux::craft` 的主要使用者。TrustTunnel scheme 创建 `craft` 实例时注入自定义的 `trusttunnel_resolver` 回调，用于从 HTTP/2 CONNECT 请求头解析目标地址和 stream 类型。

```
TrustTunnel scheme
  │
  └── h2mux::craft(transport, router, cfg, trusttunnel_resolver)
        │
        ├── nghttp2 session 初始化
        ├── frame_loop() 接收 HTTP/2 帧
        ├── address_resolver 回调 → trusttunnel_resolver
        ├── activate_stream()
        │     ├── TCP → make_duct() → connect::async_forward()
        │     ├── UDP → make_parcel()
        │     └── Check → respond 200 + RST_STREAM
        └── send_loop() 发送 HTTP/2 帧
```

### 6.2 与 transport 层的关系

TrustTunnel 使用 **Path A TLS 终结模式**：

1. `connect::peel_to_raw()` 剥离传输层到原始 TCP socket
2. `transport::wrap_with_preview()` 包装预读数据
3. `transport::encrypted::ssl_handshake()` 执行标准 TLS 握手，协商 ALPN=h2
4. 握手成功后，`transport::encrypted` 作为 TLS 传输层传递给 `h2mux::craft`

### 6.3 与 connect 模块的关系

TrustTunnel 的 TCP stream 通过 `connect::async_forward()` 建立到上游目标的连接：

```
h2mux::craft::activate_stream(stream_id)
  │
  ├── connect::async_forward(router, host, port)
  │     ├── DNS 解析
  │     ├── TCP 连接
  │     └── 返回 socket
  │
  ├── transport::make_reliable(socket)
  └── make_duct(stream_id, craft, reliable_transport)
        └── duct::start() → 双向转发
```

### 6.4 与 Stealth 层管道的关系

```
probe (预读 24 字节)
  └── detect_tls() → true
        └── stealth_scheme 管道
              ├── Tier 0: sniff() → TrustTunnel 不响应
              ├── Tier 1: verify() → TrustTunnel 不响应
              └── Tier 2: guess() → 返回 score=100
                    └── scheme::handshake() 执行
```

### 6.5 ALPN 协商

TrustTunnel 在 TLS 握手前设置 ALPN 为 `h2`：

```cpp
SSL_CTX_set_alpn_protos(ctx, "\x2h2", 3);
```

握手完成后验证 ALPN 协商结果。如果客户端不支持 h2（ALPN 不匹配），返回 `detected=tls` 并将 TLS 传输层交给上层处理标准 HTTPS 流量。
