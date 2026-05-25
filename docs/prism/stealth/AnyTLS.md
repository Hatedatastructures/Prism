# AnyTLS 伪装方案文档

## 1. 模块概述

### 1.1 协议背景

AnyTLS 是一种基于标准 TLS 的伪装协议，使用真实 TLS 证书完成握手，在应用层通过简单的密码认证实现代理功能。AnyTLS 的核心特性是内置了应用层多路复用，允许多个独立的代理连接（stream）复用同一个 TLS 连接，大幅降低握手开销和连接数。

AnyTLS 的设计目标是最大化 TLS 流量的"合法性"：从被动检测器的角度看，AnyTLS 连接与任何正常的 HTTPS 连接完全一致（标准证书、标准握手、标准加密），唯一的区别在于应用数据的内容。

Prism 中的 AnyTLS 实现参考了以下规范：

- **AnyTLS 协议规范** -- https://github.com/anytls/anytls
- **RFC 8446** -- TLS 1.3 协议
- **RFC 5246** -- TLS 1.2 协议

### 1.2 核心设计思想

AnyTLS 采用 **Path A TLS 终结模式** + **应用层多路复用** 的组合架构：

1. **标准 TLS 终结**：服务端使用配置的真实 TLS 证书完成握手，客户端看到的是完全合法的 TLS 连接
2. **应用层认证**：TLS 握手完成后，客户端发送 `SHA-256(password)` 进行身份验证，密码本身不在网络上传输
3. **内置多路复用**：认证成功后进入 AnyTLS 会话阶段，支持通过 SYN/PSH/FIN 命令创建、传输和关闭多个独立 stream
4. **流量填充**：通过 padding_factory 支持 per-packet 填充方案，用于隐藏流量时序和大小特征
5. **ECH 叠加**（可选）：可叠加 ECH (Encrypted Client Hello) 加密 SNI，进一步增强隐蔽性

### 1.3 与其他伪装方案的对比

| 特性 | Reality | AnyTLS | TrustTunnel |
|------|---------|--------|-------------|
| 证书来源 | 目标网站合成证书 | 自有真实证书 | 自有真实证书 |
| 认证机制 | X25519 ECDH | SHA-256(password) | HTTP Basic Auth |
| 内置多路复用 | 无 | 有（自定义帧） | 有（HTTP/2 CONNECT） |
| 认证阶段 | 握手阶段 | 应用数据阶段 | 应用数据阶段 |
| SNI 保护 | 无（使用目标 SNI） | 可选 ECH 加密 | 无 |
| 流量填充 | 无 | padding_factory | 无 |
| 协议协商 | 无 | Settings 交换 | ALPN h2 |

### 1.4 检测层级

AnyTLS 作为 **Tier 2** 方案，无 ClientHello 独占特征。当配置了 ECH 密钥时，在 Tier 1 的 `verify()` 中检测 ECH 扩展的存在：

- **Tier 1 verify**：如果 ClientHello 包含 ECH 扩展且配置了 `ech_key`，返回 score=300
- **Tier 2 guess**：返回固定 score=100，依赖 SNI 匹配

## 2. 架构设计

### 2.1 文件结构

```
include/prism/stealth/anytls/
├── config.hpp             # AnyTLS 配置（证书、SNI、用户、ECH、padding）
├── scheme.hpp             # stealth_scheme 子类（方案注册与握手入口）
├── padding.hpp            # padding 方案解析器 + 大小生成
└── mux/
    ├── frame.hpp          # 帧格式定义（7B header）+ 命令枚举
    ├── session.hpp        # 多路复用会话管理（recv_loop + stream 分发）
    └── transport.hpp       # 单个 stream 的 transmission 适配

src/prism/stealth/anytls/
├── scheme.cpp             # scheme 实现（TLS 握手 + 认证 + stream 管理）
├── padding.cpp            # padding 解析和大小生成实现
└── session.cpp            # 会话管理实现（帧收发 + stream 生命周期）
```

### 2.2 组件关系

```
  scheme (stealth_scheme 入口)
    │
    ├── handshake() ────────────── TLS 握手 + 认证
    │     ├── ssl_handshake()           标准 TLS 握手（Path A）
    │     ├── 读取 SHA-256(password)    32 字节密码哈希
    │     ├── 读取 padding_len + padding 可选填充
    │     ├── build_user_map()          构建用户查找表
    │     ├── 认证验证                   SHA-256(password) 比对
    │     │
    │     ├── parse_socks_target()       解析 SOCKS 地址（首个 stream）
    │     └── connect::forward()         建立上游连接 + 双向转发
    │
    ├── anytls_session ─────────── 多路复用会话
    │     ├── recv_loop()               接收循环（帧解析 + 命令分发）
    │     ├── write_frame()             帧写入（header + payload）
    │     ├── send_waste_frame()        padding 帧发送
    │     ├── wait_first_stream()       等待首个 stream 就绪
    │     │
    │     └── stream 管理
    │           ├── streams_            stream_id → channel 映射
    │           └── on_new_stream_      新 stream 回调
    │
    ├── anytls_stream_transport ── 单 stream 传输适配
    │     ├── async_read_some()         从 channel 读取
    │     ├── async_write_some()        通过 write_psh 写入
    │     └── close()                   发送 FIN + 重置 channel
    │
    └── padding_factory ────────── 填充方案
          ├── 解析 padding 方案字符串
          └── generate_sizes(pkt)       生成每包 payload 大小列表
```

## 3. 核心组件说明

### 3.1 scheme（方案入口）

`scheme` 类继承 `stealth_scheme`，是 AnyTLS 在 Prism 伪装方案管道中的入口。

- `name()` 返回 `"anytls"`
- `tier()` 返回 `2`
- `unique()` 返回 `false`
- `verify()` 检测 ECH 扩展（如果配置了 `ech_key`）
- `guess()` 返回固定 score=100
- `handshake()` 执行完整流程：TLS 握手 -> 密码认证 -> 创建 session -> 等待首个 stream

**关键设计**：AnyTLS 在 stealth 层内部完成所有 stream 的处理，不经过 `session::diversion()` 分发。每个 stream 通过 `connect::forward()` 建立独立的上游连接。

### 3.2 认证流程

```
客户端                              Prism Server
  │                                      │
  │──── TLS ClientHello ────────────────>│
  │<──── TLS ServerHello + Certificate ──│  (标准 TLS 握手)
  │──── TLS Finished ──────────────────>│
  │<──── TLS Finished ──────────────────│
  │                                      │
  │──── SHA-256(password) [32B] ────────>│  (密码哈希，非明文密码)
  │──── padding_len [2B BE] ────────────>│
  │──── padding [variable] ─────────────>│
  │                                      │
  │                                      ├── build_user_map()
  │                                      ├── SHA-256(配置密码) 逐一比对
  │                                      │
  │                                      ├── 认证成功 → 创建 anytls_session
  │                                      └── 认证失败 → auth_failed
```

**用户查找表**：预计算每个用户的 `SHA-256(password)` 作为 key，使用 `unordered_map` 进行 O(1) 查找。自定义 `sha256_hash` 哈希函数处理 32 字节 key 的哈希冲突。

### 3.3 frame（帧格式）

AnyTLS 使用 7 字节固定帧头：

```
[cmd:1B][stream_id:4B BE][length:2B BE]
```

**命令枚举**（与 mihomo/anytls 协议规范一致）：

| 命令 | 值 | 方向 | 说明 |
|------|----|------|------|
| `waste` | `0x00` | 双向 | 丢弃帧（padding） |
| `syn` | `0x01` | C->S | 创建新 stream |
| `psh` | `0x02` | 双向 | 数据推送 |
| `fin` | `0x03` | 双向 | 关闭 stream |
| `settings` | `0x04` | C->S | 客户端 Settings |
| `alert` | `0x05` | 双向 | 告警/错误 |
| `update_padding` | `0x06` | S->C | 更新 padding 方案 |
| `synack` | `0x07` | S->C | stream 打开确认（v2+） |
| `heart_req` | `0x08` | 双向 | 心跳请求 |
| `heart_resp` | `0x09` | 双向 | 心跳响应 |
| `server_settings` | `0x0A` | S->C | 服务端 Settings（v2+） |

### 3.4 anytls_session（会话管理）

`anytls_session` 管理完整的 AnyTLS 多路复用会话生命周期。

#### recv_loop 处理流程

```
recv_loop()
  │
  ├── read_exact(7B header)
  ├── frame_header::parse()
  ├── read_exact(payload)
  │
  ├── padding？→ send_waste_frame(pkt_counter_)
  │
  └── switch(cmd)
        ├── settings
        │     ├── 解析 version (v=N)
        │     ├── 解析 padding-md5
        │     │     └── MD5 不匹配 → write_frame(update_padding)
        │     └── v>=2 → write_frame(server_settings)
        │
        ├── syn
        │     ├── 创建 channel → streams_[stream_id]
        │     ├── 首个 stream？→ 记录 first_stream_id_
        │     └── 后续 stream？→ pending_syn_streams_.insert(stream_id)
        │
        ├── psh
        │     ├── 首个 stream 首个 PSH？
        │     │     ├── 保存 preread 数据
        │     │     ├── 发送到 channel
        │     │     └── first_stream_waiter_.cancel()
        │     │
        │     ├── 后续 stream 首个 PSH？
        │     │     ├── 触发 on_new_stream_ 回调
        │     │     └── write_synack() (v2+)
        │     │
        │     └── 已有 stream → channel.try_send(payload)
        │
        ├── fin → channel.try_send(error) → erase stream
        ├── alert → 同 fin
        ├── heart_req → write_frame(heart_resp)
        └── waste → 丢弃
```

#### 版本协商（v2+）

AnyTLS 支持 v1 和 v2 版本协商：

- v1：无 server_settings、无 synack、无 padding-md5 比对
- v2：增加 `server_settings`（`"v=2\nserver=prism\n"`）、`synack` 确认、`padding-md5` 比对和不匹配时自动发送 `update_padding`

### 3.5 anytls_stream_transport（stream 传输适配）

`anytls_stream_transport` 将单个 AnyTLS stream 适配为 `transport::transmission` 接口，使其可以无缝接入 Prism 的 `connect::forward()` 隧道转发。

- **读取方向**：从 `concurrent_channel` 获取数据块，支持 pending 缓冲区
- **写入方向**：通过 `anytls_session::write_psh()` 发送 PSH 帧
- **关闭**：发送 FIN 帧 + 重置 channel

### 3.6 padding_factory（填充方案）

#### 填充方案格式

```
stop=N                  # 前 N 个包做 padding，之后停止
0=30-30                 # 包 0：固定 30 字节
1=100-400               # 包 1：随机 100-400 字节
2=400-500,c,500-1000    # 包 2：400-500 字节 + 实际 payload + 500-1000 字节
3=9-9,500-1000          # 包 3：9 字节 + 500-1000 字节
```

- `min-max`：生成 `[min, max]` 范围内的密码学安全随机整数
- `c`：CheckMark，该位置放入实际 payload
- MD5 哈希：用于 Settings 交换阶段的客户端/服务端方案比对

## 4. 数据流图

### 4.1 完整连接生命周期

```
Client                          Prism Server                    Upstream
  │                                  │                              │
  │═══ TLS Handshake ═══════════════>│                              │
  │═══════════════════════════════════│                              │
  │                                  │                              │
  │── SHA-256(password) + padding ──>│                              │
  │                                  ├── auth OK                    │
  │                                  │                              │
  │── Settings (v=2) ───────────────>│                              │
  │                                  ├── server_settings (v=2) ───>│
  │                                  │                              │
  │── SYN (stream_id=1) ───────────>│                              │
  │── PSH (stream_id=1, SOCKS addr)>│                              │
  │                                  ├── parse_socks_target()       │
  │                                  │                              │
  │                                  │── connect ──────────────────>│
  │                                  │<── established ──────────────│
  │                                  │                              │
  │<── SYNACK (stream_id=1) ────────│                              │
  │                                  │                              │
  │════ PSH data ══════════════════>│═══ forward ═════════════════>│
  │<═══ PSH data ══════════════════│<═══ forward ═════════════════│
  │                                  │                              │
  │── SYN (stream_id=3) ───────────>│                              │
  │── PSH (stream_id=3, SOCKS addr)>│                              │
  │                                  ├── parse_socks_target()       │
  │                                  │── connect ──────────────────>│
  │                                  │                              │
  │════ 多 stream 并发数据 ════════>│═══ 各自独立转发 ═════════════>│
  │<════════════════════════════════│<═════════════════════════════│
  │                                  │                              │
  │── FIN (stream_id=1) ──────────>│── close upstream ───────────>│
  │                                  │                              │
  │── heart_req ──────────────────>│                              │
  │<── heart_resp ─────────────────│                              │
```

### 4.2 Session 内部数据流

```
                   ┌─────────────────────────────────────┐
                   │         anytls_session               │
                   │                                      │
 TLS Transport ───>│  recv_loop()                        │
 (encrypted)       │    │                                 │
                   │    ├── parse header ──────────┐      │
                   │    ├── read payload           │      │
                   │    │                          │      │
                   │    │  [settings] ──> version negotiation
                   │    │  [syn] ──────> create channel    │
                   │    │  [psh] ──────> channel.try_send()│
                   │    │  [fin] ──────> channel.reset()   │
                   │    │  [waste] ────> discard            │
                   │    │                          │      │
                   │    └── padding: send_waste ───┘      │
                   │                                      │
                   │  ┌─── stream 1 ──── channel ───┐     │
                   │  │   stream_transport           │     │
                   │  │   read ← channel             │     │
                   │  │   write → write_psh()        │     │
                   │  └──────────────────────────────┘     │
                   │                                      │
                   │  ┌─── stream 3 ──── channel ───┐     │
                   │  │   stream_transport           │     │
                   │  │   read ← channel             │     │
                   │  │   write → write_psh()        │     │
                   │  └──────────────────────────────┘     │
                   └─────────────────────────────────────┘
```

## 5. 配置选项

### 5.1 JSON 配置结构

```json
{
  "stealth": {
    "anytls": {
      "server_names": ["www.example.com"],
      "certificate": "/path/to/cert.pem",
      "private_key": "/path/to/key.pem",
      "users": [
        { "username": "user1", "password": "password1" },
        { "username": "user2", "password": "password2" }
      ],
      "ech_key": "",
      "padding_scheme": "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000",
      "handshake_timeout_ms": 5000,
      "idle_session_timeout_ms": 30000
    }
  }
}
```

### 5.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `server_names` | string[] | 必填 | SNI 白名单，只有匹配的 ClientHello 才会执行 AnyTLS 认证 |
| `certificate` | string | 必填 | TLS 证书文件路径（PEM 格式），必须为合法证书 |
| `private_key` | string | 必填 | TLS 私钥文件路径（PEM 格式） |
| `users` | object[] | 必填 | 用户认证列表，每个条目包含 `username` 和 `password` |
| `ech_key` | string | `""` | ECH 密钥（base64 编码），可选，用于叠加 ECH 加密 ClientHello SNI |
| `padding_scheme` | string | `""` | Padding 方案字符串，为空时不做 padding |
| `handshake_timeout_ms` | uint32 | `5000` | TLS 握手超时（毫秒） |
| `idle_session_timeout_ms` | uint32 | `30000` | 空闲会话超时（毫秒） |

## 6. 与其他模块的交互

### 6.1 与 transport 层的关系

AnyTLS 使用 **Path A TLS 终结模式**：

1. `connect::peel_to_raw()` 将传输层剥离到原始 TCP socket
2. `transport::wrap_with_preview()` 包装预读数据
3. `transport::encrypted::ssl_handshake()` 执行标准 TLS 握手
4. 握手成功后，`transport::encrypted` 作为 TLS 传输层传递给 `anytls_session`

### 6.2 与 connect 模块的关系

每个 AnyTLS stream 通过 `connect::forward()` 建立到上游代理目标的连接：

```
anytls_stream_transport (读/写)
    │
    ├── parse_socks_target() → 解析 SOCKS 地址（IPv4/Domain/IPv6）
    │
    └── connect::forward(session_ctx, "AnyTLS", target, stream_transport)
          ├── connect::dial() → 路由选择 + 连接建立
          └── connect::tunnel() → 双向透明转发
```

### 6.3 与 session 层的关系

AnyTLS 在 stealth 层内部完成所有 stream 处理，`handshake()` 返回 `detected=tls`，`session` 层不再进行协议分派。`anytls_session` 持有 TLS 传输层的 `shared_ptr`，生命周期独立于 `session` 对象。

### 6.4 与 memory 模块的关系

- `user_map_type` 使用 `memory::string` 和自定义 `sha256_hash` 哈希函数
- `padding_factory` 使用 `memory::unordered_map` 和 `memory::string`
- `anytls_session` 的 streams 使用 `std::unordered_map` + `concurrent_channel`

### 6.5 与 Stealth 层管道的关系

```
probe (预读 24 字节)
  └── detect_tls() → true
        └── stealth_scheme 管道
              ├── Tier 0: sniff() → AnyTLS 不响应
              ├── Tier 1: verify() → 检测 ECH 扩展（如果配置了 ech_key）
              └── Tier 2: guess() → 返回 score=100
                    └── scheme::handshake() 执行
```
