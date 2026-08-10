# 8 协议接入方案（VMess / sing-mux / gun / ECH / WS / Hysteria2 / TUIC / XHTTP）

> 状态：规划 → 逐协议实施。每个协议闭环：**实现 → 单测+模拟客户端跑通 → SNI/配置 → 性能逻辑优化 → 下一协议**。
> 参考实现：`E:\mihomo-Meta\mihomo-Meta`（服务端）、`sing-vmess@v0.2.5`、`sing-mux@v0.3.9`、`sing-quic`。

## 实施结果（2026-08-09）

| 协议 | 状态 | 测试 | 全量回归 |
|------|:---:|:---:|:---:|
| 1. VMess | ✅ 完成 | 18 | 2218/2218 |
| 2. sing-mux StreamRequest 补完 | ✅ 完成（修复 3 个既有 h2 bug） | 8 | 2218/2218 |
| 3. gRPC gun | ✅ 完成 | 13 | 2218/2218 |
| 4. ECH 服务端 | ✅ 完成（BoringSSL SSL_ECH_KEYS，删除旧空壳） | 18 | 2218/2218 |
| 5. WebSocket | ✅ 完成 | 14 | 2218/2218 |
| 6. QUIC 基建 | ⏳ 进行中（ngtcp2 已引入构建，server 封装源码在 `src/prism/net/transport/quic/`，API 适配待完成，暂不参与构建） | — | — |
| 7. Hysteria2 | ✅ 协议逻辑层（codec + varint + UDP 分片解析） | 7 | 2218/2218 |
| 8. TUIC v5 | ✅ 协议逻辑层（命令帧 + 地址 + 认证帧） | 6 | 2218/2218 |
| 9. XHTTP | ✅ stream-one（h2） | 7 | 2218/2218 |

**QUIC 后续工作**：完成 `quic/server.cpp` 的 ngtcp2 v1.25 API 适配（回调签名、derive_and_install、path_storage），联调真实 QUIC 握手后接入 Hysteria2/TUIC 的 stream/datagram。

**最终回归修复**（本轮）：TLS 握手全局 30 秒超时（`encrypted::ssl_handshake`）、VMess 握手 30 秒 deadline、gun/xhttp accept 失败唤醒、ws raw 缓冲 4MB 上限、mux channel 容量 512、h2mux UDP pending 数据即时处理。

## 统一接入模板（对齐现有架构）

```
probe 识别 ─→ make_protocol_handler(type) ─→ <proto>::handler::run()
                                                 ├─ codec/     线格式编解码（纯函数，零 I/O）
                                                 ├─ handler/   conn 对象（继承 transport::transmission 装饰器）
                                                 └─ config/    配置结构 + glaze 映射
```

| 步骤 | 位置 |
|------|------|
| 1. `protocol_type` 枚举 | `include/prism/net/connection/types.hpp` |
| 2. probe 首包检测 | `src/prism/handshake/recognition/probe/analyzer.cpp` |
| 3. 工厂分支 | `src/prism/protocol/handler.cpp` |
| 4. 协议模块 | `include/prism/protocol/<name>/` + `src/prism/protocol/<name>/`（handler/codec/config/constants） |
| 5. 配置聚合 | `include/prism/runtime/config.hpp`（protocol::config）+ `include/prism/settings/settings.hpp`（glaze） |
| 6. 伪装方案（如有） | `include/prism/handshake/<name>/scheme.hpp` + `src/prism/handshake/registry.cpp`（register_schemes） |
| 7. 测试 | `tests/protocol/<name>/` + `tests/handshake/<name>/`，`prism_add_test` 宏 |

**编码约束**：函数参数 ≤2（超 3 用 struct 收敛）、函数体 ≤120 行、lambda ≤10 行、纯协程无阻塞、Doxygen 中文注释、hot path 用 PMR。

---

## 1. VMess（代理协议）

- **类型**：非 TLS 外层协议，probe 首包无法唯一识别（首字节随机）。
- **接入**：probe 排除法 fallback 前增加 VMess 特征探测？**不行**——VMess 首包随机。方案：**fallback 层**，SS2022 与 VMess 无法区分，配置按 `ss.vmess` 优先级尝试：先 SS2022 salt 校验（失败）→ VMess 认证头解析（失败）→ 关闭。在 handler 工厂中 SS2022 与 VMess 共享 `shadowsocks` 探测结果，由 session 层重试逻辑完成多协议尝试。
  - 简化决策：SS2022 已实现 `probe::detect` 返回 `shadowsocks`；新增枚举 `vmess`，probe 保持 `shadowsocks`；`session::diversion` 对 `shadowsocks` 结果先尝试 VMess 认证头（16B AES-ECB 解密 CRC 校验），命中则走 vmess handler。实现为：`probe` 不改，**在 session 分发前增加 vmess pre-check**（读 16B，AES-128-ECB 解密 CRC32+时间窗校验）。
  - 备选（更干净）：probe 需要更多字节。VMess 客户端首包连续字节无法区分 SS2022。采用前者。
- **模块**：`protocol/vmess/`：`codec/kdf.hpp`（嵌套 HMAC-SHA256 KDF）、`codec/auth.hpp`（AES-ECB authID + CRC32）、`codec/header.hpp`（指令头 38+H 编解码）、`codec/chunk.hpp`（AEAD/legacy chunk 流）、`handler/conn.hpp`（transmission 装饰器）、`handler/handler.cpp`（TCP/UDP/MUX 分发）、`config.hpp`、`constants.hpp`。
- **crypto 依赖**：BoringSSL 已有（MD5/HMAC-MD5/HMAC-SHA256/AES-128-ECB/AES-128-GCM/AES-128-CFB/ChaCha20Poly1305/SHAKE128/SHA-256）；CRC32/FNV-1a 手写（各 ~20 行）。
- **响应头**：AEAD 双段 GCM（respKey=SHA256(requestKey)[:16]，respNonce=SHA256(requestNonce)[:16]），4B 内容 `{responseHeader, option, 0, 0}`；legacy 用 CFB。
- **命令**：TCP(1) → forward_pipeline；UDP(2) → async_associate 模式（chunk 即数据报，2B 长度前缀）；MUX(3) → v2ray mux 帧循环 + special FQDN 分流（`v1.mux.cool:666`、`sp.mux.sing-box.arpa:444`、`sp.packet-addr.v2fly.arpa`）。
- **v2ray mux**：`protocol/multiplex/v2mux/`（frame: len2+id2+status+option+[network]+[port2+atyp+addr]+dataLen2+data；NEW/KEEP/END/KEEPALIVE；UDP 流内包 2B len 前缀）。
- **SNI**：无（纯 TCP）。配置 `protocol.vmess.enable_tcp/udp` + `users[]`（uuid + alterID 兼容字段，默认 0）。
- **测试**：`tests/protocol/vmess/`——KDF 向量、authID 加解密往返、指令头编解码、chunk AEAD 往返、模拟客户端（手工构造 mihomo 兼容首包）→ echo 跑通。

## 2. sing-mux StreamRequest 补完（多路复用）

- **现状**：`h2mux/control.cpp:604` 未实现 StreamRequest 解析。
- **内容**：二进制（非 JSON）`[flags 2B][addrType 1B][addr][port 2B]`，flags bit0=UDP、bit1=PacketAddr；addrType：0x01 IPv4 / 0x03 域名 / 0x04 IPv6。StreamResponse：`[status 1B][错误时 vstring]`，成功时首个写前置 0x00。
- **会话头**：`[version 1B][protocol 1B: 0=smux 1=yamux 2=h2mux][padding flag][paddingLen 2B][padding]`（v1）。
- **接入**：`h2mux/control.cpp` 解析 StreamRequest；UDP 模式处理（非 PacketAddr：2B len 前缀包流；PacketAddr：addrType+addr+len+payload）。
- **测试**：构造 sing-mux 帧流模拟客户端，验证 stream open/close、UDP 包流。

## 3. gRPC (gun) 伪装（TLS 伪装方案）

- **性质**：独立方案（自带 TLS + HTTP/2），category=facade。
- **接入**：`handshake/gun/`：`scheme.cpp`（注册 "gun"）、HTTP/2 服务端用 nghttp2（已有依赖）。
  - 端点 `POST /GunService/Tun`、`Content-Type: application/grpc`。
  - 帧：`[0x00][u32 BE len][0x0A][uvarint][payload]` 手工编解码（无需 protobuf 库）。
  - h2 层：nghttp2 server session 封装为 `transport::transmission` 装饰器。
- **SNI**：`snis()` 返回配置的 SNI 列表，route_table 自动接入。
- **配置**：`stealth.gun`：`server_names[]`、`path`、`service_name`。
- **测试**：模拟 gun 客户端（构造 grpc 帧 + h2 请求）→ VLESS/Trojan echo。

## 4. ECH 服务端解密（TLS 伪装）

- **现状**：`handshake/ech/util/decrypt.cpp` 空壳。
- **接入**：BoringSSL 原生 API：`SSL_ECH_KEYS_new/add/set1_ech_keys` + `SSL_CTX_set1_ech_keys`。配置 `stealth.ech`：`keys`（PEM ECH KEYS 或 base64 config）、`server_names[]`。
- **流程**：TLS 握手时 BoringSSL 自动识别 0xfe0d 扩展 → HPKE 解密 inner CH → 取 inner SNI/ALPN 继续。Prism 侧：scheme 注册 "ech"（Tier 1 verify：检测 ClientHello 是否含 ECH 扩展 0xfe0d），handshake 用带 ECH keys 的 SSL_CTX。
- **密钥生成**：`util/keygen.cpp`（X25519 + ECHConfig 构造，draft-18 布局）。
- **测试**：生成 ECH key → 模拟客户端（BoringSSL 客户端带 ECH config）→ 跑通 + inner SNI 路由。

## 5. WebSocket 伪装（TLS 伪装）

- **性质**：独立方案（WS over TLS），承载内层 VLESS/Trojan。
- **接入**：`handshake/ws/`：`scheme.cpp`（注册 "ws"）、WS 升级握手（SHA1(base64(key)+GUID)）、帧编解码（服务端不 mask，opcode 0x2 binary、ping/pong/close 控制帧）、升级后连接封装 `transport::transmission` 直接喂给内层协议 handler。
- **HTTP 解析**：手写最小 HTTP/1.1 请求解析（GET + Upgrade: websocket），或复用 http codec 的 parser。
- **SNI**：`snis()` 返回配置 SNI；配置 `stealth.ws`：`server_names[]`、`path`。
- **测试**：模拟 WS 客户端（握手 + 帧）→ VLESS echo；mask 解码验证。

## 6. QUIC 基建（Hysteria2 / TUIC 前置）

- **依赖引入**：ngtcp2（FetchContent，C 库）+ BoringSSL QUIC API（SSL_QUIC_METHOD 已支持）。
- **封装**：`net/transport/quic/`：QUIC server 封装（connection 生命周期、stream 抽象、datagram 收发）暴露 `transport::transmission` 兼容接口 + datagram 通道。
- **验证**：ngtcp2 examples 或 ngtcp2+openssl 对拍；asio 集成测试。

## 7. Hysteria2（QUIC 代理协议）

- **接入**：`protocol/hysteria2/`（独立方案，自带 QUIC+TLS）：
  - 认证：`POST https://hysteria/auth`，`Hysteria-Auth` 头，响应状态码 **233** + `Hysteria-UDP/Hysteria-CC-RX/Hysteria-Padding`。
  - TCP：QUIC bidi stream，`0x401 varint + AddrLen varint + socksaddr + PaddingLen + padding`；响应 `status 1B + MsgLen + msg + padding`。
  - UDP：QUIC datagram，`SessionID u32 + PacketID u16 + FragID u8 + FragCount u8 + AddrLen varint + socksaddr + data`；分片重组（MTU 1197，LRU 10s）。
  - obfs：salamander（BLAKE2b-256(password||salt) XOR），BLAKE2b 需要新依赖（libb2 或 BoringSSL 无 BLAKE2……BoringSSL 无 BLAKE2b。需要 blake2 库或手写）。**注意**：项目已有 BLAKE3。BLAKE2b 需引入 `blake2` 单头实现或 FetchContent。
  - 拥塞控制：BBR/Brutal —— ngtcp2 自带 CC 接口，初期用默认。
- **SNI**：scheme "hysteria2" 注册 + SNI 路由；配置 `stealth.hysteria2`：`users[]`（password）、`server_names[]`、`obfs_password`、`up/down`。
- **测试**：模拟 hysteria2 客户端（HTTP/3 认证 + QUIC stream/datagram）→ echo。

## 8. TUIC v5（QUIC 代理协议）

- **接入**：`protocol/tuic/`（独立方案）：
  - 认证：uni stream `[VER 0x05][TYPE 0x00][UUID 16B][TOKEN 32B]`，TOKEN = `SSL_export_keying_material(label=UUID, context=password, 32)`。
  - Connect：bidi stream `[VER][TYPE 0x01][ATYP][ADDR][PORT 2B]`；ATYP 0=domain/1=IPv4/2=IPv6/0xff=None。
  - Packet：`[VER][0x02][ASSOC_ID u16][PKT_ID u16][FRAG_TOTAL u8][FRAG_ID u8][SIZE u16][ATYP][ADDR][PORT][DATA]`；native 走 datagram、quic 模式走 uni stream；分片重组。
  - Dissociate / Heartbeat。
  - 错误码：0xfffffff0-f3（QUIC app error）。
  - **v4 兼容**（可选）：BLAKE3 token（已有库）。
- **SNI**：scheme "tuic" 注册；配置 `stealth.tuic`：`users[]`（uuid+password）、`server_names[]`、`congestion`。
- **测试**：模拟 tuic v5 客户端 → echo。

## 9. XHTTP（伪装方案）

- **性质**：先做 h1/h2（mihomo 服务端同款，不支持 h3），后续 QUIC 就绪后补 h3。
- **接入**：`handshake/xhttp/`（复用 nghttp2）：
  - 路径：`POST /path`（stream-one）、`POST/GET /path/{sessionID}`（stream-up）、`POST /path/{sessionID}/{seq}`（packet-up）。
  - 响应头：`Content-Type: text/event-stream`、`X-Accel-Buffering: no`、CORS。
  - 会话管理：sessionID（32 hex）→ 上行队列 → 下行流汇聚；孤儿 30s 回收。
  - 模式：auto/stream-one/stream-up/packet-up。
- **SNI**：scheme "xhttp" 注册；配置 `stealth.xhttp`：`server_names[]`、`path`。
- **测试**：模拟 xhttp 客户端（h2 POST/GET 流）→ VLESS echo。

---

## 依赖清单

| 协议 | 新依赖 | 说明 |
|------|--------|------|
| VMess | 无 | BoringSSL 全量覆盖 + CRC32/FNV 手写 |
| sing-mux | 无 | 解析补完 |
| gun | 无 | nghttp2 已有 |
| ECH | 无 | BoringSSL ECH API |
| WS | 无 | SHA1 已有 |
| Hysteria2 | **ngtcp2 + BLAKE2b** | QUIC + blake2 单头库 |
| TUIC v5 | **ngtcp2** | 与 h2 共享 QUIC |
| XHTTP | 无（h1/h2） | nghttp2 |

## 实施顺序

1. VMess → 2. sing-mux → 3. gun → 4. ECH → 5. WS → 6. QUIC 基建 → 7. Hysteria2 → 8. TUIC → 9. XHTTP（QUIC 就绪后补 h3）
