# Reality 协议文档

## 1. 协议概述

### 1.1 协议背景

Reality 是一种 TLS 伪装方案，旨在将代理流量伪装为正常的 TLS 1.3 连接以对抗深度包检测（DPI）。与传统的 TLS 伪装方案不同，Reality 不依赖自签名证书，而是直接使用目标网站的真实证书进行握手，使得被动检测器无法区分 Reality 流量与正常的 HTTPS 流量。

Reality 最初由 XTLS 团队开发，是 Xray-core 的核心特性之一。Prism 中的 Reality 实现参考了以下规范：

- **RFC 8446** — The Transport Layer Security (TLS) Protocol Version 1.3
- **RFC 7748** — Elliptic Curves for Security (X25519)
- **draft-irtf-cfrg-x25519-mlkem768** — X25519MLKEM768 混合密钥交换
- **RFC 5289** — TLS Elliptic Curve Cipher Suites
- **RFC 8032** — Edwards-Curve Digital Signature Algorithm (Ed25519)

### 1.2 核心设计思想

Reality 的核心思想是**双向认证**：

1. **服务端认证客户端**：通过 X25519 密钥交换 + short ID 验证，确认客户端是合法的代理客户端
2. **客户端认证服务端**：通过 X25519 ECDH 共享密钥计算，确认服务端拥有对应的私钥

如果认证成功，继续内层代理协议（通常为 VLESS）。如果认证失败（非代理客户端连接），服务端将流量透明代理到配置的目标网站（如 `www.microsoft.com:443`），完成完整的标准 TLS 握手。

### 1.3 与传统 TLS 的区别

| 特性 | 标准 TLS | Reality |
|------|----------|---------|
| 证书来源 | 服务端自有证书 | 目标网站真实证书（动态获取或静态配置） |
| 认证机制 | 单向/双向证书认证 | X25519 ECDH + short ID |
| 失败行为 | 拒绝连接（Alert） | 透明代理到 dest 服务器 |
| 指纹特征 | 标准 TLS 指纹 | 与目标网站一致 |
| 扩展字段 | 标准 TLS 扩展 | 额外 reality 扩展（session_id 嵌入） |

### 1.4 密码学原语

| 原语 | 算法 | 规范 | 用途 |
|------|------|------|------|
| 密钥交换 | X25519 (Curve25519) | RFC 7748 | ECDH 共享密钥计算 |
| 混合密钥交换 | X25519MLKEM768 | draft-irtf-cfrg | 抗量子密钥交换（可选） |
| 密钥派生 | HKDF-SHA256 | RFC 5869 | TLS 1.3 密钥派生 |
| 对称加密 | AES-128-GCM | NIST SP 800-38D | TLS 记录加密 |
| 数字签名 | Ed25519 | RFC 8032 | 证书签名（合成证书） |
| 哈希 | SHA-256 | FIPS 180-4 | Transcript hash 计算 |

## 2. TLS 1.3 协议格式

### 2.1 TLS 记录层格式

所有 TLS 消息都封装在 TLS 记录中：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  ContentType  |    Version    |           Length              |
|    (1 byte)   |    (2 bytes)  |          (2 bytes)            |
+---------------+---------------+---------------+---------------+
|                         Payload (Length bytes)                |
|                                                               |
+---------------+---------------+---------------+---------------+
```

**Content Type**：
- `0x14` — ChangeCipherSpec（兼容性，TLS 1.3 中无实际作用）
- `0x15` — Alert（错误或警告）
- `0x16` — Handshake（握手消息）
- `0x17` — ApplicationData（应用数据）

**Version**：TLS 1.0-1.2 使用 `0x0301`-`0x0303`，TLS 1.3 在记录层仍使用 `0x0303`（TLS 1.2 兼容）

**Length**：payload 长度，最大 16384 字节（RFC 8446 Section 5.1）

### 2.2 ClientHello 消息格式

ClientHello 是 TLS 握手的第一个消息，Reality 客户端在其中嵌入认证信息：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  HandshakeType|        Length             |     Version       |
|   (0x01)      |       (3 bytes)           |    (2 bytes)      |
+---------------+---------------+---------------+---------------+
|                          Random (32 bytes)                    |
|                                                               |
+---------------+---------------+---------------+---------------+
|  SessionID Len|              SessionID (1-32 bytes)           |
|   (1 byte)    |        (嵌入 short_id + 认证数据)              |
+---------------+---------------+---------------+---------------+
|     Cipher Suites Length      |       Cipher Suites           |
|      (2 bytes)                |       (variable)              |
+---------------+---------------+---------------+---------------+
| Compression   |    Extensions Length            |  Extensions |
| Methods (1B)  |        (2 bytes)                |  (variable) |
+---------------+---------------+---------------+---------------+
```

### 2.3 关键 TLS 扩展

#### 2.3.1 Server Name Indication (SNI, ext_type=0x0000)

```text
+---------------+---------------+---------------+
|  Ext Type     |  Ext Length   |  Name Type    |
|   (0x0000)    |  (2 bytes)    |  (0x00=host)  |
+---------------+---------------+---------------+
+---------------+---------------+
|  Name Length  |  Server Name  |
|  (2 bytes)    |  (variable)   |
+---------------+---------------+
```

Reality 服务端通过 SNI 判断是否为代理连接：
- SNI 匹配 `server_names` 列表 -> 继续 Reality 认证
- SNI 不匹配 -> 回退到标准 TLS 或 dest 代理

#### 2.3.2 Key Share (ext_type=0x0033)

```text
+---------------+---------------+---------------+
|  Ext Type     |  Ext Length   |  Client Share |
|   (0x0033)    |  (2 bytes)    |  Length (2B)  |
+---------------+---------------+---------------+
+---------------+---------------+---------------+
|  Named Group  |  Key Exchange |  Key Exchange |
|  (2 bytes)    |  Length (2B)  |  (variable)   |
|  0x001D=X25519|               |  (32 bytes)   |
|  0x11EC=X25519|               |               |
|   MLKEM768    |               |               |
+---------------+---------------+---------------+
```

Reality 要求客户端在 key_share 扩展中包含 X25519 公钥（32 字节）。服务端使用此公钥与自己的临时私钥执行 ECDH 计算。

**支持的命名组**：
- `0x001D` — X25519（必须支持）
- `0x11EC` — X25519MLKEM768（混合密钥交换，抗量子）
- `0x0017` — secp256r1
- `0x0018` — secp384r1

#### 2.3.3 Supported Versions (ext_type=0x002B)

```text
+---------------+---------------+---------------+
|  Ext Type     |  Ext Length   |  Versions Len |
|   (0x002B)    |  (2 bytes)    |  (1 byte)     |
+---------------+---------------+---------------+
+---------------+---------------+
|  Version 1    |  Version 2    |  ...
|  (2 bytes)    |  (2 bytes)    |
+---------------+---------------+
```

TLS 1.3 版本号为 `0x0304`。Reality 仅支持 TLS 1.3。

#### 2.3.4 Reality 扩展（嵌入 session_id）

Reality 不使用独立的 TLS 扩展，而是将认证数据嵌入到 `session_id` 字段中：

```text
SessionID 格式（最多 32 字节）:
+-------------------------------+---------------+
|       short_id (0-16 bytes)   |   填充/保留    |
+-------------------------------+---------------+
```

- `short_id`：hex 编码的标识符（0-16 字节），用于区分不同的客户端配置
- 空字符串 `""` 表示接受任意 short_id

### 2.4 ServerHello 消息格式

Reality 服务端生成的 ServerHello 与标准 TLS 1.3 ServerHello 格式一致：

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+---------------+---------------+---------------+---------------+
|  HandshakeType|        Length             |     Version       |
|   (0x02)      |       (3 bytes)           |    (2 bytes)      |
+---------------+---------------+---------------+---------------+
|                          Random (32 bytes)                    |
|                                                               |
+---------------+---------------+---------------+---------------+
|  SessionID Len|            SessionID                          |
|   (1 byte)    |            (1-32 bytes)                       |
+---------------+---------------+---------------+---------------+
|     Cipher Suite (2 bytes)    |  Compression Method (1 byte)  |
+---------------+---------------+---------------+---------------+
|    Extensions Length            |         Extensions          |
|        (2 bytes)               |        (variable)            |
+---------------+---------------+---------------+---------------+
```

**ServerHello 扩展**：
- **key_share (0x0033)**：服务端临时 X25519 公钥（32 字节）
- **supported_versions (0x002B)**：`0x0304`（TLS 1.3）

### 2.5 加密握手消息

TLS 1.3 中，ServerHello 之后的所有握手消息都使用握手密钥加密：

```text
Encrypted Handshake Records:
+---------------------------------------------------------------+
|  TLS Record (content_type=0x17, Application Data)             |
|  +---------------------------------------------------------+  |
|  |  AEAD Encrypted Payload                                  |  |
|  |  +-----------------------------------------------------+  |  |
|  |  | EncryptedExtensions + Certificate + CertVerify      |  |  |
|  |  | + Finished                                          |  |  |
|  |  | + 1 byte: content_type + padding                    |  |  |
|  |  +-----------------------------------------------------+  |  |
|  |  +-----------------------------------------------------+  |  |
|  |  |  AEAD Tag (16 bytes)                                  |  |  |
|  |  +-----------------------------------------------------+  |  |
|  +---------------------------------------------------------+  |
|  +---------------------------------------------------------+  |
|  |  AEAD Tag (16 bytes)                                      |  |
|  +---------------------------------------------------------+  |
+---------------------------------------------------------------+
```

### 2.6 Prism Reality 合成证书

Reality 认证客户端不需要目标网站的真实证书。Prism 使用 Ed25519 签名算法生成**合成证书**，避免获取真实证书的网络开销：

```text
合成证书结构:
+---------------------------------------------------------------+
|  X.509 Certificate (DER encoded)                              |
|  +---------------------------------------------------------+  |
|  |  tbsCertificate                                        |  |
|  |  +---------------------------------------------------+  |  |
|  |  |  version: v3 (2)                                  |  |  |
|  |  |  serialNumber: 32 bytes (随机)                     |  |  |
|  |  |  signature: id-Ed25519 (1.3.101.112)              |  |  |
|  |  |  issuer: CN=<SNI>                                 |  |  |
|  |  |  validity: now -> now + 1 year                    |  |  |
|  |  |  subject: CN=<SNI>                                |  |  |
|  |  |  subjectPublicKeyInfo: Ed25519 (HKDF auth_key)    |  |  |
|  |  +---------------------------------------------------+  |  |
|  +---------------------------------------------------------+  |
|  +---------------------------------------------------------+  |
|  |  signatureAlgorithm: id-Ed25519                          |  |
|  |  signatureValue: Ed25519(auth_key, tbsCertificate)      |  |
|  +---------------------------------------------------------+  |
+---------------------------------------------------------------+
```

CertificateVerify 消息使用 Ed25519 私钥（从 `auth_key` 派生）对整个握手 transcript 进行签名。

## 3. Prism 架构

### 3.1 协议检测与接入

Reality 不是独立代理协议，而是 TLS 层的**前置伪装**。它在协议检测流程中的位置：

```text
TCP 连接进入
    |
    v
预读 24 字节
    |
    v
detect_tls()?
  (0x16 0x03 0x01/0x03)
    |
    v
+-------------------+
| Reality Scheme    |
| (stealth layer)   |
+-------------------+
    |
    +-- 读取完整 ClientHello
    +-- 解析 SNI, key_share, session_id
    +-- authenticate()
         |
         +-- SNI 不匹配 -> 返回 not_reality -> 走标准 TLS 流程
         +-- SNI 匹配但认证失败 -> fallback_to_dest
         +-- SNI 匹配且认证成功 -> 返回 authenticated
                                    -> 内层协议检测 (VLESS/等)
```

### 3.2 Prism 架构中的位置

```text
  Front Layer
  listener -> balancer
       |
       v
  Worker Layer
  worker -> launch
       |
       v
  Session Layer
  session -> probe (预读 24 字节 -> TLS 检测)
       |
       +-- detect_tls() == true
       |      |
       |      v
       |   stealth::reality::scheme::execute()
       |      |
       |      +-- stealth::reality::handshake(ctx)
       |             |
       |             +-- [authenticated] -> encrypted_transport (seal)
       |             |                       inner_preread (64 bytes)
       |             |                       -> 内层协议检测
       |             |
       |             +-- [not_reality] -> raw_tls_record
       |             |                    -> 标准 TLS 流程
       |             |
       |             +-- [fallback] -> 透明代理到 dest 已完成
       |
       +-- detect_tls() == false -> 非 TLS 协议
```

### 3.3 内存模型

Reality 握手阶段使用 PMR 分配器：

```text
client_hello_info:
  raw_message        // 完整 ClientHello 字节（帧竞技场）
  session_id         // session_id 字节（帧竞技场）
  server_name        // SNI 字符串（内存池）

server_hello_result:
  server_hello_msg          // ServerHello 消息（帧竞技场）
  server_hello_record       // ServerHello TLS 记录（帧竞技场）
  change_cipher_spec_record // CCS 记录（帧竞技场）
  encrypted_handshake_record // 加密握手记录（帧竞技场）
  encrypted_handshake_plaintext // 握手明文（帧竞技场）

seal:
  plaintext_buffer_    // 解密后的明文缓冲区（帧竞技场）
  record_body_buf_     // TLS 记录体读取缓冲区（帧竞技场）
  decrypted_buf_       // 解密输出缓冲区（帧竞技场）
  write_plain_buf_     // 写入明文拼接缓冲区（帧竞技场）
  write_ciphertext_buf_ // 写入密文缓冲区（帧竞技场）
  scatter_buf_         // scatter-gather 拼接缓冲区（帧竞技场）
```

## 4. 调用层次结构

### 4.1 完整握手调用链

```text
session::run()
  |
  +-- session::sniff_protocol()
  |     +-- protocol::analysis::detect_tls()
  |           +-- 检查: 0x16 0x03 0x01/0x03
  |
  +-- stealth::reality::scheme::execute()
        |
        +-- stealth::reality::handshake(ctx)
              |
              +-- [Step 1] read_tls_record(*ctx.inbound)
              |     +-- 读取 5 字节 TLS 记录头
              |     +-- 读取 payload（按 header 中的 length）
              |     +-- 返回完整 TLS 记录
              |
              +-- [Step 2] parse_client_hello(raw_record)
              |     +-- 验证 content_type == 0x16
              |     +-- 验证 handshake_type == 0x01
              |     +-- 提取 Random (32 bytes)
              |     +-- 提取 SessionID
              |     +-- 遍历 Extensions:
              |     |     +-- SNI (0x0000) -> client_hello.server_name
              |     |     +-- key_share (0x0033) -> client_hello.client_public_key
              |     |     |     +-- 查找 Named Group == X25519 (0x001D)
              |     |     |         或 X25519MLKEM768 (0x11EC)
              |     |     +-- supported_versions (0x002B) -> client_hello.supported_versions
              |     +-- 返回 {fault::code::success, client_hello_info}
              |
              +-- [Step 3] base64_decode(private_key)
              |     +-- 验证解码后长度 == 32 字节
              |     +-- 失败 -> fallback_to_dest()
              |
              +-- [Step 4] authenticate(cfg, client_hello, decoded_private_key)
              |     +-- match_server_name(sni, cfg.server_names)
              |     |     +-- 不匹配 -> 返回 reality_sni_mismatch
              |     +-- 遍历 client_hello 的 key_share 扩展
              |     |     +-- 必须包含 X25519 公钥（32 字节）
              |     +-- crypto::x25519(private_key, client_public_key)
              |     |     +-- 计算 ECDH 共享密钥
              |     +-- 解析 session_id 中的 short_id
              |     +-- match_short_id(short_id, cfg.short_ids)
              |     |     +-- 空字符串 "" 表示接受任意
              |     +-- HKDF 派生 auth_key
              |     +-- 生成服务端临时 X25519 密钥对
              |     +-- 返回 {fault::code::success, auth_result}
              |
              +-- [Step 5] crypto::x25519(server_ephemeral_key, client_public_key)
              |     +-- 计算 TLS ECDH 共享密钥（用于 TLS 密钥派生）
              |
              +-- [Step 6] generate_server_hello(...)
              |     +-- 构造 ServerHello 握手消息
              |     |     +-- Handshake Type: 0x02
              |     |     +-- Version: 0x0303 (TLS 1.2 兼容)
              |     |     +-- Random: 32 bytes (服务端随机数)
              |     |     +-- SessionID: 回显客户端 SessionID
              |     |     +-- Cipher Suite: TLS_AES_128_GCM_SHA256 (0x1301)
              |     |     +-- Extensions:
              |     |           +-- key_share: 服务端 X25519 公钥
              |     |           +-- supported_versions: 0x0304
              |     +-- 构造 ChangeCipherSpec 记录 (兼容性)
              |     +-- 构造加密握手记录:
              |           +-- EncryptedExtensions
              |           +-- Certificate (合成 Ed25519 证书)
              |           +-- CertificateVerify (Ed25519 签名)
              |           +-- Finished (HMAC over transcript)
              |
              +-- [Step 7] derive_handshake_keys(shared_secret, ch, sh)
              |     +-- HKDF-Extract(shared_secret, 全零) -> IKM
              |     +-- HKDF-Expand(IKM, "tls13 derived:early_traffic_secret")
              |     +-- HKDF-Expand(IKM, "tls13 derived:hs_traffic_secret")
              |     +-- 派生 client/server handshake key + IV
              |
              +-- [Step 8] derive_and_encrypt_finished(keys, sh_result, ch_raw)
              |     +-- 计算 transcript hash: SHA-256(ch + sh + ee_cert_cv)
              |     +-- 计算 Finished verify_data: HMAC(handshake_key, transcript)
              |     +-- 构造 Finished 消息
              |     +-- 使用 handshake key 加密
              |
              +-- [Step 9] ctx.inbound->async_write_scatter(...)
              |     +-- scatter-gather 写入:
              |           [ServerHello Record]
              |           [CCS Record]
              |           [Encrypted Handshake Record]
              |
              +-- [Step 10] consume_client_finished(inbound, keys)
              |     +-- 读取客户端 CCS 记录（跳过）
              |     +-- 读取客户端加密记录
              |     +-- 使用 client handshake key 解密
              |     +-- 验证是否为 Finished 消息
              |     +-- 校验 verify_data
              |
              +-- [Step 11] derive_application_keys(master_secret, transcript_hash)
              |     +-- HKDF-Expand(IKM, "tls13 derived:master_secret")
              |     +-- HKDF-Expand(master, "tls13 derived:c_ap_traffic")
              |     +-- HKDF-Expand(master, "tls13 derived:s_ap_traffic")
              |     +-- 派生 client/server app key + IV
              |
              +-- [Step 12] make_shared<seal>(inbound, keys)
              |     +-- 创建加密传输层对象
              |
              +-- [Step 13] reality_session->async_read_some(...)
              |     +-- 预读 64 字节内层数据
              |     +-- 使用应用密钥解密
              |
              +-- 返回 handshake_result {
              |     type = authenticated,
              |     encrypted_transport = seal,
              |     inner_preread = 64 bytes decrypted data,
              |     error = success
              |   }
```

### 4.2 回退调用链

```text
authentication 失败
    |
    +-- SNI 不匹配 (reality_sni_mismatch)
    |     +-- 返回 handshake_result {type=not_reality}
    |     +-- 原始 TLS 记录返回给调用方
    |     +-- 上层走标准 TLS 流程
    |
    +-- SNI 为空 + auth 失败
    |     +-- 返回 handshake_result {type=not_reality}
    |     +-- 同上
    |
    +-- SNI 匹配但 auth 失败（short_id 不匹配等）
          |
          +-- fallback_to_dest(ctx, raw_record)
                |
                +-- parse_dest(cfg.dest) -> host, port
                +-- ctx.worker.router.async_forward(host, port)
                |     +-- DNS 解析
                |     +-- TCP 连接到目标
                +-- async_write(dest, raw_record)
                |     +-- 将原始 ClientHello 转发给目标
                +-- make_reliable(dest_socket)
                +-- primitives::tunnel(ctx.inbound, dest_trans, ctx)
                      +-- 双向透明代理
                      +-- 客户端与目标完成标准 TLS 握手
```

### 4.3 加密传输层（seal）调用链

```text
seal::async_read_some(buffer, ec)
  |
  +-- 检查 plaintext_buffer_ 是否有剩余数据
  |     +-- 有 -> 拷贝到 buffer，返回
  |     +-- 无 -> 继续
  |
  +-- read_encrypted_record(ec)
        |
        +-- 读取 5 字节 TLS 记录头
        +-- 解析 content_type 和 length
        +-- 读取 length 字节密文体
        +-- 生成 nonce: XOR(iv, read_sequence_)
        +-- aead_open(ciphertext, tag, client_key, nonce)
        +-- 解密后的明文存入 plaintext_buffer_
        +-- read_sequence_++
        |
        +-- 拷贝明文到 buffer

seal::async_write_some(buffer, ec)
  |
  +-- write_encrypted_record(data, ec)
        |
        +-- 生成 nonce: XOR(iv, write_sequence_)
        +-- aead_seal(plaintext, server_key, nonce)
        |     +-- 追加 content type 字节
        |     +-- 计算 AEAD tag
        +-- 构造 TLS 记录: [content_type][version][length][ciphertext+tag]
        +-- async_write(transport, record)
        +-- write_sequence_++

seal::async_write_scatter(buffers, count, ec)
  |
  +-- 将所有 buffers 拷贝到 scatter_buf_
  +-- write_encrypted_record(scatter_buf_, ec)
        +-- 同上
```

## 5. 生命周期时序图

### 5.1 认证成功完整时序

```text
Client                          Prism Server                    Dest (if needed)
  |                                  |                                |
  |-- TLS ClientHello ------------->|                                |
  |  (SNI + key_share + session_id) |                                |
  |                                  |                                |
  |                                  | [parse_client_hello]           |
  |                                  | [authenticate]                 |
  |                                  |  1. SNI 匹配检查               |
  |                                  |  2. X25519 ECDH                |
  |                                  |  3. short_id 验证              |
  |                                  |  4. HKDF 派生 auth_key         |
  |                                  |                                |
  |  <- TLS ServerHello ------------|                                |
  |  <- CCS Record -----------------|                                |
  |  <- Encrypted Handshake --------|                                |
  |     (EncExt + Cert + CV + Fin)  |                                |
  |                                  |                                |
  |-- CCS ------------------------->|                                |
  |-- Encrypted Finished ---------->|                                |
  |                                  | [consume_client_finished]      |
  |                                  |  解密 + 验证 Finished          |
  |                                  | [derive_application_keys]      |
  |                                  | [seal 创建]                    |
  |                                  | [预读 64 字节内层数据]          |
  |                                  |                                |
  |  <== 应用数据 (AEAD 加密) =====>|                                |
  |  [内层 VLESS/其他协议]           |                                |
  |                                  |                                |
  |  <===========================>  |--- 明文转发 ------------------>|
  |                                  |                                |
```

### 5.2 认证失败回退时序

```text
Client                          Prism Server                    Dest Server
  |                                  |                                |
  |-- TLS ClientHello ------------->|                                |
  |  (合法 TLS 客户端，非代理)       |                                |
  |                                  |                                |
  |                                  | [parse_client_hello]           |
  |                                  | [authenticate]                 |
  |                                  |  SNI 匹配但 short_id 不匹配    |
  |                                  |                                |
  |                                  | [fallback_to_dest]             |
  |                                  |  1. 解析 dest (host:port)      |
  |                                  |  2. router.async_forward()     |
  |                                  |  3. async_write(dest, record)  |
  |                                  |                                |
  |                                  |------- TLS ClientHello ------->|
  |                                  |                                |
  |  <- TLS ServerHello -------------|<------ TLS ServerHello -------|
  |  <- CCS/Encrypted Handshake -----|<------ CCS/Encrypted Hs ------|
  |                                  |                                |
  |-- CCS ------------------------->|-------- CCS ------------------>|
  |-- Encrypted Finished ---------->|-------- Encrypted Finished --->|
  |                                  |                                |
  |  <== 标准 TLS 连接 ============>|<== 透明双向转发 ==============>|
  |  (客户端与 Dest 直接通信)        |                                |
```

### 5.3 SNI 不匹配时序

```text
Client                          Prism Server
  |                                  |
  |-- TLS ClientHello ------------->|
  |  (SNI: www.example.com)         |
  |                                  |
  |                                  | [parse_client_hello]
  |                                  |  SNI = "www.example.com"
  |                                  | [authenticate]
  |                                  |  server_names = ["www.microsoft.com"]
  |                                  |  -> SNI 不匹配!
  |                                  |
  |  <- handshake_result             |
  |     type = not_reality           |
  |     raw_tls_record = ClientHello |
  |                                  |
  |     [上层处理: 走标准 TLS 流程]   |
  |     (使用自身证书完成 TLS 握手)    |
```

## 6. 十六进制帧示例

### 6.1 TLS ClientHello（Reality 客户端）

```text
假设:
  SNI: www.microsoft.com
  X25519 Public Key: 32 bytes
  short_id: "a1b2c3d4e5f6" (6 bytes hex -> 3 bytes raw)
  SessionID: 32 bytes

Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    16 03 01 02 00                                   <- TLS Record Header
        ^^ ^^ ^^ ^^^^ ^^
        |  |  |  |    +-- Length: 0x0200 (512 bytes)
        |  |  |  +-- Version: 0x01 (TLS 1.0 in record, compat)
        |  |  +-- Content Type: 0x03 (version high byte)
        |  +-- Handshake: 0x03 (version low byte)
        +-- Content Type: 0x16 (Handshake)
0005    01 00 01 FC                                      <- Handshake Header
        ^^ ^^^^^^^^
        |  +-- Length: 0x0001FC (508 bytes)
        +-- Handshake Type: 0x01 (ClientHello)
0009    03 03                                            <- Version: TLS 1.2 (0x0303)
000B    [32 bytes Random]                                <- Client Random
002B    20                                               <- SessionID Length: 32
002C    A1 B2 C3 D4 E5 F6 XX XX XX XX XX XX XX XX XX XX  <- SessionID (short_id + padding)
003C    XX XX XX XX XX XX XX XX XX XX XX XX XX XX
004C    00 24                                            <- Cipher Suites Length: 36
004E    13 01 13 02 13 03 C0 2B C0 2F ...               <- Cipher Suites
        (TLS_AES_128_GCM, TLS_AES_256_GCM, TLS_CHACHA20, ...)
00XX    01 00                                            <- Compression Methods
00XX+2  01 94                                            <- Extensions Length: 404
00XX+4  [Extensions]
        +-- SNI (0x0000):
        |     00 00  00 12  00 10  00 00  0E
        |     00 6D 69 63 72 6F 73 6F 66 74 2E 63 6F 6D
        |     "microsoft.com"
        +-- Supported Groups (0x000A)
        +-- Key Share (0x0033):
        |     00 33  00 26  00 24  00 1D  00 20
        |     [32 bytes X25519 public key]
        +-- Supported Versions (0x002B):
        |     00 2B  00 03  02  03 04  03 03
        +-- ... (其他扩展)
```

### 6.2 TLS ServerHello（Reality 服务端响应）

```text
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    16 03 03 00 76                                   <- TLS Record Header
        ^^ ^^ ^^ ^^^^ ^^^^
        |  |  |  |    +-- Length: 0x0076 (118 bytes)
        |  |  |  +-- Version: TLS 1.2 (0x0303, 兼容)
        |  |  +-- ContentType high byte
        |  +-- ContentType: 0x16 (Handshake)
0005    02 00 00 52                                      <- Handshake: ServerHello, len=82
0009    03 03                                            <- Version: TLS 1.2
000B    [32 bytes Server Random]                         <- Server Random
002B    20                                               <- SessionID Length: 32
002C    [32 bytes SessionID]                             <- 回显客户端 SessionID
004C    13 01                                            <- Cipher Suite: TLS_AES_128_GCM_SHA256
004E    00                                               <- Compression: null
004F    00 1E                                            <- Extensions Length: 30
0051    00 2B 00 02 03 04                               <- ext: supported_versions = TLS 1.3
0057    00 33 00 24 00 22 00 1D 00 20                   <- ext: key_share (X25519)
0060    [32 bytes Server Ephemeral X25519 Public Key]
0080    14 03 03 00 01 01                               <- CCS Record (type=0x14, len=1, value=0x01)
0086    17 03 03 [Encrypted Handshake Record]            <- Application Data (type=0x17)
        [Encrypted: EncExt + Cert + CertVerify + Finished + Tag]
```

### 6.3 加密握手记录（解密前）

```text
Offset  00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
------  -----------------------------------------------
0000    17 03 03 01 F0                                   <- TLS Record
        ^^ ^^ ^^ ^^^^ ^^^^
        |  |  |  |    +-- Length: 0x01F0 (496 bytes)
        |  |  |  +-- Version: 0x0303
        |  |  +-- ContentType high
        |  +-- ContentType: 0x17 (Application Data)
0005    [496 bytes: Ciphertext + AEAD Tag]
        前 480 字节 = 握手明文 + content_type 字节 + padding
        后 16 字节 = AEAD Tag
```

## 7. 配置参数

### 7.1 JSON 配置结构

```json
{
  "stealth": {
    "reality": {
      "dest": "www.microsoft.com:443",
      "server_names": ["www.microsoft.com", "www.apple.com"],
      "private_key": "<Base64-encoded X25519 private key>",
      "short_ids": ["a1b2c3d4e5f6", ""]
    }
  }
}
```

### 7.2 参数详解

| 参数 | 类型 | 默认值 | 描述 |
|------|------|--------|------|
| `dest` | string | 必填 | 伪装目标站点（`host:port` 格式）。认证失败时流量转发至此地址 |
| `server_names` | string[] | 必填 | 允许的 SNI 列表。只有 SNI 匹配的 ClientHello 才会尝试 Reality 认证 |
| `private_key` | string (Base64) | 必填 | X25519 静态私钥（32 字节原始数据，Base64 编码）。使用 `scripts/GenRealityKeys.sh` 生成 |
| `short_ids` | string[] | 必填 | Short ID 列表（hex 编码，每对 hex 字符表示 1 字节，最长 16 字节）。空字符串 `""` 表示接受任意 short_id |

### 7.3 生成密钥对

使用 Prism 自带的脚本生成 Reality 密钥对：

```bash
# Linux/macOS
scripts/GenRealityKeys.sh

# Windows PowerShell
scripts/GenRealityKeys.ps1
```

输出示例：
```text
Private Key (Base64): kLmN8...=
Public Key (Base64):  xYzAB...=
Short ID: a1b2c3d4e5f6
```

## 8. 密钥派生体系

### 8.1 TLS 1.3 密钥派生树

```text
                    X25519 Shared Secret (32 bytes)
                              |
                              v
                    +--------------------+
                    |   HKDF-Extract     |
                    |   salt = 0x00*32   |
                    +--------------------+
                              |
                              v
                    Early Secret
                              |
                    HKDF-Expand-Label
                    "tls13 derived:early_traffic_secret"
                              |
                              v
                    server_early_key / client_early_key
                    server_early_iv  / client_early_iv
                              |
                              v
                    +--------------------+
                    |   HKDF-Extract     |
                    |   salt = empty     |
                    +--------------------+
                              |
                              v
                    Handshake Secret
                              |
                    HKDF-Expand-Label
                    "tls13 derived:hs_traffic_secret"
                              |
                    +---------+---------+
                    |                   |
                    v                   v
              server_hs_key        client_hs_key
              server_hs_iv         client_hs_iv
                    |                   |
                    v                   v
                    +--------------------+
                    |   HKDF-Extract     |
                    |   salt = empty     |
                    +--------------------+
                              |
                              v
                    Master Secret
                              |
                    HKDF-Expand-Label
                    "tls13 derived:c_ap_traffic"
                    "tls13 derived:s_ap_traffic"
                              |
                    +---------+---------+
                    |                   |
                    v                   v
              server_app_key      client_app_key
              server_app_iv       client_app_iv
```

### 8.2 Reality 认证密钥派生

```text
                    Client Hello + Server Hello
                              |
                              v
                    Transcript Hash (SHA-256)
                              |
                              v
                    +--------------------+
                    |   HKDF-Expand      |
                    |   label = "reality"|
                    |   auth_key         |
                    +--------------------+
                              |
                              v
                    auth_key (32 bytes)
                              |
                              v
                    用于 Ed25519 证书签名
```

## 9. 边缘情况与错误处理

### 9.1 SNI 不匹配

```text
情况: 客户端 SNI 不在 server_names 列表中
条件: match_server_name(sni, server_names) 返回 false
处理: 返回 handshake_result {type=not_reality}
影响: 客户端可能是正常 TLS 用户，不应拒绝
后续: 上层走标准 TLS 流程（使用自身证书）
```

### 9.2 Short ID 不匹配

```text
情况: 客户端 session_id 中的 short_id 不在 allowed 列表中
条件: match_short_id(short_id, short_ids) 返回 false
     且 SNI 匹配（确认是代理客户端但配置不对）
处理: fallback_to_dest()
影响: 客户端配置错误，透明代理到 dest 服务器
     客户端看到合法的 TLS 连接（到 microsoft.com）
```

### 9.3 私钥长度不正确

```text
情况: Base64 解码后的私钥长度 != 32 字节
条件: decoded_key_str.size() != tls::REALITY_KEY_LEN
处理: fallback_to_dest()
影响: 服务端配置错误，无法进行 ECDH 计算
缓解: 启动时应验证私钥格式
```

### 9.4 目标服务器不可达

```text
情况: fallback_to_dest 连接 dest 失败
条件: router.async_forward() 返回错误
处理: 返回 fault::code::reality_dest_unreachable
影响: 客户端连接被断开
缓解: 配置可靠的 dest 服务器
```

### 9.5 证书获取失败

```text
情况: 需要 dest 证书但获取失败
条件: fetch_dest_certificate() 返回错误
处理: 返回 fault::code::reality_certificate_error
影响: 无法构造伪造证书
备注: Prism 当前使用合成 Ed25519 证书，不再依赖 dest 证书
```

### 9.6 客户端发送 Alert

```text
情况: 客户端在服务端 Finished 后发送 TLS Alert
条件: consume_client_finished() 解密发现 inner_type == ALERT
处理: 返回 fault::code::reality_handshake_failed
影响: 客户端拒绝了服务端的 Finished（密钥协商失败）
原因: 可能是中间人攻击或密钥计算错误
```

### 9.7 序列号溢出

```text
情况: AEAD 序列号达到 2^64 - 1
条件: read_sequence_ / write_sequence_ 溢出
处理: 当前实现未显式处理（实际场景中几乎不可能触发）
影响: nonce 重复，AEAD 安全性降低
缓解: 应在序列号接近溢出时重新密钥协商
```

### 9.8 记录长度超限

```text
情况: TLS 记录 payload 超过 16384 字节
条件: header length > MAX_RECORD_PAYLOAD
处理: read_encrypted_record() 分配超大缓冲区
影响: 内存浪费或 OOM
缓解: 添加长度上限检查
```

### 9.9 TLS 1.3 版本协商

```text
情况: 客户端不支持 TLS 1.3
条件: supported_versions 扩展不包含 0x0304
处理: 当前实现未显式拒绝，但后续握手会失败
影响: 客户端连接异常断开
缓解: 在 parse_client_hello 中检查 TLS 1.3 支持
```

## 10. 性能特征

### 10.1 Scatter-Gather 写入

服务端在发送握手记录时使用 scatter-gather I/O，将三个记录合并为单次系统调用：

```text
async_write_scatter:
  [iov 0]  server_hello_record (~123 bytes)
  [iov 1]  change_cipher_spec_record (6 bytes)
  [iov 2]  encrypted_handshake_record (~500 bytes)
```

减少系统调用次数，降低延迟。

### 10.2 合成证书优化

Prism 不使用 dest 服务器的真实证书，而是生成合成的 Ed25519 证书：

- 无需网络连接获取证书
- 无证书缓存和管理开销
- 认证客户端无法区分合成证书与真实证书
- Ed25519 签名速度快（约 10 微秒）

### 10.3 预读优化

握手完成后，立即从加密传输层预读 64 字节内层数据：

```cpp
constexpr std::size_t preread_size = 64;
memory::vector<std::byte> inner_buf(preread_size);
const auto inner_n = co_await reality_session->async_read_some(inner_buf, ec);
```

这 64 字节通常足够内层协议（如 VLESS）进行协议检测，避免了额外的往返延迟。

## 11. 与其他协议的交互

### 11.1 与 VLESS 的关系

Reality 认证成功后，内层协议通常为 VLESS：

```text
TCP -> Reality 握手 -> seal (加密传输) -> 预读 64 字节
                                            |
                                            v
                                    协议分析 -> detect_vless()
                                            |
                                            v
                                    VLESS Handler -> Pipeline
```

### 11.2 与标准 TLS 的关系

当 SNI 不匹配时，Reality 让位给标准 TLS 流程：

```text
TCP -> Reality handshake -> not_reality -> raw_tls_record
                                              |
                                              v
                                    标准 TLS 处理
                                    (使用自身证书)
                                              |
                                              v
                                    内层协议检测
```

### 11.3 与连接池的关系

回退到 dest 服务器时，Prism 的 DNS 路由器和连接池被复用：

```text
fallback_to_dest -> ctx.worker.router.async_forward(host, port)
                         |
                         +-- DNS 解析（使用配置的 DNS 服务器）
                         +-- 连接池检查（是否有空闲连接）
                         +-- 建立新连接或使用池化连接
```
