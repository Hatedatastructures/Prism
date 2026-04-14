# Reality 协议文档

本文档包含 Reality 协议的完整规范以及 Prism 内的实现细节。

---

## 第一部分：协议规范

### 1. 协议概述

Reality 是基于 TLS 1.3 的协议伪装方案，在 ClientHello 的 session_id 中嵌入加密认证信息，使代理流量与访问正常网站的 TLS 连接完全一致。不需要自签或 CA 证书，利用目标网站的真实证书进行伪装。

**核心特点**：
- **无证书部署**：利用目标网站真实证书，无需自签/CA 证书
- **TLS 1.3 伪装**：线缆上与标准 TLS 1.3 握手流量完全一致
- **X25519/X25519MLKEM768 混合密钥交换**：支持纯 X25519 和后量子混合密钥交换
- **session_id 隐蔽信道**：认证信息通过 ClientHello 的 session_id 字段加密传递
- **Ed25519 自签名证书**：每次握手临时生成，HMAC-SHA512 签名

**协议参数**：
- **密钥交换**：X25519（32 字节公钥）
- **认证密钥派生**：HKDF-SHA256（PRK = HMAC-SHA256(salt, shared_secret)）
- **session_id 加密**：AES-256-GCM（32 字节密钥，12 字节 nonce，16 字节 tag）
- **TLS 密码套件**：TLS_AES_128_GCM_SHA256（0x1301）
- **签名算法**：Ed25519（0x0807）

### 2. 完整会话流程

```
阶段 1: TCP 连接建立
    客户端 -> TCP SYN -> Prism 服务端
    客户端 <- TCP SYN+ACK <- Prism 服务端
    客户端 -> TCP ACK -> Prism 服务端

阶段 2: Reality TLS 1.3 握手
    客户端 -> TLS ClientHello（含加密 session_id）-> Prism 服务端
    Prism 服务端:
        解析 ClientHello → 提取 SNI、key_share、session_id
        检查 SNI 是否匹配 server_names

        ├─ SNI 不匹配 → 非 Reality 客户端 → 走标准 TLS 路径
        │
        ├─ SNI 匹配 → Reality 认证:
        │   X25519 密钥交换（长期私钥 × 客户端公钥）
        │   HKDF 派生 auth_key → AES-256-GCM 解密 session_id
        │   验证格式标记 (0x01) 和 short_id
        │
        │   ├─ 认证失败 → 连接 dest → 透明代理 → 双向隧道
        │   └─ 认证成功 → TLS 1.3 握手:
        │       临时 X25519 密钥交换 → TLS 1.3 密钥调度
        │       ServerHello + CCS + 加密握手消息
        │       （Ed25519 证书 + CertificateVerify + Finished）
        │
    客户端 <- ServerHello + CCS + Encrypted[EE + Cert + CV + Finished] <- Prism 服务端
    客户端 -> CCS + Encrypted[ClientFinished] -> Prism 服务端

阶段 3: 加密应用数据传输（TLS 1.3 应用数据记录）
    客户端 <==> TLS 1.3 AES-128-GCM 加密 <==> Prism 服务端 <==> 目标服务器

阶段 4: 连接关闭
    任一方 -> TLS close_notify -> 对方
```

### 3. 二进制认证格式

#### 3.1 ClientHello session_id 隐蔽信道

```
ClientHello Random 字段（32 字节）分区:
+-------------------+-------------------+
| Random[0:20]      | Random[20:32]     |
| HKDF salt (20B)   | AEAD nonce (12B)  |
+-------------------+-------------------+

session_id（32 字节 = 16 密文 + 16 GCM tag）:
解密后的明文（16 字节）:
+------+------+-------+-----------+----------+
| 0x01 | 0x08 | 0x02  | timestamp | short_id |
| 1B   | 1B   | 1B    | 5B        | 8B       |
+------+------+-------+-----------+----------+
  版本   方法  保留     时间戳       客户端标识
```

#### 3.2 认证密钥派生

```
1. shared_secret = X25519(server_private_key, client_public_key)
2. PRK = HMAC-SHA256(salt=Random[0:20], IKM=shared_secret)
3. auth_key = HKDF-Expand(PRK, info="REALITY", length=32)

加密参数:
    算法: AES-256-GCM
    密钥: auth_key (32 字节)
    Nonce: Random[20:32] (12 字节)
    AAD: raw_message（session_id 区域清零）
```

#### 3.3 TLS 1.3 ServerHello 响应

```
服务端发送的消息序列:

1. ServerHello TLS 记录（明文）:
    Version=0x0303, CipherSuite=0x1301
    Extensions: supported_versions(0x0304) + key_share(服务端临时 X25519 公钥)

2. ChangeCipherSpec 记录（兼容性）: 0x14 0x03 0x03 0x00 0x01 0x01

3. 加密握手记录（Application Data 外壳）:
    Type=0x17, 使用服务端握手密钥 AES-128-GCM 加密
    内部明文: EncryptedExtensions(空) + Certificate(Ed25519 自签名) +
              CertificateVerify(Ed25519 签名 transcript hash) +
              Finished(HMAC-SHA256(finished_key, transcript_hash))
```

#### 3.4 Ed25519 自签名证书格式

```
X509 DER 结构（每次握手临时生成）:
    Version: v3, Serial: 1, Validity: now ~ now+3600s
    Subject/Issuer: CN=Reality (自签名)
    Public Key: Ed25519 (临时生成)
    Signature: HMAC-SHA512(auth_key, ed25519_public_key)

CertificateVerify:
    message = 0x20 * 64 + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    signature = Ed25519_sign(private_key, message)
```

### 4. TLS 1.3 密钥调度

严格遵循 RFC 8446 Section 7，使用自定义 X25519 共享密钥替代标准 TLS ECDHE 结果。

```
Step 1:  early_secret = HKDF-Extract(0^32, 0^32)
Step 2:  derived_secret = Derive-Secret(early_secret, "derived", "")
Step 3:  handshake_secret = HKDF-Extract(derived_secret, shared_secret)
         shared_secret = X25519(ephemeral_private, client_public)
Step 4:  hello_hash = SHA-256(ClientHello_msg || ServerHello_msg)

--- 握手密钥 ---
Step 5:  c_hs_traffic = Derive-Secret(handshake_secret, "c hs traffic", hello_hash)
Step 6:  s_hs_traffic = Derive-Secret(handshake_secret, "s hs traffic", hello_hash)
Step 7:  server_handshake_key = HKDF-Expand-Label(s_hs_traffic, "key", "", 16)
Step 8:  server_handshake_iv  = HKDF-Expand-Label(s_hs_traffic, "iv", "", 12)
Step 9:  client_handshake_key = HKDF-Expand-Label(c_hs_traffic, "key", "", 16)
Step 10: client_handshake_iv  = HKDF-Expand-Label(c_hs_traffic, "iv", "", 12)
Step 11: server_finished_key = HKDF-Expand-Label(s_hs_traffic, "finished", "", 32)

--- Master Secret ---
Step 12: derived_master = Derive-Secret(handshake_secret, "derived", "")
Step 13: master_secret = HKDF-Extract(derived_master, 0^32)

--- 应用数据密钥（ClientFinished 验证后） ---
Step 14: full_transcript = SHA-256(CH || SH || EE || Cert || CV || Finished)
Step 15: s_ap_traffic = Derive-Secret(master_secret, "s ap traffic", full_transcript)
Step 16: c_ap_traffic = Derive-Secret(master_secret, "c ap traffic", full_transcript)
Step 17: server_app_key = HKDF-Expand-Label(s_ap_traffic, "key", "", 16)
Step 18: server_app_iv  = HKDF-Expand-Label(s_ap_traffic, "iv", "", 12)
Step 19: client_app_key = HKDF-Expand-Label(c_ap_traffic, "key", "", 16)
Step 20: client_app_iv  = HKDF-Expand-Label(c_ap_traffic, "iv", "", 12)

Derive-Secret(Secret, Label, Context) = HKDF-Expand-Label(Secret, Label, Context, 32)
HKDF-Expand-Label(Secret, Label, Context, Length) = HKDF-Expand(Secret, HkdfLabel, Length)
HkdfLabel = Length(2) || len(1) || "tls13 " + Label || len(1) || Context
```

### 5. X25519/X25519MLKEM768 混合密钥交换

| 类型 | Named Group | Key Exchange 长度 | X25519 公钥位置 |
|------|-------------|-------------------|----------------|
| 纯 X25519 | `0x001D` | 32 字节 | 完整的 Key Exchange 数据 |
| X25519MLKEM768 | `0x11EC` | >= 32 字节 | Key Exchange 末尾 32 字节 |

Prism 实现（[request.cpp](../../src/prism/protocol/reality/request.cpp) `parse_key_share()`）：

```cpp
// 纯 X25519
if (named_group == tls::NAMED_GROUP_X25519 && key_len == tls::REALITY_KEY_LEN)
{
    std::memcpy(info.client_public_key.data(), ext_data.data() + offset, tls::REALITY_KEY_LEN);
    info.has_client_public_key = true;
    return;
}
// X25519MLKEM768 混合：提取末尾 32 字节
if (named_group == tls::NAMED_GROUP_X25519_MLKEM768 && key_len >= tls::REALITY_KEY_LEN)
{
    const auto x25519_offset = offset + key_len - tls::REALITY_KEY_LEN;
    std::memcpy(info.client_public_key.data(), ext_data.data() + x25519_offset, tls::REALITY_KEY_LEN);
    info.has_client_public_key = true;
}
```

### 6. TLS 1.3 应用数据记录

```
加密记录格式:
+--------+--------+--------+----------------------------------+
| Type   | Version| Length | Encrypted Payload + AEAD Tag     |
| 0x17   | 0x03   | 0x03   | 2B    | NB                      |
+--------+--------+--------+----------------------------------+

加密: data + content_type(0x17) → nonce = iv XOR sequence → AES-128-GCM-seal
解密: AES-128-GCM-open → 去掉末尾 content_type + padding → 应用数据

Nonce: iv XOR big_endian(sequence, 8B)，读/写方向独立计数
```

---

## 第二部分：Prism 实现

### 7. 总体入口链路

1. **连接接收**：`listener` 监听端口接受连接，`balancer` 分发到 worker
   入口：[listener.hpp](../../include/prism/agent/front/listener.hpp)

2. **协议探测**：`analysis::detect()` 识别首字节 `0x16` → `protocol_type::tls`
   入口：[analysis.cpp](../../src/prism/protocol/analysis.cpp)

3. **Reality 握手入口**：session 在 `diversion()` 中检查 Reality 配置，启用则调用 `reality::handshake()`
   入口：[session.cpp](../../src/prism/agent/session/session.cpp)

4. **握手状态机**：`reality::handshake()` 协调 ClientHello 解析、认证、回退、TLS 1.3 握手
   入口：[handshake.cpp](../../src/prism/protocol/reality/handshake.cpp)

5. **握手结果分发**：
   - `authenticated` → 创建加密传输层，内层固定为 VLESS
   - `not_reality` → 走标准 TLS 路径（BoringSSL 握手）
   - `fallback` → 透明代理已完成，会话结束
   - `failed` → 记录日志，关闭连接

6. **内层协议处理**：加密传输层创建后，预读 64 字节，内层固定为 VLESS
   入口：[session.cpp](../../src/prism/agent/session/session.cpp)

### 8. 握手实现

#### 8.1 源文件结构

| 文件 | 说明 |
|------|------|
| [constants.hpp](../../include/prism/protocol/reality/constants.hpp) | TLS 1.3 协议常量 |
| [config.hpp](../../include/prism/protocol/reality/config.hpp) | Reality 配置结构体 |
| [request.hpp](../../include/prism/protocol/reality/request.hpp) | ClientHello 解析器声明 |
| [request.cpp](../../src/prism/protocol/reality/request.cpp) | ClientHello 解析器实现 |
| [auth.hpp](../../include/prism/protocol/reality/auth.hpp) | Reality 认证逻辑声明 |
| [auth.cpp](../../src/prism/protocol/reality/auth.cpp) | Reality 认证实现 |
| [keygen.hpp](../../include/prism/protocol/reality/keygen.hpp) | TLS 1.3 密钥调度声明 |
| [keygen.cpp](../../src/prism/protocol/reality/keygen.cpp) | TLS 1.3 密钥调度实现（RFC 8446 Section 7） |
| [response.hpp](../../include/prism/protocol/reality/response.hpp) | ServerHello 生成器声明 |
| [response.cpp](../../src/prism/protocol/reality/response.cpp) | ServerHello 生成器实现 |
| [session.hpp](../../include/prism/protocol/reality/session.hpp) | Reality 加密传输层声明 |
| [session.cpp](../../src/prism/protocol/reality/session.cpp) | Reality 加密传输层实现 |
| [handshake.hpp](../../include/prism/protocol/reality/handshake.hpp) | 握手状态机声明 |
| [handshake.cpp](../../src/prism/protocol/reality/handshake.cpp) | 握手状态机实现 |
| [hkdf.hpp](../../include/prism/crypto/hkdf.hpp) | HKDF-SHA256/HMAC-SHA256/HMAC-SHA512 |
| [hkdf.cpp](../../src/prism/crypto/hkdf.cpp) | HKDF 实现（BoringSSL HMAC API） |
| [x25519.hpp](../../include/prism/crypto/x25519.hpp) | X25519 密钥交换 + Ed25519 密钥对 |
| [x25519.cpp](../../src/prism/crypto/x25519.cpp) | X25519 实现（BoringSSL EVP_PKEY API） |

#### 8.2 握手流程 (reality::handshake)

```
Step 1: read_tls_record()
    从 transport 读取完整 TLS ClientHello 记录（preread = probe 已读 24 字节）
    失败 → fallback_to_dest

Step 2: parse_client_hello()
    提取 random、session_id、SNI、key_share、supported_versions
    保存 raw_message 用于 transcript hash

Step 3: Base64 解码私钥，验证长度 = 32 字节

Step 4: authenticate()
    ├─ SNI 匹配检查 → 不匹配返回 not_reality
    ├─ X25519 公钥存在性 + TLS 1.3 支持 + session_id 长度(>=32) 检查
    ├─ X25519(长期私钥, 客户端公钥) → 全零检测（低阶点攻击防护）
    ├─ HKDF 派生 auth_key → AES-256-GCM 解密 session_id
    └─ 验证版本标记 [0]==0x01，匹配 short_id [8:16]

    认证失败分支:
    SNI 不匹配 → not_reality（标准 TLS）
    SNI 为空 + auth 失败 → not_reality（IP 连接不发 SNI）
    SNI 匹配 + auth 失败 → fallback_to_dest

Step 5: fetch_dest_certificate()
    临时连接 dest:443 → TLS 握手到 Certificate 阶段 → 提取叶子证书 DER → 断开

Step 6: TLS 1.3 握手
    6a. ephemeral_shared = X25519(临时私钥, 客户端公钥)
    6b. generate_server_hello()（先用 dummy 密钥）
    6c. derive_handshake_keys() → 握手密钥 + master_secret + finished_key
    6d. 用正确 finished_key 重算 Finished → 重新加密握手消息
    6e. 发送 ServerHello + CCS + 加密握手记录
    6f. 读取客户端 CCS + ClientFinished，解密验证
    6g. derive_application_keys()

Step 7: 创建加密传输层 session(transport, keys)，预读 64 字节内层数据
```

#### 8.3 回退机制 (fallback_to_dest)

Reality 认证失败但 SNI 匹配时，透明代理到 dest 目标服务器：

```
1. 解析 dest 配置（host:port / [IPv6]:port / 纯 host）
2. DNS 解析 → TCP 连接 dest
3. 将完整 ClientHello 数据写入 dest
4. 双向隧道（primitives::tunnel）→ 会话结束
```

效果：非 Reality 客户端看到的是正常 TLS 网站响应。

#### 8.4 关键实现细节

**两阶段 X25519 密钥交换**：
1. 认证阶段：`X25519(长期私钥, 客户端公钥)` → auth_key → 解密 session_id
2. TLS 1.3 阶段：`X25519(临时私钥, 客户端公钥)` → TLS 握手密钥

两阶段使用不同 ECDH 共享密钥，确保前向保密（临时私钥握手后丢弃）。

**低阶点攻击防护**：

```cpp
// auth.cpp - 共享密钥全零检测
bool all_zero = true;
for (const auto byte : shared_secret)
    if (byte != 0) { all_zero = false; break; }
if (all_zero)
    return {fault::code::reality_key_exchange_failed, result};
```

**Dummy 密钥 → 正确密钥重算**：

ServerHello 生成需要 handshake key（用于 Finished），而 handshake key 派生需要 ServerHello 字节（transcript hash），存在循环依赖。Prism 解法：
1. 用 dummy 密钥生成完整 ServerHello + 加密握手消息（Finished 不正确）
2. 从 ServerHello 消息计算真正的 handshake keys
3. 用正确 finished_key 重算 Finished → 用正确 handshake key 重新加密

**session 作为传输层**：

Reality 的 `session` 继承 `channel::transport::transmission`，握手后替代原始 TCP 传输层。读写自动经过 TLS 1.3 记录加解密。上层 handler（VLESS）完全不感知 Reality。

```
读取: 检查明文缓冲区 → 空 → 读 TLS 记录(5B header + body) → AES-128-GCM 解密 → 去掉 content_type
写入: data + content_type(0x17) → AES-128-GCM 加密 → TLS 记录 → 写入底层
```

### 9. 错误处理

| 场景 | fault::code | 值 | 说明 |
|------|-------------|-----|------|
| Reality 未配置 | reality_not_configured | 49 | 配置不完整 |
| 认证失败 | reality_auth_failed | 50 | session_id 解密/版本/short_id 不匹配 |
| SNI 不在 server_names | reality_sni_mismatch | 51 | 非 Reality 客户端，走标准 TLS |
| X25519 密钥交换失败 | reality_key_exchange_failed | 52 | 无效公钥或全零共享密钥 |
| TLS 握手失败 | reality_handshake_failed | 53 | 通用握手错误 |
| 回退目标不可达 | reality_dest_unreachable | 54 | DNS/TCP 连接失败 |
| 证书获取失败 | reality_certificate_error | 55 | dest TLS 握手失败 |
| TLS 记录格式错误 | reality_tls_record_error | 56 | 记录头/长度/类型不合法 |
| 密钥调度错误 | reality_key_schedule_error | 57 | HKDF 派生失败 |

**错误处理策略**：
- SNI 不匹配 → `not_reality`，走标准 TLS
- SNI 为空 + 认证失败 → `not_reality`
- SNI 匹配 + 认证失败 → `fallback_to_dest`，透明代理（不泄露 Reality 存在）
- 共享密钥全零 → 拒绝（低阶点攻击）
- AEAD 解密失败 → 关闭连接

---

## 第三部分：协议常量

### 10. TLS 记录层常量

| 常量 | 值 | 说明 |
|------|-----|------|
| RECORD_HEADER_LEN | 5 | TLS 记录头长度 |
| MAX_RECORD_PAYLOAD | 16384 | TLS 记录最大载荷 |

### 11. Content Type / Handshake Type

| 常量 | 值 | 常量 | 值 |
|------|-----|------|-----|
| CHANGE_CIPHER_SPEC | 0x14 | CLIENT_HELLO | 0x01 |
| ALERT | 0x15 | SERVER_HELLO | 0x02 |
| HANDSHAKE | 0x16 | ENCRYPTED_EXTENSIONS | 0x08 |
| APPLICATION_DATA | 0x17 | CERTIFICATE | 0x0B |
| | | CERTIFICATE_VERIFY | 0x0F |
| | | FINISHED | 0x14 |

### 12. Extension Type

| 常量 | 值 | 说明 |
|------|-----|------|
| EXT_SERVER_NAME | 0x0000 | SNI |
| EXT_SUPPORTED_GROUPS | 0x000A | 支持的曲线组 |
| EXT_KEY_SHARE | 0x0033 | 密钥共享 |
| EXT_SUPPORTED_VERSIONS | 0x002B | 支持的版本 |

### 13. Named Groups / 版本 / 密码套件

| 常量 | 值 | 说明 |
|------|-----|------|
| NAMED_GROUP_X25519 | 0x001D | X25519 |
| NAMED_GROUP_X25519_MLKEM768 | 0x11EC | X25519MLKEM768 混合 |
| VERSION_TLS12 | 0x0303 | TLS 1.2（legacy） |
| VERSION_TLS13 | 0x0304 | TLS 1.3 |
| CIPHER_AES_128_GCM_SHA256 | 0x1301 | TLS_AES_128_GCM_SHA256 |
| SIGNATURE_SCHEME_ED25519 | 0x0807 | Ed25519 签名算法 |

### 14. Reality 认证常量

| 常量 | 值 | 说明 |
|------|-----|------|
| REALITY_KEY_LEN | 32 | X25519 密钥长度 |
| SHORT_ID_MAX_LEN | 16 | short ID 最大长度 |
| SESSION_ID_MAX_LEN | 32 | TLS session_id 最大长度 |
| AEAD_TAG_LEN | 16 | AEAD tag 长度 |
| AEAD_NONCE_LEN | 12 | AEAD nonce 长度 |
| AES_128_KEY_LEN | 16 | AES-128 密钥长度 |

### 15. 配置参数

```cpp
// config.hpp
struct config
{
    memory::string dest;                          // 目标伪装网站 (host:port)
    memory::vector<memory::string> server_names;  // 允许的 SNI 列表
    memory::string private_key;                   // Base64 编码 X25519 私钥 (32B)
    memory::vector<memory::string> short_ids;     // hex 编码 short ID 列表，"" 接受任意

    [[nodiscard]] auto enabled() const noexcept -> bool
    {
        return !dest.empty() && !private_key.empty() && !server_names.empty();
    }
};
```

配置示例（[configuration.json](../../src/configuration.json)）：

```json
{
  "agent": {
    "reality": {
      "dest": "www.microsoft.com:443",
      "server_names": ["www.microsoft.com"],
      "private_key": "cGAv/vuH9mRJmvo4lqOwMZgR56mL4vMjBAwmVMS69Fw=",
      "short_ids": ["45587ac66ce007e4"]
    }
  }
}
```

---

## 第四部分：实现备注

### 16. 安全

**低阶点攻击防护**：X25519 密钥交换后检查共享密钥是否全零，防止对方发送 Curve25519 低阶点公钥导致 ECDH 结果可预测。

**前向保密**：认证阶段（长期私钥）和 TLS 1.3 阶段（临时私钥）使用不同 ECDH 共享密钥。长期私钥泄露不影响历史 TLS 会话密钥。临时私钥握手后丢弃。

**回退安全**：SNI 不匹配走标准 TLS；SNI 匹配但认证失败回退 dest，返回真实网站内容；任何情况不返回 Reality 特有错误信息。

**证书安全**：每次握手随机生成 Ed25519 密钥对，有效期 1 小时，签名使用 HMAC-SHA512(auth_key, public_key)，客户端可用相同 auth_key 验证。

### 17. 性能

- 每次 Reality 握手都重新获取 dest 证书（临时 TCP 连接 dest:443 → TLS 到 Certificate 阶段 → 提取 DER → 断开），潜在优化为缓存
- 加密传输层开销：读取 +5B header + AES-128-GCM open，写入 +5B header + 16B tag + AES-128-GCM seal

### 18. 兼容性

| 客户端 | Reality | X25519MLKEM768 | 备注 |
|--------|---------|----------------|------|
| sing-box | 完整支持 | 支持 | 推荐客户端 |
| Xray-core | 完整支持 | 支持 | Reality 原始实现 |
| Mihomo (Clash Meta) | 完整支持 | 支持 | 完整兼容 |
| Shadowrocket | 支持 | 部分支持 | iOS 客户端 |

> Prism 遵循 Mihomo/sing-box 兼容的协议格式，session_id 明文 `[0]=0x01, [1]=0x08, [2]=0x02` 为 Mihomo 固定格式。内层协议固定为 VLESS。

### 19. 限制

- 仅服务端模式，不支持客户端
- 密码套件仅 TLS_AES_128_GCM_SHA256，签名仅 Ed25519
- 每次握手重新获取 dest 证书（未缓存）
- 不支持 0-RTT、PSK 会话恢复、TLS KeyUpdate
- dest DNS 解析使用 Boost.Asio resolver（未接入 Prism 解析层）

### 20. 与 TLS 文档的关系

- [tls.md](tls.md) 描述标准 TLS 握手流程（BoringSSL SSL_accept）
- 本文档描述自定义 TLS 1.3 握手（不使用 BoringSSL）

在 session 层（[session.cpp](../../src/prism/agent/session/session.cpp)）的分流：Reality 配置启用 → `reality::handshake()` → 根据结果分发；未启用或 `not_reality` → 标准 TLS 路径。

### 21. 参考资料

- RFC 8446: TLS Protocol Version 1.3 — https://datatracker.ietf.org/doc/html/rfc8446
- RFC 5869: HKDF
- RFC 7748: X25519
- RFC 8032: Ed25519
- Xray-core Reality — https://github.com/XTLS/Xray-core
- sing-box — https://sing-box.sagernet.org/
- Mihomo — https://wiki.metacubex.one/
