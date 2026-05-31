---
name: crypto-audit
description: 修改加密、密钥交换、密钥派生、证书处理代码后触发。
---

# Skill: 密码学协议安全审计

在修改涉及加密、密钥交换、密钥派生、证书处理代码后，必须对变更部分执行以下审计清单。密码学实现的任何缺陷都可能导致整个防御体系崩溃。

## 审查系统的检测原理

审查系统在密码学层面有两个核心检测入口：

1. **证书链验证**：旁路设备实时检查服务端返回的证书 — 自签名证书直接阻断，CN/SAN 与 SNI 不匹配则封锁，非受信 CA 签发的证书标记为可疑。大量域名批量申请免费 CA 证书也会触发降级审查。
2. **密钥派生推断**：如果密钥派生存在缺陷（如 nonce 重复、密钥复用），审查系统可以通过选择密文攻击推断出加密密钥，进而解密整个会话。

此外，密码学实现的**时序侧信道**也需关注：如果密钥比较或签名验证不是常量时间的，审查系统可以通过精确测量响应时间来逐字节推断密钥。

## 触发条件

- 修改了 AEAD 加密/解密封装代码
- 修改了 HKDF、X25519、BLAKE3 等密钥派生/交换原语代码
- 修改了 HMAC 认证或消息认证逻辑
- 修改了帧加密/解密或记录层逻辑
- 修改了协议级加密（如基于 AEAD 的流加密协议）
- 修改了配置中密钥相关字段（private_key、password、users、short_id）
- 修改了证书生成、签名或 TLS 握手逻辑
- 修改了多用户认证或会话绑定逻辑

## 审计清单

### 1. AEAD 加密解密

**核心原理**：AEAD（Authenticated Encryption with Associated Data）的安全性依赖于"同一密钥下 nonce 绝不重复"这一不可违反的约束。nonce 重复的后果是灾难性的：

- **AES-GCM nonce 重复**：nonce 重复的后果分两阶段：首先，密钥流复用使攻击者可直接恢复明文差分（C1 ⊕ C2 = P1 ⊕ P2）；其次，利用两组认证标签联立方程可恢复认证子密钥 H，进而伪造任意消息的认证标签。机密性和完整性同时崩溃。
- **ChaCha20-Poly1305 nonce 重复**：nonce 重复的后果分两阶段：首先，密钥流复用使攻击者可直接恢复明文差分（C1 ⊕ C2 = P1 ⊕ P2）；其次，利用两组密文的 Poly1305 认证标签联立方程可恢复 Poly1305 一次性密钥，进而伪造任意消息。机密性和完整性同时崩溃。

| 检查项 | 说明 |
|--------|------|
| **Nonce 唯一性** | 同一密钥下每次 seal/open 是否使用不同的 nonce？是否存在计数器回绕、随机碰撞或初始化不当导致 nonce 重复的风险 |
| **Nonce 溢出处理** | 计数器型 nonce 递增溢出时是否正确拒绝加密操作？溢出边界取决于 nonce 长度：12-byte nonce 为 2^96-1，24-byte（XChaCha20）为 2^192-1。nonce 字节序依赖协议上下文：TLS 用大端计数器，SS2022 用小端计数器 |
| **Tag 长度验证** | 解密时是否验证密文长度 >= tag 长度？AES-GCM tag = 16 字节，ChaCha20-Poly1305 tag = 16 字节。短于 tag 的密文应立即拒绝（`ciphertext_len >= tag_length() ? len - tag_length() : 0` 防止无符号下溢），不得进入解密流程 |
| **附加数据（AD）完整性** | AD 是否包含足够的上下文信息？AD 应至少包含：记录类型、协议版本、序列号或方向标识。AD 缺失或不足会降低认证强度，使攻击者可以在不同上下文中重放密文 |
| **密钥长度匹配** | 密钥长度是否与算法匹配？AES-128-GCM = 16 字节密钥，AES-256-GCM = 32 字节密钥，ChaCha20-Poly1305 = 32 字节密钥，XChaCha20-Poly1305 = 32 字节密钥 + 24 字节 nonce。同一连接的不同阶段可能使用不同算法（如 Reality TLS 1.3 密钥调度用 AES-128-GCM，认证用 AES-256-GCM） |
| **计数器空间规划** | AES-GCM 的 nonce 通常使用 4 字节固定前缀 + 8 字节计数器。计数器空间是否足够覆盖单次会话的最大加密次数？如果预期单会话加密量超过 2^64-1 次，必须在此之前触发密钥轮换。应在协议设计阶段预计算计数器空间是否满足需求 |
| **Poly1305 一次性密钥零化** | ChaCha20-Poly1305 每次加密时从 ChaCha20 块函数派生一个 Poly1305 一次性密钥。加密完成后该一次性密钥是否被安全擦除？应使用 OPENSSL_cleanse 擦除派生的 Poly1305 密钥 |
| **密钥零化** | 不再使用的密钥材料（临时密钥、派生中间值、握手密钥）是否被安全擦除？应使用 `OPENSSL_cleanse` 或等价的防优化擦除函数，不得依赖普通析构。**现状提醒**：当前代码库尚未广泛使用 OPENSSL_cleanse，AEAD 上下文析构为默认行为。新增密钥处理代码应主动添加零化 |
| **TLS 1.3 加密记录上限** | AES-GCM 的 TLS 1.3 加密记录上限为 2^24 条（RFC 8446 Section 5.5），远小于理论 nonce 空间。Reality 实现必须在此阈值前触发 key update。ChaCha20-Poly1305 无此限制 |

### 2. 密钥交换

**核心原理**：密钥交换是整个安全信道的基石。如果交换被攻破，后续所有加密都毫无意义。

| 检查项 | 说明 |
|--------|------|
| **低阶点检测** | X25519 共享密钥计算后是否检查全零？低阶点输入（如全零公钥）会导致共享密钥为全零值，攻击者可以预计算该值下的所有派生密钥。检查方式：`all_of(shared.begin(), shared.end(), [](auto b) { return b == 0; })` 时必须拒绝 |
| **密钥对生成** | 私钥是否使用密码学安全随机数生成器（CSPRNG）生成？不得使用 `rand()`、`mt19937` 或其他非密码学 PRNG。X25519 私钥还应进行 clamp 操作（置低位、清高位） |
| **静态密钥安全** | 长期私钥是否通过安全通道传递？不得在日志、错误消息、调试输出中打印密钥的任何部分（包括十六进制或 Base64 形式） |
| **临时密钥提供前向安全性** | 密钥交换是否使用临时密钥对（ephemeral）提供前向安全性？纯静态密钥交换（如长期密钥直接作为共享密钥）在私钥泄露后，所有历史会话都可被解密 |
| **密钥确认** | 共享密钥计算完成后是否经过密钥确认步骤？双方应交换基于共享密钥的确认值（如 HMAC），确保双方派生出相同的密钥，防止未知密钥共享攻击 |

### 3. HKDF 密钥派生

**核心原理**：HKDF 是将共享密钥转换为可用的加密密钥的标准方法。设计不当的派生路径会导致密钥碰撞、跨会话密钥复用或上下文混淆。

#### 3.1 Extract 阶段设计要求

- **salt 必须是随机的**，不得使用固定常量。固定 salt 使 HKDF 退化为纯哈希，丧失提取熵的能力。推荐使用握手过程中的随机值（如客户端和服务端的随机数拼接）作为 salt。
- **IKM（输入密钥材料）处理**：IKM 应是密钥交换的原始输出，不得在 Extract 前做任何哈希或截断操作。

#### 3.2 Expand 阶段设计要求

- **info 字段格式规范**：必须包含 `"protocol_name|purpose|session_binding"` 三部分信息。
  - `protocol_name`：协议标识符，防止不同协议的密钥碰撞
  - `purpose`：密钥用途（如 `enc`、`dec`、`mac`、`handshake`、`application`）
  - `session_binding`：会话绑定信息（如握手摘要 transcript hash）
- **不同方向必须使用不同密钥**：客户端到服务端（C→S）和服务端到客户端（S→C）的加密密钥必须从不同的 info label 派生。例如：`Expand(PRK, "protocol|enc|c2s", 32)` 和 `Expand(PRK, "protocol|enc|s2c", 32)`。
- **握手密钥和应用密钥必须分离**：握手阶段的密钥和应用数据阶段的密钥必须从不同的派生路径生成。握手密钥在握手完成后应立即零化。
- **派生链必须完整**：不得跳过中间步骤或复用派生中间值。

#### 3.3 完整派生链示例

```
shared_secret (X25519 输出)
    │
    ▼
HKDF-Extract(salt=client_random || server_random, IKM=shared_secret)
    │
    ▼ PRK (伪随机密钥)
    │
    ├─► HKDF-Expand(PRK, info="protocol|handshake|key",  32) → hs_key
    ├─► HKDF-Expand(PRK, info="protocol|handshake|iv",   12) → hs_iv
    │
    │   （握手完成后，hs_key 和 hs_iv 立即零化）
    │
    ├─► HKDF-Expand(PRK, info="protocol|app|enc|c2s",    32) → app_enc_c2s
    ├─► HKDF-Expand(PRK, info="protocol|app|enc|s2c",    32) → app_enc_s2c
    ├─► HKDF-Expand(PRK, info="protocol|app|iv|c2s",     12) → app_iv_c2s
    ├─► HKDF-Expand(PRK, info="protocol|app|iv|s2c",     12) → app_iv_s2c
    └─► HKDF-Expand(PRK, info="protocol|app|mac",        32) → app_mac_key
```

| 检查项 | 说明 |
|--------|------|
| **Extract salt 随机性** | salt 是否为握手随机值或会话特定值？固定 salt 禁止使用 |
| **salt 重用风险** | HKDF-Extract 的 salt 是否在不同会话间避免重复使用？虽然 HKDF 在 salt 相同时仍提供安全性，但 salt 重用降低 Extract 的随机化效果，使不同会话的 PRK 存在可关联性。应确保每个会话使用唯一的 salt（如 client_random + server_random 拼接） |
| **info 字段三要素** | info 是否包含协议名、用途、会话绑定三部分？缺少任一部分都会降低安全性 |
| **方向密钥隔离** | C→S 和 S→C 的密钥是否从不同的 info label 派生？不得共享同一密钥 |
| **握手/应用密钥分离** | 握手密钥和应用密钥是否从不同的派生路径生成？ |
| **握手密钥零化** | 握手完成后，握手密钥是否被安全擦除？残留的握手密钥可能被用于解密握手记录 |
| **派生链完整性** | 从 shared_secret 到最终密钥，每一步是否都有明确的 security proof？是否存在跳步 |
| **输出长度匹配** | 派生输出长度是否与下游算法匹配？32 字节密钥不应派生出 16 字节，12 字节 IV 不应派生出 8 字节 |

### BLAKE3 使用审计

Prism 使用 BLAKE3 进行普通哈希和密钥哈希。BLAKE3 的输出是可扩展的（XOF），截断用于固定长度场景时应确保截断长度足够。BLAKE3 的密钥模式与 HMAC 语义不同，不得在需要 HMAC 的场景中替代 HMAC。

### 4. 常量时间操作

**核心原理**：非常量时间的密码学操作会通过时序侧信道泄露秘密信息。攻击者通过精确测量响应时间，可以逐字节推断出密钥、密码或认证令牌。

| 检查项 | 说明 |
|--------|------|
| **密码/令牌比较** | 密码、认证令牌、UUID 的比较是否使用常量时间函数（如 `CRYPTO_memcmp`）？标准 `memcmp` 在首个不等字节处立即返回，响应时间与匹配前缀长度成正比，可被逐字节二分搜索利用 |
| **短标识符比较** | 协议中的短标识符（如 short_id、auth_id）匹配是否使用常量时间比较？ |
| **HMAC 验证** | HMAC 结果比较是否在常量时间内完成？不得使用 `==` 运算符比较 HMAC 输出 |
| **AEAD 认证标签比较** | AEAD 解密后的 tag 验证是否由加密库内部以常量时间完成？不得在应用层手动比较 tag |
| **分支不可预测** | 密码学关键路径的条件分支是否不依赖于秘密数据？秘密数据不应出现在 `if` 条件中（除非分支的两个路径执行时间完全相同） |

### 5. 密钥生命周期

**核心原理**：密钥从生成到销毁的整个生命周期都必须受控。任何阶段的疏忽都可能导致密钥泄露。

#### 5.1 密钥隔离

不同用途的密钥必须从不同的派生路径生成，不得复用同一密钥。密钥复用会打破安全证明 — 在一个上下文中使用密钥产生的密文可能被用于攻击另一个上下文中的同一密钥。

- **TLS 1.3 key schedule 中间值零化**：TLS 1.3 密钥调度中的中间 secret（early_secret、handshake_secret、derived_secret）在使用完毕后是否被安全擦除？这些中间值可以推导出所有后续密钥。应在每次派生阶段完成后使用 OPENSSL_cleanse 擦除不再需要的中间 secret

#### 5.2 密钥轮换周期

| 密钥类型 | 建议轮换周期 | 说明 |
|----------|-------------|------|
| 长期私钥（private_key） | 90 天 | 泄露影响最大，应严格保护并定期轮换 |
| 用户密码/UUID | 30 天 | 多用户场景下密码泄露影响单个用户，但可能被用于分区攻击 |
| 短标识符（short_id） | 7 天 | 用于快速匹配，轮换频率应高于密码 |
| 会话密钥 | 每连接 | 每个连接使用独立的会话密钥，确保前向安全性 |
| 握手密钥 | 握手完成后立即销毁 | 握手密钥仅在握手阶段有效，不得用于应用数据 |

#### 5.3 序列号与方向

| 检查项 | 说明 |
|--------|------|
| **方向隔离** | 读方向和写方向的序列号空间是否完全独立？不得共享同一计数器 |
| **序列号初始化** | 每个方向的序列号是否从 0（或协商值）开始？不得使用未初始化的值 |
| **序列号溢出** | 序列号溢出时是否触发密钥轮换或连接终止？溢出后继续使用会导致 nonce 重复 |
| **原子递增** | Nonce 计数器递增是否为原子操作？多线程或多路复用场景下，非原子的递增可能导致 nonce 重复。详细审计见 `replay-audit` Section 3.1 |
| **密钥绑定** | Nonce 计数器是否与特定密钥绑定？密钥轮换后计数器必须重置，否则新密钥可能与旧密钥使用相同的 nonce。详细审计见 `replay-audit` Section 3.1 |
| **密钥材料所有权** | 密钥数据是否由拥有所有权的容器（如 `std::vector<std::uint8_t>`、`std::array`）持有？不得用 `span` 或裸指针引用局部变量的密钥数据（悬垂引用 bug） |

### 6. 证书与签名

**核心原理**：证书是 TLS 握手中审查系统的首要检测目标。伪造证书的质量直接决定了服务能否在审查环境中存活。

| 检查项 | 说明 |
|--------|------|
| **自签名证书检测** | 审查系统直接阻断自签名证书。服务端返回的证书必须能通过证书链验证 — 要么由受信 CA 签发，要么伪造得足够完整（包括完整的证书链、合理的中间 CA）。纯自签名在审查环境下不可用 |
| **伪造证书质量** | 伪造证书是否包含足够的扩展字段？缺失扩展（如 Key Usage、Extended Key Usage、Subject Alternative Name、Authority Key Identifier、Subject Key Identifier）是已知特征。证书必须看起来像真实的 CA 签发证书 |
| **CN/SAN 与 SNI 一致性** | 伪造证书的 CN 和 SAN 是否使用了目标域名（即 ClientHello 中的 SNI 值）？硬编码的代理软件名称或通用名称（如 "localhost"、"proxy"）是已知泄漏风险 |
| **证书链完整性** | 伪造证书的链结构是否完整？必须包含：叶子证书 → 中间 CA 证书 → 根 CA 证书。不完整的链（如仅返回叶子证书）会被审查系统识别 |
| **序列号随机性** | 证书序列号是否使用密码学安全随机数生成？固定值、递增值、或可预测的序列号是可识别特征 |
| **有效期合理性** | 证书的有效期是否与真实 CA 证书一致？Let's Encrypt 通常签发 90 天有效期。异常短（如 1 天）或异常长（如 10 年）的有效期是可疑的 |
| **证书透明度（CT Log）** | 通过公开 CA 注册的证书会被记入 CT Log，可被事后关联分析。CT Log 中的证书注册模式（如同一实体批量注册大量不相关域名）可能被用于识别代理服务 |
| **批量申请降级审查** | 大量域名批量申请免费 CA 证书（如 Let's Encrypt）会触发审查系统的降级审查。使用固定数量的合法域名、避免频繁申请新证书是更安全的策略 |
| **签名算法选择** | 签名算法是否与目标域名的真实证书一致？现代 CA 普遍使用 ECDSA P-256 或 RSA-PSS。使用过时的签名算法（如 SHA-1 with RSA）是可识别特征 |

### 7. 分区预言攻击防御

**核心原理**：在多用户共享同一服务端口的场景下，如果不同用户的认证失败行为存在差异，攻击者可以利用这种差异逐步缩小密钥搜索空间。

#### 7.1 攻击模型

1. 多个用户共享同一个服务器端口，每个用户使用不同的密码/UUID 进行认证
2. 攻击者构造一个密文，尝试在多个候选密钥下解密
3. 如果该密文能在某个候选密钥 K_i 下解密成功（即使明文无意义），攻击者即可确认 K_i 为系统中活跃的有效密钥
4. 如果服务端对不同用户的认证失败行为不同（不同的错误消息、不同的响应时间、不同的连接关闭方式），攻击者可以确认哪个密钥是活跃的，从而识别出有效用户

#### 7.2 防御要求

| 检查项 | 说明 |
|--------|------|
| **认证失败行为一致性** | 所有用户的认证失败行为必须完全相同 — 相同的错误消息、相同的响应时间、相同的连接关闭方式。不得泄露是哪个用户认证失败 |
| **密钥承诺** | 加密方案是否提供密钥承诺（key commitment）？AEAD 方案应使用密钥承诺机制，确保密文只能在一个密钥下解密成功 |
| **认证失败响应统一** | 认证失败的响应是否在固定延迟后返回？不得因用户数量或匹配状态影响响应时间。推荐：认证失败后先等待固定时间（如 100ms），再返回统一错误 |
| **错误消息统一** | 错误消息不得包含任何用户标识信息。所有认证失败返回相同的错误码和消息格式 |
| **旁路信息控制** | 连接关闭行为、日志记录、内存分配模式等不得因认证失败而不同。攻击者可能通过旁路信息（如连接是否立即关闭 vs 延迟关闭）推断认证状态 |

## 交叉引用

- `replay-audit` 覆盖了本 skill 未深入探讨的 AEAD nonce 操作安全（原子递增、密钥绑定、UDP nonce 处理、nonce 记忆持久化、nonce 空间大小分析）、时间戳防重放窗口、首包认证、多用户分区预言攻击维度
- `security-audit` 提供了安全审计 skills 的编排指南，确定修改特定代码时应按何种顺序执行哪些审计
- `dpi-audit` 覆盖了本 skill 未深入探讨的 TLS 指纹一致性、ALPN 协商状态机、TCP/IP 栈指纹维度
- `leak-audit` 覆盖了本 skill 未深入探讨的证书元数据泄漏、日志密钥泄漏、错误响应指纹维度
- `probe-audit` 覆盖了本 skill 未深入探讨的首包认证处理、协议识别层时序侧信道维度

## 审计流程

1. **绘制密钥派生图**：从初始密钥材料（X25519 共享密钥、预共享密钥等）到最终使用的加密密钥，绘制完整的派生链。标注每一步的 salt、IKM、info 参数。
2. **验证每步参数**：检查每一步 HKDF/AEAD 的参数正确性 — salt 是否随机、info 是否包含三要素、nonce 是否唯一、密钥长度是否匹配算法。
3. **检查常量时间**：在所有涉及秘密数据比较的地方确认使用常量时间函数。特别关注密码比较、HMAC 验证、短标识符匹配。
4. **验证密钥隔离**：确认不同用途的密钥不会碰撞或复用。派生路径的 info 必须互不相同。C→S 和 S→C 必须使用不同的密钥。
5. **验证证书链**：确认证书能通过审查系统的链验证（非自签名、CN/SAN 与 SNI 一致、有效期合理、扩展字段完整、序列号随机）。
6. **验证分区攻击防御**：确认多用户场景下认证失败行为完全一致，不存在信息泄漏。
7. **验证密钥生命周期**：确认握手密钥在握手完成后零化，会话密钥每连接独立，序列号空间按方向隔离。
8. **测试边缘场景**：全零共享密钥、nonce 溢出、密钥长度不匹配、空 AD、密文短于 tag 长度等。

## 常见反模式（禁止）

```cpp
// ❌ Nonce 重复 — 彻底破坏 AEAD 安全性
// AES-GCM: 2 次 nonce 复用即可恢复认证子密钥 H，攻击者可伪造任意标签
// ChaCha20-Poly1305: nonce 复用可恢复 Poly1305 一次性密钥
std::uint8_t nonce[12] = {0};  // 固定 nonce，每次加密都相同

// ✅ 计数器型 nonce + 溢出检测
std::uint8_t nonce[12];
auto ctr = encode_be<std::uint64_t>(sequence_number++);
if (sequence_number == 0)
{
    // 溢出，必须拒绝加密
    return fault::code::nonce_exhausted;
}
memcpy(nonce + 4, ctr.data(), 8);  // 前 4 字节固定，后 8 字节递增

// ❌ 非常量时间密码比较 — 侧信道泄露
// 审查系统通过精确测量响应时间逐字节推断密钥
if (std::string_view(received) == expected_password) { ... }  // 反模式: 内联伪代码
if (memcmp(received.data(), expected.data(), len) == 0) { ... }  // 反模式: 内联伪代码

// ✅ 常量时间比较
if (CRYPTO_memcmp(received.data(), expected.data(), len) == 0) { ... }  // 内联伪代码

// ❌ span 引用局部变量 — 密钥数据悬垂
std::string decoded = base64_decode(key);
result.decoded_privkey = std::span<const std::uint8_t>(
    reinterpret_cast<const std::uint8_t*>(decoded.data()), decoded.size());
// decoded 析构后 span 悬挂，密钥数据被释放

// ✅ 拥有所有权的容器
result.decoded_privkey.assign(
    reinterpret_cast<const std::uint8_t*>(decoded.data()),
    reinterpret_cast<const std::uint8_t*>(decoded.data() + decoded.size()));

// ❌ 未检测低阶点 — 共享密钥可能全零
auto [ec, shared] = x25519(privkey, pubkey);
// shared 可能全零（低阶点攻击）

// ✅ 检测全零共享密钥
auto [ec, shared] = x25519(privkey, pubkey);
if (std::all_of(shared.begin(), shared.end(), [](auto b) { return b == 0; }))  // 表格内嵌示例
{
    return {fault::code::kexfail, {}};
}

// ❌ 密钥派生路径缺少上下文绑定 — 跨会话可碰撞
auto key = hkdf_expand(secret, "");  // 空 info

// ✅ 每步派生绑定会话上下文（三要素：协议名|用途|会话绑定）
auto key = hkdf_expand(secret, "proxy|app_enc|" + session_id);

// ❌ 方向密钥复用 — C→S 和 S→C 使用同一密钥
auto enc_key = hkdf_expand(prk, "protocol|enc", 32);
// 双向都用 enc_key 加密

// ✅ 方向隔离 — 不同方向从不同 info 派生
auto enc_c2s = hkdf_expand(prk, "protocol|enc|c2s", 32);
auto enc_s2c = hkdf_expand(prk, "protocol|enc|s2c", 32);

// ❌ 握手密钥未零化 — 握手完成后密钥残留
void on_handshake_complete()
{
    // hs_key 仍然在内存中
}

// ✅ 握手密钥零化
void on_handshake_complete()
{
    OPENSSL_cleanse(hs_key.data(), hs_key.size());
    OPENSSL_cleanse(hs_iv.data(), hs_iv.size());
}

// ❌ 分区预言攻击 — 认证失败行为不一致
for (auto& user : users)
{
    if (user.password == received_password)
    {
        return accept(user);
    }
}
// 到达此处：没有用户匹配
return reject("user not found");  // 泄露了"无此用户"信息
// 攻击者可区分"密码错误"和"用户不存在"

// ✅ 统一认证失败响应
bool authenticated = false;
for (auto& user : users)
{
    if (CRYPTO_memcmp(user.password.data(), received_password.data(),
                      user.password.size()) == 0)
    {
        authenticated = true;
        // 不立即返回，继续遍历以保持常量时间
    }
}
if (!authenticated)
{
    // 固定延迟 + 统一错误消息
    co_await async_sleep(100ms);
    co_return reject("authentication failed");  // 不泄露具体原因
}

// ❌ 自签名证书 — 审查系统直接阻断
X509* cert = X509_new();
X509_sign(cert, pkey, EVP_sha256());  // 自己签自己

// ❌ 固定证书序列号 — 可识别特征
ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

// ❌ 硬编码 CN — 代理软件指纹
X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
    (std::uint8_t*)"ProxyServer", -1, -1, 0);

// ✅ 伪造证书应模拟真实 CA 证书
// - CN/SAN 与 ClientHello SNI 一致
// - 序列号随机生成
// - 扩展字段完整（Key Usage, EKU, SAN, AKI, SKI）
// - 有效期与目标 CA 一致（如 90 天）
// - 签名算法与目标域名真实证书一致

// ❌ Nonce 溢出不检测 — 导致 nonce 重复
void encrypt(std::uint64_t seq, ...)
{
    std::uint8_t nonce[12];
    memset(nonce, 0, 4);
    std::uint64_t val = seq;  // seq 可能已溢出回 0
    memcpy(nonce + 4, &val, 8);
    // 如果 seq 从 2^64-1 溢出到 0，nonce 将重复
}

// ✅ Nonce 溢出检测
void encrypt(std::uint64_t seq, ...)
{
    if (seq > MAX_SEQUENCE)
    {
        return fault::code::nonce_exhausted;
    }
    // ... 生成 nonce
}

// ❌ 密钥长度不匹配 — 静默截断产生弱密钥
auto key_16 = derive_key(secret, 16);  // 请求 16 字节
aes_256_gcm_encrypt(key_16, ...);      // 但 AES-256 需要 32 字节

// ✅ 密钥长度与算法匹配
auto key_32 = derive_key(secret, 32);  // AES-256 需要 32 字节
aes_256_gcm_encrypt(key_32, ...);
```
