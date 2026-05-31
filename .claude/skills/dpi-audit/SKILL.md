---
name: dpi-audit
description: 修改 TLS 握手、ALPN 协商、ClientHello/ServerHello 处理、伪装方案代码后触发。
---

# Skill: DPI 指纹与 TLS 握手审计

在修改涉及 TLS 握手、协议识别、伪装方案代码后，必须对变更部分执行以下审计清单。

## 审查系统的检测原理

审查系统在 TLS 握手阶段运行**指纹黑名单**机制：提取 ClientHello 的密码套件列表、扩展字段及顺序、椭圆曲线等信息计算指纹（如 JA3/JA4），与已知的非浏览器指纹库比对。Go 标准库、Python requests、已知代理工具的指纹已被收录，命中即阻断。

同时审查系统会进行**多维度交叉验证**：SNI 与证书 CN/SAN 是否一致、证书是否由受信 CA 签发、ALPN 协商结果与后续流量是否匹配。任何一项不一致都可能触发阻断。

指纹检测不止于 TLS。**TCP/IP 栈指纹**（初始 TTL、TCP 窗口大小、TCP 选项顺序）可以识别操作系统。如果 TLS 指纹声称是 Chrome/Windows，但 TCP/IP 栈指纹显示是 Linux 内核，这种交叉矛盾会直接暴露伪装。

审查系统的指纹检测是**持续进化**的：Chrome 每次大版本更新可能改变扩展顺序或新增扩展。如果代理软件的指纹停留在旧版 Chrome 特征，审查系统可以通过版本差异识别出"永不更新的 Chrome"，这本身就是异常。

此外，审查系统不只检查 ClientHello 指纹。**TLS 库的服务端行为指纹**同样可识别：BoringSSL、OpenSSL、LibreSSL 在密码套件选择偏好、扩展处理细节、错误响应格式上都有差异。如果 ClientHello 声称是 Chrome（使用 BoringSSL），但服务端行为显示 OpenSSL 特征，这种不匹配暴露伪装。

## 触发条件

- 修改了伪装方案代码
- 修改了 ClientHello 解析或特征提取逻辑
- 修改了 ALPN 协商逻辑
- 修改了 TLS 传输层
- 修改了任何方案的握手流程
- 修改了 TLS 相关配置项
- 修改了 TCP socket 参数设置
- 修改了 HTTP/2 或应用层帧构造逻辑
- 修改了证书处理或 SNI 路由逻辑

## 审计清单

### 1. ClientHello 指纹一致性

**适用范围**：ClientHello 指纹审计适用于出站连接（Prism 作为客户端连接 dest 服务器时的 ClientHello 构造）。入站连接的 ClientHello 由下游客户端发送，Prism 仅解析不做控制。ServerHello 指纹仅适用于 Reality 方案（手动构造 ServerHello），ShadowTLS/Restls 继承后端服务器的 ServerHello 指纹。

TLS ClientHello 是 DPI 审查的首要目标。审查系统提取以下字段计算指纹哈希，与已知浏览器指纹库进行比对。任何一个字段的不一致都可能导致指纹失配。

| 检查项 | 说明 |
|--------|------|
| **密码套件顺序** | 加密套件列表及其排列顺序是否与目标浏览器完全一致？审查系统维护黑名单，已知非浏览器指纹直接阻断。顺序差异即使只有一个套件位置不同，也会产生不同的 JA3/JA4 哈希 |
| **扩展字段完整性** | supported_groups、key_share、signature_algorithms、psk_key_exchange_modes、session_ticket 等扩展是否与目标浏览器模板匹配？缺失扩展本身就是异常特征。Chrome 通常携带 15+ 个扩展 |
| **扩展顺序一致性** | 扩展字段的排列顺序是否与目标浏览器完全一致？不同客户端的扩展顺序是可区分的。例如 Chrome 的典型顺序：0x000b (ec_point_formats) → 0x000a (supported_groups) → 0x000d (signature_algorithms) → 0x0016 (ALPN) → ... |
| **扩展内部值顺序** | 不仅扩展的顺序要一致，每个扩展内部的值也要一致。如 `signature_algorithms` 列表中算法的排列顺序（如 `rsa_pss_rsae_sha256` 在 `rsa_pkcs1_sha256` 前还是后）、`supported_groups` 中曲线的排列顺序（如 `x25519` 在 `secp256r1` 前还是后） |
| **GREASE 值** | Chrome 等浏览器在密码套件列表、扩展列表、ALPN 列表、supported_groups、key_share 中填充 GREASE 随机值，用于前瞻兼容性测试。已知 GREASE 值包括 0x0a0a、0x1a1a、0x2a2a、0x3a3a、0x4a4a、0x5a5a、0x6a6a、0x7a7a、0x8a8a、0x9a9a、0xaaaa、0xbaba、0xcaca、0xdada、0xeaea、0xfafa。缺少 GREASE 值是非浏览器客户端的强特征 |
| **后量子密钥交换** | Chrome 已在 key_share 扩展中包含 ML-KEM-768（Kyber-768）密钥共享。ML-KEM-768 的 key_share 数据长度固定为 1184 字节，加上 X25519 的 32 字节，使 ClientHello 总长度膨胀到约 1700 字节。如果代理的 ClientHello 缺少 ML-KEM 密钥共享或 key_share 数据长度不等于 1184 字节，审查系统可以通过缺失的后量子扩展识别出"非最新 Chrome"。Chrome 同时发送 X25519 + ML-KEM-768 两个 key_share |
| **Chrome 124+ 扩展随机化** | Chrome 124 引入了会话级随机化：每次 TLS 连接的 GREASE 位置和非关键扩展的顺序都会随机变化。静态模板（硬编码扩展顺序）不再匹配最新 Chrome 的行为。代理必须实现同样的随机化逻辑，否则"每次连接扩展顺序完全相同"本身就是非浏览器特征 |
| **TLS 版本列表** | `supported_versions` 扩展是否包含且仅包含目标版本？现代 Chrome 仅包含 0x0304 (TLS 1.3)，加上 GREASE 值。多余的旧版本（如包含 0x0303）或缺少版本会暴露非浏览器特征 |
| **ClientHello.random** | 必须为密码学安全伪随机数（CSPRNG），不得使用可预测的随机源、固定种子或存在模式。32 字节全零或具有可识别模式的随机数是严重漏洞 |
| **指纹版本追踪** | 指纹模板是否跟随目标浏览器版本更新？停滞在旧版 Chrome 特征的"永不更新的客户端"本身就是异常。需要建立指纹模板的持续更新机制，至少跟踪每个 Chrome 大版本号的指纹变化 |
| **JA4+ 指纹体系** | JA4 是 JA3 的进化版，分组更细。JA4（客户端指纹）按 SNI 是否存在、ALPN 是否存在将扩展分组编码。JA4S（服务端指纹）编码 ServerHello 的密码套件选择和扩展响应。JA4X（证书指纹）编码证书的密钥类型、签名算法、有效期范围。代理的 ClientHello 必须在所有 JA4 维度上与目标浏览器匹配 |
| **ClientHello 总长度合规** | ClientHello 总长度是否与目标浏览器版本一致？含后量子密钥交换（ML-KEM-768）的 Chrome ClientHello 约 1700 字节，不含约 500 字节。异常短或异常长的 ClientHello 都是可识别特征。审查系统可通过 ClientHello 长度直接判断是否使用了后量子密钥交换 |

#### GREASE 审计要点

GREASE 值必须出现在以下位置，且每个位置最多出现一次：

- 密码套件列表中的一个位置（随机插入）
- 扩展列表中的一个位置（随机插入）
- ALPN 扩展内部协议列表中的一个位置
- supported_groups 扩展内部的一个位置
- key_share 扩展内部的一个位置
- supported_versions 扩展内部的一个位置

每个位置使用的具体 GREASE 值应从 16 个已知值中随机选择，且各位置独立随机。

**⚠️ 实现验证**：当前 Prism 的 `tls.cpp` 中 GREASE 仅存在于注释，实际未通过 `SSL_CTX_set_grease` 等 API 启用。审计时应验证 GREASE 在 BoringSSL context 中是否真正生效，而非仅检查注释。客户端方向的 GREASE 已通过 BoringSSL 自动处理。

#### 后量子密钥交换审计要点

```
key_share 扩展内部结构:
  - X25519 key_share: group=0x001d, data_length=32, data=<32 bytes CSPRNG>
  - ML-KEM-768 hybrid key_share: group=0x11EC (IANA 最终分配), data_length=1218
    (X25519 32B + ML-KEM-768 1184B + 2B 头), data=<CSPRNG>
```

验证要点：
- X25519 和 ML-KEM-768 的顺序是否与目标浏览器一致
- ML-KEM-768 的 group ID 是否正确（IANA 最终分配为 0x11EC，Prism 代码使用此值）。注意：Reality ServerHello 仅发送 X25519 key_share（group=0x001D），不发送 ML-KEM
- key_share 数据长度是否精确匹配（X25519=32, ML-KEM-768=1184）
- key_share 数据是否为 CSPRNG 生成

#### 指纹模板维护机制

指纹模板必须持续跟随目标浏览器版本更新。停滞在旧版特征的"永不更新的客户端"本身就是异常。

**指纹版本号**：每个指纹模板标注目标 Chrome 大版本号（如 Chrome 126）。模板更新时同步更新版本号，记录变更日期。

**更新触发**（Chrome 约 4 周一个大版本）：
- 扩展列表变化（新增/移除扩展）
- 扩展顺序变化
- GREASE 值变化（极罕见但需确认）
- supported_versions 变化
- key_share 变化（如新的后量子算法替代 ML-KEM-768）
- 密码套件列表变化

**验证方法**：
1. 使用 Wireshark/tcpdump 抓取目标浏览器的真实 ClientHello
2. 与代码中的模板逐字节对比（扩展 ID、扩展长度、扩展内部字段值及顺序）
3. 计算 JA4 指纹哈希，与已知浏览器指纹数据库比对

**回归测试**：每次指纹模板更新后，运行 `RealityBench` 及相关 benchmark 确认握手成功率无回归。

**存放位置**：在 `docs/wiki/fingerprints/` 目录下维护各版本的指纹快照（JSON 格式），包含字段：
```json
{
  "chrome_version": "126",
  "capture_date": "2026-05-29",
  "cipher_suites": [...],
  "extensions": [{"id": "0x...", "name": "...", "order": 1}],
  "supported_groups": [...],
  "signature_algorithms": [...],
  "key_share_groups": ["x25519", "ml-kem-768"],
  "alpn": [...],
  "total_hello_length": 1700
}
```

### 2. ServerHello 响应合规性

ServerHello 是服务端指纹的核心来源。审查系统通过 ServerHello 的字段选择反推服务端 TLS 库类型。

| 检查项 | 说明 |
|--------|------|
| **版本号固定** | `legacy_version` 必须为 `0x0303`（TLS 1.2 兼容格式），`supported_versions` 扩展中必须为 `0x0304`（TLS 1.3）。不得使用 `0x0301` 作为 `legacy_version`，也不得在 `supported_versions` 中返回非 TLS 1.3 的值 |
| **random 字段** | 必须为密码学安全随机数，不得包含可识别的模式或固定字节。在 HelloRetryRequest 场景中，`random` 必须为特殊的 `hello_retry_request` 常量值（RFC 8446 §4.1.3 定义） |
| **cipher_suite 选择** | 必须从 ClientHello 提供的列表中选择，且选择逻辑与主流服务器行为一致。选择逻辑本身是 TLS 库指纹（见第 3 节） |
| **证书质量** | 证书是否由受信 CA 签发？CN/SAN 是否与 SNI 匹配？证书链是否完整？证书的有效期、密钥类型、签名算法是否与主流 Web 服务器证书一致？ |
| **扩展响应完整性** | ServerHello 必须包含 `key_share`、`supported_versions` 扩展。如果使用了 PSK，还必须包含 `pre_shared_key` 扩展。缺少预期扩展或返回非预期扩展都是指纹 |
| **session_id 回显** | 必须原样回显 ClientHello 中的 `session_id`，不得修改或截断。TLS 1.3 中 `session_id` 仅用于兼容性，但值必须匹配 |

### 3. TLS 库服务端行为指纹

这是最容易被忽视但最致命的指纹维度。审查系统不仅看 ClientHello，也分析服务端行为来反推 TLS 库类型。如果 ClientHello 模拟了 Chrome/BoringSSL 特征，但服务端行为暴露了 OpenSSL 特征，这种不一致直接暴露伪装。

| 行为维度 | BoringSSL（Chrome/Google 服务端） | OpenSSL |
|----------|-----------------------------------|---------|
| **密码套件选择偏好** | AES-GCM 优先，然后是 ChaCha20-Poly1305。始终优先选择有硬件加速的算法 | 无 AES-NI 时 ChaCha20 优先（OpenSSL 1.1.1+ 的策略）。有 AES-NI 时 AES-GCM 优先 |
| **HelloRetryRequest 格式** | HRR 中的扩展顺序与 BoringSSL 实现一致。`key_share` 扩展在 `selected_version` 之后的特定位置 | HRR 中扩展顺序不同，可能在 cookie 处理上有差异 |
| **MAC 失败 Alert** | 返回 `bad_record_mac`（描述码 20）。这是 RFC 规定的标准行为 | 可能返回 `decrypt_error`（描述码 51）。偏离 RFC 但不影响互操作性 |
| **记录层版本号** | 始终使用 `0x0303`，包括握手阶段 | 握手阶段可能使用 `0x0301`（SSL 3.0 兼容）。这种差异可被被动检测 |
| **OCSP Stapling** | Google 服务端通常启用 OCSP Stapling，在 TLS 握手中返回 Certificate Status 消息 | 未配置时完全不返回 OCSP 响应。缺失 OCSP Stapling 在高信誉域名上可疑 |
| **Certificate Compression** | 支持 `compress_certificate` 扩展（brotli/zstd），响应中可能使用压缩证书 | 默认不支持 Certificate Compression。不支持此扩展与声称的服务器类型不一致时可疑 |
| **NewSessionTicket 行为** | 握手完成后发送的 NST 消息格式、ticket 生命周期、max_early_data_size 与 BoringSSL 实现一致 | NST 格式和参数可能不同。ticket 结构是 TLS 库指纹 |
| **Alert 消息格式** | TLS 1.3 中 Alert 使用 ApplicationData 记录加密传输（除握手阶段的致命 Alert） | 行为一致，但 Alert 描述码的选择可能不同 |

#### 服务端行为一致性审计要点

- 确认密码套件选择偏好与声称的 TLS 库匹配
- 确认 HRR 格式与声称的 TLS 库匹配
- 确认错误场景下返回的 Alert 描述码与声称的 TLS 库一致
- 确认记录层版本号的使用策略与声称的 TLS 库一致
- 确认 OCSP Stapling 的启用/禁用状态与声称的服务器类型一致（高信誉域名应启用）
- 确认 Certificate Compression 扩展的支持/不支持状态与声称的 TLS 库一致

### 4. 证书链与 SNI 交叉验证

证书是审查系统进行域名关联和伪装检测的核心锚点。

| 检查项 | 说明 |
|--------|------|
| **证书签发方式** | 审查系统直接阻断自签名证书。证书必须由受信 CA 签发或伪造得足以通过链验证。使用 Let's Encrypt 等免费 CA 是可行方案，但需注意批量申请的行为异常 |
| **CN/SAN 与 SNI 一致** | 证书的 CN（Common Name）和 SAN（Subject Alternative Name）必须与 ClientHello 中的 SNI 匹配。不匹配会被审查系统直接封锁 |
| **证书链完整性** | 证书链是否包含完整的中级证书？缺少中间 CA 证书会导致验证失败。证书链中不应包含多余的非必要证书 |
| **批量申请异常** | 大量域名集中申请免费 CA 证书的行为会触发降级审查。申请模式应分散化，避免时间或 IP 集中的批量特征 |
| **证书透明度日志** | 所有公开受信 CA 签发的证书都会被记入 CT Log，可被事后关联分析。伪造证书的注册模式（域名选择、申请时间、申请频率）应避免批量特征 |
| **证书字段一致性** | 证书的密钥类型（RSA/ECDSA）、签名算法、有效期范围应与主流 Web 服务器证书一致。异常的密钥长度或过期时间本身是指纹 |
| **回落目标可达性** | 回落目标是否指向真实可达的高信誉第三方域名？不可达的目标会导致回落失败，间接暴露代理行为 |

### 5. ALPN 协商状态机

ALPN 协商是 TLS 握手中可被审查的关键字段，且协商结果必须与后续实际流量行为完全一致。

| 检查项 | 说明 |
|--------|------|
| **ALPN 设置方式** | 必须使用回调函数在每次握手时动态选择 ALPN，而非在共享 SSL_CTX 上设置固定 ALPN 列表。后者会污染所有连接，导致所有连接协商出相同的 ALPN 结果——这在多域名场景下是异常行为 |
| **ALPN 与实际流量一致** | 如果协商结果为 `h2`，后续流量必须真正体现 HTTP/2 帧结构（以 SETTINGS 帧开头，使用 HPACK 头部压缩，遵守流控制等）。如果协商了 `h2` 但实际传输的是非 HTTP/2 数据，状态机关联分析会检测到这种不一致 |
| **ALPN 降级处理** | 客户端不支持所需 ALPN 时，是否正确降级到安全传输模式？降级时应将连接作为标准 TLS 传输转发到回落目标，而非暴露代理行为 |
| **ALPN 选择逻辑** | ALPN 选择逻辑是否与目标服务器的行为一致？真实 Web 服务器通常优先选择 `h2`，然后是 `http/1.1`。选择逻辑的顺序偏好本身是服务端指纹 |
| **无 ALPN 扩展处理** | 如果 ClientHello 不包含 ALPN 扩展，服务端不得在 ServerHello 中返回 ALPN 扩展。这是 RFC 规范要求 |

### 6. 协议状态机完整性

TLS 握手是一个严格的状态机，每个状态的转换都必须与标准实现完全一致。

| 检查项 | 说明 |
|--------|------|
| **状态转换序列** | TLS 1.3 握手的状态转换序列是否与目标实现完全一致？不只是"字段匹配"，而是整个状态机转换序列都必须模拟。包括：ClientHello → ServerHello/HelloRetryRequest → EncryptedExtensions → Certificate → CertificateVerify → Finished → Finished |
| **CCS 插入时机** | ChangeCipherSpec（CCS）兼容性记录的插入时机必须正确。TLS 1.3 中 CCS 仅用于中间件兼容性，必须在 ServerHello 之后、Finished 之前的正确位置插入。过早或过晚的 CCS 都是状态机异常 |
| **Finished 消息顺序** | 服务端的 Finished 消息必须在 Certificate + CertificateVerify 之后发送。客户端的 Finished 消息必须在收到服务端 Finished 之后发送。顺序错误违反 TLS 1.3 协议规范 |
| **错误状态转换** | 收到非预期消息时的状态转换是否与标准实现一致？例如在等待 ServerHello 时收到 ApplicationData 的处理。自定义的错误处理路径（如不发送 Alert 直接断开）本身就是指纹 |
| **重协商行为** | TLS 1.3 不支持重协商。收到重协商请求（TLS 1.2 的 HelloRequest）时，必须按照标准行为拒绝（发送 `no_renegotiation` Alert），而非忽略或断开 |
| **协议降级防御** | 审查系统可能强制协议降级（如发送仅支持 TLS 1.2 的 ClientHello）。如果服务端在降级后的行为与标准 TLS 1.2 实现不一致，降级路径暴露指纹。必须确保 TLS 1.2 降级路径同样合规 |
| **0-RTT 处理** | 如果支持 0-RTT，必须正确处理 early data 的接收和拒绝逻辑。不当的 0-RTT 处理可能导致重放攻击或状态机异常 |

### 7. 握手后应用层指纹

握手完成后的第一个应用层数据包是审查系统的第二个检测窗口。

| 检查项 | 说明 |
|--------|------|
| **HTTP/2 SETTINGS 帧首发** | 握手完成后第一个应用层帧必须为 HTTP/2 SETTINGS 帧。非标准帧序列（如直接发送 HEADERS 或 DATA 帧）是异常。SETTINGS 帧的流 ID 必须为 0 |
| **SETTINGS 参数值** | HTTP/2 SETTINGS 帧中的参数值是否与主流实现一致？关键参数包括：`HEADER_TABLE_SIZE`（HPACK 动态表大小）、`INITIAL_WINDOW_SIZE`（初始流控窗口）、`MAX_FRAME_SIZE`（最大帧大小）、`MAX_CONCURRENT_STREAMS`（最大并发流数）。自定义参数值是服务端指纹 |
| **WINDOW_UPDATE 行为** | WINDOW_UPDATE 帧的频率和增量值是否与主流实现一致？异常的流量控制行为（如超大增量值、从不发送 WINDOW_UPDATE）是服务端指纹 |
| **流优先级** | 是否正确处理 HTTP/2 的流优先级和依赖关系？完全忽略 PRIORITY 帧或使用非标准权重值是简化实现的标志 |
| **Session Resumption 行为** | 正常浏览器利用 TLS session resumption 或 0-RTT 减少握手延迟。如果代理的每次连接都是完整握手（缺少 session resumption），本身是异常特征。应支持 Session Ticket 复用，且 NewSessionTicket 的 ticket lifetime、max_early_data_size 等参数与目标服务器一致 |
| **HTTP/2 GOAWAY 处理** | 连接关闭时是否正确发送 GOAWAY 帧？直接断开不发送 GOAWAY 是非标准行为 |
| **HTTP/2 PING 行为** | 是否正确响应 PING 帧？不响应 PING 或响应内容不正确（必须原样回传 opaque data）是异常 |
| **HTTP/1.1 行为** | 如果协商了 `http/1.1`，后续数据是否遵循 HTTP/1.1 格式（请求行、头部、CRLF 分隔）？混用协议格式会被检测 |
| **EncryptedExtensions 指纹** | Reality 发送空 EncryptedExtensions（0 字节扩展），而标准 BoringSSL 服务端会发送 ALPN、extended_master_secret 等扩展。此差异可被指纹识别。审计时应评估是否需要补充标准扩展 |
| **NewSessionTicket 缺失** | Reality 握手后不发送 NewSessionTicket，而标准 TLS 1.3 服务端至少发送一个 NST。缺少 NST 是异常行为，可被用于区分 Reality 与标准 TLS 服务端 |

### 8. SNI 处理安全性

SNI（Server Name Indication）是审查系统关联客户端意图的核心字段，处理不当会导致安全风险。

| 检查项 | 说明 |
|--------|------|
| **SNI 白名单** | 服务端 SNI 白名单是否只包含经过审查的高流量、高信誉域名？白名单应避免包含敏感域名（如被封锁域名）或低信誉域名 |
| **空 SNI 防御** | 空 SNI 的连接必须安全回落到下一个伪装方案或转发到真实目标，不得直接拒绝连接或返回异常响应。直接拒绝空 SNI 会暴露代理行为特征：真实 Web 服务器不会因为空 SNI 而断开连接 |
| **SNI 交叉验证** | 服务端返回的证书 CN/SAN 必须与 ClientHello 中的 SNI 匹配。不匹配的证书会被审查系统标记 |
| **SNI 长度校验** | SNI 的域名长度不得超过 DNS 规范限制（253 字节）。每段标签不得超过 63 字节。超长 SNI 可能是缓冲区溢出攻击或指纹探测 |
| **通配符 SNI 处理** | 通配符域名（如 `*.example.com`）的处理逻辑是否正确？通配符仅匹配一级子域名 |
| **SNI 编码安全** | SNI 必须为有效的 DNS 名称（小写 ASCII，无尾随点）。包含非 ASCII 字符、下划线或其他非法字符的 SNI 应安全回落 |

### 9. ECH/ESNI 阻断防御

ECH（Encrypted Client Hello）和 ESNI（Encrypted SNI）是 SNI 加密方案，但审查系统对此有明确的对抗策略。

| 检查项 | 说明 |
|--------|------|
| **ECH 扩展检测** | 审查系统对携带 ECH（extension type 0xFE0D）或老版 ESNI 扩展的 ClientHello 采取高概率丢弃或注入 RST。原因：审查系统无法窥探加密后的 SNI，宁可误杀不可放过 |
| **ECH 禁用决策** | 短期内为确保连通率可能需要禁用 ECH，但这牺牲了 SNI 隐私。需根据部署环境的审查强度权衡连通率与隐私 |
| **ECH 外部 SNI** | 即使启用 ECH，ClientHello 仍包含明文的外部 SNI（outer SNI），指向 ECH 配置服务商。审查系统可能将已知 ECH 服务商域名列入高审查名单 |
| **替代策略** | 如需隐藏 SNI，考虑以下方案替代 ECH：双 TLS（外层正常握手 + 内层加密握手）、CDN 前置（通过 CDN 节点中转流量）、域名前置（HTTP Host 与 SNI 不一致，但现代 CDN 已基本封堵） |
| **ECH GREASE** | Chrome 发送 ECH GREASE 扩展（即使没有真实 ECH 配置）。如果模板模拟 Chrome 但缺少 ECH GREASE，也是指纹偏差 |

### 10. TCP/IP 栈指纹

TCP/IP 栈指纹是 TLS 指纹之外的第二维度，审查系统通过交叉验证两层指纹的一致性来检测伪装。

| 检查项 | 说明 |
|--------|------|
| **初始 TTL 值** | TTL 值可以推断操作系统和距离。常见初始值：Linux=64, Windows=128, macOS=64。如果 TLS 指纹声称是 Windows Chrome 但 TTL 初始值显示 Linux（64 或因路由跳数减少后的值），交叉矛盾暴露伪装。需考虑网络路径上的跳数衰减 |
| **TCP 窗口大小** | 初始窗口大小是否与声称的操作系统一致？Linux 默认约 64240 字节，Windows 默认约 65535 字节。异常的窗口大小是 OS 指纹 |
| **TCP 选项顺序** | TCP 选项（MSS、Window Scale、SACK Permitted、Timestamp、NOP）的排列顺序和值是否与目标操作系统一致？Linux 和 Windows 的 TCP 选项顺序不同。例如 Linux 通常按 MSS → SACK → Timestamp → NOP → Window Scale 排序 |
| **TCP 选项值** | MSS 值、Window Scale 值、SACK 最大数量等选项值是否与目标操作系统一致？自定义值是 OS 指纹 |
| **IP 层特征** | IP 头中的 Don't Fragment（DF）位设置、TOS/DSCP 字段、IP ID 生成策略（递增、随机、零）是否与目标行为一致？不同 OS 的 IP ID 生成策略不同 |
| **QUIC/UDP 共存** | 如果服务端同时监听 TCP 443 和 UDP 443（QUIC），UDP 上的 QUIC 握手是否也经过合规处理？审查系统会同时检查 TCP 和 UDP 端口。QUIC ClientHello 同样有指纹 |
| **跨层一致性** | 所有层次的指纹必须指向同一个操作系统/浏览器组合。TLS 扩展顺序模拟 Chrome/Windows，但 TCP 选项顺序和 TTL 暴露了 Linux 内核——这种矛盾是致命的 |

### 11. TLS 记录层合规性

TLS 记录层是握手数据和应用数据的实际传输载体，记录层的构造方式是 TLS 库指纹。

| 检查项 | 说明 |
|--------|------|
| **记录版本号** | TLS 记录头的 `legacy_record_version` 应为 `0x0301`（TLS 1.0）或 `0x0303`（TLS 1.2）。BoringSSL 始终使用 `0x0303`，OpenSSL 在握手阶段可能使用 `0x0301`。不得使用 `0x0300` 或其他非标准值 |
| **content_type 正确性** | ApplicationData 记录的 content_type 必须为 `0x17`，Alert 为 `0x15`，Handshake 为 `0x16`，ChangeCipherSpec 为 `0x14`。加密后的记录外部 content_type 必须为 `0x17`（ApplicationData），即使内部是 Handshake 或 Alert |
| **记录长度合规** | 单条 TLS 记录有效载荷不得超过 2^14 + 256 字节（TLS 1.3 的 2^14 明文上限 + 256 字节 AEAD 标签/填充空间）。超长记录是协议违规 |
| **零填充剥离** | TLS 1.3 中，加密记录的内部明文末尾包含零填充字节 + 真实的 content_type 字节。剥离逻辑必须从末尾向前扫描找到第一个非零字节作为 content_type。剥离错误会导致数据损坏或 content_type 解析错误 |
| **记录分片策略** | TLS 记录如何分片是 TLS 库的指纹。BoringSSL 和 OpenSSL 在大数据分片上的行为有差异（如 Certificate 消息是否拆分为多条记录）。记录大小应与目标实现一致 |
| **空记录处理** | TLS 1.3 禁止发送零长度的 ApplicationData 记录。发送空记录是协议违规，也是实现缺陷的标志 |
| **记录边界时机** | 握手消息与 CCS 记录之间的记录边界是否与标准实现一致？不恰当的记录合并（如将 CCS 和 Finished 放在同一记录中）是异常 |

### 12. 伪装方案指纹隔离

多个伪装方案可能共存于同一服务端口，方案之间的指纹隔离至关重要。

| 检查项 | 说明 |
|--------|------|
| **方案间无泄漏** | 当 SNI 匹配方案 A 但实际走方案 B 时，方案 A 的特征不得泄漏到方案 B 的流量中。方案切换必须是干净的，不得残留前一方案的协议特征 |
| **非认证流量处理** | 非认证客户端的流量必须被完整转发到真实目标，不丢弃任何字节。丢弃或修改非认证流量字节会导致协议违规或指纹异常 |
| **CCS 记录处理** | ChangeCipherSpec 兼容记录必须正确处理。TLS 1.3 中 CCS 仅用于中间件兼容性，代理必须正确透传或模拟 CCS 记录，不得吞没或重复 |
| **错误隔离** | 一个方案的解析错误不得影响另一个方案的判断。方案 A 解析失败后回退到方案 B 时，读取的缓冲区数据必须完整保留并传递给方案 B |
| **缓冲区边界** | 多方案共用预读缓冲区时，每个方案只应消耗自己需要的数据，不得多读或少读。缓冲区偏移量在方案切换时必须正确重置 |
| **时序隔离** | 不同方案的响应时序不得泄漏方案类型。例如方案 A 的响应延迟为 50ms，方案 B 的响应延迟为 200ms，时序差异本身就是指纹 |

---

## 反模式代码示例与维护建议

审计执行流程、所有禁止/正确的代码模式对照、指纹模板维护策略详见 anti-patterns.md。

## 交叉引用

- `crypto-audit` 覆盖了本 skill 未深入探讨的证书字段完整性（CN/SAN 与 SNI 匹配、签名算法选择、有效期合理性、序列号随机性）、密钥交换安全性（X25519 低阶点检测）、常量时间操作维度
- `leak-audit` 覆盖了本 skill 未深入探讨的 TLS Alert 描述码指纹（BoringSSL vs OpenSSL 行为差异可被 JA4S 检测）、HTTP 错误响应格式指纹、部署规模追踪维度
- `probe-audit` 覆盖了本 skill 未深入探讨的 TLS 握手后应用层行为探测、多阶段探针响应一致性、回落机制形式化安全维度
- `security-audit` 提供了安全审计 skills 的编排指南，确定修改特定代码时应按何种顺序执行哪些审计
