---
name: dpi-fingerprint-audit
description: 深度包检测（DPI）指纹审计。在修改 TLS 握手、ALPN 协商、ClientHello/ServerHello 处理、伪装方案代码后触发，检查 TLS 指纹一致性、ALPN 状态机合规性、SNI 处理安全性、TCP/IP 栈指纹、GREASE 合规性、后量子密钥交换、TLS 库指纹等问题。
---

# Skill: DPI 指纹与 TLS 握手审计

在修改涉及 TLS 握手、协议识别、伪装方案代码后，必须对变更部分执行以下审计清单。审查系统通过旁路设备提取 TLS 握手阶段的所有明文字段进行模式匹配，任何非标准特征都会触发阻断。

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

## 审计清单

### 1. ClientHello 指纹一致性

| 检查项 | 说明 |
|--------|------|
| **密码套件顺序** | 加密套件列表及其排列顺序是否与目标浏览器一致？审查系统维护黑名单，已知非浏览器指纹直接阻断 |
| **扩展字段完整性** | supported_groups、key_share、signature_algorithms、psk_key_exchange_modes 等扩展是否与目标浏览器模板匹配？缺失扩展本身就是异常特征 |
| **扩展顺序一致性** | 扩展字段的排列顺序是否与目标浏览器完全一致？不同客户端的扩展顺序是可区分的 |
| **扩展内部值** | 不仅扩展的顺序要一致，每个扩展内部的值也要一致。如 signature_algorithms 列表中算法的排列顺序、supported_groups 中曲线的排列顺序 |
| **GREASE 值** | Chrome 等浏览器在密码套件、扩展、ALPN 中填充 GREASE 随机值（如 0x0a0a, 0x1a1a），用于前瞻兼容性测试。缺少 GREASE 值是非浏览器客户端的强特征 |
| **后量子密钥交换** | Chrome 已在 key_share 扩展中包含 ML-KEM（Kyber）密钥共享。如果代理的 ClientHello 缺少 ML-KEM，审查系统可以通过缺失的后量子扩展识别出"非最新 Chrome" |
| **session_id 用途** | 如果协议使用 session_id 承载加密认证数据，长度是否正确？不足则认证失败 |
| **TLS 版本列表** | supported_versions 扩展是否包含且仅包含目标版本？多余的旧版本会暴露非浏览器特征 |
| **随机数字段** | ClientHello.random 是否为密码学安全随机数？ |
| **指纹版本追踪** | 指纹模板是否跟随目标浏览器版本更新？停滞在旧版 Chrome 特征的"永不更新的客户端"本身就是异常。需要建立指纹模板的持续更新机制 |

### 2. ServerHello 响应合规性

| 检查项 | 说明 |
|--------|------|
| **版本号固定** | ServerHello 的 legacy_version 必须为 0x0303（TLS 1.2 兼容），supported_versions 扩展中为 0x0304（TLS 1.3）|
| **random 字段** | 必须为密码学安全随机数，不得包含可识别的模式或固定字节 |
| **cipher_suite 选择** | 必须从 ClientHello 提供的列表中选择，且选择逻辑与主流服务器行为一致 |
| **证书伪造质量** | 伪造证书签名是否正确？证书的 CN/SAN 是否与目标域名一致？ |
| **扩展响应完整性** | ServerHello 的扩展响应（key_share、pre_shared_key、supported_versions）是否与标准实现一致？缺少预期扩展或返回非预期扩展都是指纹 |

### 3. TLS 库服务端行为指纹

| 检查项 | 说明 |
|--------|------|
| **密码套件选择偏好** | 不同 TLS 库在面临多个可选密码套件时的选择偏好不同。BoringSSL、OpenSSL、LibreSSL 的优先级策略各异。选择策略必须与声称的 TLS 库一致 |
| **Hello Retry Request 行为** | 收到不包含合适 key_share 的 ClientHello 时，TLS 库发送 HRR 的格式和参数有实现差异。HRR 中的 extension 顺序和具体值是 TLS 库指纹 |
| **Alert 描述码精确性** | 同一种错误条件（如 MAC 验证失败），BoringSSL 返回 `bad_record_mac`，OpenSSL 可能返回 `decrypt_error`。Alert 描述码的选择是 TLS 库指纹 |
| **记录层构造差异** | 不同 TLS 库在分片、填充、记录版本号处理上有微小差异。这些差异在协议规范允许范围内，但可作为指纹 |
| **OCSP Stapling** | 真实 Web 服务器通常启用 OCSP Stapling（Certificate Status Request 扩展）。如果服务端声称是标准 Web 服务器但从不返回 OCSP 响应，缺失本身是特征 |
| **Certificate Compression** | Chrome 支持 compress_certificate 扩展（brotli/zstd）。如果服务端不识别此扩展，与声称的服务器类型不一致 |

### 4. 证书链与 SNI 交叉验证

| 检查项 | 说明 |
|--------|------|
| **证书签发方式** | 审查系统直接阻断自签名证书。证书必须由受信 CA 签发或伪造得足以通过链验证 |
| **CN/SAN 与 SNI 一致** | 证书的 CN/SAN 必须与 ClientHello 中的 SNI 匹配，不匹配会被封锁 |
| **证书链完整性** | 证书链是否完整？中间证书缺失会导致验证失败 |
| **批量申请异常** | 大量域名申请免费 CA 证书的行为会触发降级审查 |
| **证书透明度日志** | 注册的证书会被记入 CT Log，可被事后关联分析。伪造证书的注册模式应避免批量特征 |
| **dest 域名选择** | 回落目标是否指向真实可达的高信誉第三方域名？不可达的目标会导致 fallback 失败 |

### 5. ALPN 协商状态机

| 检查项 | 说明 |
|--------|------|
| **ALPN 设置方式** | 必须使用回调函数在握手时选择 ALPN，而非在共享 SSL_CTX 上设置（后者会污染所有连接） |
| **ALPN 与流量一致** | 协商结果为 h2 后，后续流量是否真正体现 HTTP/2 帧结构？ALPN 与实际传输不匹配会被状态机关联分析检测 |
| **ALPN 降级处理** | 客户端不支持所需 ALPN 时，是否正确降级？降级时应返回标准 TLS 传输而非代理 |
| **HTTP/2 帧指纹** | 如果协商了 h2，SETTINGS 帧的参数（HEADER_TABLE_SIZE、INITIAL_WINDOW_SIZE 等）是否与主流实现一致？自定义参数值是服务端指纹 |

### 6. 协议状态机完整性

| 检查项 | 说明 |
|--------|------|
| **状态转换序列** | TLS 握手的状态转换序列是否与目标实现完全一致？不只是"字段匹配"，而是整个状态机转换序列（如 CCS 插入时机、Finished 消息顺序）都必须模拟 |
| **错误状态转换** | 收到非预期消息时的状态转换是否与标准实现一致？自定义的错误处理路径本身就是指纹 |
| **重协商行为** | 收到重协商请求时的行为是否与标准 Web 服务器一致？ |
| **协议降级防御** | 审查系统可能强制协议降级（如发送仅支持 TLS 1.2 的 ClientHello）。如果服务端在降级后的行为与标准 TLS 1.2 实现不一致，降级路径暴露指纹 |

### 7. 握手后应用层指纹

| 检查项 | 说明 |
|--------|------|
| **HTTP/2 帧序列** | 握手完成后第一个应用层帧是否为标准 HTTP/2 SETTINGS？非标准帧序列（如直接发送 DATA 帧）是异常 |
| **HTTP/2 流量控制** | WINDOW_UPDATE 帧的频率和增量值是否与主流实现一致？异常的流量控制行为是服务端指纹 |
| **HTTP/2 优先级** | 是否正确处理 HTTP/2 的流优先级和依赖关系？完全忽略优先级是简化实现的标志 |
| **会话恢复模式** | 正常浏览器利用 TLS session resumption 或 0-RTT 减少握手延迟。如果代理的每次连接都是完整握手，缺少 session resumption 本身是异常特征 |

### 8. SNI 处理安全性

| 检查项 | 说明 |
|--------|------|
| **SNI 白名单** | 服务端 SNI 白名单是否只包含经过审查的高流量、高信誉域名？ |
| **空 SNI 防御** | 空 SNI 的连接是否安全回落到下一个伪装方案或转发到真实目标？不得直接拒绝或返回异常 |
| **SNI 交叉验证** | 服务端返回的证书 CN 是否与 ClientHello 中的 SNI 匹配？ |

### 9. ECH/ESNI 阻断防御

| 检查项 | 说明 |
|--------|------|
| **ECH 扩展检测** | 审查系统对携带 ECH 或老版 ESNI 扩展的 ClientHello 采取高概率丢弃或 RST。原因：审查系统无法窥探加密后的 SNI，宁可误杀 |
| **ECH 禁用决策** | 短期内为确保连通率可能需要禁用 ECH，但这牺牲了 SNI 隐私。需根据部署环境权衡 |
| **替代策略** | 如需隐藏 SNI，考虑双 TLS（外层正常握手 + 内层加密握手）、WebSocket+TLS、CDN 前置等方案替代 ECH |

### 10. TCP/IP 栈指纹

| 检查项 | 说明 |
|--------|------|
| **初始 TTL 值** | TTL 值可以推断操作系统（Linux=64, Windows=128）。如果 TLS 指纹声称是 Windows 但 TTL 显示 Linux，交叉矛盾暴露伪装 |
| **TCP 窗口大小** | 初始窗口大小是否与声称的操作系统一致？Linux 和 Windows 的默认值不同 |
| **TCP 选项顺序** | TCP 选项（MSS、Window Scale、SACK、Timestamp）的排列顺序和值是否与目标操作系统一致？ |
| **IP 层特征** | IP 头中的 Don't Fragment 位、TOS 字段等是否与目标行为一致？ |
| **QUIC/UDP 共存** | 如果服务端同时监听 TCP 443 和 UDP 443（QUIC），UDP 上的 QUIC 握手是否也经过合规处理？审查系统会同时检查 TCP 和 UDP 端口 |

### 11. TLS 记录层合规性

| 检查项 | 说明 |
|--------|------|
| **记录版本号** | TLS 记录头的 legacy_record_version 应为 0x0301（TLS 1.0）或 0x0303（TLS 1.2），不得使用 0x0300 |
| **content_type 正确性** | ApplicationData 记录的 content_type 必须为 0x17，Alert 为 0x15，Handshake 为 0x16 |
| **记录长度合规** | 单条 TLS 记录有效载荷不得超过 2^14 + 256 字节（TLS 1.3 限制） |
| **零填充剥离** | TLS 1.3 内层明文末尾的零填充 + content_type 剥离逻辑是否正确？剥离错误会导致数据损坏 |
| **记录分片策略** | TLS 记录如何分片是 TLS 库的指纹。BoringSSL 和 OpenSSL 在大数据分片上的行为有差异。记录大小应与目标实现一致 |

### 12. 伪装方案指纹隔离

| 检查项 | 说明 |
|--------|------|
| **方案间无泄漏** | 当 SNI 匹配方案 A 但实际走方案 B 时，方案 A 的特征是否泄漏到方案 B 的流量中？ |
| **非认证流量处理** | 非认证客户端的流量是否被完整转发到真实目标，不丢弃任何字节？ |
| **CCS 记录处理** | ChangeCipherSpec 兼容记录是否正确插入？TLS 1.3 中间件兼容性要求 |

## 审计流程

1. **识别变更范围**: 确定本次修改涉及哪个伪装方案、哪个握手阶段
2. **追踪握手路径**: 从 ClientHello 接收到最终响应发送，追踪完整握手路径
3. **计算指纹**: 使用 JA3/JA4 算法计算变更后的 ClientHello/ServerHello 指纹，与主流浏览器对比
4. **交叉一致性验证**: SNI → 证书 CN/SAN → 证书签发链 → ALPN → 后续流量 → TCP/IP 栈特征 → GREASE 值 → 后量子扩展 → TLS 库行为，整条链是否逻辑自洽
5. **状态机完整性**: 验证所有状态转换（包括错误路径、降级路径）与目标实现一致
6. **握手后指纹**: 验证应用层帧序列（SETTINGS、WINDOW_UPDATE 等）与主流实现一致
7. **TLS 库行为审计**: 确认服务端的密码套件选择偏好、Alert 描述码、记录构造等与声称的 TLS 库一致
8. **测试回落机制**: 确认非预期输入能正确回落到安全状态

## 常见反模式（禁止）

```cpp
// ❌ 污染共享 SSL_CTX 的 ALPN 设置
SSL_CTX_set_alpn_protos(ctx->native_handle(), alpn_data, alpn_len);

// ✅ 使用回调函数在握手时选择 ALPN
SSL_CTX_set_alpn_select_cb(ctx->native_handle(), ...);

// ❌ 直接拒绝空 SNI，暴露代理行为
if (sni.empty()) { close(); }

// ✅ 空 SNI 安全回落
if (sni.empty()) { set_preread(result); co_return result; }

// ❌ TLS 指纹与 TCP/IP 栈指纹矛盾
// TLS 扩展顺序模拟 Chrome/Windows，但 TCP 选项顺序和 TTL 暴露了 Linux 内核

// ✅ 所有层次的指纹必须指向同一个操作系统/浏览器组合

// ❌ 缺少 GREASE 值 — 非浏览器客户端的强特征

// ✅ 在密码套件、扩展、ALPN 中正确填充 GREASE 值

// ❌ 缺少后量子密钥交换 — "非最新 Chrome"
// Chrome 已在 key_share 中包含 ML-KEM (Kyber)

// ✅ 跟随浏览器版本更新 key_share 扩展，包含后量子密钥共享

// ❌ 指纹模板永不更新 — "永不更新的 Chrome" 是异常

// ✅ 建立指纹模板的持续更新机制，跟随目标浏览器版本

// ❌ TLS 库行为不一致 — ClientHello 声称 Chrome/BoringSSL，但服务端行为暴露 OpenSSL
// 如：密码套件选择偏好不符、Alert 描述码不匹配、记录分片策略不同

// ✅ 服务端行为指纹与 ClientHello 声称的 TLS 库完全一致
```
