# Prism Preview 全协议修复与 Mihomo 全量验证任务提示词

下面的内容可以直接复制到新的 Codex 任务中执行。

## 任务目标

你现在负责完成 `I:\code\Prism` 的 Preview 全协议真实验证和识别架构修复。

这不是只读分析任务，也不是只跑单元测试的任务。你必须完成代码修复、必要的架构重构、构建、真实 `PrismPreview` 启动、隔离的 Mihomo 启动、真实业务请求、分阶段日志采集、失败重现、测试清理和最终独立复核。只有所有有效协议组合、所有要求的识别模式和所有真实业务请求都通过后才能结束。

必须解决两个层面的问题：

1. 修复外层 TLS 和魔改 TLS carrier 的识别架构。SNI/ALPN 只能作为候选提示，不能作为 ShadowTLS、Restls、Reality、WebSocket、XHTTP、Gun 等协议的最终身份判断。
2. 保证当前 Preview 声明支持的所有普通代理协议、Native TLS、魔改 TLS、MUX、UDP/XUDP、QUIC 协议都能通过本机真实 Mihomo 业务请求验证。

## 不可违反的约束

### 模型和子代理

- 主代理和所有子代理只能使用 `gpt-5.6-luna`。
- 推理强度只能使用 `max`。
- 最多使用 4 个子代理，不能超过 4 个。
- 子代理必须分配清晰且互不重叠的任务范围。
- 不允许中途主动打断正在执行的子代理。
- 必须等待已经启动的子代理全部完成。
- 子代理完成后，主代理必须重新检查其实际 diff、测试结果、进程和临时文件，不能直接相信子代理的“完成”结论。
- 子代理不再需要时必须关闭或归档，不能留下无意义的运行任务。
- 如果子代理失败，主代理必须接管任务继续完成，不能将失败标记成跳过。

### Git 和工作树

- 禁止 `git commit`、`git push`、`git amend`，除非用户之后明确授权。
- 当前工作树是 dirty 的，所有已有修改都属于用户。开始时必须记录：

  ```powershell
  git status --short
  git diff --stat
  git branch --show-current
  git log -1 --format='%h %ci %s'
  ```

- 不允许 `git reset --hard`、`git checkout --`、`git clean`，也不允许覆盖、删除或回滚无关修改。
- 只允许在当前 `I:\code\Prism` 工作区工作。
- 不要创建新的 worktree，除非用户之后明确要求。
- 只使用现有 `build/` 构建目录，禁止创建 `build_debug`、`build_release`、`build_tmp` 等新构建目录。
- 不要修改生产 PSM 代码来掩盖 Preview 的问题。Preview 的修复必须保持在 Preview、Preview/Application、Preview/Composition、Preview/Runtime、Preview/Protocols、Preview/Transport 和必要的测试/CMake 范围内。
- Preview 生产代码不能依赖 `TestSupport`。
- 只有 Contract 测试可以同时连接生产 PSM 和 Preview。

### 禁止 Python

- 禁止使用 Python 脚本读取、修改、生成、启动或清理测试。
- 可以使用 PowerShell、C++、仓库已有 Go 测试工具、CMake、CTest、Mihomo 和 OpenSSL。
- 如果已有脚本依赖 Python，必须使用 PowerShell、C++、Go 或仓库已有工具替代，不能为了方便新增 Python。

### 构建规则

- 每次构建前必须读取当前时间。
- 严格按照仓库 `AGENTS.md` 的时间和内存规则选择构建并发数。
- 构建前必须输出当前时间、构建目录、构建配置和并发数。
- 构建失败必须保留完整错误输出，不能只截取最后一行。
- 不允许使用旧二进制、旧配置或旧日志代替当前源代码验证。
- 每次最终声明前必须记录当前 `PrismPreview.exe` 的 SHA-256、当前配置 SHA-256、Mihomo 可执行文件路径和 SHA-256。

## 开始时必须核对的项目事实

开始后先进行只读审计，并使用 CodeGraph 理解调用路径。仓库存在 `.codegraph/` 时，优先使用：

```text
codegraph explore "<symbol or architecture question>"
```

重点核对下面的文件和符号：

- `Preview/Application/Application.cpp`
- `Preview/Runtime/Session.hpp`
- `Preview/Runtime/Recognition/MixedTrialMode.hpp`
- `Preview/Runtime/Recognition/ConfiguredMode.hpp`
- `Preview/Runtime/Recognition/ProbeBuffer.hpp`
- `Preview/Composition/Recognition/TlsCandidateFactory.hpp`
- `Preview/Composition/Recognition/LayeredCandidateFactory.hpp`
- `Preview/Composition/Recognition/CandidateRegistry.hpp`
- `Preview/Composition/Recognition/SettingsBuilder.hpp`
- `Preview/Runtime/Middleware/Builtin/Relay.hpp`
- `Preview/Protocols/Shadowtls/Server.hpp`
- `Preview/Protocols/Shadowtls/Conn.hpp`
- `Preview/Protocols/Restls/Server.hpp`
- `Preview/Protocols/Reality/Carrier.hpp`
- `Preview/Transport/NativeTls.hpp`
- `Preview/Transport/Encrypted.hpp`
- `Preview/Protocols/Ws`
- `Preview/Protocols/Xhttp`
- `Preview/Protocols/Gun`
- `Preview/Protocols/Anytls`
- `Preview/Protocols/Trusttunnel`
- `Preview/Ingress`
- `Preview/Application/Configuration`
- `Preview/CMakeLists.txt`
- `tests/Preview`
- `tests/Contract`
- `tests/Preview/integration/Matrix`
- `tests/go`
- `logs/preview-validation-local` 中当前最新的真实运行日志

必须重新核对以下事实，不能直接照搬旧结论：

- `MakeTcpRecognitionConfig()` 会把 carrier 的 SNI、ALPN、priority、fallback 复制到识别候选。
- `TlsCandidateFactory::InspectFeatures()` 当前主要依据 SNI、ALPN、ECH 和 fallback 进行结构匹配。
- ShadowTLS、Restls、WebSocket、XHTTP、Gun 的真正协议认证发生在 carrier commit 阶段。
- `MixedTrialMode` 会先筛选结构候选，再执行 Prepare/Commit。
- `Session` 会把识别结果中的 `transport` 交给内层协议 handler。
- `RelayMiddleware` 会收集方向错误并映射最终 fault code。
- 旧日志中可能出现“recognition accepted、accept success、dial success、HTTP 200，但 relay io_error”。这种情况不能直接等同于业务失败。
- 旧日志和旧 PASS 不能证明当前二进制正确，必须使用当前可执行文件和当前配置重新验证。

## 必须实现的识别架构

目标流程必须明确分成下面这些层次：

```text
Raw TCP ingress
    ↓
TLS record reassembly / byte-preserving probe
    ↓
ClientHello structural parse
    ↓
Carrier hint collection
    - SNI
    - ALPN
    - TLS version
    - ECH presence
    - record boundary
    - carrier-specific non-secret features
    ↓
Carrier candidate ranking
    ↓
Bounded carrier authentication trial
    - Native TLS
    - Reality
    - ShadowTLS
    - Restls
    - WebSocket
    - XHTTP
    - Gun/gRPC
    - TrustTunnel where configured
    ↓
Successful carrier handoff
    - explicit transport type
    - exact consumed bytes
    - replay/remaining bytes ownership
    - encrypted/protected/plain data-plane semantics
    ↓
Inner protocol recognition
    - HTTP
    - SOCKS5
    - VLESS
    - Trojan
    - VMess
    - Shadowsocks2022
    - AnyTLS
    - TrustTunnel
    ↓
Inner protocol authentication
    ↓
MUX / UDP / XUDP / QUIC data-plane setup
    ↓
Dial
    ↓
Relay
    ↓
Payload verification and clean close
```

必须满足以下语义：

1. SNI 和 ALPN 只能作为 carrier hint，不能直接代表 carrier 身份。
2. SNI/ALPN 可以用于候选排序和减少无意义的 trial，但不能在没有明确 fallback 策略时直接关闭连接。
3. ShadowTLS 必须由自己的 Session ID/HMAC 和后续 handover 确认。
4. Restls 必须由自己的认证、目标 ServerHello 和 handover 确认。
5. WebSocket 必须在 TLS 解密后执行 HTTP Upgrade，并校验 path/host。
6. XHTTP 必须在 TLS 解密后执行实际的 HTTP/2 或 XHTTP 模式接入。
7. Gun/gRPC 必须在 TLS 解密后执行 HTTP/2/gRPC 头和帧验证。
8. Reality 必须执行密钥、short ID、ClientHello 特征和响应流程，不能只把 SNI 命中作为成功。
9. ECH 不能简单对所有非 Reality 连接统一拒绝。必须区分 outer ClientHello、inner SNI、ECH GREASE、真实 ECH 和缺少 SNI 的情况。
10. 每个 carrier trial 必须拥有独立、可取消、可清理的状态，失败候选不能消费成功候选需要的输入。
11. `ProbeBuffer`、ReplayTransport 和 carrier transport handoff 必须保证：
    - 已读取的 ClientHello 不丢失；
    - 未消费数据不会重复消费；
    - inner handler 不会再次读取原始 TLS record；
    - commit 失败不会破坏 fallback 输入；
    - commit 返回值明确说明 consumed bytes、remaining bytes、transport kind 和 failure stage。
12. `CarrierAcceptResult.Transport` 非空不能单独代表数据面已经正确建立。必须明确区分 handshake accepted、carrier authenticated、transport handoff complete 和 first inner payload available。
13. `MixedTrial` 不能仅通过 `Prepared.size() == 1` 粗暴结束。必须具有优先级、hint 匹配等级、carrier auth 结果、ambiguity 规则、fallback 规则、取消和超时清理。
14. `Configured` 模式必须验证唯一候选的 carrier commit 和 inner protocol handoff。
15. `MixedTrial` 必须验证多个候选、多个 carrier、相同 SNI 下不同协议和 fallback。
16. `DeterministicRoute` 如果当前配置和实现允许，必须一并验证；如果不适用，必须给出配置验证器和源码证据，不能默默跳过。

## 必须覆盖的协议矩阵

先从当前源代码、配置验证器、候选注册表、协议目录、Mihomo 支持情况和已有测试生成有效组合矩阵，不能盲目排列无效组合。

至少覆盖这些内层协议：

- HTTP
- SOCKS5
- VLESS
- Trojan
- VMess
- Shadowsocks2022
- AnyTLS
- TrustTunnel
- Hysteria2
- TUIC

至少覆盖这些外层 carrier/传输：

- 裸 TCP
- Native TLS
- Reality
- ShadowTLS
- Restls
- WebSocket over TLS
- XHTTP over TLS
- Gun/gRPC over TLS
- TrustTunnel 实际 TLS/HTTP2 入口
- ECH 相关路径（如果当前配置和实现声明支持）

必须覆盖这些识别模式：

- Configured
- MixedTrial
- DeterministicRoute（如果当前实现和配置允许）

必须覆盖这些数据面：

- TCP
- SOCKS5 UDP
- VLESS UDP/XUDP
- Trojan UDP
- VMess UDP
- Shadowsocks2022 UDP
- smux
- yamux
- h2mux
- 当前配置实际支持的 4 connections / 64 streams、1 connection / 256 streams 等 MUX 组合
- Hysteria2 QUIC
- TUIC QUIC

矩阵规则：

- 所有源代码和配置声明支持的有效组合必须真实运行。
- 真正不合法的组合必须由配置验证器拒绝并记录为 `InvalidByConfiguration`，不能标为 `Skipped`。
- 最终有效矩阵不得出现 `Skipped`、`Pending`、`Unknown`、`NotSupported`、`Blocked` 或未解释的 TODO。
- 每个有效矩阵行至少重复 3 次。
- 第一次请求必须成功，不能只要求后两次成功。
- 必须验证真实业务 payload，不能只看端口、握手、health check 或 URL-test 延迟。

## Mihomo 和 Agent 网络隔离

测试不能影响本机已有 Agent、Codex、SSH、系统代理或主 Mihomo 网络。

开始测试前记录：

- 所有已有 Prism/PrismPreview/Mihomo 进程；
- 所有已有监听端口；
- 主 Mihomo PID、名称、路径和监听端口；
- 当前全局代理相关环境变量；
- 当前 SSH/Codex 连接状态。

硬性规则：

1. 只能操作本次任务自己启动的进程。
2. 不能终止已有的 `verge-mihomo.exe`、Codex、SSH、系统服务或其他用户进程。
3. 每个案例使用独立 Mihomo home、独立配置、独立 HTTP/SOCKS 端口和独立 external-controller 端口。
4. PrismPreview 使用随机、隔离且未占用的监听端口。
5. 测试只使用进程级环境变量，禁止修改全局 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、系统代理或用户代理配置。
6. Codex、SSH、Agent 网络请求必须保持直连。只对本地测试地址设置进程级 `NO_PROXY`。
7. 测试不得使用主 Mihomo 的端口、home、配置、cache.db 或 external-controller。
8. 每个案例结束后必须停止自己启动的 Mihomo、PrismPreview、target、TLS fixture、UDP echo、QUIC fixture 和 helper，并确认 PID 已退出。
9. 每个案例的临时 home、cache、临时配置和临时中间日志必须删除。只保留最终矩阵、首个失败日志、最终必要诊断和哈希。
10. 如果测试异常退出，必须先执行故障清理，再继续下一行。

## 测试目标服务

优先使用仓库已有 C++/Go/PowerShell helper，不要重新写 Python 工具。

目标服务尽量全部在本机运行：

- HTTP 响应或文件服务；
- TLS target；
- UDP echo；
- QUIC target；
- WebSocket/HTTP2/gRPC helper；
- ShadowTLS/Restls handover target；
- Reality target。

每条真实测试必须能够回答：

```text
Mihomo 是否成功连接 PrismPreview？
raw ingress 是否完成？
ClientHello 是否完整读取？
识别候选是谁？
carrier hint 是什么？
carrier authentication 是否成功？
carrier transport 是否交接完成？
inner protocol 是否认证？
MUX/UDP/QUIC 是否启动？
dial 是否成功？
relay 双向 payload 是否通过？
目标服务是否收到请求？
Mihomo 是否收到正确响应？
连接关闭是否被正确分类？
```

每行必须保留：

- test case id；
- protocol；
- carrier；
- recognition mode；
- transport；
- mux mode；
- PrismPreview executable path 和 SHA-256；
- exact config path 和 SHA-256；
- Mihomo path 和 SHA-256；
- target process 和 target port；
- 所有子进程 PID；
- attempt number；
- first result；
- repeated results；
- first failure stage；
- native error；
- protocol error；
- payload result；
- cleanup result。

## TDD 和修复顺序

必须先建立真实失败证据，再修复。

### 第一阶段：RED

至少建立这些失败测试：

1. SNI/ALPN 不匹配时，记录明确的 carrier hint mismatch，而不是只返回无上下文的 `no_match`。
2. SNI/ALPN 命中但 carrier auth 失败时，区分 `carrier_auth_failed` 和 `no_match`。
3. ShadowTLS HMAC/handshake 失败和 ClientHello parse 失败必须区分。
4. Restls handover 失败和 TLS SNI 不匹配必须区分。
5. carrier commit 返回 transport 后，验证 replay、consumed bytes 和 first payload 语义。
6. Relay 对 clean EOF、protocol EOF、decrypt failure、connection reset、write failure、timeout 必须返回不同错误类别。
7. Configured、MixedTrial、DeterministicRoute 分别覆盖 carrier acceptance、ambiguity、fallback 和 cancellation。

### 第二阶段：架构修复

按单一根因逐项修复，不要同时修改无关模块：

1. carrier hint 与 carrier authentication 分离；
2. 候选 trial、优先级和 fallback；
3. TransportHandoff、ProbeBuffer 和 Replay；
4. inner protocol handoff；
5. Relay 错误语义和日志；
6. 各具体 carrier 的协议细节。

### 第三阶段：目录整理

保持 Preview 分层：

```text
Preview/Foundation
Preview/Transport
Preview/Net
Preview/Runtime
Preview/Composition
Preview/Protocols
Preview/Application
tests/Preview
tests/Contract
tests/Support
```

目录要求：

- 识别数据结构放在 `Runtime/Recognition`；
- carrier hint 和 carrier trial orchestration 放在 `Composition/Recognition`；
- 各 carrier 的具体协议逻辑放在 `Protocols/<Carrier>`；
- transport wrapper 放在 `Transport`；
- Application 只负责配置、注册、生命周期和组合，不承载协议细节；
- 测试按模块放在 `tests/Preview/<module>`；
- Mihomo runner 放在 `tests/Preview/integration/Matrix`；
- 临时文件只能放在 `logs/preview-validation-local/<run-id>`；
- 不允许把临时 helper、配置、exe、日志散落到仓库根目录；
- 移动文件时同步更新 CMake、聚合头文件和所有引用；
- 目录整理不能丢弃现有用户文件。

## 子代理分工

最多 4 个子代理，全部使用 `gpt-5.6-luna`、推理强度 `max`。

### 子代理 1：识别架构和 carrier handoff

范围：

- `Preview/Runtime/Recognition`；
- `Preview/Composition/Recognition`；
- ProbeBuffer、ConfiguredMode、MixedTrialMode、Profile；
- carrier hint/auth trial；
- RED/GREEN 测试；
- 不修改 Mihomo runner 和 QUIC。

### 子代理 2：carrier 数据面

范围：

- Native TLS；
- Reality；
- ShadowTLS；
- Restls；
- WebSocket；
- XHTTP；
- Gun/gRPC；
- TrustTunnel/ECH；
- carrier transport 语义和 handoff 测试；
- 不修改矩阵 runner。

### 子代理 3：Mihomo 隔离测试框架

范围：

- `tests/Preview/integration/Matrix`；
- Mihomo 独立 home/config/port/PID 管理；
- exact executable/config hash；
- first request + repeat 3 times；
- 进程清理；
- Agent 网络隔离；
- 最终矩阵生成；
- 不修改 carrier 核心代码。

### 子代理 4：协议、MUX、UDP、QUIC 验证

范围：

- VLESS/Trojan/VMess/SS2022/HTTP/SOCKS5/AnyTLS/TrustTunnel；
- smux/yamux/h2mux；
- UDP/XUDP；
- Hysteria2/TUIC QUIC；
- 本地 target/echo；
- 真实 payload 验证。

每个子代理完成后，主代理必须阅读实际 diff、检查文件范围、检查 CMake 边界、重新运行相关测试、检查进程和临时目录，并对关键结论独立复核。

## 验证顺序

必须按以下顺序执行：

1. 只读审计和当前失败复现；
2. 建立 RED 测试；
3. 修复识别架构；
4. 运行 Recognition/Carrier/Transport/Relay focused tests；
5. 构建 PrismPreview；
6. 运行单 carrier、单协议最小 Mihomo 测试；
7. 运行所有 carrier 单协议矩阵；
8. 运行所有内层协议 Native TLS 矩阵；
9. 运行魔改 TLS + 所有有效内层协议矩阵；
10. 运行 Configured；
11. 运行 MixedTrial；
12. 运行 DeterministicRoute（如果当前实现允许）；
13. 运行 MUX；
14. 运行 UDP/XUDP；
15. 运行 Hysteria2/TUIC QUIC；
16. 运行完整 Mihomo 矩阵，每行至少 3 次；
17. 运行 focused CTest；
18. 运行完整 CTest；
19. 重新检查工作树；
20. 重新检查主 Mihomo、Codex、SSH 和系统网络；
21. 清理所有本次任务启动的进程和临时文件；
22. 主代理独立复核所有结果；
23. 所有门槛满足后才能结束。

## 完成条件

只有同时满足下面所有条件才能报告完成：

- 所有有效 TCP 协议组合通过；
- 所有有效 Native TLS 组合通过；
- Reality 通过；
- ShadowTLS 通过；
- Restls 通过；
- WebSocket 通过；
- XHTTP 通过；
- Gun/gRPC 通过；
- AnyTLS 通过；
- TrustTunnel 通过；
- Hysteria2 通过；
- TUIC 通过；
- 所有有效 MUX 组合通过；
- 所有有效 UDP/XUDP 组合通过；
- Configured 通过；
- MixedTrial 通过；
- DeterministicRoute 在适用配置下通过；
- 每个有效矩阵行第一次请求成功；
- 每个有效矩阵行至少重复 3 次且全部成功；
- 所有业务 payload 被本地目标服务正确收到并验证；
- 没有只依赖端口、TLS handshake 或 URL-test 的假 PASS；
- 没有 `Skipped`、`Pending`、`Unknown`、`NotSupported`、`Blocked`；
- 没有未解释的 `io_error`；
- clean EOF 不再被错误报告成协议失败；
- 所有 carrier handoff 都有明确日志；
- 所有 failure stage 都可区分；
- 所有本次启动的子进程已经退出；
- 所有临时 Mihomo home、cache、临时配置和临时 helper 已清理；
- 主 Mihomo PID、Codex、SSH、系统代理和 Agent 网络请求没有被影响；
- 完整 CTest 通过；
- 当前构建和当前配置哈希已经记录；
- 主代理已独立复核子代理修改和最终矩阵；
- 没有执行 commit、push 或 amend。

## 最终报告格式

最终报告必须包含：

1. 根因结论：识别架构问题、识别算法问题、数据面问题、已经修复的内容和不是根因的内容。
2. 修改文件和目录调整：每个文件为什么修改，是否移动文件，CMake/聚合头是否同步，Preview/PSM/TestSupport 边界是否保持。
3. 测试矩阵：总行数、首次成功数、3 次重复成功数、Configured 数量、MixedTrial 数量、DeterministicRoute 数量、Native TLS 数量、魔改 TLS 数量、UDP/QUIC/MUX 数量，失败数必须为 0。
4. 每个关键矩阵行的 PrismPreview SHA-256、配置 SHA-256、Mihomo SHA-256、target、结果、payload 和 cleanup 结果。
5. 测试命令、退出码、通过数、失败数和运行时间。
6. 网络隔离证据：主 Mihomo PID 前后相同、监听端口前后相同、Codex/SSH 未经过测试 Mihomo、全局代理变量未修改、本次进程均已退出。
7. 子代理复核：每个子代理任务、完成状态、主代理复核内容、关闭/归档状态以及主代理修正过的问题。
8. 如果任何一项没有通过，不能写“完成”，必须继续修复和验证。
