# Next-Gen 协议完成度矩阵

> 更新日期：2026-09-11（Preview 确定性路由/有界试探识别策略、legacy 控制和窗口读取回归、QUIC 连接绑定、QUIC candidate 前置拒绝、Dgram over-reporting 收口、稳定性和性能门禁增量；L5/跨实现性能/Gate D 仍未闭合）
> 配套文档：[NEXTGEN_IMPLEMENTATION_PLAN.md](../NEXTGEN_IMPLEMENTATION_PLAN.md)、[benchmark.md](benchmark.md)、[coverage.md](coverage.md)、[LIFECYCLE_AUDIT.md](LIFECYCLE_AUDIT.md)、[LONG_TERM_PLAN.md](../LONG_TERM_PLAN.md)

## 等级定义

| 等级 | 含义 |
|---|---|
| L1 | codec、帧解析、边界和非法输入的纯函数测试 |
| L2 | conn/session 握手、认证和数据面测试（memory stream 回环） |
| L3 | runtime 纵向链路：listener → recognition → accept_protocol → dial → relay / udp_service → 真实 loopback 上游 |
| L4 | preview 与生产 Prism 的双向对拍 |
| L5 | 与 mihomo、sing-box、quic-go、sing-quic 等外部实现互操作 |

“已实现”只表示代码目录中存在相应组件；只有存在可复现测试证据时，才提升对应等级。

## 2026-09-11 当前证据

- 当前 Release 构建树注册 `3982` 个 CTest；deterministic/interop 之外的功能集合
  `3855/3855` 通过（普通功能组使用 `-j8`），`25` 个 `StealthNested2` 用例明确 Disabled；
  PerformanceContract `4/4` 通过。perf/stress 使用 `-j1`，`Perf_Recognition` `741.10s`
  通过，其余实际执行项 `97/97` 通过；`Perf_MultiConnLinear` 的 coroutine 捕获悬空
  段错误已修复，并经单项连续 3 次回归通过。
- `build/interop-results/summary.json` 当前为 `scope=full`、`63 total / 54 pass /
  9 blocked / 0 failed`，并记录 `recognition_coverage_complete=true`、固定 Go
  reference `reference_versions`、每个实际用例的 `wall_time_ms`、
  `peak_working_set_bytes` 和 `metrics_available`。
- 生产 Prism 的 CTest `interop` 组仍单独运行 `-j1`：单次复核 `4/4` 通过；TUIC
  独立连续 5 次为 `4/5`，仍有一次首连接 echo timeout。Fresh L4 对拍中
  SOCKS5/SS2022/VMess echo PASS、VLESS/Trojan echo FAIL；这些结果属于生产
  analyzer/QUIC 前置阻塞，不计入 Preview Evidence Gate 的 `63` 条外部矩阵结果，
  也未修改生产目录。
- `build/perf-contract-results.json` 当前为 `prism.perf-contract.v2`，包含 production/
  Preview 原始样本、`comparisons` 分级、CPU 字段和 `peak_working_set_bytes`。
- 当前 Contract 比较中，`ss2022.session_key` median `+12.86%`/p95 `+5.61%`、
  `socks5.parse_addr_port` median `+339.47%`/p95 `+321.49%`、
  `transport.udp_loopback` median `+10.91%`/p95 `+17.23%` 均为
  `block`；这是真实迁移阻塞证据，不是测试失败，也不能通过调整
  分类阈值消除。
- 当前仍未闭合的状态以机器结果为准：Reality/Restls 双向与 ShadowTLS
  Preview client→reference server 为 `interface-gap`，VLESS/Trojan/VMess 生产单端口
  为 `blocked-production-prerequisite`，native TLS codec-vector 为
  `environment-unavailable`。

## 2026-09-03 Preview 增量

- XHTTP Stream-one 已按 HTTP/2 标准使用小写 `:method`、`:path` 和 `content-type`，客户端工厂补齐 ALPN、connection preface、响应头确认和 request half-close；Preview client→Go reference server、Go reference client→Preview server 两方向均由真实 echo 验证，stream-up/packet-up 仍未验。
- SS2022 TCP 服务端已支持 `ServerConfig.UsePsk` 的 raw 16 字节 PSK，正确/错误 raw PSK 和 password 兼容路径均有回归。
- VLESS 未知 `ATYP` 现在返回 `BadMessage`，已知地址的截断输入继续返回 `NeedMore`。
- HTTP/2/HPACK 已补齐截断整数、固定载荷、END_HEADERS 和 idle/closed stream DATA 的负向测试。
- Preview Recognition 已能解析 TLS ClientHello SNI，并按大小写规范化和最长单标签通配执行可选 scheme；`Configured`（单候选兼容入口）、`DeterministicRoute`（唯一结构选择）和 `MixedTrial`（有界认证试探）均有真实 wire、预算、回滚和稳定性覆盖，Profile route 已在确定性/试探 coordinator 中实际裁剪 TLS candidate，SettingsBuilder 对仅配置 `Scheme + Recognition.Routes` 的 TLS candidate 派生 route patterns 供 inspector 校验，显式 `DefaultCandidate` 可控制缺失 SNI 的 fallback，候选结果保留实际外层 `Scheme`。SettingsBuilder 可将配置、immutable Profile、resolver 和 TcpListener SessionFactory 成对接线。legacy 路径不再用 ASCII VLESS、Trojan `CRLFCRLF` 或 VMess 首字节进行协议猜测，VLESS 仅接受标准二进制结构，opaque 协议由配置候选认证确认。新增 LayeredCandidateFactory 后，carrier 提交与内层 HTTP handler 的组合回归 `2/2` 通过。
- native ngtcp2 QUIC client/server UDP loopback、连接级 ALPN/CID 绑定、Hysteria2/TUIC provider-backed datagram 工厂和 MUX 生命周期均已验证；stream 首字节不再作为协议猜测依据。
- TCP Settings/Profile 构建在调用候选 factory 前拒绝 Hysteria2/TUIC/QuicCarrier，稳定返回 `QuicCandidateRequiresGateway`；QUIC 候选必须由独立 gateway/Composition 入口安装。
- 2026-09-10 双模式 Session 接线回归新增 `DeterministicProfileResolvesByStructuralSelector`、确定性首字节冲突编译期拒绝、route-aware TLS SNI 派生、Probe partial+error 字节保留、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归、错误 coordinator mode guard、canonical mode 名称、Settings idle timeout 映射、`AuthRequired` 缺省认证器拒绝、TLS Session ID 长度、重复扩展、deterministic route 目标边界、ECH 无 inner Hello 时拒绝、MaxConnections listener 装配和认证器共享所有权回归；当前全量 CTest 为 `3858` 注册、`3833/3833` active 通过、`25` Disabled、失败 `0`，`Perf_Recognition` `765.00s`，全量墙钟 `897.21s`。
- 当前默认 Release 构建树（benchmark/stress 开启、interop/perf Contract 关闭）注册 3858 个 CTest；3833 个 active 用例全部通过，25 个 `StealthNested2` 用例明确 Disabled，失败 0。新增 RecognitionPerf 默认 1000 warmup、7×10000 samples、RecognitionStability 5/5、LayeredCandidate 2/2、Settings/Profile bootstrap、CandidateRegistry 核心工厂和 carrier 组合、canonical `Deterministic` 配置（兼容 `Configured`/`DeterministicRoute`）与 `MixedTrial` 识别策略、TLS route implicit selector/ClientHello boundary、HTTP authority IPv6 校验、Session/Dial/Listener 失败收口（含 detached session 异常）、scheme exception replay/close、Snapshot partial+error replay 和 carrier scheme exception、ShadowTLS v3 ClientHello/ServerHello parser、stateful record protector、标准 server relay 回归、SOCKS5/HTTP greeting 分片 Probe、Probe partial+error 保留、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归、HTTP/2 connection preface（整包/分片/客户端发送）、HTTP/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC reference vectors、WebSocket RFC 6455 帧边界/握手、AnyTLS 独立认证帧 reference、TrustTunnel 标准 HTTP/2 CONNECT、gun-lite 握手回注、XHTTP client/server 两方向、确定性首字节冲突编译拒绝、route-aware TLS SNI 派生和 SOCKS5 longitudinal 5/5 均在全量门禁中通过。
- 外部互操作状态不在文档中手工复制；`scripts/interop/Run-Matrix.ps1` 已于
  2026-09-08 在当前 HEAD `daad642655c13a14a7529f344f80bbac843d623f` 重新生成
  `build/interop-results/summary.json` 及逐用例 JSON：总计 57、pass 48、blocked 9、
  failed 0；该次 runner 记录 `source_state=dirty`（使用当前未提交工作树二进制）；新增 Trojan Preview↔独立 Go reference 双向 authenticated-echo、VLESS
  Preview↔独立 Go reference 双向 TCP authenticated-echo、SOCKS5 Preview↔独立 Go
  reference 双向 TCP authenticated-echo、HTTP CONNECT Preview↔独立 Go reference
  双向 TCP authenticated-echo、Hysteria2 `sing-quic`/TUIC `quic-go` client↔Preview server authenticated-echo、
  Hysteria2/TUIC/VLESS reference UDP→Preview authenticated-UDP-echo，
  以及 VMess `sing-vmess` TCP/UDP client→Preview server、Preview client→独立
  `sing-vmess` reference server TCP/UDP。
  TUIC Preview→mihomo reference TCP+UDP、native TLS Preview↔Go reference TCP、WebSocket Preview↔Go
  `gobwas/ws` reference 双向 TCP、AnyTLS 独立认证帧 reference 双向 TCP、gun-lite 独立 reference 双向 TCP、Go `x/net/http2` 与 Preview XHTTP/TrustTunnel 两方向、ShadowTLS reference client→Preview server 已 PASS；Reality/Restls 双向和 ShadowTLS Preview client→reference server 方向共五条记录为 `interface-gap`，native TLS codec-vector 为 `environment-unavailable`，其余缺口和生产 analyzer 前置必须按结果中的状态字段解释。

## 公共层与运行时（Gate A/B/C 证据）

| 组件 | 代码 | 等级 | 证据 |
|---|---|---|---|
| relay（双向转发） | `preview/Runtime/Middleware/Builtin/Relay.hpp` | L3 | 独立双向 buffer、半关闭、空闲超时、写失败、并发双向——TimeoutRelay 7/7 + DialRelayEcho |
| memory stream | `preview/Transport/MemoryStream.hpp` | L3 | 单 executor 契约 + close/cancel/timeout 挂起读——Transport 15/15 |
| XHTTP transport | `preview/Protocols/Xhttp/Conn.hpp` | L2 | pending flush 所有权、channel 背压、EOF 重复防护、标准小写字段和 request half-close——XhttpErrorMatrix 7/7 + XhttpNgxE2E 2/2（stream-up/packet-up 未验） |
| mux session（smux/yamux/h2mux 公共） | `preview/Protocols/Mux/Session.hpp` | L2 | 非法帧/payload 超限 teardown、20/20 含 OwnershipAudit（stream 级错误矩阵、背压待补） |
| mux 中间件接入 | `preview/Runtime/Middleware/Builtin/Mux.hpp` + `preview/Runtime/Session.hpp` | L3 | 协议专用 listener 已配 `AcceptProtocol` 时正确包装——MuxE2ETest 2/2（直通/包装+中继） |
| pad 中间件接入 | `preview/Runtime/Middleware/Builtin/Pad.hpp` + `preview/Runtime/Session.hpp` | L3 | `ctx.pad` 透传，按配置包装 `PadTransport`——PadE2ETest 2/2 |
| DNS 解析接入 | `preview/Net/Dns/Resolver.hpp` + `preview/Net/Dialer/Dialer.hpp` | L3 | `async_resolve` 带 LRU/负缓存 + `dial_with_dns` 域名→IP 拨号——DnsDialE2ETest 3/3 |
| runtime：tcp_listener + session | `preview/Runtime/` | L3 | 亲和性、识别、AcceptProtocol、dial、relay、udp_service、流量统计 + mux/pad/dns——ListenerE2E 4/4、SessionOrchestration 5/5 |
| recognition | `preview/Runtime/Recognition/` + `preview/Composition/Recognition/` | L3 | 首包矩阵、ProbeBuffer 回注、Configured/DeterministicRoute/MixedTrial、ClientHello/SNI、TLS carrier→内层 handler 组合、路由执行和协议候选——Recognition/LayeredCandidate focused 与稳定性全绿 |

## 代理协议

| 协议 | 代码 | L1 | L2 | L3 | L4 | 证据 |
|---|---|---|---|---|---|---|
| SOCKS5 | `preview/Protocols/Socks5/` | ✅ | ✅ | ✅ TCP+UDP | ✅ 双向 | codec/session、TCP/UDP 纵向和错误矩阵全绿；新增 `Socks5LongitudinalCoverage` 5/5 覆盖认证/half-close/超时/统计/上游中断；独立 Go RFC1928 reference 双向 TCP echo 已 PASS |
| VLESS | `preview/Protocols/Vless/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession 15/15、ErrorMatrix 5/5，未知 ATYP 已拒绝；标准二进制头结构识别，legacy 不再接受 ASCII `VLESS` magic；独立 Go reference 双向 TCP 和 authenticated-UDP-echo 已 PASS |
| Trojan | `preview/Protocols/Trojan/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession、ErrorMatrix、CodecDeep 和纵向 TCP/UDP 证据齐全；legacy 不再猜 `CRLFCRLF`，配置候选负责凭据确认；与独立 Go reference 双向 authenticated-echo 已 PASS，真实生产单端口识别仍待补 |
| VMess | `preview/Protocols/Vmess/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession、ErrorMatrix 和纵向 TCP/UDP 证据齐全；标准 AEAD ChunkMasking/方向 key 已对齐，legacy 探测不再猜任意 `0x01`，MixedTrial 通过有界 AuthID/UUID 确认；`sing-vmess` TCP+UDP ↔ Preview server 已 PASS，生产单端口识别仍待补 |
| Shadowsocks 2022 | `preview/Protocols/Shadowsocks2022/` | ✅ | ✅ | ✅ TCP+UDP | ✅ 双向 | raw PSK、长度边界和纵向 TCP/UDP 证据齐全；与 sing-shadowsocks v0.2.12 双向互操作已有记录 |

## 伪装方案（当前为参考实现，迁移决策未定）

| 方案 | 代码 | 现状 | 说明 |
|---|---|---|---|
| Reality | `preview/Protocols/Reality/` | L1/L2 | crypto 与握手有测试；完整链路未验 |
| ShadowTLS | `preview/Protocols/Shadowtls/` | L3（server relay） | v3 ClientHello/ServerHello、application-data HMAC、目标 TLS relay 和 mihomo reference client→Preview server 已验证；Preview client→reference server 方向仍缺完整外层 TLS |
| Restls | `preview/Protocols/Restls/` | L1/L2 | 完整链路未验 |
| AnyTLS | `preview/Protocols/Anytls/` | L3（认证帧） | 独立 Go reference 双向认证帧 + TCP echo 已通过；真实 TLS/多路复用路径未验证 |
| TrustTunnel | `preview/Protocols/Trusttunnel/` | L3/L5 | 标准 TLS/HTTP/2 CONNECT、Basic Auth、authority、DATA echo 和 half-close 已由 Go `x/net/http2` 双方向验证；旧简化 Conn 保留兼容测试 |
| WebSocket | `preview/Protocols/Ws/` | L5 | RFC 6455 conn/session、mask/控制帧边界和 Go `gobwas/ws` reference 双向 TCP authenticated-echo 已通过 |
| XHTTP | `preview/Protocols/Xhttp/` | L3/L5 | Stream-one 标准 HTTP/2、TLS/ALPN/HEADERS/DATA echo 已通过；Preview client→Go reference server 与 Go reference client→Preview server 两方向均 PASS；stream-up/packet-up 未验 |
| gRPC (gun) | `preview/Protocols/Gun/` | L2（gun-lite） | gun-lite CONNECT/raw 数据面与独立 Go reference 双向 TCP 已通过；标准 HTTP/2/gRPC 闭环仍缺 |
| native TLS | `preview/Protocols/Native/` | L2 | TLS 回环；标准 Go `crypto/tls` reference 双向 TCP authenticated-echo 已 PASS |
| ECH | `preview/Protocols/Ech/` | L1 | keygen/ClientHello 扫描；完整互操作缺 |

> 决策：迁移前须明确每个方案"迁移 / 继续用 psm / 实验"三选一，并补对应证据。

## 多路复用（协议层，未接 runtime）

| 复用 | L1 | L2 | 说明 |
|---|---|---|---|
| smux | ✅ | ✅ | 帧编解码 + session 回环；长生命周期/背压待补 |
| yamux | ✅ | ✅ | 同左 |
| h2mux | ✅ | ✅ | 含 sing-mux StreamRequest（SingmuxRequest 7/7 + SingmuxE2E 通过，生产侧） |

## 历史质量门禁（2026-08-20）

| 门禁 | 结果 |
|---|---|
| Fuzz smoke | CodecFuzzTest 9/9、FuzzExtendedTest 6/6、DgramErrorCoverage 63/63（本次未重跑，仍绿） |
| Stress | Socks5/Vless/Networking/TimeoutRelay/UdpRelay 共 21/21（本次未重跑） |
| 本次新增纵向 | Trojan 11/11、VMess 11/11、SS2022 8/8、Mux 2/2、Pad 2/2、DnsDial 3/3、Golden 18/18 均绿 |
| Benchmark | 6 个 bench 基线已记录（见 benchmark.md；coverage 插桩下，正式基线待纯净 Release） |
| Coverage | lines 91.2%、functions 93.6%、branches 44.5%（见 coverage.md；本次新增分支待补至 60%+） |
| ASAN | 未执行（待白天构建窗；本次以 fuzz/stress 替代） |
| 全量回归 | 历史 Gate B/C 回归 166/166 绿；当前总量见下方 2026-09-05 门禁 |

## 2026-09-07 本地 Gate D 门禁

> 当前权威门禁（2026-09-11）：Release 构建 exit `0`；CTest 注册 `3972` 项，
> `3947/3947` active 通过，`25` 个 `StealthNested2` 用例明确 Disabled，失败 `0`；
> 功能并行 `3853/3853`，perf/stress 串行 `94/94`，`Perf_Recognition` `936.62s`，
> perf/stress 标签时间 `957.38s`，全量墙钟 `957.67s`；G7/mirror `260/260`，
> detached `DANGEROUS=0`。外部矩阵为 `63 total / 54 pass / 9 blocked / 0 failed`，
> 真实单端口识别 HTTP、SOCKS5、VLESS、Trojan、VMess、SS2022 共 `6/6` 通过。
> 生产 analyzer、Reality/Restls/ShadowTLS carrier endpoint 和完整网络性能对拍仍是 Gate D blocker。

> 2026-09-10 历史本地回归：CTest `3867` 注册、`3842/3842` active 通过、`25`
> Disabled、失败 `0`；`Perf_Recognition` `676.26s`，全量墙钟 `802.33s`；G7/mirror
> `260/260`，detached `DANGEROUS=0`。此前 `3858/3833` 与 `765.00s/897.21s`
> 为历史快照；外部矩阵仍以 `build/interop-results/summary.json` 的 `61/52/9/0`
> 结果为准。

> 2026-09-10 识别矩阵最新结果：新增 sing-vmess TCP-only、sing-shadowsocks SS2022
> reference client → Preview `MixedTrial` 单端口 authenticated-echo；完整矩阵为
> `63 total / 54 pass / 9 blocked / 0 failed`，HTTP、SOCKS5、VLESS、Trojan、VMess、
> SS2022 六条真实单端口识别均通过。

> Pad 配置映射后的历史全量回归：CTest `3868` 注册、`3843/3843` active 通过、`25`
> Disabled、失败 `0`；`Perf_Recognition` `682.03s`，全量墙钟 `817.40s`；Pad focused `3/3`。

> Pad CSPRNG 失败收口后的历史全量回归：CTest `3869` 注册、`3844/3844` active 通过、
> `25` Disabled、失败 `0`；`Perf_Recognition` `698.72s`，全量墙钟 `807.99s`；
> Pad focused `11/11`。

> TrustTunnel/DNS/Pad 最终回归：CTest `3870` 注册、`3845/3845` active 通过、`25`
> Disabled、失败 `0`；`Perf_Recognition` `707.47s`，全量墙钟 `816.59s`；外部矩阵
> `63 total / 54 pass / 9 blocked / 0 failed`。

> DNS First loser 生命周期回归：独立 cancellation signal、首胜取消和 owner release 均已验证，
> DnsUpstream focused `34/34` 通过。

> 历史权威本地回归：CTest `3858` 注册、`3833/3833` active 通过、`25` Disabled、失败 `0`；
> `Perf_Recognition` `765.00s`，全量 CTest 墙钟 `897.21s`。当前权威结果见本节最上方。

最新复核（2026-09-10）：CTest `3858` 注册、`3833/3833` active 通过、`25` Disabled；完整外部矩阵 `scope=full`、`production_prerequisite_included=true`，共 `61 total / 52 pass / 9 blocked / 0 failed`；Preview-only scope 为 `58 total / 52 pass / 6 blocked / 0 failed`。Deterministic HTTP、Deterministic SOCKS5、MixedTrial VLESS 与 MixedTrial Trojan 四条真实单端口识别记录均通过，`recognition_coverage_complete=true`。新增 TrustTunnel 标准 HTTP/2 两方向、XHTTP client/server 两方向、request half-close、TrustTunnel transport EOF/队列回归、CandidateRegistry 核心工厂/外层 carrier 组合、Configured/DeterministicRoute/MixedTrial 识别策略、TLS route implicit selector/ClientHello boundary、HTTP bracket IPv6 校验、Session/Dial/Listener 失败收口、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归、ShadowTLS v3 ClientHello/ServerHello parser、stateful application-data、标准 server relay、Go/mihomo v3 client→Preview server authenticated-echo 与 Go golden、SOCKS5/HTTP greeting 分片 Probe、Probe partial+error 保留、确定性首字节冲突编译拒绝、route-aware TLS SNI 派生、TLS record version、scheme 大小写和 Scheme mismatch 校验，以及 HTTP/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC reference vectors 已注册并通过；阻塞项为 5 条 `interface-gap`、1 条 `environment-unavailable` 和 3 条 `blocked-production-prerequisite`。

| 门禁 | 结果 |
|---|---|
| Release build | `cmake --build build --config Release -j 16`：exit `0`（2026-09-11 白天最终本地构建） |
| 全量 CTest | 最终 `3972` 注册，`3947/3947` active 通过，`25` `StealthNested2` 明确 Disabled，失败 `0`；Socks5Longitudinal、LayeredCandidate、Settings/Profile bootstrap、CandidateRegistry、Configured/DeterministicRoute/MixedTrial 识别策略、TLS route boundary、HTTP bracket IPv6、Session/Dial/Listener 失败收口、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception、legacy Pipeline 预取消控制、窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归、ShadowTLS codec/Conn/Relay、ShadowTLS over-report、Mux read loop over-report、VLESS Conn 读写 over-report、SS2022 UDP/发送 over-report、Common Read window、SOCKS5/HTTP greeting 分片 Probe、Probe partial+error 保留、H2 preface、HTTP/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC reference vectors、WebSocket RFC 6455、Gun coalesced handshake、TrustTunnel 标准 HTTP/2、XHTTP client/server、Pad/DNS/TrustTunnel/serializer/QUIC random failure paths、Hysteria2/TUIC/TrustTunnel/SOCKS5/Trojan/VLESS/AnyTLS/Reality/VMess/SS2022 over-report 回归和 HTTP/SOCKS5/VLESS/Trojan/VMess/SS2022 单端口识别均通过 |
| Recognition stability | `RecognitionStability` `5/5`；顺序 1000/模式、16/32 并发、逐字节分片、EOF/half-close、timeout、mutation、10000 opaque 前缀 |
| Recognition performance | `Perf_Recognition` `1/1`；默认 1000 warmup、7 samples、10000 trials/sample，CTest 专用 timeout `1800s`，2026-09-11 全量运行耗时 `936.62s`；本次 perf/stress 标签时间 `957.38s`，全量墙钟 `957.67s` |
| H2/XHTTP regression | H2 focused `41/41`；`XhttpNgxE2E` `2/2`、`XhttpErrorMatrix` `7/7` |
| QUIC/carrier/MUX | Task 7 focused 主会话 `119/119`；扩大集合报告 `149/149`；native ngtcp2 loopback 通过 |
| G7/mirror | 当前 `260 headers, 260 owned entries`；早期 `259/259` 为历史快照 |
| detached audit | `DANGEROUS: 0`（`REVIEW: 27`） |
| Preview Gate D workflow | 已加入 perf/stability focused steps、interop classifier 和 verbose artifacts；本地 workflow syntax gate 已通过（主工作流 `5` 个、Preview Gate D `7` 个字面 `run` 块），hosted run 待提交后验证 |
| 生产边界 | `src/prism/`、`include/prism/` 无改动；未执行 commit/push，hosted CI 未在本工作树验证 |

## Gate D 缺口（2026-09-05 更新）

| 项 | 状态 |
|---|---|
| L4 生产对拍（preview ↔ psm 双向） | ⚠️ 部分：socks5/ss2022 双向 PASS；vless/trojan/vmess authfail PASS、echo 受阻于生产识别器（`src/prism/handshake/recognition/probe/analyzer.cpp`；详见 `interop/psm-l4.md`） |
| L5 外部互操作 | ⚠️ 完整机器矩阵当前 `61` 条：`52 pass`、`5 interface-gap`、`1 environment-unavailable`、`3 blocked-production-prerequisite`、`0 protocol-failure/implementation-mismatch`；Preview-only 子集为 `58` 条（`52 pass`、`5 interface-gap`、`1 environment-unavailable`）。Deterministic HTTP、Deterministic SOCKS5、MixedTrial VLESS 与 MixedTrial Trojan 四条真实单端口识别记录均通过，`recognition_coverage_complete=true`。HTTP CONNECT/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC/XHTTP/TrustTunnel reference vectors 和标准双向 echo、SOCKS5/Trojan/VLESS/AnyTLS/WebSocket/gun-lite/native TLS 双向 TCP、ShadowTLS reference client→Preview server authenticated-echo、VLESS/TUIC/Hysteria2 reference UDP→Preview、TUIC Preview→mihomo reference TCP+UDP 已补；Reality/Restls 双向与 ShadowTLS Preview client→reference server 方向仍缺标准 carrier endpoint，native TLS codec-vector 不适用，VLESS/Trojan/VMess 生产单端口 echo 仍等待 analyzer 授权 |
| L5 golden vector | ✅ 已做 18/18（SOCKS5/VLESS + Trojan/VMess/SS2022 各 3+） |
| preview vs psm 同场景性能对标 | ⚠️ Preview recognition baseline 与同一 Contract 的 codec/TCP/UDP loopback 已做；同一代理握手/外网/RSS harness 的 psm 对拍仍未做，不能计算迁移百分比 |
| 生命周期/错误链审查结论文档 | ✅ 已做 `LIFECYCLE_AUDIT.md`（detached/引用捕获/teardown/流量时序） |
| Trojan/VMess/SS2022 纵向链路（L3） | ✅ 已做（经 `preview/Composition/Adapters`，零耦合） |
| mux 中间件接入 runtime session | ✅ 已做 2/2 |
| pad 中间件接入 | ✅ 已做 2/2 |
| DNS resolver 接入 dial | ✅ 已做 3/3 |
| 伪装方案迁移决策 | ❌ 未定（链 S 待 S0 scheme_executor） |
| SOCKS5 纵向场景回归 | ✅ `Socks5LongitudinalCoverage` 5/5；认证、half-close、idle timeout、traffic 统计、上游中断均通过 |
| 真 bug 修复 | ✅ `session.hpp` recognition 放宽、`trojan/vmess` ipv6 16 字节二进制、`mux.hpp` 直通、`run_coro` ioc.stop 时序；2026-08-22 审查修复：Socks5 E2E UAF、地址编码越界/回绕、udp_tunnel 守护、ODR/自包含、无锁统计等（见 git 工作区） |

当前 `build/interop-results/summary.json` 还保存 `reference_versions`，版本来自固定的
`tests/go/go.mod`，包括 mihomo、quic-go、sing-quic、sing-vmess 和 metacubex/tls，
避免外部互操作结果只记录实现名称而缺少依赖版本。

> 本次新增：`TrojanE2ETest` 8/8、`TrojanUdpE2ETest` 3/3、`VMessE2ETest` 8/8、`VMessUdpE2ETest` 3/3、`SS2022E2ETest` 5/5、`SS2022UdpE2ETest` 3/3、`MuxE2ETest` 2/2、`PadE2ETest` 2/2、`DnsDialE2ETest` 3/3、`GoldenVector` 9→18
