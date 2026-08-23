# Next-Gen 协议完成度矩阵

> 更新日期：2026-08-20（链 P 代理协议 L3 全打通 + adapter v2 收敛验收 + mux/pad/dns 接入 + golden 18/生命周期审计）
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

## 公共层与运行时（Gate A/B/C 证据）

| 组件 | 代码 | 等级 | 证据 |
|---|---|---|---|
| relay（双向转发） | `core/middleware/builtin/relay.hpp` | L3 | 独立双向 buffer、半关闭、空闲超时、写失败、并发双向——TimeoutRelay 7/7 + DialRelayEcho |
| memory stream | `core/transport/memory_stream.hpp` | L3 | 单 executor 契约 + close/cancel/timeout 挂起读——Transport 15/15 |
| XHTTP transport | `protocols/xhttp/conn.hpp` | L2 | pending flush 所有权、channel 背压、EOF 重复防护——XhttpErrorMatrix 5/5（stream-up/packet-up 未验） |
| mux session（smux/yamux/h2mux 公共） | `protocols/mux/session.hpp` | L2 | 非法帧/payload 超限 teardown、20/20 含 OwnershipAudit（stream 级错误矩阵、背压待补） |
| mux 中间件接入 | `core/middleware/builtin/mux.hpp` + `core/runtime/session.hpp:152` | L3 | 协议专用 listener 已配 `accept_protocol` 时正确包装——MuxE2ETest 2/2（直通/包装+中继） |
| pad 中间件接入 | `core/middleware/builtin/pad.hpp` + `core/runtime/session.hpp` | L3 | `ctx.pad` 透传，按配置包装 `pad_transport`——PadE2ETest 2/2 |
| DNS 解析接入 | `core/net/dns/resolver.hpp` + `core/net/dialer/dialer.hpp` | L3 | `async_resolve` 带 LRU/负缓存 + `dial_with_dns` 域名→IP 拨号——DnsDialE2ETest 3/3 |
| runtime：tcp_listener + session | `core/runtime/` | L3 | 亲和性、识别、accept_protocol、dial、relay、udp_service、流量统计 + mux/pad/dns——ListenerE2E 4/4（AffinityBalancer/TcpListener/StopStopsAccepting/ConnectionStorm）、SessionOrchestration 5/5 |
| recognition | `core/recognition/` | L3 | 首包矩阵（含 VLESS 结构化识别）、probe 回注、SNI 路由 + 协议专用放宽——RecognitionTest 13/13 |

## 代理协议

| 协议 | 代码 | L1 | L2 | L3 | L4 | 证据 |
|---|---|---|---|---|---|---|
| SOCKS5 | `protocols/socks5/` | ✅ | ✅ | ✅ TCP+UDP | ✅ 双向 | ConnSession 16/16、ErrorMatrix 8/8、Dgram 7/7；纵向：TCP CONNECT 3/3（FullConnectEcho/DialRefused/ReplyWriteFailure）+ UDP ASSOCIATE 5/5（echo/非法帧/空闲超时/TCP 断开/静默上游 A-1）。⚠️ 认证/half-close/超时/统计/延迟应答场景随 adapter v2 重构移除（旧 14 场景套件已删），缺口见 Gate D |
| VLESS | `protocols/vless/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession 15/15、ErrorMatrix 5/5；纵向：TCP 9/9（含 BadUuid/DialRefused/Traffic identity）+ UDP 3/3（echo/空闲超时/EOF） |
| Trojan | `protocols/trojan/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession、ErrorMatrix、CodecDeep 齐全；纵向经 adapter 缝：TCP 8/8（domain/ipv4/ipv6/BadPassword/DialRefused/HalfClose/IdleTimeout/Traffic identity）+ UDP 3/3（echo/空闲超时/TCP断开）— `TrojanE2ETest`/`TrojanUdpE2ETest` |
| VMess | `protocols/vmess/` | ✅ | ✅ | ✅ TCP+UDP | ⚠️ authfail | ConnSession、ErrorMatrix 齐全；纵向经 adapter：TCP 8/8（domain/ipv4/ipv6/BadUuid/DialRefused/HalfClose/IdleTimeout/Traffic identity）+ UDP 3/3 |
| Shadowsocks 2022 | `protocols/shadowsocks2022/` | ✅ | ✅ | ✅ TCP+UDP | ✅ 双向 | Codec/ConnSession 齐全；纵向经 adapter：TCP 5/5（domain/ipv4/BadPassword/DialRefused/Traffic）+ UDP 3/3（直连数据报通道）— `SS2022E2ETest`/`SS2022UdpE2ETest`；**L5 外部互操作：与 sing-shadowsocks v0.2.12（mihomo 同栈）双向 PASS**（`tests/go/interop/run_interop.ps1`，2026-08-20） |

## 伪装方案（当前为参考实现，迁移决策未定）

| 方案 | 代码 | 现状 | 说明 |
|---|---|---|---|
| Reality | `protocols/reality/` | L1/L2 | crypto 与握手有测试；完整链路未验 |
| ShadowTLS | `protocols/shadowtls/` | L2 | codec/session 相对较好；真实互操作缺 |
| Restls | `protocols/restls/` | L1/L2 | 同左 |
| AnyTLS | `protocols/anytls/` | L1/L2 | 多路复用路径未验证 |
| TrustTunnel | `protocols/trusttunnel/` | L1/L2 | HTTP/2 CONNECT 路径未闭环 |
| WebSocket | `protocols/ws/` | L2 | conn/session 有测试；异常边界待补 |
| XHTTP | `protocols/xhttp/` | L2 | 仅 stream-one；stream-up/packet-up 未验 |
| gRPC (gun) | `protocols/gun/` | L1 | 偏 codec；HTTP/2/gRPC 闭环缺 |
| native TLS | `protocols/native/` | L2 | TLS 回环；未接识别分发 |
| ECH | `protocols/ech/` | L1 | keygen/ClientHello 扫描；完整互操作缺 |

> 决策：迁移前须明确每个方案"迁移 / 继续用 psm / 实验"三选一，并补对应证据。

## 多路复用（协议层，未接 runtime）

| 复用 | L1 | L2 | 说明 |
|---|---|---|---|
| smux | ✅ | ✅ | 帧编解码 + session 回环；长生命周期/背压待补 |
| yamux | ✅ | ✅ | 同左 |
| h2mux | ✅ | ✅ | 含 sing-mux StreamRequest（SingmuxRequest 7/7 + SingmuxE2E 通过，生产侧） |

## 质量门禁（2026-08-20）

| 门禁 | 结果 |
|---|---|
| Fuzz smoke | CodecFuzzTest 9/9、FuzzExtendedTest 6/6、DgramErrorCoverage 63/63（本次未重跑，仍绿） |
| Stress | Socks5/Vless/Networking/TimeoutRelay/UdpRelay 共 21/21（本次未重跑） |
| 本次新增纵向 | Trojan 11/11、VMess 11/11、SS2022 8/8、Mux 2/2、Pad 2/2、DnsDial 3/3、Golden 18/18 均绿 |
| Benchmark | 6 个 bench 基线已记录（见 benchmark.md；coverage 插桩下，正式基线待纯净 Release） |
| Coverage | lines 91.2%、functions 93.6%、branches 44.5%（见 coverage.md；本次新增分支待补至 60%+） |
| ASAN | 未执行（待白天构建窗；本次以 fuzz/stress 替代） |
| 全量回归 | 166/166 绿（含 Trojan/VMess/SS2022/Mux/Pad/DnsDial/GoldenVector），`SessionOrchestration.UnknownProtocolRejected` 仍绿 |

## Gate D 缺口（2026-08-20 更新）

| 项 | 状态 |
|---|---|
| L4 生产对拍（preview ↔ psm 双向） | ⚠️ 部分：socks5/ss2022 双向 PASS；vless/trojan/vmess authfail PASS、echo 受阻于生产识别器（`src/prism/handshake/recognition/probe/analyzer.cpp`；详见 `interop/psm-l4.md`） |
| L5 外部互操作 | ⚠️ SS2022 双向 PASS（sing-shadowsocks v0.2.12）；其余协议待做 |
| L5 golden vector | ✅ 已做 18/18（SOCKS5/VLESS + Trojan/VMess/SS2022 各 3+） |
| preview vs psm 同场景性能对标 | ❌ 未做（需 E1） |
| 生命周期/错误链审查结论文档 | ✅ 已做 `LIFECYCLE_AUDIT.md`（detached/引用捕获/teardown/流量时序） |
| Trojan/VMess/SS2022 纵向链路（L3） | ✅ 已做（经 `core/runtime/adapter` 缝，零耦合） |
| mux 中间件接入 runtime session | ✅ 已做 2/2 |
| pad 中间件接入 | ✅ 已做 2/2 |
| DNS resolver 接入 dial | ✅ 已做 3/3 |
| 伪装方案迁移决策 | ❌ 未定（链 S 待 S0 scheme_executor） |
| SOCKS5 纵向场景回归 | ❌ adapter v2 重构移除的认证/half-close/超时/统计/延迟应答 5 类场景待补测（旧 14 场景套件已删，现仅 3/3） |
| 真 bug 修复 | ✅ `session.hpp` recognition 放宽、`trojan/vmess` ipv6 16 字节二进制、`mux.hpp` 直通、`run_coro` ioc.stop 时序；2026-08-22 审查修复：Socks5 E2E UAF、地址编码越界/回绕、udp_tunnel 守护、ODR/自包含、无锁统计等（见 git 工作区） |

> 本次新增：`TrojanE2ETest` 8/8、`TrojanUdpE2ETest` 3/3、`VMessE2ETest` 8/8、`VMessUdpE2ETest` 3/3、`SS2022E2ETest` 5/5、`SS2022UdpE2ETest` 3/3、`MuxE2ETest` 2/2、`PadE2ETest` 2/2、`DnsDialE2ETest` 3/3、`GoldenVector` 9→18
