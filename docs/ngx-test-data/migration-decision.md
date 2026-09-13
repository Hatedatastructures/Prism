# Preview 迁移决策矩阵

> 更新日期：2026-09-11
>
> 本表只记录证据驱动的迁移建议，不执行 `src/prism/` 或 `include/prism/` 迁移。
> `experimental` 表示 Preview 仍是参考实现或能力不完整；`keep-psm` 表示生产实现
> 仍是当前可用路径；`migrate` 只有在 L1-L5、生命周期和同 harness 性能证据齐全后
> 才允许使用。

> 本轮最终本地证据（2026-09-11）：CTest `3982` 注册、deterministic/interop 之外的功能集合
> `3855/3855` 通过、`25` Disabled、失败 `0`；PerformanceContract `4/4`，
> `Perf_Recognition` `741.10s`，其余 perf/stress 实际执行项 `97/97` 通过；
> `Perf_MultiConnLinear` 修复后单项连续 `3/3` 通过；G7/mirror `260/260`，
> detached `DANGEROUS=0`。外部矩阵为 `63 total / 54 pass / 9 blocked / 0 failed`；
> 生产 analyzer 与 carrier endpoint blockers 仍保持原状态。

> 当前性能 Contract 机器结果（来源：`build/perf-contract-results.json`，schema
> `prism.perf-contract.v2`）：`vless.parse_request`、`transport.mock_write` 和
> `vless.parse_request`、`transport.mock_write` 与 `transport.tcp_loopback` 为 `noise`；
> `ss2022.session_key` median `+12.86%`、p95 `+5.61%`，
> `socks5.parse_addr_port` median `+339.47%`/p95 `+321.49%`、
> `transport.udp_loopback` median `+10.91%`/p95 `+17.23%`，按规则标记为 `block`。
> 这些差异不被平均值或
> 重新选择样本隐藏，因此当前没有协议满足 `migrate`。

> 外部矩阵最新结果：`63 total / 54 pass / 9 blocked / 0 failed`；新增 VMess、SS2022
> 两条真实 `MixedTrial` 单端口识别记录，识别证据为 HTTP/SOCKS5/VLESS/Trojan/VMess/
> SS2022 `6/6`。这仍不解除生产 analyzer 或 Reality/Restls/ShadowTLS carrier 前置。

> Pad 配置映射后的最新本地回归：CTest `3868` 注册、`3843/3843` active 通过、`25`
> Disabled、失败 `0`；`Perf_Recognition` `682.03s`，全量墙钟 `817.40s`。

> Pad CSPRNG 失败收口后的最新本地回归：CTest `3869` 注册、`3844/3844` active 通过、
> `25` Disabled、失败 `0`；`Perf_Recognition` `698.72s`，全量墙钟 `807.99s`。

> TrustTunnel/DNS/Pad 历史回归：CTest `3870` 注册、`3845/3845` active 通过、
> `25` Disabled、失败 `0`；`Perf_Recognition` `707.47s`，全量墙钟 `816.59s`；
> 外部矩阵 `63 total / 54 pass / 9 blocked / 0 failed`。

> 2026-09-08 ShadowTLS v3 标准首包/relay 增量后复核：CTest 注册 `3826` 项，`3801/3801` active 通过，`25`
> 个 `StealthNested2` 明确 Disabled；`Perf_Recognition` 正式默认参数耗时 `629.91s`，
> 全量 CTest 墙钟 `762.50s`，专用 CTest timeout 为 `1800s`。该增量只影响 Preview record/relay data-plane，不解除外部 carrier 或生产
> analyzer 的 Gate D 前置。

> 2026-09-10 历史全量复核：CTest `3858` 注册、`3833/3833` active 通过、`25` Disabled、失败 `0`；
> `Perf_Recognition` `765.00s`，全量墙钟 `897.21s`。早先 `629.91s/762.50s`、`1017.75s/1149.13s`、`631.62s/746.10s`、`704.52s/819.63s`、`910.39s/1043.53s`、`694.03s/811.57s`、`695.29s/811.94s`、`781.21s/945.66s`、`1504.73s/1662.60s`、`806.15s/960.65s`、`699.80s/827.68s` 为历史性能样本，不能用于替代本次结果。

> 历史全量复核覆盖上述快照：CTest 注册 `3858` 项，`3833/3833` active 通过，`25` Disabled，
> `Perf_Recognition` `765.00s`，全量墙钟 `897.21s`；早先 `629.91s/762.50s`、`1017.75s/1149.13s`、`631.62s/746.10s`、`704.52s/819.63s`、`910.39s/1043.53s`、`694.03s/811.57s`、`695.29s/811.94s`、`781.21s/945.66s`、`1504.73s/1662.60s`、`806.15s/960.65s`、`699.80s/827.68s` 为历史样本。

| 组件 | L1/L2 | L3 | L4 生产对拍 | L5 外部互操作 | 性能 | 当前建议 | 阻塞 |
|---|---|---|---|---|---|---|---|
| HTTP / SOCKS5 | 已有 Preview 测试 | SOCKS5 TCP/UDP 已有纵向证据；`Socks5LongitudinalCoverage` 5/5 补齐认证/half-close/timeout/统计/上游中断 | SOCKS5 双向 PASS | 独立 Go RFC1928 reference 双向 TCP PASS；其他外部方向待补 | `socks5.parse_addr_port` median `+339.47%`/p95 `+321.49%`（`block`；Preview 地址结果包含文本化成本）；psm 网络对拍待补 | `experimental` | 性能 block、Gate D L5 |
| VLESS | codec/session + 非法 ATYP 已验证 | TCP/UDP 纵向 PASS | fresh L4 echo 仍受生产 analyzer 阻塞，authfail PASS | 独立 Go reference 双向 TCP/UDP PASS；其他外部方向待补 | 待补 | `experimental` | 生产前置、L5、性能 |
| Trojan | codec/session 已验证 | TCP/UDP 纵向 PASS | fresh L4 echo 仍受生产 analyzer/SS2022 fallback 阻塞，authfail PASS | Preview↔独立 Go reference 双向 PASS；其他外部方向待补 | 待补 | `experimental` | 单端口识别、生产前置 |
| VMess | 标准 AEAD ChunkMasking/response wire、codec/session 已验证 | TCP/UDP 纵向 PASS | fresh L4 VMess echo PASS；历史 analyzer/fallback 证据需继续观察 | `sing-vmess` TCP+UDP → Preview server、Preview client → 独立 `sing-vmess` reference server TCP/UDP PASS | 待补 | `experimental` | L5、性能；生产结果需稳定性复核 |
| Shadowsocks 2022 | raw PSK/长度边界已验证 | TCP/UDP 纵向 PASS | 双向 PASS | sing-shadowsocks 双向 PASS | `ss2022.session_key` median `+12.86%`（`block`；p95 `+5.61%`）；codec Contract 与 Preview recognition baseline 已有，网络 harness 待补 | `experimental` | 性能 block |
| XHTTP / HTTP2 | 标准字段、状态负向和 H2 preface 已验证 | Stream-one TLS/HTTP2 client/server 已验证 | 待补 | Preview client→Go `x/net/http2` server、Go reference client→Preview server authenticated-echo 均 PASS；request half-close 已验证 | 待补 | `experimental` | stream-up/packet-up、生产对拍、性能 |
| WebSocket / gRPC | WebSocket RFC 6455 codec/session 已验证；gun-lite 已验证 | WebSocket 双向 TCP E2E PASS；gun-lite 双向 TCP PASS | 待补 | WebSocket 已通过独立 Go `gobwas/ws` reference 双向 TCP；gun-lite 已通过独立 Go reference 双向 TCP；标准 gRPC/HTTP2 待补 | 待补 | `experimental` | 外部全链路、统一性能 |
| Native TLS | TLS codec/session 已验证 | TLS 回环已验证 | 未做 | 标准 Go `crypto/tls` reference 双向 TCP authenticated-echo PASS | 独立 Preview baseline；网络对拍待做 | `experimental` | 统一性能、其他 carrier 组合 |
| Reality / ShadowTLS / Restls | codec/session 已验证；ShadowTLS v3 首包/relay 已补 | 未闭合 | 待补 | ShadowTLS reference client→Preview server authenticated-echo PASS；Reality/Restls 双向与 ShadowTLS Preview client→reference server 仍为 interface-gap | 独立基线 | `keep-psm` | SNI/真实双向对拍 |
| AnyTLS / TrustTunnel | AnyTLS codec/session 和独立认证帧已验证；TrustTunnel 标准 HTTP/2 CONNECT、Basic Auth、DATA 和 half-close 已验证 | AnyTLS 认证帧 TCP E2E PASS；TrustTunnel 标准 TLS/HTTP2 CONNECT E2E PASS | 待补 | AnyTLS 独立认证帧 reference 双向 TCP PASS；TrustTunnel Go `x/net/http2` reference 双向 CONNECT echo PASS | 独立基线；完整 TLS/多路复用性能待补 | `experimental` | 生产对拍、统一性能 |
| Hysteria2 / TUIC v5 | codec + provider 接口已验证 | native ngtcp2 UDP loopback 1/1；TUIC uni/bidi 认证和连接级绑定、Hysteria2 HTTP/3 认证流通过 | 未做 | Hysteria2 独立 `sing-quic` client↔Preview server TCP authenticated-echo + reference UDP→Preview authenticated-UDP-echo PASS；TUIC 独立 `quic-go` client↔Preview server TCP/UDP、Preview client↔mihomo reference server TCP/UDP authenticated-echo PASS | `transport.udp_loopback` median `+10.91%`、p95 `+17.23%`（`block`）；独立 Preview recognition baseline，网络对拍待做 | `experimental` | 性能 block、其他 L5 |

## 门禁状态

历史复核（2026-09-10）：CTest `3858` 注册、`3833/3833` active 通过、`25` Disabled；完整外部矩阵 `61 total / 52 pass / 9 blocked / 0 failed`，Preview-only 子集 `58 total / 52 pass / 6 blocked / 0 failed`，并新增 Deterministic HTTP、Deterministic SOCKS5、MixedTrial VLESS 与 MixedTrial Trojan 四条真实单端口识别记录（`recognition_coverage_complete=true`）。本轮还补齐确定性首字节冲突编译期拒绝、route-aware TLS SNI 派生、Probe partial+error 字节保留、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归。TrustTunnel 标准 HTTP/2 两方向、XHTTP 两方向与 request half-close、TrustTunnel transport 边界、CandidateRegistry 核心工厂/外层 carrier 组合、Configured/DeterministicRoute/MixedTrial 识别策略、TLS route boundary、HTTP bracket IPv6 校验、Session/Dial/Listener 失败收口、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception、ShadowTLS v3 ClientHello/ServerHello parser、stateful application-data、标准 server relay、Go/mihomo v3 client→Preview server authenticated-echo 与 Go golden、SOCKS5 greeting 分片 Probe、TLS record version、scheme 大小写和 Scheme mismatch 校验、HTTP/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC reference vectors 均已注册并通过；5 条为 `interface-gap`，1 条为 `environment-unavailable`，VLESS/Trojan/VMess 生产单端口 echo 为 3 条独立的 `blocked-production-prerequisite` 前置。当前权威结果见文档开头。

- Preview Evidence Gate：历史识别策略增量前的 CTest 为 `3774` 注册；当前权威基线为 `3874` 注册、`3849/3849` active 通过、`25` Disabled、`Perf_Recognition` `723.21s`、全量墙钟 `846.49s`；G7 `260/260`；detached `DANGEROUS=0`。完整外部矩阵为 63 条（54 pass、5 interface-gap、1 environment-unavailable、3 blocked-production-prerequisite、0 failure），Preview-only 子集为 60 条（54 pass、5 interface-gap、1 environment-unavailable）；六个真实单端口识别记录均 PASS，`recognition_coverage_complete=true`；生产 analyzer 前置仍单独阻塞 VLESS/Trojan/VMess 单端口 echo。Hysteria2/TUIC/TrustTunnel/XHTTP 标准 HTTP/2 两方向、ShadowTLS Preview server→mihomo v3 client、VLESS/TUIC/Hysteria2 reference TCP/UDP→Preview、TUIC Preview→mihomo reference TCP+UDP、native TLS 双向 TCP、WebSocket 双向 TCP、AnyTLS 独立认证帧双向 TCP、gun-lite 双向 TCP、HTTP/SOCKS5/Trojan/VLESS/VMess/SS2022 reference vectors 均有机器矩阵 PASS，Reality/Restls 双向和 ShadowTLS reverse 仍缺标准 carrier endpoint，native TLS codec-vector 不适用，VLESS/Trojan/VMess 生产单端口 echo 仍等待 analyzer 授权。
- Production Prerequisite Gate：`blocked-production-prerequisite`；VLESS/Trojan/VMess 真实单端口 echo 需要生产 analyzer 授权变更。
- 总 Gate D：未关闭；本轮明确不修改生产代码，也不以直接 handler 对拍替代单端口证据。

机器证据入口：外部矩阵逐用例 JSON 与汇总位于 `build/interop-results/`（当前 HEAD
`daad642655c13a14a7529f344f80bbac843d623f`，2026-09-07 重跑，`source_state=dirty`），codec 性能
Contract 位于 `build/tests/Contract/preview-production-perf.json`；这些文件由 runner
生成，表格中的 `blocked` 只表示明确的环境或生产前置阻塞，不等同于通过。

## 结果记录格式

外部互操作和性能 runner 必须写出以下字段，文档只引用结果文件：

```json
{
  "protocol": "ss2022",
  "direction": "preview-client-to-reference-server",
  "scenario": "authenticated-echo",
  "implementation": "sing-shadowsocks@0.2.12",
  "commit": "<runner checkout commit>",
  "platform": "windows-x64",
  "status": "pass",
  "exit_code": 0,
  "command": "<reproducible command>",
  "artifacts": ["<raw log>", "<metrics json>"]
}
```

允许的 `status` 值为 `pass`、`protocol-failure`、`implementation-mismatch`、
`environment-unavailable`、`interface-gap` 和 `blocked-production-prerequisite`。任何非 `pass` 状态
都必须保留原始日志和失败原因。
