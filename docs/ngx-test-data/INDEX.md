# Next-Gen 测试数据索引

本目录记录 `tests/common` 新架构的可重复测试基线、协议完成度和对拍材料。

当前本地基线（2026-09-11）：Release 构建通过；CTest 注册 `3961` 项，
`3936/3936` active 通过，`25` 个 `StealthNested2` 用例明确 Disabled，失败 `0`。

最终权威门禁：功能并行 `3842/3842`，perf/stress 串行 `94/94`，
`Perf_Recognition` `613.06s`，perf/stress 标签时间 `630.58s`，全量墙钟 `630.85s`，
G7/mirror `260/260`，detached `DANGEROUS=0`；外部矩阵为 `63 total / 54 pass /
9 blocked / 0 failed`。下文的更早数字均为历史快照。

历史基线：CTest 注册 `3867` 项，`3842/3842` active 通过，`25` 个
`StealthNested2` 用例明确 Disabled；`Perf_Recognition` `676.26s`，全量 CTest
墙钟 `802.33s`；G7/mirror `260/260`，detached `DANGEROUS=0`。上面的 3858
快照保留作历史对照。

Pad 配置映射后的最新回归：CTest 注册 `3868` 项，`3843/3843` active 通过，`25`
Disabled；`Perf_Recognition` `682.03s`，全量墙钟 `817.40s`；Pad focused `3/3`。

Pad CSPRNG 失败收口后的最新回归：CTest 注册 `3869` 项，`3844/3844` active 通过，
`25` Disabled；`Perf_Recognition` `698.72s`，全量墙钟 `807.99s`；Pad focused `11/11`。

历史回归：CTest 注册 `3870` 项，`3845/3845` active 通过，
`25` Disabled；`Perf_Recognition` `707.47s`，全量墙钟 `816.59s`；外部矩阵为
`63 total / 54 pass / 9 blocked / 0 failed`。

双模式配置接线历史基线：CTest 注册 `3858` 项，`3833/3833` active 通过，
`25` 个 `StealthNested2` 用例明确 Disabled；当前主机最新全量墙钟 `897.21s`，其中
`Perf_Recognition` 正式默认参数运行 `765.00s`，全量 CTest 墙钟 `897.21s`，专用 CTest timeout 为 `1800s`。

## 文档

- [protocol-matrix.md](protocol-matrix.md)：协议与公共层的完成度矩阵（L1-L5 等级 + Gate A-D 证据）。
- [benchmark.md](benchmark.md)：Preview 独立性能基线、同一 Contract 的 codec/TCP/UDP 指标与 2026-09-05 recognition harness 记录；不替代跨实现网络对拍。
- [coverage.md](coverage.md)：覆盖率报告（lines 91.2%，2026-08-18）。
- `transmission.md`：传输接口、关闭、取消、超时和半关闭语义（尚未单独建立；当前结论见 [LIFECYCLE_AUDIT.md](LIFECYCLE_AUDIT.md)）。
- `interop/`：preview 与生产栈、外部实现的对拍记录——[psm-l4.md](interop/psm-l4.md)（L4 生产对拍，2026-08-20）；最新机器结果由 `scripts/interop/Run-Matrix.ps1` 写入 `build/interop-results/summary.json`，当前完整结果为 `scope=full`、`production_prerequisite_included=true`、`63 total / 54 pass / 9 blocked / 0 failed`，并包含 HTTP、SOCKS5、VLESS、Trojan、VMess、SS2022 六条真实单端口识别记录（`recognition_coverage_complete=true`），以及 HTTP CONNECT、SOCKS5/Trojan/VLESS 双向 TCP、VLESS/TUIC/Hysteria2 reference UDP→Preview authenticated-UDP-echo、Hysteria2/TUIC 双向 authenticated-echo 和 VMess 双向 TCP/UDP echo。

最新矩阵增量（2026-09-10）：新增 sing-vmess TCP-only 与 sing-shadowsocks SS2022
reference client → Preview `MixedTrial` 单端口认证/echo；当前完整结果为
`63 total / 54 pass / 9 blocked / 0 failed`，真实单端口识别记录为 HTTP、SOCKS5、
VLESS、Trojan、VMess、SS2022 共 `6/6`。
- golden vector：位于 [tests/preview/interop/GoldenVectorTest.cpp](../../tests/preview/interop/GoldenVectorTest.cpp)，当前 18/18；尚未拆成独立 `vectors/` 目录。
- 识别策略性能/稳定性：`Deterministic`（兼容 `Configured` 单候选入口与 `DeterministicRoute` 多候选实现）和 `MixedTrial`（有界试探）由 `tests/preview/perf/RecognitionPerf.cpp` 与 `tests/preview/stress/RecognitionStabilityTest.cpp` 覆盖；历史双模式设计见 [task-8-report.md](../superpowers/task-8-report.md)。
- [migration-decision.md](migration-decision.md)：按 L1-L5、生命周期和性能证据记录逐协议迁移建议。
- [interop/carrier-interface-gaps.md](interop/carrier-interface-gaps.md)：Reality/ShadowTLS/Restls 当前五条标准 carrier endpoint 缺口、已通过的 ShadowTLS server 方向、解锁条件和禁止的替代路径。
- [task-22-two-mode-wiring-report.md](../superpowers/task-22-two-mode-wiring-report.md)：双模式 Settings 接线、SNI 裁剪和 MixedTrial 回归证据。
- [task-23-hysteria2-interface-gap-report.md](../superpowers/task-23-hysteria2-interface-gap-report.md)：Hysteria2 Preview HTTP/3 单向控制/QPACK 流接口缺口证据。
- [task-28-hysteria2-native-session-report.md](../superpowers/task-28-hysteria2-native-session-report.md)：Hysteria2 Native HTTP/3 provider 接线和真实 `sing-quic` authenticated-echo 证据。

## 记录规则

1. “有实现”不等于“已完成”；每个协议分别记录 codec、session、回环、生产对拍、外部互操作、性能、stress 和 fuzz。
2. 回归测试必须记录测试目标、异常路径和关闭语义，不能只记录成功样例。
3. 测试命令统一使用仓库 `build/` 目录；不在本目录存放构建产物、运行日志或凭据。
4. 每次协议行为或公共传输契约发生变化时，同步更新矩阵中的证据和下一道门禁。

## 迁移前待建材料（Gate D 清单）

| 材料 | 位置 | 内容 |
|---|---|---|
| 生产对拍记录 | `interop/psm-l4.md`（2026-08-20） | preview client ↔ 生产 Prism server；socks5/ss2022 双向 PASS，vless/trojan/vmess 认证失败路径 PASS、echo 受阻于生产识别器（`probe/analyzer.cpp`） |
| 外部互操作/golden vector | `interop/` 或 `tests/preview/interop/` | mihomo/sing-box 或确定性字节向量 |
| 性能对标 | `benchmark.md` 追加 | Preview recognition baseline 与同一 Contract 的 codec/TCP/UDP 指标已完成；代理握手、外网吞吐和 RSS 对拍仍待建 |
| 生命周期审查 | `transmission.md` + 结论文档 | relay/udp_service/mux 的关闭、取消、超时语义结论 |
