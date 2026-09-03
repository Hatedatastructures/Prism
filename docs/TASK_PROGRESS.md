# TASK_PROGRESS

> 自动维护，勿手工编辑。每个单元结束更新。
> 无人值守：只记录事实与决策，不向用户汇报。测试数据见 docs/test-data/（主项目任务）
> 与 docs/ngx-test-data/（Next-Gen 任务）。
> 权威计划文档：docs/NEXTGEN_IMPLEMENTATION_PLAN.md（阶段 0-6 + Gate A-D）。
> 2026-08-18 起废弃旧 T0-T7 任务编号（内容已并入实施计划阶段化结构）。
> 2026-09-03：本文件记录 Gate D 分层推进事实；总 Gate D 仍受生产识别器前置阻塞。

## 实施计划总览

| 阶段 | 内容 | 状态 |
|---|---|---|
| 阶段 0 | 冻结真实基线（计划/矩阵/文档） | ✅ 已完成 |
| 阶段 1 | 公共层正确性收口（relay/memory_stream/XHTTP/MUX） | ✅ 已完成（Gate A） |
| 阶段 2 | 协议完成度矩阵 + 门禁定义 | 🔄 进行中（Preview L1-L3 与 native QUIC 已补；全协议 L5 和完整性能仍缺） |
| 阶段 3 | SOCKS5 纵向链路（TCP CONNECT + UDP ASSOCIATE） | ✅ 已完成（Gate B） |
| 阶段 4 | VLESS 扩展验证（TCP + UDP） | ✅ 已完成（Gate C） |
| 阶段 5 | preview/psm 适配与迁移决策 | ⏸ 用户决策：暂不迁移 |
| 阶段 6 | 质量门禁 | ✅ 6a-6f 全部完成（2026-08-20，全量回归 166/166 绿） |

## 质量门禁进度（阶段 6）

| 门禁 | 状态 | 证据 |
|---|---|---|
| 6a Fuzz smoke | ✅ | CodecFuzzTest 9/9、FuzzExtendedTest 6/6、DgramErrorCoverage 63/63 |
| 6b Stress | ✅ | Socks5/Vless/Networking/TimeoutRelay/UdpRelay 21/21 |
| 6c Benchmark 基线 | ✅ | docs/ngx-test-data/benchmark.md |
| 6d 覆盖率 | ✅ | lines 91.2%、functions 93.6%；build/coverage.html |
| 6e ASAN | ✅ | 2026-08-20 完成（见 NEXTGEN_IMPLEMENTATION_PLAN.md 6e 记录） |
| 6f 配置恢复 + 全量回归 | ✅ | 全量回归 166/166 绿（2026-08-20，见 protocol-matrix.md 质量门禁表） |

## 迁移前缺口（Gate D，见 protocol-matrix.md 与 AGENTS.md 活跃 TODO）

1. L4 生产对拍（preview ↔ psm 双向）——⚠️ 部分：socks5/ss2022 双向 PASS；vless/trojan/vmess echo 受阻于生产识别器（见 interop/psm-l4.md）
2. L5 外部互操作 或 golden vector——⚠️ SS2022 双向 runner PASS，7 个伪装 codec-vector PASS；其余全链路方向明确记录为 environment-unavailable；golden vector 18/18 ✅
3. preview vs psm 同场景性能对标——⚠️ 已有同一 Contract 的 codec 指标（PerformanceContract 1/1），完整网络 harness 尚未做
4. 生命周期/错误链审查结论文档——✅ 已做（docs/ngx-test-data/LIFECYCLE_AUDIT.md）
5. Trojan/VMess/SS2022 纵向链路（L3）——✅ 已做（经 core/runtime/adapter 缝）
6. mux 中间件接入 runtime、DNS 接入 dial——✅ 已做（mux 2/2、pad 2/2、DNS 3/3）
7. 伪装方案迁移决策——✅ 已生成 `docs/ngx-test-data/migration-decision.md`；当前建议仍为 experimental/keep-psm
8. SOCKS5 纵向场景回归——adapter v2 重构移除的认证/half-close/超时/统计/延迟应答场景待补测

## 当前焦点

- 任务：迁移前缺口补齐（Preview Evidence Gate → 外部互操作 → 迁移决策）
- 门禁：Preview Evidence Gate（总 Gate D 仍等待生产前置）
- 数据文件：docs/ngx-test-data/（matrix/benchmark/coverage 已更新）

## 2026-09-03 增量事实（Preview）

- Linux CI P0 已完成：`Base64.hpp` 的 `B0/B1/B2` 改为 `Byte0/Byte1/Byte2`，commit `bdb7801d`，hosted run #23 已通过。
- XHTTP Stream-one 已使用标准小写 `:method`、`:path`、`content-type: text/event-stream`，并有真实回归断言。
- SS2022 TCP 服务端已按 `ServerConfig.UsePsk` 使用 raw 16 字节 PSK；password 派生路径保持兼容，正确/错误 raw PSK 均有测试。
- VLESS 地址解析对未知 `ATYP` 返回 `BadMessage`；已知类型的截断输入仍返回 `NeedMore`。
- UDP endpoint 解析拒绝空 host、非法/溢出端口和未括号 IPv6；合法 IPv4、`[IPv6]:port` 与域名语法通过，域名解析保持异步。
- Preview HTTP/2/HPACK 已拒绝截断整数 continuation、SETTINGS ACK 非空载荷、零窗口增量、非法 RST_STREAM、缺少 END_HEADERS 及 idle/closed stream DATA。
- Preview Recognition 已增加 ClientHello record/SNI 解析、大小写规范化、最长单标签通配和可选 scheme executor；native ngtcp2 QUIC client/server UDP 回环 1/1 通过，Hysteria2/TUIC provider 工厂和 datagram provider 回归通过。
- 当前默认 Release 构建树（benchmark/stress 开启、interop/perf Contract 关闭）注册 `3512` 个 CTest，全部通过；本轮 H2Codec 27/27、Recognition 24/24、ProtocolContract 12/12、QUIC provider/loopback 58/58。
- 外部矩阵已实际生成：52 条记录，8 条 pass（SS2022 双向 runner + 7 个 codec-vector），44 条明确 blocked，0 条 protocol-failure/implementation-mismatch；结果在 `build/interop-results/summary.json`。

### 当前仍未完成

- Hysteria2/TUIC 仍缺少带真实 QUIC 会话的完整协议认证/外部流量闭环；provider-backed datagram 工厂已可用。
- 全协议（代理协议 + 伪装方案）双向外部互操作和完整网络同 harness 性能对拍；当前缺失项均以 environment-unavailable 明确记录。
- VLESS/Trojan/VMess ↔ 生产 Prism 的真实单端口 echo；原因是生产 `analyzer.cpp` 尚未获授权修改，状态保持 `blocked-production-prerequisite`。
- Preview Evidence Gate 尚未因外部 L5/完整性能缺口关闭；逐协议迁移决策矩阵已生成，但没有协议达到 migrate 条件。

## 已完成单元（2026-08-18 确认）

- 阶段 0-4 全部验收记录见 docs/NEXTGEN_IMPLEMENTATION_PLAN.md（Gate A/B/C 证据）
- h2mux sing-mux StreamRequest：SingmuxRequest 7/7 + SingmuxE2E 通过（生产侧，2026-08-18 复核）
- SOCKS5 UDP ASSOCIATE：Socks5UdpE2ETest 4/4（echo/非法帧/空闲超时/TCP 断开）
- VLESS UDP：VlessUdpE2ETest 3/3（echo/空闲超时/EOF）
- 全链路回归：ListenerE2E 4/4（adapter v2 重构后规模）、VlessE2E 9/9、SessionOrchestration 5/5、Recognition 13/13
- 2026-08-22：七路并行审查修复（P0 正确性 + 假断言 + 结构性 + 样板收敛），详见 git 工作区与 protocol-matrix.md 真 bug 修复条目
- 2026-08-22：全量回归 3266/3267（唯一失败为既有 flaky MuxUploadSim，见错误日志）；
  本轮新抓并修复的潜伏假断言：Trojan/VMess 半关闭 EOF 码、SS2022Udp BadPskDrop 契约、
  Pad 回环长度语义、token_bucket 扣减丢 `- n`（P3 引入，RateLimitTest 当场抓获）

## 决策记录

- 2026-08-18：用户明确“迁移不迁移用户说了算，先不迁移”；preview 保持参考实现 + 迁移候选定位，优先补齐 Gate D 证据。
- 2026-08-18：旧 T0-T7 任务编号废弃，统一以 NEXTGEN_IMPLEMENTATION_PLAN.md 阶段化结构为准。

## 错误日志

- 无（各轮测试失败均已当场修复并回归，见实施计划阶段记录）
- 2026-08-22：`MuxUploadSim`（SmuxLargeUpload 为主）存在既有 flaky SEGFAULT——
  ioc 析构销毁挂起协程的 Windows 竞态（文件头 @note 自认）。对照实验：
  HEAD 版 60 轮崩溃 12 次、本次工作区版 60 轮崩溃 7 次，与本次改动无关且未恶化。
  全量回归 3266/3267 的唯一失败即此。待单独修测试驱动方式（run_and_drain 不彻底）。

## 待提交清单（全部任务完成后生成，供用户处理）

- 无（用户明确未授权 git commit）
