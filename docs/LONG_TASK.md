# Prism 主项目长任务执行提示词（LONG_TASK.md v5）

> 本文件是一份**可直接执行的完整长任务提示词**：把大工程拆成原子单元，
> 执行者按任务栈顺序连续推进，每个单元跑完整质量门禁，失败则纠错重来，
> 直到任务栈清空。**不需要循环调度器**——一次启动，按序执行到底。
>
> **v5 修订（无人值守模式）**：
> - **无人值守**：所有任务无需向用户汇报，执行者自主推进、自主分析、自主决策；
>   用户只查看测试数据文件
> - **禁止自动 git commit / push**；全部任务完成后生成「待提交清单」供用户处理
> - 测试数据写入 `docs/test-data/<组件>.md`，数据未达标不得前进
> - v4 及之前的"向用户汇报/等待指示"要求全部移除
>
> 配套文件：
> - 进度记录：`docs/TASK_PROGRESS.md`（执行中自动维护，只记录事实与决策）
> - 测试数据：`docs/test-data/`（每组件一个数据文件，用户查看的唯一依据）
> - 架构约束：`docs/ARCHITECTURE.md`（依赖 DAG / 四层所有权 / 传参规范）
> - 质量基线：`AGENTS.md`（构建 / 测试 / 资源清理）
> - 蓝图参考：`docs/management-design.md`（T8 详设）
>
> 版本记录：v2 新增 T2-T5/T7/T9；v3 全自动模式；v4 去循环调度、禁自动提交；
> v5 无人值守（无汇报、数据文件驱动）。
> 任务编号映射（按执行顺序）：`T3 正确性→T1`、`T8 技术债→T2`、`T4 协议面→T3`、
> `T7 性能→T4`、`T6 可观测→T5`、`T2 中间件→T6`、`T5 质量工程→T7`、`T1 管理面→T8`、`T9 运维→T9`。

---

## 0. 使用方法

1. 完整阅读本文件，确认任务栈（第 2 节）与门禁矩阵（第 3 节）。
2. 检查 `docs/TASK_PROGRESS.md`：不存在则按第 7 节模板初始化；存在则从「当前焦点」继续。
3. **连续执行**：从当前焦点开始，按第 1 节协议逐个推进单元，直到任务栈全部完成，
   汇总写入 `docs/test-data/INDEX.md` 并结束。中途不中断、不等待人工介入。
4. **无人值守**：执行过程中不向用户汇报、不请求确认；所有中间结果写入
   `docs/test-data/` 与 `docs/TASK_PROGRESS.md`。无法自主决策时才停止并记录问题。
5. **禁止自动提交**：任何情况下不执行 git commit/push；全部任务完成后在
   `docs/TASK_PROGRESS.md` 末尾生成「待提交清单」（文件列表+摘要），供用户自行处理。

---

## 1. 执行协议（每个单元的标准流程）

```
单元开始
├─ ① 读 docs/TASK_PROGRESS.md，确认当前任务/子任务/单元；全部 done →
│    汇总写入 docs/test-data/INDEX.md 并结束
├─ ② 选取「下一个可验证单元」（一个原子改动，≤ 1 个子任务粒度）
├─ ③ 前置调研（先读代码再动手）：
│     · 读入口文件与相邻模块，确认调用链与所有权
│     · 列出改动影响面（头文件依赖、聚合头、调用方）
│     · 对照 ARCHITECTURE.md 确认模块层级归属
├─ ④ 实施改动（严格遵守第 5 节架构红线 + AGENTS.md 编码规则）
├─ ⑤ 写/改测试（同一单元内完成，禁止“代码先跑测试后补”）
├─ ⑥ 跑该单元的门禁（第 3 节 G1-G16 中适用的项）→ 测试数据写入
│    docs/test-data/<组件>.md
├─ ⑦ 自主分析：对比四象限数据（分支覆盖/覆盖率/性能/压测）——
│     全部达标 → 更新 TASK_PROGRESS.md → 继续下一单元
│     有红或数据不达标 → 执行第 4 节纠错协议，修复后重跑 ⑥（≤3 次，
│     再失败简化或 SKIP，原因记入进度文件与数据文件）
├─ ⑧ 资源清理：终止本轮启动的进程（G11）
└─ 单元结束
```

**铁律**：
- 一次只动一个单元；单元之间不夹带无关改动（防行为漂移）。
- 每个单元必须有测试伴随；纯重构单元以「现有全量回归」为门禁。
- 门禁红 = 该单元工作作废重做（或小修重跑），绝不允许带红前进。
- 跨模块大改动先写「影响面清单」再动手。
- **自动决策**：评估性内容（T3-3 等标注「评估」的单元）自主完成调研→决策→实施，
  决策理由写入 TASK_PROGRESS.md 决策记录区；无法决策时选保守方案并记录。
- **无人值守**：不向用户汇报、不请求确认；数据文件未 PASS 不得前进。
- **禁止自动提交**：任何情况下不执行 git commit / push。

---

## 2. 任务栈（按序执行，前序完成才进入后序）

执行顺序总览：

```
T1 正确性三件套（P0） → T2 技术债与安全清理（P0.5，穿插） → T3 协议面补齐（P1）
→ T4 性能纵深（P1） → T5 可观测性基建（P1，T8 前置） → T6 中间件管线移植（P1）
→ T7 质量工程升级（P2） → T8 管理面全景（P2，依赖 T5） → T9 运维组件（P3）
```

---

### T1 正确性三件套（P0 — 先补短板）

#### T1-1 隧道 half-close 补完【最高优先级，协议正确性】

- **目标**：`tunnel_relay` 支持半关闭语义——一端 EOF 后仍转发另一方向剩余数据，两端 EOF 才关闭。
- **现状**：`src/prism/net/connection/tunnel/tunnel_relay.cpp:47-50`，`relay_loop` 读到 EOF 立即 `co_return`，`operator||` 会取消另一方向 → 「小请求 + 大响应」场景丢数据（management-design.md 7.1 明确标注最高优先级）。
- **实现要点**：
  1. 双阶段状态机：`{双向并发 → 单向-仅A已EOF → 单向-仅B已EOF → 关闭}`
  2. 不再用 `operator||` 硬取消；两个 loop 共享 EOF 标志，EOF 方向只停读，另一方向继续读到自身 EOF
  3. idle_timer 语义在单向阶段仍然生效；pad 包装层行为不变
  4. 流量统计/lease 累计时机不变（结束后一次性上报）
- **影响面**：`tunnel_relay.cpp/.hpp`；检查所有调用点（session.cpp 兜底分支、forward_pipeline、各协议 handler 内部转发循环是否同样缺陷——一并修复或记录）。
- **验收**：
  - 新单测 `TunnelHalfClose`：内存流模拟 A 发数据后 shutdown → B 继续回发大响应（> buffer 多块）→ A 完整收到；对称场景；双向同时 EOF；中途错误；单向阶段空闲超时。
  - 现有隧道测试全量回归。
  - Go interop 补「请求端先关 → 响应完整送达」用例（tests/go）。
- **关联 skills**：tunnel-audit、coroutine-audit、write-test。

#### T1-2 worker 优雅停机

- **目标**：worker 停机不再直接 `ioc_.stop()` 强杀，改为：拒绝新会话 → cancel 活跃会话 → 短 drain 窗口 → 超时兜底 → join。
- **现状**：`src/prism/runtime/worker/worker.cpp:29-32` `stop()` 直接 `resources_->stop()`（issues.md B-16 未修）；活跃会话数据半写、detached 协程无收尾。
- **实现要点**：
  1. 停机协议：`stop()` 置 stopping 标志（balancer 停止分发）→ 遍历活跃 session 调 `close()` → 等待 `coroutine/registry` 活跃计数归零（含 5s 超时兜底）→ 剩余协程强制 cancel → `ioc.run()` 自然返回
  2. 复用 `foundation/coroutine/registry`（已有 active/spawned/cancelled 统计）
  3. 与 main.cpp 现有信号流程（listener/QUIC stop → worker stop → join）对齐，不破坏退出码
- **验收**：
  - 新测试 `GracefulShutdownTest`：并发 100 会话且有传输中数据 → 触发 stop → 断言：会话数据完整、registry 活跃计数归零、进程正常退出。
  - 现有 signal/启动测试回归。
- **关联 skills**：co-lifecycle-audit、concurrency-audit、error-chain-audit。

#### T1-3 伪装方案后端连接路由化

- **目标**：restls/shadowtls 握手后端连接从「裸 `tcp::resolver + async_connect`」改为走 `outbound::dial`，支持反向代理/路由规则。
- **现状**：`src/prism/handshake/restls/handshake.cpp:55`、`src/prism/handshake/shadowtls/handshake.cpp:465` 均有 `TODO(P5)`：裸解析直连，不经过路由。
- **实现要点**：
  1. 调研 reality/native 等方案的后端连接方式，统一拨号入口
  2. 改为注入 dialer/outbound 上下文（注意 handshake 阶段在 session 内，`res_->worker->outbound` 可用）
  3. 保持超时/取消语义不变
- **验收**：
  - 反向代理（reverse_map）配置下 restls/shadowtls 握手 E2E 通过。
  - 路由规则命中/未命中行为与 forward 路径一致。
  - 现有 handshake 测试全量回归。
- **关联 skills**：probe-audit、replay-audit、dpi-audit、debug-cpp。

**T1 DoD**：三件套各自测试 + 全量回归绿；issues.md 中 B-16 等对应条目标记已修复。

---

### T2 技术债与安全清理（P0.5 — 穿插执行，安全问题最优先）

> 本任务与 T1 并行穿插：**T2-1 在 T1 完成后立即执行**，T2-2/T2-3 可在任意任务间隙推进。
> 目的：清掉旧坑，降低后续任务（T4/T6 性能与架构改动）的噪音与风险。

#### T2-1 HIGH 级安全问题立即修（先做，独立单元逐个闭环）

- **S-2 明文凭据**：`src/configuration.json` 硬编码 `I:\code\Prism\key.pem` 路径、明文密码 `"prism"`、Base64 私钥、明文 PSK。
  - 修复：改为 `configuration.example.json` + 默认配置去凭据 + `.gitignore` 排除本地配置；启动时缺失配置给出明确中文错误提示。
- **B-11 栈溢出**：`include/prism/protocol/shadowsocks/util/tracker.hpp:177-202` `derive_aead` PSK 长度未校验，>56 字节栈溢出。
  - 修复：入口校验 PSK 长度（≤56），非法返回错误码；补边界测试。
- **B-10 越读**：`src/prism/crypto/blake3.cpp:27-33` `keyed_hasher` 未校验密钥长度。
  - 修复：校验 + 错误传播；补测试。
- **B-23 溢出**：`src/prism/net/dns/upstream.cpp:603-614` Content-Length 无溢出保护（可能 OOM）。
  - 修复：上限校验（如 64KB）+ 溢出算术保护；补测试。
- **B-24 BIO 泄漏/崩溃**：`src/prism/handshake/reality/util/response.cpp:614` `BIO_new` 未检查；`B-14/B-15` X509 系列返回值未检查、签名失败仍继续。
  - 修复：逐调用点检查返回值，失败走错误码；补测试。
- **S-5/S-6**：`RAND_bytes` 返回值检查；`loader/load.hpp:36-69` 配置加载后验证（空密码/零超时/无效端口）。
- **B-1**：`src/prism/net/connection/dialer/dial.cpp:55,97,126` `value_or(0)` 静默接受无效端口 → 改为错误码。

> 注意：以上行号为 issues.md 记录值，**实施前先按新架构确认实际位置**（旧路径 `stealth/instance/connect/resolve` 已在 10 模块重构中迁移）。

#### T2-2 issues.md 全量重审（106 项）

- **目标**：产出 `logs/issues.md` v2——按新 10 模块结构重映射，逐项标记 `真 bug / 已修复(重构后) / 过时`，保留可复现项作为后续任务输入。
- **方法**：每个条目：旧路径 → 新路径定位 → 读源码验证 → 分类 → 更新清单。
- **验收**：重审表完整（106 项全覆盖），HIGH 级真 bug 修复闭环；medium 项按优先级并入后续任务 backlog。
- **关联 skills**：debug-cpp、security-audit。

#### T2-3 工程残留清理

- `cmake-build-release/` 违规构建目录（AGENTS.md 禁止）→ 确认无用后删除。
- 5 个 `worktree-agent-*` 残留分支 → 确认后删除。
- 聚合头补齐（issues D-2）：`handshake.hpp`/`multiplex.hpp`/`protocol.hpp`/`recognition.hpp` 遗漏子头。
- 文档同步：`docs/protocol-integration-plan.md` 过期（QUIC 标"进行中"实际已完成）；`docs/index.md` 引用不存在的 `tutorial/` 目录 → 修正或移除断链。
- **验收**：清理清单核对通过；聚合头编译验证（每个聚合头单独 include 编译）。

---

### T3 协议面补齐（P1 — 兼容面与互操作）

#### T3-1 XHTTP h3 / packet-up / stream-up

- **目标**：XHTTP 从仅 stream-one(h2) 扩展为完整模式：stream-up、packet-up、h3。
- **现状**：`src/prism/handshake/xhttp/scheme.cpp`(126 行) + `session.cpp`(469 行) 仅实现 stream-one（h2 POST）；protocol-integration-plan 明示「QUIC 就绪后补 h3」，QUIC 已就绪（quic_gateway 已接入 main.cpp、GoCompat_hysteria2/tuic 已注册）。
- **实现要点**：
  1. **调研先行**：对照 mihomo xhttp 实现梳理三个模式的会话模型（stream-up: `POST/GET /path/{sessionID}`；packet-up: `POST /path/{sessionID}/{seq}`；h3: QUIC datagram 直通）。产出设计记录再动手。
  2. 会话管理：sessionID（32 hex）→ 上行队列 → 下行流汇聚；孤儿 30s 回收（复用到现有 session.cpp 结构）。
  3. h3 服务端：复用 `protocol/hysteria2/` 已有的 h3_server/qpack 基建（QPACK 605 行已实现），接入 `quic_gateway` 或独立入口。
  4. 模式选择配置：`auto / stream-one / stream-up / packet-up`。
- **影响面**：`handshake/xhttp/`、`net/transport/quic/`、`protocol/hysteria2/h3_server`（复用评估）、配置 schema。
- **验收**：
  - 三模式 E2E（h2 客户端 + h3 客户端）。
  - Go 互操作：mihomo xhttp 客户端（tests/go 新增）对拍。
  - 孤儿会话回收、超时路径测试。
- **关联 skills**：dpi-audit、probe-audit、tunnel-audit、write-test、map-config。

#### T3-2 传统 Shadowsocks（AEAD 分块）支持

- **目标**：新增传统 SS AEAD 模式（aes-128/256-gcm、chacha20-ietf-poly1305），与 SS2022 共存。
- **现状**：`src/prism/protocol/shadowsocks/codec/` 仅 `framing.cpp`（2022 系）；无传统 AEAD 分块（2B 长度前缀 + 16B tag + salt 首包 + HKDF 子密钥）实现；tests/common 也仅有 shadowsocks2022。
- **实现要点**：
  1. 传统 SS AEAD chunk 编解码（纯函数）：`[2B len][16B tag][payload][16B tag]` + 首包 salt + HKDF-SHA1 子密钥派生。
  2. 重放防护：salt 复用检测（现有 `salts.hpp`/`replay.hpp` 扩展或新建）。
  3. probe 识别：传统 SS 与 SS2022 首包区分策略（salt 长度/格式差异）→ 确认后接入 recognition（对照 protocol-integration-plan 中「SS2022 与 VMess 无法区分」的 fallback 方案）。
  4. 配置：`method` 字段（`aes-256-gcm` / `chacha20-ietf-poly1305` 等）+ 密码派生（EVP_BytesToKey / openssl kdf 对齐 mihomo）。
- **影响面**：`protocol/shadowsocks/`、`handshake/recognition/probe/`、配置 schema、tests/common（补传统 SS codec）。
- **验收**：
  - Codec/Session/错误矩阵测试（半包、超长、坏 tag）。
  - Go 互操作：shadowsocks-rust / mihomo 传统 SS 客户端对拍（tests/go 新增）。
  - 与 SS2022 并存：同端口 fallback 顺序测试。
- **关联 skills**：crypto-audit、replay-audit、probe-audit、write-test、map-config。

#### T3-3 VLESS XTLS / VISION flow（评估 + 实施）

- **目标**：评估并为 VLESS 增加 `flow` 支持（xtls-rprx-vision），实现服务端直通模式。
- **现状**：生产 vless（`protocol/vless/`）与 tests/common 均无 flow 字段；BoringSSL 为服务端库（非客户端 uTLS），需评估 XTLS 直通在服务端侧的可行性。
- **实现要点（评估单元先行，自动决策）**：
  1. 调研 xray-core VISION 服务端流程：ClientHello 捕获 → 记录指纹 → TLS 握手完成后进入直通模式（不解析内层流量）→ 仅识别 FIN。
  2. 评估 BoringSSL 下实现路径（TLS 回调挂钩 vs 自定义 BIO）；产出可行性结论 + 设计（写入决策记录）。
  3. 若可行：`flow` 配置字段 + vless 握手 flow 字段编解码 + 直通隧道（性能：减少一层加解密）。若不可行或收益/成本失衡：记录决策，缩减为 flow 字段透传 + 明确不支持说明，并更新文档。
- **验收**：E2E + 性能对比（VISION vs 非 flow，bench 报告）；mihomo/xray VLESS+vision 客户端互操作。
- **关联 skills**：dpi-audit、crypto-audit、tunnel-audit、bench-perf。

**T3 DoD**：三协议各自互操作 + 全量回归绿；`docs/protocol-integration-plan.md` 状态表更新（XHTTP h3 完成、传统 SS 完成）。

---

### T4 性能纵深（P1 — 有明确量化验收）

> 基准基线：`docs/performance-report.md`（2026-05-06）；新基准 e755ce0 已超 Go 1.1-6.5x。
> 每个单元：优化前跑基准记录基线 → 优化 → 复测 → 差距必须收窄且不劣化其它项。

#### T4-1 全局内存池分片（sharded_pool）

- **目标**：Global Pool 多线程竞争消除。现状：4 线程 3530ns/分配（vs ThreadLocal 36ns，35× 差距，performance-report 七/十二）。
- **实现要点**：
  1. `foundation/memory/pool.hpp` 新增 `sharded_pool`：N 个子池（按线程 id 哈希取模），原子计数跨片归还归位。
  2. `memory::system::enable_pooling()` 全局池切换为 sharded 实现（保持 API 兼容）。
  3. 不引入锁竞争：单线程路径无锁取片。
- **验收**：`MemoryBench`/`PoolContentionStress` 4/8/16 线程对比，目标 <150ns@4T；现有内存测试回归。
- **关联 skills**：audit-memory、pool-audit、bench-perf。

#### T4-2 连接建立 P99 优化

- **目标**：连接 P99 336us（P50 的 3.5 倍，performance-report 八）→ <250us。
- **现状**：瓶颈=健康检查 + DNS 偶发阻塞（performance-report 十二）。
- **实现要点**：
  1. 拨号快速路径：健康检查异步化/降频（不阻塞 connect 返回）。
  2. resolver 结果缓存热路径（复用 dns/cache）。
  3. deadline 分层（总超时 + 阶段超时），避免偶发慢查询拖尾。
- **验收**：连接延迟 bench P99 <250us；多 worker 并发下 P99 稳定（对照 `tests/perf/ConcurrentBench`）。
- **关联 skills**：bench-perf、pool-audit、debug-cpp。

#### T4-3 小包合并读写

- **目标**：小包 TCP 回环 20us → 12-15us（performance-report 十二「合并读写」方案）。
- **实现要点**：
  1. 写侧 scatter-gather：`async_write_some` 多 buffer（iovec 合并）替代逐包写。
  2. 读侧聚合：小包攒批后一次写出（在 tunnel relay 层做批处理，注意延迟权衡）。
  3. 对照 `tests/perf/TcpBlockMatrix` 建矩阵验收。
- **验收**：64B 回环 bench 达标；大包吞吐不劣化（G10 ±3%）。
- **关联 skills**：bench-perf、traffic-audit、tunnel-audit。

#### T4-4 SNI 路由表重建与临时字符串消除

- **目标**：issues P-1（`recognition.cpp:51` 每次 TLS 连接重建 SNI 路由表）、P-2（`routes.cpp:71` 每次查找构造临时 `memory::string`）。
- **实现要点**：
  1. 路由表改为 L2 级缓存（worker 生命周期内构建一次），COW 指针交换支持热更新（为 T8-4 规则表铺路）。
  2. 查找用 `string_view` 键（域名字段按 view 比较，避免临时分配）。
- **验收**：识别吞吐 bench 提升；现有 recognition 测试回归；benchmark 无劣化项。
- **关联 skills**：bench-perf、concurrency-audit、probe-audit。

#### T4-5 send_loop 堆分配消除

- **目标**：issues P-3（smux/craft.cpp:552）、P-4（h2mux/craft.cpp:637，每帧两次堆分配）、P-5（shadowsocks/conn.cpp:583）。
- **实现要点**：
  1. 合并缓冲区复用：send_loop 持有持久 buffer（PMR/复用池），帧头 + payload 一次组装。
  2. 消除每帧 `new`：改用 `memory::vector`（local_pool）+ 预分配。
  3. 对照 smux/yamux 已有的零分配路径（yamux 部分已优）统一模式。
- **验收**：`MuxBench`/`CodecPerf` 对比；全量回归。
- **关联 skills**：bench-perf、audit-memory、mux-audit。

**T4 DoD**：全部 5 项量化验收达标；`docs/performance-report.md` 增加 2026 新基准节。

---

### T5 可观测性基建（P1 — T8 管理 API 的数据前置）

> 依据：management-design 第一章「性能分层原则」。热路径代价纪律：**≤1 原子或 1 条件分支**。
> 本任务产出 T8 的 `/stats/latency`、`/stats/traffic`、`/traces` 数据源，**必须先于 T8**。

#### T5-1 HDR 延迟直方图

- **目标**：`foundation/rate/hdr.hpp`（或 `diagnose/hdr`）：分阶段记录 `accept → DNS → 拨号 → TLS 握手 → 首字节 → 首包响应`。
- **实现要点**：
  1. 每 worker 一张 HDR 直方图（~200 bucket 数组），更新 = 时间戳差 + 1 次 CAS。
  2. 冷路径聚合导出 P50/P95/P99；慢会话检测 = P99 超阈值触发采样标记。
  3. 热路径插入点：listener 接受、diversion 各阶段、handler 首包。
- **验收**：单测（bucket 精度/聚合正确性）；bench 验证热路径代价（对照基线上涨 ≤ 原子操作量级）；`/stats/latency` 数据源可用（T8 消费）。
- **关联 skills**：concurrency-audit、bench-perf、error-chain-audit。

#### T5-2 EWMA 实时速率

- **目标**：指数加权移动平均速率（`rate = α×sample + (1-α)×rate`），原子更新，替代窗口计数。
- **实现要点**：
  1. `foundation/rate/ewma.hpp`：每连接/每用户一份，原子读写。
  2. 接入 `user/stats/traffic` 与 tunnel_relay 统计点。
  3. 为 T8 `/traffic` 实时速率与 T8-4 限速器提供输入。
- **验收**：单测（收敛性/时序）；热路径代价审计；与现有 stats 一致性测试。
- **关联 skills**：concurrency-audit、stats 相关测试 review。

#### T5-3 采样式追踪（sampled tracing）

- **目标**：1/N 采样（原子计数器），命中会话的事件序列写入 SPSC ring buffer，满即丢，冷路径导出回放。
- **实现要点**：
  1. `diagnose/trace/` 扩展：采样判定（1 原子）+ ring buffer（SPSC，无锁）。
  2. 采样会话记录各阶段时间戳 + 关键参数（复用 T5-1 的阶段点）。
  3. 冷路径 API：ring 回放导出（供 T8 `/traces`）。
- **验收**：并发写读无丢失测试（超过容量丢旧不阻塞）；热路径代价审计；导出格式单测。
- **关联 skills**：concurrency-audit、error-chain-audit。

**T5 DoD**：三组件独立测试 + 热路径代价基准报告；T8 依赖接口就绪。

---

### T6 中间件管线移植生产（P1 — 原型回灌）

> 依据：`tests/common/core/middleware/*` 注释明确「对应生产库 forward_pipeline / outbound::dial / tunnel_relay 的中间件化」。
> 本任务把已验证的 psmtest 原型映射为生产 `psm::connect` 实现。

#### T6-0 前置调研（先做，不写代码）

- 对齐生产 `transmission`（`include/prism/net/transport/transmission.hpp`）与 psmtest `transmission` 的接口差异（签名/错误模型/所有权）
- 梳理 `forward_pipeline.cpp:18-79` 全部硬编码决策点：mux 判断 → dial → pad（self_framed 特判 65-70 行）→ relay
- 梳理 `session.cpp:297-313` 兜底分支与 forward_pipeline 的重复组装
- 产出：`docs/TASK_PROGRESS.md` 中的「影响面清单」（新模块归属、依赖方向、调用方列表）

#### T6-1 管线基础设施落地

- 新建 `include/prism/net/connection/tunnel/pipeline.hpp`（psm::connect 命名空间）：
  `middleware` 基类（name/handle）+ `pipeline`（add/run，任一失败终止）+ `context`（inbound/outbound/target/detected/traffic/pad_cfg/buffer）
- 新建 `builtin` 中间件：`dial_middleware`（默认函数=outbound::dial）、`pad_middleware`（按 detected 决定是否包装，替代 self_framed 特判）、`relay_middleware`（封装 tunnel_relay 双向转发 + 统计 + lease）
- 类型约束对齐生产：PMR 容器、fault::code、shared_transmission
- **验收**：新模块编译 + 纯管线单测（内存流，参照 MiddlewarePipelineTest 模式，但连生产 outbound::dial 的注入点留接口）

#### T6-2 forward_pipeline 重构

- `forward_pipeline` 改为管线链：`pipeline.add<dial>().add<pad>().add<relay>().run(inbound, ctx)`
- mux 分支决策：评估「mux 中间件（拦截消费）」vs「保持管线外分支」；选择耦合更低者并记录理由
- **验收**：8 协议 E2E + Go 互操作（GoCompat/GoCmp 系列）全量回归；行为与重构前一致（对比 forward.log 关键路径日志）

#### T6-3 session 兜底分支合并

- `session.cpp:297-313` 的 tunnel 组装删除，统一走管线；diversion 只保留「识别 → 工厂 → 管线」
- **验收**：E2E 回归；diversion 单测（handshake 失败/未知协议/超时路径）不回归

#### T6-4 authenticator 接入生产

- 生产认证统一：socks5（用户名/密码）、trojan/vless（凭据）、hysteria2（Hysteria-Auth）等改为 `authenticator` 接口，生产实现接 `user/directory`
- 认证结果携带 identity，喂给流量统计（对齐 tests/common `TrafficIdentityTest` 语义）
- **验收**：各协议认证成功/失败/错误凭据测试矩阵；按用户流量统计测试（TrafficIdentity 生产版）
- **关联 skills**：replay-audit、error-chain-audit、map-config（如新增配置）

#### T6-5 中间件测试补全

- mux/pad 中间件单测（当前零覆盖）；pipeline 组合测试（dial→pad→relay 全链）
- **验收**：tests/infrastructure/MiddlewarePipelineTest 扩展 + 生产管线测试

**T6 DoD**：管线替代硬编码链；self_framed 特判消失；认证统一；全量回归绿；ARCHITECTURE.md 依赖审计 grep 零新增命中。

---

### T7 质量工程升级（P2 — 让「生产级」有机器保证）

> 现状：`.github/workflows/build.yml` 仅「构建 + ctest」，无 Go 互操作 / ASAN / fuzz / benchmark 门禁。
> 本任务把 LONG_TASK 的门禁矩阵 CI 化，让后续任务与回归有自动兜底。

#### T7-1 CI 增加 Go 互操作 Job

- Windows job 增 Go 1.22+（actions/setup-go）→ 构建 `GoTest*`/`GoCmp*` targets → 跑 `GoTest*`/`GoCmp*` ctest（需 MINGW 环境 + Prism 显式配置路径，参照 `tests/go/run_go_test.ps1`）。
- **验收**：CI 中 Go 测试全绿（hysteria2/tuic/vmess/singvmess + 7 个 cmp）。

#### T7-2 CI 增加 ASAN Job

- `-DPRISM_ENABLE_ASAN=ON`（MinGW Makefiles + Debug）→ 构建 → 跑核心测试子集（内存相关 target：MemoryLifecycleTest、各类 ConnSession/Stress）。
- **验收**：ASAN 0 泄漏 0 错误；记录已知 flaky（HandshakeTimeout）白名单策略。

#### T7-3 fuzz 测试（libFuzzer targets）

- 背景：vmess 指令头、sing-mux 帧、tuic 命令帧、anytls 帧、reality 记录、SS chunk 全是手写解析器，最易藏崩溃/越界（management-design 7.5）。
- 实现：
  1. CMake 选项 `PRISM_ENABLE_FUZZ=ON`（`-fsanitize=fuzzer,address`），每 codec 一个 target 包 `parse` 纯函数（零 I/O 架构是理想 fuzz 目标）。
  2. 首批 targets：vmess header/chunk、vless/trojan framing、SS2022 chunk、smux/yamux/h2mux frame、tuic 命令帧、anytls frame、reality record、http parser、dns format。
  3. 种子语料：现有测试向量 + Go 互操作抓包。
- **验收**：每个 target 短跑（60s）无崩溃；发现的问题修复后回归；CI 中 fuzz smoke job（每 PR 60s × N）。
- **关联 skills**：write-test、debug-cpp、security-audit。

#### T7-4 benchmark 回归门禁

- CI 增 benchmark job：跑关键 bench（MuxBench/CodecPerf/ProtocolPerf/Tunnel 相关）→ 解析输出 → 与基线对比（阈值 ±3%）→ 劣化即失败。
- 基线：首次运行生成 `docs/bench-baseline.json` 后固化。
- **验收**：CI 门禁生效；基准报告同步更新。

**T7 DoD**：CI 全绿（含新增 jobs）；fuzz targets ≥ 10 个零崩溃；benchmark 门禁有基线文件。

---

### T8 管理面全景（P2 — 最长任务，6 阶段，依赖 T5）

> 详设见 `docs/management-design.md`。每阶段独立 DoD、可并行 ①-④，⑤ 聚合，⑥ 最外。
> 数据源依赖：T5（HDR/EWMA/采样追踪）必须先于本任务完成。
> **范围自动决策**（management-design 第八章开放问题，决策写入记录）：管理 API 用独立端口（默认 9090，本机绑定）；
> 持久化用 SQLite 单机模式（若引入依赖评估成本，成本过高则先用 JSON 文件持久化）；配额重置时区用 UTC；
> SSE 鉴权复用 Bearer token；自适应治理阈值从 balancer 负载评分三分位起步。

#### T8-1 账户扩展

- `user/entry` 增加：过期时间、配额（日/总）、禁用标志；配置层 glaze 映射 + 序列化
- `user/directory` 增加 `for_each` 遍历接口（`record.hpp:45 TODO(#account)` 前置）
- **验收**：AccountDirectory 测试扩展（过期/配额/禁用 CRUD）；无热路径代价
- **关联 skills**：map-config、leak-audit、write-test。

#### T8-2 按用户统计补完

- `stats/account/collect()`（`include/prism/user/stats/record.hpp:44-47` 当前恒返回空）落地：遍历 directory 输出账户快照
- 流量按 identity 聚合（消费 T6-4 的 authenticator identity）
- **验收**：多用户并发流量后 collect 正确；TrafficIdentity 生产测试

#### T8-3 会话注册表

- `resource/session_registry`：COW map（复用 directory 模式），session 创建/销毁钩子写入值拷贝快照，**严禁存 L3 引用**
- 快照字段：session_id/协议/用户/目标/上下行/开始时间/阶段/实时速率（EWMA，T5-2）
- **验收**：注册表并发读写测试；热路径代价 ≤ 1 原子 + 1 条件分支（对照 management-design 热路径纪律）

#### T8-4 规则表 + 限速 + 动态封禁

- `foundation/rule/`：COW 规则表（静态条目 + 带过期动态条目，惰性清理）
- `foundation/rate/token_bucket`：两级令牌桶（per-user + per-connection）
- 分层防御：L1 静态规则 → L2 动态封禁（rate::counter 触发）→ L3 挑战响应（RFC-065 接线，executor.hpp:75 有未接线的 tracker）→ L4 限速
- 热路径注入点：`net/connection/tunnel` 双向转发循环
- **验收**：规则命中/过期/封禁升级全链路测试；bench 验证热路径零锁
- **关联 skills**：pool-audit、traffic-audit、security-audit、map-config。

#### T8-5 管理 API

- `runtime/api/`（独立 io_context，冷路径）：REST JSON（glaze）+ SSE（/traffic 实时、/alerts）
- 资源树按 management-design C1 清单落地；Bearer token 认证；独立端口默认本机绑定
- 消费 T5（latency/traffic/traces）与 T8-1~T8-4 数据
- **验收**：API 集成测试（含鉴权/错误路径）；worker 线程在 API 高负载下延迟无劣化（bench 对比）

#### T8-6 订阅生成器

- 冷路径从 directory 生成 Clash 订阅 YAML，URL token 认证
- **验收**：生成的订阅可被 Clash/mihomo 解析（golden 文件对比）

**T8 DoD**：管理面全链路可用；热路径纪律审计（management-design 第 4 节机制清单逐项核对）；全量回归 + 压力测试绿。

---

### T9 运维组件（P3 — 产品化刚需，独立可并行）

#### T9-1 ACME 自动证书

- http-01 挑战（JWS + 两个 HTTP 端点，手写，不引入重型库）；续期定时器（90 天周期，提前 30 天）
- 新证书构建新 SSL_CTX → COW 指针交换（复用 T4-4 的 COW 机制），连接中断零感知
- 配置：`cert: {auto, domains[], email, acme_dir}` 或手工 PEM（降级路径）
- **验收**：挑战/续期/交换全链路测试（mock ACME server）；SSL_CTX 交换不中断现有连接
- **关联 skills**：crypto-audit、map-config、error-chain-audit。

#### T9-2 Windows 服务化 + 崩溃转储

- `SetUnhandledExceptionFilter` → `MiniDumpWriteDump`（minidump 落盘）+ 日志记录（~50 行）
- Windows 服务封装（SCManager）或至少一键安装脚本；自愈（服务恢复策略）
- **验收**：人为触发崩溃 → minidump 生成 + 日志；服务安装/卸载/重启脚本测试
- **关联 skills**：error-chain-audit、leak-audit。

#### T9-3 TLS 会话复用缓存

- BoringSSL session ticket + 服务端 session cache（内部缓存），重连握手 1.5 RTT → 1 RTT
- `SSL_CTX_set_session_cache_mode` + ticket key 轮换；LRU + 上限防内存膨胀
- **验收**：重连握手 RTT 对比测试；缓存上限/LRU 测试
- **关联 skills**：dpi-audit、bench-perf、pool-audit。

#### T9-4 节点健康自检

- 冷路径周期任务：拨号出站目标（DNS + TCP 连通性）+ 延迟测量（复用 dialer + resolver）
- 结果经 `/health` 暴露（T8-5 扩展）；订阅生成器联动自动排除故障节点
- **验收**：健康检查周期任务测试；故障节点排除逻辑测试
- **关联 skills**：pool-audit、bench-perf。

**T9 DoD**：四组件各自测试 + 集成验证；`/health` 与订阅联动测试。

---

## 3. 质量门禁矩阵（每个单元必须执行适用的项）

| 编号 | 门禁 | 命令/方式 | 触发时机 | 通过标准 |
|---|---|---|---|---|
| G1 | 编译 | `cmake --build build --config Release -j 16`（晚间 22:00-08:00 用 `-j 1`） | 每个单元 | 0 错误 0 警告 |
| G2 | 单元测试 | `ctest --test-dir build -R <相关target> --output-on-failure` | 每个单元 | 全绿 |
| G3 | 全量回归 | `ctest --test-dir build --output-on-failure -j 1 --timeout 30`（约 2600 用例） | 每个子任务收尾 | 全绿（HandshakeTimeout 已知 flaky 除外，需二次确认） |
| G4 | 依赖 DAG 审计 | `docs/ARCHITECTURE.md` 第 261-262 行的 4 条 grep | 改动任何头文件 | 除已知环外 0 命中 |
| G5 | detached 审计 | `bash scripts/audit_detached.sh src/`（MSYS2 环境） | 新增/修改 co_spawn | 0 DANGEROUS |
| G6 | 编码规范 | AGENTS.md 规则 1/3/13（参数≤3、函数≤120 行、lambda≤10 行）、Doxygen 中文注释、规范 v2 大驼峰（存量未迁移文件暂循旧风格） | 每个单元 | 逐项自查通过 |
| G7 | 协程纯度 | 无阻塞调用/无锁/无 busy-wait（coroutine-audit skill 清单） | 每个单元 | 逐项自查通过 |
| G8 | 生命周期 | co-lifecycle-audit 清单（shared_ptr 捕获、co_await 后成员访问、PMR 资源） | 每个单元 | 逐项自查通过 |
| G9 | 错误链 | error-chain-audit（新增错误路径必须传播/记录，不吞异常） | 新增错误处理 | 逐项自查通过 |
| G10 | 性能门禁 | 热路径改动必须跑相关 bench（`build/benchmarks/*.exe`）并对比基线 | 热路径改动 | 不劣于基线 ±3% |
| G11 | 资源清理 | `taskkill //F //PID <pid>`（只杀本轮启动的进程） | 每个单元结束 | 无本轮进程残留 |
| G12 | 测试质量 | review-test 清单（错误矩阵/边界/并发覆盖） | 每个子任务收尾 | 与同模块测试深度对齐 |
| G13 | 分支覆盖测试 | 新组件/新函数每个分支路径（if/else、switch case、边界、半包、坏数据、错误矩阵、超时/取消）必须有对应测试用例命中 | 每个单元 | 逐分支核对清单，无未测分支 |
| G14 | 代码覆盖率 | `PRISM_ENABLE_COVERAGE=ON` 构建 + ctest + gcovr（`gcovr --root . --filter "src/prism/" --html-details build/coverage.html --print-summary`） | 每个子任务收尾 | 新组件模块覆盖率 ≥ 80%（行+分支） |
| G15 | 压力测试 | `build/stresses/<相关>Stress.exe` 短跑 30-60s | 有状态/并发组件 | 无崩溃、无内存泄漏、错误计数为 0 |
| G16 | 压测回归 | 并发/长跑压测，记录峰值内存与泄漏曲线 | 涉及内存池/缓存的组件 | 曲线平稳，无单调增长泄漏 |

**说明**：G3 全量回归较慢，可在子任务收尾时跑；单元级至少 G1+G2+G4-G9。
**四象限**：每个新组件 Q1 分支（G13）+ Q2 覆盖率（G14）+ Q3 性能（G12）+ Q4 压测（G15/G16）；
小改动豁免规则与测试数据文件规范见 NEXTGEN_TASK.md 2.4/2.5（同一约定，数据目录用 `docs/test-data/`）。

---

## 4. 纠错协议与提交纪律

### 纠错协议

| 级别 | 触发 | 处理 |
|---|---|---|
| L1 编译/测试失败 | G1/G2 红 | 修复该单元改动 → 重跑门禁 → 继续（最多 3 次） |
| L2 架构违规 | G4 新增依赖环、G5 出现 DANGEROUS、跨层 include | **停止该单元**，回退改动，拆解设计（评估归属层/接口抽象）后再实施 |
| L3 行为漂移 | 改动范围超出当前单元（夹带无关重构） | 立即回退漂移部分，记录到「后续候选」再继续 |
| L4 重复失败 | 同一单元连续 3 次 L1 失败 | 暂停该单元：重新调研、简化方案（如缩小单元范围）后继续；仍无法收敛则标记 `SKIP`（记录原因），继续下一单元，最终总结报告中列出 |
| L5 回归异常 | G3 出现非 flaky 失败 | 定位是哪个单元引入 → 回退该单元 → 修复重跑；严禁带红进入下一任务 |

**纠错纪律**：
- 回退用 `git checkout -- <file>`；回退后重跑受影响门禁。
- 每次 L2/L4/L5 必须写入 `docs/TASK_PROGRESS.md` 的「错误日志」区，作为知识沉淀。
- **全自动处理**：以上全部由代理自主完成，无需人工介入；无法决策时选保守方案并记录。

### 提交纪律（重要）

- **禁止自动提交**：任何情况下不得执行 `git commit` / `git push` / `git amend`。
- 不向用户汇报、不请求提交批准；全部任务完成后在 `docs/TASK_PROGRESS.md` 末尾
  生成「待提交清单」：按任务分组列出文件清单 + 摘要 + 建议 message
  （`fix:`/`feat:`/`refactor:`/`perf:`/`test:`/`docs:`），供用户自行处理。
- 期间若用户主动指示提交，按指示执行（仅 `git add <指定文件>`，禁止 `git add -A`）。
- **Go 产物**：`tests/go/**/*.exe`、`logs/*.log` 等构建产物不得提交。

---

## 5. 架构红线（低耦合高内聚，逐条不可违反）

1. **依赖单向性**：严格遵循 ARCHITECTURE.md 模块层级表（foundation→crypto/diagnose→net/user→resource→protocol→handshake→settings/runtime）。新增 include 前先查层级；禁止下行模块引用上行模块（已知环 settings↔runtime、net↔resource 不得新增同类）。
2. **聚合头同步**：新增子头文件必须同步加入模块聚合头；聚合头内按模块分组。
3. **前向声明优先**：头文件中能前向声明就不 include；unique_ptr 成员析构放 .cpp。
4. **资源归属**：新资源按 L1-L4 模型归位（进程/worker/session/detached），detached 协程严禁引用 L3；热路径容器用 PMR（memory::string/vector），禁止裸 std::vector 入场（对照 issues P-9）。
5. **接口收敛**：函数参数 ≤3，超过用 struct 收敛；opts 结构独立 POD、不继承；资源访问链式（`res_->worker->process->cfg->...`），不加透传 getter。
6. **单一职责**：一个文件一个职责；中间件/模块内部高内聚，外部低耦合；新增跨模块调用前先自问「这个逻辑属于哪一层」。
7. **错误双轨**：热路径 fault::code 不抛异常；启动/致命用 exception::deviant 层次。新增错误枚举进 `foundation/fault/code.hpp` 并保持兼容。
8. **性能纪律**：热路径（每包/每连接）只允许原子/条件分支；冷路径可任意复杂度但绝不占用 worker 线程；任何旁路缓冲「满了就丢」。
9. **不新增全局可变状态**：跨 worker 共享数据必须走资源容器（L1/L2）或 COW 快照，禁止全局单例。
10. **测试伴随**：生产代码与测试同单元落地；测试命名 PascalCase，异步测试必须 `co_spawn + ioc.run()` 模式（MuxLifecycle 模式），禁止 `run_for/poll` 驱动异步。
11. **评估先行（自动决策）**：标注「评估」的单元（T3-3 等）必须先产出设计结论并写入决策记录，然后按结论实施或降级（保守方案），全程无需人工确认。

---

## 6. 达标标准（DoD，全部满足才算任务完成）

- [ ] 任务栈 T1 → T9 顺序完成，各任务内部子任务 100% 验收通过（SKIP 项有明确原因记录）
- [ ] G3 全量回归绿（非 flaky），G4/G5 零命中，G10 性能不劣化
- [ ] 无新增 TODO/FIXME/裸直连/硬编码特判；issues.md v2（T2-2 产出）中对应条目标记修复
- [ ] 文档同步：聚合头、ARCHITECTURE.md（如模块归属变化）、management-design.md（T8 各阶段状态表）、performance-report.md（T4 新基准）、protocol-integration-plan.md（T3 状态表）、issues.md
- [ ] 每个新模块有独立测试 target；每个修复有回归测试；fuzz targets ≥ 10 个零崩溃（T7 后）
- [ ] CI（T7 后）全绿含 Go/ASAN/fuzz/benchmark 门禁
- [ ] 进度文件 `docs/TASK_PROGRESS.md` 完整记录（含错误日志与决策记录）
- [ ] `docs/test-data/` 每个组件数据文件齐全且状态 PASS；`INDEX.md` 无 FAIL 状态
- [ ] `docs/TASK_PROGRESS.md` 末尾已生成「待提交清单」（供用户处理，不自动提交）

---

## 7. 进度记录模板（写入 docs/TASK_PROGRESS.md）

```markdown
# TASK_PROGRESS

> 自动维护，勿手工编辑。每个单元结束更新。
> 无人值守：只记录事实与决策，不向用户汇报。测试数据见 docs/test-data/。

## 总览
| 任务 | 状态 | 进度 | 备注 |
|---|---|---|---|
| T1 正确性三件套 | pending/in_progress/done | 0-100% | |
| T2 技术债与安全清理 | pending/in_progress/done | 0-100% | 穿插执行 |
| T3 协议面补齐 | pending/in_progress/done | 0-100% | |
| T4 性能纵深 | pending/in_progress/done | 0-100% | |
| T5 可观测性基建 | pending/in_progress/done | 0-100% | T8 前置 |
| T6 中间件管线移植 | pending/in_progress/done | 0-100% | |
| T7 质量工程升级 | pending/in_progress/done | 0-100% | |
| T8 管理面全景 | pending/in_progress/done | 0-100% | 依赖 T5 |
| T9 运维组件 | pending/in_progress/done | 0-100% | |

## 当前焦点
- 任务：T1-2 worker 优雅停机
- 单元：步骤 1（stop 协议 + stopping 标志）
- 门禁：G1 绿 / G2 绿 / G4-G9 自查通过
- 数据文件：docs/test-data/worker-shutdown.md（未创建则创建）

## 已完成单元
- [x] T1-1 half-close 状态机（2026-08-16）→ 数据文件 PASS → docs/test-data/tunnel-halfclose.md
- ...

## 决策记录（全自动模式）
- T3-3 VISION 评估（2026-08-16）：BoringSSL 服务端不支持 uTLS 指纹 → 降级为 flow 字段透传
- ...

## 错误日志
- 2026-08-16 L2：T1-1 初版在 relay_loop 引入了共享 buffer 竞争 → 回退，改为左右独立 span
- ...

## SKIP 记录
- 无

## 后续候选（行为漂移记录）
- 发现 socks5 handler 内部转发循环疑似同样 half-close 缺陷，待 T1-1 完成后确认

## 待提交清单（全部任务完成后生成，供用户处理）
- 无
```

---

## 8. 长任务执行提示词（一次性启动，无需循环调度）

```text
你是 Prism 仓库主项目的长任务执行代理（任务规范：docs/LONG_TASK.md v5，必须先完整阅读）。
运行模式：一次性长任务，连续执行直到任务栈（T1-T9）完成。
无人值守：不向用户汇报、不请求确认、不自动 git commit/push；所有测试数据与结论
写入 docs/test-data/<组件>.md，用户只查看这些文件。

执行流程：
1. 读 docs/TASK_PROGRESS.md 确定当前任务与单元；不存在则按第 7 节模板初始化。
   全部 done → 汇总写入 docs/test-data/INDEX.md 并结束。
2. 按「执行协议」（第 1 节）逐个推进单元：前置调研 → 原子改动 → 写测试
   （生产级代码，遵守第 5 节架构红线 + AGENTS.md 编码规则 + 相关 skills 审计清单）。
3. 每个单元跑门禁（第 3 节 G1-G16 适用的项；G1 构建前先确认当前时间决定线程数，
   晚间 22:00-08:00 强制 -j 1）。
4. 每单元门禁完成后，把原始数据（bench 表/gcovr 摘要/stress 日志尾部）写入
   docs/test-data/<组件>.md（模板见 NEXTGEN_TASK.md 2.4，同一约定），
   自主分析四象限（G13/G14/G12/G15-G16）是否达标：
   - 全部 PASS → 更新 TASK_PROGRESS.md → 继续下一单元。
   - 任一 FAIL → 按第 4 节纠错协议自主修复重跑并更新数据文件（≤3 次）；
     仍失败 → 简化方案或标记 SKIP（记录原因）后继续下一单元，绝不无进展空转。
5. 每个单元结束清理本轮启动的进程（G11）。

纪律：一次只动一个单元；不夹带无关改动；数据文件未 PASS 不得前进；不自动提交；
评估性单元（T3-3）自动调研→决策→记录→实施；每单元必须有实际进展
（改动或有效调研结论），禁止无产出循环；全部任务完成后在 TASK_PROGRESS.md
末尾生成「待提交清单」（文件列表+摘要+建议 message）。
```

---

## 9. 使用提示

- 每个单元工作量以「1-2 小时可完成并可验证」为粒度；子任务过大时继续拆分。
- **执行顺序弹性**：T2 可穿插任意间隙；T5 必须先于 T8；T1/T3/T4/T6 相互独立（按序执行即可）。
- T8 开放问题已按第 2 节「范围自动决策」确定默认值，执行中如需调整直接改决策记录。
- 文档（protocol-integration-plan.md 等）已过期的部分，在任务执行中顺手修正或提示（并入 T2-3）。
- 长时间执行注意事项：
  - 构建/测试进程耗时长，G11 清理必须在每个单元结束执行，防止内存堆积。
  - 若执行被中断（进程被杀/会话超时），重启时按 TASK_PROGRESS.md 从当前焦点单元继续，
    已完成的单元不回退。
  - 提交完全受用户控制：全部完成后查看「待提交清单」自行处理，执行者不自动提交。
