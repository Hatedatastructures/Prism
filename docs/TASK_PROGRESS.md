# TASK_PROGRESS

> 自动维护，勿手工编辑。每个单元结束更新。
> 无人值守：只记录事实与决策，不向用户汇报。测试数据见 docs/test-data/（主项目任务）
> 与 docs/ngx-test-data/（Next-Gen 任务）。
> 权威计划文档：docs/NEXTGEN_IMPLEMENTATION_PLAN.md（阶段 0-6 + Gate A-D）。
> 2026-08-18 起废弃旧 T0-T7 任务编号（内容已并入实施计划阶段化结构）。
> 2026-09-05：本文件记录 Gate D 分层推进事实；总 Gate D 仍受生产识别器、外部 L5 和完整对拍前置阻塞。

## 实施计划总览

| 阶段 | 内容 | 状态 |
|---|---|---|
| 阶段 0 | 冻结真实基线（计划/矩阵/文档） | ✅ 已完成 |
| 阶段 1 | 公共层正确性收口（relay/memory_stream/XHTTP/MUX） | ✅ 已完成（Gate A） |
| 阶段 2 | 协议完成度矩阵 + 门禁定义 | 🔄 进行中（Preview 确定性路由/有界试探两种策略、native QUIC、稳定性和 Preview 性能已补；全协议 L5 和跨实现性能仍缺） |
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
3. preview vs psm 同场景性能对标——⚠️ 已有同一 Contract 的 codec、固定 16 KiB memory transport、TCP loopback 和固定 1200 字节 UDP loopback 指标（PerformanceContract focused 4/4，含 median/p95/p99/MAD/CPU、进程 `peak_working_set_bytes`、comparisons 及 TCP `bytes_per_second`/UDP `packets_per_second` 字段）；外部矩阵已为每个实际用例记录 `wall_time_ms`/`peak_working_set_bytes`/`metrics_available`，真实代理握手、持续吞吐和多连接 RSS harness 尚未做
4. 生命周期/错误链审查结论文档——✅ 已做（docs/ngx-test-data/LIFECYCLE_AUDIT.md）
5. Trojan/VMess/SS2022 纵向链路（L3）——✅ 已做（经 core/runtime/adapter 缝）
6. mux 中间件接入 runtime、DNS 接入 dial——✅ 已做（mux 2/2、pad 2/2、DNS 3/3）
7. 伪装方案迁移决策——✅ 已生成 `docs/ngx-test-data/migration-decision.md`；当前建议仍为 experimental/keep-psm
8. SOCKS5 纵向场景回归——✅ `Socks5LongitudinalCoverage` 5/5 已补齐认证/half-close/超时/统计/上游中断场景

## 当前焦点

- 2026-09-11 最终权威门禁（拆分跑法）：Release 全量构建 exit `0`；功能并行
  `ctest -LE "perf|stress" -j 8` `3853/3853` 通过（`30.48s`）；perf/stress 串行
  `ctest -L "perf|stress" -j 1` `94/94` 通过，`Perf_Recognition` `936.62s`，
  perf/stress 标签时间 `957.38s`，全量墙钟 `957.67s`；合计注册 `3972`、active `3947`、
  `25` Disabled、失败 `0`；
  G7/mirror `260/260`，
  detached `DANGEROUS=0`。外部矩阵为 `63 total / 54 pass / 9 blocked / 0 failed`。
  Recognition/Profile/Session focused 集合 `215/215` 通过。

- 2026-09-11 当前工作树复核：普通功能组使用 `ctest --no-tests=error
  -LE "perf|stress|interop" -j 8`，`3855/3855` 通过（`26.49s`）。性能/压力组保持
  `-j1`；`Perf_Recognition` `741.10s` 通过，其余 `97/97` 实际用例通过。期间发现
  `Perf_MultiConnLinear` 因带引用捕获的 coroutine lambda 生命周期错误产生
  `SEGFAULT`，已改为显式参数的命名协程；构建后单项连续 `3/3` 通过。生产目录未修改。
  生产 `interop` CTest 单次复核为 `4/4`；独立 TUIC 连续 5 次为 `4/5`，仍有一次
  首连接 echo timeout。Fresh L4 生产对拍为 SOCKS5/SS2022/VMess echo PASS、
  VLESS/Trojan echo FAIL；当前生产前置阻塞范围收窄为 VLESS/Trojan analyzer 和
  TUIC 首连接竞态，不能写成 Preview/生产全部完成。

- 2026-09-11 PerformanceContract 迁移复核：三轮 Contract `4/4` 均通过，最终机器结果
  将 `ss2022.session_key` median `+12.86%`/p95 `+5.61%`、`socks5.parse_addr_port`
  median `+339.47%`/p95 `+321.49%`、`transport.udp_loopback` median `+10.91%`/
  p95 `+17.23%` 分类为 `block`。这些是当前 Preview/生产同 harness
  的真实差异，已写入迁移矩阵；本轮不通过改阈值、换样本或重命名指标来消除，因此没有
  协议可标记为 `migrate`。

- 2026-09-11 Dgram over-reporting 收口（P-M23）：TrustTunnel、SOCKS5、Trojan 和
  VLESS 的 datagram 发送循环、精确读取窗口与 payload 窗口现在拒绝底层返回超过剩余
  容量的字节数，并统一传播 `BadLength`；新增回归与 Hysteria2/TUIC 错误矩阵合计
  `66/66` 通过。生产目录未修改。

- 2026-09-11 Stream over-reporting 收口（P-M24）：AnyTLS、Reality、VMess 和 SS2022
  的精确读取/写入辅助现在拒绝底层返回超过剩余窗口的字节数，避免错误数据被当成
  有效握手或推进偏移；新增 AnyTLS/Reality/VMess/SS2022 回归，相关 focused `5/5`
  通过。生产目录未修改。

- 2026-09-11 ShadowTLS 精确读取收口（P-M25）：ShadowTLS `ReadExact()` 现在拒绝底层
  返回超过剩余窗口的字节数，避免超额读取被误解释为 `BadAuth`；新增回归并纳入
  ShadowTLS/VMess 错误集合，focused `15/15` 通过。生产目录未修改。

- 2026-09-11 Mux/VLESS/SS2022 over-reporting 收口（P-M26）：Mux 精确读、VLESS Conn
  读写以及 SS2022 UDP 临时缓冲/发送循环现在拒绝超过剩余窗口的底层返回；新增公开
  握手和 Mux 回归，相关 focused `19/19` 通过。生产目录未修改。

- 2026-09-11 公共传输边界收口（P-M27）：Common `ReadMin/ReadRemaining` 修复
  Preview 传输类型并拒绝 over-report；HTTP/1.1、SOCKS5、Trojan、VMess、VLESS
  的读写/拼接路径，以及 WebSocket、Gun、TrustTunnel 握手读循环和 HTTP/2/XHTTP
  驱动均在使用返回长度前校验目标窗口，异常返回不再越界推进或构造 span；新增
  over-report 回归，相关 focused `117/117`、功能全量 `3853/3853`、perf/stress
  `94/94` 通过。生产目录未修改。

- 2026-09-11 EVP 错误传播收口（P-H20）：VMess/SS2022 AES-GCM 与 Reality
  SessionId 现在拒绝非法密钥、Nonce 和不可表达的长度，并检查每次 EVP
  Init/Update/Final/Tag 调用；失败时清空输出且不推进 nonce。VMess 认证头、响应头
  和连接应答检查期望密文长度并传播 `CryptoError`/失败结果。旧实现的非法参数
  成功 RED 已复现，修复后相关 focused `53/53` 通过。

- 2026-09-11 Reliable 连接错误契约收口（P-M02）：`Reliable::Connect()` 的 connect
  操作统一使用 `redirect_error`，普通拒绝和 timeout 返回错误码而不是抛异常，失败
  路径关闭 socket。`ReliableConnectReturnsErrorCodeOnRefusal` 与相关 Transport
  focused `4/4` 通过。

- 2026-09-11 Connector completion/multi-buffer 收口（P-M03）：预读 completion 投递到
  关联 executor，multi-buffer 读用有界聚合缓冲并按序回写，短写续写改为事件投递，
  避免 inline 回调和递归栈增长。新增 3 个回归，`Connector` focused `8/8` 通过。

- 2026-09-11 Transmission 异常桥接收口（P-M04）：默认 completion-handler 桥接捕获
  底层读写协程异常并以 `generic:io_error` 回调一次，新增读/写异常回归，
  `CoreTransmission` focused `2/2` 通过。

- 2026-09-11 TaskRegistry 关闭语义收口（P-M05）：每个 tracked 协程绑定独立
  Asio cancellation slot；新增同步 `Cancel()` 请求入口，`CancelAndWait()` 改为同一
  executor 上非阻塞等待的 `awaitable<bool>`，直到 completion 真正释放 token 或超时。
  取消计数改为在实际释放时累加，析构路径先请求取消再解绑 Owner_；Preview/生产
  `TaskRegistry` 与 `OwnershipAudit.TaskRegistryDanglingOwner` focused `14/14` 通过。

- 2026-09-11 TokenBucket 极值算术收口（P-M07）：时间基准的 `now + 1` 改为饱和
  编码，补发乘法、令牌加法和相对时间增量均受打包字段/桶容量上限约束；超大
  `RefillCount` 不再回绕，正常并发不超发语义保持。TokenBucket、Throttle、Ban
  focused `10/10` 通过。

- 2026-09-11 FlatBuffer/Parser 长度契约收口（P-M08）：FlatBuffer 记录初始容量，
  `Prepare`/倍增增长拒绝 `size_t` 溢出；Parser 要求 `Config::MaxPayloadLen`，在
  追加、头长和 payload 长度计算前执行统一上限检查，超限清空并返回 `BadLength`，
  `Want()` 只报告未消费 payload。FlatBuffer、smux、h2mux focused 回归通过。

- 2026-09-11 静态凭据比较收口（P-M10）：新增 `Preview::ConstantTimeEqual`，覆盖
  二进制凭据和长度差异；StaticAuthenticator、SOCKS5、Trojan、VLESS、VMess、TUIC、
  Hysteria2、TrustTunnel 与识别候选 fallback 均完成全序列比较，避免内容差异短路。
  Authenticator、协议会话和 Basic Auth focused `75/75` 通过。

- 2026-09-11 ProbeDefense 窗口/容量收口（P-M11）：Tracker 支持可注入时钟，查询和
  记录路径主动清理过期来源；新增 key 达到上限时淘汰最旧项，`MaxRecords=0` 拒绝
  插入。过期挑战和零容量回归已纳入 `CoreModulesCoverage` 并通过。

- 2026-09-11 SNI 路由并发/查找收口（P-M12）：`SniRouteTable` 使用不可变 COW 快照
  原子发布，Lookup 按值返回；通配路由按首个标签后的后缀直接哈希查找，消除全表
  扫描并保持精确优先、单标签和大小写归一化语义。路由 focused `9/9` 通过，含
  并发读写回归。

- 2026-09-11 通用地址编码收口（P-M09）：严格拒绝空 IPv4 段、非法 IPv4/IPv6 文本、
  非 16 字节 IPv6 原始输入和空/超长域名；公共编码失败时不追加 wire，SOCKS5、
  Trojan、Hysteria2、TUIC、SS2022 构造器传播失败并清空整帧。CommonAddress 与
  协议地址 focused 回归通过。

- 2026-09-11 Statistics identity 上限收口（P-M13）：`IdentityTraffic` 与
  `TrafficCounter` 增加默认 100000、可配置的最大 identity 数；COW 快照达到上限
  后拒绝新 key，已有 key 继续精确累加，避免客户端可控身份导致无界复制。容量和
  原有并发统计 focused `9/9` 通过。

- 2026-09-11 Profile/HTTP1 边界收口（P-M14/P-M15）：RecognitionBudget 增加
  `MaxRoutes`、`MaxCandidateNameBytes`、`MaxSchemeBytes` 并接入 Profile/Settings
  校验；HTTP/1 parser 拒绝重复安全头、折叠行、非法头名/值和超过 64KiB 的头块。
  Profile/Settings 与 Http11 focused 均通过；PreparedState 内部大小仍由具体候选负责。

- 2026-09-11 QPACK 解码预算收口（P-M16）：静态表模式继续拒绝动态指令，并增加
  64KiB 头块、128 字段、16KiB 单字段/Huffman 输出上限；超限输入在追加/解码前失败。
  QpackInterop focused `11/11` 通过；第三方 nghttp3 内部动态状态仍不由 Preview 伪装审计。

- 2026-09-11 AnyTLS 零进展收口（P-M17）：`SendBytes` 拒绝底层写入返回 0 或超过
  剩余缓冲区的计数，避免握手忙循环和 offset 越界；zero-progress/over-reporting
  focused `2/2` 通过。其他协议的独立发送循环仍保留后续复查项。

- 2026-09-11 SampleTracer RingSize 边界收口（P-H10）：非二次幂/零容量归一化为默认
  256，合法容量封顶 65536，避免位掩码索引越界和极值分配；SampleTracer focused
  `5/5` 通过。

- 2026-09-10 TrustTunnel Basic Auth 收口：解析改用严格 Preview Base64 decoder，拒绝中间
  padding/尾随数据，并对用户名和密码执行恒定时间比较；`TrusttunnelCodecDeep` `5/5`
  通过。DNS First loser、Pad random failure 和相关 focused 回归均保持通过。

- 2026-09-10 serializer 随机失败收口：VMess 请求头和 SS2022 TCP 请求盐的随机源统一
  走 `Crypto::FillRandom`，失败时不再生成可发送的伪握手；`VmessBeast` 与
  `Shadow2022Beast` focused `9/9` 通过。

- 2026-09-10 QUIC/HTTP3 随机失败收口：ngtcp2 `rand_ctx` 绑定连接所有权，随机源失败
  不再静默继续或生成确定性字节；nghttp3 初始化失败也不再 fallback。可注入失败源的
  `NativeQuicLoopback.RandomSourceFailureRejectsConnection` 与 QUIC/HTTP3 focused `12/12`
  通过。

- 2026-09-10 Crypto key 长度收口：BLAKE3 keyed hasher/hash 和 AES-ECB 改为
  `std::expected`，严格拒绝非法 key 长度并传播 `BadLength`/`CryptoError`；AES-192
  合法路径保持兼容。Crypto focused `49/49` 通过。

- 2026-09-10 真实 socket 读超时收口（P-H14）：`Reliable`/`Unreliable` 的读与
  定时器竞速，awaitable 与 completion-handler 两条路径都执行 `SetTimeout()`；
  新增真实 TCP/UDP 超时与“超时前到达数据”回归；`Unreliable` 移除重复的
  `enable_shared_from_this` 后，基类 completion-handler 桥接不再返回 `not_supported`，
  Transport focused `21/21` 通过。

- 2026-09-10 H2Mux 帧头校验收口（P-H02）：未知 `FrameType` 在帧头阶段返回
  `BadMessage`；window_update/ping 强制 4 字节负载、close 强制 0 字节，违规返回
  `BadLength`，杜绝“按声明长度分配/读取 16MB payload 后丢弃”。`H2muxFrameError`、
  `MuxBeast`、`MuxSessionDeep2` focused 与全部 Mux 用例 `128/128` 通过。

- 2026-09-10 Mux 接收预算收口（P-H01）：`SessionOptions.MaxStreamRxBytes`（4MiB）
  与 `MaxSessionRxBytes`（16MiB，0 = 不限）限制接收队列；`StreamHandle` 记账并在
  `ReadSome`/`Close`/`Reset`/`OnRst` 释放预算，超限按协议错误关闭会话。新增
  单流超限、跨流会话超限、消费后释放 3 个回归；全部 Mux 用例 `131/131` 通过
  （含 100MB 传输 perf 用例）。发送侧 `PendingWrites_` 字节预算仍未实现。

- 2026-09-10 UDP relay 关联表收口（P-H03）：`AssocTable` 对称回收未配对与配对
  条目（配对按两侧最后活动最大值判定空闲），配对时淘汰过期候选并择优最新来源；
  新增 `RelayOptions.MaxAssociations`（默认 256，0 = 不限）拒绝超限新会话且不影响
  已有会话；新增 B-first 陈旧条目、关联上限、单侧活跃 3 个回归，连续 5 轮无
  flaky，UdpRelay focused `7/7` 通过。

- 2026-09-11 Mux writer 取消路径收口（P-H17）：请求节点改为 producer/writer
  共享所有权，移除 `Consumed` 二次确认等待；`Teardown()` 统一唤醒并失败化排队
  请求，writer 完成后立即出队。旧实现的 200ms 卡住场景已形成 RED，修复后
  `MuxWriteContract` `9/9` 通过；功能全量 `3771/3771`、perf/stress `94/94` 均通过。

- 2026-09-11 Listener RAII 收口（P-H13）：`TcpListener` 析构幂等调用 `Stop()`，
  `Lifetime.Stopped` 防止停止后已完成的 accept 进入 SessionFactory；新增
  `DestructorStopsAccepting`，Listener focused `52/52` 通过。P-H17 的 writer
  改动与本项共同通过完整功能和 perf/stress 门禁。

- 2026-09-11 Mux 流 ID 收口（P-H12）：`AllocateId()` 改为单调 32 位分配，保持
  客户端奇数/服务端偶数，不再在 `65535` 后回绕复用旧 ID；耗尽时拒绝新流并关闭
  会话。`StreamIdWrapAround` 现验证第 32769 个客户端流为 `65537`，全部 Mux
  focused 回归通过。

- 本地快速回归（非证据档）：功能性用例可用 `ctest --test-dir build -LE "perf|stress"
  -j 8`（实测 `3769` 用例 `22.4s`，0 失败）；性能用例的**证据档**必须保持
  `-j 1` 默认参数，迭代时可用 `PRISM_RECOGNITION_PERF_WARMUP=50
  PRISM_RECOGNITION_PERF_SAMPLES=1 PRISM_RECOGNITION_PERF_TRIALS=1000` 将
  `Perf_Recognition` 从 `741s` 缩短到约 `10s`（快速档结果不得写入证据）。

- 2026-09-10 DNS First 生命周期收口：并发 resolver 为每个上游使用独立 cancellation
  signal，首个成功后取消并等待 losers；`FirstReleasesOwnerAfterLosersAreCanceled`
  和 DnsUpstream focused `34/34` 通过，owner 不再被 detached loser 延迟持有。

- 2026-09-10 Pad CSPRNG 失败收口后的历史回归：CTest 注册 `3869` 项，`3844/3844`
  active 通过，`25` 个 `StealthNested2` 明确 Disabled，失败 `0`；`Perf_Recognition`
  `698.72s`，全量墙钟 `807.99s`；Pad focused `11/11`。

- 2026-09-10 Pad 配置映射后的历史本地回归：CTest 注册 `3868` 项，`3843/3843`
  active 通过，`25` 个 `StealthNested2` 明确 Disabled，失败 `0`；
  `Perf_Recognition` `682.03s`，全量墙钟 `817.40s`；Pad focused `3/3`。

- 2026-09-10 识别证据扩展：新增真实 sing-vmess TCP-only 与 sing-shadowsocks SS2022
  client → Preview `MixedTrial` 单端口 listener 认证/echo；当前外部矩阵为
  `63 total / 54 pass / 9 blocked / 0 failed`，真实单端口识别记录为 HTTP、SOCKS5、
  VLESS、Trojan、VMess、SS2022 共 `6/6`，`recognition_coverage_complete=true`。

- 2026-09-10 历史本地回归：Release 全量构建 exit `0`；CTest 注册 `3867` 项，
  `3842/3842` active 通过，`25` 个 `StealthNested2` 明确 Disabled，失败 `0`；
  `Perf_Recognition` `676.26s`，全量墙钟 `802.33s`；G7/mirror `260/260`，detached
  `DANGEROUS=0`，生产目录无 diff。此前 `3858/3833` 为历史快照。

- 历史权威本地回归（2026-09-10）：CTest 注册 `3858` 项，`3833/3833` active 通过，`25` 个
  `StealthNested2` 明确 Disabled，失败 `0`；`Perf_VmessMultiThread` 5.23s、
  `Perf_Recognition` `765.00s`，全量墙钟 `897.21s`；专用 CTest timeout `1800s`；G7/mirror `259/259`，detached
  `DANGEROUS=0`，生产目录无 diff。

- 2026-09-10 全量门禁复核（历史运行）：`ctest --no-tests=error -j 1` 注册 `3858` 项，
  `3833/3833` active 通过，`25` 个 Disabled，失败 `0`；`Perf_Recognition` 运行 `765.00s`，
  全量墙钟 `897.21s`。本轮新增 `DeterministicProfileResolvesByStructuralSelector`、确定性首字节冲突编译期拒绝、
  route-aware TLS SNI 派生、Probe partial+error 字节保留、两个错误 coordinator mode guard 和 canonical mode 名称回归；早先 `629.91s/762.50s`、`1017.75s/1149.13s`、
  `631.62s/746.10s` 作为历史样本保留；legacy Pipeline 现在也遵守预取消控制并保留回放传输，首包探测使用窗口读取而非逐字节请求；TUIC client/server perf test 改为显式等待 server coroutine 收口，消除 detached 生命周期竞态。

- 2026-09-07 识别策略增量：新增 `DeterministicRoute`。它允许多个带首字节或 TLS route 选择器的候选；非 TLS 首字节冲突在 Profile 编译期拒绝，运行期未消除的结构歧义在认证前返回 `Ambiguous`，不执行密码学试探；`MixedTrial` 继续作为显式配置的有界认证试探策略，`Configured` 保留旧的单候选兼容入口。ProfileBuilder、Settings、Pipeline、RecognitionPerf 和 RecognitionStability 均已接线，相关 focused/稳定性回归通过。

- 2026-09-07 混合明文/TLS route 边界修复：非 TLS 首包不再被 SNI route 逻辑标记为 Applicable，新增 `DoesNotApplyTlsRouteToCleartextPrefix` 回归；`MixedTrialMode` focused `32/32` 通过。

- 2026-09-07 VLESS 地址构造增量：TCP 请求和 UDP 帧的 IPv4、IPv6、Domain、未知 ATYP 及长度边界均严格校验；非法输入返回空 wire，不再写入零地址或任意长度地址。仅保留 `CmdMux` 的零长度 Domain 占位兼容语义；VLESS 相关 82 个 focused 用例全部通过。

- 2026-09-08 ShadowTLS v3 标准首包、ServerHello 解析、stateful application-data、server relay 和外部 mihomo client 增量后的最终回归：Release 构建 exit `0`；CTest 注册 `3826` 项，`3801/3801` active 通过，`25` 个 `StealthNested2` 明确 Disabled，失败 `0`；全量墙钟 `762.50s`，`Perf_Recognition` 正式默认参数 `629.91s`，专用 CTest timeout `1800s`；`ShadowtlsCodecDeep` 9/9、`ShadowtlsConnSession` 7/7、`ShadowtlsRelay` 4/4、`Perf_MultiConnLinear` 通过，且 C++ wire 与独立 Go HMAC-chain golden 一致。另修复性能测试 `vector<bool>` 并发 packed-bit data race。新增确定性模式的 Profile/Settings/Pipeline、歧义前置拒绝、唯一首字节认证、TLS route implicit selector、ClientHello boundary、HTTP bracket IPv6 校验、空 route 拒绝、Session/Dial/Listener 失败收口（含 detached session 异常、scheme exception replay/close）、Snapshot partial+error replay、carrier scheme exception、SOCKS5 分片 Probe 和性能/稳定性覆盖均通过。

- 2026-09-10 历史门禁复核：CTest `3858` 注册、`3833/3833` active 通过、`25` Disabled；完整外部矩阵 `scope=full`、`production_prerequisite_included=true`，共 `61 total / 52 pass / 9 blocked / 0 failed`，其中 5 条为 carrier `interface-gap`、1 条为 native TLS codec `environment-unavailable`、3 条为生产 analyzer 的 `blocked-production-prerequisite`；Preview-only scope 为 `58 total / 52 pass / 6 blocked / 0 failed`。四个真实单端口识别记录（Deterministic HTTP、Deterministic SOCKS5、MixedTrial VLESS、MixedTrial Trojan）均为 pass，且 `recognition_coverage_complete=true`。本轮还补齐确定性首字节冲突的编译期拒绝、route-aware TLS SNI 派生、Probe partial+error 字节保留、legacy Pipeline 控制回归、窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归。XHTTP、TrustTunnel 两方向和 half-close 已纳入真实互操作，ShadowTLS Preview server→mihomo v3 client authenticated-echo 已纳入矩阵，Preview TLS 无显式 route 时已改为拒绝并完整回注，ShadowTLS v3 application-data record 的方向性 HMAC 链已有 Go golden 和 Conn opt-in 回归，TLS record version、scheme 大小写和 CandidateRegistry Scheme mismatch、TLS route boundary、HTTP bracket IPv6、空 route、Session/Dial/Listener 失败收口（含 detached session 异常、scheme exception replay/close）、Snapshot partial+error replay、carrier scheme exception、SOCKS5 greeting 最小长度均有回归，性能 Contract 现在保存环境指纹和原始性能样本数组，生产目录仍无差异。

- 2026-09-10 Preview 审计增量修复：SOCKS5 客户端禁止认证降级到 `NOAUTH`；DNS over TCP/DoT 超过 `65535` 字节在长度编码前返回 `message_size`；WebSocket codec 拒绝 RSV/保留 opcode、非法控制帧和非规范扩展长度；Hysteria2 拒绝未知消息 Kind；Snapshot 默认捕获上限为 `64 KiB` 并支持显式预算；MemoryStream 半关闭后禁止本端继续写入；VMess/SS2022 握手盐和密钥材料统一走带失败检查的 CSPRNG helper。对应 focused 回归已通过；Gate D 的 carrier endpoint、完整 L5 和生产 analyzer 前置仍保持 blocked。

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
- 当前默认 Release 构建树（benchmark/stress 开启、interop/perf Contract 关闭）注册 `3858` 个 CTest；`3833/3833` active 通过，`25` 个 `StealthNested2` 用例明确 Disabled，失败 `0`。本轮 H2 connection preface（整包/分片/客户端发送）、HTTP/SOCKS5/Trojan/VLESS/VMess/Hysteria2/TUIC reference vectors、Configured/DeterministicRoute/MixedTrial 识别策略、TLS route boundary、HTTP bracket IPv6、空 route 拒绝、Session/Dial/Listener 失败收口、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception、ShadowTLS v3 ClientHello/ServerHello parser、stateful record protector、标准 server relay、SOCKS5 分片 Probe、Probe partial+error 保留、legacy Pipeline 控制和窗口读取性能回归、协议认证标记和账户租约传递、TUIC server coroutine 生命周期回归、QUIC、稳定性、性能、SOCKS5 纵向、TrustTunnel 标准 HTTP/2 CONNECT、gun-lite 握手回注、XHTTP client factory/half-close、分层 carrier、Settings candidate registry、ECH 无 inner Hello 拒绝、deterministic route 目标边界、确定性首字节冲突编译拒绝、route-aware TLS SNI 派生、MaxConnections listener 装配和认证器共享所有权，以及四个真实单端口识别记录均在全量门禁内通过。
- 外部矩阵已在当前工作树于 2026-09-09 重新生成：61 条记录，52 条 pass，9 条明确 blocked，0 条 protocol-failure/implementation-mismatch；其中生产 analyzer 前置的 3 条记录单独标记 `blocked-production-prerequisite`。Deterministic HTTP、Deterministic SOCKS5、MixedTrial VLESS、MixedTrial Trojan 四条真实单端口识别均通过。Hysteria2/TUIC/TrustTunnel/XHTTP 标准 HTTP/2 两方向、VLESS/TUIC/Hysteria2 reference UDP→Preview、VMess 双向 TCP/UDP、TUIC Preview→mihomo reference TCP+UDP、native TLS 双向 TCP、WebSocket 双向 TCP、AnyTLS 独立认证帧双向 TCP、gun-lite 双向 TCP、HTTP/SOCKS5/Trojan/VLESS/VMess reference vectors 均已进入矩阵并通过，结果在 `build/interop-results/summary.json`。

### 当前仍未完成

- Hysteria2/TUIC 的 provider-backed datagram、Native QUIC 单向/双向流和 TLS exporter 已可用；TUIC/Hysteria2 TCP、TUIC Preview→mihomo reference TCP+UDP、Hysteria2 reference UDP→Preview、TUIC/VLESS reference UDP→Preview authenticated-UDP-echo 均已稳定通过，其他 QUIC 伪装方案的完整 L5 仍待补。
- 全协议（代理协议 + 伪装方案）双向外部互操作和完整网络同 harness 性能对拍；Reality/Restls 双向与 ShadowTLS Preview client→reference server 因缺少标准 Preview client/carrier endpoint 以 `interface-gap` 明确记录，native TLS codec-vector 标为不适用的环境阻塞；ShadowTLS reference client→Preview server 已 PASS；具体 endpoint 解锁条件见 `docs/ngx-test-data/interop/carrier-interface-gaps.md`。
- VLESS/Trojan/VMess ↔ 生产 Prism 的真实单端口 echo；原因是生产 `analyzer.cpp` 尚未获授权修改，状态保持 `blocked-production-prerequisite`。
- Preview Evidence Gate 尚未因外部 L5/完整性能缺口关闭；逐协议迁移决策矩阵已生成，但没有协议达到 migrate 条件。

### 2026-09-05 增量事实

- Preview 已实现 Configured 与 MixedTrial 两种识别模式：Configured 保持单候选确定性，MixedTrial 支持候选决策表、认证试探预算、歧义和超时/取消终态。
- legacy 探测不再把 ASCII `VLESS` 或任意首字节当作 VLESS；标准二进制 VLESS 仅在固定头结构和合法 command/ATYP 满足时识别，配置候选仍负责 UUID 认证。
- Preview QUIC 网关已改为连接级协议/ALPN/CID 绑定，stream 首字节不再在 H3/TUIC 之间重新猜测；native ngtcp2 UDP loopback、provider datagram 和相关 MUX 回归通过。
- Preview HTTP/2 已补充 peer `END_STREAM` 半关闭保留状态；XHTTP 新增客户端工厂、标准 ALPN/HTTP2 preface、响应头确认和同一写队列上的 request half-close，并修复 Stream-one 客户端响应失败。
- 新增 `tests/preview/perf/RecognitionPerf.cpp` 与 `tests/preview/stress/RecognitionStabilityTest.cpp`。默认性能 harness 为 1000 warmup、7 samples、每 sample 10000 次，输出真实延迟/读取/分配/离散度字段；稳定性覆盖 1000 次顺序、16/32 并发、逐字节分片、EOF/half-close、timeout、mutation 和 10000 个 opaque 前缀洪水。
- 最终本地门禁（SOCKS5 补测前）：Release 构建 `exit 0`；全量 CTest `3693` 注册、`3668/3668` active 通过、`25` Disabled、`0` 失败；G7/mirror `251/251`，detached audit `DANGEROUS=0`。
- 2026-09-05 SOCKS5 增量：新增真实 listener/session/relay 的 `Socks5LongitudinalCoverage`，focused CTest `5/5` 通过；CMake 重新生成后当前注册总数 `3701`（含 LayeredCandidate 2/2 与 opaque flood 稳定性），最终全量门禁已重跑并通过 `3676/3676` active，`25` Disabled，`0` 失败。
- 本轮未修改 `src/prism/` 或 `include/prism/`，未执行 commit/push；hosted Linux/Windows CI 仍需在提交后单独验证。
- Preview Gate D workflow 已改为开启 benchmark/stress，并新增 recognition performance/stability 步骤与 verbose artifact；workflow/build 两份静态语法检查均通过。
- TLS carrier→inner protocol 组合已由 `LayeredCandidateFactory` 提供，真实 ClientHello/SNI/ALPN + HTTP wire 成功/失败回归 `2/2`。
- legacy VMess 首字节 `0x01` 不再被无配置探测误判；VMess 只通过 MixedTrial 的有界认证候选确认，Recognition/Layered focused `61/61` 通过。
- VLESS 无 magic 猜测修正后，Recognition/Layered/TLS focused `90/90` 通过；此前完整 Release 构建 exit `0`，全量 CTest `3721` 注册、`3696/3696` active 通过、`25` Disabled、失败 `0`，其中 `Perf_Recognition` 全量运行 `560.21s`；其 CTest 专用 timeout 为 `900s`。
- VMess Preview 已对齐标准 AEAD 数据面：ChunkMasking 的 SHAKE128 长度、方向 key/nonce、12 字节 GCM nonce、无 AAD response header 和明文长度 `4` 均有 Contract/codec/session 回归；VMess focused `50/50`、stealth error `9/9` 通过。
- 2026-09-05 外部互操作增量：独立 `sing-vmess` 客户端的 TCP+UDP → Preview VMess server authenticated-echo PASS；矩阵当前 `11 pass / 41 blocked / 0 failed`。
- 2026-09-05 VLESS 外部互操作增量：独立 Go VLESS reference 与 Preview client/server 双向 TCP authenticated-echo PASS；Preview UDP 工厂仍为显式 `NotSupported`，矩阵当前 `13 pass / 39 blocked / 0 failed`。
- 2026-09-05 SOCKS5 外部互操作增量：独立 Go RFC1928 reference 与 Preview client/server 双向 TCP authenticated-echo PASS；矩阵当前 `15 pass / 37 blocked / 0 failed`。
- 2026-09-05 HTTP CONNECT 外部互操作增量：独立 Go HTTP/1.1 reference 与 Preview client/server 双向 TCP authenticated-echo PASS；矩阵当前 `17 pass / 35 blocked / 0 failed`。
- 2026-09-05 TUIC 外部互操作增量：独立 `quic-go` client 通过 Preview Native QUIC 的 uni 认证流、TLS exporter 和 bidi Connect 流 authenticated-echo PASS；反向 reference server 随后接入 mihomo TUIC v5 server。
- 2026-09-05 TUIC UDP 外部互操作增量：独立 `quic-go` client 通过 Preview Native QUIC 的 uni 认证流和标准 TUIC v5 DATAGRAM packet authenticated-UDP-echo PASS；矩阵新增 1 条 pass。
- 2026-09-06 VLESS UDP 外部互操作增量：Preview `Dgram` 增加标准 VLESS UDP over TCP 的 2 字节大端长度分帧，独立 Go reference 与 Preview client/server 双向 authenticated-UDP-echo PASS；矩阵新增 2 条 pass，并修复 interop server 的 accepted socket 双移动回归。
- 2026-09-05 Hysteria2 外部互操作实现：新增 `Http3::NativeServerSession`，将异步 QUIC provider、HTTP/3 控制/QPACK stream、nghttp3 写偏移和认证后 raw bidi stream 串行接线；修复 ngtcp2 write-side reset/FIN 语义并补齐标准 UDP datagram wire 后，Preview NativeClient↔Go reference、独立 `sing-quic` client↔Preview server 和 reference UDP→Preview authenticated-UDP-echo 均通过。
- 2026-09-06 TUIC 反向互操作收口：mihomo v1.19.30 TUIC v5 reference server 接入矩阵；修复认证流必须发送 FIN、QUIC 关闭后写重试不得解引用已释放连接，以及 reference server `AuthenticationTimeout=0` 立即关闭的问题；Preview client→reference server TCP+UDP authenticated-echo PASS。
- 2026-09-08 最新本地回归（在上述识别策略、carrier、外部互操作基础上增加 CandidateRegistry 核心工厂、大小写规范化、Scheme 组合、TCP/UDP loopback 性能指标、原始性能样本、显式 TLS route fallback、TLS record version、TLS route boundary、HTTP bracket IPv6、空 route 拒绝、Session/Dial/Listener 失败收口（含 detached session 异常）、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception、ShadowTLS v3 ClientHello/ServerHello parser、stateful record protector、标准 server relay、SOCKS5 greeting 最小长度和 Scheme mismatch 校验、vector<bool> data-race 修复）：完整 Release 构建通过；CTest 注册 `3826` 项，`3801/3801` active 通过，`25` Disabled，失败 `0`，包含 `Perf_Recognition` 和 `Perf_VmessMultiThread`；完整 CTest 墙钟耗时 `762.50s`；G7/mirror `259/259`、detached `DANGEROUS=0`、生产目录 diff 为空；完整外部矩阵为 `57 total / 48 pass / 9 blocked / 0 failed`，Preview-only 子集为 `54 total / 48 pass / 6 blocked / 0 failed`，runner 记录 `source_state=dirty`。
- 2026-09-09 TLS 识别热路径收口：`ReadClientHello`、Configured TLS 边界探测和 TLS carrier candidate 解析直接使用稳定 `ProbeSnapshot` 字节视图，去掉重复临时复制；legacy Pipeline 控制路径新增预取消回归；TLS focused recognition `103/103`、Release 构建、全量 CTest（`3852` 注册、`3827/3827` active、`25` Disabled、失败 `0`）和外部矩阵 `61/52/9/0` 均通过，wire/回注/认证语义不变。
- 2026-09-09 QUIC 配置边界收口：`BuildProfileFromSettings` 在调用候选 factory 前拒绝 `hysteria2`/`tuic`，稳定返回 `QuicCandidateRequiresGateway`，避免 TCP Profile 把 QUIC 候选误报为 resolver 缺失；新增 `RejectsQuicCandidateBeforeCallingFactory`，ProfileBootstrap focused `12/12` 通过。
- 2026-09-09 canonical 识别配置：`Recognition.Mode = "Deterministic"` 映射到现有确定性 coordinator，旧的 `Configured`/`DeterministicRoute` 配置值继续兼容；新增 canonical mode 名称断言，ProfileSettings focused `13/13` 通过。
- 2026-09-09 C++ API 命名同步：`RecognitionMode::Deterministic` 作为 `DeterministicRoute` 的同值兼容别名加入，配置层与 Runtime 层使用同一 canonical 方案名，不改变既有分派语义。
- 2026-09-05 双模式配置接线增量：新增 Composition `SettingsBuilder`，将已解析的
  `RecognitionConfig`、候选工厂、immutable Profile 和 resolver 成对安装到
  `SessionOptions`；`ConfiguredCandidate` 在 `MixedTrial` 中改为显式配置错误，Settings/Profile
  focused `14/14` 通过。该入口仍要求调用方提供包含凭据和 handler 的候选工厂，完整协议配置映射待后续补齐。
- 2026-09-06 双模式路由补强：Profile/Settings 增加显式 `DefaultCandidate`，MixedTrial 在缺失
  SNI 时只使用配置的 fallback candidate；候选元数据保留实际外层 `Scheme`，避免自定义候选名
  覆盖伪装方案名，Profile/Settings/Recognition focused `88/88` 通过。
- 2026-09-06 Composition 接线补强：新增 `CandidateRegistry`，为 HTTP、SOCKS5、VLESS、Trojan、
  VMess、SS2022 提供带不可变配置捕获的 typed builder，并支持大小写规范化与 `ss2022`/
  `shadowsocks` 别名；带 `Scheme` 的候选必须组合已注册的 carrier binding，未注册时不再
  静默 passthrough；TCP Profile 编译阶段拒绝 Hysteria2/TUIC/QuicCarrier。相关 focused
  回归 `CandidateRegistry 10/10`、`ProfileBootstrap 12/12`、`ProfileCompile 25/25`、
  `ProfileSettings 11/11` 通过。完整协议凭据配置、carrier 实现和 QUIC gateway 仍由
  Composition/QUIC 入口显式提供。
- 2026-09-06 native TLS 外部互操作：新增 Preview `Native::Connect` 客户端工厂和标准 Go
  `crypto/tls` reference，Preview client→Go server、Go client→Preview server 双向 TCP PASS。
- 2026-09-05 MixedTrial 死锁修复：完整 `Structural` candidate 出现时不再等待未完成的 opaque
  fallback，避免 VLESS/VMess 等客户端在等待早期响应时互相等待；MixedTrial/Session focused
  `35/35` 通过。未注册 scheme 现在返回空传输而不是静默 passthrough，SchemeExecutor `3/3` 通过。
- Settings candidate 已增加 `Scheme`、`ServerNames`、`Alpn` 元数据，并允许 `hysteria2`/
  `tuic` 协议名；解析回归纳入 ProfileSettings，具体凭据和 QUIC 会话仍由 Composition
  候选工厂提供。
- Hysteria2 外部互操作已增加真实接口探针：Preview QUIC 的单向流创建/接收回环已通过，
  但 `Http3::Server::Init()` 仍只接受同步 stream-id 回调，缺少 provider 生命周期、
  stream ID 和 nghttp3 输出的适配器；矩阵将该方向记录为 `interface-gap`（exit `2`，
  不计入 protocol failure），证据为 `build/interop-results/hysteria2_reference-client-to-preview-server_interface-contract.*`。
- 互操作分类器已加入 Preview Gate D workflow；`InteropRunner.Tests.ps1` 验证
  `pass/protocol-failure/implementation-mismatch/environment-unavailable/interface-gap/
  blocked-production-prerequisite` 六类状态，矩阵的两个 Hysteria2 interface-gap 记录均为 exit `2`。

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
