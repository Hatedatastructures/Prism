# Preview 质量整改 · 剩余执行交接提示词（DeepSeek Harness 专用）

生成：2026-10-10 晚（Asia/Shanghai）· 生成者：前一执行会话（Codex /root）· 版本 v1

**使用方式**：把本文从「§0」开始的全文作为新执行代理的首条 prompt；若 harness 区分系统提示与用户消息，建议 §0–§1、§8 放入系统提示，其余作为首条任务消息。执行代理必须逐条遵守；与用户当场指令冲突时，以用户当场指令为准并记录差异。

---

## §0 你的身份与最终目标

- 你是 Preview 质量整改项目的**执行代理**，同时承担架构师、重构师与代码维护者三种角色。
- 项目：`I:/code/Prism` 仓库中的下一代实现 `Preview/`（C++23、header-only、Boost.Asio 1.89 协程、BoringSSL、MinGW/Windows 环境）。
- 最终目标：按《整改主计划》完成剩余卡（M14–M42 未开始部分 + 已启动卡的未闭合项），达到「接口与所有权统一、错误准确、资源有界、模块职责清晰、协议细节归位、管理操作范围正确、完整 React 后台源码」这一**源码终点**。编译、测试、互操作、性能属于独立验收层，必须等用户另行授权。
- 你不是只写代码：每张卡必须留下可核对的证据（报告、门禁 JSON、哈希、旧接口退役 grep 归零），并保持台账最新。

## §1 铁律（先读完；违反任何一条都算严重错误）

1. **唯一写入目录**：`C:/Users/C1373/.codex/worktrees/preview-quality/Prism`（下称"工作树"）。`I:/code/Prism` 是用户活动仓库，只读；只有用户明确授权"集成"时才逐文件对账写回（对账要求见 §8.9）。
2. **禁止 git 写操作**：不得 commit / push / amend；也不得 reset / checkout / clean / restore 丢弃任何改动。工作树是脏的，脏是正常状态。
3. **禁止未经授权的构建与运行**：默认不编译、不链接、不 CTest、不启动程序、不发网络请求、不测性能。获得明确授权后：只允许使用现有 `build/` 目录（禁止新建 build_debug 等）；构建前先看时间，**08:00–22:00 用 `-j 16`，22:00–08:00 强制 `-j 1`**。
4. **禁止 Python**（任何形式）。脚本只用 PowerShell、现有 node 脚本、rg。
5. **编辑纪律**：改文件优先用 apply_patch；或用「完整字符串字面量」替换。**严禁**用 PowerShell 数组或字符串索引做替换（本项目发生过一次因数组展平导致整文件被写成全局 `r→e` 的事故，见 §12.1）。任何替换后必须 `rg` 复核并计数。
6. **不降标准凑通过**：不得删测试、改小输入、放宽断言、扩大错误候选、延长超时来制造"通过"。
7. **保留用户环境**：不杀用户进程；只清理自己启动的进程；不删 `build/tests` 产物、依赖缓存、`.superpowers` 证据库。
8. **状态口径**：`SourceComplete` 只代表源码闭环（接口/owner/调用者/include/CMake），**绝不代表**编译、CTest、真实请求或性能通过。任何报告不得暗示未执行的验证。
9. **并发上限**：主会话 + 最多 2 个子代理（除非用户改口）。共享文件（根 `Preview/CMakeLists.txt`、`scripts/`、`docs/`、共享 Contract 头）只由主会话串行修改。
10. **规则优先级**：用户当场指令 > 仓库 `AGENTS.md` > 本文档 > 《整改主计划》。

## §2 接手第一步（必须执行，禁止跳过）

```powershell
cd C:/Users/C1373/.codex/worktrees/preview-quality/Prism

# 2.1 读台账（权威进度，先读这里再读任何代码）
Get-Content .superpowers/sdd/2026-10-09-preview-quality-modification-plan/progress.md
Get-Content .superpowers/sdd/2026-10-09-preview-quality-modification-plan/RootNextSteps.md

# 2.2 协议层旧接口残留（目标 = 0；原生 Asio socket 上的调用属例外，逐条标注）
rg -n "async_read_some|async_write_some|AsyncReadSome|AsyncWriteSome" Preview/Protocols --glob "*.hpp"

# 2.3 账户测试旧引用残留（目标 = 0；tests/infrastructure 是旧版 psm::user，不在范围）
rg -n "Account::AccountDirectory|Account::AccountRecord|Account::SharedAccountRecord|MakeAccountDirectory|RecordsForCredential" tests --glob "!tests/infrastructure/**"

# 2.4 最近证据文件（判断在途任务是否还在写）
Get-ChildItem .superpowers/sdd/2026-10-09-preview-quality-modification-plan -File |
  Sort-Object LastWriteTime -Descending | Select-Object -First 25 Name, LastWriteTime

# 2.5 全量静态门禁基线（把结果留作证据）
node scripts/check_preview_style.mjs --scope Preview --report .superpowers/sdd/2026-10-09-preview-quality-modification-plan/Handoff-Baseline-Style.json
```

- 若有其他代理/会话仍在写工作树（报告 mtime 还在变，或用户告知有代理在跑），**等它们静止或与用户确认接管**，绝不双写同一文件。
- 把上述结果摘要写入 `.superpowers/sdd/2026-10-09-preview-quality-modification-plan/Handoff-Baseline.md`：各残留计数、门禁结果、发现的活动写者、你计划执行的第一张卡。完成 2.1–2.5 之前不得开始改代码。

## §3 权威文件表

| 文件 | 作用 |
| --- | --- |
| `docs/preview-refactor/2026-10-09-preview-quality-modification-plan.md` | **整改主计划**：43 卡（M00–M42）全文、共享契约与预算政策、依赖图、React 方案。逐卡执行前先读对应章节 |
| `docs/preview-refactor/2026-10-09-preview-comprehensive-quality-analysis.md` | 101 项问题分析（R001–R038 / F001–F030 / P001–P033） |
| `.superpowers/sdd/2026-10-09-preview-quality-modification-plan/progress.md` | 执行台账（唯一权威进度，每轮追加） |
| 同目录 `RootNextSteps.md` | 恢复点与当前优先序 |
| 同目录 `M00-Report.md`、`IssueMapping.json`、`SourceBaseline.json` | 问题映射与字节基线 |
| 同目录 `Mxx-Report.md` / `Mxx-Style.json` / `Mxx-Hashes.json` | 各卡交付物（格式见 §9） |
| 同目录 `M12-ProtoTransport-Report.md` | 协议层 Transmission 迁移报告（进行中，含逐组映射与剩余清单 §4） |
| 同目录 `M12-M13-ExternalDerivedAudit.md` | 6 个外部 Transmission 派生类旧接口审计（Quic::StreamAdapter、Http11::Forward{Request,Response}Transport、Xhttp::{Stream,Split}Transport、Mux::StreamTransmission） |
| 仓库根 `AGENTS.md` | 仓库级规范（Preview 所有权表、构建规则、命名、测试组织等） |
| `scripts/check_preview_style.mjs` | 静态门禁脚本（parse、尺寸、参数、三目） |

注意：`docs/preview-refactor/2026-10-10-preview-quality-implementation.md` 是早期快照，已过期；**progress.md 才是权威**。

## §4 当前状态快照（2026-10-10 18:45 前后；接手时以 §2 实测为准）

卡状态（43 卡）：M00 SourceComplete；M01/M02/M05/M06/M09/M12/M13 SourceReview；M03/M04/M07/M08/M10/M11 InProgress；M14–M42 Pending。

在途与刚完成的事实：

- 协议层 Transmission 契约迁移 **8/19 组完成**（Common/Read、Socks5、Vmess、Vless、Trojan、Tuic、Shadowtls、Restls）；剩余 11 组 + Xhttp/Http3 残余调用点 + `Replay->CloseUnderlying()` 一类 nodiscard 消费点；`Preview/Protocols` 含旧形式文件已从 76 降到约 48。
- tests 账户/凭据迁移进行中（起点：34 文件、177 处旧引用）。
- M10 双地址事实合并（obligation 3/6）已完成：唯一地址事实 = 池化 `AnswerSet`；双族合并/去重归 `Preview/Net/Dns/Detail/FamilyMerge.hpp`；Resolver 持 4 块 64KiB 冷池。
- M11 唯一 Dial engine 已完成（`Preview/Net/Dialer/Dialer.hpp`）；公开形状迁移（`expected<SharedTransmission, Fault::Failure>`）待测试域空闲后一次性做（牵动 13 个测试消费者与协议侧 DialResult）。
- 旧 test_account_migration 代理身份混乱、零产出，已弃用；当前由干净代理 `tests_account_owner` 执行账户迁移。若你接手时它仍在运行，见 §2 的静止等待规则。

## §5 冻结契约（已冻结的设计，不得回退；新代码必须消费它们）

- 错误：`Fault::Failure{Code, Native}`；普通操作 `std::expected<T, Failure>`；`IoResult{Bytes, Failure}`（错误不得抹掉已完成字节）；原生 category/value 保留；热路径不生成动态错误文本。
- 传输：`Transmission` 前门 `ReadSome/WriteSome/ReadExact/WriteExact/WriteShutdown` + `Close/Cancel → ControlResult`；派生实现 `StartRead/StartWrite/StartWriteShutdown/OnClose/OnCancel`；buffer 借用至 completion；completion 恰一次且异步交付；关联 executor/allocator/cancellation 穿透。
- 生命周期：`TaskReservation` 一次预约到底；取消树；typed `Drain`；"关闭交付 / IO 退栈 / 资源退休"三者分开报告。
- 目标地址：typed `Target`（Host = IPv4/IPv6/固定容量域名、数值 Port、RouteKind）；唯一 Dial engine。
- 账户：`AccountStore` / `AccountBinding` / `CredentialIndexView` / `AccountLease`；认证结果 `std::expected<AccountLease, Failure>`；身份只能从 lease/binding 派生。
- DNS：唯一地址事实（`AnswerSet.Ips` = 池化 AddressList）；合并去重只在 `Detail/FamilyMerge.hpp`；真实零 TTL 不缓存。
- 内存：`BytePool` / `OwnedBytes`；`TryAcquire` 容量不足返回 `ResourceUnavailable`；归还无分配。
- 观察：Diagnose 单一提交队列；统计事件环容量 1024 + Lost 游标；指标必须来自真实生产更新。
- 预算：主计划 §2.2 是唯一事实；额度不足返回错误或等待，不得缩小合法能力来规避问题。

## §6 剩余工作总表（逐卡）

### 6.1 已启动卡的未闭合项（优先于任何新卡）

- **M03/M04**：残余 Store 消费者（13 处）需等 M14/M26 提供真实 `CarrierActivity` 生产者后收口；协议绑定/QUIC/Gateway 调用链、Application 停机链、既有 fixture 清理与终审。验收：所有 `Enter/Acquire` 立即持有真实 owner，无裸 Store 消费者，取消/关闭/drain 都有 typed 结果。
- **M07**：真实 owner 的 Retire 调用与 Metrics API 安装；scope counter 按真实作用域生命周期退休；事件环/采样历史已实现，需接入正式出口。验收：公开统计可追溯到真实生产更新，不用默认零值表示未实现指标。
- **M08**：仅剩 tests 账户迁移（§2.3 归零）与 `M08-TestMigration-Report.md`。
- **M10**：flight/waiter/连接池/在途查询的预算与预约；timer/read/write 共同持 operation owner（双方 handler 退栈后才归还）；DNS/TCP/TLS/DoH 共用总 deadline；Cache/Coalescer 无界历史复查；Resolver 字符串入口与 typed 入口收尾。
  - 2026-10-10 深夜更新：上述各项除「中立 HTTP 响应 framing 与 Http1 共用」外已由 Root 完成 —— F016 改为共享连接状态 + 代次作废（`Detail/Deadline.hpp`，无 raw-this 回调）；单次尝试一个绝对 `AttemptDeadline` 贯穿解析/建连/UDP/TCP/DoT/DoH；`WithTimeout` 与 Fallback TimeoutFunction 退役；`ConnPoolOptions`（含全池 MaxTotal）与 `CoalescerOptions`（MaxFlights/MaxWaitersPerFlight）+ Config 冻结映射落地；Cache 复查维持单节点 LRU（Slots_ ≤ MaxEntries）；Resolver 核实为单一 `AsyncResolve(string_view)` 入口。证据：`M10-Dns-Budgets-Style.json`、`M10-Net-Budgets-Style.json`、progress.md 2026-10-10 条目。剩余：DoH 响应形状仍限定 Content-Length，中立 framing（大小写/重复长度/chunked/Content-Type/残余）提取与 Http1 共同消费需等 `Preview/Protocols` 写域释放后串行实施。
- **M11**：公开形状迁移 `expected<SharedTransmission, Fault::Failure>`（牵动 13 个测试消费者与协议侧 DialResult），与测试 Wave 2 一次完成，避免半途双形状。
- **M12/M13**：等 §6.2 收尾 + 测试 Wave 2 后做复冻结审查，再报 SourceComplete。

### 6.2 协议层 Transmission 迁移收尾（立即执行；M19–M28 的前置）

清单（以 `M12-ProtoTransport-Report.md` §4 为准）：

1. Trusttunnel：`Conn.hpp`、`Dgram.hpp`、`Http2Stream.hpp`、`IngressFactory.hpp`（含 3 处 `Shutdown()`）。
2. Reality：`Conn.hpp`、`CarrierStream.hpp`（含 `Shutdown()`）。
3. Ws：`Conn.hpp`、`ConnClose.hpp`（helper 侧）。
4. Anytls：`Conn.hpp`、`Stream.hpp`（`Shutdown()->void` → `StartWriteShutdown`；保留 `SendFin()`/`FinSent`/`Stopping` 判定）。
5. Gun：`Conn.hpp`、`GrpcStream.hpp`（含 `Shutdown()`）。
6. Quic：`DatagramAdapter.hpp`、`NativeConnection.hpp`、`StreamAdapter.hpp` 及其它内联旧调用点。
7. Mux：`Stream.hpp`、`StreamState.hpp`、`H2Mux/Http2Stream.hpp`、`SingMux/Stream.hpp`（含 `Shutdown()` 与 `Submit(Termination::Fin)` 路径）。
8. Hysteria2：`Conn.hpp`、`Dgram.hpp`。
9. Http1：`ForwardRequestTransport.hpp`、`ForwardResponseTransport.hpp`（含 `Shutdown()`）。
10. Shadowsocks2022：`Dgram.hpp`、`Conn.hpp`。
11. Common/BindingLifetime：`BoundTransmission` 的 5 处覆写。
12. 其余：Xhttp/Http3 等内部残余调用点、`Replay->CloseUnderlying()` 一类 nodiscard 消费点全量核对、`M12-M13-ExternalDerivedAudit.md` 的 6 个外部派生类（Quic::StreamAdapter、Http11::Forward{Request,Response}Transport、Xhttp::{Stream,Split}Transport、Mux::StreamTransmission）。

统一模式（已在前 8 组验证，照抄即可）：派生类实现 5 项新虚函数（`StartRead/StartWrite/StartWriteShutdown/OnClose/OnCancel`）；需要协程的读写用 `co_composed` + `weak_from_this().lock()` 保活、结果恰交付一次；含内联逻辑的类把原协程体整体保留为私有 `ReadPartial/WritePartial(std::error_code&)`，新前门一次性映射为 `IoResult`；helper 内部改 `co_await X->ReadSome/WriteSome(...)` 并用 `Fault::ToNative(Failure)` 回写本地 `error_code`；预读/透传层用「命中缓冲→`PostResult`，否则 token 直通」；`Close/Cancel` 改 `OnClose/OnCancel → ControlResult` 并补真实半关闭。

验收：§2.2 的 rg 归零（原生 Asio 例外逐条标注）；`node scripts/check_preview_style.mjs --scope Preview/Protocols` 0 parse、0 尺寸/参数违规；报告更新为最终版。无阻断，继续按同一方法推进即可。

### 6.3 M14–M18（网络数据面与 QUIC/HTTP 底座）

- **M14 通用 UDP association 双向数据面**（依赖 M11/M13/M04）：删掉 Exchange 单 reply 模型；association 提供拥有型 `Send/Receive/Cancel/Close/Drain`；IPv4/IPv6 各持一个私有资源；up/down pump 独立、目标无回复不阻塞下一上传；发送准入登记实际 IP+port 授权 endpoint，不相关/过期/旧关联来源在封回协议前拒绝并计数；单包 DNS/send deadline 与 association idle 分开；合法空 UDP 有效、多回复不误作下一请求应答；所有 packet/socket/lease/task 归同一 association，关闭不影响共享 listener 或兄弟关联。交付 `M14-Report.md`。
- **M15 Boundary 中立句柄、索引与唯一 socket 权限**（依赖 M01–M04）：`QuicConnectionOwner` 公开面只留 `Start/ReceivePacket/Snapshot/RequestClose/Drain`，删 Native Server 暴露；公共 socket 最终关闭权留 Boundary，协议只取窄 Send、Executor 与缓存 LocalEndpoint；一个 connection owner 为唯一事实，固定 CID 与 peer 索引，删每包 string key 与全表 Native 查找；factory 调用前预留 owner/CID 容量（closing 仍计数），状态只在 listener executor 更新；Dispatcher 同步借用 admission、真正消费时 move；接受/拒绝计数统一、listener 提交失败回滚 Ready 并完成 completion。
- **M16 QUIC ACK、credit、FIN/reset 与 callback**（依赖 M15、M12/M13）：实现 TransmitLedger（稳定 chunk、stream offset、Submitted/Acknowledged 保活已接受数据）；安装 ACK callback；write 按"已接受字节"返回，数据异步保活到 ACK 或 stream_close，UDP 排空不参与退休；每 stream 只选 callback 或 accept queue 一种交付，关闭后回收 State 并补远端 stream credit；FIN 采用 Queued/Submitted/WriteClosed 三态，Blocked 保留由 pump 重试；Reset 保留应用 code，不变普通 EOF；C callback 只使用预留存储与值失败；所有 loop/send/FIN/关闭任务进正式 task tree。
- **M17 HTTP/2 帧、HPACK 与流控**（依赖 M02、M13）：9 字节 header 解析后立即拒绝超限 frame；RX 用有预算 chunk/游标；raw block 64KiB / 128 字段 / 单字段 16KiB / decoded 总量 64KiB 四层预算在复制前检查；修复未知 frame 忽略、CONTINUATION 顺序、GOAWAY offset/u32；新 stream 从最新 settings 初始化；`SubmitData` 明确返回 Accepted/Blocked/Closed/Invalid 并提供可取消 `AwaitWritable`；接收 credit 由下游拥有数据的消费回执归还。
- **M18 HTTP/3 native 头与 event owner**（依赖 M16/M17/M13）：nghttp3 与独立 QPACK 共用 HeaderLimits，设置 field-section 限制；HeaderBlock 用预留字节 storage + 字段索引，`TryAppend` 返回值错误并映射 ABI 码；headers/data/event/response 全部有预算，NativeClient/Server 不得无限累计；nghttp3 状态/callback/input/output/native 适配归 Detail；client/server 所有 driver tracked，完成通知与 Drain 明确。

### 6.4 M19–M28 协议卡（要点）

- **M19 TrustTunnel**（依赖 M17/M13/M08）：CarrierOwner 拥有 H2Session/driver/writer/TLS，返回 transport view、owner 仅弱观察避免引用环；删"成功 move 空字段后 driver 仍使用"的路径；两层 writer 改统一完整 write owner，失败完成 active 与全部 pending；FIN/driver/wire/最终 Close 全 tracked；Basic 认证、CONNECT、凭据语法归协议 Detail，lease 一次移交。
- **M20 普通 VLESS 唯一 wire 与 XUDP**（依赖 M14/M13/M08）：普通 UDP 固定握手 Target，客户端/服务端统一 `[uint16BE Length][Payload]`；删 StandardWire 选择、载荷地址解析、回复插地址；reader 区分 EOF/取消/timeout/截断/坏 frame，不 break 后返回 Success；XUDP 独立归 Detail/Xudp（每 id lease、socket epoch、迟到结果身份校验）；root/child/writer 停止与 drain 用值结果，id 复用前完成旧资源退休。
- **M21 WebSocket 唯一 frame writer**（依赖 M13）：DATA/PONG/CLOSE 全部排入同一 frame writer，reader 不得直接写底层 socket；mask/header/payload 在取得预算后编码，stream write 允许明确 partial count；保留消息、分片、UTF8 规则，随机失败与 I/O 失败返回 typed 结果；Close frame 与最终 carrier 关闭分开，reader/writer 真实 drain 后释放 owner。
- **M22 SS2022 raw UDP 入口预约与 peer 资源**（依赖 M14/M15/M08）：packet 在 post/Operation/task 创建前同时取得 binding/peer/bytes/task 预算；peer lease 与 packet operation 分开，posted/running/pending send/reply 均计费；replay/nonce/credential/session 替换仍归 SS2022；closing peer 保留到 drain；Reap 改有界 expiry 索引/定时 owner；TCP 与 raw UDP 只消费统一 Target/OwnedBytes。
- **M23 XHTTP 各模式资源与逻辑会话**（依赖 M17/M13）：Mode 冷冻结为 enum，分别拥有 StreamOne/StreamUp/PacketUp 状态；PendingUpload、PacketBodies 先检查字节及数量预算再取得存储；body 完成/断开/拒绝/sequence/迟到 callback 归同一 mode owner；wire/logical writer 使用统一 ticket；路径解析/生成只有一处；TLS 委托统一 Encrypted 能力。
- **M24 Gun/gRPC 消息、背压与 driver**（依赖 M17/M13）：声明 message 长度后预留完整 message 容量再收 body（保留 16MiB 能力）；消费 credit 与消息容量关联，避免完整 message 交付与小窗口互等；queue/ClientResult/handler 输出累计预算；grpc-status 检查完整数字、范围与重复一致性；读写、response driver 全部 tracked，退出必通知，最终 drain 归 session。
- **M25 AnyTLS 根、stream 与首 PSH**（依赖 M13/M08/M26）：首 PSH 消费中立目标原语（保留同 frame 尾部），不借 SingMux 私有 parser；Frame 错误、非法 command、EOF、取消、timeout 明确写入根结果；SYN/PSH/FIN/ALERT/heartbeat 进同一 frame writer；Stop 用原 executor 退休能力，nested mux、child、FIN、writer 全部 drain；lease、Prepared/Ingress 与根状态保持一套事实。
- **M26 Mux 可回收 RX、writer 与 task tree**（依赖 M04/M08/M11–M13）：RX 迁为可回收 OwnedBytes，按实际 retained 块计费、消费后可归还；完整 writer 使用有界请求槽，partial 完成后回执、失败完成全部 ticket；WINDOW_UPDATE 进入同一合并 writer 队列；root/stream/FIN 每次 Enter 立即持预约，取消/错误/drain 保留值原因；child/writer/FIN 结束后才释放根 lease；StreamHandle 直接消费正式 Transmission，退役 SessionBase 及旧桥。
- **M27 Mux 唯一 wire 与控制事件**（依赖 M26/M17）：frame 事件同时表达 payload 与 terminal/control flags，DATA+FIN 先交付数据再发布 EOF；Yamux Ping、GoAway、WindowUpdate 正式状态处理；H2Mux 选择标准 HTTP/2 双端实现并删私有 9 字节伪 wire 入口；SingMux 纯 codec 与异步 reader 同一解析事实；Padding 有界或冷绑定拒绝。
- **M28 剩余 TLS、HTTP/1 与 ECH 闭环**（依赖 M05/M10/M13）：各 carrier 握手 I/O 复用统一能力，wire/auth/record/control 保留协议 owner；Reality Carrier/Prepared 共用唯一认证、server flight 与 Finished 路径；ECH key/scan 职责明确、资源真正拥有；Http1 request/response/header/trailer/chunk/Upgrade 与半关闭迁入完整 Detail owner、复用中立 framing；Common 只保留真实共享语义。

### 6.5 M29–M36

- **M29 唯一冷装配与一次性 prepared 识别**：分开 TCP proxy/TLS carrier/QUIC/Mux/ECH typed slots；wire 解析、材料解释、credential trial 归协议 Detail；ProviderCatalog 覆盖全部正式类别，删 Application 协议 switch 与重复 RegisterConfigured；内外层识别共用中立协调 owner 与 owned PreparedAdmission，winner Commit 只消费一次；Commit 后污染不得回退其他协议；listener 只接一个新连接 QUIC factory，构造即拒绝重复。
- **M30 Runtime 窄权限、准入与稳定快照**：宽 Context 拆为不可变已认证输入、dial 结果、decoration 操作、relay 拥有值；删每 session 动态单项 Pad/Dial Pipeline；listener 取得额度立即持 reservation（覆盖 peer/transport/request 构造与任务提交）；Worker admission 与控制命令分开（停止接入不阻止取消/关闭/drain 命令交付）；Registry 由真实 owner 维护、控制侧发布稳定值快照；Ban/Throttle 明确 owner、有界键、过期摘除。
- **M31 Application 启动、回滚与停机**：StartupTransaction 唯一回滚者（generation/process/protocol/boundary/operations/publish 分阶段）；typed Shutdown/Blocked 贯穿 listener/provider/task/application，删忽略返回值与"普通失败再 throw"；deadline 到期返回失败时继续保活仍在清理的 owner；worker join 只在控制线程非协程阶段；检查 ClosingStorage 后才标记资源完成；日志失败独立记账。
- **M32 管理查询、scoped 命令与 Operation owner**：Generation/Stream/Task 查询用完整父身份；Revoke 先封准入，CloseSessions=true 提交账户范围取消、真实结束后才 Completed；ProcessDrain 与 WorkerDrain 分开（Drain 必停止目标新接入，删可忽略的 StopAccepting）；Session/Stream/Task 取消只定位目标 owner，作用域不匹配明确 Rejected；Accepted 创建有界 OperationId，终态含完成/失败/timeout/blocked；管理监听独立 context/controller。
- **M33 有界配置与两阶段 Reload**：配置最多 1MiB、读取前后检查、集合数量与乘法溢出在冷校验拒绝；Reload 采用 prepare token → worker ack → 单一 commit/rollback，失败不部分修改；旧 session 保留原 generation pin，新接入切换到新冻结绑定；worker 数量、监听地址/端口、运行时池容量、QUIC engine 种类变化返回 RestartRequired；最多保留 8 个活动/退休 generation；ValidateOnly 不发布，Apply 携带 BaseGeneration。
- **M34 管理 HTTP、命令令牌与静态资源 owner**：HttpServer 与 Connection 分别拥有接入/socket/deadline/请求/drain；连接/头/体/响应分预算，响应写独立 deadline；保留 loopback、校验 Host/Origin、不开跨源 CORS；每次启动生成命令令牌，POST 必带、令牌不进 URL/日志；静态资源冷启动按 manifest 加载为只读 catalog、拒绝任意文件系统路径；/Operations 错误不回退 SPA；启动成功才发布 Web/API 能力。
- **M35 全协议 Detail、命名与公共入口闭合**：逐模块确认 public facade、Options/Result、Binding/Ingress 与私有实现（目录表见主计划 §3）；每个迁移同步生产、工具/测试引用与 CMake，删旧路径不留 forward include；标识符 PascalCase、中文 Doxygen、长 namespace 在所属作用域收窄；第三方 ABI/Asio 官方接口/wire 字段精确例外；清除热路径 throw/catch 与三目。
- **M36 CMake、源码门禁与无兼容层收尾**：include 与 target 依赖同步（Foundation/Net/Boundary/Runtime 不依赖具体上层装配）；磁盘文件与 target_sources 双向核对（大小写、生产 CPP、scope include、文本拼装）；按 101 项账逐项给出实现/复查/保留理由；删除旧 aliases/overload/结果/fallback 与重复入口；更新文档与 hash；不得用"文件小于 600 行"代替设计判断。

### 6.6 M37–M42 React 后台

以主计划 §4 为唯一事实。关键钉死项：

- 位置：工作树内新建 `Web/`（生产集成时映射回 `I:/code/Prism/Web`）。
- 版本（精确版本 + 锁文件，禁止 latest）：React/React DOM/types 19.3.0；Vite 8.3.4；@vitejs/plugin-react 6.1.2；TypeScript 7.0.2；React Router DOM 7.18.4；TanStack Query 5.104.1；Tailwind CSS 与 Vite 插件 4.3.3；Lucide React 1.54.0。
- 结构：App / Api / Features / Components/Ui / Styles；业务状态留各 Feature；QueryClient 只负责服务端状态；不建携带全部页面业务的万能 Context。
- API：单一 `/Operations` 入口；64 位 ID 与计数一律十进制字符串（前端 string/BigInt）；时间 Unix 毫秒；命令不自动重试、Accepted 后只轮询同一 OperationId；查询带 AbortSignal、页面退出停止订阅；后台页面不可见暂停轮询；错误用 typed code；敏感材料不进公开配置/事件正文/页面缓存。
- 页面任务：M38 概览/Worker/账户页；M39 Session/Stream/Task 页；M40 事件/配置/操作中心；M41 视觉与可访问性；M42 同源资源、打包规则与维护交付。细节与接口表见主计划 §4。
- 前端源码同样禁三目（TS/TSX）；React 与第三方规定的接口/宏拼写精确保留。

## §7 执行顺序与并行（Wave 计划）

- **W1（立刻）**：§6.2 协议迁移收尾 + §6.1 M08 账户测试迁移收尾。两者写域不重叠可并行；同一文件只允许一个写者。
- **W2**：测试 Wave 2（`tests/Preview/Transport` 与各协议测试的旧 API 迁移）与 M11 公开形状迁移合并规划、一次完成；主会话同时做 M10 剩余与 M07 剩余。
- **W3**：M14 → M15 → M16 → M17 → M18（严格按依赖）。
- **W4**：M19–M28，一卡一写域；按依赖排（TrustTunnel、VLESS、Ws、SS2022、XHTTP、Gun、AnyTLS、Mux、Mux-wire、其余 TLS/HTTP1/ECH）。
- **W5**：M29 → M30 → M31 →（M32 → M33 → M34）→ M35 → M36。
- **W6**：M37–M42。
- M03/M04 残余在 M14/M26 提供 CarrierActivity 生产者后随时收口，不要搁置到 W5 之后。
- 主会话保留：共享 Contract、根 CMake、scripts、docs、跨模块调用者、最终集成与验收。
- 子代理规则：派单必须写明写域、依赖、验收命令与交付文件；完成后由主会话复核（报告 + rg + 门禁 + 抽查 diff）才算验收；子代理不得改共享文件。

## §8 工程规范（完整）

### 8.1 代码风格

- 标识符、目录、文件名 PascalCase（命名空间 `Preview::`）；宏 UPPER_CASE；尾随返回类型 `auto f() -> T`；有意义的返回值加 `[[nodiscard]]`；`#pragma once`；LF 行尾。
- 注释：Doxygen 风格中文（`@file/@brief/@details/@param/@return/@note`）；禁止英文注释（第三方 ABI 例外精确到接口）。
- **禁止三目运算符**（C++ 与 TS/TSX 同样适用）。
- 生产 header ≤ 600 行；测试 cpp ≤ 800 行；函数 ≤ 120 行；lambda ≤ 10 行；参数默认 ≤ 2、复杂边界 ≤ 3（先拆职责，或引入有领域语义与生命周期的 request/options/result，不用万能 struct 藏参数）。
- Production header-only：`Preview/` 下不新增生产 `.cpp`；唯一例外是 `Application/Main/PreviewMain.hpp` 作为 CMake CXX source 编译。

### 8.2 接口与所有权

- 每个公共接口写明：输入所有权/借用期限、输出与错误、取消、半关闭、最终关闭者、executor。
- 每份 buffer、队列节点、task slot、lease、容量额度都有明确 owner 与释放条件。
- 完成合同：buffer 借用至 completion 返回；completion 恰一次；普通完成不得同步重入发起者；关联 executor/allocator/cancellation slot 穿透所有 wrapper 与 Connector 层。

### 8.3 错误与异常

- 热路径（请求处理、协议循环、I/O 完成、关闭路径）不 throw、不 catch；普通错误、取消、超时、额度不足一律返回值结果。
- 启动/致命/配置错误可用项目异常分类（冷路径）；第三方不可恢复异常只在线程/进程入口收口，不修改第三方运行时。
- `Fault::Failure{Code, Native}` 保留领域错误与原生 category/value；`IoResult{Bytes, Failure}` 允许"已完成字节 + EOF/错误"同时存在；取消不得折叠成通用 IoError。
- 动态错误文本只在日志/API 输出边界格式化，热路径不生成。

### 8.4 资源与预算

- 预算唯一事实 = 主计划 §2.2；容量不足返回 `ResourceUnavailable` 或等待额度；关闭与额度归还不得依赖新的数据 buffer 分配。
- 资源取得用 `TryAcquire` 风格并返回明确失败；归还无分配；跨异步边界必须拥有实际存储与 allocator/context pin。
- 不为每个空闲连接预分配其最大预算；chunk 从进程/worker 拥有的有界池取得，共享总容量优先于局部上限。

### 8.5 模块职责与依赖方向

- 所有权表（同 `AGENTS.md`）：`Protocols/<Name>` 只拥协议 wire/认证/状态机；`Composition` 编译期装配与冻结；`Boundary` socket/CID/入口 drain；`Runtime` worker/listener/调度/通用数据面生命周期；`Application` 读取配置、进程级服务与启停。
- 依赖方向必须能被 include 与 CMake target 双重验证：`Protocols` 不依赖 `Composition/Application`；`Runtime/Boundary` 不引具体协议装配；共享纯契约下沉中立模块；禁止作用域 include 或文本拼装伪造边界。

### 8.6 无兼容层

- 迁移时同步改完实际调用者、测试与 CMake 后，删除旧 API、别名、旧结果形状、fallback、forward include；不留 `Legacy`/`Compat`、旧 overload、双向同步字段、第二正式入口。

### 8.7 测试规范

- 默认不新增测试、不重组测试目录（除非用户授权）；现有测试只做 API/路径同步，保持输入、断言、循环、超时、GoogleTest 宏序列完全不变。
- `tests/Preview/` 内项目自有标识符 PascalCase；`TEST/TEST_F` 放 `.cpp`；异步用 `co_spawn + io_context.run()` 模式；每 cpp ≤ 800 行；共享测试 HPP 只放职责明确的封装。
- Windows 纯大小写改名用两步法（`git mv a tmp && git mv tmp A`），并以 Linux/大小写敏感环境复核。

### 8.8 CMake 与门禁

- 新增/移动任何头文件必须同步 `Preview/CMakeLists.txt` 的 target_sources（磁盘 ↔ 登记双向核对）；缺失登记由主会话统一执行。
- 每卡收尾跑 `node scripts/check_preview_style.mjs --scope <目录> --report <证据路径>`；要求 0 parse、0 尺寸/参数违规；该结果只是语法树级证据，不能当编译证据。
- `parseRecoveries`/`bracedDefaultRecoveries` 是解析器已知恢复，不是错误；`foreignAbiContracts` 是已登记的第三方 ABI 例外。

### 8.9 工具与平台

- Shell 为 PowerShell；检索用 `rg`；若仓库根有 `.codegraph/` 可用 `codegraph explore`；禁止 Python。
- 编辑用 apply_patch 或全字符串字面量替换；改后必须 `rg` 复核。绝不用数组/字符串索引拼接替换（§12.1）。
- **集成模式（仅用户授权后）**：向 `I:/code/Prism` 回写前逐文件对账用户在该目录的增量（基线 → 工作树 → 当前 I: 三方比较），冲突交用户裁决；不得整目录覆盖。
- 行尾 LF（`.gitattributes` 已强制）；Windows 上确保 `core.autocrlf=input` 或 `core.eol=lf`。

## §9 交付格式与状态机

状态机：`Pending → InProgress → SourceReview → SourceComplete`（SourceComplete 仅源码闭环）。

每卡交付物（统一放 `.superpowers/sdd/2026-10-09-preview-quality-modification-plan/`）：

1. `<卡号>-Report.md`：变更文件清单；每文件旧→新映射；调用链（谁消费新接口）；旧接口退役清单 + rg 归零证据；问题编号映射（R/F/P，查 `IssueMapping.json`）；门禁结果；**未执行验收项声明**（编译/测试/互操作/性能）。
2. `<卡号>-Style.json`：门禁报告（0 parse、0 违规）。
3. `<卡号>-Hashes.json`：本卡交付文件 sha256（防静默漂移）。
4. 台账追加到 `progress.md`（一行摘要 + 证据指针）。

报告禁止：把静态门禁当编译通过；把"文件数减少"当完成；空实现、固定成功、提前清零、缩小输入、忽略错误。

## §10 验收分层（独立报告，不得互相替代）

1. 静态/源码/风格（本阶段主战场）→ 2. configure → 3. 编译/链接（含独立多 TU 与 Linux 大小写/ODR）→ 4. focused tests → 5. 全量 CTest → 6. 真实 Main/监听请求 → 7. 互操作 → 8. 性能（同输入比较分配/吞吐/延迟）→ 9. 文档与清理。

授权后的构建命令（只准用现有 `build/`）：

```powershell
# 白天（08:00-22:00）
cmake --build build --config Release --target PrismPreview -j 16
# 夜间（22:00-08:00）
cmake --build build --config Release --target PrismPreview -j 1
# 测试（按需筛选，非全量时显式注明筛选名）
ctest --test-dir build --output-on-failure -j 1 --timeout 30
```

未来必须建立的验收场景（主计划 §5）：配置/编译/链接/独立多 TU/Linux 大小写；错误、取消、partial I/O、额度耗尽、调度失败；QUIC ACK/丢包重传/FIN/credit 与 HTTP 窗口/header 预算；UDP 空包/多回复/来源隔离/地址族；账户跨协议撤销、child 准入、scoped 管理操作与 Reload 回滚；真实 Main 请求与 drain；分配/保留内存/吞吐/延迟同输入比较；React 真实 API/响应式/键盘/断线/操作终态；全量 CTest 与会话进程/临时产物清理。

注意：新的 `BOOST_ASIO_HAS_PTHREADS` ABI 纪元会让旧受影响二进制/运行时/性能证据全部失效，重建后再引用。

## §11 React 补充执行细则

见 §6.6 与主计划 §4；补充：

- 开发态 Vite 只能 loopback 运行，API 代理到本机 Operations；生产页面与 API 同源；命令令牌由 Bootstrap 下发、只存内存。
- 组件库统一（Button/Input/Select/Dialog/Tabs/Badge/Table/Skeleton/Tooltip/Sheet），不为每页复制样式；深浅色主题用 tokens；键盘焦点、错误说明、状态颜色、减少动画必须显式实现。
- 验收分层：源码 → 类型检查/构建（需授权）→ 真实 API → 响应式/键盘/断线 → 操作终态；未执行的浏览器检查不得写成"通过"。

## §12 已知坑（血泪清单）

1. **PowerShell 数组展平（最高危）**：`@( @('a','b') )` 单元素嵌套会被展平；`foreach` 后 `$pair[0]` 变成字符串首字符。本项目曾因此把整个文件写成全局 `r→e`。规避：只用 apply_patch，或 `$text.Replace('完整旧串','完整新串')`；替换后必须计数复核。
2. Boost 1.89 `co_composed` 对 error_code 签名会 `throw_error`；普通取消/错误必须显式 `as_tuple(...)` 或 `redirect_error(...)` 后处理。
3. `any_completion_handler` 的 allocator 代理在 handler 消费后悬空；延迟清理必须使用自有 allocator（Transport 已有 CleanupMemory 模式，照抄）。
4. Windows 大小写：MinGW include 大小写不敏感，纯大小写改名必须两步 `git mv` 并以 Linux 复核；`core.ignorecase=true` 下几乎必踩。
5. `parseRecoveries`/`bracedDefaultRecoveries` 是解析限制噪声；不要"修复"它们，也不要因此改代码结构。
6. 不要删除 `build/tests` 产物（正常产物可能很大）；只清理自己启动的进程（`taskkill //F //PID <pid>`）。
7. `.superpowers/sdd/2026-10-09-preview-quality-modification-plan/` 是证据库，禁止当临时目录清理或覆盖。
8. `docs/preview-refactor/2026-10-10-preview-quality-implementation.md` 是早期快照、已过期；进度以 `progress.md` 为准。
9. 账户测试中 `TEST(PreviewAccountDirectory, ...)` 等套件名是**故意保留**的，不是旧 API 残留，不要改名。
10. `tests/infrastructure/**` 是旧版 `psm::user` 测试，不在 Preview 范围，不要迁移。

## §13 汇报格式

- 用户中文提问用中文回复；先给结论（完成/未完成 + 数字），再给证据指针（报告/门禁/哈希路径），再给未闭合与阻碍。
- 每轮/每卡末尾更新 `progress.md`：轮次、卡号、状态变化、证据文件、未执行项。
- 绝不虚报：没有执行的验证不写"通过"；没有检查的目录不写"已核"。遇到无法安全推进的阻碍：停下并明确报告"谁阻塞了哪一步、需要什么授权/输入"，不要强行绕过。
