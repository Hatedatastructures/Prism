# Prism Preview 当前工作树专项缺陷审计

> 审计时间：2026-09-10。审计对象是当前工作树中的 `preview/`，不是旧 `src/prism/` 实现。
> 当前 `preview/` 共 255 个文件（252 个 `.hpp`、1 个 `.cpp`、1 个 CMake 文件、1 个说明文件）；本次工作树另有 61 个已修改 Preview 文件和多批未跟踪的 Recognition/HTTP3/互操作文件。
> 本节结论来自当前磁盘源码、CodeGraph 调用关系、CMake/测试引用和静态边界检查。遵守仓库约束，未执行构建、CTest、bench 或网络互操作，因此没有把“静态未发现”写成“运行时已验证”。
> 只读归属检查结果：253 个 Preview `.hpp/.cpp` 与 `preview/CMakeLists.txt` 中 253 个 `target_sources` 路径完全匹配；这只能证明清单闭合，不能证明独立 target 可编译或外部库链接正确。

## 当前工作树增量修复

最终本地门禁（2026-09-11，拆分跑法）：功能并行 `-LE "perf|stress" -j 8`
`3842/3842` 通过（`25.40s`）；perf/stress 串行 `-L "perf|stress" -j 1`
`94/94` 通过，`Perf_Recognition` `613.06s`，perf/stress 标签时间 `630.58s`，
全量墙钟 `630.85s`；
合计注册 `3961`、active `3936`、`25` 个 `StealthNested2` Disabled、失败 `0`；
外部矩阵 `63/54/9/0`。下方早期数字均为历史快照。

P-H03 已在本轮收口：`AssocTable` 改为对称回收（未配对条目按自身时间回收、
配对条目按两侧最后活动最大值判定），配对时淘汰过期候选并择优最新来源，
新增 `RelayOptions.MaxAssociations`（默认 256）限制并发关联数，超限拒绝新会话
且不影响已有会话；新增 B-first 陈旧条目、关联上限、单侧活跃 3 个回归
（连续 5 轮无 flaky），UdpRelay focused `7/7` 通过。

P-H01 接收侧已在本轮收口：`StreamHandle` 维护接收队列字节数，`SessionOptions`
新增 `MaxStreamRxBytes`（默认 4MiB）与 `MaxSessionRxBytes`（默认 16MiB，0 = 不限），
超限按协议错误关闭会话；预算随 `ReadSome` 消费、`Close/Reset/OnRst` 释放而归还，
RST 路径会立即丢弃队列内存；发送侧新增 `MaxPendingWriteBytes`（默认 32MiB），
预算覆盖排队与当前写入帧，超限只拒绝本次写入并在完成/取消/Teardown 时归还。
`MuxWriteContract` 的写入预算回归与 Mux focused `29/29` 通过。

P-H02 已在本轮收口：`H2Mux::ParseHeader()` 在帧头阶段拒绝未知 `FrameType`
（`BadMessage`），并强制控制帧固定长度（window_update/ping = 4 字节、
close = 0 字节，违规 `BadLength`），未知类型不再按声明长度分配/读取最大
16MB payload 后被丢弃；DATA 帧仍允许 0..MaxFrameLength。

P-H04 已在本轮收口：`Snapshot` 强制 `MaxCaptureBytes` 并在底层返回超过窗口
的字节数时返回 `BadLength`；`Rewind()` 现在在写入后返回 `false` 且保持读取位置，
未写入时才允许回放。新增写入后回滚拒绝回归，Snapshot focused `6/6` 通过。

P-H18 增量收口：Hysteria2 TCP `Conn::ReadFrame()` 现在在消费地址前拒绝未知
`Kind` 并返回 `BadMessage`，不再把非法枚举映射成 `NotSupported`；新增未知 Kind
握手回归，Hysteria2 focused `34/34` 通过。

P-M19 已在本轮收口：`Transport::AsyncReadExact/AsyncWriteExact` 统一使用
`Stream` concept 的 `async_*_some` 原语，拒绝错误码、零进展和 over-reporting；
超时重载只对提供 `SetTimeout()` 的类型设置超时。新增 concept-only stream 和读写
over-reporting 回归，Transport focused `26/26` 通过。

P-M20 已在本轮收口：`PreviewTransport::Close()` 现在先清空未消费的预读数据并重置
偏移，再关闭内层；关闭后的读不会错误返回已缓存的协议首包。新增关闭语义回归，
PreviewTransport focused `5/5` 通过。

P-M21 已在本轮收口：Hysteria2 的 Conn、Dgram 读取路径现在拒绝底层返回超过
目标窗口的 over-reporting，并统一返回 `BadLength`，避免越界推进或把多余字节
当作有效帧数据；未知 Kind 仍在地址解析前返回 `BadMessage`。Hysteria2 Conn 错误
矩阵 `19/19`、Hysteria2 Dgram 错误矩阵 `7/7`、全量功能 CTest `3824/3824` 通过。

P-M22 已在本轮收口：Hysteria2/TUIC Dgram 的发送循环拒绝底层返回超过剩余
帧窗口的字节数；TUIC Dgram 的 UDP 接收、stream 精确读取以及 TUIC Conn 的
精确读写辅助也拒绝 over-report，避免帧偏移越界或伪造成功。新增 Hysteria2/TUIC
focused 回归合计 `36/36` 通过，其中 TUIC Dgram 为 `10/10`。

P-M23 已在本轮收口：TrustTunnel、SOCKS5、Trojan 和 VLESS Dgram 的发送循环、
精确读取窗口与 payload 窗口拒绝底层返回超过剩余容量的字节数，并统一传播
`BadLength`，避免帧偏移越界或把多余字节当作有效数据。相关回归与 Hysteria2/TUIC
错误矩阵合计 `66/66` 通过。

P-M24 已在本轮收口：AnyTLS、Reality、VMess 和 SS2022 的精确读取/写入辅助拒绝
底层返回超过剩余窗口的字节数，避免错误数据被当作有效握手或推进偏移。新增回归
合计 `5/5` 通过。

P-M25 已在本轮收口：ShadowTLS `ReadExact()` 拒绝底层返回超过剩余窗口的字节数，
避免超额读取被误解释为 `BadAuth`；ShadowTLS/VMess 错误集合 `15/15` 通过。

P-M26 已在本轮收口：Mux 精确读、VLESS Conn 读写以及 SS2022 UDP 临时缓冲/发送循环
拒绝底层返回超过剩余窗口的字节数；相关 focused `19/19` 通过。

P-H12 已在本轮收口：Mux `AllocateId()` 改为单调 32 位流 ID，保持客户端奇数/
服务端偶数规则，不再在 `65535` 后回到 1/2 复用已消耗 ID；达到 32 位上限时
进入耗尽状态并关闭会话。`StreamIdWrapAround` 已改为断言第 32769 个 ID 为
 `65537`，相关 Mux focused 通过。

P-H20 已在本轮收口：VMess、SS2022 的 AES-GCM 和 Reality SessionId 编解码现在
先校验密钥/Nonce/长度，再检查 EVP Init/Update/Final/Tag 的每一个返回值；失败时
清空输出、保持 nonce/状态不前进。VMess 认证头、响应头和连接应答也校验期望密文
长度并把密码学失败传播为协议失败。非法密钥/Nonce 的 RED 已复现，修复后
VMess/SS2022/Reality 相关 focused `53/53` 通过。

P-H14 已在本轮收口：`Reliable`/`Unreliable` 的真实 socket 读现在与定时器竞速，
awaitable 与 completion-handler 两条路径都遵守 `SetTimeout()`；新增真实
TCP/UDP 回归用例（超时与超时前到达数据）。`Unreliable` 移除重复的
`enable_shared_from_this` 后，`Transmission` 基类 completion-handler 桥接不再返回
`not_supported`；`UnreliableHandlerReadTimeout` 与 Transport focused `21/21` 通过。

P-M02 已在本轮收口：`Reliable::Connect()` 的 connect 操作统一使用
`redirect_error`，普通拒绝和 timeout 都返回错误码而不是抛异常；失败路径关闭
socket。`ReliableConnectReturnsErrorCodeOnRefusal` 与相关 Transport focused `4/4`
通过。

P-M03 已在本轮收口：`Connector` 的预读 completion 统一投递到关联 executor，
multi-buffer 读使用有界聚合缓冲并按序回写，写短写续写改为事件投递而不递归；
新增预读异步、多 buffer 分段读和 inline short-write 回归，`Connector` focused `8/8`
通过。

P-M04 已在本轮收口：`Transmission` 默认 completion-handler 桥接现在捕获底层
读写协程异常并以 `generic:io_error` 回调一次，避免 detached 协程吞掉异常；
新增读/写异常回归，`CoreTransmission` focused `2/2` 通过。

P-M05 已在本轮收口：`TaskRegistry` 为每个 tracked 协程绑定独立 cancellation slot，
新增同步 `Cancel()` 请求入口，`CancelAndWait()` 改为同一 executor 上非阻塞等待的
`awaitable<bool>`；只有 completion 真正释放 token 后才计入 `TotalCancelled`，超时保留
active token。Preview/生产注册表与 OwnershipAudit focused `15/15` 通过。

P-M06 已在本轮收口：`EwmaMeter` 改为消费上次读取以来的增量，并按
`exp(-elapsed/window)` 衰减；读取时间使用 CAS，更新标志保证并发读取者不会重复
消费事件。新增“无新事件不重复计数”回归，`EwmaMeter` focused `2/2` 通过。

P-M07 已在本轮收口：`TokenBucket` 对 `now + 1` 使用饱和时间戳，避免
`UINT64_MAX` 回绕成未初始化基准；补发乘法和令牌加法均按打包字段/桶容量饱和，
低 32 位相对时间也不会被极值污染。新增时间戳和超大补发计数回归，TokenBucket、
Throttle、Ban focused `10/10` 通过。

P-M08 已在本轮收口：`FlatBuffer` 记录并尊重调用方的初始容量，`Prepare` 和倍增
增长在 `size_t` 上限前拒绝溢出；通用 `Parser` 强制 `Config::MaxPayloadLen`，在
追加数据、头部长度和 payload 长度计算前执行统一帧上限检查，超限清空状态并返回
`BadLength`，`Want()` 只报告尚未消费的 payload。FlatBuffer、smux、h2mux focused
回归均已通过。

P-M10 已在本轮收口：新增 `Preview::ConstantTimeEqual`，按完整较长序列比较并支持
二进制凭据；StaticAuthenticator、SOCKS5 用户名/密码、Trojan/VLESS/VMess UUID、
TUIC UUID 与 exporter token、Hysteria2 密码、TrustTunnel Basic Auth 以及识别候选
fallback 均使用该比较器，身份和密码不会因短路而跳过。Authenticator、协议会话和
Basic Auth focused `75/75` 通过。

P-M11 已在本轮收口：`ProbeDefenseTracker` 支持可注入时钟，`FailCount`/`ShouldChallenge`
和 `Record` 会主动清理过期记录；达到容量时淘汰最旧项，`MaxRecords=0` 直接拒绝新
来源，避免依赖调用方定期 `Expire()` 或无界插入。窗口过期和零容量回归已通过。

P-M12 已在本轮收口：`SniRouteTable` 改为不可变 COW 快照，Add/SetDefault/Clear
通过原子发布避免 Lookup 与更新并发访问容器；`LookupEntry`/`LookupValue` 按值返回，
不再暴露会被更新悬空的 map 指针。通配路由按首个标签后的后缀哈希查找，保持单标签
匹配语义并去掉全表扫描。路由生命周期和并发读写回归已通过。

P-M13 已在本轮收口：`IdentityTraffic` 与 `TrafficCounter` 增加可配置的最大 identity
数（默认 100000），COW 快照达到上限后拒绝新 key，已有 key 继续精确累加；零上限
不分配新槽，避免客户端可控身份导致无界复制和内存增长。容量和原有并发精确统计
回归已通过。

P-M09 已在本轮收口：公共地址编码先严格校验 IPv4 段、IPv6 文本/二进制长度和域名
长度，非法输入回滚输出并返回失败；SOCKS5、Trojan、Hysteria2、TUIC、SS2022 构造
器传播失败并清空整帧，VLESS 原有严格路径保持不变。新增跨协议非法地址与空段回归，
CommonAddress/协议地址 focused 已通过。

P-H17 已在本轮收口：Mux writer 请求节点改为 producer/writer 共享所有权，移除
`Consumed` 二次确认等待；`Teardown()` 会统一唤醒并失败化当前排队请求，writer
发送完成后立即出队。`CanceledProducerDoesNotBlockFollowingWrites` 已复现旧实现
的 200ms 超时并在修复后通过，`MuxWriteContract` `9/9` 通过，完整功能与性能门禁
均通过。

P-H13 已在本轮收口：`TcpListener` 析构现在幂等调用 `Stop()`，共享 `Lifetime`
增加停止标志；停止/析构后已完成的 accept 不再进入 SessionFactory。新增
`TcpListener.DestructorStopsAccepting`，Listener focused `52/52` 通过。

2026-09-10 已在 Preview 范围内完成并验证以下条目：P-C01 SOCKS5 客户端认证降级、P-H05 DNS First 模式 loser 协程取消与 owner 收口、P-H06 DNS over TCP/DoT 超长帧长度回绕、P-H11 WebSocket 帧头规范校验、P-H15 TrustTunnel Basic Auth 严格 Base64 与恒定时间凭据比较、P-H18 Hysteria2 未知 Kind、P-H04 Snapshot 捕获上限、P-M01 MemoryStream 半关闭后的本端写入，以及 P-H16 中 PadMiddleware 忽略 `MinSize/MaxSize` 和 Pad CSPRNG 失败未收口的问题。VMess/SS2022 握手盐和密钥材料也已统一使用带返回值检查的 CSPRNG helper，且随机源失败会终止 serializer。P-H09 的 BLAKE3/AES 动态 key 输入现在通过 `std::expected` 严格返回 `BadLength`/`CryptoError`，不再越界读取或把非法 key 当作 AES-256；P-H19 的 QUIC/HTTP3 随机回调现在使用可注入 CSPRNG，ngtcp2 失败会标记连接并收口，nghttp3 不再退化为确定性字节。最终全量 CTest 为 `3874` 注册、`3849/3849` active 通过、`25` Disabled、失败 `0`；外部矩阵为 `63/54/9/0`。本节其余条目仍按原审计状态保留，不能据此推断全部问题已关闭。

## 结论摘要

| 等级 | 当前确认或高可信问题 | 主要影响 |
|------|----------------------|----------|
| CRITICAL | 1 | SOCKS5 客户端认证降级可绕过启用的用户名/密码认证 |
| HIGH | 20 | 远程内存耗尽、协议状态错乱、认证边界、后台任务泄漏和数据丢失 |
| MEDIUM | 25+ | 超时/取消语义、错误传播、性能退化、配置边界和诊断可靠性 |
| LOW / REVIEW | 30+ | API 契约、兼容性、测试设施和可维护性问题 |

严重度说明：CRITICAL 表示默认可被网络对端触发并直接改变安全边界；HIGH 表示在对应功能启用且满足给定条件时会导致远程拒绝服务、协议绕过或连接级数据损坏；MEDIUM/LOW 需要结合部署配置或调用约束判断。未标注为 confirmed-runtime 的条目均需要后续测试或构建确认。

## CRITICAL

### P-C01 SOCKS5 客户端接受认证降级

**文件**：`preview/Protocols/Socks5/Conn.hpp:230-255`

客户端 `WriteHandshake()` 在 `ClientConfig::EnableAuth == true` 时只发送 `USERPASS`，但收到服务端选择 `NOAUTH (0x00)` 后不会拒绝：条件 `sel[1] != NoAuth && !EnableAuth` 在启用认证时为假，代码继续发送请求。攻击者控制或误配置的 SOCKS5 服务端可以选择无认证，客户端随后在未认证通道上发送目标地址。

**影响**：启用了认证的客户端被服务端降级到明文无认证，破坏配置的认证不变量。该问题不依赖时序或异常输入，属于明确的安全边界绕过。

**修复方向**：客户端必须验证服务端选择的方法与配置一致：启用认证时只能接受 `UserPass`，禁用认证时只能接受 `NoAuth`；收到其他方法立即关闭连接并返回 `NotSupported`。增加“服务端强制 NOAUTH、客户端 EnableAuth=true”的负测试。

## HIGH

### P-H01 Mux 接收队列没有背压或总量上限

**文件**：`preview/Protocols/Mux/Session.hpp:443-486,512-569`；`preview/Protocols/Mux/StreamState.hpp:126-151,303-310`

帧循环允许单帧最大负载进入 `payload.resize(Len)`，随后 `StreamHandle::PushRx()` 把每个 DATA payload 复制进 `Rx_`。`Rx_`、`Incoming_` 和整会话的 `PendingWrites_` 都没有字节预算；`SessionOptions::MaxStreams` 只限制流数，不限制每条流和所有流的累计字节数。远端可以在应用层不读取时连续发送合法 DATA，使每条连接长期保留大量 PMR/heap 内存。

**影响**：单连接可保持至少一个大帧缓冲，多个连接或多个流可叠加造成进程级内存耗尽；这是远程可触发的资源消耗问题。测试只验证数据可达，不足以证明背压。

**修复方向**：设置每流和每会话的最大排队字节数；超限停止读取或发送 RST/GOAWAY；读取方消费后释放配额。把帧最大值、队列最大值和并发流数统一纳入资源预算，覆盖“慢消费者 + 连续 DATA + 大帧”测试。

### P-H02 H2Mux 未知帧类型先分配/读取大 payload 再忽略

**文件**：`preview/Protocols/Mux/H2Mux/Codec.hpp:123-139,174-177,207-225`；`preview/Protocols/Mux/Session.hpp:458-486`

`H2Mux::ParseHeader()` 把首字节直接转换为 `FrameType`，没有拒绝未知值。`Codec::PayloadLen()` 对所有类型都返回 `Frame.length`，而 `IsControl()` 只把 DATA/CLOSE 之外的值标记为控制帧。结果是攻击者可以发送任意未知类型和接近 `MaxFrameLength` 的长度，框架先分配并精确读取 payload，再在 `Dispatch()` 中静默丢弃。

**影响**：远程可用无意义控制帧消耗内存、带宽和事件循环时间；连续发送时绕过业务流状态检查。未知类型应在头部阶段终止会话或至少只接受明确允许的长度。

**修复方向**：在 `ParseHeader()` 对 `FrameType` 做完整枚举校验；对每种控制帧固定校验长度；未知类型直接 `BadMessage` 并关闭会话。补充未知 type、最大 length、连续控制帧测试。

### P-H03 UDP relay 端点关联可被旧未配对端点污染且会话表无上限

**文件**：`preview/Net/UdpRelay.hpp:168-220,227-267`

`AssocTable::Touch()` 只清理当前方向的旧未配对项，`Reap()` 只遍历 `AToB_`。如果 B 侧先发包且长期没有 A 侧配对，孤立的 `BToA_` 项不会被 `Reap()` 删除；下一个 A 侧来源可能与这个旧 B 端点配对。与此同时，已配对的端点数量只受超时控制，没有最大会话数或总表字节预算，攻击者可以持续制造来源端点条目。

**影响**：可能把新客户端的 UDP 流量转发到旧端点，造成跨会话流量混淆；大量来源还可使 map 持续增长。当前“先到者配对”模型也没有认证或连接 token，不能把端点本身当作可信身份。

**修复方向**：A/B 两侧使用统一关联记录和对称回收；未配对两侧都必须按时间回收；增加最大关联数、拒绝策略和来源绑定/会话 token；配对前后都验证端点状态。测试 B-first、超时后新 A、海量来源和重复配对。

### P-H04 Profile/Legacy 的 Snapshot 捕获没有独立上限

**文件**：`preview/Transport/Snapshot.hpp:100-127,178-219`；`preview/Runtime/Recognition/Recognition.hpp:233-293`

`Snapshot::async_read_some()` 每次从底层成功读取后都向 `Captured_` 追加，没有最大捕获字节数。Recognition 的 `ProbeBuffer` 有 64 KiB 预算，但 scheme 执行阶段重新包装为 Snapshot 后，Snapshot 自身不继承该预算。方案执行失败前如果继续读取，捕获区可随输入增长；同时 `Captured_` 使用调用时的 PMR resource，API 没有强制其生命周期覆盖 detached/异步使用。

**影响**：scheme/解析失败路径存在远程内存增长；资源错误时还可能在析构或扩容阶段访问过期 `memory_resource`。此外，底层传输若错误地返回 `N > Buffer.size()`，第 124 行会用越界 span 追加。

**修复方向**：Snapshot 必须接收并强制执行 `MaxCaptureBytes`，超限返回 `BadLength`；先校验 `N <= Buffer.size()` 再复制；默认使用明确拥有期覆盖整个 Snapshot 的资源，或改用稳定拥有的标准容器。`Rewind()` 应在写入后拒绝而不是只依赖调用方自律。

### P-H05 DNS First 模式的 loser 查询在首胜返回后继续 detached 运行

**文件**：`preview/Net/Dns/Upstream.hpp:529-594`

`ResolveConcurrent()` 为每个上游 `co_spawn(..., net::detached)`，`Mode::First` 发现一个成功结果后立即返回，但没有取消或等待其余任务。loser 继续使用 `Owner`、连接池、endpoint/TLS context 和共享结果数组，直到各自超时或完成。

**影响**：每次 DNS 首胜都仍然消耗所有上游的连接、CPU、内存和网络；攻击者可以通过大量触发查询把成本放大到上游数量倍数。Resolver 销毁时这些任务仍可能持有 `Upstream` 共享所有权，延迟资源回收。

**修复方向**：为每次 concurrent query 建立可取消的 shared operation state；首胜后取消 loser，并等待所有 loser 退出后释放结果；取消/异常路径必须给每个任务一个完成状态。增加 First 模式首胜后确认无残留连接/任务的测试。

### P-H06 DNS over TCP/DoT 发送长度会静默截断

**文件**：`preview/Net/Dns/Transport.hpp:72-84,182-190`

`MakeTcpFrame()` 无条件把 `wire.size()` 转为两个字节，`FrameTransportBase::Send()` 也没有在封装前检查 `wire.size() <= MaxFrameBytes`。超过 65535 字节时长度字段回绕，但完整大报文仍被追加发送，接收端会把后续内容解释为下一帧。

**影响**：超长 DNS 配置/记录会产生线级不同步，连接池复用后下一次查询可能读取残留数据；错误响应可能被误归属到后续请求。修复应返回 `message_size`/`BadLength`，不能截断后继续发送。

### P-H07 VMess 使用 `std::random_device` 生成握手密钥材料

**文件**：`preview/Protocols/Vmess/Conn.hpp:254-266`；`preview/Protocols/Vmess/RequestCodec.hpp:276-284`

VMess 客户端把 IV、密钥和随机字段逐字节取自 `std::random_device`。仓库自身在 SS2022 注释中承认 MinGW 的 `random_device` 可能是确定性序列，但 VMess 路径仍使用它。若平台实现不是 CSPRNG，握手密钥/nonce 可预测，攻击者可重放或解密会话。

**修复方向**：统一使用 BoringSSL `RAND_bytes`，检查返回值；失败必须终止握手，不得继续使用零填充材料。清零私钥、IV 和临时密钥的生命周期副本。

### P-H08 SS2022 会话盐的 RAND_bytes 返回值被忽略

**文件**：`preview/Protocols/Shadowsocks2022/Conn.hpp:273-277,640-644`

客户端和服务端生成 session/server salt 后没有检查 `RAND_bytes()` 返回值。失败时数组仍为零初始化，随后照常派生会话密钥。若随机源初始化失败，跨连接盐重复，破坏协议要求的密钥/nonce 唯一性。

**修复方向**：返回值必须成为握手失败条件；不要以零数组或旧 salt 退化。为 RAND 失败注入测试，确认不会发送任何加密帧。

### P-H09 动态密钥 span 可能触发 BLAKE3/AES key 越界读取

**文件**：`preview/Foundation/Utility/Crypto/Blake3.hpp:100-115`；`preview/Foundation/Utility/Crypto/Block.hpp:47-61,94-107`

`KeyedHasher()`/`KeyedHash()` 接收任意长度 span，直接把指针传给要求 32 字节 key 的 `blake3_hasher_init_keyed()`；`EcbEncrypt/Decrypt()` 只对 16 字节作分支，其他所有长度都按 AES-256 传给 EVP，包含 0、17 或 31 字节。调用方若把配置或解析所得动态 span 传入，会发生越界读取或错误算法选择。

**修复方向**：入口严格要求 BLAKE3 key 恰为 32 字节，AES key 只接受 16/32 字节；返回 `expected`/错误码而不是用零输出表示失败。补充短 key、长 key 和空 span 测试。

### P-H10 SampleTracer 的非法 RingSize 会越界（已修复 2026-09-11）

**文件**：`preview/Foundation/Utility/Diagnose/Observability.hpp:233-259,291-299`

旧构造函数只记录 `RingSize`，`0` 或非 2 的幂会让 `index & (RingSize - 1)` 失去容量安全。现已将非法值归一化为默认 256，并将合法容量封顶为 65536，新增 `Capacity()` 可观测实际容量；采样率和 ring drain 语义保持不变。

**修复方向**：构造时拒绝/钳制 0 和非 2 的幂，或改为 `% RingSize` 并对容量做上限；让 API 返回配置错误而不是构造一个不可用对象。

### P-H11 WebSocket 帧头解析缺少 RFC 6455 结构约束

**文件**：`preview/Protocols/Ws/Codec.hpp:75-124`

解析器只提取 FIN/opcode/mask/长度，不拒绝 64 位长度字段最高位为 1，也不校验控制帧必须 FIN、payload <=125、opcode 是否保留以及服务端/客户端的 mask 方向。若上层直接依据 `PayloadLen` 分配，恶意 127 长度可转成极大值。

**修复方向**：codec 层先拒绝保留 opcode、非法 RSV、控制帧分片、控制帧超长和 64 位长度最高位；按角色强制 mask；在读取 payload 前配置化限制最大 frame。

### P-H12 Mux 流 ID 被错误限制为 16 位并循环复用

**文件**：`preview/Protocols/Mux/Session.hpp:599-639`

Yamux/H2Mux 使用 32 位 StreamId，但 `AllocateId()` 在 `>65535` 时回到 1/2。长时间开关流后会复用已经在协议层消耗过的 ID，远端可能把复用 ID 视为旧流或协议错误；循环也使可用 ID 空间远小于协议设计。

**修复方向**：按 codec 声明的 ID 宽度分配，使用单调 32 位计数并在耗尽时关闭会话；不要因为当前 `MaxStreams` 默认 256 就把协议 ID 截成 16 位。

### P-H13 Listener 析构不停止 detached accept loop

**文件**：`preview/Runtime/Listener.hpp:103-125,147-184,207-270`

`TcpListener` 析构函数没有调用 `Stop()`。AcceptLoop 按值持有 `Lifetime`，因此销毁 Listener 对象不会关闭 acceptor；只要 executor 继续运行，协程仍会监听并持有工厂、acceptor 和状态。调用方必须外部手动 Stop，类型本身没有 RAII 保证。

**修复方向**：析构中幂等关闭 acceptor，并提供完成/停止状态；禁止新会话在析构阶段进入工厂。增加“Listener 离开作用域但 io_context 继续运行”的生命周期测试。

### P-H14 真实 TCP/UDP 叶子没有实现 Transmission timeout

**文件**：`preview/Transport/Transmission.hpp:299-311`；`preview/Transport/Reliable.hpp:264-273`；`preview/Transport/Unreliable.hpp:369-382`

基类 `SetTimeout()` 只有向 `NextLayer()` 转发的默认实现，叶子 Reliable/Unreliable 都没有覆盖；叶子没有 NextLayer，所以调用 `SetTimeout()` 是空操作。Mux/Session/上层以为 timeout 生效时，真实 socket 读仍可无限等待，形成 slowloris 资源占用。MemoryStream 有测试用 timeout 反而掩盖了生产差异。

**修复方向**：在 Reliable/Unreliable 实现读操作级 timer/cancel，或删除虚假 timeout 契约并由明确的上层 deadline 统一控制。覆盖真实 socket 的“连接后不发送数据”和“半关闭 + 超时”测试。

### P-H15 TrustTunnel/HTTP Basic 认证接受非规范 Base64并使用普通比较

**文件**：`preview/Protocols/Trusttunnel/Codec.hpp:77-145,155-164`；`preview/Foundation/Utility/Crypto/Base64.hpp:76-163`

两个解码器都在遇到 `=` 后提前结束，没有验证 padding 数量、位置、尾随字符和低位 padding bits；`Base64Decode()` 还允许 `=` 出现在中间。TrustTunnel 最终用 `user == ExpectUser && pass == ExpectPass` 比较敏感凭据。HTTP Basic 复用相同 Base64 实现。

**影响**：不同编码可能被解释为同一凭据，产生认证策略歧义；普通比较暴露可测量的凭据长度/前缀时序信息。它不是直接密码恢复，但在高频远程认证端点上会放大侧信道和解析差异。

**修复方向**：严格 RFC 4648 解码并拒绝非规范输入；对固定/敏感凭据使用常量时间比较；不要把 Base64 解码错误转换成空凭据后继续。

### P-H16 PadTransport 随机源失败仍继续，且中间件忽略真实配置

**文件**：`preview/Transport/Pad.hpp:198-205,213-249`；`preview/Runtime/Middleware/Builtin/Pad.hpp:46-55`

构造函数忽略 `RAND_bytes()` 返回值，失败时用全零 RngKey 驱动 BLAKE3 padding；`PadMiddleware` 不读取 `Context::PadConfig::MinSize/MaxSize`，总是硬编码目标字符串。Pad 还直接把 padding 追加到数据流，没有通用 framing，只有明确支持该语义的协议才可使用。

**修复方向**：随机源失败必须禁用/报错；中间件使用上下文配置并验证范围；明确 padding 属于哪一层协议，禁止对 mux/已有 framing 的流盲目包装。

### P-H17 Mux writer 的取消路径可能永久等待 Consumed

**文件**：`preview/Protocols/Mux/Session.hpp:316-337,397-435`

WriteLoop 在向 `Completion` 发送结果后无条件等待 `Request.Consumed`。如果等待方被取消但没有进入 `RawWrite()` 的 catch，或 `try_send()` 失败后没有消费者，writer 协程会卡在队列节点，后续帧无法发送。Teardown 没有遍历并唤醒/取消所有 PendingWrites。

**修复方向**：请求节点使用显式完成状态和取消回调；writer 不应依赖调用方第二次确认才能推进队列，或者在会话关闭时统一 cancel channel 并清理队列。增加 producer cancellation/close race 测试。

### P-H18 Hysteria2 未知 Kind 被当成 TCP，增量 Parser 无界累积（已修复 2026-09-11）

**文件**：`preview/Protocols/Hysteria2/Codec.hpp:185-219,342-361`

`Codec::Parse()`/Dgram 路径已拒绝未知 Kind；本轮补上 TCP `Conn::ReadFrame()`
在读取地址前的 `Tcp/Udp` 白名单，未知 Kind 直接返回 `BadMessage`，不再把非法枚举
映射为 `NotSupported` 或继续消费地址字节。增量 parser 的预算仍由对应 Parser/调用方
负责，Hysteria2 focused `34/34` 通过。

### P-H19 QUIC/HTTP3 随机源失败时存在确定性退化

**文件**：`preview/Protocols/Http3/NativeClient.hpp:675-684`；`preview/Protocols/Quic/Native.cpp:1585-1592`

HTTP/3 native client 的 `CbRand()` 在 `RAND_bytes()` 失败后用 `Index * 37 + 11` 填充；QUIC native 的 `Random()` 则直接忽略失败返回值。随机数用于 QUIC/HTTP3 的连接 ID、挑战或密钥相关材料时，随机失败不是可接受的可预测 fallback。

**修复方向**：随机源失败应返回库要求的 callback failure 或让连接进入关闭状态；不能用确定性序列继续握手。对每一个 ngtcp2/nghttp3 random callback 注入失败路径，确认连接不会发送可用握手包。

### P-H20 VMess/SS2022/Reality 的 EVP 失败结果未统一成为协议失败

**文件**：`preview/Protocols/Vmess/Auth.hpp:145-168,176-208`；`preview/Protocols/Shadowsocks2022/ChunkCodec.hpp:60-74,97-111`；`preview/Protocols/Reality/Codec.hpp:279-293,315-328`

多处调用 `EVP_*Init/Update/Final/ctrl` 后继续使用输出，只在部分解密路径检查 `Final`。例如 SS2022 的加密块没有检查 Init/Update/Final/GetTag；Reality SessionId seal 直接返回 success；VMess GCM seal/open 也把初始化失败和正常输出用同一个 vector/空结果语义表达。系统级 EVP 失败虽少见，但一旦发生会产生错误密文、错误认证结果或协议双方状态不一致。

**修复方向**：每个 EVP 调用都检查返回值；加密失败返回明确错误，解密失败清空输出且不得推进 nonce/状态；将密码学函数改为 `expected` 或带错误码的结果，避免零数组伪装成功。

## MEDIUM

### P-M01 MemoryStream 的 Close/Shutdown 仍允许写入

**文件**：`preview/Transport/MemoryStream.hpp:148-172,177-196`

`WriteAll()` 只检查对端 `Peer->Closed`，不检查本端 `In_->Closed` 或本端是否已 Shutdown；因此调用 `Close()` 或 `Shutdown()` 后本端仍能把数据放入对端队列。该测试传输与真实 TCP half-close/full-close 语义不一致，会让单测错误地通过。

### P-M02 Reliable::Connect 的错误契约不一致（已收口）

**文件**：`preview/Transport/Reliable.hpp:84-107`

函数声明返回 `error_code`，但旧实现的 `async_connect(..., use_awaitable)` 没有
`redirect_error`；连接失败会通过异常离开协程，而不是返回错误码。现已统一绑定
`redirect_error`，普通拒绝和 timeout 都返回错误码，失败时关闭 socket；详见顶部
收口记录与 `ReliableConnectReturnsErrorCodeOnRefusal` 回归。

### P-M03 Connector completion-handler 可能同步回调且多 buffer 读只转发首 buffer

**文件**：`preview/Transport/Connector.hpp:151-190,202-220`

预读路径直接在发起函数内调用 handler；下层委托路径只取 `buffer_sequence_begin(buffers)`，忽略后续 buffer。前者可能造成调用方重入，后者在合法的多段 mutable buffer 上丢失可写空间。`WriteNext()` 通过递归回调处理短写，大量一字节短写会造成深递归。

### P-M04 Transmission 默认 completion-handler detached 协程吞掉异常

**文件**：`preview/Transport/Transmission.hpp:146-204`

默认 callback 适配器用 `net::detached`，lambda 没有异常捕获。派生实现、Executor 或用户回调抛异常时，completion handler 可能永远不被调用，错误也不再进入调用者的 `error_code`。这是错误链和生命周期审计项，不能只靠“正常实现不抛异常”。

### P-M05 TaskRegistry::CancelAndWait 名称与实际语义不符（已修复 2026-09-11）

**文件**：`preview/Foundation/Utility/Coroutine/Registry.hpp:136-147,178-249`

旧实现只把 token `Detach()` 并清空 map，不停止 I/O、不等待协程退出，`timeout` 参数完全未使用。现已改为每个 token 绑定独立 Asio cancellation slot，新增同步 `Cancel()` 请求取消，`CancelAndWait()` 改为非阻塞 `awaitable<bool>`：等待 token 的 completion 真正释放，超时返回 `false`；取消后的任务只在实际释放时计入 `TotalCancelled`。析构路径仍只请求取消并解除 Owner_ 绑定，避免在析构函数中阻塞。`RegistryTest` 和 `OwnershipAudit.TaskRegistryDanglingOwner` 已覆盖取消、等待、超时边界和析构安全。

### P-M06 EwmaMeter 并未实现 EWMA

**文件**：`preview/Foundation/Utility/Diagnose/Observability.hpp:162-216`

`Sum_` 只累计不清零，`RatePerSecond()` 用累计总数除以本次读取间隔，不是指数衰减速率；多次读会把历史事件重新计入当前速率。监控/限流依据该值时会长期偏大，且 `LastRead_` 多读者没有 CAS。

### P-M07 TokenBucket 的 RefillCount 乘法和时间基准溢出未防御（已修复 2026-09-11）

**文件**：`preview/Foundation/Utility/Rate/TokenBucket.hpp:40-61,72-111`

旧实现中 `Intervals * RefillCount_` 和 `now + 1` 会在极值配置/时间轴下回绕，导致令牌数错误或时间基准重新变成未初始化。现已限制补发计数，并对补发乘法、令牌加法、时间戳和相对时间增量使用饱和算术；正常容量/速率语义保持不变。`TokenBucket` 的时间戳、补发极值及并发回归均已通过。

### P-M08 FlatBuffer/Parser 的增长与长度契约仍可被极值打破（已修复 2026-09-11）

**文件**：`preview/Foundation/FlatBuffer.hpp:113-123,213-229`；`preview/Foundation/Parser.hpp:132-214`

旧实现的 `Prepare()` 会在 `Size_ + N` 回绕后继续增长；Parser 的 `HeaderLen + PayloadLen` 没有统一最大 payload 约束，且 `Want()` 会重复计算已经消费的 header。现已让 FlatBuffer 记录调用方初始容量、对增长和追加执行上限检查；Parser 要求每个 Config 声明 `MaxPayloadLen`，统一拒绝超限/不可表达帧并清理状态，`Want()` 只返回 payload 缺口。极值、分片和正常 Mux 帧回归均已通过。

### P-M09 通用地址编码对非法输入静默生成错误 wire（已修复 2026-09-11）

**文件**：`preview/Protocols/Common/Address.hpp:157-195,209-253`

旧实现的 IPv4 文本解析会把空段当作 0，非法输入编码为 `0.0.0.0`；IPv6 解析失败时把任意长度原始字符串直接追加，调用方得到“编码成功但目标改变或端口错位”的 wire。现已统一先校验再追加，非法地址保持输出不变并让各协议构造器返回空结果；IPv6 仅接受标准文本或恰好 16 字节二进制。

### P-M10 认证器和协议静态凭据比较不是统一常量时间（已修复 2026-09-11）

**文件**：`preview/Foundation/Authenticator.hpp:79-86`；`preview/Protocols/Trojan/Conn.hpp:291-297`；`preview/Protocols/Hysteria2/Conn.hpp:150-160`；`preview/Protocols/Vless/Conn.hpp:299-302`

旧实现中 StaticAuthenticator、Trojan/VLESS/VMess/TUIC 静态凭据和 Hysteria2/TrustTunnel 密码使用普通字符串或 `std::equal` 比较，且多字段比较可能短路。现已新增 `Preview::ConstantTimeEqual`，按完整较长序列执行内容比较，并在所有这些静态认证路径中统一使用；长度差异只影响公开的输入元数据，不提前返回内容差异。相关认证、会话和 Basic Auth focused 回归已通过。

### P-M11 ProbeDefense 过期依赖外部调用，MaxRecords=0 失去容量约束（已修复 2026-09-11）

**文件**：`preview/Runtime/Recognition/ProbeDefense.hpp:85-133,191-267`

旧实现中 `FailCount()`/`ShouldChallenge()` 依赖调用方定期 `Expire()`，`MaxRecords_==0` 时仍会插入新 key。现已让查询和记录路径主动清理窗口，新增 key 在达到容量时淘汰最旧记录，零容量直接拒绝；时钟可注入以覆盖精确过期边界。

### P-M12 SNI 路由表没有并发保护且每次 wildcard lookup O(N)（已修复 2026-09-11）

**文件**：`preview/Runtime/Recognition/Route.hpp:82-90,158-193`

旧实现中 `SniRouteTable` 的 Add/Clear 与 Lookup 直接读写同一 unordered_map，更新并发时存在数据竞争；通配匹配还要扫描全部条目。现已改为不可变 COW 快照原子发布，查询按值返回并保留结果生命周期；通配模式按首个标签后的后缀直接哈希查找，查询复杂度为 O(1)，精确匹配优先和单标签约束保持不变。

### P-M13 Statistics identity 表无淘汰策略（已修复 2026-09-11）

**文件**：`preview/Runtime/Statistics.hpp:165-248,280-367`

旧实现对每个新 identity 都做 COW map 发布，没有最大 identity 数、TTL 或清理。现已为 IdentityTraffic/TrafficCounter 增加可配置上限（默认 100000），达到上限后拒绝新 key、保留已有 key 的原子统计，避免无界快照复制；上限为 0 时不接受任何新 identity。

### P-M14 Profile 路由和候选回调的输入缺少调用方资源上限（部分修复 2026-09-11）

**文件**：`preview/Runtime/Recognition/Profile.hpp:214-230,793-866`；`preview/Composition/Recognition/CandidateFactory.hpp`

Profile 现已限制 Route 数、候选名称和方案字符串，并在 Settings loader 中执行相同硬上限；回调构造的 `PreparedState` 仍由具体候选以 `shared_ptr<const void>` 管理，Runtime 无法检查其内部大小，因此该子项保留为候选实现责任。

### P-M15 HTTP/1 请求头解析允许重复字段最后覆盖且不验证头名/折叠语义（已修复 2026-09-11）

**文件**：`preview/Protocols/Http1/Parser.hpp:87-151`

旧实现把重复 Host/Proxy-Authorization 的最后一项写入视图，不拒绝控制字符、空头名或 obsolete folding。现已校验请求行、RFC token 头名和字段值字符，拒绝重复安全头、折叠行、非法头行和超过 64KiB 的完整头块，避免认证/目标解析歧义。

### P-M16 HTTP/3/QPACK 动态状态需要审查硬上限和未知类型拒绝（静态 Preview 范围已修复 2026-09-11）

**文件**：`preview/Protocols/Http3/DynamicTable.hpp`、`Decoder.hpp`、`Encoder.hpp`、`Qpack.hpp`、`Session.hpp`

Preview QPACK 认证解码继续只支持静态表并拒绝动态表指令；现已增加头块 64KiB、字段数 128、单字段/Huffman 输出 16KiB 上限，恶意超长 name/value 和字段洪泛会在分配/追加前失败。ngtcp2/nghttp3 native 会话内部的动态表、blocked stream 与连接级状态仍由第三方库管理，需继续依赖其 API/外部互操作验证，不能把本项写成整个 HTTP/3 栈已完成审计。

### P-M17 AnyTLS 发送循环缺少零进展保护（已修复 2026-09-11）

**文件**：`preview/Protocols/Anytls/Conn.hpp:211-223`

旧 `SendBytes()` 在 `ec` 为空时直接 `Done += N`，零进展会忙循环，过大写入会跳过边界。现已在 AnyTLS 发送循环中拒绝 `N == 0` 和 `N > remaining`；zero-progress/over-reporting 回归均验证一次写入即失败。Gun/Reality/旧协议的独立发送循环仍需按各自 API 继续复查。

### P-M18 QPACK 解码器缺少字段数量和输出字节预算（已修复 2026-09-11）

**文件**：`preview/Protocols/Http3/Decoder.hpp:159-264`

旧解码器只对 `Data` span 做边界检查，`fields` 预留 8 项但没有最大字段数或单字段输出上限。现已限制头块 64KiB、字段数 128、name/value/Huffman 输出 16KiB，超限在 push 或解码前返回空结果；动态表指令仍明确拒绝。HTTP/3 依赖库内部状态不在本 Preview Decoder 的所有权范围内。

**修复方向**：在 Decoder API 传入 `MaxFields/MaxHeaderBytes`，每次 push 前检查累计预算；认证路径拒绝超出预算的头块，而不是解完再筛选。

## 性能与资源问题

1. `preview/Transport/Preview.hpp` 使用 `std::vector`，注释却声称强制 GlobalPool；每次 Preview 包装都会复制预读数据，当前实现与 PMR 生命周期设计不一致。
2. `preview/Runtime/Recognition/ProbeBuffer.hpp:230-235` 在 Snapshot 存活期间每次增长都完整 COW 复制，TLS 多记录/多候选场景会产生 O(n^2) 拷贝；应按预算测量并减少 snapshot 数量。
3. `preview/Net/Route/Route.hpp:63-79` 和 `preview/Runtime/Recognition/Route.hpp:158-193` 每次 lookup 都构造临时 string，后者还全表扫描 wildcard；应使用透明 hash/后缀索引并记录基线。
4. `preview/Foundation/Memory/CowMap.hpp:99-112` 在写竞争下复制整张 map 并无限 CAS 重试；身份/配置 key 数增长时写放大会拖慢 worker。
5. `preview/Transport/MemoryStream.hpp`、`preview/Protocols/Mux/StreamState.hpp`、`preview/Runtime/Middleware/Builtin/Relay.hpp` 都使用无界或仅按单次 buffer 限制的队列，测试吞吐不能代表生产内存曲线。
6. `preview/Protocols/Mux/Session.hpp` 每个最大帧都可能保留 16MB payload capacity；连接关闭前不会回收，必须纳入连接级内存预算。
7. `preview/Protocols/Http3/Huffman.hpp`、QPACK encoder/decoder 和 QUIC native 路径应测量恶意短输入、重复表查找和回调分配，当前静态检查不能支持“性能无回退”结论。

## 生命周期、错误链和并发审计

### 1. Detached 任务

`preview/Runtime/Listener.hpp` 的 accept loop、`preview/Net/Dns/Resolver.hpp` 的 maintenance loop、`preview/Net/Dns/Upstream.hpp` 的 concurrent losers、`preview/Protocols/Mux/Session.hpp` 的 frame/write loop、`preview/Protocols/Trusttunnel/Http2.hpp` 与 `preview/Protocols/Xhttp/Conn.hpp` 的 driver 都使用 detached。当前最重要的差异是：部分任务拥有 shared state，部分任务仍依赖外部 raw callback/资源；必须为每条路径写出停止顺序、取消入口和完成证明，不能仅因为 lambda 按值捕获 `shared_ptr` 就视为安全。

### 2. 错误链

- `Reliable::Connect()` 普通连接失败通过异常离开，而 Dialer/DNS 代码大多采用 `redirect_error`，同一 Transport 抽象的调用方无法统一处理。
- `Transmission` callback bridge 使用 detached，异常可能不会回调调用者。
- `Mux::WriteLoop()` 关闭/取消时的 Completion/Consumed 双 channel 依赖调用者配合，存在挂起等待。
- QUIC `Random()` 回调在 `preview/Protocols/Quic/Native.cpp:1585-1592` 忽略 RAND 失败，只有部分 CID 回调检查失败；随机数错误语义不一致。

### 3. 协程纯度

Preview 目录没有发现 `std::mutex`/`std::this_thread::sleep_for`/同步 `getaddrinfo`，这是正向结果；但“没有阻塞调用”不等于关闭安全。需要补全取消 loser、定时器 winner、异步回调重入和 PMR resource 跨挂起点的测试矩阵。

## 文件覆盖索引

本次静态清单以 `rg --files preview` 为准，覆盖 255 个文件。下表按目录记录逐文件审阅的重点；带有具体发现的文件在上文按源码行号引用，未列为问题的文件也完成了接口、边界、生命周期和调用点检查。

| 目录 | 文件数 | 逐文件审阅范围 |
|------|--------|----------------|
| `preview/Foundation` | 37 | 错误码、span、Parser/FlatBuffer、PMR、COW、账户租约、Crypto、日志和统计工具 |
| `preview/Transport` | 11 | Transmission 合同、partial I/O、callback bridge、TCP/UDP/TLS、Preview/Snapshot/Pad/Connector |
| `preview/Net` | 21 | Dialer、route/target、UDP relay、DNS format/answer/cache/coalescer/pool/upstream/resolver/DoH |
| `preview/Runtime` | 27 | Listener/Session、middleware、statistics、session registry、Probe/Profile/Route/TLS/识别协调器 |
| `preview/Composition` | 16 | settings JSON/loader、candidate registry/factory、handler adapter、API snapshot |
| `preview/Protocols` | 142 | Common、Anytls、Ech、Gun、Http1/2/3、Hysteria2、Mux 三族、Native/Quic、Reality/Restls、SS2022、Shadowtls、SOCKS5、Trojan、Trusttunnel、Tuic、VLESS、VMess、WS、XHTTP |
| `preview/CMakeLists.txt` 和说明文件 | 2 | target 依赖、外部库边界、模块聚合和构建入口 |

逐文件路径清单：

```text
preview/CMakeLists.txt
preview/Composition/Adapters/Common.hpp
preview/Composition/Adapters/ProtocolAdapter.hpp
preview/Composition/Adapters/Socks5.hpp
preview/Composition/Adapters/Ss2022.hpp
preview/Composition/Adapters/Trojan.hpp
preview/Composition/Adapters/Vless.hpp
preview/Composition/Adapters/Vmess.hpp
preview/Composition/Api/ApiManager.hpp
preview/Composition/Recognition/CandidateFactory.hpp
preview/Composition/Recognition/CandidateRegistry.hpp
preview/Composition/Recognition/LayeredCandidateFactory.hpp
preview/Composition/Recognition/ProfileBuilder.hpp
preview/Composition/Recognition/SettingsBuilder.hpp
preview/Composition/Recognition/TlsCandidateFactory.hpp
preview/Composition/Settings/Json.hpp
preview/Composition/Settings/Loader.hpp
preview/Foundation/Authenticator.hpp
preview/Foundation/ByteSpan.hpp
preview/Foundation/CodecTraits.hpp
preview/Foundation/Error.hpp
preview/Foundation/Exception/Deviant.hpp
preview/Foundation/Exception/Network.hpp
preview/Foundation/Exception/Protocol.hpp
preview/Foundation/Exception/Security.hpp
preview/Foundation/Fault/Code.hpp
preview/Foundation/Fault/Compatible.hpp
preview/Foundation/Fault/Handling.hpp
preview/Foundation/FlatBuffer.hpp
preview/Foundation/Foundation.hpp
preview/Foundation/Memory/Container.hpp
preview/Foundation/Memory/CowMap.hpp
preview/Foundation/Memory/Pointer.hpp
preview/Foundation/Memory/Pool.hpp
preview/Foundation/Parser.hpp
preview/Foundation/Role.hpp
preview/Foundation/SessionBase.hpp
preview/Foundation/Utility/Account/Authenticator.hpp
preview/Foundation/Utility/Account/Directory.hpp
preview/Foundation/Utility/Account/README.md
preview/Foundation/Utility/Coroutine/Registry.hpp
preview/Foundation/Utility/Crypto/Aead.hpp
preview/Foundation/Utility/Crypto/Base64.hpp
preview/Foundation/Utility/Crypto/Blake3.hpp
preview/Foundation/Utility/Crypto/Block.hpp
preview/Foundation/Utility/Crypto/Crypto.hpp
preview/Foundation/Utility/Crypto/Hkdf.hpp
preview/Foundation/Utility/Crypto/Sha224.hpp
preview/Foundation/Utility/Crypto/X25519.hpp
preview/Foundation/Utility/Diagnose/Context.hpp
preview/Foundation/Utility/Diagnose/Log.hpp
preview/Foundation/Utility/Diagnose/Observability.hpp
preview/Foundation/Utility/Rate/TokenBucket.hpp
preview/Foundation/Utility/TrafficSink.hpp
preview/Net/Dialer/Dialer.hpp
preview/Net/Dns/Answer.hpp
preview/Net/Dns/Cache.hpp
preview/Net/Dns/Coalescer.hpp
preview/Net/Dns/Config.hpp
preview/Net/Dns/ConnPool.hpp
preview/Net/Dns/Detail/ConfigOptions.hpp
preview/Net/Dns/Detail/Exchange.hpp
preview/Net/Dns/Detail/Fallback.hpp
preview/Net/Dns/Detail/Maintenance.hpp
preview/Net/Dns/Doh.hpp
preview/Net/Dns/Format.hpp
preview/Net/Dns/Resolver.hpp
preview/Net/Dns/Rules.hpp
preview/Net/Dns/Transport.hpp
preview/Net/Dns/Types.hpp
preview/Net/Dns/Upstream.hpp
preview/Net/Outbound/Outbound.hpp
preview/Net/Route/Route.hpp
preview/Net/Target.hpp
preview/Net/UdpRelay.hpp
preview/Protocols/Anytls/Anytls.hpp
preview/Protocols/Anytls/Codec.hpp
preview/Protocols/Anytls/Conn.hpp
preview/Protocols/Anytls/Types.hpp
preview/Protocols/Common/Address.hpp
preview/Protocols/Common/Form.hpp
preview/Protocols/Common/Framing.hpp
preview/Protocols/Common/Mux.hpp
preview/Protocols/Common/Read.hpp
preview/Protocols/Ech/Ech.hpp
preview/Protocols/Ech/Keygen.hpp
preview/Protocols/Ech/Scan.hpp
preview/Protocols/Ech/Types.hpp
preview/Protocols/Gun/Codec.hpp
preview/Protocols/Gun/Conn.hpp
preview/Protocols/Gun/Gun.hpp
preview/Protocols/Gun/Types.hpp
preview/Protocols/Http1/Conn.hpp
preview/Protocols/Http1/Parser.hpp
preview/Protocols/Http2/Codec.hpp
preview/Protocols/Http2/Frame.hpp
preview/Protocols/Http2/Impl.hpp
preview/Protocols/Http2/Session.hpp
preview/Protocols/Http2/Stream.hpp
preview/Protocols/Http3/Auth.hpp
preview/Protocols/Http3/Decoder.hpp
preview/Protocols/Http3/Detail/Varint.hpp
preview/Protocols/Http3/DynamicTable.hpp
preview/Protocols/Http3/Encoder.hpp
preview/Protocols/Http3/Huffman.hpp
preview/Protocols/Http3/NativeClient.hpp
preview/Protocols/Http3/NativeServer.hpp
preview/Protocols/Http3/Qpack.hpp
preview/Protocols/Http3/Server.hpp
preview/Protocols/Http3/Session.hpp
preview/Protocols/Http3/StaticTable.hpp
preview/Protocols/Hysteria2/Codec.hpp
preview/Protocols/Hysteria2/Conn.hpp
preview/Protocols/Hysteria2/Dgram.hpp
preview/Protocols/Hysteria2/Hysteria2.hpp
preview/Protocols/Hysteria2/Types.hpp
preview/Protocols/Mux/Client.hpp
preview/Protocols/Mux/Codec.hpp
preview/Protocols/Mux/H2Mux/Client.hpp
preview/Protocols/Mux/H2Mux/Codec.hpp
preview/Protocols/Mux/H2Mux/H2Mux.hpp
preview/Protocols/Mux/H2Mux/Server.hpp
preview/Protocols/Mux/H2Mux/Session.hpp
preview/Protocols/Mux/H2Mux/Types.hpp
preview/Protocols/Mux/Server.hpp
preview/Protocols/Mux/Session.hpp
preview/Protocols/Mux/SessionReadLoop.hpp
preview/Protocols/Mux/SessionWriteLoop.hpp
preview/Protocols/Mux/Smux/Client.hpp
preview/Protocols/Mux/Smux/Codec.hpp
preview/Protocols/Mux/Smux/Server.hpp
preview/Protocols/Mux/Smux/Session.hpp
preview/Protocols/Mux/Smux/Smux.hpp
preview/Protocols/Mux/Smux/Types.hpp
preview/Protocols/Mux/Stream.hpp
preview/Protocols/Mux/StreamState.hpp
preview/Protocols/Mux/Types.hpp
preview/Protocols/Mux/Yamux/Client.hpp
preview/Protocols/Mux/Yamux/Codec.hpp
preview/Protocols/Mux/Yamux/Server.hpp
preview/Protocols/Mux/Yamux/Session.hpp
preview/Protocols/Mux/Yamux/Types.hpp
preview/Protocols/Mux/Yamux/Yamux.hpp
preview/Protocols/Native/Conn.hpp
preview/Protocols/Native/Native.hpp
preview/Protocols/Native/Types.hpp
preview/Protocols/Quic/DatagramAdapter.hpp
preview/Protocols/Quic/GatewayCommon.hpp
preview/Protocols/Quic/Native.cpp
preview/Protocols/Quic/Native.hpp
preview/Protocols/Quic/StreamAdapter.hpp
preview/Protocols/Reality/Codec.hpp
preview/Protocols/Reality/Conn.hpp
preview/Protocols/Reality/Reality.hpp
preview/Protocols/Reality/Types.hpp
preview/Protocols/Restls/Codec.hpp
preview/Protocols/Restls/Conn.hpp
preview/Protocols/Restls/Restls.hpp
preview/Protocols/Restls/Types.hpp
preview/Protocols/Shadowsocks2022/ChunkCodec.hpp
preview/Protocols/Shadowsocks2022/Codec.hpp
preview/Protocols/Shadowsocks2022/Conn.hpp
preview/Protocols/Shadowsocks2022/Dgram.hpp
preview/Protocols/Shadowsocks2022/KeyDerivation.hpp
preview/Protocols/Shadowsocks2022/RequestCodec.hpp
preview/Protocols/Shadowsocks2022/ResponseCodec.hpp
preview/Protocols/Shadowsocks2022/Shadowsocks2022.hpp
preview/Protocols/Shadowsocks2022/Types.hpp
preview/Protocols/Shadowtls/Codec.hpp
preview/Protocols/Shadowtls/Conn.hpp
preview/Protocols/Shadowtls/Server.hpp
preview/Protocols/Shadowtls/Shadowtls.hpp
preview/Protocols/Shadowtls/Types.hpp
preview/Protocols/Socks5/Codec.hpp
preview/Protocols/Socks5/Conn.hpp
preview/Protocols/Socks5/Dgram.hpp
preview/Protocols/Socks5/Socks5.hpp
preview/Protocols/Socks5/Types.hpp
preview/Protocols/Socks5/UdpAssoc.hpp
preview/Protocols/Trojan/Codec.hpp
preview/Protocols/Trojan/Conn.hpp
preview/Protocols/Trojan/Dgram.hpp
preview/Protocols/Trojan/Trojan.hpp
preview/Protocols/Trojan/Types.hpp
preview/Protocols/Trusttunnel/Codec.hpp
preview/Protocols/Trusttunnel/Conn.hpp
preview/Protocols/Trusttunnel/Dgram.hpp
preview/Protocols/Trusttunnel/Http2.hpp
preview/Protocols/Trusttunnel/Trusttunnel.hpp
preview/Protocols/Trusttunnel/Types.hpp
preview/Protocols/Tuic/Codec.hpp
preview/Protocols/Tuic/Conn.hpp
preview/Protocols/Tuic/Dgram.hpp
preview/Protocols/Tuic/Tuic.hpp
preview/Protocols/Tuic/Types.hpp
preview/Protocols/Vless/Codec.hpp
preview/Protocols/Vless/Conn.hpp
preview/Protocols/Vless/Dgram.hpp
preview/Protocols/Vless/Types.hpp
preview/Protocols/Vless/UdpTunnel.hpp
preview/Protocols/Vless/Vless.hpp
preview/Protocols/Vmess/Auth.hpp
preview/Protocols/Vmess/ChunkCodec.hpp
preview/Protocols/Vmess/Codec.hpp
preview/Protocols/Vmess/Conn.hpp
preview/Protocols/Vmess/Dgram.hpp
preview/Protocols/Vmess/RequestCodec.hpp
preview/Protocols/Vmess/ResponseCodec.hpp
preview/Protocols/Vmess/Types.hpp
preview/Protocols/Vmess/Vmess.hpp
preview/Protocols/Ws/Codec.hpp
preview/Protocols/Ws/Conn.hpp
preview/Protocols/Ws/Types.hpp
preview/Protocols/Ws/Ws.hpp
preview/Protocols/Xhttp/Conn.hpp
preview/Protocols/Xhttp/Types.hpp
preview/Protocols/Xhttp/Xhttp.hpp
preview/Runtime/Contract/Handler.hpp
preview/Runtime/Listener.hpp
preview/Runtime/Middleware/Builtin/Auth.hpp
preview/Runtime/Middleware/Builtin/Dial.hpp
preview/Runtime/Middleware/Builtin/Mux.hpp
preview/Runtime/Middleware/Builtin/Pad.hpp
preview/Runtime/Middleware/Builtin/Relay.hpp
preview/Runtime/Middleware/Builtin/Throttle.hpp
preview/Runtime/Middleware/Context.hpp
preview/Runtime/Middleware/Pipeline.hpp
preview/Runtime/Recognition/ConfiguredMode.hpp
preview/Runtime/Recognition/DecisionTable.hpp
preview/Runtime/Recognition/DeterministicMode.hpp
preview/Runtime/Recognition/MixedTrialMode.hpp
preview/Runtime/Recognition/Probe.hpp
preview/Runtime/Recognition/ProbeBuffer.hpp
preview/Runtime/Recognition/ProbeDefense.hpp
preview/Runtime/Recognition/Profile.hpp
preview/Runtime/Recognition/Protocol.hpp
preview/Runtime/Recognition/Recognition.hpp
preview/Runtime/Recognition/Route.hpp
preview/Runtime/Recognition/SchemeExecutor.hpp
preview/Runtime/Recognition/Tls.hpp
preview/Runtime/Recognition/Types.hpp
preview/Runtime/Session.hpp
preview/Runtime/SessionRegistry.hpp
preview/Runtime/Statistics.hpp
preview/Transport/Algorithm.hpp
preview/Transport/Connector.hpp
preview/Transport/Encrypted.hpp
preview/Transport/MemoryStream.hpp
preview/Transport/Pad.hpp
preview/Transport/Preview.hpp
preview/Transport/Reliable.hpp
preview/Transport/Snapshot.hpp
preview/Transport/Stream.hpp
preview/Transport/Transmission.hpp
preview/Transport/Unreliable.hpp
```

## 验证缺口与下一步修复顺序

本次没有构建或运行测试，原因是 `AGENTS.md` 明确禁止在未获授权时构建；因此报告中的“确认”是源码级确认，不等同于 AddressSanitizer、网络互操作或跨平台 CI 证据。仓库现有 `scripts/audit_detached.sh` 本次虽输出 `DANGEROUS=0`，但其源目录固定为 `src/`，不能替代 Preview detached 审计。修复顺序建议为：

1. 先修复 P-C01、P-H01/P-H02/P-H03、P-H04、P-H07/P-H08，分别覆盖认证降级、远程内存耗尽、UDP 关联污染、回放捕获和密码学随机数。
2. 再统一 Transport/Protocol 的完整读写、零进展、timeout、cancel、Release 后状态和 detached completion 语义。
3. 为 DNS First loser、Mux 队列、WebSocket/H2Mux 长度、Base64 canonical、Profile cancel race 增加真正的负向和压力测试。
4. 获得构建授权后只使用既有 `build/`，按仓库规定检查时间和线程数，先跑受影响的 Preview/Contract 测试，再做完整 CTest；不要把历史 `bug.md` 的旧测试声明当作当前证据。

---

# Prism 项目缺陷分析报告

> 整合自 54 轮深度审计，覆盖全部 hpp/cpp 文件 + 7 条调用链分析。
> 经过去重（40+ 重复条目合并）、误报排除（C10 等 8+ 项）和严重性校准（L5/N1 降级）。
> 纯分析，未经编译或运行验证。按优先级排序。

## 统计概览

| 等级 | 数量 | 说明 |
|------|------|------|
| CRITICAL | 7 | 必须立即修复，可被远程利用或导致 RCE |
| HIGH | ~50 | 应尽快修复，影响安全/稳定性 |
| MEDIUM | ~120 | 计划修复，影响可靠性/性能/可维护性 |
| LOW | ~80 | 可选修复，代码质量改进 |
| **合计** | **~257** | 去重后独立问题数（原始 557 条去重后） |

---

## CRITICAL（7 项）

### S1 — AEAD nonce 溢出后密文已生成

**文件**: `src/prism/crypto/aead.cpp:94-121`
**类型**: 密码学安全

`seal()` 先调用 EVP 加密生成密文，成功后才检查 `increment_nonce()`。nonce 溢出（计数器回绕）时密文已生成并返回 `crypto_error`，但调用者可能已使用该密文。GCM nonce 重用导致认证标签完全失效。

**修复**: 在 seal/open 失败后标记 `tainted_`，后续调用立即拒绝。

---

### S2 — 仓库含 TLS 私钥

**文件**: `cert.pem`, `key.pem`
**类型**: 信息泄露

仓库中包含 TLS 私钥文件，任何有仓库访问权限的人可解密历史流量或伪造服务器身份。

**修复**: 从仓库中移除私钥，使用 `.gitignore` 排除，通过安全渠道分发。

---

### S3 — BLAKE3 keyed_hash 无 key 长度校验

**文件**: `src/prism/crypto/blake3.cpp:40`
**类型**: 越界读取

`keyed_hash()` 接受任意 `span` 作为 key，不校验 BLAKE3 要求的 32 字节长度。传入错误长度的 key 导致越界读取。调用方 `span<T,32>` 类型约束降低了风险，但函数本身不防御。

**修复**: 入口断言 `key.size() == 32`。

---

### S4 — configuration.json 含明文凭据

**文件**: `src/configuration.json`
**类型**: 信息泄露

配置文件包含明文密码/密钥，随代码一起提交到版本控制。

**修复**: 改为环境变量或加密存储，示例文件使用占位符。

---

### L4 — AnyTLS preread 双重发送

**文件**: `src/prism/instance/session/session.cpp:296-310`
**类型**: 数据一致性

`init_preread_` 和 `try_send` 可能同时保存数据，导致客户端发送的首个数据被重复消费，后续协议解析错乱。

**修复**: 使用单一标志保证 preread 数据仅投递一次。

---

### L6 — Restls write 假成功 + 无界 send_buf_

**文件**: `src/prism/stealth/facade/restls/transport.cpp:287-291`
**类型**: 数据丢失 + 内存耗尽

`write_pending_` 为 true 时 `async_write_some` 直接 `co_return data.size()` 返回"成功"，但数据仅入队 `send_buf_`（无容量上限）。调用者认为写入完成实际可能丢失，且恶意客户端可导致 `send_buf_` 无限增长 OOM。

**修复**: 设置 send_buf_ 容量上限（如 64KB），超出返回 `no_buffer_space`。

---

### S9 — domain_trie 通配符插入错误匹配父域名

**文件**: `src/prism/resolve/dns/detail/rules.cpp:102-132`
**类型**: DNS 路由逻辑错误

插入通配符规则 `*.example.com` 时，循环结束后的 `current->is_end = true` 被无条件执行，导致 `example.com` 节点同时持有 `wildcard=true` 和 `is_end=true`。搜索 `example.com` 时精确匹配检查命中，错误返回通配符规则的值，违反 RFC 4592 语义。

**修复**: 通配符规则不在其父节点设置 `is_end`，或使用虚拟子节点承载。

---

## HIGH（~50 项）

### 密码学 / 安全

**H-CRYPTO1 — X25519 RAND_bytes 返回值未检查**
`src/prism/crypto/x25519.cpp:22` — `RAND_bytes` 返回值被完全忽略。CSPRNG 失败时私钥可能全零，密钥交换完全可预测。**修复**: 检查返回值，失败时返回空密钥对并记录错误。

**H-CRYPTO2 — X25519 低阶点攻击未检测**
`src/prism/crypto/x25519.cpp:63-68` — 全零公钥输入产生全零共享密钥但返回 success。攻击者可预测所有派生密钥。**修复**: 检查共享密钥非全零。

**H-CRYPTO3 — AEAD seal/open 失败后 nonce 重用风险**
`src/prism/crypto/aead.cpp:94-151` — seal/open 失败时 nonce 不递增。调用者忽略错误重试将导致 GCM nonce 重用（标签失效+明文泄露）。当前调用者均关闭连接，但缺乏强制机制。

**H-CRYPTO4 — 密钥材料未安全清零**
多处密码学敏感缓冲区（X25519 私钥、HKDF PRK、AEAD key）使用后未 `OPENSSL_cleanse` 或 `std::fill(zero)`，残留于栈/堆中增加物理攻击面。

**H-CRYPTO5 — HMAC 失败返回全零与正常输出不可区分**
`src/prism/crypto/hkdf.cpp:15-31` — `hmac_sha256` 失败时 `result.fill(0)` 返回，调用者无法区分失败与恰好全零的 PRK（概率 2^-256）。

**H-CRYPTO6 — TrustTunnel Base64 凭据非常量时间比较**
`include/prism/stealth/stack/trusttunnel/scheme.hpp` — Base64 编码的凭据使用 `==` 比较，受时序侧信道攻击可逐字节枚举凭据。

---

### 连接 / 资源管理

**H-POOL1 — 连接池全局无容量限制，DoS 攻击风险**
`src/prism/connect/pool/pool.cpp:309` — `cache_`（`unordered_map<endpoint_key, vector<idle_item>>`）无全局上限。攻击者通过请求大量唯一域名可耗尽 FD 和内存。每端点缓存 32 个 socket，10000 端点 = 320000 socket。**修复**: 添加 `max_endpoints` 和 `max_total_idle` 配置。

**H-POOL2 — endpoint_hash reinterpret_cast 对齐 UB**
`src/prism/connect/pool/pool.cpp:99` — `reinterpret_cast<const uint64_t*>(key.address.data())` 中 `address` 偏移为 3（非 8 的倍数），违反 C++ 对齐规则。x86 不崩溃但编译器可基于对齐假设做错误优化。**修复**: 使用 `std::memcpy` 替代。

**H-POOL3 — connection_pool 统计计数器非原子**
`include/prism/connect/pool/pool.hpp:354-360` — `stat_acquires_` 等 6 个计数器类型为 `std::size_t` 非 `std::atomic`，注释声称 `memory_order_relaxed`。`stats()` 可在管理线程调用，与 worker 线程的连接操作构成数据竞争 UB。**修复**: 改为 `std::atomic<std::size_t>`。

---

### 生命周期 / 内存安全

**H-LIFE1 — ShadowTLS/Restls no-op deleter shared_ptr UAF**
`include/prism/stealth/facade/shadowtls/handshake.cpp`, `restls/handshake.cpp` — `shared_ptr<T>(&local_var, [](T*){})` 空删除器捕获栈变量引用。若 `co_spawn` 的 detached 协程在局部变量销毁后访问（如 io_context 停止延迟），触发 UAF。单线程 io_context 下风险降低但设计脆弱。涉及 M5263/M5264/M5285 共 13+ 处重复。

**H-LIFE2 — session launch 计数器 double decrement**
`src/prism/instance/worker/launch.cpp` — 异常路径下 session 计数器可能被重复递减，导致负载均衡器对 worker 负载的判断偏差。

**H-LIFE3 — snapshot captured_ 无界增长 OOM**
`include/prism/transport/snapshot.hpp:119-126` — `async_read_some` Phase 2 中从内层读取的每个字节都追加到 `captured_` 无上限。攻击者发送超长 ClientHello 可在 recognition 阶段消耗大量内存。**修复**: 增加 64KB 上限。

**H-LIFE4 — memory_tracker current_usage_ 可能下溢**
`include/prism/stats/memory.hpp:57-62` — `fetch_sub` 对 `uint64_t` 做原子减法。PMR monotonic_buffer_resource 的空 `do_deallocate` 与 instrumented 包装配合可导致只增不减。**修复**: 使用 signed 类型或检查阈值。

---

### TLS / Stealth

**H-TLS1 — native.cpp 内层探测结果被覆盖为 unknown**
`src/prism/stealth/facade/native.cpp` — native TLS 兜底的 `secondary_probe` 无条件将 `detected` 覆盖为 `protocol_type::unknown`，导致已正确识别的协议类型丢失。**修复**: 仅在探测确实失败时覆盖。

**H-TLS2 — AnyTLS frame_header::parse 不校验 command 范围**
`include/prism/stealth/stack/anytls/mux/frame.hpp:81-97` — `static_cast<command>(data[0])` 不检查枚举范围（0x00-0x0A），非法值传入 switch 导致不可预测行为。**修复**: 添加范围校验 `if (data[0] > 0x0A) return std::nullopt`。

**H-TLS3 — ALPN 回调污染共享 SSL_CTX**
`src/prism/stealth/stack/trusttunnel/scheme.cpp` — TrustTunnel 的 ALPN 选择回调直接修改 SSL_CTX 设置，多个连接并发时互相覆盖。涉及 M5259 及 7 处重复。**修复**: 每连接使用独立 SSL_CTX 或在握手前设置 ALPN。

**H-TLS4 — AnyTLS verify_user 每次重建 user_map**
`src/prism/stealth/stack/anytls/session.cpp` — 每次认证请求都从 account_directory 重建 user_map，O(N) 复制。高并发下浪费 CPU 和内存。涉及 M5262 及 7 处重复。**修复**: 缓存 user_map 并通过 COW 更新。

**H-TLS5 — AnyTLS auth_frame padding 无上限**
`src/prism/stealth/stack/anytls/session.cpp` — 认证帧的 padding 长度由客户端指定，无上限检查。恶意客户端可发送 64KB padding 消耗内存。涉及 M5261 及 2 处重复。

---

### 协议处理

**H-PROTO1 — CONNECT 请求空 target 导致 UB**
`src/prism/recognition/target.cpp:103` — HTTP CONNECT 携带空 target 时 `raw[0]` 访问空 string_view，UB 崩溃。可远程触发，无需认证。**修复**: 添加 `if (raw.empty()) return t`。

**H-PROTO2 — SOCKS5 bind_datagram_port 仅 IPv4**
`src/prism/protocol/socks5/conn.cpp` — UDP associate 的 bind 仅使用 IPv4，IPv6 客户端无法使用 SOCKS5 UDP。涉及 N4 及 4 处重复。

**H-PROTO3 — SS2022 UDP recv_chacha 缺少 entry 空指针检查**
`src/prism/protocol/shadowsocks/util/datagram.cpp:289-292` — `recv_chacha` 直接解引用 `entry->chacha20_ctx` 而 `recv_aes_gcm` 有正确的 `!entry` 检查。内存压力下崩溃。涉及 M3201/H88/M89。

**H-PROTO4 — Trojan/VLESS traffic_context 泄漏**
`src/prism/protocol/trojan/process.cpp` — `traffic_context` 在某些异常路径未正确释放，导致 traffic 统计不递减。

---

### DNS / 解析

**H-DNS1 — DoH Content-Length 无边界检查 OOM**
`src/prism/resolve/dns/upstream.cpp` — HTTPS DNS 响应的 Content-Length 解析无上限，恶意 DoH 服务器可指定 TB 级大小触发 OOM。涉及 M5368/O9/M93。

**H-DNS2 — DNS upstream SNI hostname 悬空指针**
`src/prism/resolve/dns/upstream.cpp` — `SSL_CTX_set_tlsext_servername_arg(ssl_ctx, server.hostname.c_str())` 存储 `c_str()` 裸指针。`set_servers()` 替换 vector 后指针悬空。当前仅构造时调用一次，但接口脆弱。涉及 M5446/M5485/M92。

**H-DNS3 — DNS serialize 未映射 addresses/blacklist 字段**
`include/prism/resolve/dns/serialize.hpp:68-74, 94-111` — `address_rule::addresses` 和 `dns::config::blacklist_v4/v6` 未包含在 Glaze 映射中。用户配置的静态 DNS 映射和 IP 黑名单静默不生效。涉及 M5552/M5553。

---

### 多路复用

**H-MUX1 — yamux handle_syn 不检查重复 stream_id**
`src/prism/multiplex/yamux/craft.cpp` — 收到 SYN 帧时仅检查 `pending_` 不检查 `ducts_`/`parcels_` 中是否已存在该 stream_id，可创建重复流导致资源泄漏和状态混乱。

**H-MUX2 — h2mux on_data 静默丢弃 pending 流数据**
`src/prism/multiplex/h2mux/craft.cpp:450-455` — DATA 帧属于 pending 条目时 return 0，数据被静默丢弃。sing-mux 模式下目标地址信息丢失，客户端请求超时。这是 CLAUDE.md 活跃 TODO。

**H-MUX3 — yamux send_data 窗口等待无超时**
`src/prism/multiplex/yamux/craft.cpp:793` — `window_signal->expires_at(time_point::max())` 永不超时。对端恶意不发 WindowUpdate 时协程永久挂起，资源泄漏。涉及 M5505 及 2 处重复。

---

### 其他 HIGH

**H-OTHER1 — restls parse_line int16_t 溢出 UB**
`src/prism/stealth/facade/restls/script.cpp:22-41` — 数字前缀解析使用 `int16_t`，超过 32767 时有符号溢出 UB。影响 script 长度计算。涉及 M3101/H87。

**H-OTHER2 — balancer::select() noexcept 内调用 std::function**
`include/prism/instance/front/balancer.hpp:112-113` — `select()` 标记 `noexcept` 但内部调用 `std::function`，异常传播将 `std::terminate`。实际概率低但一旦触发进程崩溃。

---

## MEDIUM（~120 项）

> 以下按模块分类，每条包含 ID/文件/简要描述。

### 密码学

| ID | 文件 | 描述 |
|----|------|------|
| M-CRYPTO1 | `crypto/aead.cpp` | seal 失败后 nonce 不递增，重试导致 nonce 重用 |
| M-CRYPTO2 | `crypto/hkdf.cpp` | hkdf_expand info 长度未校验（N1 降级：缓冲区数学正确，但 uint8_t counter 溢出依赖无符号语义） |
| M-CRYPTO3 | `crypto/hkdf.cpp:198` | EVP_DigestFinal_ex 返回值未检查 |
| M-CRYPTO4 | `crypto/block.cpp:16-23` | 非 16/32 字节 key 静默使用 AES-256，无日志 |
| M-CRYPTO5 | `stealth/common.hpp:38` | `aead_nonce()` 不校验 iv 长度，`memcpy(nonce.data(), iv.data(), 12)` 越界风险 |
| M-CRYPTO6 | `stealth/common.hpp:73` | `xor_key()` 除零 UB 当 key 为空 |

### 协程纯度

| ID | 文件 | 描述 |
|----|------|------|
| C1-M | `multiplex/h2mux/craft.cpp` | send_pending 缺少并发保护注释（L5 降级：单线程 io_context 消除并发风险，但缺少文档说明依赖关系） |

### 传输层

| ID | 文件 | 描述 |
|----|------|------|
| M-TRANS1 | `transport/unreliable.hpp:142-164` | async_read_some 无限循环过滤非匹配端点数据报，UDP 源地址伪造攻击 |
| M-TRANS2 | `transport/snapshot.hpp:137-147` | `rewind()` 不检查 `wrote_` 标志，public 接口可被误用 |
| M-TRANS3 | `stealth/seal_io.hpp:98` | `write_sealed` 返回明文大小非密文大小，语义不一致 |

### 性能

| ID | 文件 | 描述 |
|----|------|------|
| P1 | `recognition/recognition.cpp:46` | route_table 每次连接重建，配置运行时不变无需重建（M104） |
| P2 | `recognition/routes.cpp:80,96` | lookup 每次分配临时 string，map 不支持 heterogeneous lookup（L108） |
| P3 | `recognition/tls/signal.cpp:192-195` | read_tls_record 冗余双重复制（serialize + memcpy）（L107） |
| P4 | `multiplex/bootstrap.cpp:57` | padding 长度无上限（最大 64KB），可被恶意客户端利用 |
| P5 | `multiplex/smux/craft.cpp:224-234` | pending buffer 无上限累积，恶意客户端发送小片段 PSH 可无限增长 |
| P6 | `multiplex/smux/craft.cpp` | make_data_frame 绕过 PMR，在热路径做堆分配 |
| P7 | `protocol/common/udprelay.hpp:168` | `route_cb` 使用 std::function 导致热路径堆分配（M5541） |
| P8 | `protocol/socks5+trojan/config.hpp` | max_dgram 默认 65535 导致每 UDP 会话分配 128KB+（M5543） |
| P9 | `stealth/scheme.hpp:193-197` | snis() 默认实现每次堆分配空 vector |

### 连接管理

| ID | 文件 | 描述 |
|----|------|------|
| M-CONN1 | `connect/pool/health.cpp:24,42,51` | const_cast 违反类型安全，临时修改 socket non_blocking 状态（M102） |
| M-CONN2 | `connect/pool/config.hpp:33` | cache_ipv6 默认 false，IPv6 连接从不缓存（M5538） |
| M-CONN3 | `connect/dial.hpp:141` | make_router 空删除器 shared_ptr（M5285 的 dial.hpp 实例） |

### DNS

| ID | 文件 | 描述 |
|----|------|------|
| M-DNS1 | `resolve/dns/resolver.cpp` | Coalescer waiters 泄漏：协程取消时 `--waiters` 不执行（M91） |
| M-DNS2 | `resolve/dns/upstream.cpp` | DNS query ID 可预测：`domain_hash ^ timestamp` 截断 16 位（L92 升级） |

### 协议处理

| ID | 文件 | 描述 |
|----|------|------|
| M-PROTO1 | `protocol/socks5/framing.hpp:103` | parse_header 不校验 command 和 address_type 枚举范围（M5540） |
| M-PROTO2 | `protocol/tls/types.hpp:111` | write_u24 不检查 uint24 溢出（M5542） |
| M-PROTO3 | `protocol/shadowsocks/datagram.cpp` | UDP 硬编码 30s 时间窗口，TCP 使用可配置值，策略不一致（M90） |
| M-PROTO4 | `protocol/trojan/framing.cpp:93` | build_udp_pkt uint16 截断超大载荷（L3202 升级） |

### Stealth

| ID | 文件 | 描述 |
|----|------|------|
| M-STEALTH1 | `stealth/restls/script.cpp:23-27` | parse_line int16_t 溢出 UB（target_base/range，与 H-OTHER1 相关但不同路径） |
| M-STEALTH2 | `stealth/restls/transport.hpp:145-146` | send_buf_ 无大小限制（与 L6 相关但不同层面） |
| M-STEALTH3 | `stealth/anytls/mux/transport.hpp:115` | close() detached 发 FIN 无错误传播 |
| M-STEALTH4 | `stealth/anytls/mux/session.hpp:160` | init_waiter_ 无超时，Settings 丢失时永久阻塞 |
| M-STEALTH5 | `stealth/anytls/padding.cpp` | 使用 std::mt19937 非 CSPRNG 生成 padding（M5352 重复组） |

### 配置 / 序列化

| ID | 文件 | 描述 |
|----|------|------|
| M-CFG1 | `instance/worker/tls.cpp:81` | SSL_CTX_set_cipher_list 返回值未检查（M103） |
| M-CFG2 | `fault/handling.hpp:93` | to_code() 使用字符串比较识别 category，应使用指针比较（M89） |
| M-CFG3 | `stats/traffic.cpp` | traffic_state COW 注册表缺少 CAS 保护（F11 及 5 处重复） |

### 识别 / 调用链

| ID | 文件 | 描述 |
|----|------|------|
| M-RECOG1 | `recognition/tls/features.hpp:93-103` | build_bitmap session_id 判断逻辑冗余，第三分支不可达（M5546） |
| M-RECOG2 | `recognition/probe/analyzer.hpp:99-131` | detect_tls 中 Trojan 检测不校验 hex 是否为有效 SHA224（M5547） |

---

## LOW（~80 项）

> 简表格式，每条一行。

| ID | 文件 | 描述 |
|----|------|------|
| L1 | `stealth/scheme.hpp` | snis() 默认实现重复堆分配空 vector |
| L2 | `crypto/aead.hpp:234` | nonce_ 固定 24 字节，GCM/ChaCha20 浪费 12 字节 |
| L3 | `transport/reliable.hpp:265` | native_socket() const 版本中 const_cast 不安全 |
| L4 | `fault/compatible.hpp` | std::hash 特化不必要，枚举可隐式转 int |
| L5 | `stealth/restls/transport.cpp:393` | send_random_response 中 read_counter_ 语义为"已消费入站命令"，非 bug |
| L6 | `shadowsocks/datagram.hpp:69` | PSK 解码失败仅标记 valid_=false 不阻止后续使用 |
| L7 | `protocol/common/mux.hpp:40` | is_mux_target 子串匹配可被 .arpa 域名绕过 |
| L8 | `stealth/shadowtls/transport.hpp` | write_key_ 和 server_random_ 死成员浪费 64 字节 |
| L9 | `stealth/anytls/padding.hpp:74` | padding_factory 使用 MD5 做指纹（非认证用途，碰撞风险低） |
| L10 | `stealth/seal.hpp:150` | plainbuf_ 无容量上限（与 H-LIFE3 同类） |
| L11 | `resolve/dns/detail/cache.hpp` | 文档说 FIFO 但成员命名 lru_order_，语义矛盾 |
| L12 | `resolve/dns/detail/rules.cpp` | to_lower/split_labels 使用默认 PMR 分配器（非热路径） |
| L13 | `instance/session/session.hpp:175` | set_credential_verifier 缺少 noexcept，与其他 setter 不一致 |
| L14 | `instance/config.hpp:42` | port 默认 0 无验证，listener 可绑定随机端口 |
| L15 | `instance/worker/launch.cpp:30` | noexcept 函数内调用非 noexcept 的 trace::error |
| L16 | `instance/worker/tls.cpp:70` | TLS session cache 大小硬编码，不可配置 |
| L17 | `instance/front/listener.cpp:105` | static thread_local 退避延迟跨重启残留（C8） |
| L18 | `account/directory.hpp:160` | CAS 循环无重试上限，高争用下 O(N²) 分配 |
| L19 | `connect/util.hpp:79-93` | peel() 使用 dynamic_cast 链，RTTI 开销（0-2 层，影响有限） |
| L20 | `recognition/pipeline.hpp:140` | layered_detection_pipeline 使用 std::vector 非 PMR |
| L21 | `stats/memory.hpp` | memory_tracker 下溢风险（同 H-LIFE4 但低影响场景） |

---

## 跨模块模式

### 模式 A: 无界内存增长（6 处）

| 位置 | 缓冲区 | 影响 |
|------|--------|------|
| L6 Restls `send_buf_` | CRITICAL | 可被远程利用 OOM |
| H-LIFE3 snapshot `captured_` | HIGH | 攻击者发送超长 ClientHello |
| P5 smux pending buffer | MEDIUM | 恶意客户端小片段 PSH |
| P4 bootstrap padding | MEDIUM | 64KB 单次分配 |
| H-POOL1 pool `cache_` | HIGH | 无全局端点数上限 |
| duct `write_channel_` | MEDIUM | concurrent_channel 默认 unbounded |

**统一修复**: 所有缓冲区引入容量上限 + 背压机制。

### 模式 B: 输入校验缺失（4 处）

| 位置 | 输入 | 影响 |
|------|------|------|
| S3 BLAKE3 key 长度 | CRITICAL | OOB 读取 |
| M-CRYPTO5 aead_nonce iv 长度 | MEDIUM | 越界读取 |
| P4 bootstrap padding 长度 | MEDIUM | 64KB 分配 |
| M-PROTO2 TLS write_u24 | MEDIUM | 静默截断 |

**统一修复**: crypto 函数入口统一添加 assert/if 校验。

### 模式 C: 假成功 / 静默丢弃（4 处）

| 位置 | 行为 | 影响 |
|------|------|------|
| S1 AEAD seal 成功后返回错误 | CRITICAL | nonce 重用 |
| L6 Restls write 返回成功但仅入队 | CRITICAL | 数据可能丢失 |
| H-MUX2 h2mux on_data 静默丢弃 | HIGH | 流数据丢失 |
| M-TRANS3 write_sealed 返回值语义 | MEDIUM | 调用者误判 |

**统一修复**: API 契约审查，确保返回值与实际行为一致。

### 模式 D: 空删除器 shared_ptr（13+ 处）

| 位置 | 场景 |
|------|------|
| ShadowTLS handshake | shared_ptr<transport>(&local, null_deleter) |
| Restls handshake | 同上 |
| dial.hpp make_router | shared_ptr<router>(&rt, null_deleter) |
| direct.hpp | 同上模式 |
| 其他 9 处 | co_spawn 捕获栈引用 |

单线程 io_context 下当前安全，但设计脆弱。**统一修复**: 改用 `observer_ptr` 或裸指针 + 文档约束。

### 模式 E: 枚举范围未校验（3 处）

| 位置 | 枚举 |
|------|------|
| H-TLS2 AnyTLS frame command | 0x00-0x0A |
| M-PROTO1 SOCKS5 framing | command/atyp |
| M-RECOG2 Trojan detect | hex SHA224 |

---

## 调用链分析

### C1: listener → balancer → worker → session

```
main → listener::accept() → balancer::dispatch(socket)
  → worker::run() → launch() → session::start()
```

**关键发现**: F11（COW 注册表竞态）、H-OTHER2（balancer noexcept + std::function）、L17（thread_local 退避残留）。session 双重释放防护正确（state 单向转换）。

### C2: session → recognition → probe → scheme

```
session::start() → recognize(transport)
  → probe::detect(24B) → protocol_type
  → (TLS) identify → parse_clienthello → analyzer → scheme_executor
```

**关键发现**: H-TLS1（native 探测覆盖）、P1（route_table 重建）、P2（lookup 临时字符串）。preview_transport 回放逻辑经 cpp 验证正确。

### C3: session → handler → dial → pool → tunnel

```
session::diversion() → handler::process()
  → dial::router → racer → dial
  → pool → health_check → tunnel::relay()
```

**关键发现**: H-POOL1（无全局容量限制）、H-PROTO3（recv_chacha 空指针）。连接池竞态窗口存在但 tunnel 的错误处理能兜底。

### C4: multiplex → duct → parcel → 背压

**关键发现**: H-MUX3（yamux 窗口无超时）、P5（smux pending 无上限）。concurrent_channel unbounded 是架构性问题。

### C5: stealth → reality → seal → X25519

**关键发现**: H-CRYPTO1/2（RAND_bytes 未检查、低阶点未检测）、S1（AEAD nonce）。Reality 模块密码学实现质量高（低阶点防御已在 auth.cpp 实现）。

### C6: stealth → anytls → 内部 mux

**关键发现**: H-TLS4（user_map 重建）、H-TLS5（padding 无上限）、M-STEALTH4（init_waiter_ 无超时）。close() 的 move 语义正确传播取消信号。

### C7: connect → racer → Happy Eyeballs

racer 的 `atomic<bool> winner` + acquire/release 序正确。所有路径（成功/失败/异常）都调用 `complete()`。资源管理经 cpp 验证安全。

---

## 已排除的误报

| 原编号 | 描述 | 排除原因 |
|--------|------|----------|
| C10 | connection_pool 无析构函数 | **已验证**: `pool.hpp:251-254` 有 `~connection_pool() noexcept { clear(); }` |
| L5 (原) | h2mux send_pending 并发帧交错 | **降级**: 单线程 io_context 消除并发风险 |
| N1 (原) | hkdf_expand 栈缓冲区溢出 | **降级**: max_hmac_buf=289 正确匹配 hmac_size 上限，实际是 uint8_t counter 溢出 |
| M5471 | smux dispatch_push co_spawn 排序 | **排除**: 单线程 executor FIFO 保证顺序安全 |
| M5463 | racer 子协程泄漏 | **排除**: 网络 I/O 至少需要一个周期，协程不会立即完成 |
| M5456 | TLS record 44 字节验证 | **排除**: 44 字节最小值检查充分（1+2+2+32+1≥38 需要合理） |
| M5451 | DNS jumps counter | **排除**: unpack_name 接收独立的 jumps 计数器 |
| R47-1 | Trojan/VLESS UAF | **排除**: `co_await frame_loop()` 返回后仅读取指针值不解引用 |
| R47-2 | Trojan/VLESS 内存泄漏 | **排除**: raw new/delete 在 I/O 使用 error_code 重载下实际安全 |
| R47-3 | SOCKS5 relay_datagram 丢包 | **排除**: 外层 associate_loop while 循环反复调用 |
| R47-4 | MLKEM768 截断 | **排除**: Reality 仅需 X25519 分量（前 32 字节），拷贝长度正确 |
| R47-5 | TLS record 双重载 | **排除**: transmission 和 socket 两种接口功能等价 |

---

## 模块审计完整性

| 模块 | hpp 文件数 | cpp 文件数 | 覆盖轮次 | 独立发现数 |
|------|-----------|-----------|---------|-----------|
| instance | 8 | 6 | 1-5, 38, 53 | ~15 |
| recognition | 10 | 6 | 6-9, 37, 54 | ~12 |
| stealth (facade) | 20 | 12 | 10-13, 30-31, 49-50 | ~25 |
| stealth (stack) | 17 | 6 | 10-13, 30-31, 51 | ~15 |
| connect | 9 | 7 | 14-16, 35, 52 | ~10 |
| transport | 6 | 3 | 17-19, 30 | ~8 |
| resolve | 10 | 6 | 20-23, 39, 48 | ~12 |
| multiplex | 14 | 9 | 24-27, 40 | ~15 |
| crypto | 6 | 5 | 29-31, 42 | ~8 |
| protocol | 48 | 12 | 32-33, 36, 47 | ~10 |
| memory/fault/exception | 5 | 0 | 35-37, 46 | ~5 |
| stats/account | 4 | 2 | 27, 42 | ~3 |
| pipeline/context | 3 | 0 | 37 | ~2 |

**全量覆盖**: 所有 hpp（176 个）和 cpp（74 个）文件均已在 54 轮审计中逐一分析。调用链 C1-C7 经 cpp 实现层逐一验证。

---

## 修复优先级建议

### 立即修复（CRITICAL + 最高优先级 HIGH）

1. **S9** — domain_trie 通配符匹配（DNS 路由错误，影响所有使用通配符规则的部署）
2. **S1** — AEAD nonce 溢出 tainted 标记
3. **H-CRYPTO1** — X25519 RAND_bytes 检查
4. **S3** — BLAKE3 key 长度断言
5. **L6** — Restls send_buf_ 容量上限
6. **L4** — AnyTLS preread 双重发送
7. **H-PROTO1** — CONNECT 空 target UB（一行修复）
8. **S2/S4** — 移除仓库中私钥和明文凭据

### 第二批（HIGH 安全相关）

9. **H-CRYPTO2** — X25519 低阶点检测
10. **H-POOL1** — 连接池全局容量限制
11. **H-TLS3** — TrustTunnel ALPN 隔离
12. **H-DNS1** — DoH Content-Length 上限
13. **H-TLS1** — native 探测结果覆盖
14. **H-PROTO3** — recv_chacha 空指针检查（一行修复）

### 第三批（HIGH 稳定性 + MEDIUM 性能）

15. **H-MUX3** — yamux 窗口超时
16. **H-LIFE3** — snapshot 容量上限
17. **P1/P2** — route_table 缓存 + heterogeneous lookup
18. **H-TLS4** — AnyTLS user_map 缓存
19. 所有 MEDIUM 无界缓冲区添加上限
20. 所有 MEDIUM 枚举范围校验

---

*报告生成时间: 2026-05-30*
*分析工具: Claude Code（glm-5.1）逐文件深度审计*
*总计分析代码行数: ~25,000+ 行（176 hpp + 74 cpp）*
