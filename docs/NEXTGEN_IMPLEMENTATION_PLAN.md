# Prism Next-Gen 实施计划

> 当前权威本地门禁（2026-09-11）：Release 构建 exit `0`；功能并行 `3853/3853`，
> perf/stress 串行 `94/94`，CTest 注册 `3972`、active `3947`、`25` 个测试明确
> Disabled；`Perf_Recognition` `936.62s`，perf/stress 标签时间 `957.38s`，全量墙钟
> `957.67s`。以下较早状态行
> 保留为历史快照；Gate D 仍受外部 L5、carrier endpoint 和生产 analyzer 前置阻塞。

> 2026-09-11 P-M05：TaskRegistry 为 tracked 协程绑定独立 cancellation slot，
> `Cancel()` 只请求取消，`CancelAndWait()` 在同一 executor 上非阻塞等待 token
> 真正释放或超时；Preview/生产注册表与 OwnershipAudit 回归已通过。

> 2026-09-11 P-M07：TokenBucket 的时间戳、补发乘法和令牌加法改为饱和算术，
> 极值时间轴与超大补发计数不再污染打包状态；TokenBucket/Throttle/Ban focused 已通过。

> 2026-09-11 P-M08：FlatBuffer 增长与 Parser 帧长计算增加上限/溢出防护，Parser
> 要求 Config 声明 `MaxPayloadLen`；超限输入清空并返回 `BadLength`，`Want()` 只报告
> 未消费 payload，FlatBuffer/smux/h2mux focused 已通过。

> 2026-09-11 P-M10：静态认证路径统一使用 `Preview::ConstantTimeEqual`，覆盖二进制
> UUID/token、用户名/密码和 Basic Auth，身份与密码比较不再短路；相关 focused 已通过。

> 2026-09-11 P-M11：ProbeDefenseTracker 查询/记录路径主动清理过期来源，容量达到
> 上限时淘汰最旧项，`MaxRecords=0` 拒绝插入，并支持可注入时钟；窗口和容量回归已通过。

> 2026-09-11 P-M12：SNI 路由表改用不可变 COW 快照原子发布，查询按值返回；单标签
> 通配后缀改为哈希查找，避免并发更新数据竞争和每次 O(N) 扫描；路由回归已通过。

> 2026-09-11 P-M09：通用地址编码改为严格校验并回滚失败输出，协议构造器不再把
> 非法 IPv4/IPv6/域名变成可发送的错误 wire；跨协议地址回归已通过。

> 2026-09-11 P-M13：IdentityTraffic/TrafficCounter 增加可配置最大 identity 数，
> 达到上限拒绝新 key、保留已有 key 的精确统计，避免无界 COW 快照复制；容量回归已通过。

> 2026-09-11 P-M14/P-M15：Profile 增加 route/name/scheme 元数据预算并接入 Settings，
> HTTP/1 parser 严格校验请求行和头字段、拒绝重复安全头与折叠；PreparedState 内部大小
> 仍由候选实现负责，Http11/Profile/Settings focused 已通过。

> 2026-09-11 P-M16：Preview QPACK 静态解码增加头块/字段数/单字段输出预算并继续拒绝
> 动态表指令；QpackInterop focused `11/11` 通过，nghttp3 第三方内部状态仍单独保留。

> 2026-09-11 P-M17：AnyTLS `SendBytes` 拒绝零进展和超额写入，避免握手循环卡死或
> offset 越界；新增 zero-progress/over-reporting 回归通过。

> 2026-09-11 P-M23：TrustTunnel、SOCKS5、Trojan 和 VLESS datagram 的发送循环、
> 精确读取窗口与 payload 窗口拒绝底层 over-report，并传播 `BadLength`；相关回归与
> Hysteria2/TUIC 错误矩阵合计 `66/66` 通过。

> 2026-09-11 P-M24：AnyTLS、Reality、VMess 和 SS2022 的精确读取/写入辅助拒绝
> 底层 over-report，避免错误数据被当成有效握手或推进偏移；新增回归 `5/5` 通过。

> 2026-09-11 P-M25：ShadowTLS `ReadExact()` 拒绝底层 over-report，新增回归纳入
> ShadowTLS/VMess 错误集合，focused `15/15` 通过。

> 2026-09-11 P-M26：Mux 精确读、VLESS Conn 读写以及 SS2022 UDP 临时缓冲/发送循环
> 拒绝底层 over-report；新增公开握手和 Mux 回归，focused `19/19` 通过。

> 2026-09-11 P-M27：Common `ReadMin/ReadRemaining` 修复 Preview 传输类型并拒绝
> over-report；HTTP/1.1、SOCKS5、Trojan、VMess、VLESS 的读写/拼接路径，以及
> WebSocket、Gun、TrustTunnel 握手读循环和 HTTP/2/XHTTP 驱动均在使用返回长度前
> 校验目标窗口；新增 focused `117/117`，生产目录未修改。

> 2026-09-11 P-H10：SampleTracer 对 RingSize 执行非零/二次幂校验和 65536 容量封顶，
> 防止位掩码索引越界及极值分配；Observability focused 回归已通过。

> 目标：把 tests/common 中的 preview 协议组件库，逐步收敛为可验证、可对拍、可选择性迁移到生产栈的新一代架构。
>
> 本计划不等同于立即把 tests/common 搬入 src/prism。迁移必须建立在公共层正确性、完整纵向链路和生产对拍结果之上。
>
> 当前状态（2026-09-10）：阶段 0～4 的既有 Gate A/B/C 证据保留；Preview 已补齐 XHTTP 标准字段、客户端工厂与 request half-close、TrustTunnel 标准 TLS/HTTP2 CONNECT、SS2022 TCP raw PSK、VLESS 非法 ATYP、标准二进制 VLESS 结构识别、VLESS UDP over TCP 标准长度分帧、VMess 标准 AEAD ChunkMasking/response wire、HTTP/2/HPACK 负向校验、HTTP/2 connection preface、TLS/SNI 基础解析、Configured/DeterministicRoute/MixedTrial 三种识别模式、TLS route selector/ClientHello boundary、HTTP authority IPv6 校验、空 route 防隐式 default、Session/Dial/Listener 失败收口（含 detached session 异常、scheme exception replay/close、Snapshot partial+error replay、carrier scheme exception）、ShadowTLS v3 标准 ClientHello/ServerHello parser、stateful application-data record protector 和 server relay、TLS carrier→内层 handler 组合和 native ngtcp2 QUIC UDP 回环。最新本地 Release 构建通过，CTest 注册 `3874` 项、`3849/3849` active 通过、`25` 个 StealthNested2 明确 Disabled；`Perf_Recognition` `723.21s`、全量墙钟 `846.49s`；G7/mirror `260/260`、detached `DANGEROUS=0`。外部矩阵当前为 63 条机器记录（54 pass、9 blocked、0 failure），其中 5 条为 carrier `interface-gap`、1 条为 native TLS `environment-unavailable`、3 条为生产 analyzer `blocked-production-prerequisite`；HTTP、SOCKS5、VLESS、Trojan、VMess、SS2022 六个真实单端口识别记录均通过，`recognition_coverage_complete=true`。本轮还加入确定性首字节冲突的编译期拒绝、route-aware TLS SNI 派生、Probe partial+error 字节保留、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、VMess/SS2022 serializer 随机失败收口、QUIC/HTTP3 随机回调失败收口。HTTP CONNECT、SOCKS5、Trojan、VLESS、VMess、AnyTLS、WebSocket、TrustTunnel、XHTTP、Hysteria2、TUIC 已完成独立 reference authenticated-echo 或标准 codec/vector；完整网络性能对拍和全协议 L5 仍未闭合。VLESS/Trojan/VMess 真实生产单端口 echo 仍是 `blocked-production-prerequisite`，迁移决策矩阵已生成但没有协议满足 `migrate`。生产目录本轮不修改。

> 历史本地门禁（2026-09-10）：CTest 注册 `3867` 项，`3842/3842` active 通过，
> `25` Disabled，`Perf_Recognition` `676.26s`，全量墙钟 `802.33s`；最终权威结果见
> 上方当前状态段，不再使用本段数字作为当前基线。

> 2026-09-11 fresh 生产复核：Release 全量构建和普通功能 `3855/3855` 通过；完整
> 外部矩阵保持 `63 total / 54 pass / 9 blocked / 0 failed`。临时配置 L4 echo 中
> SOCKS5、SS2022、VMess 通过，VLESS/Trojan 仍被生产 analyzer/fallback 阻塞；
> GoCompat 单次 `4/4` 通过，TUIC 独立 5 次 `4/5`（一次首连接 timeout）。历史
> VMess fallback 失败分析保留为待观察证据，不再作为当前必现结论；生产目录本轮不修改。

> 外部识别矩阵随后扩展为 `63 total / 54 pass / 9 blocked / 0 failed`：新增 sing-vmess
> TCP-only 与 sing-shadowsocks SS2022 reference client → Preview `MixedTrial` 单端口
> authenticated-echo，HTTP/SOCKS5/VLESS/Trojan/VMess/SS2022 六条真实识别均通过。

> Pad 配置映射后的历史本地门禁：CTest `3868` 注册、`3843/3843` active 通过、`25`
> Disabled、失败 `0`；`Perf_Recognition` `682.03s`，全量墙钟 `817.40s`。

> Pad CSPRNG 失败收口后的历史本地门禁：CTest `3869` 注册、`3844/3844` active 通过、
> `25` Disabled、失败 `0`；`Perf_Recognition` `698.72s`，全量墙钟 `807.99s`。

> TrustTunnel/DNS/Pad 历史本地门禁：CTest `3870` 注册、`3845/3845` active 通过、
> `25` Disabled、失败 `0`；`Perf_Recognition` `707.47s`，全量墙钟 `816.59s`；
> 外部矩阵 `63 total / 54 pass / 9 blocked / 0 failed`。

> DNS First 生命周期随后收口：每个 detached loser 使用独立 cancellation signal，首胜后
> 取消并等待所有 worker 完成；DnsUpstream focused `34/34` 通过，owner release 回归已纳入门禁。
>
> 2026-09-05 双模式配置接线：Composition 新增 `SettingsBuilder`，将 Settings candidate 工厂、immutable Profile 与 resolver 成对安装到 `SessionOptions`，并可直接生成 `TcpListener::SessionFactory`；`ConfiguredCandidate` 在 `MixedTrial` 中被拒绝，避免无效配置。Profile route 已在 Configured/MixedTrial coordinator 中按完整 ClientHello/SNI 裁剪候选；显式 `DefaultCandidate` 可作为缺失 SNI 的受控 fallback，候选元数据保留实际外层 `Scheme`；核心六种 TCP 协议现可通过 `CandidateRegistry` 使用不可变 typed builder，完整凭据、custom carrier 和 QUIC 参数仍由 Composition 入口显式提供。

> 2026-09-10 双模式 Session 接线新增 `DeterministicProfileResolvesByStructuralSelector`、确定性首字节冲突编译期拒绝、route-aware TLS SNI 派生、Probe partial+error 字节保留、legacy Pipeline 预取消控制和窗口读取性能回归、协议认证标记和账户租约传递、错误 coordinator mode guard、canonical mode 名称、Settings idle timeout 映射、`AuthRequired` 缺省认证器拒绝、TLS Session ID 长度、重复扩展、deterministic route 目标边界、ECH 无 inner Hello 时拒绝、MaxConnections listener 装配和认证器共享所有权回归；最新全量 CTest 为 `3858` 注册、`3833/3833` active 通过、`25` Disabled，失败 `0`，`Perf_Recognition` `765.00s`，全量墙钟 `897.21s`。
>
> Settings candidate 现可表达 `Scheme`、`ServerNames`、`Alpn`，并接受 `hysteria2`/`tuic` 协议名；协议名统一为 ASCII 小写，`ServerNames`/`Alpn` 可随外层 `Scheme` 显式提供，只有 `Scheme + Recognition.Routes` 时由 SettingsBuilder 将 route pattern 派生为 TLS inspector 的 ServerNames；TCP Profile 会在编译期拒绝 QUIC 候选；真实 carrier、凭据和 QUIC 会话仍由 Composition/QUIC 工厂负责。
>
> Hysteria2 外部闭环已由 `Http3::NativeServerSession` 接通：异步 provider 生命周期、stream ID、nghttp3 输出偏移和认证后 raw bidi stream 均在同一 executor 串行处理；认证响应保持 HTTP/3 stream 打开，避免客户端后续 QUIC raw stream 被过早关闭。`InteropHysteria2` 与独立 `sing-quic` client authenticated-echo 已在矩阵中稳定通过；Preview NativeClient 的正常 QUIC FIN 修复后，reference server→Preview client 方向也已通过；reference UDP→Preview authenticated-UDP-echo 已通过。完整 QUIC L5 仍待补。

> 2026-09-07 识别策略增量：在保留 `Configured` 单候选兼容入口的基础上新增 `DeterministicRoute`。
> 该模式允许多个带首字节或 TLS route 选择器的候选，结构歧义在认证前返回 `Ambiguous`；
> `MixedTrial` 仍是显式配置的有界认证试探模式。三者共享 Profile、ProbeBuffer、Snapshot、
> Candidate resolver 和 carrier 分层，QUIC 仍由独立 UDP gateway 处理。

> 注意：上面的状态行保留了早期快照；当前权威基线见本文开头的 `3961` 注册、
> `3936/3936` active 通过结果。

> 2026-09-10 历史本地复核：CTest 注册 `3858` 项、`3833/3833` active 通过、`25` 个
> `StealthNested2` 明确 Disabled；全量墙钟 `897.21s`，`Perf_Recognition` 正式运行 `765.00s`。

## 1. 总体设计

当前项目有两套相互参照的实现：

~~~text
生产栈：psm::...
  ├─ src/prism/
  ├─ include/prism/
  └─ 当前代理服务与生产测试

新架构栈：preview::...
  ├─ tests/common/core/
  ├─ tests/common/protocols/
  └─ tests/preview/
~~~

preview 当前定位为：

- 新架构实验场；
- 协议参考实现；
- client/server 回环测试库；
- 生产协议的 golden model；
- 未来迁移候选。

在完成纵向验证前，不把它直接定义为生产实现，也不直接将整个目录搬入 src/prism。

最终请求链路：

~~~text
listener
  → runtime/session
    → recognition
      → protocol::accept
        → middleware::pipeline
          ├─ auth
          ├─ dial
          ├─ mux
          ├─ pad
          └─ relay
            → outbound/dialer/dns/route
              → upstream
~~~

各层职责：

| 层 | 负责 | 不负责 |
|---|---|---|
| transmission | 异步读写、关闭、取消、半关闭、超时、装饰器导航 | 协议解析、DNS、路由 |
| protocol conn | 握手、认证、帧编解码、目标地址、协议数据面 | 上游路由、统计编排 |
| recognition | 首包、TLS、SNI、协议类型识别 | 建立上游连接 |
| middleware | 认证、拨号、复用、填充、转发 | 嵌入具体协议格式 |
| outbound | DNS、路由、TCP/UDP 拨号 | 入站协议握手 |
| runtime/session | 请求生命周期和模块编排 | 手写协议帧 |
| resource | process/worker/session 生命周期和资源归属 | 业务转发流程 |

## 2. 用户指定的代码风格

新代码以 src/prism/protocol/multiplex/smux/control.cpp:225 的协程表达式风格为准：

~~~cpp
auto async_push = [self, sp, payload = std::move(payload)]() mutable
    -> net::awaitable<void>
{
    co_await sp->on_data(std::move(payload));
};

auto on_error = [sp](const std::exception_ptr &ep)
{
    if (ep)
    {
        log_spawn_error(ep, 0, "dispatch stream data");
        sp->close();
    }
};

net::co_spawn(transport_->executor(), std::move(async_push), std::move(on_error));
~~~

新代码约束：

- async_task、on_error、co_spawn 分开书写；
- 协程和完成处理器交给 co_spawn 时使用 std::move；
- shared_ptr 按值捕获，确保 detached 协程保活；
- detached 协程禁止捕获 session 局部变量的引用或裸指针；
- 错误回调必须关闭 stream、删除 datagram 状态、结束 session 或传播错误；
- 不使用没有错误处理的裸 net::detached，除非有明确理由；
- 非基本返回类型使用换行的后置返回类型；
- 不批量格式化与当前单元无关的旧代码。

例如：

~~~cpp
auto connect_target(...)
    -> net::awaitable<std::pair<fault::code, shared_transmission>>
{
    ...
}
~~~

基本类型可以保持紧凑：

~~~cpp
auto is_open() const noexcept -> bool
{
    return open_;
}
~~~

## 3. 阶段计划

### 阶段 0：冻结真实基线

状态：已完成。

工作内容：

1. 盘点每个协议的 codec、conn、dgram、client/server、错误矩阵、回环、互操作、性能和 stress 状态；
2. 盘点 preview runtime 是否真的能完成 listener → session → pipeline → relay；
3. 更新 docs/TASK_PROGRESS.md 中已经过时的状态；
4. 建立 docs/ngx-test-data/INDEX.md；
5. 建立 docs/ngx-test-data/protocol-matrix.md；
6. 明确 preview 是参考实现、替换候选还是最终目标实现；当前默认按“参考实现 + 替换候选”处理。

每个协议至少标记：

~~~text
codec / session / preview loopback / production interop /
external interop / performance / stress / fuzz
~~~

不把“有头文件”或“自回环通过”直接判定为完成。

### 阶段 1：公共层正确性收口

状态：已完成。

优先文件：

~~~text
tests/common/core/middleware/builtin/relay.hpp
tests/common/protocols/xhttp/conn.hpp
preview/Transport/MemoryStream.hpp
tests/common/protocols/mux/session.hpp
~~~

1. relay：上行和下行必须使用独立 buffer，同时审查统计、idle timer、EOF、error、cancel、timeout 和 half-close 的关闭顺序。
2. XHTTP：pending 数据的所有权必须转移给异步任务，禁止成员容器清空后仍使用其 span；channel 满时禁止静默丢协议数据。
3. memory_stream：明确单 executor/单线程模型，或通过 strand 支持跨线程；文档、接口和实现必须一致。
4. MUX：区分可忽略控制帧、stream 可恢复错误、必须关闭 session 的错误；非法帧和 payload 超限不能无条件 continue。

阶段 1 的回归测试：

~~~text
RelayFullDuplex
RelayHalfCloseUpstream
RelayHalfCloseDownstream
RelayConcurrentBidirectionalTransfer
RelayIdleTimeout
RelayReadError
RelayWriteError
XhttpPendingFlush
XhttpChannelBackpressure
MemoryStreamCloseWhileReadPending
MemoryStreamCancelWhileReadPending
MemoryStreamTimeoutWhileReadPending
MuxMalformedFrameClosesSession
MuxPayloadLimitClosesSession
MuxClosedStreamData
~~~

阶段 1 验收记录：

- relay：独立双向 buffer、半关闭、部分写、超时、错误和幂等关闭已收口；`TimeoutRelay.*` 7/7，`MiddlewarePipeline.DialRelayEcho` 1/1；
- XHTTP：pending flush 已转移 payload 所有权，channel 满载不再静默丢 DATA；`XhttpErrorMatrix.*` 5/5；
- memory stream：明确单 executor 约束，并覆盖 close/cancel/timeout 的挂起读；`Transport.*` 15/15；
- MUX：非法帧和 payload 超限会关闭 session，既有 session 回归共 20/20 通过；
- 未执行 git commit、push 或 amend；未修改生产 `src/prism` 协议代码。

### 阶段 2：协议完成度矩阵和测试门禁

状态：进行中。

| 等级 | 含义 |
|---|---|
| L1 | codec 纯函数正确性 |
| L2 | conn/session 握手与数据面 |
| L3 | preview client/server 回环 |
| L4 | preview 与生产 Prism 对拍 |
| L5 | 与 mihomo、sing-box、quic-go、sing-quic 等外部实现互操作 |

每个协议检查：半包、非法输入、认证失败、timeout、cancel、half-close、TCP、UDP、MUX、生产对拍、外部互操作、性能、stress、fuzz。

阶段 2 当前动作：

1. 以 [docs/ngx-test-data/protocol-matrix.md](ngx-test-data/protocol-matrix.md) 固化“有代码”和“有证据”的区别；
2. SOCKS5 TCP CONNECT 纵向链路已打通全部 Gate B 场景（认证/失败/变体/半关闭/超时/统计/异常）；
3. VLESS 已复用同一 runtime 编排验证抽象（Gate C 通过）；

### 阶段 3：SOCKS5 第一条纵向链路

状态：已完成（Gate B 通过）。

第一条完整链路只做 SOCKS5 TCP CONNECT：

~~~text
listener
  → session
    → socks5::accept
      → auth middleware
        → dial middleware
          → relay middleware
            → loopback upstream
~~~

首批范围：

- 无认证或用户名密码认证；
- IPv4、IPv6、domain 目标；
- 上游成功和失败；
- 双向连续传输；
- half-close；
- timeout、cancel、read error、write error；
- session 正常关闭和异常关闭；
- traffic 统计。

TCP 稳定后再增加 UDP ASSOCIATE，不同时引入 QUIC、MUX 和 TLS。

验收要求：runtime 不复制 SOCKS5 专属拨号和 relay 逻辑；协议 conn 只负责握手、目标和数据面；关闭后没有悬挂任务和未清理 stream。

验收记录（`tests/preview/core/runtime/ListenerE2ETest.cpp` 14/14、`SessionOrchestrationTest.cpp` 5/5 通过）：

- `TcpListener.Socks5TcpConnectFullChain`：真实 `socks5::accept` → target → dial → relay → echo；
- CONNECT 应答“拨号后发送”：`server_config::defer_connect_reply` + `conn::send_connect_reply`，由 `middleware::context::post_dial` 回调在拨号成功/失败后发送协议级应答；
- `Socks5TcpConnectDialRefused`：上游拨号拒绝时客户端收到正确的 `connection_refused` 错误码；
- `Socks5TcpConnectAuthSuccess` / `Socks5TcpConnectAuthFailure`：RFC 1929 用户名密码认证；
- `Socks5TcpConnectIpv4` / `Socks5TcpConnectIpv6`：地址变体；
- `Socks5TcpConnectHalfCloseClient`：客户端半关闭后下行仍可读；
- `Socks5TcpConnectIdleTimeout`：relay 空闲超时关闭；
- `Socks5TrafficReport`：relay 结束点流量上报；
- `Socks5TcpConnectUpstreamAbort`：上游 accept 后立即关闭 → 读侧 EOF；
- `StopStopsAccepting` / `ConnectionStorm`：listener 生命周期与并发。

UDP ASSOCIATE 数据面（真实 UDP 语义，`tests/preview/core/runtime/Socks5UdpE2ETest.cpp` 5/5 通过）：

- 新增 `tests/common/protocols/socks5/udp_assoc.hpp`：UDP 关联数据面服务（bind → BND 应答 → 双向帧循环 → 空闲超时 → TCP 控制断开终止）；
- runtime session 增加协议无关 dgram 分支：`middleware::context::is_dgram` + `session_options::udp_service`（SOCKS5 与未来 VLESS UDP 共用）；
- `Socks5UdpAssociateEcho`：client TCP 握手 → BND 端口 → UDP 帧往返 echo（domain/ipv4 目标）；
- `Socks5UdpAssociateBadFrame`：FRAG≠0 非法帧丢弃，关联不中断；
- `Socks5UdpAssociateIdleTimeout`：空闲超时关闭数据面；
- `Socks5UdpAssociateTcpCloseTerminates`：TCP 控制连接断开终止数据面；
- 修复：`socks5::conn` 公开 `send_assoc_reply`（带 BND 地址应答）。

### 阶段 4：VLESS 扩展验证

状态：已完成（Gate C 通过）。

用 VLESS 验证 UUID 认证、TCP 命令、地址解析、identity 统计，以及与 SOCKS5 共用 runtime、middleware、outbound、relay。

如果 VLESS 接入时需要复制一套 runtime/middleware 编排代码，先暂停协议接入，修正抽象边界。

验收记录（`tests/preview/core/runtime/VlessE2ETest.cpp` 9/9、`RecognitionTest.cpp` 13/13 通过）：

- `TcpListener.VlessTcpConnectFullChain`：真实 `vless::accept` → target → dial → relay → echo；
- `VlessTcpConnectBadUuid`：UUID 不匹配时服务端静默断开（Xray 语义），客户端握手失败；
- `VlessTcpConnectDialRefused` / `VlessTcpConnectUpstreamAbort`：上游失败传播；
- `VlessTcpConnectIpv4` / `VlessTcpConnectIpv6`：地址变体；
- `VlessTcpConnectHalfCloseClient` / `VlessTcpConnectIdleTimeout`：半关闭与空闲超时；
- `VlessTrafficReport`：identity 为握手 UUID 十六进制，认证结果传入 middleware。

过程中发现并修复的库内问题：

1. `recognition::detect` 无法识别真实 VLESS wire（首字节 version 0x00，非 "VLESS" 字符串）——新增结构化识别（version 0x00 + addnl_len 0 + 合法 cmd/atyp）；
2. `vless::conn::read_handshake` 解析后未回填 `request_header.uuid`（恒为零）——补 memcpy，使 UUID 认证身份可传入 middleware。

结论：VLESS 与 SOCKS5 共用同一 `runtime::session` 编排，runtime 零协议特判，`accept_protocol` / `dial` / `relay` / `udp_service` 抽象可复用。

VLESS UDP 命令纵向链路（`tests/preview/core/runtime/VlessUdpE2ETest.cpp` 3/3 通过）：

- 新增 `tests/common/protocols/vless/udp_tunnel.hpp`：UDP over 流数据面（读流帧 → 真实 UDP socket 转发 → 回包封帧写回流；空闲超时 + 流 EOF 终止），对齐生产端 `protocol::common::frame_loop`；
- 与 SOCKS5 UDP 共用 runtime `udp_service` 抽象，`make_accept_vless_udp` 仅做 cmd 判定；
- `VlessUdpConnectEcho`：流上帧往返 echo（domain/ipv4 目标）；
- `VlessUdpConnectIdleTimeout`：空闲超时关闭流；
- `VlessUdpConnectStreamEofTerminates`：客户端断开（EOF）终止数据面。

### 阶段 5：preview 与 psm 的适配/迁移决策

状态：已完成（2026-08-20，adapter v2 收敛验收通过）。

当前 adapter 层（tests/common/core/runtime/adapter/）存在遗留问题：未编译死代码、UDP 缺口、identity 泄密。收敛方向（用户已确认）：删除 make_accept 工厂、保留 ProtocolHandler 基类、修掉全部编译/功能 bug。

#### 5.1 结构收敛（v2 目标形态）

```text
adapter/
├── handler.hpp            # 保留：ProtocolHandler 基类 + AcceptResult（唯一协议接口）
├── socks5/vless/trojan/vmess/ss2022.hpp   # 具体 handler：补 UDP、统一 identity
├── protocol_adapter.hpp   # 单一适配：make_protocol_accept(shared_ptr<ProtocolHandler>) → protocol_accept_fn
│                          # 合并 ctx 装配（target/identity/is_dgram/post_dial），删除 5 份重复
```

删除（未编译/无人接线的死代码）：
- protocol_factory.hpp：make_accept 重载 + (type, configs) 枚举分发（臃肿且无人 include）
- transmission_bridge.hpp：从未编译（override 不存在的 psm shutdown/set_timeout；psm::net 命名空间不存在）
- fault_bridge.hpp：从未编译、从未被 include

移除 src/prism/protocol/handler.cpp 的 PRISM_ENABLE_PREVIEW 空壳（宏未定义 + include 测试树头文件，一开就炸）。

#### 5.2 功能修复

| 项 | 修复 |
|---|---|
| VLESS UDP | handler 检查 req.cmd==udp → is_dgram=true + 保留 conn（udp_service 走 udp_tunnel） |
| SOCKS5 UDP | handler 检查 req.cmd==udp_associate → is_dgram=true + 保留 conn；CONNECT 才挂 post_dial |
| Trojan/VMess UDP | 保持 dgram 包装（对齐 accept_packet 语义）；Trojan 不再填明文密码 |
| SS2022 | 明确本缝仅 TCP（SS2022 UDP 是独立 socket 通道） |
| identity | Trojan/SS2022 置空（不泄漏密码）；SOCKS5 用 req.username；VLESS 用请求 uuid；VMess 用配置 uuid |

#### 5.3 测试补齐

- AdapterTest：make_protocol_accept 的 ctx 装配 / 失败映射 / 空传输兜底；
- UDP E2E 切回 adapter 缝（Socks5Udp/VlessUdp 删除本地 helper）；
- VlessE2ETest 切换为 adapter make_accept_vless（删除本地 helper）；
- 恢复真实 SOCKS5 TCP CONNECT 纵向用例（client 握手 → accept → post_dial → relay → echo；含 dial 拒绝错误码）；
- recognition VLESS 结构化识别负例；
- session 分支：udp_service 缺失 → not_supported。

#### 5.4 验收

- adapter 相关 target 全部编译通过，相关回归全绿；
- 无未编译死代码；无明文密码进入 identity/统计；
- 调用链树形分支覆盖表更新到 docs/ngx-test-data/。

#### 5.5 验收结果（2026-08-20）

- 结构收敛：删除 protocol_factory / transmission_bridge / fault_bridge 死代码；src/prism/protocol/handler.cpp 空壳清空（git diff 归零）；adapter 收敛为单一 `make_protocol_accept(shared_ptr<ProtocolHandler>)`，5 个协议 handler 变薄封装；
- 功能修复：VLESS/SOCKS5 UDP 分支补齐、SOCKS5 CONNECT 应答延迟到拨号后（dial 失败→connection_refused）、Trojan/SS2022 identity 置空（不泄密）、recognition 21 字节边界负例；
- 测试证据：25 个 target 编译通过，163/163 用例通过——AdapterTest 4/4、Socks5TcpE2E 2/2、Socks5Udp 4/4、VlessUdp 3/3、Vless 9/9、VMess 8/8、VMessUdp 3/3、Trojan 8/8、TrojanUdp 3/3、SS2022 5/5、ListenerE2E 4/4、SessionOrchestration 5/5、Recognition 13/13、MiddlewarePipeline 1/1、Transport 15/15、TimeoutRelay 7/7、XhttpErrorMatrix 5/5、MuxSessionDeep2 8/8、Socks5ConnSession 16/16、Socks5ConnErrorMatrix 8/8、Socks5Dgram 7/7、DnsDial 3/3、MuxE2E 2/2、PadE2E 2/2、GoldenVector 18/18；
- 遗留（进入阶段 6 / Gate D）：性能基线、preview↔psm 对拍、外部互操作、fuzz 未闭环。

只有阶段 3 和阶段 4 通过后，才决定是否迁移生产代码。必须回答：

| 项目 | 问题 |
|---|---|
| 接口 | preview::transmission 与 psm::transport::transmission 如何互通 |
| 错误 | preview::error/fault 与生产 fault/exception 的边界是什么 |
| 生命周期 | 两套 session、worker、detached task 是否遵循同一所有权模型 |
| 内存 | preview memory policy 能否安全进入生产热路径 |
| 互操作 | preview 和生产能否互相作为 client/server |
| 性能 | 是否有可重复 baseline，是否存在明显劣化 |

默认迁移顺序：

~~~text
transmission contract
  → SOCKS5
    → VLESS
      → Trojan
        → VMess/SS2022
          → stealth
            → QUIC/Hysteria2/TUIC
~~~

不做全目录直接搬迁。

#### 5.6 审计整改（2026-08-20 审查发现）

状态：已完成（2026-08-20，A-1~A-6 全部落地）。

对阶段 5 交付物（adapter v2 + udp_assoc + session）按 cpp-lifetime / co-lifecycle / error-chain / coroutine-purity / review-test 规范全量审查，发现以下问题。每个整改单元独立可验证，遵循「单个工作单元流程」，不跨单元混改。

| 编号 | 严重度 | 问题 | 文件 |
|---|---|---|---|
| A-1 | P1 | 空闲超时不覆盖「等上游回包」阶段：egress_.async_receive_from 无超时竞速，客户端发一个包到静默目标可无限挂住关联 | `protocols/socks5/udp_assoc.hpp:226` |
| A-2 | P2 | SOCKS5 post_dial 丢弃 send_connect_reply 返回的 error，应答写失败静默丢失 | `adapter/socks5.hpp:51` |
| A-3 | P2 | bind_and_reply 失败路径不关闭已 open 的 UDP socket，依赖析构兜底 | `protocols/socks5/udp_assoc.hpp:86-102` |
| A-4 | P3 | vless/vmess 重复实现 uuid_hex，应抽公共 util | `adapter/vless.hpp`、`adapter/vmess.hpp` |
| A-5 | P3 | frame_loop 内 64KB up{} 每迭代零初始化，热路径开销 | `protocols/socks5/udp_assoc.hpp:220` |
| A-6 | P3 | handler::name() 无消费者（纸面接口） | `adapter/handler.hpp` |

##### U1：udp_assoc 空闲超时覆盖全循环（A-1，P1）

- 改动：frame_loop 的 idle timer 从「只武装在收客户端帧前」改为覆盖整个循环迭代——egress 回包等待也纳入 `recv || wait` 竞速；任一阶段超时即 co_return 并 close。
- 测试：新增「静默上游」用例——客户端发一个数据报到黑洞端点（无回包），断言 idle_timeout 到期后关联关闭且 TCP 控制仍开着。
- 验收：Socks5UdpE2ETest 由 4/4 → 5/5；既有 echo/非法帧/空闲/TCP 断开不回归。

##### U2：SOCKS5 应答写失败处理（A-2，P2）

- 改动：post_dial 内检查 send_connect_reply 返回值；失败时记录错误并 close（对齐 dial 失败分支的收口）。
- 测试：Socks5TcpE2ETest 补「应答写失败」用例——握手后拨号成功前客户端断开，断言会话收口、无协程残留。
- 验收：Socks5 相关回归全绿。

##### U3：bind_and_reply 失败路径 RAII 收口（A-3，P2）

- 改动：bind_and_reply 任一失败分支先 close 已 open 的 socket 再 co_return；或统一 scope_exit 收口。
- 测试：失败路径难注入，以代码审查 + 既有 UDP 回归为验收。

##### U4：uuid_hex 去重（A-4，P3）

- 改动：抽 `adapter/common.hpp` 提供 uuid_hex，vless/vmess handler 复用。
- 验收：编译 + Vless/VMess E2E 不回归。

##### U5：frame_loop 缓冲复用（A-5，P3）

- 改动：up/wire 提为成员或循环外复用，消除每迭代 64KB 零初始化。
- 验收：编译 + Socks5UdpE2ETest（U1 后 5/5）不回归。

##### U6：name() 消费（A-6，P3，二选一）

- 改动 A：session 成功路径把 handler name 写入 ctx.detected / 统计标签；
- 改动 B：删除 name() 虚接口。
- 决策：推荐改动 A（统计可区分协议来源）；不保留无消费者的虚接口。

##### 5.6 整体验收

- A-1/A-2/A-3 修复并有回归证据；A-4/A-5 收敛；A-6 二选一落地（接入失败日志）；
- 相关回归（Socks5TcpE2E、Socks5UdpE2E、AdapterTest、Vless/VMess/Trojan/SS2022 E2E、ListenerE2E、SessionOrchestration）全绿；
- 生命周期/错误链审查结论落 `docs/ngx-test-data/LIFECYCLE_AUDIT.md`（Gate D 缺项之一）。

##### 5.6 验收结果（2026-08-20）

- U1：frame_loop 两阶段均纳入 `recv_guarded`（recv || idle_wait 竞速）；新增 `Socks5UdpAssociateSilentUpstreamIdleTimeout` —— Socks5UdpE2E 4/4 → 5/5；
- U2：post_dial 检查 send_connect_reply 返回值，失败记 `diagnose::warn` + close；新增 `ReplyWriteFailureAfterClientDisconnect` —— Socks5TcpE2E 2/2 → 3/3；
- U3：新增 `close_sockets()`，bind_and_reply 四失败分支统一收口；
- U4：抽 `adapter/common.hpp::uuid_hex`，vless/vmess 复用（删除重复实现）；
- U5：up/wire 提为循环外复用（消除 64KB 每迭代零初始化）；
- U6：`make_protocol_accept` 失败路径以 `h->name()` 记日志（name() 有真实消费者）；
- 验证：26 个 target 全绿（13 个 adapter/协议 E2E + 13 个阶段 1/2 回归），审查结论已追加至 `LIFECYCLE_AUDIT.md` 第 6 节。

##### 5.6 工作范围

准备修改：

~~~text
tests/common/protocols/socks5/udp_assoc.hpp
tests/common/core/runtime/adapter/socks5.hpp
tests/common/core/runtime/adapter/vless.hpp
tests/common/core/runtime/adapter/vmess.hpp
tests/common/core/runtime/adapter/common.hpp   （U4 新增）
tests/preview/core/runtime/Socks5UdpE2ETest.cpp
tests/preview/core/runtime/Socks5TcpE2ETest.cpp
tests/preview/core/runtime/AdapterTest.cpp
docs/ngx-test-data/LIFECYCLE_AUDIT.md
~~~

暂不修改：src/prism/、全局错误体系、QUIC、生产 listener（维持阶段 5 边界）。

### 阶段 6：质量门禁

状态：完成（6a-6d 已完成，2026-08-18 晚；6e ASAN 环境不可行，改走 Debug+_GLIBCXX_ASSERTIONS 替代路径，2026-08-20 17 个 preview 核心 target 全绿；6f Release 恢复 + 21 target 回归全绿，2026-08-20）。

逐步加入 Build + Unit Test、Protocol Interop、ASAN + lifetime、Coverage、Fuzz smoke、Benchmark regression、Stress / memory。

每个新增或修改的公共组件至少需要正常路径、错误路径、半包/边界、关闭/取消/超时测试；热路径需要性能基线；并发或长生命周期组件需要 stress 测试。

#### 6a. Fuzz smoke（运行类，晚间可执行）

- 目标：`CodecFuzzTest` / `FuzzExtendedTest` / `DgramErrorCoverage`（`tests/preview/core/fuzz/`）
- 验收：全部通过，无崩溃/挂起
- 结果：CodecFuzzTest 9/9、FuzzExtendedTest 6/6、DgramErrorCoverage 63/63 ✅

#### 6b. Stress 基线（运行类，晚间可执行）

- 目标：`Socks5StressTest` / `VlessStressTest` / `NetworkingStressTest` / `TimeoutRelayTest` / `UdpRelayTest`；5.6 完成后补 `Socks5UdpE2ETest`（静默上游 + 空闲超时）长跑
- 验收：全部通过；记录并发量级与耗时到 ngx-test-data
- 结果：3/3、3/3、4/4、7/7、4/4 全部通过 ✅

#### 6c. Benchmark 基线（运行类，晚间可执行）

- 目标：`Socks5FrameBench` / `RecognitionPipeBench` / `CodecBench` / `ProtocolBench` / `MuxBench` / `LatencyBench`
- 记录数值到 `docs/ngx-test-data/benchmark.md`（标注构建配置：Release+COVERAGE，数值为参考基线）
- 结果：已记录 ✅（帧编解码 ns 级、Tunnel 双向 GiB/s 级）

#### 6d. 覆盖率报告（运行类，晚间可执行）

- 目标：跑 preview 测试集（ctest 子集）→ `gcovr` 生成 HTML 报告
- 产出：`build/coverage.html` + 摘要写入 `docs/ngx-test-data/coverage.md`
- 结果：lines 91.2%、functions 93.6%、branches 44.5% ✅

#### 6e. ASAN 内存检查（构建类，白天 -j 16）
- 重配 `build/` 为 `-DCMAKE_BUILD_TYPE=Debug -DPRISM_ENABLE_ASAN=ON -G "MinGW Makefiles"`
- 构建 preview 核心 target（runtime/recognition/socks5/vless/mux/transport/xhttp）
- 运行测试，修复发现的内存问题
- 注意：会覆盖当前 coverage 配置，完成后恢复

- **结果（2026-08-20）**：ASAN/UBSan 在当前 MSYS2 ucrt64 环境均不可行（`g++` 无 `libasan`、`clang++` 无 compiler-rt asan runtime、`pacman -Ss libasan` 无包），已探测确认。
- 替代路径：Debug + `-D_GLIBCXX_ASSERTIONS` 重配 `build/`，构建 17 个 preview 核心 target（runtime/adapter/socks5/vless/vmess/trojan/ss2022/xhttp/mux/transport/relay）全部通过；6a fuzz 基线（CodecFuzzTest 9/9、FuzzExtendedTest 6/6、DgramErrorCoverage 63/63）复跑确认。
- 结论：无 STL 边界断言触发、无崩溃/挂起；内存检查以 Debug 边界断言 + fuzz + stress + LIFECYCLE_AUDIT 静态审查覆盖。

#### 6f. 配置恢复与收口（白天 -j 16）
- 恢复 `Release + COVERAGE=ON` 配置
- 全量回归（ctest 子集）
- 同步计划文档与 ngx-test-data

- **结果（2026-08-20）**：恢复 `Release`（ASAN OFF、COVERAGE OFF），重建并回归 21 个 target 全绿（ListenerE2E 4、SessionOrchestration 5、AdapterTest 4、Socks5 UDP/TCP 5/3、Socks5Conn 16、Socks5Err 8、Vless TCP/UDP 9/3、VMess 8/3、Trojan 8/3、SS2022 5/3、XhttpErr 5、MuxSession 5、MuxDeep2 8、Transport 15、TimeoutRelay 7、Socks5Stress 3）。

## 4. 单个工作单元流程

~~~text
确认影响面
  → 读取调用方和测试
    → 设计数据流与所有权
      → 修改最小范围代码
        → 添加对应回归测试
          → 静态审查协程/生命周期/错误链
            → 用户允许后构建和运行相关测试
              → 更新 ngx-test-data 与 TASK_PROGRESS
~~~

一次只推进一个可验证单元，不在一个单元里同时做协议重写、runtime 重构、错误体系重构、CMake 大整理和无关格式化。

## 5. 当前第一批工作范围

准备修改：

~~~text
tests/common/core/middleware/builtin/relay.hpp
tests/common/protocols/xhttp/conn.hpp
preview/Transport/MemoryStream.hpp
tests/common/protocols/mux/session.hpp
tests/preview/ 对应回归测试
docs/ngx-test-data/
docs/TASK_PROGRESS.md
~~~

暂不修改：

~~~text
src/prism/runtime/
src/prism/protocol/handler.cpp
全局错误体系
全部协议目录
QUIC 生产接入
生产 listener
~~~

## 6. 决策门

### Gate A：公共层可用

relay buffer 独立；XHTTP pending flush 生命周期安全；memory_stream 线程模型明确；MUX 非法帧语义明确；对应回归测试存在。

### Gate B：第一条纵向链路可用

~~~text
listener → session → SOCKS5 → auth → dial → relay → upstream
~~~

TCP、错误、关闭、half-close、timeout 至少有验证。

### Gate C：抽象可以复用

VLESS 接入时不得复制一套 runtime/middleware 编排逻辑。

### Gate D：允许迁移

必须有 preview/psm adapter 或明确迁移接口、生产对拍、外部互操作或 golden vector、性能基线，以及生命周期和错误链审查结论。

只有 Gate D 通过后，才进入生产目录迁移设计。

#### 已完成项

- ✅ **golden vector**：SOCKS5/VLESS 编解码 roundtrip 验证（`tests/preview/interop/GoldenVectorTest.cpp` 9/9 通过，2026-08-19）——证明 preview 编解码与标准兼容

#### 已完成项（2026-08-20 追加）

- ✅ **外部互操作（L5）· SS2022 双向**：preview ↔ sing-shadowsocks v0.2.12（mihomo 同栈）双向互通（`tests/go/interop/run_interop.ps1`，Direction A/B 均 PASS，2026-08-20）。修复了 preview SS2022 TCP 握手头格式与标准实现的偏差：标准握手首部为裸 AEAD 块（无长度块前缀）、数据面为 chunk 流；服务端响应按 writeResponse 语义延迟到首次发送数据（payloadLen + 裸块 payload）。

- ✅ **生产对拍（L4）· SOCKS5 / SS2022 双向**：preview client ↔ 生产 Prism server（`tests/preview/integration/InteropPrismL4.cpp`，2026-08-20）。`socks5`、`ss2022` 的 echo + authfail 均 PASS；`vless/trojan/vmess` authfail PASS（凭据/格式校验有效）。修复了 preview SS2022 服务端响应格式：标准响应 = server salt + 固定头裸块 + 总是跟一个 AEAD 空块，且客户端消费空块必须推进 nonce（`chunk_codec::open_raw` 增加认证判定重载），否则数据面 nonce 失步。

#### 仍缺项（迁移前补齐）

- ❌ 生产对拍（L4）数据面全通：socks5/ss2022 已 PASS；vless/trojan/vmess echo 受阻于生产识别器——`src/prism/handshake/recognition/probe/analyzer.cpp` 只识别 SOCKS5/TLS/HTTP，其余一律回退 shadowsocks，VLESS/Trojan/VMess 首包被当 SS2022 解密失败（`decrypt fixed header failed: expected 11 plain bytes, got 27 enc bytes`）。生产 TODO（`logs/issues.md` T-1），不在 preview 侧改。
- ⚠️ 外部互操作（L5）其他协议：当前 runner 已为全部协议生成逐方向记录；Reality/Restls 双向与 ShadowTLS Preview client→reference server 方向仍为 `interface-gap`，native TLS codec-vector 不适用；ShadowTLS reference client→Preview server 已完成 authenticated-echo，TrustTunnel 已补齐标准 TLS/HTTP2 CONNECT 双向 echo，AnyTLS 已补齐独立认证帧 reference 双向 TCP（不等同于完整 TLS/多路复用），WebSocket 已补齐独立 Go `gobwas/ws` reference 双向 TCP authenticated-echo。
- ⚠️ preview vs psm 同场景性能对标：`PerformanceContract` 已固定输入/预热/迭代/重复，并输出 codec、固定 16 KiB memory-transport、本机 TCP loopback 和固定 1200 字节 UDP loopback 的 median/p95/p99/MAD/CPU 字段，另输出 TCP `bytes_per_second`、UDP `packets_per_second`、进程 `peak_working_set_bytes`、environment、原始样本数组及 production/preview `comparisons` 分级；外部矩阵已补每用例 `wall_time_ms`/`peak_working_set_bytes`，但代理握手、持续吞吐和多连接 RSS 的统一真实网络 harness 尚未建立。
- ⚠️ QUIC/Hysteria2/TUIC：Preview native ngtcp2 client/server UDP loopback、单向/双向流和 TLS exporter 已通过；TUIC 与 Hysteria2 独立 reference client↔Preview server 的 TCP/UDP authenticated-echo、TUIC Preview↔mihomo reference TCP+UDP 已 PASS，其他伪装方案的完整 QUIC L5 仍待做。
- ✅ 生命周期/错误链审查结论文档（`docs/ngx-test-data/LIFECYCLE_AUDIT.md` 第 6 节，2026-08-20）
- ✅ 逐协议迁移建议矩阵：`docs/ngx-test-data/migration-decision.md` 已生成；当前没有协议满足 `migrate` 条件。

## 7. 明确禁止的路径

- 不把 tests/common 整体直接移动到 src/prism；
- 不在公共层并发问题未解决前继续扩展协议数量；
- 不把 preview 自回环测试当作外部协议兼容证明；
- 不使用无错误回调的 detached 协程掩盖异常；
- 不在新代码中捕获 session 局部对象的引用；
- 不为了满足格式而批量修改与当前单元无关的旧代码；
- 不未经用户允许执行构建、长跑测试或产生大量临时产物；
- 不执行 git commit、push 或 amend。

## 8. 结论

~~~text
真实基线
  → 公共层收口
    → 测试矩阵
      → SOCKS5 纵向链路
        → VLESS 抽象验证
          → preview/psm 迁移决策
            → CI 与长期质量门禁
~~~

第一批代码工作围绕 relay、XHTTP、memory stream、MUX 的公共层问题展开；第一条完整代理链路选择 SOCKS5 TCP CONNECT；VLESS 用来验证抽象是否真正可复用；QUIC、stealth 和全量迁移放到后面。
