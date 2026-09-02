# Prism Next-Gen 实施计划

> 目标：把 tests/common 中的 preview 协议组件库，逐步收敛为可验证、可对拍、可选择性迁移到生产栈的新一代架构。
>
> 本计划不等同于立即把 tests/common 搬入 src/prism。迁移必须建立在公共层正确性、完整纵向链路和生产对拍结果之上。
>
> 当前状态：阶段 0～5 已完成（Gate A/B/C 通过 + adapter v2 收敛）；阶段 5.6 审计整改 A-1~A-6 已完成（2026-08-20，26 个 target 全绿）；阶段 6（质量门禁）6a-6f 全部完成（2026-08-20，6e 以 Debug+_GLIBCXX_ASSERTIONS 替代 ASAN）；Gate D 推进中：L5 SS2022 外部互操作双向 PASS（sing-shadowsocks v0.2.12）+ L4 生产对拍 socks5/ss2022 双向 PASS、vless/trojan/vmess 认证失败路径 PASS（echo 受阻于生产识别器，见 Gate D）。

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
- ❌ 外部互操作（L5）其他协议：VLESS/Trojan/VMess/Reality 等与 mihomo/sing-box 对拍（SS2022 双向已完成，2026-08-20）
- ❌ preview vs psm 同场景性能对标
- ✅ 生命周期/错误链审查结论文档（`docs/ngx-test-data/LIFECYCLE_AUDIT.md` 第 6 节，2026-08-20）

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
