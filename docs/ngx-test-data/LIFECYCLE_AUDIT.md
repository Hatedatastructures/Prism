# 生命周期 / 错误链审计（preview）

> 日期：2026-08-20
> 范围：`tests/common` 公共层、runtime/session、adapter 缝、Trojan/VMess/SS2022 L3

## 1. 所有权模型

| 层 | 资源 | 生命周期 | 约束 |
|---|---|---|---|
| L1 全局 | `memory::system::enable_pooling()` | 进程 | 热路径 PMR 池 |
| L2 worker | `runtime::session` + `session_options` | 连接 | `shared_ptr<session>` + `co_spawn` 按值捕获 `self` |
| L3 session | `ctx.inbound`/`outbound`/`traffic`/`pad` | 单次 `run()` | `shared_transmission` 管理，`close()` 幂等 |
| L4 detached | `listener::accept_loop`、`relay`、`udp_service` | 独立协程 | 禁止捕获 L3 局部引用/裸指针，必须 `shared_ptr` 按值 |

## 2. 协程生命周期审计

### 2.1 detached 约束
- `net::co_spawn(executor, lambda, net::detached)` 的 lambda 必须按值捕获 `self`（`shared_ptr`）
- 禁止 `co_await` 后使用裸指针/迭代器/引用（可能失效，需重取）
- `erase()` 后用返回值更新迭代器

### 2.2 已审计点
- `runtime::session::run`：`protocol_guard` 保存 pre-accept 传输，失败时双 `close()`（行 114-130），`post_dial` 在 dial 成功/失败后均触发（SOCKS5 延迟应答）
- `listener::accept_loop`：`co_spawn(ex_, [sess, transport]()->awaitable<void>{ co_await sess->run(transport); }, detached)` 按值捕获 `sess`+`transport`
- `relay`：`relay_state` 为 `shared_ptr`，`relay_up`/`relay_down`/`relay_idle` 通过 `operator||` 竞争，结束点 `close_relay` + `traffic->report`
- `trojan/vmess/ss2022` dgram：`async_receive_from` 错误即 `break`，`close()` 触发对端 EOF

### 2.3 本次修复
- **session recognition 门**：协议专用 listener 已配 `accept_protocol` 时，`recognition` 仅作预读回注，不再因 `unknown` 直接 `protocol_error`（`session.hpp:99-107`）。`UnknownProtocolRejected`（无 `accept_protocol`）仍返回 `protocol_error`，回归通过。
- **traffic 上报时序**：`run_coro` 的 `ioc.stop()` 会废弃在途 `relay`，`Trojan/VMess TrafficIdentity` 在 `proxy->close()` 后加 50ms `steady_timer` 让出，使 `relay` 完成 `report` 后再停 ioc（`TrojanE2ETest.cpp:616` 同理）。

## 3. 错误链审计

### 3.1 分层
- **热路径**：`fault::code` 枚举，不抛异常（`preview::fault::code`）
- **启动/致命**：`exception::deviant` → `network`/`protocol`/`security`
- **协议层**：`preview::error`（`bad_auth`/`bad_magic`/`io_error`/`not_supported` 等）→ adapter `map_*_error` 转 `fault::code`

### 3.2 映射表（adapter 层唯一出口）

| 协议 | `error::bad_auth` → | `error::not_supported` → | 其余 → |
|---|---|---|---|
| Trojan | `auth_failed`（静默断） | `not_supported` | `protocol_error`/`io_error` |
| VMess | `auth_failed` | `not_supported` | `protocol_error`/`io_error` |
| SS2022 | `auth_failed` | `not_supported` | `protocol_error`/`io_error` |

- Trojan 客户端 `connect` 恒 `success`（不读服务端应答），bad_auth 表现为服务端静默断 → 客户端读 `0`/`ec`
- VMess 客户端 `connect` 对 bad_uuid 返回 `bad_auth`/`io_error`（AEAD 解密失败）

### 3.3 管道错误传播
- `pipeline::run`：任一 `middleware::handle` 返回非 `success` 即终止，`session` 捕获 `dial_ec` 后触发 `ctx.post_dial(dial_ec)`（SOCKS5 据此发送错误码）
- `mux_middleware`：未启用时 `success` 直通（原 `not_supported` 会截断管线，已修正 `mux.hpp:48`）
- `pad_middleware`：恒 `success`（可选装饰）

## 4. 内存/PMR

- `memory::string/vector` 使用全局池/帧竞技场，`enable_pooling()` 必须在 `main` 首行
- `transmission` 装饰链：`next_layer()` 逐层委托，`lowest_layer<T>()` 导航到底层 `reliable`/`unreliable`
- `trojan/vmess` ipv6 编码原直接塞字符串 `::1`，现经 `make_address_v6().to_bytes()` 转 16 字节二进制（与线缆一致）

## 5. 待补

- 覆盖率 `branches 44.5%` 需补错误/边界分支至 60%+
- `scheme_executor`（链 S）尚未接入 recognition，伪装方案仍 L1/L2
- `E1 prism 链接溢出` 未解，`L4/L5` 对拍、外部互操作、性能对标仍阻塞

## 6. 阶段 5.6 审计整改结论（2026-08-20）

针对 adapter v2 交付物（udp_assoc + adapter 缝 + session）按 cpp-lifetime / co-lifecycle / error-chain / coroutine-purity / review-test 复审，发现并修复：

| 编号 | 问题 | 修复 | 回归 |
|---|---|---|---|
| A-1 | udp_assoc 空闲超时不覆盖「等上游回包」阶段：egress 收包无超时，静默上游可无限挂住关联 | frame_loop 两阶段（收客户端帧 / 收上游回包）均纳入 `recv_guarded`（recv \|\| idle_wait 竞速）；idle_timeout=0 时退化为纯等待 | 新增 `Socks5UdpAssociateSilentUpstreamIdleTimeout`（Socks5UdpE2E 4→5/5） |
| A-2 | SOCKS5 post_dial 丢弃 send_connect_reply 错误，应答写失败静默丢失 | 检查返回值，失败记 `diagnose::warn` + `close()` | 新增 `ReplyWriteFailureAfterClientDisconnect`（Socks5TcpE2E 2→3/3） |
| A-3 | bind_and_reply 失败路径不关闭已 open 的 UDP socket | 新增 `close_sockets()`，四个失败分支统一收口 | 代码审查 + UDP 回归 |
| A-4 | vless/vmess 重复实现 uuid_hex | 抽 `adapter/common.hpp` 公共 util | Vless/VMess E2E 不回归 |
| A-5 | frame_loop 内 64KB up{} 每迭代零初始化 | up/wire 提为循环外复用 | Socks5UdpE2E 5/5 |
| A-6 | handler::name() 无消费者 | `make_protocol_accept` 失败路径以 name() 记日志 | AdapterTest 4/4 |

生命周期复核结论：

- udp_assoc 无循环引用：svc 由 udp_service lambda 持有，run() 内 `self` 按值捕获，结束即析构；
- frame_loop / tcp_watch 竞速由 `operator||` 取消保证，close()/close_sockets() 幂等；
- session protocol_guard 失败双 close 无泄漏路径（既有结论保持）。

验证：Socks5UdpE2E 5/5、Socks5TcpE2E 3/3、AdapterTest 4/4、Vless/VMess/Trojan/SS2022 E2E 全绿、ListenerE2E 4/4、SessionOrchestration 5/5、其余 12 个回归 target 全绿。