# preview 协议库规范（tests/common）

> 本规范描述 `tests/common/`（preview 库）的**真实架构**与统一设计标准。
> 参考 Go 参考实现（mihomo transport / sing 系列）的接口模式。目标：
> **可替换主项目 src/prism 的新一代架构**（NEXTGEN_TASK.md）。
> 更新：2026-08-31（Preview Foundation、Transport、Net、Runtime、Protocols、
> Composition 已移出 tests/common；TestSupport 已独立分层；剩余 tests/preview
> 测试目录暂不物理迁移）。

## 1. 目录结构与模块归属

```
tests/common/
  （仅保留该规范入口；Preview 生产头已全部移出）

tests/TestSupport/
  Runner/{TestRunner.hpp,gtest_main.cpp}
  Production/ProductionMockTransport.hpp
  Preview/PreviewMockTransport.hpp
  Tls/MockTlsServer.hpp
  Fixtures/RuntimeTestHelpers.hpp
  Benchmark/Bench.hpp
  Stress/StressHelper.hpp

preview/
  Foundation/         已从 tests/common/Core 物理迁移的基础层候选实现
  Transport/          已从 tests/common/Core 物理迁移的传输层候选实现
  Net/                已从 tests/common/Core/Net 物理迁移的网络层候选实现
  Runtime/            已从 tests/common/Core/{Middleware,Recognition,Runtime} 物理迁移的运行时实现
  Composition/        已从 tests/common/Core/{Runtime/Adapter,Api,Settings} 物理迁移的组合实现
  Protocols/           已从 tests/common/Protocols 物理迁移的协议候选实现

  当前职责拆分头（仍由协议聚合头兼容包含）：
    Net/Dns/Types.hpp
    Net/Dns/Detail/{ConfigOptions,Exchange,Fallback,Maintenance}.hpp
    Protocols/Http3/{Detail/Varint,Huffman,StaticTable,DynamicTable,Decoder,Encoder}.hpp
    Protocols/Mux/{StreamState,SessionReadLoop,SessionWriteLoop}.hpp
    Protocols/Shadowsocks2022/{ChunkCodec,KeyDerivation,RequestCodec,ResponseCodec}.hpp
    Protocols/Vmess/{Auth,ChunkCodec,RequestCodec,ResponseCodec}.hpp

最终职责目录：
  preview/Foundation/{Fault,Exception,Memory,Utility}
  preview/Transport/{Reliable,Encrypted,Buffered,Detail}
  preview/Net/{Dns,Endpoint,Connection,Socket,Detail}
  preview/Runtime/{Session,Worker,Front,Resource,Contract,Detail}
  preview/Protocols/{Common,Http,Socks5,Trojan,Vless,Vmess,Shadowsocks2022,Mux,Http3}
  preview/Composition/{Adapters,ProtocolFactory,ProtocolRegistry,Bootstrap}
```

### 1.1 协议目录（proxy/stealth）

每个普通协议一个目录，保留薄的 `Types/Codec/Conn/Dgram` 聚合入口；复杂协议的
认证、请求/响应和数据面按职责拆分，聚合头只做兼容 include：

```
  preview/Protocols/<proto>/
  Types.hpp   — 常量、枚举、标志位、配置结构
  Codec.hpp   — 编解码聚合入口（具体职责见下表）
  Conn.hpp    — 连接装饰器（继承 Transmission，模板化 Memory）
  Dgram.hpp   — UDP 数据报封装（需要时）
  <proto>.hpp — 聚合头（re-export 上述）
```

伪装方案同构：Types/Codec/Conn + 聚合头（无 Dgram 或按需）。

复杂协议拆分：

```text
Vmess/           Auth + RequestCodec + ResponseCodec + ChunkCodec
Shadowsocks2022/ KeyDerivation + RequestCodec + ResponseCodec + ChunkCodec
Http3/           StaticTable + DynamicTable + Decoder + Encoder + Huffman + Detail/Varint
Mux/             StreamState + SessionReadLoop + SessionWriteLoop + Session
Net/Dns/Detail/  ConfigOptions + Exchange
```

例外（**薄聚合头**，无 Codec 层，聚合头仅 re-export 子头、不定义工厂）：

```
preview/Protocols/Ech/    — Keygen/Scan/Types（无 Conn：SSL_ECH_KEYS 构造 + ClientHello 扫描）
preview/Protocols/Native/ — Types/Conn（原生 TLS 直通，无帧编解码）
preview/Protocols/Xhttp/  — Types/Conn（HTTP/2 stream-one，帧处理在 Http2/ 子库）
```

> 三者均为 TLS 直通/解密类方案，不存在 Build/Parse 帧编解码层，
> 故不套用 Types/Codec/Conn/Dgram 四件套，聚合头保持薄形态。

数据面扩展（在四件套基础上按需增补）：
- `Protocols/Socks5/UdpAssoc.hpp` — SOCKS5 UDP ASSOCIATE 真实数据面（关联会话表 + 空闲回收）
- `Protocols/Vless/UdpTunnel.hpp` — VLESS UDP over 流（数据报封装隧道）
- `Protocols/Ech/` 含 Keygen/Scan（无 Conn）
- `Protocols/Native/` 为 Types/Conn（原生 TLS 直通）
- `Protocols/Xhttp/` 为 Types/Conn（帧处理在 Http2/ 子库）

### 1.2 多路复用（Mux/）

```
preview/Protocols/Mux/Smux/（Yamux/H2Mux 同构）
  Types.hpp   — 帧类型/常量
  Codec.hpp   — 帧编解码（模板化 FrameCodec 策略）
  Session.hpp — 会话状态机（流表/帧循环/背压，模板注入 Codec）
  Client.hpp  — 客户端封装（OpenStream 视角）
  Server.hpp  — 服务端封装（AcceptStream 视角）
  Smux.hpp    — 聚合头

preview/Protocols/Mux/StreamState.hpp
  SessionIface/StreamHandle — 流状态、通知和生命周期窄契约
preview/Protocols/Mux/SessionReadLoop.hpp
  ReadExact — 帧头/负载的完整读取拼接
preview/Protocols/Mux/SessionWriteLoop.hpp
  WriteFrame — uint8_t 到 Transmission 的写入适配
```

共享 `Mux/Session.hpp` 模板框架 + `Mux/Stream.hpp`（流句柄 StreamHandle）。

## 2. 接口设计（统一 Transmission + 模板策略 + 多态）

### 2.1 传输抽象（preview/Transport/Transmission.hpp）

单一 `Preview::Transmission` 虚接口（全部模块统一使用）：

| 方法 | 语义 |
|---|---|
| `async_read_some(span<byte>, ec)` | 异步读，返回实际字节数 |
| `async_write_some(span<const byte>, ec)` | 异步写，返回实际字节数 |
| `AsyncRead/AsyncWrite` | 组合操作（读满/写满） |
| `Close()` / `Cancel()` | 全关 / 取消挂起操作 |
| `Shutdown()` | 半关写方向（对端读 EOF） |
| `SetTimeout(ms)` | 读超时（0=禁用） |
| `IsOpen()` | 打开状态 |
| `NextLayer()` / `lowest_layer<T>()` | 装饰器链导航（后者 Asio 风格豁免） |
| `TransportType()` | Tcp / Udp |
| `Release()` | 释放底层所有权 |

- **装饰器模式**：协议 Conn 继承 Transmission 包装底层（Preview → Conn → Reliable）。
- **叶子节点**：MemoryStream / Reliable / Unreliable / Encrypted / Pad。
- **concept**：`TransmissionLike` 约束模板参数。
- 生命周期：`SharedTransmission`（shared_ptr）管理。

### 2.2 会话接口（preview/Foundation/SessionBase.hpp）

虚拟流/会话的统一接口（Mux StreamHandle 实现）：

| 方法 | 语义 |
|---|---|
| `ReadSome(span)` | 读，返回字节数（0=EOF/超时/取消） |
| `WriteAll(span)` | 全写，返回错误码 |
| `Shutdown()` | 半关（发 FIN） |
| `Close()` / `Cancel()` | 关闭 / 取消 |
| `SetTimeout(ms)` | 读超时 |
| `IsOpen()` | 状态 |
| `Executor()` | 执行器 |

### 2.3 协议 conn 模板化

```cpp
template <Preview::Memory::Restrict Memory = Preview::Memory::SessionResource<>>
class Conn : public Transmission, public std::enable_shared_from_this<Conn<Memory>>;
```

- `Memory` 注入会话内存策略（arena 复用零分配）。
- 聚合头内联 `Connect(SharedTransmission, config)` / `Accept(SharedTransmission, config)` 工厂。

## 3. 错误体系边界（T1-2 决策）

| 体系 | 用途 | 定义 |
|---|---|---|
| `preview/Foundation/Error.hpp` | **协议编解码**（细粒度：need_more/unexpected_eof/bad_length/bad_auth/...） | `Preview::Error`（boost::system::error_category） |
| `preview/Foundation/Fault/Code.hpp` | **中间件/流程**（粗粒度：io_error/timeout/canceled/auth_failed/...） | `Preview::Fault::Code` |

- 桥接：`Fault::ToCode(boost::system::error_code)` 已支持 error 转换。
- **禁止第三种体系**；新错误优先入 Error.hpp（编解码）或 Fault（流程）。

## 4. 认证抽象（preview/Foundation/Authenticator.hpp）

```cpp
struct AuthResult { bool Ok; std::string identity; };
class Authenticator {
    virtual auto Check(std::string_view identity, std::string_view Secret) const -> AuthResult = 0;
};
```

- `StaticAuthenticator` / `RejectAuthenticator` 内置。
- 已接入：socks5/trojan/vless/hysteria2（vmess/ss2022 密码学校验豁免、tuic 无认证）。

## 5. 中间件管线（preview/Runtime/Middleware/）

```
Pipeline（Add/Run）→ Context（Inbound/Outbound/Target/detected/traffic/identity/pad）
  ├─ Builtin/Dial    （默认函数 = Outbound 拨号）
  ├─ Builtin/Mux     （多路复用判断）
  ├─ Builtin/Pad     （按 detected 决定是否填充）
  └─ Builtin/Relay   （双向转发 + 统计）
```

- 消费 `Context.identity`（认证结果）与 `Context.traffic`（流量统计回调）。
- 超时/背压：T4-5 扩展（Context.timeout 字段，Relay 优先于构造参数）。

## 5.1 中间件扩展（T4/T5）

```
Builtin/Auth      （Authenticator 校验 → Context.identity；T4-1）
Builtin/Throttle  （TokenBucket 限速 → blocked；T5-4）
Builtin/Ban       （失败计数封禁，窗口过期解封；T5-4）
```

## 5.2 运行时骨架（preview/Runtime/，T4/T5）

```
Session            （Run：识别 → 认证/拨号/转发管线；T4-2）
Listener           （TCP AcceptLoop + 亲和性分发 FNV-1a + 会话工厂；T4-3）
Statistics         （TrafficCounter：identity 维度聚合；T4-4）
PerWorkerTraffic   （alignas(64) 原子槽 + identity 聚合；T5-2）
SessionRegistry    （COW 值拷贝快照，严禁 L3 引用；T5-7）
  Contract/          （ProtocolHandler/AcceptResult 等稳定类型擦除接口）
  Composition/       （具体协议 adapter/factory 绑定；不属于 Runtime）
```

> `preview/Composition/Adapters/` 是具体协议绑定的组合层，不属于 Runtime。
> `Common.hpp`、`Handler.hpp`、`ProtocolAdapter.hpp` 以及五个具体 adapter
> 已归属 `PreviewComposition`；`Handler.hpp` 已迁移到 `Runtime/Contract` 作为稳定契约。
> Runtime 不得拥有或 include 具体 Protocol，具体协议绑定只在 Composition 发生。

### 5.2.1 TrafficSink 契约

`preview/Foundation/Utility/TrafficSink.hpp` 定义协议数据面与运行时统计之间的最小接口。
`Middleware::Context` 只保留兼容类型别名；协议 UDP 数据面不得 include 完整
`Middleware/Context.hpp`。该接口不拥有实现对象，Report 调用不分配内存。

## 5.3 账户与限速（preview/Foundation/Utility/Account/ + preview/Foundation/Utility/Rate/，T5）

```
Account/CowMap     （模板化 COW：快照 + CAS 更新；O3/O6 复用）
Account/Directory  （Entry 原子活跃 + Lease RAII + TryAcquire CAS；T5-3）
Account/Authenticator（DirectoryAuthenticator：未禁用/未过期/配额；T5-1）
Rate/TokenBucket   （惰性补发 + 单 CAS；T5-4）
```

## 5.4 网络协议补充（T3）

```
Net/UdpRelay    （D5：动态关联会话表 + 超时回收 + 端口不匹配丢弃 + 单侧关闭终止）
Http1/Parser    （CONNECT 请求解析：method/target/Host/Proxy-Authorization）
Http1/Conn      （CONNECT 握手：ReadRequest + SendResponse + CheckBasic(407)）
```

## 5.5 运营与可观测（T5/T6）

```
Api/ApiManager    （资源树契约：ListSessions/TrafficSummary/ConfigSnapshot；O7）
Settings/Json     （自包含 JSON 解析：递归下降 + 深度 32 + 转义）
Settings/Loader   （配置加载校验：必填/范围/类型；生产用 glaze）
Diagnose/Observability（HDR 指数桶 + EWMA + 1/N 采样 SPSC ring；O5）
```

## 6. 命名空间与编码规范

> **2026-08-22 规范 v2**：标识符切换大驼峰（`Preview::` / PascalCase 文件名）。
> **2026-08-30 迁移完成**：TestSupport 已拆成生产 mock、Preview mock、TLS、Runner、
> Fixtures、Benchmark 和 Stress 子目录；生产 mock 与 Preview mock 类型体系独立。
> 小写 `preview::` 体系已废弃。

- **全库 `Preview::`**；禁止历史命名体系混用与 psm:: 混用。
  - **测试支持依赖说明**：`tests/TestSupport/Runner/TestRunner.hpp` 和 `gtest_main.cpp`
    使用生产库 `psm::*`；`ProductionMockTransport.hpp` 位于 `Psm::Testing`，属于
    `ProductionTestSupport`，不是 Preview 生产候选实现；Preview fixtures 位于
    `Preview::Testing`。
  - **RuntimeTestHelpers.hpp**（runtime E2E 公共样板，`Preview::Testing`
    命名空间位于 TestSupport/Fixtures）：RunCoro/echo 上游/ChainStatePtr/
    DialUpstream/TailReadGuarded 等；仅 tests/preview/core/runtime 使用。
- CMake target 策略：`PreviewFoundation`、`PreviewTransport`、`PreviewNet`、
  `PreviewRuntime`、`PreviewProtocolsCommon`、各 `PreviewProtocol<Scheme>`、
  `PreviewComposition` 和 `TestSupport` 按职责拆分。`Core` 只是过渡物理路径。
- 本批删除旧的三个 snake_case Preview target；consumer 直接链接
  PascalCase target，不保留 snake_case alias。
- 标识符 PascalCase（2026-08-22 规范 v2）；Doxygen 中文注释（@file/@brief/@details/@return）。
- 头文件保护 `#pragma once`；聚合头同步（新增子头必须入聚合头 + CMake）。

## 7. 测试三层模型

1. **Codec 纯函数**：Build/Parse 无 I/O 单测。
2. **回环 Session**：Client/Server 配对（MemoryStream 或 loopback socket）。
3. **错误矩阵**：坏数据/边界/超时/取消/错误码传播。

异步测试必须 `co_spawn + ioc.run()` 模式（MuxLifecycle 模式），禁止 `run_for/poll` 驱动。

## 8. 构建（CMake）

- `preview/CMakeLists.txt` 定义 `PreviewFoundation`、`PreviewTransport`、
  `PreviewNet`、`PreviewRuntime`、`PreviewComposition`、
  `PreviewProtocolsCommon` 和全部 `PreviewProtocol<Scheme>` 的根级 source
  ownership；`tests/common/CMakeLists.txt` 不再拥有 Preview 生产头；
  `tests/TestSupport/CMakeLists.txt` 定义
  `TestSupport` 和 `ProductionTestSupport`。
- `PreviewComposition` 是唯一同时依赖 Runtime 和具体 Protocol 的层。
- Preview 生产 target 不得依赖 TestSupport；Runtime 不得依赖具体 Protocol。
- 所有 public header 必须在一个且仅一个 target 的 `target_sources` 中登记。
- `scripts/check_common_headers.ps1` 按 target 检查磁盘头文件、重复登记、陈旧登记
  和未知 target，支持 `-CheckMirror` 输出独立镜像 drift。
- 测试 consumer 必须显式链接所需模块；禁止通过全量公共 target 获得所有协议。

### 8.1 target 过渡状态

本批已删除旧的三个 snake_case Preview target。
Foundation、Transport、Net、Runtime、Protocols 和 Composition 已从 `tests/common` 物理迁移至项目根级
`preview/`；`tests/common` 不再承载 Preview 生产头。
`tests/preview` 的物理目录暂不迁移；其 CMake 链接已经使用 PascalCase 模块 target。

### 8.2 物理迁移与职责拆分状态

- Phase 2C：Net 的 Target/Dialer/Route/Outbound/DNS/UdpRelay 已迁移至
  `preview/Net/`。
- Phase 2D：Runtime 的 Middleware/Recognition/Session/Listener/Registry/Statistics
  已迁移至 `preview/Runtime/`；具体协议 adapter 位于
  `preview/Composition/Adapters/`，`Runtime/Contract/Handler.hpp` 只提供稳定契约。
- Phase 2E：`tests/common/Protocols/**` 已整体迁移至 `preview/Protocols/**`，每个
  协议由独立 `PreviewProtocol<Scheme>` target 拥有；Composition 是唯一同时依赖
  Runtime 与具体协议的层。
- Phase 3/4：TestSupport 已按 Production/Preview/Tls/Runner/Fixtures/Benchmark/Stress
  拆分；Preview mock 使用事件通知等待，生产 mock 保留原行为；契约测试位于
  `tests/Contract/`，只在该层并列依赖 psm 与 Preview。
- Phase 6：VMess/SS2022 的 Auth/Request/Response/Chunk、QPACK 的
  StaticTable/DynamicTable/Decoder/Encoder/Huffman、Mux 流状态与读写适配、DNS
  Exchange/Fallback/Maintenance 已抽出；Mux 更细的帧状态循环拆分和跨平台性能
  基线固化保留为后续垂直切片。

### 8.3 参数与性能约束

协议装配边界的四参数入口统一使用轻量 `*Parameters` 值对象：字段中的
`SharedTransmission` 转移所有权，配置/地址/随机数只借用，调用期间必须保持有效。
已覆盖 SOCKS5、Trojan、VLESS、VMess、Reality、ShadowTLS、TrustTunnel、HTTP/1.1
CONNECT 和 SS2022 UDP 装配入口。参数对象不引入虚调用或额外共享指针链；数据面
Codec 仍保持静态/内联路径。

Preview benchmark 通过 `PreviewCodecBench`、`PreviewTransportBench`、
`PreviewRuntimeBench` 和 `PreviewDnsBench` 按领域聚合现有 perf 可执行文件；这些
target 只在 `PRISM_ENABLE_BENCHMARK=ON` 时注册，不加入默认构建。
2026-08-31 Windows Release smoke：Core AEAD 16KB 为 994 ns/op（9.77 GiB/s）、
PMR 计数为 1 allocation/op；VMess/SS2022 Chunk 分别约 1304/1440 ns/op；
并发 Arena 与 malloc 对比均为 P50 200 ns、P99 400 ns、P999 500 ns。该组数据
用于记录基线，正式跨平台回退阈值仍需 Linux 复测后固化。

## 9. 镜像复制策略

`preview/Foundation/` 的部分模块与生产 `include/prism/` 存在复制关系，按文件登记：

| 目录 | 与生产关系 | 同步策略 |
|---|---|---|
| `preview/Foundation/Fault/` | 镜像 `include/prism/foundation/fault/`（逐字，仅命名空间差异） | 锁定：人工比对，改动需两侧同步 |
| `preview/Foundation/Exception/` | 镜像 `include/prism/foundation/exception/` | 锁定 |
| `preview/Foundation/Memory/{Container,Pool}.hpp` | 镜像 `include/prism/foundation/memory/` | 锁定 |
| `preview/Foundation/Memory/CowMap.hpp` | Preview-only 扩展，无生产镜像 | 不进入严格镜像集合 |
| `preview/Foundation/Memory/Pointer.hpp` | 正式 fork；生产对应 `memory/pointer.hpp` 为固定 512B arena，Preview 为可配置会话 arena | 不进入严格镜像集合 |
| `preview/Foundation/Utility/Crypto/` | **已分叉**（Aead.hpp 15.1KB vs 9.6KB，各自演进） | 分叉：preview 自包含实现，白名单豁免镜像 diff |
| `preview/Foundation/Utility/Diagnose/` | 正式 fork | Preview 观测接口独立演进，不要求与 psm 逐字同步 |
| `preview/Net/Dns/` | 正式 fork | Preview DNS 已有独立 11 层分层和扫描优化，不作为逐字镜像 |

> 镜像文件头注 `@note 镜像自 include/prism/...，同步策略：锁定/分叉`。
> `scripts/check_common_headers.ps1 -CheckMirror` 按上表执行规范化镜像比较；
> Fault/Exception/Memory 的九个登记文件除登记的 namespace/path 转换外必须一致，未声明差异
> 使门禁 hard fail。生产 `memory/frame_arena` 已独立放入
> `include/prism/foundation/memory/pointer.hpp`，不改变九个池职责镜像的比较范围。
> Crypto/Diagnose/DNS 是正式 fork，不进入严格镜像集合。

## 26. DNS 解析子系统（2026-08-29 重构定稿，A-30）

`preview/Net/Dns/` 分层扩至 **12 个根头及 Detail 辅助头**：Config / Format / **Answer**（热路径扫描）/
**Transport**（概念+Udp/Tcp/Tls）/**ConnPool**（连接池）/**Doh** / Cache /
Coalescer / Rules / Upstream / Resolver / Types；Detail 下有 ConfigOptions、Exchange、Fallback 和 Maintenance。
依赖单向：Resolver → 编排层 → 传输层 →
字节层；Transport 之上的层"知道 DNS"，之下只知道"字节帧"（`TransportLink` /
`PoolableTransport` 分层 concept）；单文件 ≤400 行红线。

关键决策：

- **热路径零物化**：应答解析走 `Answer::ScanAnswers` 单遍扫描（owner name 只
  推进偏移不构造字符串，地址内联 small_vector<8>），实测比 `Message::Unpack`
  快 4.6×（50 vs 234 ns/op）；Unpack 保留给测试/golden 路径。
- **缓存**：槽位式 LRU（世代号惰性重排，Get 命中 O(1) 提升），查找键 260 字节
  栈缓冲 + 透明哈希异构查找（命中路径零堆分配，实测 105 ns/op）；
  `MaxEntries=0` = 无限；`EvictExpired` 由 Resolver 的 30s MaintenanceLoop 周期调用。
- **连接池**：`ConnPool<Link>` per-server 空闲复用（上限/懒过期），TCP/DoT/DoH
  收益为省 1-2 RTT 建连握手；复用连接首次失败自动新建重试一次；
  UDP 不入池；`Server.KeepAlive=false` 退回每查询新建。
- **RCODE 语义**（与主项目一致）：0=成功、3=NXDOMAIN（成功+空 IP → 上层负缓存）；
  其余 RCODE = 上游拒绝（Fallback 继续下一上游）。
- **超时负缓存**：默认所有失败均负缓存，`Config.NegativeOnTimeout=false` 时
  超时可立即重试（2026-08-29 项目所有者拍板）。
- **通配符语义**（2026-08-29 与生产统一，项目所有者拍板）："至少消耗一级子域"，
  `*.example.com` 不匹配裸域 `example.com`；生产 `domain_trie` 已同步修正为
  wild_value 槽位（同域通配与精确规则共存互不覆盖），生产测试
  `DnsRules.TrieWildcardMatch` / `DnsRulesDeep3.SearchWildcardNotMatchExact` 断言已翻转。
- **维护循环**：Resolver 30s 周期 EvictExpired + flight FlushCleanup + 连接池
  清扫（`alive_` 存活标记模式）；flight 清理仍保留查询入口执行（生产
  query_pipeline 同款，防顺序解析加入陈旧 flight 永久挂起）。
- **性能基准**（`tests/preview/perf/DnsPerf.cpp`，perf 标签）：历史基线为 Cache
  105 ns/op、Scan 50 ns/op（Unpack 234）、回环 E2E 9111 QPS（并发 500，
  2026-08-29 实测，跨机器噪声大仅作对标记录）。2026-08-31 Windows
  Release smoke 为 Cache 127 ns/op、Scan 51 ns/op（Unpack 226）、回环
  9142 QPS；本次仅完成可重复性 smoke，正式回退阈值仍需跨 Windows/Linux 基线
  复测后锁定。
- **EDNS0**：查询 Additional 段宣告接收缓冲 4096（RFC 6891，无 DO 位）；
  响应 OPT（type 41）的 TTL 字段为扩展标志位，不参与最小 TTL（ScanAnswers 与
  Message::MinTtl 双路径一致，见 `DnsAnswer.TestOptRecordExcludedFromMinTtl`）；
  完整 EDNS 选项（ECS 等）解析仍未覆盖，为遗留缺口。
