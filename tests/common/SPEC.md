# preview 协议库规范（tests/common）

> 本规范描述 `tests/common/`（preview 库）的**真实架构**与统一设计标准。
> 参考 Go 参考实现（mihomo transport / sing 系列）的接口模式。目标：
> **可替换主项目 src/prism 的新一代架构**（NEXTGEN_TASK.md）。
> 更新：2026-08-16（T1-6，按真实架构重写；同日一致性整理：G7 门禁补全 / psm 兼容豁免 / 薄聚合头说明）。

## 1. 目录结构与模块归属

```
tests/common/
  Core/                基础层（Adapter/ 为唯一上向依赖例外，见 5.2）
    Memory/ Fault/ Exception/ Crypto/ Coroutine/ Rate/ Diagnose/ Account/ Api/
    Error.hpp  Transmission.hpp  Authenticator.hpp  FlatBuffer.hpp  Parser.hpp
    SessionBase.hpp  CodecTraits.hpp  ByteSpan.hpp  Role.hpp
    Transport/        Reliable/Unreliable/Encrypted/Pad/Preview/Snapshot/Connector/
                      MemoryStream/Algorithm/Stream
    Protocol/         Address/Form/Framing/Read/Mux
    Net/              Target/Dialer/Route/Outbound/Dns/UdpRelay
    Middleware/       Pipeline/Context + Builtin(Auth/Dial/Mux/Pad/Relay/Throttle)
    Recognition/      Protocol/Probe/Route/Recognition/SchemeExecutor/ProbeDefense
    Runtime/          Session/Listener/SessionRegistry/Statistics + Adapter/
    Settings/         Json/Loader
  Protocols/          全协议平铺（含 Http1/Http2/Http3/Quic/Mux 子库）
    <proto>/          Types/Codec/Conn/Dgram + 聚合头（四件套，见 1.1）
    Mux/              Smux/Yamux/H2Mux（模板化 FrameCodec + Client/Server/Session）
  TestRunner.hpp  MockTransport.hpp  MockTlsServer.hpp  ProgrammableTransport.hpp  RuntimeTestHelpers.hpp  gtest_main.cpp
  Stress/             StressHelper.hpp
  Bench/              Bench.hpp
```

### 1.1 协议目录（proxy/stealth）

每个协议一个目录，**聚合头四件套**（扁平结构，无 Codec/Kdf/Chunk 子目录）：

```
tests/common/Protocols/<proto>/
  Types.hpp   — 常量、枚举、标志位、配置结构
  Codec.hpp   — 帧编解码（Build/Parse 纯函数 + 解析状态机）
  Conn.hpp    — 连接装饰器（继承 Transmission，模板化 Memory）
  Dgram.hpp   — UDP 数据报封装（需要时）
  <proto>.hpp — 聚合头（re-export 上述）
```

伪装方案同构：Types/Codec/Conn + 聚合头（无 Dgram 或按需）。

例外（**薄聚合头**，无 Codec 层，聚合头仅 re-export 子头、不定义工厂）：

```
tests/common/Protocols/Ech/    — Keygen/Scan/Types（无 Conn：SSL_ECH_KEYS 构造 + ClientHello 扫描）
tests/common/Protocols/Native/ — Types/Conn（原生 TLS 直通，无帧编解码）
tests/common/Protocols/Xhttp/  — Types/Conn（HTTP/2 stream-one，帧处理在 Http2/ 子库）
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
tests/common/Protocols/Mux/Smux/（Yamux/H2Mux 同构）
  Types.hpp   — 帧类型/常量
  Codec.hpp   — 帧编解码（模板化 FrameCodec 策略）
  Session.hpp — 会话状态机（流表/帧循环/背压，模板注入 Codec）
  Client.hpp  — 客户端封装（OpenStream 视角）
  Server.hpp  — 服务端封装（AcceptStream 视角）
  Smux.hpp    — 聚合头
```

共享 `Mux/Session.hpp` 模板框架 + `Mux/Stream.hpp`（流句柄 StreamHandle）。

## 2. 接口设计（统一 Transmission + 模板策略 + 多态）

### 2.1 传输抽象（Core/Transmission.hpp）

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

### 2.2 会话接口（Core/SessionBase.hpp）

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
| `Core/Error.hpp` | **协议编解码**（细粒度：need_more/unexpected_eof/bad_length/bad_auth/...） | `Preview::Error`（boost::system::error_category） |
| `Core/Fault/Code.hpp` | **中间件/流程**（粗粒度：io_error/timeout/canceled/auth_failed/...） | `Preview::Fault::Code` |

- 桥接：`Fault::ToCode(boost::system::error_code)` 已支持 error 转换。
- **禁止第三种体系**；新错误优先入 Error.hpp（编解码）或 Fault（流程）。

## 4. 认证抽象（Core/Authenticator.hpp）

```cpp
struct AuthResult { bool Ok; std::string identity; };
class Authenticator {
    virtual auto Check(std::string_view identity, std::string_view Secret) const -> AuthResult = 0;
};
```

- `StaticAuthenticator` / `RejectAuthenticator` 内置。
- 已接入：socks5/trojan/vless/hysteria2（vmess/ss2022 密码学校验豁免、tuic 无认证）。

## 5. 中间件管线（Core/Middleware/）

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

## 5.2 运行时骨架（Core/Runtime/，T4/T5）

```
Session            （Run：识别 → 认证/拨号/转发管线；T4-2）
Listener           （TCP AcceptLoop + 亲和性分发 FNV-1a + 会话工厂；T4-3）
Statistics         （TrafficCounter：identity 维度聚合；T4-4）
PerWorkerTraffic   （alignas(64) 原子槽 + identity 聚合；T5-2）
SessionRegistry    （COW 值拷贝快照，严禁 L3 引用；T5-7）
Adapter/           （协议接入缝：MakeProtocolAccept + 错误映射复用 Fault::ToCode（唯一表，见 §3）；协议适配器薄封装）
```

> `Core/Runtime/Adapter/` 是 Core 层**唯一的例外**：适配器直接 include 上层
> `Protocols/`（Socks5/Ss2022/Trojan/Vless/Vmess 共 5 文件 7 处），使 Core/
> 失去独立可编译性。此为 preview 期临时设计（减少接入样板），迁移方向：
> 目录上移至组合层或协议类型模板注入，纳入 NEXTGEN 迁移决策。

## 5.3 账户与限速（Core/Account/ + Core/Rate/，T5）

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
> **2026-08-25 迁移完成**：全库 `Preview::Testing`（含 MockTransport/MockTlsServer/RuntimeTestHelpers/TestRunner），
> 小写 `preview::` 体系已废弃。

- **全库 `Preview::`**；禁止历史命名体系混用与 psm:: 混用。
  - **主库依赖说明**：`TestRunner.hpp`（继承主库 `psm::diagnose` 日志）、`MockTransport.hpp`
    （继承主库 `psm::transport::transmission`）、`MockTlsServer.hpp`
    （内存 TLS 后端）、`gtest_main.cpp`
    （初始化主库 `psm::memory::system` 池）——这些是对**生产库** `psm::*` 命名空间的合法引用，
    属于 tests/common 自身 `Preview::Testing` 命名空间内的跨库调用，非本库遗留。
  - **RuntimeTestHelpers.hpp**（runtime E2E 公共样板，`Preview::Testing`
    命名空间与 TestRunner 同层）：RunCoro/echo 上游/ChainStatePtr/
    DialUpstream/TailReadGuarded 等；仅 tests/preview/core/runtime 使用。
- 库名策略：**`prism_ngx` 唯一主名**（INTERFACE 库）；
  `prism_test_common` / `vmtest_common` 仅为旧链接结构兼容别名，新代码一律链接 `prism_ngx`。
- 标识符 PascalCase（2026-08-22 规范 v2）；Doxygen 中文注释（@file/@brief/@details/@return）。
- 头文件保护 `#pragma once`；聚合头同步（新增子头必须入聚合头 + CMake）。

## 7. 测试三层模型

1. **Codec 纯函数**：Build/Parse 无 I/O 单测。
2. **回环 Session**：Client/Server 配对（MemoryStream 或 loopback socket）。
3. **错误矩阵**：坏数据/边界/超时/取消/错误码传播。

异步测试必须 `co_spawn + ioc.run()` 模式（MuxLifecycle 模式），禁止 `run_for/poll` 驱动。

## 8. 构建（CMake）

- 单一 `prism_ngx` INTERFACE 库（tests/common/CMakeLists.txt）。
- `prism_test_common` / `vmtest_common` 为兼容别名（指向 prism_ngx）。
- 全部头文件列于 target_sources（G7 完整性门禁）。
- **G7 门禁自动化**：`scripts/check_common_headers.ps1` 校验磁盘头文件与
  target_sources 双向一致（漏登记/重复/漂移），已接入 CI（build.yml 两平台）；
  支持 `-CheckMirror` 开关输出镜像分叉警告（白名单见 §9）。

## 9. 镜像复制策略

`Core/` 的部分模块与生产 `include/prism/` 存在复制关系，按文件登记：

| 目录 | 与生产关系 | 同步策略 |
|---|---|---|
| `Core/Fault/` | 镜像 `include/prism/foundation/fault/`（逐字，仅命名空间差异） | 锁定：人工比对，改动需两侧同步 |
| `Core/Exception/` | 镜像 `include/prism/foundation/exception/` | 锁定 |
| `Core/Memory/` | 镜像 `include/prism/foundation/memory/` | 锁定 |
| `Core/Crypto/` | **已分叉**（Aead.hpp 15.1KB vs 9.6KB，各自演进） | 分叉：preview 自包含实现，白名单豁免镜像 diff |
| `Core/Diagnose/`、`Core/Net/Dns/` | 部分分叉 | 待评估（Dns 已于 2026-08-26 重构为 7 层分层：Config/Format/Cache/Coalescer/Rules/Upstream/Resolver，对齐主项目 net/dns，见 A-29） |

> 镜像文件头注 `@note 镜像自 include/prism/...，同步策略：锁定/分叉`。
> `scripts/check_common_headers.ps1 -CheckMirror` 按上表输出分叉警告；
> 白名单（`$mirrorWhitelist`）中的文件允许差异，新增白名单条目必须同步更新本表。
