# Preview 下一代实现全量问题审计（当前工作树）

> 文档状态说明（2026-10-05）：本文保留原版本的分析、计划或验收快照，文中的“当前”、完成标记、路径和测试数字均属于原记录时点。今天的 Preview 入口、已执行范围与剩余责任见[开发入口](../../Preview/README.md)和[当前执行状态](2026-10-03-preview-no-compat-status.md)。本轮不改写原始历史结果；旧任务提示词需先核对现行 AGENTS.md、无兼容层计划和真实源码，不能直接替代当前任务卡。
<!-- pathcheck:historical=本文含 2026-10-05「本轮不改写原始历史结果」声明，路径按原记录时点解释；当前坐标与 git 证据映射见 .superpowers/sdd/2026-10-09-preview-quality-modification-plan/M36-DocCitationTriage.md -->

> 审查时间：2026-10-01
> 分支：`codex/preview-refactor-20260928`
> 审查对象：**当前工作树** `Preview/`、`tests/Preview/`、Preview CMake、`src/preview_main.cpp` 与 `src/prism/preview/` 桥接层
> 方法：静态源码+include+CMake target 分析；两个并行子代理分别深挖（协议/网/传输半区 与 组合/运行时/应用半区），主进程独立复核关键 CRITICAL/HIGH 证据并进行树型全局扫描。未构建、未运行测试、未启动服务。
> 证据分级：**[已验证]** = 主进程亲自读过并确认行号；**[子代理]** = 并行审计提供，行号按报告引用，未独立复核；**[推断]** = 由结构推导。
> 重要背景：本报告基于**当前工作树**，它与 `docs/preview-refactor/` 下的 9 月历史文档（9-25/9-26/9-27/9-30 各 audit）描述的状态不同——当时还是 `Application.cpp`（4408 行）、`Ingress/` 目录、`.cpp` 文件；当前树已完成 `Ingress→Boundary` 迁移、`.cpp→header-only` 化改、`Application.cpp` 拆分删除。历史文档不适用于当前树。

---

## 0. 结论摘要

Preview 是下一代纯 header-only 实现，规模 611 个文件 / 12 万行（`Preview/`），外加 `tests/Preview` 340 个 C++ 测试源。整体工程质量**明显优于旧版**（错误码、生命周期 owner、边界检查都有认真设计），但存在五类系统性问题：

1. **跨层协议服务未通过中间件收口**：UDP/QUIC 网关、AnyTLS 数据面、VLESS XUDP 等服务被塞进 `Composition/`、`Application/`、协议目录等各处，`Runtime/Middleware` 六件套（Auth/Dial/Mux/Pad/Relay/Throttle）在热路径多数是骨架/手动拼装，没有真正接管跨协议逻辑。这正是你担心的"网关类文件不在自己模块内"。
2. **物理 include 图 ≫ CMake target 图**：协议层 `#include` 了大量跨 target 头文件（Composition/Boundary/Net/Runtime），而 `PreviewBoundary.cmake` 的 `AssertPreviewDependency` 只校验 CMake 链接边、查不到头文件级越界。隐藏依赖多处存在。
3. **大量手写重复实现**：三份 `BeastCodec` 状态机、两份手写 OpenSSL AEAD 管线、VLESS 单独重写 `AddressCodec`、四套 UDP 会话表——违背 DRY，且是"屎山倾向"的主要来源。
4. **header-only 化走极端**：零 `.cpp`、连 500+ 行状态机（`NativeConnection`、`Hysteria2/Admission`、`ConfiguredMode`）都靠 `inline` 拆帽文件堆在头里；`#include` 中间夹 namespace 语义级 hack；编译单影响面极大。
5. **双后端并存**：`Preview/`（PrismPreview，纯引）与 `src/prism/preview/`（生产 fallback 桥接）+ `src/preview_main.cpp` + `include/prism/net/transport/preview.hpp` 旧 Preview 装饰器共存，职责和入口分裂。

按严重度，具体 CRITICAL/HIGH 问题见第 6 节 Bug 清单，全部带 `路径:行号`。

---

## 1. 规模与树型统计

### 1.1 总体规模（当前磁盘）

| 指标 | 数值 |
|---|---|
| `Preview/` 文件数 | 611 |
| `Preview/` 总行数 | 120,461 |
| `Preview/` 下 `.cpp` | **0**（纯 header-only） |
| `tests/Preview/` C++ 测试源 | 340 |
| 最小 pre-preview 桥接（`src/prism/preview/`+`src/preview_main.cpp`） | 4 文件 |
| 顶层 CMake 脚本长度 | `Preview/CMakeLists.txt` 1,061 行 + `CMake/PreviewBoundary.cmake` ~460 行 |

### 1.2 按顶层目录行数分布

| 目录 | 文件 | 行数 | 占比 | 主要问题 |
|---|---|---|---|---|
| `Protocols/` | 263 | 52,986 | 44% | 跨层网关/数据面塞入；三份 BeastCodec、手写 AEAD |
| `Runtime/` | 67 | 13,223 | 11% | 中间件半成品；Front include Composition |
| `Composition/` | 68 | 13,088 | 11% | 兼任"协议运行态"与"配置装配"；大量服务手工层 |
| `Foundation/` | 64 | 9,761 | 8% | 与生产 `include/prism/` 镜像双份 |
| `Application/` | 49 | 9,694 | 8% | Start.hpp 巨型启动函数；失败回滚遗漏 |
| `Net/` | 24 | 5,341 | 4% | DNS 单文件超长；UdpRelay 仅测试用 |
| `Transport/` | 13 | 3,715 | 3% | 四套 UDP 会话表 |
| `Operations/` | 11 | 2,728 | 2% | — |
| `Boundary/` | 6 | 1,704 | 1% | 网关/关联表 |
| `Account/` | 9 | 1,646 | 1% | — |
| `Lifecycle/` | 8 | 1,511 | 1% | — |
| `Scheduler/` | 5 | 1,293 | 1% | — |
| `Statistics/` | 10 | 853 | 1% | — |
| `Resource/` | 6 | 430 | <1% | — |

**单文件长度分布**：>573 行的文件约 40 个（详见第 4 节）。当前最大的单个文件是 `Protocols/Shadowsocks2022/ResponseCodec.hpp` 573 行。**注意**：AGENTS.md 规定"每个生产 header 必须不超过 600 行"，当前文件普遍逼近但未超——但这条规则只约束了单文件行数，没有约束"DGI 模块内文件总数也不该这么大"以及"逻辑上该拆而未拆"。

### 1.3 关键文件名冲突

- `Preview/Runtime/Recognition/Recognition.hpp` 里有 `Pipeline` 类（识别流水线），`Preview/Runtime/Middleware/Pipeline.hpp` 也有 `Pipeline`（中间件链），同名不同义。同一 `Preview::` 下 `Runtime::...` 与 `Middleware::...` 命名空间推进下不算冲突，但搜索/理解成本高，且两者职责在真实请求路径其实交织（识别完进 middleware）。

---

## 2. 构建系统：CMake 巨型脚本 + 边界检查与源码 include 脱节

### 2.1 CMake 本身臃肿 **[已验证]**

- `Preview/CMakeLists.txt` 1,061 行，手写 50 个 `add_library`（37 个协议 target + 10 个横向 target + boundary/diagnose），每个协议 target 逐一列源文件。
- `Preview/CMake/PreviewBoundary.cmake` ~460 行手写"允许链接表"（`_GetPreviewAllowedInternalLinks`）、graph 收集、闭包审计、顺序解析、精确大小写校验、`PRISM_PREVIEW_BOUNDARY_FAULT` 负向边测试注入。
- **评价**：这套 CMake 复杂度远超"下一代独立模块"应有的体量。它想做的事（保证模块边界）本可以通过**源码 include 图检查**直接做，而不是靠维护 50 个 target 的允许边表。且它只约束 CMake 链接边，对头文件物理 include 无效（见 2.3）。

### 2.2 CMake"故障注入"测试负向边 — 反模式 **[已验证]**

`Preview/CMakeLists.txt:1038-1057`：

```cmake
# C02 负向边的可选配置注入；默认空值不改变生产图。
if(DEFINED PRISM_PREVIEW_BOUNDARY_FAULT AND ...)
  if("${PRISM_PREVIEW_BOUNDARY_FAULT}" STREQUAL "RuntimeComposition")
    target_link_libraries(PreviewRuntime INTERFACE PreviewComposition)
  ...
```

用编译期 flag 把"合法依赖"伪装成"故障注入测试"来验证边界断言器能抓到非法边。这份测试装置属于测试基建，但写进了**生产 CMake**（1061 行的同一份文件），且 `RuntimeComposition` 这个"故障"对应的源码依赖**实际已经存在**（2.3），说明它其实是在掩盖真实违规。

### 2.3 物理 include 图 vs CMake target 图系统性脱节 **[已验证/子代理]**

这是本仓库最隐蔽的结构问题：头文件的 `#include` 越过了 CMake 边界，但 `AssertPreviewTargetGraph` 只查 `LINK_LIBRARIES`/`INTERFACE_LINK_LIBRARIES`，对 `.hpp` 里的 `#include <Preview/...>` 无感知。已知越界：

| 目标 | include 了 | 违反边界 | 证据 |
|---|---|---|---|
| `PreviewRuntime` | `Composition/Adapters/DataPlane.hpp`、`Composition/Recognition/ProtocolMatrix.hpp` | Runtime 不链接 Composition | `Runtime/Front/UdpFront.hpp:25-26`、`Runtime/Front/QuicFront.hpp:24` |
| `PreviewRuntime` (`QuicFront`) | `Protocols/Quic/GatewayCommon.hpp` 且继承之 | Runtime 不链接协议 | `Runtime/Front/QuicFront.hpp:95`（`final : public GatewayCommon`） |
| `PreviewProtocolShadowsocks2022` | `Boundary/Datagram/DatagramClassifier.hpp`、`Net/Dns/Resolver.hpp` | 协议 target 只链接 Common | `Protocols/Shadowsocks2022/Ss2022Gateway.hpp:8-9` |
| `PreviewProtocolReality/Restls/Shadowtls` | `Composition/Carrier/FacadeCarrier.hpp` | 协议反向 include Composition | `Protocols/Reality/Carrier.hpp:9`、`Restls/Carrier.hpp:9`、`Shadowtls/Carrier.hpp:10` |
| `PreviewProtocolHysteria2` | `Net/Target.hpp` | Hysteria2 不链接 Net | `Protocols/Hysteria2/Admission.hpp:33` |
| `PreviewProtocolMux` | `Runtime/SessionControl.hpp` | Mux 不链接 Runtime | `Protocols/Mux/SessionContract.hpp:29` |
| `PreviewTransport` | `Statistics/Redaction.hpp` | Transport 只链接 Foundation | `Transport/Encrypted.hpp:14` |

其中 `UdpFront/QuicFront` 由于 CMake 默认不链接 Composition/协议，连编译都只能靠"故障注入" flag。这是把**真实存在的架构违规**藏在"测试开关"后面的典型案例。

### 2.4 过渡注释即未完成重构标记 **[已验证]**

`PreviewBoundary.cmake` 里多处 `# C0X 过渡` 注释：
- 290-291 行：`# C05 过渡：Composition 暂时消费 Operations/Statistics`
- 293 行：`# C03 过渡：Configuration 暂时消费 Account 合同`
- 240 行：`# C05 拆分 Operations/Statistics 编译归属`

这些"暂时/过渡"的绕过边就是当前仍存在的耦合。Composition 作为一个"协议装配层"，**却永久链接了 Operations/Statistics（操作服务/统计）**，职责边界没有收口。

### 2.5 Preview Application CMake 的 STRICT 风格设定 **[已验证]**

`Preview/Application/CMakeLists.txt` 有 110 多行，其中：
- `set_source_files_properties(Startup/Start.hpp PROPERTIES LANGUAGE CXX)` + `add_library(PreviewApplication STATIC Startup/Start.hpp)` —— 把 `.hpp` 当 `.cpp` 编译（AGENTS.md 规定的 header-only 入口方案）；
- 输出路径硬编码断言 `PrismPreview` 必须输出到 `build/src`（`Preview/Application/CMakeLists.txt:69-78`），构建产物目录写死；
- `-Wl,--image-base,0x141000000`、`-static-libgcc` 等目标平台细节直接写死。

评价：编译模式（.hpp 当 .cpp）是 header-only + 静态库的折衷，但把"输出到 build/src"这种产物约定写进 `FATAL_ERROR` 级别的断言，违背了"构建目录可配置"的 CMake 惯例，迁移/使用 CMake preset 会被卡死。

---

## 3. 按树逐层审查

### 3.1 `Application/`

#### 3.1.1 `Startup/Start.hpp` — 571 行巨型启动函数 **[已验证]**

`Application::Start()`（`Preview/Application/Startup/Start.hpp:63` 起，一直到文件末尾）把以下全部塞进一个函数：
- GenerationPhase 构建、Diagnose 安装、account/worker context 初始化
- **SS2022 UDP gateway 的 Keys 收集 + `Ss2022Gateway` 构造 + `Send` lambda 闭包抓 `weak_ptr<RuntimeState>`**（196-251 行）
- **BoundaryDispatcher 装配：3 个回调 lambda 分别闭包 `Ss2022Gateway`/`QuicConnectionRegistry`**（177-203 行）
- NativeTLS、QUIC provider 选择（Hysteria2/TUIC 工厂构造 if-else 分支）
- UDP service 工厂 4 个（Socks5/Vless/Trojan/Vmess）+ `Services->UdpService` switch 分发 lambda
- `Services->Mux` lambda：**手工 switch `detected` 协议类型** → `VlessXudp::Run` / `AnytlsService::Run` / `MuxService::Run`（383-425 行）
- `ProtocolProfile::MakeTcpProfile`、listener、worker start、operations 启动

一个函数里同时出现了"拉平所有跨层组件的注册"——这本质上就是没有中间件的直接后果：跨协议特殊逻辑无法插拔进 pipeline，只能在一个巨型 `Start()` 里用 lambda 和 `switch` 粘合。

#### 3.1.2 `Start()` 失败回滚遗漏：`MakeTcpProfile` 分支无 rollback **[已验证]**

`Start.hpp:430-435`：

```cpp
const auto Profile = ProtocolProfile::MakeTcpProfile(ProtocolContext, BindingMuxModes);
if (!Profile)
{
    LastError_ = Profile.error();
    return std::unexpected(*LastError_);   // ← 没有 RunStartupRollback！
}
```

前后所有失败分支（112、137、258、285、308、324 行）在返回前都调用 `Shutdown::RunStartupRollback(...)`，唯独这个分支**直接返回**。此时已创建 Runtime、Diagnose、account、DNS、Boundary 网关等资源都不会被回滚，`State_` 也不 `reset()`。失败场景：协议 profile 构建失败（如某协议 factory 未注册）→ 进程带着半初始化的 runtime 继续运行或泄漏。属真实缺陷。

#### 3.1.3 `Application/RuntimeState.hpp` — 145 行的"上帝状态体" **[已验证]**

145 行里平铺了 30+ 个跨 8 个模块的 `shared_ptr/unique_ptr`（`RuntimeState.hpp:60-144`）：AccountDirectory、ConfigurationGeneration、EventRing、Resolver、DatagramClassifier、QuicPacketGateway、QuicConnectionRegistry、Ss2022Gateway、BoundaryDispatcher、DiagnoseRuntime、SessionServices、Process、Listener、DatagramListener、MuxService、OperationsServer 等。**它就是"把所有跨协议服务握在手里"的结构化形态**——中间件化应该让这些跨层服务以可插拔协议 provider 注册，而不是让 application 状态体持有全部。

#### 3.1.4 Application 配置/验证 9 文件堆叠 **[子代理]**

`Application/Configuration/Validation/` 9 个文件（ValidationTypes/Common/Schema/ProtocolIndependent/Reference/Capability/Secret/Carrier/Configuration）承担校验，其中 `ReferenceValidation.hpp` 588 行单函数 `ValidateProtocolBindings` 117 行。与 `Composition/Settings/Loader` 构成**两套配置加载/校验体系并存**（3.3.4）。

### 3.2 `Runtime/`

#### 3.2.1 中间件六件套（Auth/Dial/Mux/Pad/Relay/Throttle）热路径手动拼装 **[子代理]**

`Runtime/Session/DataPlaneRelay.hpp` 是真实请求路径核心：
- `RunStream` 直接手动调 `AuthMiddleware::Handle`（约 161 行），未走 Pipeline 统一调用点；
- `RunMux` 直接调用 `Run` 回调（约 110 行），`MuxMiddleware` 基本是 no-op；
- `RunDatagram` 在两个位置直接调用 datagram service（约 138 行）；
- Dial 只包了一个元素 Pipeline（约 215-218 行），是"仪式性管线"。

结果：管线框架存在，但热路径的跨协议新增逻辑（VLESS XUDP、AnyTLS、UDP relay、mux 接管、SS2022 UDP gateway）都绕过它，落在 `Start.hpp`、`Composition/`、`Application/` 的手工分支里。**中间件化的目标（协议特殊逻辑可插拔）没有达成**。

#### 3.2.2 `Runtime/Recognition/` 31 个文件 — 识别子系统的复杂度爆炸 **[已验证/子代理]**

31 个文件管理"协议识别 + 每协议配置 + 混合试用（MixedTrial_* 6 个）+ 确定性/配置模式 + 深度探测（ProbeDefense/RawIngressProbe）"。`Tls.hpp` 566 行（ClientHello 解析器全 inline）、`Recognition.hpp` 407 行、`ConfiguredMode.hpp` 428 行。这套识别子系统承担了 Reality/Restls/ShadowTLS/Anytls 等多种 TLS 伪装方案的识别，复杂度有部分合理性，但：
- `MixedTrialPlan/Attempt/Decision/Cleanup/Model/Mode` 六个文件是同一状态机的碎片化切片；[子代理] 认为可合并；
- `Pipeline` 类名与 Middleware::Pipeline 撞名（1.3）。

#### 3.2.3 `Runtime/Front/UdpFront.hpp` + `QuicFront.hpp` = 第二套 UDP/QUIC front **[已验证]**

`QuicFront`（`Runtime/Front/QuicFront.hpp:95`）继承 `Protocols/Quic/GatewayCommon`，管理连接/流/数据报绑定；`UdpFront` 管理 datagram。但**当前 Application 的真实 UDP 入口是 `Boundary/Datagram/DatagramListener` + `Boundary/Quic/QuicConnectionRegistry`**（`Start.hpp` 只装配 Boundary 组件，从未构造 UdpFront/QuicFront）。这是两套平行的 UDP/QUIC 入口 API，语义未证明等价。历史审计（9-30）已记录该问题，当前树仍存在。且两套 API 里只有 Boundary 被接线，Runtime/Front 属于"公开但未接入生产"的平行实现。

#### 3.2.4 `Runtime/Recognition/Recognition.hpp` 的 `Pipeline` 与 `Runtime/Middleware/Pipeline`：[已验证] 命名冲突见 1.3。

### 3.3 `Composition/`

#### 3.3.1 Anytls 数据面 7 文件 vs 协议目录 4 文件 — 协议被劈两半 **[子代理]**

`Composition/Anytls{Service,Wire,Frame,Session,Stream,Relay,Close}.hpp`（约 2000 行）承载 AnyTLS 的 SETTINGS/SYN/PSH/FIN 帧循环、stream relay、关闭 owner；`Protocols/Anytls/`（4 文件 537 行）只放类型/编解码。`AnytlsService::Run` 是帧 dispatch 服务入口，从 `Start.hpp` lambda 被调用。**同一个协议的两个模块物理分离**，这是典型"协议数据面散在组合层"。

#### 3.3.2 `VlessXudp.hpp` — VLESS XUDP 协议数据面放 Composition **[已验证]**

`Composition/VlessXudp.hpp` 523 行：`Run()` 是 VLESS CommandMux UDP 服务端数据面（帧解析/会话表/上游 UDP 转发）。`ReadFrame`/`WriteDatagram`/`ReadAddress`（约 96-292 行）是纯协议解析逻辑，应属 `Protocols/Vless/`。它放在 Composition 表明 Composition 在承担协议运行态。

#### 3.3.3 `UdpService.hpp` 554 行 + `DatagramService.hpp` — UDP 中继工厂 **[子代理]**

`UdpServiceLogger.hpp`/`UdpService.hpp` 的每个 `Run*` 是各协议 UDP 中继数据面的完整实现（Socks5/Vless/Trojan/Vmess），通过 `datagram data-plane Service` 回调被调用，**绕过 Middleware/Pipeline**。UDP 中继是一个典型中间件候选——它跨协议、跨连接生命周期、和拨号/限流/统计正交——但现在被做成四个相似的手工数据面。

#### 3.3.4 两套配置加载：`Composition/Settings/Loader(+LoaderModels+LoaderRecognitionHelpers)` vs `Application/Configuration` **[子代理/已验证]**

- `Composition/Settings/`：`Loader.hpp` 535 行 + `LoaderModels.hpp` + `LoaderRecognitionHelpers.hpp` + `Json.hpp`（自维护 JSON parser）——**生产不调用**（`rg LoadConfig` 仅 `tests/Preview/core/settings`），是死路径但占大头；
- `Application/Configuration/`：Glaze + 校验体系，生产启动主路径。
两套并存，徒增维护面。

#### 3.3.5 `Composition/Recognition/` 17 文件 — 两套候选工厂 **[子代理]**

`CandidateFactory.hpp`(433)/`CandidateFactoryHelpers.hpp`(415)/`TlsCandidateFactory.hpp`/`TlsCandidateModel.hpp`/`LayeredCandidateFactory.hpp`/`ProfileBuilder`/`SettingsBuilder`/`ProtocolMatrix` 等，与 `Runtime/Recognition/` 的 `Candidate/Profile/CandidateSelection/ConfiguredMode` 构成**两套候选构建体系**。`SettingsBuilder::Build...`（`SettingsBuilder.hpp:150`）等只被测试消费。生产走的候选路径和 Composition 里的候选构建器牵连不清。

### 3.4 `Boundary/`

#### 3.4.1 网关位置总体合理（相对改进），但复杂度集中 **[已验证]**

`Boundary/` 6 文件把"UDP 入口 + QUIC CID 路由 + 关联生命周期 + 分发"收拢成一个独立模块，方向正确。问题在实现复杂度：
- `DatagramListener.hpp` 用 **8 个 atomic<bool> 状态**（Started/Closed/Bound/Ready/Draining/ReceiveLoopStarted/ReceiveLoopCompleted + 转移）+ channel 完成信号 + `Health()` 快照。状态机比需要的复杂；
- `QuicPacketGateway.hpp` 五阶段 readiness（Socket/ReceiveLoop/Handshake/Protocol）+ Draining/Closed/Failed，且**单连接预算超限会全局 Failed**（见 Bug：第 6 节 B-01）；
- `DatagramAssociation.hpp` 的 `Table` + `Association` 生命周期管理完整，但协议层仍各自带一份 UDP 会话表（见 3.6.4），未收敛到这里。

#### 3.4.2 `BoundaryDispatcher` 三回调闭包 Application **[已验证]**

`BoundaryDispatcher::Options`（`Start.hpp:177-203` 构造）传 3 个 lambda：首包未知 CID → SS2022 抢判定；普通包 → SS2022 或 QuicConnectionRegistry；另有事件日志。`weak_ptr<RuntimeState>` 闭包抓 application 状态。这本质上把"SS2022 vs QUIC 的数据面路由"用手工 lambda 写死在 Application 装配里——正是你所说的"可以通过中间件/typed provider 实现"的东西。

### 3.5 `Protocols/`

#### 3.5.1 文件归属错位总表 **[子代理/已验证]**

| 文件 | 属于协议编解码吗？ | 实际承载 | 放错后消费方 | 证据 |
|---|---|---|---|---|
| `Protocols/Shadowsocks2022/Ss2022Gateway.hpp` | ❌ | SS2022 UDP 网关（认证、peer 表、replay window、DNS、outbound relay） | `Application/Startup/Start.hpp`、`RuntimeState.hpp:24`、`BoundaryDispatcher` | `Ss2022Gateway.hpp:42-389` |
| `Protocols/Vless/UdpTunnel.hpp` | ❌ | VLESS UDP-over-TCP 数据面中继（空闲计时、DNS、转发） | `Composition/UdpService.hpp:36`（`MakeVless`） | `Vless/UdpTunnel.hpp:83-397` |
| `Protocols/Quic/GatewayCommon.hpp` | ❌ | QUIC 网关连接表基类 | `Runtime/Front/QuicFront.hpp:95` 继承 | `GatewayCommon.hpp:91-170` |
| `Protocols/Hysteria2/Admission.hpp`(+559行) / `Protocols/Tuic/Admission`+`AdmissionRuntime` | ❌ | QUIC 账户租约/admission（跨层会话服务） | Application/Composition | `Hysteria2/Admission.hpp:140-560` |
| `Protocols/Mux/SessionContract.hpp` | ⚠️ | 竟然 include `Runtime/SessionControl.hpp` | 进程内 SessionControl 是 Runtime 层概念 | `Mux/SessionContract.hpp:29` |

**结论**：你观察到的"网关/特殊逻辑文件不归位"在协议层确实存在，且集中表现为"UDP 网关（SS2022）、UDP 数据面（VLESS）、QUIC 网关基类、账户 admission（Hysteria2/TUIC）"四类—这些都是天然的中间件/typed provider 候选。

#### 3.5.2 手写重复实现（DRY 严重违反）**[已验证/子代理]**

- **三份 BeastCodec**：`Socks5/BeastCodec.hpp`(324)、`Vless/BeastCodec.hpp`(~219)、`Trojan/BeastCodec.hpp`(245)，同一种"Message 值对象 + Serializer 增量写 + Parser 增量读/超读"模式，几乎逐行镜像。可收敛为 `Common/` 模板。
- **手写 OpenSSL AEAD 两份 vs 共享封装一份**：`Shadowsocks2022/ResponseCodec.hpp:148-289`（`UdpSeal/UdpOpen` + 手写 `CryptSeparate` AES-ECB）、`Shadowsocks2022/ChunkCodec.hpp:64-305`（`AeadSeal/AeadOpen`）都是手写 EVP；而 `Vmess/ChunkCodec.hpp:48` 用的是 `Preview::Crypto::AeadCipher::Aes128Gcm`（`Foundation/Utility/Crypto/Aead.hpp:394` 现成封装）。同库内"一个协议用共享封装，另一个协议手写两遍 EVP"，荒谬。
- **VLESS 单独重写 AddressCodec**：`Common/Address.hpp:220-273` 已有 `EncodeAddress<Addr,Alloc>` 模板；`Socks5/AddressCodec.hpp`/`Trojan/AddressCodec.hpp` 只是薄壳转发；`Vless/AddressCodec.hpp`(219) 却整份重写 `EncodeAddressBody/ParseAddressBody`。VLESS ATYP 枚举值（`Vless/Types.hpp:46-54`）与 Socks5/Trojan 不同，但 `Common` 模板已用 `EnumT` 参数化，本可复用。
- **四套 UDP 会话表**：`Boundary/Datagram/DatagramAssociation.hpp`（Table+Association）、`Protocols/Socks5/UdpAssoc.hpp`、`Protocols/Vless/UdpTunnel.hpp`、`Net/UdpRelay.hpp`(398) 各自实现关联生命周期/超时/配对。`DatagramAssociationTable` 已存在且被 Boundary 使用，协议层却不用。

#### 3.5.3 协议内不一致（命名/错误语义）**[子代理/已验证]**

- **命名空间 `Http11`**：`Protocols/Http1/*` 全部 `namespace Preview::Http11`（`Http1/Parser.hpp:29`、`Conn.hpp:38`）——Http2=Http3=Http2/Http3，只有 Http1 拼成 `Http11`。
- **bool 错误语义混用**：`Hysteria2/Io.hpp` 的 `ReadExact`/`SendBytes` 返回 `true=失败`；`Vless/UdpTunnel.hpp:282` `ReadExactWithTimeout` 返回 `true=成功`（`co_return !ReadError && ...`）。调用方稍不留神就写反。
- **include-in-middle 绕循环依赖**：`Hysteria2/Admission.hpp:193-198` 中途关/开 namespace 并夹 `#include <DatagramSession.hpp>`/`<StreamSession.hpp>`——文件内 hack。
- **注释语言不统一**：中英混排（`NativeConnectionCallbacks.hpp` 全英、`NativeConnectionStreams.hpp` 全中），与 CLAUDE.md"禁止英文注释"冲突。

### 3.6 `Transport/`

- `Transmission` 抽象面：`NextLayer()` 装饰链 + `AsyncWrite`/`async_read_some`/`async_write_some`（completion-handler 与 awaitable 双 API）+ `Close/Cancel`。`PreviewTransport`（`Transport/Preview.hpp:193`）等包装器结构清晰。
- **漏洞**：`Type` 枚举（`Tcp/Udp/Frame` 等）被用于掩盖 byte stream vs datagram vs QUIC 的差异，但 `Transport/Unreliable.hpp`、`DatagramAdapter`、`QuicNativeConnectionStreams` 的传输语义并不等价（见历史审计）。[子代理]
- 四套 UDP 会话表见 3.5.2。

### 3.7 `Foundation/`

#### 3.7.1 与生产 `include/prism/` 镜像双份维护 **[已验证]**

`Preview/Foundation/` 中多处标注"镜像自 include/prism/... 同步策略：锁定"：
- `Foundation/Fault/Code.hpp` 逐字镜像生产 `include/prism/foundation/fault/code.hpp`，仅把 `psm::fault` 改 `Preview::Fault`、snake_case 改 PascalCase；
- `Foundation/Exception/{Deviant,Network,Protocol,Security}.hpp`、`Foundation/Memory/{Pool,Container}.hpp` 同。

这意味着 Preview 与旧版基础类型**物理隔离但内容重复**，靠"同步策略：锁定"约束（即不许改动）。一旦旧版升级（补错误码、修 bug），Preview 不会自动跟上，且两套错误码枚举数值可能漂移。这是"复制代码 = 双份维护"的最直接例子。

#### 3.7.2 `Foundation/Utility/Diagnose/` — 参考级分层，但 11+8 文件膨胀

Diagnose 是 CLAUDE/AGENTS 反复提到的"参考模块"（facade/backend 分离、README 427 行）。它确实分层清晰，但文件数已达 11 个头 + 8 个 `Detail/` + 一个 427 行 README，辅助日志系统 = 整套框架。`README.md:211` 甚至规定了 `TryWith()` 传参的左值约束等"文档即契约"细节——这套日志框架在本库其它模块是标杆，但对一个日志系统而言复杂度已经不低。

### 3.8 `Net/`

- `Dns/` 12+6 文件，`Format.hpp` 555 行（一整份 DNS 报文编解码 inline）+ `Resolver.hpp` 544 行 + `Cache.hpp`/`Coalescer.hpp`/`Rules.hpp`/`Upstream.hpp`/`Doh.hpp`/`ConnPool.hpp`——DNS 子系统是仅次于协议层的第二大单域，单文件 500+ 行居多（可拆但结构尚清）。
- `Net/UdpRelay.hpp` 398 行**生产零消费者**（仅测试）：见第 5 节死代码。
- `Net/Route/Route.hpp` + `Net/Outbound/Outbound.hpp` 生产路径无强消费？[子代理] 标注为待核（生产 `Start()` 用的是 `Services->Dial` lambda + `DialTargetWithResolver`，未走 Route/Outbound 类的实例方法）。

---

## 4. 单文件超长清单（> 520 行，共约 40 个）

以下文件均接近或超过 AGENTS 的 600 行上限（按当前磁盘行数，排序）：

| 文件 | 行数 | 拆因 |
|---|---|---|
| `Protocols/Shadowsocks2022/ResponseCodec.hpp` | 573 | 手写 AEAD + UDP 全管线 |
| `Application/Startup/Start.hpp` | 571 | 巨型启动函数（见 3.1.1） |
| `Runtime/Recognition/Tls.hpp` | 566 | ClientHello 解析全 inline |
| `Application/Configuration/Validation/ReferenceValidation.hpp` | 562 | 单函数 117 行 |
| `Operations/Routes/HttpJson.hpp` | 561 | JSON writer 全 inline |
| `Net/Dns/Format.hpp` | 555 | DNS 编解码全 inline |
| `Protocols/Hysteria2/Conn.hpp` | 555 | 握手+数据面+UDP 全塞一个类 |
| `Runtime/Listener.hpp` | 553 | — |
| `Lifecycle/TaskRegistry.hpp` | 551 | CAS 重试/barrier 逻辑内联 |
| `Protocols/Http3/NativeClient.hpp` | 547 | — |
| `Net/Dns/Resolver.hpp` | 544 | — |
| `Protocols/Http2/Codec.hpp` | 543 | Frame+HPACK 全 inline |
| `Protocols/Http1/ForwardResponseFramingDetail.hpp` | 542 | ~20 个状态机方法全 inline |
| `Protocols/Hysteria2/Dgram.hpp` | 542 | — |
| `Runtime/SessionControl.hpp` | 540 | — |
| `Application/ProtocolAcceptors.hpp` | 535 | — |
| `Composition/Settings/Loader.hpp` | 535 | JSON 手工解析 |
| `Foundation/Utility/Diagnose/Detail/ContextDecoder.hpp` | 532 | — |
| `Protocols/Http1/ForwardRequestTransport.hpp` | 526 | — |
| `Protocols/Restls/Conn.hpp` | 526 | — |
| `Composition/VlessXudp.hpp` | 523 | 协议数据面放 Composition |
| `Protocols/Quic/NativeConnection.hpp` | 523 | 前置声明+5 个拆帽文件 |

**重点病理**：`Protocols/Quic/NativeConnection.hpp` + `NativeConnection{Transport,Streams,Datagrams,Lifecycle,Callbacks,Providers,Facades}.hpp`（8 文件共 ~3000 行）= 一个类被物理切开但**全部 inline**，毫无编译边界的"伪拆分"——既没达到 header-only 的隔离效果，还制造了符号间循环引用的麻烦（`NativeConnectionCallbacks` 全是空回调，见第 5 节）。

---

## 5. 死代码 / 未接线代码

| 严重 | 内容 | 证据 |
|---|---|---|
| HIGH | `Protocols/Common/Form.hpp` 无人 include | 全库 grep 0 命中；协议层不用其枚举 |
| HIGH | `Protocols/Common/Mux.hpp` `IsMuxTarget()` 无人调用 | 全库 grep 0 命中 |
| MEDIUM | `Net/UdpRelay.hpp` 398 行仅测试消费 | `rg` 仅 `tests/...UdpRelayTest.cpp`、`NetworkingStressTest.cpp` |
| MEDIUM | `Protocols/Quic/GatewayCommon::GuessProtocol()` 恒返回 Unknown | `(void)FirstBytes; return Unknown;`，诱饵 API |
| MEDIUM | `NativeConnectionCallbacks.hpp` 三空回调 `AckDatagram/RecvRetry/VersionNegotiation` | 注册进 callback table 但空实现；`recv_retry` 空 = 对 Retry 无响应，`ack_datagram` 空 = DATAGRAM ACK 丢失触发对端无限重传 |
| MEDIUM | `Composition/Settings/Loader` 及 `LoaderModels/LoaderRecognitionHelpers` 生产无消费 | 仅 `tests/Preview/core/settings` 用；生产走 Glaze `ConfigurationParser` |
| MEDIUM | `Composition/Recognition/SettingsBuilder` 的 `BuildProfileFromSettings/BuildSessionOptionsFromSettings/MakeSessionFactory` 无生产调用 | 生产用 `ProtocolProfile::MakeTcpProfile` |
| MEDIUM | `Composition/Api/` 无生产消费 | 仅 `Performance/StatisticsBenchmark.hpp` 引用 |
| LOW | `Transport` 里 `Stream` 抽象 vs `Transmission` 的关系需确认 || 

**双世代桥接**（非死代码但易混淆）：
- `src/prism/preview/ProductionWorkerServices.hpp`——include 新 `Preview/` 的 `ProtocolAdapter/Socks5Factory/CandidateFactory/Dialer/Session/Reliable`，把新 Preview 协议接入旧 production worker；
- `src/preview_main.cpp`——旧 Preview 启动入口，**数据面明确用 production fallback**，`preview_protocol_adapters=0`（文本里有 `"prism_preview"`... 实际日志写明 `preview_protocol_adapters=0`）；并用自己的 `PreviewRuntimeConfig` 再定义 `Mode{hybrid}`。
- `include/prism/net/transport/preview.hpp`（旧 preview 装饰器，20 个调用者）。
三段平行 Preview 认知：`Preview/` 新一代、`src/prism/preview/` 过渡桥、`include/prism/net/transport/preview.hpp` 旧装饰器。历史文档 9-30 已指出，当前树仍存在。

---

## 6. Bug 清单（按严重度排序）

### CRITICAL

**[已验证] B-01 `QuicPacketGateway::Handle` 单连接预算超限/handler 拒绝 → 全局永久 Failed**
`Boundary/Quic/QuicPacketGateway.hpp:203-206，292-296`：`if (State->Packets >= Options_.MaxPacketsPerConnection) { MarkBoundedFailure(); return false; }`，且 `Handler` 返回 false 或 `Options_.Dispatch` false 也 `MarkBoundedFailure()`。`MarkBoundedFailure` 置 `BoundedFailure_=true`、`Readiness=Failed`，`Health().Healthy()` 要求 `!BoundedFailure`（50-51 行）。
**失败场景**：任意一个连接达到 65,536 包，或 SS2022 抢判定回调/Hysteria2 handler 拒了一次 → **整个 gateway 进入 Failed，所有其它正常 QUIC/TUIC/Hysteria2 连接全部失去服务**。应 per-connection 记账。注：`>=` 让第 65,536 个包就触发（应 `>` 或允许最后一包）。

**[已验证] B-02 `Ss2022Gateway::Process` 每包新建临时 UDP socket，只收一个上游回包即丢弃**
`Protocols/Shadowsocks2022/Ss2022Gateway.hpp:265-291`：`Net::ip::udp::socket Socket(Strand_);` 局部变量，`async_send_to` 一个载荷后 `(async_receive_from || Timer)` 竞速，收到第一包或超时即 `co_return`，socket 析构。
**失败场景**：客户端经 SS2022 UDP 会话向上游发查询，上游回复**多个分片/多包**（大 DNS、QUIC-ish 或 UDP 流式应用）→ 只回第一包，其余全丢。且每个 client 包都新建一个临时 socket/端口，破坏 NAT 会话保持。`PeerState` 里却维护了 `NextPacket/ReplayBits`（关联型语义），与"每包一问一答"的实现自相矛盾。

**[已验证] B-03 `Start.hpp` `MakeTcpProfile` 失败分支无 rollback**
`Application/Startup/Start.hpp:430-434`：唯一一个失败后 `return` 却不调用 `RunStartupRollback`/`State_.reset()` 的分支（前后 112/137/258/285/308/324 行均 rollback）。
**失败场景**：协议 profile 构建失败 → Runtime 半初始化状态留在对象内，后续 `Run()` 可能继续访问空 `ProviderBindings`/`Profile` 崩溃，或内存不释放。

### HIGH

**[子代理] B-04 `VlessXudp::Run` 请求-响应串行 + 64KB 栈缓冲**
`Composition/VlessXudp.hpp:516-527`：每个 client datagram 先 `async_send_to` 上游，然后 `(async_receive_from || ResponseTimeout)` 阻塞等第一个上游回包，超时 `continue`。
**失败场景**：上游静默/慢 → 后续 client datagram 全部排队串行；`std::array<uint8_t, MaxDatagram=65535> Response{}` 64KB 在协程帧中随每个会话常驻。适用于查询型 UDP，对 UDP 流式/多包回复吞吐是瓶颈，且超时被当成"正常 continue"而非错误上报。同模式也出现在 `UdpService::RunStreamDatagrams`（`UdpService.hpp:348-352` 等，超时 break 后返回 Success，而非 Timeout 语义）。[子代理]

**[子代理] B-05 `Ss2022Gateway::Handle` 每包 detached spawn 无并发上限**
`Ss2022Gateway.hpp:99-106`：`co_spawn(Strand_, ... Process(...), detached)`；`Handle` 是同步入口每包裸 spawn。虽有 `MaxPeers{1024}`，但 spawn 发生在 `AcceptPeer` 之前（Process 内部才限制 peer 数），协程本身无上限。攻击者可打满 strand/内存。治理方式：入口做 in-flight 计数/有界队列，或改为单 pump 循环。

**[已验证] B-06 `NativeConnectionStreams.hpp:233-238` 冗余 if**
```cpp
if (ErrorCode) { co_return Offset; }
co_return Offset;
```
两分支返回同一值，`if (ErrorCode)` 无意义。若意图是"部分写入 + 错误"，调用方看到 `ErrorCode!=0` 时 `Offset>0` 会被当成部分写入而上层重复重发；若意图不同，实为死分支。需明确语义合为一个 return。

### MEDIUM

- **[已验证] B-07 `Runtime/Recognition/Tls.hpp` 566 行**“全 inline ClientHello 解析 + `ParseServerName/Alpn` 等无状态工具”——结构上属"头文件承载实现"，故障定位/编译影响面大，非逻辑 bug 但维护熵高。
- **[子代理] B-08 `TaskRegistry` ReserveTaskId 泄漏**：`Lifecycle/TaskRegistry.hpp:390-398` 等 `Barrier.Enter()` 失败后未释放已保留的 TaskId/globalId（关闭/容量边界），`PostTaskRegistryCommand` 失败时也保留 id 不释放。集中在关闭、容量 edge，非常规热路径但真实。
- **[已验] B-09 Application 与生产的双份错误码/类型镜像**（3.7.1）：同步策略"锁定"表示两套不会自动一致，错误码数值漂移风险真实存在。
- **[子代理] B-10 `AnytlsService` 任何位置注入的硬编码服务端指纹**：`"v=2\nserver=prism\n"` 硬编码到 SETTINGS，违反"不暴露实现指纹"（但 CLAUDE 未列指纹为禁止项，标 MEDIUM）。
- **[子代理] B-11 `UdpService` 超时被静默当作 Success**（见 B-04）：idle timeout 返回 Success 而非 Timeout，日志/统计失真。

### LOW

- `BoundaryDispatcher` 事件回调 `catch(...)` 吞异常（日志盲区）。[子代理]
- `GatewayCommon::GuessProtocol` 恒返回 Unknown（见第 5 节）。
- `Http11` 命名（3.5.3）。

---

## 7. 中间件化建议 —— “协议特殊逻辑应走中间件”怎么落

你的判断是对的：这些"特殊协议逻辑"（SS2022 UDP 网关、VLESS XUDP、AnyTLS 数据面、UDP 中继、mux 接管、TUIC/Hysteria2 admission）**天然应该以 typed provider / middleware 形式注册**，而不是：
- 塞进 `Protocols/`（Ss2022Gateway、Vless/UdpTunnel）；
- 塞进 `Composition/`（Anytls*、VlessXudp、UdpService、MuxService）；
- 塞进 `Application/Startup/Start.hpp`（BoundaryDispatcher lambda、Mux switch）；
- 塞进 `Application/RuntimeState.hpp`（30+ 跨层指针）。

**建议方向**（优先级排序）：

1. **建立"协议 provider"槽位**：一个类（`ProtocolProvider`）把 `{wire codec, auth/admission, session factory, udp/carrier 能力}` 收进协议自身模块；Composition 只做注册 + 选择 + 持有已绑定实例。这样 `Start.hpp` 不再需要为每种协议手工 `MakeXxxOptions`/`switch`。
2. **UDP/QUIC 数据面收口到 `Boundary/` + 中间件**：SS2022 网关的"认证+peer+relay"下沉 `Protocols/Shadowsocks2022`（已下沉大半，把 relay 循环设计成**关联型长连接**而不是每包临时 socket 修 B-02）；`UdpService`/`VlessXudp`/`DatagramService` 收敛为**单一 UDP 中间件**接收 typed provider 回调。
3. **复用现有 `Runtime/Middleware` 管线**：把 `DataPlaneRelay` 里手动调用的 Auth/Dial/Relay/Mux/Pad/Throttle 真正挂到 `Pipeline` 上，让跨协议新增逻辑以 middleware/typed provider 注册，补掉 `MuxMiddleware` no-op、`Pad` 未接管线等缺口。
4. **收敛重复实现**：`Common/` 承接 `BeastCodec` 模板、地址编解码模板（消除 Vless 重写）、四套 UDP 会话表收敛到 `Boundary/DatagramAssociationTable`；SS2022 的 AEAD 复用 `Foundation/Utility/Crypto/Aead.hpp`。
5. **修复 include-vs-target 脱节**：要么补 CMake 链接边让 target 图 = include 图，要么（更推荐）给 `PreviewBoundary.cmake` 增加**源码 include 图检查**（`.hpp` 彼此 include 的文件归属必须落在允许边内），让边界断言真正防住头文件级越界。
6. **二选一消除双后端**：以 `Preview/` + `PrismPreview` 为准，把 `src/prism/preview/`、`src/preview_main.cpp`、`include/prism/net/transport/preview.hpp` 明确标为退役/删除，只留一个 Preview 入口。

---

## 8. 与历史文档的关系

`docs/preview-refactor/` 下 9/26-9/30 的多份 audit 基于**重构前**状态（`Application.cpp` 4408 行、`Ingress/`、`.cpp` 文件、`QuicAdmissionContext` 等）。当前工作树已：
- `Ingress/` → `Boundary/`（`UdpListener`→`DatagramListener`、`QuicGateway`→`QuicPacketGateway`、`QuicCidRegistry`→`QuicConnectionRegistry` 等）；
- `Application.cpp` 44xx 行 → 删除，拆成 `Application.hpp` + `RuntimeState.hpp` + `Startup/Start.hpp` 等；
- 全 `header-only`（0 个 `.cpp`）；
- `Native.cpp` 2580 行 → header 化拆分（`NativeConnection*` 8 文件）。

所以历史文档的**具体行号和文件级断言在本树不成立**，但其**核心定性**（协议 owner 不收拢、include 越界、两套 UDP/QUIC 入口、死代码）在本树依然成立——本报告已在当前树重新取证。

---

## 9. 最重要结论（Top 5）

1. **协议特殊逻辑没有通过中间件收口**，散在 `Protocols/`（Ss2022Gateway、Vless/UdpTunnel、Hysteria2/Tuic Admission）、`Composition/`（Anytls*、VlessXudp、UdpService、MuxService）、`Application/Startup/Start.hpp`（巨型 lambda + switch）与 `RuntimeState.hpp`（30+ 跨层指针）。这是"臃肿"的根因，也解释了为什么文件归属错位。
2. **物理 include 图样例越过 CMake target 图**（至少 8 处已知），`PreviewBoundary.cmake` 只能检查链接边防不住头文件 include，且 `PRISM_PREVIEW_BOUNDARY_FAULT=RuntimeComposition` 在掩盖真实违规。
3. **CRITICAL 级 3 个真实 bug**：`QuicPacketGateway` 全局失败传播（B-01）、`Ss2022Gateway` 每包临时 socket 单回包（B-02）、`Start::MakeTcpProfile` 失败不回滚（B-03）——其中前两个影响真实数据面正确性，第三个影响启动健壮性。
4. **大量手写重复**（三份 BeastCodec、两份手写 AEAD、VLESS 重写 AddressCodec、四套 UDP 会话表）构成"屎山"倾向，且与 `Foundation/Utility/Crypto/Aead.hpp` 这类现成封装共存，说明是"没来得及收敛"而非"不可复用"。
5. **header-only 走极端 + 双后端并存**：0 `.cpp`、500+ 行状态机靠拆帽 inline 文件堆在头层、`Preview/` 与 `src/prism/preview/`+`src/preview_main.cpp`+旧 `preview.hpp` 多套 Preview 认知并存，是下一步重构最需要先决策的两个结构性命题。

---

## 附录 A：独立验证记录

主进程复核过的关键证据（读文件原文确认）：
- `Preview/Application/Startup/Start.hpp:430-434` — MakeTcpProfile 无 rollback（B-03）✅
- `Preview/Protocols/Shadowsocks2022/Ss2022Gateway.hpp:99-106`（每包 spawn）、`:265-291`（局部 socket 单回包）✅ B-02/B-05
- `Preview/Boundary/Quic/QuicPacketGateway.hpp:203-206, 292-296`（全局 failed）✅ B-01
- `Preview/Protocols/Quic/NativeConnectionStreams.hpp:233-238`（冗余 return）✅ B-06
- `Preview/Composition/VlessXudp.hpp:505-541`（串行请求-响应 + 64KB 栈缓冲）✅ B-04
- `Preview/Application/RuntimeState.hpp:60-144`（30+ 跨层指针）✅
- `Preview/CMakeLists.txt:1038-1057`（故障注入）✅
- `Preview/Foundation/Exception/Security.hpp:10`、`Fault/Code.hpp:10-13`（镜像自生产）✅

## 附录 B：未验证/需后续运行时确认

- 子代理报告中的 `TaskRegistry` ID 泄漏（B-08）、`UdpService` 超时静默（B-11）、`Http1` `Http11` 拼写影响面——未在运行时复现，行号为来源引用。
- `Net/UdpRelay.hpp` 生产零消费（`rg` 结果，未在线程内逐一验证 target 链接）。
- `NativeConnection` 空回调 `ack_datagram/recv_retry` 对 ngtcp2 的实际影响（取决于 ngtcp2 是否要求必实现，未查 API 文档确认）。
