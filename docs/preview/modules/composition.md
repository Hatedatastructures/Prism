# Composition 模块

## 职责与边界

Composition 拥有编译期 builtin/协议描述、能力校验、配置到 typed provider 的冷路径准备，以及 Prepared → Frozen → Bound 的一次性装配。成功绑定后的 `BoundCatalog` 持有各真实 protocol owner、mux root 和 carrier owner，并提供冷路径查找与关闭/排空入口。

Composition 不拥有协议 wire/auth 状态机、listener、packet/frame 热循环或 Application 启停。具体协议 binding 实现关闭、取消、stream half-close 和最终 close；Composition 只转发关闭并在调用者驱动的 executor 上等待 typed drain 结果。

## 关键源码

- [ProtocolCatalog.hpp](../../../Preview/Composition/Protocol/ProtocolCatalog.hpp)：builtin 名称、协议类型和能力描述。
- [Builtin/Registry.hpp](../../../Preview/Composition/Builtin/Registry.hpp)、[Builtin/Snapshot.hpp](../../../Preview/Composition/Builtin/Snapshot.hpp)：builtin 注册与冻结快照。
- [Provider/ConfigurationCompiler.hpp](../../../Preview/Composition/Provider/ConfigurationCompiler.hpp)、[Provider/ProviderInstancePreparation.hpp](../../../Preview/Composition/Provider/ProviderInstancePreparation.hpp)：配置实例与真实 Prepare 分派。
- [Provider/ProviderCatalog.hpp](../../../Preview/Composition/Provider/ProviderCatalog.hpp)、[Provider/ProviderCatalogTypes.hpp](../../../Preview/Composition/Provider/ProviderCatalogTypes.hpp)：Typed Prepared/Active owner 变体与绑定事务。
- [Provider/BoundCatalog.hpp](../../../Preview/Composition/Provider/BoundCatalog.hpp)、[Application/Assembly/ProviderAssembly.hpp](../../../Preview/Application/Assembly/ProviderAssembly.hpp)：运行前 owner 收口及 Application 交接。
- [Contract/Ingress/ProtocolConfiguration.hpp](../../../Preview/Contract/Ingress/ProtocolConfiguration.hpp)：协议实例与承载绑定的输入值。

## include 与 CMake 依赖

- `Preview/CMakeLists.txt` 将 `Composition/` 下相关头文件登记为 `PreviewComposition` INTERFACE target，include 根为仓库根。
- 当前 CMake 图中 `PreviewComposition` 消费 `PreviewRuntime`、`PreviewAccount`、`PreviewFoundation`、`PreviewNet`、`PreviewProtocolsCommon` 和 provider 所需的 HTTP、SOCKS5、VMess、VLESS、Trojan、Shadowsocks2022、AnyTLS、Reality、QUIC、Hysteria2、TUIC 等 protocol targets。
- 当前 `Preview/CMakeLists.txt` 还标有一条 C05 过渡依赖：Composition 暂时消费 `PreviewOperations` 与 `PreviewStatistics`，并注明过渡结束后应移除此边。此处是当前实际 CMake 图，不应理解为长期模块所有权目标。
- 测试按职责登记于 `tests/Preview/Composition` 及 `Builtin`、`Protocol`、`Provider`、`Recognition` 子目录。

## 当前配置与绑定流

1. [ConfigurationCompiler.hpp](../../../Preview/Composition/Provider/ConfigurationCompiler.hpp) 接收 generation pin、generation use state、协议实例、协议 binding 和认证服务。它按实例 `Id` 收集 TCP/UDP binding；无显式 binding 的已处理实例在冷编译中采用默认 TCP 选择。
2. `ProviderInstancePreparation::Handles` 只认可 `ProtocolCatalog` 中具有实现槽位的协议。`Prepare` 按 descriptor 和 typed `ProtocolType` 转入各协议的 Prepare 函数；未实现实例以 `ProviderFailure` 失败，不产生空槽成功或 fallback。
3. `ProviderCatalog::Prepare` 产生 owning `PreparedCatalog`；`FrozenCatalog::Bind` 只消费一次、按顺序创建真实 binding，并在失败或 stop 时关闭尚未发布的 owner。
4. `BoundCatalog` 被 Application 纳入 generation 服务快照。运行热路径使用已绑定 factory/entry，而不是重新查找 builtin 名称。

## 所有权、错误与执行器

- Prepare/Bind 是监听前的控制冷路径。Prepared 值拥有配置、generation pin 与 typed 服务句柄；BoundCatalog 拥有发布后的真实 binding owner。
- 重复实例、未知 builtin、能力不足、缺失依赖或绑定失败由 `ProviderFailure` 分类并保留实例 id/path；停止请求返回 Cancelled。异常不会被转换成成功。
- `BoundCatalog::Close` 只请求真实 owner 关闭，不等待 I/O。`Drain` 调用各 owner 的 drain 并保留首个 `Fault::Failure`，仍继续尝试其余 owner。调用方须驱动相关 executor；是否退休以 owner 的真实退休状态为准。
- 没有 Composition 级通用 stream half-close：协议的 stream、mux、QUIC 与 carrier owner 分别执行其生命周期契约。

## 配置支持、生产接线与运行证据

- **模型支持：** `ProtocolConfiguration`/`ProtocolBindingConfiguration` 将协议实例、TCP/UDP、mux modes、carrier 与 recognition 路由分开表达。Builtin descriptor 同时声明能力要求和提供能力。
- **生产接线：** Application 的 [ProviderAssembly.hpp](../../../Preview/Application/Assembly/ProviderAssembly.hpp) 调用 `Compile`；当前 `ProviderInstancePreparation.hpp` 为实际 typed 槽位分派。`Handles`、`PreparedInstance` 和 `ActiveBinding` 源码都可核对支持边界。
- **运行证据边界：** 本页只列源码接线与测试映射，不登记 build、CTest、运行或互操作结果；通过结论只能来自绑定当次源码、配置和 binary hash 的验收报告。本页不声称通过。

## 测试位置

- [tests/Preview/Composition](../../../tests/Preview/Composition/)：builtin、协议描述与 profile 装配。
- [tests/Preview/Composition/Provider](../../../tests/Preview/Composition/Provider/) 和 [tests/Preview/Composition/Recognition](../../../tests/Preview/Composition/Recognition/)：provider Prepare/Bind 与识别组装。
- [tests/Preview/Integration/Session](../../../tests/Preview/Integration/Session/)：通过真实配置化 session 覆盖跨 Composition 与协议 owner 的场景。
- 根登记见 [tests/Preview/CMakeLists.txt](../../../tests/Preview/CMakeLists.txt)。
