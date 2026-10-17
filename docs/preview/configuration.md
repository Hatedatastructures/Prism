# Preview 配置与装配

配置模板位于 [`Preview/Application/Configuration/PreviewConfiguration.json`](../../Preview/Application/Configuration/PreviewConfiguration.json)，模型位于 `Preview/Application/Configuration/PreviewConfiguration.hpp`，JSON 字段映射位于 `Preview/Application/Configuration/PreviewConfigurationJson.hpp`。配置校验、能力检查和装配入口分别见 `Preview/Application/Configuration/Validation/`、`Preview/Application/Startup/GenerationPhase.hpp` 与 `Preview/Application/Startup/ProtocolServices.hpp`。

## 配置文件与 secret

`PrismPreview` 默认读取可执行文件同目录的 `PreviewConfiguration.json`。可将配置路径作为第一个位置参数传入；入口没有 `--config` 参数解析。`PrismPreview` 构建后，配置模板由 CMake 复制到 `build/src/PreviewConfiguration.json`。

主入口把 `SecretRef` 传给 secret resolver。环境变量名称以前缀 `PRISM_PREVIEW_SECRET_` 开始，reference 转为大写字母数字，其他字符替换为下划线。配置中的 `Secrets` 也属于当前模型；敏感值不应通过文档、日志或命令历史泄漏。

相对路径需按字段自己的解析者理解：Native TLS 证书/私钥和 `Operations.WebDirectory` 的相对路径由配置路径上下文解析；日志目录按日志配置实现解释。部署时使用绝对路径可避免工作目录差异，具体语义以字段 owner 为准。

## 顶层模型

当前模型包含以下顶层字段；该列表表示 JSON model 的结构，不代表每个字段都已接入运行时服务：

| 字段 | 作用 |
| --- | --- |
| `SchemaVersion` | 配置 schema 版本。 |
| `Runtime` | worker 数量、要求的 capability、session timeout。 |
| `Listeners` | TCP、UDP、QUIC listener 和入口超时。 |
| `NativeTls` | Native TLS 与 ECH 文件配置。 |
| `Builtins` | 内建 capability 声明。 |
| `Protocols` | 协议实例及协议选项。 |
| `Carriers` | 类型化 carrier、匹配规则与 carrier options。 |
| `ProtocolBindings` | 协议实例到 TCP/UDP/mux/recognition 的绑定。 |
| `Recognition` | 识别模式及配置候选。 |
| `Accounts`、`Secrets` | 账户凭据与 secret reference。 |
| `Routes` | 路由配置模型；当前非空 Routes 会在启动 service 校验时返回 UnsupportedService。 |
| `Dns` | DNS server 与 timeout。 |
| `Logging`、`Trace` | 日志和关联信息输出。 |
| `Statistics` | 统计启用与采样间隔。 |
| `Operations` | 管理入口、timeout 与 Web 资源目录。 |
| `HotReload` | generation reload 的启用状态与 ack timeout；由 Operations reload 命令使用，不表示后台自动监视配置文件。 |
| `Shutdown` | 停机超时预算。 |

JSON 字段按 `PreviewConfigurationJson.hpp` 中的 PascalCase 映射拼写；当前 parser 开启未知字段错误，拼错字段会在解析阶段失败。模型定义、schema validation、service/capability validation 与启动绑定是不同阶段；字段能解析不等于能力已接线。

## listener 与 binding

当前启动校验要求恰好一个 TCP listener、最多一个 UDP listener 和一个 QUIC listener；UDP 与 QUIC 同时配置时必须共用地址和端口。默认仓库模板启用 loopback TCP/UDP 入口，TCP binding 指向 SOCKS5；QUIC listener 列表为空。模板是示例配置，使用前替换示例凭据并确认监听地址符合部署范围。

协议实例、carrier 和 `ProtocolBindings` 通过 ID 引用。配置阶段检查协议、carrier、能力和 binding 合同；启动阶段准备实际 provider service，并将被冻结的 typed binding 发布给 Runtime/Boundary。未绑定、没有实现或与 ingress 先决条件不符的配置会以启动错误拒绝。

当前 carrier `Type` 标签映射为 `NativeTls`、`Reality`、`ShadowTls`、`Restls`、`WebSocket`、`Xhttp`、`Gun`。具体协议和 carrier 的可组合范围见[协议目录](protocols/README.md)及各协议页，不能只根据这份类型列表推断任意组合均可用。

## 账户凭据

账户至少需要 `Credential` 或 `SecretRef`。协议级 `Credentials` 及账户身份消歧规则由 Account 和协议 owner 实施；共享 secret 只有在请求身份能唯一判定时才可认证。凭据编码、认证失败表现和协议命令能力需查阅具体协议页。

## 能力与运行验收

Preview 不会因配置文件被外部修改而自动重载。当前 reload 入口是已接线的 Operations 命令：需要启用 `HotReload.Enabled` 并运行 Operations 管理端点；命令可先以 `ValidateOnly` 准备并验证候选 generation，再申请发布。包含 restart-required 字段的变更会返回需重启结果，不会作为热更新发布。Operations 未启用、热更新未启用或变更要求重启时，应使用受控停机并以新配置重新启动。该接线说明不代表任何特定 reload 请求已通过运行验收，操作与结果范围见 [Operations 模块](modules/operations.md)。

阅读某项能力时按以下顺序核实：

1. 配置模型是否提供相应字段，schema 是否允许。
2. `GenerationPhase`、`ProtocolServices`、`BoundaryPhase` 等启动路径是否校验并实际构造该能力。
3. 当前测试或运行证据覆盖哪个具体输入、配置和二进制版本。

例如 `Routes` 字段存在且会经过 schema/reference 校验，但当前启动 service validation 明确拒绝非空 `Routes`。其它字段也应逐项沿启动链确认，不能由本页的字段清单代替源码审计。
