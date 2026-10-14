# Preview 配置说明

Preview 使用独立的严格 JSON schema。模板为 [PreviewConfiguration.json](../../Preview/Application/Configuration/PreviewConfiguration.json)，字段模型是 [PreviewConfiguration.hpp](../../Preview/Application/Configuration/PreviewConfiguration.hpp)，JSON 映射为 [PreviewConfigurationJson.hpp](../../Preview/Application/Configuration/PreviewConfigurationJson.hpp)。本页按 2026-10-09 的当前源码核对。

## 文件与解析规则

`PrismPreview` 默认读取可执行文件同目录的 `PreviewConfiguration.json`，或将第一个位置参数用作配置路径。构建 `PrismPreview` 后，CMake 把源模板复制到 `build/src/PreviewConfiguration.json`。部署配置可保存在独立目录并显式传入。

本页配置的是 `PrismPreview` server 进程：`Listeners` 描述本地 TCP/UDP/QUIC 入口，`Operations.Endpoint` 描述本地管理入口，`Protocols`/`ProtocolBindings`/`Accounts` 描述服务端协议、绑定和认证材料。当前 schema 没有 `Role`、`Client` 或 `Server` 切换字段，也没有独立 client 配置段；外部 client/interop 工具使用各自的 CLI 和配置，不由本 JSON schema 解析。入口只接受无参数默认路径或 `Argv[1]` 位置路径，没有 `--config` 开关。

所有字段大小写必须与模型一致，例如 `Listeners`、`Accounts`、`Logging.Level`。解析器拒绝未知字段。v1 必填根字段包括 `SchemaVersion`、`Runtime`、`Listeners`、`Builtins`、`Protocols`、`Carriers`、`ProtocolBindings`、`Accounts`、`Routes`、`Dns`、`Statistics`、`Operations`、`HotReload`、`Shutdown`，因此只写一个 listener 的 JSON 片段不能作为完整配置。

下面的 JSON 块用于解释相应字段，修改完整模板时替换对应部分。旧版的 `agent`、`pool`、`buffer`、`protocol`、`multiplex`、`stealth` 和 `trace` 字段不属于 Preview schema。

## 运行与监听

```json
{
  "Runtime": { "WorkerCount": 2, "RequiredCapabilities": [], "SessionTimeout": 30000 },
  "Listeners": {
    "Tcp": [{ "Id": "tcp-main", "Address": "127.0.0.1", "Port": 1080, "Timeout": 5000 }],
    "Udp": [],
    "Quic": [],
    "Timeout": 5000
  }
}
```

`WorkerCount` 必须在 1–4096；超时字段使用毫秒并接受各自校验规则。当前应用要求恰好一个 TCP listener，UDP 与 QUIC 各至多一个。声明 UDP 和 QUIC 时，两者必须使用相同地址和端口。配置端口须为 1–65535；测试内部使用的 ephemeral port 不是 JSON 端口示例。

`Address` 为 `127.0.0.1` 时仅允许本机接入；改为可路由地址或 `0.0.0.0` 会扩大监听范围。Operations 有独立的 loopback 限制，不随代理 listener 改为公网地址。

## 协议与绑定

协议实例的 `Id`、`Name`、`Builtin` 和 binding 的 `ProtocolId` 构成引用关系。最小 SOCKS5 模板中的对应部分为：

```json
{
  "Protocols": [
    { "Id": "protocol-socks5", "Name": "socks5", "Builtin": "socks5", "Requires": [] }
  ],
  "Carriers": [],
  "ProtocolBindings": [
    {
      "Id": "binding-socks5",
      "ProtocolId": "protocol-socks5",
      "TcpEnabled": true,
      "UdpEnabled": false,
      "MuxModes": [],
      "Priority": 0,
      "Recognition": {}
    }
  ]
}
```

`TcpEnabled`、`UdpEnabled` 与 `MuxModes` 都要通过内建协议能力校验。Mux 名称严格使用 `Smux`、`Yamux`、`H2Mux`；`Auto` 或小写名称不属于此配置列表。`CarrierId` 可选，给出时必须引用真实 carrier。AnyTLS、TrustTunnel 的协议性质和允许组合由 preflight 校验，不能将它们随意当作 TLS carrier。

SOCKS5、VLESS、Trojan、VMess 的流接入按当前 `ProtocolBindings[]` 的 `UdpEnabled` 判定 UDP 命令权限，同一协议的其它绑定不会放大该权限。SS2022 的 raw UDP 由协议实例持有一个共享 gateway：任一绑定启用 raw UDP 时，该实例会准备入口；raw packet 没有 TCP carrier/binding 身份。两者的作用范围不同，配置与验证应分别核对。

全局 `Recognition.Mode` 默认 `MixedTrial`；`Configured` 模式配合 `ConfiguredCandidate` 选择已编译候选，`Deterministic` 使用路由识别。候选和 capability 在冷路径编译，运行态消费冻结的绑定。组合校验和测试可定位到 [ReferenceValidation.hpp](../../Preview/Application/Configuration/Validation/ReferenceValidation.hpp) 与 [ConfigurationValidationHeadersTest.cpp](../../tests/Preview/Application/Configuration/ConfigurationValidationHeadersTest.cpp)。

QUIC 协议有 `Quic` 选项，包括 `Alpn`、`ServerName`、`CredentialSecretRef`、`MaxStreams`、`MaxDatagrams`，TUIC 还需要 `Uuid`。这类协议容量字段与账户的 stream quota 是不同层级，启用时还须满足 TLS 和 QUIC listener 的配置合同。

## 账户与 secret

```json
{
  "Accounts": [
    { "Id": "local", "SecretRef": "proxy-password", "Credential": "" }
  ],
  "Secrets": {}
}
```

`Id` 在配置中必须唯一，账户至少提供 `Credential` 或 `SecretRef`。入口的环境变量 resolver 将 `SecretRef` 转成 `PRISM_PREVIEW_SECRET_` 前缀、字母数字大写、其余字符替换为下划线。例如 `proxy-password` 对应 `PRISM_PREVIEW_SECRET_PROXY_PASSWORD`：

```powershell
$env:PRISM_PREVIEW_SECRET_PROXY_PASSWORD = 'YOUR_PASSWORD'
.\build\src\PrismPreview.exe 'C:\Prism\PreviewConfiguration.json'
```

`Secrets` 对象也可提供配置内 secret；保留在文件中的凭据需按部署权限管理。相同 reference 应使用唯一、清晰的环境变量名，避免字符规范化后的名称碰撞。

账户 `Credentials` 可按 `Http`、`Socks5`、`Vless`、`Trojan`、`Vmess`、`Shadowsocks2022`、`AnyTls`、`TrustTunnel` 提供协议凭据；已给出的协议凭据优先于通用 `Credential`。SOCKS5、HTTP、AnyTLS、TrustTunnel 使用 password，Trojan 的 token 由密码生成，VLESS/VMess 使用 16-byte UUID 文本，Shadowsocks 2022 使用 Base64 编码的 16-byte PSK。协议目录装配由 [AccountAssembly.hpp](../../Preview/Application/Assembly/AccountAssembly.hpp) 执行。

当前 JSON 账户模型没有 `MaxConnections`、`MaxStreams` 或 rate 字段；配置装配使用默认 `QuotaPolicy{}` 与 `UnlimitedRatePolicy{}`。真实 factory 测试中的 MaxStreams=1 通过 cold 账户 policy 注入，不能据此添加不存在的 JSON 配额字段。

## TLS 与 carrier

```json
{
  "NativeTls": {
    "Enabled": true,
    "CertificateFile": "cert.pem",
    "PrivateKeyFile": "key.pem"
  }
}
```

Native TLS 启用时要求证书、私钥可读且匹配。相对证书和私钥路径按配置文件所在目录解析。carrier 的 `Options` 为类型化对象；Native TLS、Reality、ShadowTLS、Restls、WebSocket、XHTTP、Gun 的字段分别以模型和 `CarrierValidation.hpp` 为准，不复用旧 `stealth.*` 配置。

`Carriers[].Match` 可包含 `ServerNames`、`Alpn`、`Priority` 和 `Fallback`。启用前同时检查协议允许的 carrier、SNI/ALPN 路由歧义和所需 secret；“模板可解析”与“真实 TLS 互操作通过”分别验收。

## DNS、路由与控制字段

| 对象 | 当前字段 | 说明 |
| --- | --- | --- |
| `Dns` | `Servers`、`Timeout` | Servers 为字符串列表；当前模板使用 `1.1.1.1`，Timeout 单位毫秒。没有旧版 DNS 服务器对象/cache tuning 字段 |
| `Routes` | 每项 `Id`、`Match`、`Target`、`Requires` | 配置模型和引用校验存在，但当前 `ConfigurationStartup::ValidateSupportedServices` 对非空 `Routes` 返回 `UnsupportedService`，错误信息为 `configured routes are not wired into PrismPreview startup`；当前配置应保持为空。 |
| `Operations` | `Enabled`、`Endpoint`、`Timeout` | Endpoint 须使用 loopback 地址；IPv6 写成 `[::1]:9090` |
| `Statistics` | `Enabled`、`Interval` | 字段可解析；当前 bytes observation、Interval flush 和 scoped runtime evidence 已存在，但 Task 6B 全协议/全 epoch/最终 shutdown 验收仍未完成 |
| `HotReload` | `Enabled`、`AckTimeout` | 模型与研究 owner 存在；当前 main 没有已验收的文件监视热重载操作流程 |
| `Shutdown` | `Timeout` | 应用停机预算，完整取消/drain 结果需看实际验收 |

不要把模型字段存在、研究测试通过或日志输出等同于生产 listener 已消费此设置。当前 `Routes` 是启动拒绝项；`Statistics`、`HotReload` 等字段仍需按执行状态判断生产接线。存量与未部署职责的迁移见[当前执行状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 日志与 Trace

```json
{
  "Logging": {
    "Level": "Info",
    "RenderMode": "CompactHuman",
    "Directory": "logs",
    "FileName": "preview.log",
    "Console": false,
    "RotateBytes": 67108864,
    "RotateFiles": 8,
    "FlushIntervalMs": 250
  },
  "Trace": {
    "IncludeCorrelation": true,
    "IncludeWorker": true,
    "IncludeSession": true,
    "IncludeStream": false
  }
}
```

Level 支持精确名称 `Trace`、`Debug`、`Info`、`Access`、`Warn`、`Error`、`Critical`、`Off`。RenderMode 仅支持 `CompactHuman`、`HumanWithFields`、`Structured`。`Logging.Directory` 按进程工作目录使用，和相对证书路径的基准不同；部署中可使用绝对日志路径。

普通日志提交允许丢弃，输出失败属于观察层，不应变成业务认证或转发失败。格式、字段、轮转和停止合同见 [Diagnose 指南](../../Preview/Foundation/Utility/Diagnose/README.md)。

修改完成后运行 server 检查启动错误的 `code/path/message` 与 READY，再用独立 client 验证真实请求与停机。当前入口没有独立的 `--check` 或 `--config` 开关；本页示例是字段与操作说明，不能当作本轮已执行的运行结果。
