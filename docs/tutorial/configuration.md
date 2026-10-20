# 配置

默认配置源是 `Include/Prism/Application/Configuration/PrismConfiguration.json`。构建后配置复制到 `build/src/PrismConfiguration.json`。程序优先读取命令行第一个参数指定的文件；没有参数时，使用可执行文件同目录的配置。

配置解析、schema 校验和运行时装配是不同阶段。字段名称及 JSON 映射以 `Include/Prism/Application/Configuration/PrismConfigurationJson.hpp` 和 `Include/Prism/Application/Configuration/PrismConfiguration.hpp` 为准；校验入口见 `Include/Prism/Application/Configuration/ConfigurationValidator.hpp`。通用配置区包括：

| 区域 | 用途 |
| --- | --- |
| `Runtime` | worker 数量、会话超时、进程级连接上限和运行能力要求。 |
| `Listeners` | TCP、UDP、QUIC 入口地址和端口。 |
| `NativeTls` | 原生 TLS、证书和 ECH 文件设置。 |
| `Builtins`、`Protocols`、`Carriers`、`ProtocolBindings` | 声明已编译能力，并把协议和承载配置绑定。 |
| `AccountGroups`、`Accounts` | 账户身份、分组与凭据来源。 |
| `Routes`、`Dns` | 路由和名称解析设置。 |
| `Logging`、`Trace`、`Statistics` | 诊断和观察配置。 |
| `Operations` | 管理服务设置，包括 endpoint 与可选 Web 目录。 |
| `HotReload`、`Shutdown` | 重载确认和停机期限。 |

配置声明某个协议或能力，不代表当前 build 中已装配该能力；启动校验会检查配置与已编译 binding 的匹配情况。

`Runtime.MaxConnections` 限制同一 listener 上同时保持的活动 TCP 会话数，默认 `0` 表示不限制。超额连接在进入会话工厂前被拒绝并关闭，因此不会建立上游连接或消耗账户配额。该字段变更需要重启：它不属于热重载可发布字段。

## 凭据引用

程序把 `SecretRef` 转换为环境变量名：前缀为 `PRISM_SECRET_`，引用中的字母数字转成大写，其他字符转成下划线。例如引用 `operator` 对应环境变量 `PRISM_SECRET_OPERATOR`。变量缺失或为空时，凭据解析失败。

Windows PowerShell 设置当前进程环境变量的示例：

```powershell
$env:PRISM_SECRET_OPERATOR = '<从安全存储读取的值>'
```

不要把真实值写进配置、命令历史、文档或日志。`Operations.WebDirectory` 若配置为相对路径，会相对于配置文件位置解析；未设置时，进程使用默认 Web 资源目录。
