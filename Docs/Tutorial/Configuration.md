# 配置

可直接从[`Examples/Socks5.json`](Examples/Socks5.json)开始。它是一份完整的本机 SOCKS5 TCP 示例：监听 `127.0.0.1:1080`，用户名为 `local`，演示密码为 `change-me`，UDP、QUIC、Operations 和 Web 控制台均关闭。演示密码只允许用于回环 listener；部署前应换成 `SecretRef` 并检查监听地址。

## 先看懂配置的几块内容

可以把代理配置想成几个相互连接的部分：

- **Listener（监听入口）**：服务在哪个 IP 地址和端口等待客户端连接，例如 `127.0.0.1:1080`。`127.0.0.1` 只允许本机访问。
- **Protocol（协议实例）**：说明 Prism 要处理哪一种代理协议，例如 SOCKS5。
- **ProtocolBinding（协议绑定）**：把某个协议实例接到一个或多个传输入口上，并明确是否启用 TCP、UDP、承载或 mux。只写协议实例还不会自动开放入口。
- **Account（账户）**：客户端登录时使用的用户名和凭据。示例里账户 `Id` 是 `local`，所以 curl 的用户名也必须是 `local`。

最小示例的关系可以读成：`Listeners.Tcp` 打开 `127.0.0.1:1080` → `ProtocolBindings` 的 `binding-socks5` 引用 `protocol-socks5` 并启用 TCP → `Accounts` 提供用户名和密码。后面的字段表会逐项解释这些区域。

## 配置文件位置

程序第一个位置参数是配置文件路径；不传参数时，读取可执行文件同目录下的 `PrismConfiguration.json`。构建 `Prism` 会将仓库默认配置复制到 `build/src/PrismConfiguration.json`。命令行没有 `--config` 选项。

完整的当前默认配置见 [`PrismConfiguration.json`](../../Include/Prism/Application/Configuration/PrismConfiguration.json)。默认配置和上述最小示例只启用 SOCKS5 TCP，不代表其他协议也已配置。

## 主要字段

| 区域 | 用途 | 初学者需要记住 |
| --- | --- |
| `Runtime` | worker 数量、session 超时、TCP 活动连接上限和内存池分段增长参数。 | `MaxConnections: 0` 表示不限制。进程池和每个 worker 池都独立使用 `BytePool`：默认从 4 MiB 起步，每次增长 4 MiB，单个池最多 128 MiB，上限最大可配到 16 GiB；三项都必须是非零且是 64 KiB 的整数倍，初始值和增长步长不能超过上限。 |
| `Listeners` | TCP、UDP、QUIC 的监听地址和端口。 | 当前必须配置恰好一个 TCP listener；UDP 和 QUIC 各最多一个。不要把只监听本机的 `127.0.0.1` 当成公网地址。 |
| `Protocols` | 声明要使用的协议实例和内建类型。 | 例如 `Builtin: "socks5"` 表示 SOCKS5 实例；还要由 `ProtocolBindings` 启用它。 |
| `Carriers` | 配置 Native TLS、Reality、ShadowTLS 等承载及证书、密钥和识别条件。 | 只有选择相应承载的 binding 才会使用它。证书路径必须在运行 Prism 的主机上存在且可读。 |
| `ProtocolBindings` | 通过 `ProtocolId` 连接协议实例，并设置 TCP/UDP、可选 carrier、mux 和识别规则。 | `ProtocolId` 必须与 `Protocols[].Id` 完全一致；未被 binding 使用的协议不会接入 listener。 |
| `AccountGroups`、`Accounts` | 配置账户分组、用户名和凭据。 | 示例账户 `Id` 同时作为 SOCKS5 用户名。`Credential` 是配置中的直接凭据；`Credentials` map 可按协议覆盖；生产环境建议用 `SecretRef`。 |
| `Routes` | 预留的路由配置区域。 | 当前必须保持空数组；非空数组会被启动校验拒绝。 |
| `Dns` | 配置上游域名解析服务器。 | 配置的 DNS 地址必须能从部署 Prism 的机器访问。 |
| `Logging`、`Trace`、`Statistics` | 控制日志、请求关联信息和统计采样。 | 相对日志目录按进程的工作目录解析，不一定相对配置文件目录。 |
| `Operations` | 可选 HTTP 管理 API 和 Web 资源目录。 | API 和 Web 页面是两回事；不构建 Web 资源时仍可只使用 API。启用前先确认 endpoint 的网络可达范围。 |
| `HotReload`、`Shutdown`、`Storage` | 控制配置发布确认、停机期限和持久化数据目录。 | 修改磁盘上的 JSON 不会自动让运行中的进程重新读取；可热重载范围仍受配置类型限制。 |

JSON 中 `true`/`false` 是开关，端口和超时是数字，字符串要用双引号，`[]` 表示空列表，`null` 表示未设置。不要在 JSON 值后面添加注释；需要改配置时，优先编辑完整示例里的字段，保留逗号和括号结构。

### 常见的两种修改

**修改端口**：把 `Listeners.Tcp[0].Port` 从 `1080` 改成新端口；发起请求时也要把 curl 地址中的 `:1080` 改成同一个端口。端口在服务器和客户端两边不一致时，客户端会连错位置。

**修改 SOCKS5 登录信息**：把账户对象的 `Id` 改为要使用的用户名；本机演示时也可以把 `Credential` 改成自己的临时密码。随后 curl 的 `--proxy-user` 必须使用同一组用户名和密码。不要把这种直接写入 JSON 的方式用于生产凭据。

协议类型、承载和可用传输组合见[协议支持说明](Protocols.md)。启动阶段会校验实例与 binding 的引用、能力和组合；错误信息中的字段路径用于定位配置位置。

## 生产凭据

不要把生产密码写入配置文件。`SecretRef` 是秘密的**名称/引用**，不是秘密本身；Prism 会通过启动时的环境变量解析它。将账户从示例的：

```json
{
  "Id": "local",
  "GroupId": "local-users",
  "SecretRef": "",
  "Credential": "change-me"
}
```

改为引用：

```json
{
  "Id": "local",
  "GroupId": "local-users",
  "SecretRef": "operator",
  "Credential": ""
}
```

程序从启动进程的环境变量 `PRISM_SECRET_OPERATOR` 读取该值。Windows PowerShell 启动示例：

```powershell
$env:PRISM_SECRET_OPERATOR = '<从安全存储注入的值>'
& '.\build\src\Prism.exe' '.\path\to\PrismConfiguration.json'
```

上面第一行只设置当前 PowerShell 窗口的环境变量；必须从同一个窗口启动 Prism。若 Prism 已经在运行，在另一个窗口设置变量不会改变现有进程读到的值。部署到 systemd 或 Windows 服务时，应在服务管理器的进程环境中设置变量，而不是只在交互式终端里设置。

Linux shell：

```bash
export PRISM_SECRET_OPERATOR='<从安全存储注入的值>'
./build/src/Prism ./path/to/PrismConfiguration.json
```

变量名规则是 `PRISM_SECRET_` 加上 SecretRef 的大写字母数字形式；其他字符替换为下划线。例如 `service/key` 对应 `PRISM_SECRET_SERVICE_KEY`。环境变量必须存在于 Prism 进程的环境中；在另一个终端设置变量不会更新已运行的服务。不要把真实值提交到仓库、写进命令历史或输出到日志。

启动时若报错 `SecretRef cannot be resolved`，先检查配置里 `SecretRef` 的拼写，再检查环境变量名是否按上述规则转换，以及该变量是否真的传给了 Prism 进程。检查时只确认变量“存在”，不要打印它的内容。

## 限制和路径

- 非空 `Routes` 暂不支持。启动错误若指向 `Routes`，请改为空数组；不能通过填写 `Match`/`Target` 启用路由。
- `UdpEnabled: true` 只有在存在 UDP listener、协议实现支持 UDP 且实例/binding 均启用时才生效。
- QUIC 协议需要配置 QUIC listener、`Protocols[].Quic` 凭据选项和 `UdpEnabled: true` 的协议 binding；当前接入使用 ALPN `h3`。
- 证书和密钥路径应指向部署主机上的实际文件，并确保 Prism 进程可读。
- `Operations.WebDirectory` 为相对路径时，按配置文件目录解析；未构建或未配置 Web 资源不影响独立管理 API。

本页描述当前配置结构，不代表配置中列出的所有功能组合都已通过第三方客户端互操作。需要核对当前 Mihomo 测试模板时，见[协议支持说明](Protocols.md)和[构建与测试](../Testing.md)。
