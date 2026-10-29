# 协议支持

本页说明当前配置入口和能力边界。README 中列出的协议或承载表示源码提供相应实现，不表示默认配置已启用，也不表示每种客户端、传输和复用组合都已完成互操作验证。

## 先认识这些名称

第一次看配置时，可以先记住下面几件事：

- **Listener（监听入口）**决定 Prism 在哪里接收连接，例如 TCP 的 IP 地址和端口。
- **Protocol（协议实例）**决定 Prism 按哪种代理协议解释客户端数据，例如 SOCKS5、VLESS 或 Hysteria2。
- **ProtocolBinding（协议绑定）**把协议实例接到相应入口，并打开 TCP/UDP 等能力。它通过 `ProtocolId` 找到 `Protocols[].Id`。
- **Carrier（承载）**是在代理协议外再套一层传输或伪装方式，例如 TLS、WebSocket、XHTTP。它不是 SOCKS5、VLESS 这类代理协议本身。
- **Mux（多路复用）**是在一条连接上承载多个逻辑数据流的方式，只适用于明确支持它的组合。
- **Account（账户）**提供客户端认证所需的身份和秘密；具体使用哪个字段由协议的认证方式决定。

可以把配置关系简化为：

```text
Listener（开门接收连接）
  └─ ProtocolBinding（决定接入方式和启用能力）
       ├─ Protocol（处理对应的代理协议）
       ├─ Carrier（可选的 TLS/HTTP 承载）
       └─ Account（协议需要认证时使用）
```

因此，只配置 listener、只声明 protocol，或只创建账户，都不能单独完成一个可用入口。最简单的可运行配置见[`Socks5.json`](Examples/Socks5.json)。

## 配置如何启用协议

需要同时检查 listener、协议实例和 `ProtocolBindings`：

1. `Listeners` 打开对应的 TCP、UDP 或 QUIC 入口。
2. `Protocols` 声明协议实例，例如默认配置中的 SOCKS5。
3. `ProtocolBindings` 通过 `ProtocolId` 指向协议实例，并启用需要的传输。TCP 使用 `TcpEnabled`；UDP 关联和 QUIC 使用 `UdpEnabled`。承载、识别规则和 mux 也由 binding 组合。
4. `Accounts` 提供与该协议匹配的账户身份和凭据。TCP 协议没有专属覆盖时使用账户的通用 `Credential`/`SecretRef`；专属凭据通过 `Credentials` map 指定，键名大小写敏感，例如 SOCKS5 使用 `Socks5`。Hysteria2/TUIC 的认证值另在 `Protocols[].Quic.CredentialSecretRef` 配置，并关联到对应账户。

阅读 JSON 时，先用 `Id` 对照引用关系：`ProtocolBindings[].ProtocolId` 要能找到 `Protocols[].Id`；若 binding 设置了 `CarrierId`，也要能找到对应的 `Carriers[].Id`。这些 ID 是配置内部的连接线，不能随意拼错。`Name` 通常用于给实例起可读名称，真正用于引用的是 `Id`。

[`Examples/Socks5.json`](Examples/Socks5.json) 是完整的 SOCKS5 TCP 配置。仓库默认配置目前也只启用 SOCKS5 TCP；它不会自动开启表格中的其他协议或 UDP。

## 读取 README 的协议列表

根目录[README 的协议支持表](../../README.md)列出当前实现的 TCP、QUIC、UDP 关联、承载和 mux 类型。本页补充这些功能如何通过配置启用，不把源码中有实现等同于默认配置可用或已验证所有客户端组合。

- TCP 协议需要 TCP listener、协议实例和 `TcpEnabled: true` 的 binding。客户端用户名对应账户 `Id`；凭据可使用通用 `Credential`/`SecretRef`，或按协议设置 `Credentials` 覆盖项。
- UDP 关联需要 UDP listener、协议实例选项和 `UdpEnabled: true` 的 binding。只启动 UDP listener 不会自动为每个协议启用 UDP。
- Hysteria2/TUIC 需要 QUIC listener、`Protocols[].Quic` 配置和 `UdpEnabled: true` 的 binding；当前使用 HTTP/3 ALPN `h3`。
- TLS/HTTP 承载需要承载实例、匹配的协议 binding 和对应证书/密钥、识别配置。不是每个代理协议都支持每种承载。
- mux 只能配置在实际支持该模式的协议 binding 上，不能作为全局开关。

`Routes` 字段目前保留在配置模型中，但非空数组会被启动校验拒绝。自定义路由还没有可用的部署配置路径。

### 按目标功能检查配置

| 想做什么 | 至少要检查哪些位置 | 常见误区 |
| --- | --- | --- |
| SOCKS5 TCP | `Listeners.Tcp`、`Protocols`、引用该实例的 `ProtocolBindings.TcpEnabled`、账户 | 默认示例只绑定 TCP；客户端的用户名和密码要与账户一致。 |
| SOCKS5 等协议的 UDP 关联 | UDP listener、协议本身的 UDP 选项、对应 binding 的 `UdpEnabled` | 单独打开 UDP listener 不会让每个协议自动支持 UDP。 |
| Hysteria2 或 TUIC | QUIC listener、`Protocols[].Quic`、账户关联、binding 的 `UdpEnabled` | QUIC 使用 UDP 传输；还要匹配凭据和 `h3` ALPN。 |
| TLS/HTTP 承载 | `Carriers` 里的承载实例、binding 的 `CarrierId`、证书/密钥和识别选项 | 创建证书或 carrier 不会自动把它套到所有代理协议上。 |
| 多路复用 | 对应 binding 的 `MuxModes` 和该协议支持的模式 | 不能假设一个 mux 模式适用于所有协议。 |

如果启动错误指出一个 JSON 路径（例如 `ProtocolBindings[0].ProtocolId`），方括号里的数字表示数组位置，从 0 开始。先打开配置文件并定位这一项，再对照引用的 `Id` 是否存在、拼写和大小写是否一致。

## Mihomo / Clash 互操作

仓库保留了当前互操作用的 [`PrismConfigurationMatrix.json`](../../PrismConfigurationMatrix.json) 和 [`PrismClient.yaml`](../../PrismClient.yaml)。它们是测试 fixture，不是生产默认配置；其中的节点和注释区分了常规用例、手工验证用例以及尚未验证的组合，不应把整份矩阵当成所有客户端都兼容的承诺。

手动 runner 位于 [`RunCurrentMixedCase.ps1`](../../Test/Prism/Integration/Matrix/RunCurrentMixedCase.ps1)。运行条件、命令和结果目录见[构建与测试](../Testing.md)。目前该 runner 要求 Windows PowerShell 7.4+、已构建的 Prism 和矩阵 file server，并固定将隔离结果写到 `H:\` 根目录；没有 H 盘时不能直接使用它。

如果目标组合不在现有 fixture 中，应先按配置结构建立独立的协议和客户端用例，再将对应的成功结果作为该组合的互操作证据。配置解析成功或源码中存在协议实现都不能替代真实请求验证。

对使用者来说，客户端至少要填写目标服务器地址和端口；启用了认证时，还要使用与 Prism 账户匹配的用户名和密码。服务器地址填写**运行 Prism 的主机**，而不是把 `127.0.0.1` 原样复制到另一台电脑上：`127.0.0.1` 永远表示“当前这台设备”。客户端配置字段请以所用 Mihomo/Clash 派生客户端的官方文档为准；不同客户端即使协议名称相同，支持的字段和选项也可能不同。

下面是一个**代理节点片段**，展示 Mihomo SOCKS5 客户端如何对应本页的本机示例：

```yaml
proxies:
  - name: "Prism SOCKS5"
    type: socks5
    server: 127.0.0.1
    port: 1080
    username: local
    password: change-me
    udp: false
```

这里的 `server` 和 `port` 对应 Prism 的 TCP listener，`username` 和 `password` 对应示例账户。`udp: false` 对应示例没有启用 UDP 关联。此片段只定义一个节点，不是完整的 Mihomo 配置；完整客户端配置还需按你使用的客户端设置入口端口、策略组或规则，或者通过其图形界面选择节点。`change-me` 只适合本机回环演示，不能直接用于部署。

客户端字段可查阅 [Mihomo 官方 SOCKS 节点文档](https://wiki.metacubex.one/en/config/proxies/socks/)和[通用节点字段说明](https://wiki.metacubex.one/en/config/proxies/)。QUIC 客户端字段见[官方 Hysteria2 文档](https://wiki.metacubex.one/en/config/proxies/hysteria2/)和[官方 TUIC 文档](https://wiki.metacubex.one/en/config/proxies/tuic/)。这些页面说明的是客户端配置格式；Prism 服务端仍按本仓库的 JSON 配置格式配置。
