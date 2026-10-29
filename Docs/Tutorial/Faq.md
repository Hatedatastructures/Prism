# 常见问题

## Prism 从哪里读取配置？

程序第一个位置参数是配置文件路径；不传参数时读取可执行文件同目录的 `PrismConfiguration.json`。没有 `--config` 选项。可从[`Socks5.json`](Examples/Socks5.json)开始。

如果不确定程序实际读取了哪一份文件，启动时显式传入绝对路径，并保留这条启动命令用于排查。

## `change-me` 可以用于部署吗？

不可以。它是仅供回环 listener 使用的示例凭据。部署时用 `SecretRef` 从进程环境或安全存储提供真实凭据，并按[部署说明](Deployment.md)检查监听范围。

## 为什么配置了 UDP listener，客户端仍不能使用 UDP？

UDP 是否可用还取决于协议是否支持、协议实例选项和 binding 的 `UdpEnabled`。默认 SOCKS5 示例只启用 TCP。见[协议支持说明](Protocols.md)。

## `Routes` 可以配置自定义路由吗？

当前不可以。字段保留在配置模型中，但启动时的配置检查会拒绝非空 `Routes`。

## 配置列出一个协议，是否代表客户端一定能连接？

不代表。协议实例必须由对应 binding 启用，传输、承载和客户端参数也必须匹配。源码存在、配置可解析和真实客户端互操作是不同的证据层。当前入口与限制见[协议支持说明](Protocols.md)。

## 为什么有 Listener 还要配置 ProtocolBinding？

Listener 只负责在端口接收网络连接；ProtocolBinding 决定把连接交给哪个协议实例处理，以及是否启用 TCP、UDP、承载或 mux。协议实例、binding 和账户之间的关系见[协议支持说明](Protocols.md)。

## Hysteria2 / TUIC 应使用什么 ALPN？

当前 QUIC binding 使用 HTTP/3 ALPN `h3`。还需配置 QUIC listener、协议的 `Quic` 选项和 `UdpEnabled: true` 的 binding；参考[协议支持说明](Protocols.md)及仓库的互操作 fixture。

## Prism 构建为什么不需要 Node.js？

核心 `Prism` target 不需要 Node.js/npm。它们只在安装 Web 依赖并构建可选 `PrismWeb` target 时需要。

## 编辑配置文件后，运行中的 Prism 会自动更新吗？

不会自动监视文件变化。配置里的 `HotReload` 默认关闭；仅编辑 JSON 不会改变已运行进程的配置。初学者修改设置后应先停掉服务，再用新配置重新启动。显式热重载则需要满足对应的服务端配置和管理操作条件。

## `127.0.0.1` 可以给另一台电脑连接吗？

不可以。`127.0.0.1` 总是表示当前设备自身。远程客户端需要连接运行 Prism 的主机地址，并且服务端 listener、操作系统防火墙和网络路由都允许访问。对外开放前先更换演示凭据并确认认证配置。

## CTest 全部通过是否表示已兼容 Mihomo/Clash？

不表示。CTest 只说明本次实际执行的用例通过。Mihomo/Clash 互操作是单独的手动 runner；需核对它的 PowerShell、构建产物和输出目录限制，见[构建与测试](../Testing.md)。
