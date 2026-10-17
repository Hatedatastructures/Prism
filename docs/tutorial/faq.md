# Preview 常见问题

本页回答日常启动与部署问题。Preview 的当前配置合同见 [Preview 配置](../preview/configuration.md)，项目入口和执行指南见 [Preview 总览](../preview/README.md)，跨模块资源责任见[仓库架构](../ARCHITECTURE.md)。

## 默认从哪里读取配置？

不传参数时，`PrismPreview` 从可执行文件所在目录读取 `PreviewConfiguration.json`。传入参数时，第一个位置参数就是配置路径，例如：

```powershell
& '.\PrismPreview.exe' 'C:\Prism\PreviewConfiguration.json'
```

主入口不解析 `--config` 开关。Native TLS 证书和私钥的相对路径以配置文件目录为基准。

## 应该改哪一份配置？

仓库模板位于 `Preview/Application/Configuration/PreviewConfiguration.json`，构建 `PrismPreview` 时会复制到 target 输出目录旁。正式部署请保留独立副本，并使用位置参数明确指定；这样源模板更新不会悄悄变成服务配置变更。

## 默认模板启用了哪些协议？

当前源模板的 `Protocols` 和 `ProtocolBindings` 声明 SOCKS5。协议实现目录、可测试的 codec 或 standalone interop harness 存在，不代表模板已经绑定该协议，也不代表该路径完成了真实请求验收。按 [Preview 配置](../preview/configuration.md)建立完整的 protocol、carrier、binding 与账户关系。

## 如何安全提供密码？

在配置里为账户使用 `SecretRef`，并向运行进程设置对应 `PRISM_PREVIEW_SECRET_...` 环境变量。reference 字母转大写、数字保留、其它字符换成下划线。值为空时视为未提供。不要把生产 secret 写进仓库模板或运行日志。

## READY 表示可以用了么？

READY 表示应用在启动流程结束时发布了就绪状态，并报告 TCP 端口及 UDP/QUIC readiness 字段。它并不代替账户认证、目标 dial、实际 stream/datagram 请求或停机 drain 验收。用配置匹配的 client 发送真实请求并检查响应。

## 为什么配置字段存在，功能仍不能用？

schema/model、reference validation、Composition provider 和启动/请求路径是不同环节。字段被解析不自动表示生产 listener 消费了它；请看权威配置页对每个功能的当前接线说明，并以实际请求/互操作证据确认。

## 修改配置后怎样生效？

外部编辑配置文件不会自动触发 reload。若 Operations 管理端点和 `HotReload.Enabled` 均启用，可通过 Operations reload 命令先做 `ValidateOnly`，再按需申请发布；包含 restart-required 字段的变更会要求重启。没有启用该命令，或命令要求重启时，安排受控停机，用新配置路径启动匹配程序并重新做请求检查。具体配置边界见 [Preview 配置](../preview/configuration.md)和 [Operations 模块](../preview/modules/operations.md)。

## 怎样正常停止？

前台实例按 Ctrl+C；进程管理器可发送 SIGTERM。等待进程自然退出并确认相关端口释放。若必须强制结束，要与正常 drain 单独记录。

## 测试通过可以证明部署正常吗？

只可以确认该次测试覆盖的层级。配置单测、codec/session 用例、真实 listener 请求、第三方互操作和性能测试各自回答不同问题。报告应匹配当前源码、配置和 binary hashes；参考 [Preview 总览](../preview/README.md)中的验收指引。

## 去哪里找构建说明？

使用 [Preview 总览](../preview/README.md)中的当前开发入口和构建规则。仓库要求在运行 build 前取得适用的明确授权，并遵守唯一 `build/` 目录、时间/线程与资源清理规则。
