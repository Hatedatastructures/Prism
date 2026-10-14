# Preview 常见问题

本文使用 `PrismPreview` 与 `PreviewConfiguration.json`。完整字段见[配置说明](configuration.md)，定位方法见[故障排查](troubleshooting.md)。

## 默认配置在哪里，怎样换配置？

源模板在 `Preview/Application/Configuration/PreviewConfiguration.json`，构建后复制到 `build/src/PreviewConfiguration.json`。程序默认读取 executable 同目录文件，也可运行 `.\PrismPreview.exe 'C:\Prism\PreviewConfiguration.json'`。路径是第一个位置参数；入口没有 `--config` 开关。

## 双击退出或启动失败，怎样看原因？

在终端直接运行并查看 stderr 的 `PrismPreview startup failed code=... path=... message=...`。先查配置路径、严格字段、凭据、证书、监听端口及日志目录。普通启动不要求管理员权限；缺少编译器运行库时须补齐实际运行环境。

## 怎样修改端口和本机访问范围？

修改 `Listeners.Tcp[0].Port` 与 `.Address`；默认 `127.0.0.1:1080`。当前只支持一个配置 TCP listener，UDP/QUIC 各至多一个；二者同时声明必须共享地址/端口。Operations 的 `Endpoint` 保持 loopback。

## 默认可以用 HTTP 代理测试吗？

默认模板启用 SOCKS5。使用 `socks5h://127.0.0.1:1080` 并提供模板中替换后的 password；HTTP 客户端需要另行声明 HTTP 协议与 binding，不能只改 curl 的代理类型。

## 怎样开调试日志？

将 `Logging.Level` 改为 `Debug`，需要控制台日志时设置 `Logging.Console` 为 true。RenderMode 使用 `CompactHuman`、`HumanWithFields` 或 `Structured`；所有名称区分大小写。相对 `Logging.Directory` 按启动工作目录解释。

## 怎样配置账户连接/stream 限额？

当前 `Accounts` JSON 没有此类字段，应用装配使用默认 quota。生产账户模块支持 typed policy；真实 factory 配额用例注入该 policy，其结果不代表 JSON 配额已接线。当前责任见[执行状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)。

## Routes、Statistics 和 HotReload 字段意味着已可部署吗？

这些字段有配置模型或相关 owner，但当前非空 `Routes` 会在 `ConfigurationStartup::ValidateSupportedServices` 阶段以 `UnsupportedService` 拒绝启动，并提示 routes 尚未接入 PrismPreview startup。Statistics bytes observation/Interval flush 已有 scoped 当前证据，但全协议和最终 shutdown 验收仍未完成；HotReload 文件监视仍有实施卡。以实际 listener 消费、请求/关闭证据为准。

## 如何正常停机？

前台 Windows 进程用 Ctrl+C；入口还注册 SIGTERM。应用负责停止接入、取消活动 owner、等待 drain 并释放资源。等待进程退出和端口释放后再重启；终止进程的强杀结果需与自然退出分开记录。

## 测试通过能证明什么？

配置、factory、协议 codec、实际 Application/Boundary、第三方互操作和性能分别提供不同范围的证据。`ctest` 执行已有 binary，源码变化后先构建对应 target。历史报告保留日期和版本；完整任务状态从[当前执行状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)进入。

许可证和使用条款见仓库 [LICENSE](../../LICENSE)。
