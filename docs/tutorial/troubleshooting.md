# Preview 故障排查

先保留原始证据，再改配置或重启。字段含义和可用组合见 [Preview 配置](../preview/configuration.md)，入口及执行步骤见 [Preview 总览](../preview/README.md)，各层责任见[仓库架构](../ARCHITECTURE.md)。本页不把旧日志、历史测试结果或未匹配的 binary 当作当前事实。

## 先建立一次故障记录

记录故障时间、操作系统、源码 revision/工作树状态、可执行文件和配置文件的 SHA-256、完整启动命令、工作目录、stderr/stdout、READY 字段、客户端命令和目标。去除 password、token、私钥和 secret 环境变量值后再分享日志。

Windows 上可先执行只读检查：

```powershell
Get-FileHash -Algorithm SHA256 'C:\Prism\PrismPreview.exe'
Get-FileHash -Algorithm SHA256 'C:\Prism\config\PreviewConfiguration.json'
Get-NetTCPConnection -State Listen -LocalPort 1080 -ErrorAction SilentlyContinue
Get-Process -Name PrismPreview -ErrorAction SilentlyContinue
```

确认 PID/端口归属后再操作进程。端口可能属于其它用户服务，不要按进程名批量结束或清空构建产物。

## 程序未启动

1. 检查配置路径是否存在、进程账户是否可读，以及命令中的第一个位置参数是否是预期文件。没有参数时程序读取 executable 同目录的 `PreviewConfiguration.json`。
2. 保存错误代码、JSON path 和完整说明。对照权威配置页检查字段大小写、类型、id 引用、协议能力和 credential 格式。
3. 检查 Native TLS 证书与私钥是否能从配置文件所在目录找到并由服务账户读取。
4. 检查监听地址是否属于主机、端口是否已被占用，以及 UDP/QUIC 是否按当前配置合同使用正确 endpoint。
5. 若进程刚启动即退出，先核对目标平台所需运行库和程序架构；不要由 MinGW 的单个链接选项推断所有依赖都已静态链接。

主入口没有单独 `--check` 参数。运行前的 JSON lint 只说明语法可解析，完整字段与 runtime 装配仍需用匹配 binary 启动验证。

## READY 但客户端失败

按阶段分开检查：

| 现象 | 核对方向 |
| --- | --- |
| 无法建立 TCP 连接 | READY 中的 `tcp_port`、listener 地址、端口占用、防火墙、client 代理类型 |
| TCP 已接入但认证拒绝 | Account id、credential 格式、`SecretRef` 是否解析到非空 secret、client 是否使用正确的认证方式 |
| 认证成功但目标失败 | 请求目标与端口、DNS 设置、路由/出站能力、目标端可达性 |
| UDP/QUIC 不可用 | READY 中对应的 `udp_ready`/`quic_ready` 等状态、配置是否启用该能力、client 是否发起了真实数据报或 QUIC 会话 |
| TLS/carrier 握手失败 | carrier binding、SNI/ALPN/path/authority、证书文件位置及实际 wire 模式 |

对比一个正确 credential 与一个错误 credential，并记录后端 dial 是否发生、响应内容、读写字节、半关闭与最终关闭结果。只证明 listener 可连接的端口探测不能替代代理请求。

## SecretRef 无法解析

入口从 reference 生成变量名：`PRISM_PREVIEW_SECRET_` + 字母大写、数字保留、其它字符替换为下划线。检查服务管理器注入的变量名是否完全匹配、进程环境是否包含变量、值是否为空，以及 reference 规范化后是否与其它名称冲突。不要将变量值打印到排障输出。

## 停机或 drain 卡住

保存当前进程 PID、未完成请求、触发信号、原始错误及端口状态。前台 Ctrl+C 或 SIGTERM 是请求正常退出；等待程序收尾并自然退出后，再核对 listener/QUIC 活动及端口释放。取消命令已接受、一个 stream 收到 FIN 或一次测试进程退出，都不能单独证明所有 owner 已物理退休。

若不得不强制终止，将它记录为故障隔离操作而非正常关闭证据。保留失败输入和对应 binary/config hash 后，再在安全窗口复现；不要为了重启而打断用户仍在运行的实例。

## 测试结果如何解读

源码/CMake 中存在测试 target 仅说明有相应场景。运行某个测试时需确保当前 binary 对应当前源码，并区分配置校验、协议测试、真实 Application/Boundary 请求、外部互操作、压力和性能结果。测试失败时保留完整命令、CTest 名称、原始输出和源码/binary hashes；不要删除、改小测试输入或把历史通过记录移作当前证据。
