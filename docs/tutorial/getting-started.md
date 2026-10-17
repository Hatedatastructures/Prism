# Prism Preview 上手指南

本指南带你准备一份配置、启动一个已有的 `PrismPreview` 程序，并核对一次真实请求。这里的操作步骤和命令示例不是某个本地 binary 的构建或运行验收结果。构建入口、当前 Preview 文档索引见 [Preview 总览](../preview/README.md)，完整 JSON 字段见 [Preview 配置](../preview/configuration.md)，模块和关闭责任见[仓库架构](../ARCHITECTURE.md)。

## 准备程序与配置

使用同一源码版本生成的 `PrismPreview` 和 `PreviewConfiguration.json`。CMake 的 `PrismPreview` target 输出到构建树的 `src/`，并在构建后把源模板复制到可执行文件旁边。维护者构建前须遵守仓库的构建授权、唯一 `build/` 目录及线程规则。本页提供操作步骤；任何构建、测试或运行通过结论都应查阅绑定对应源码 revision、配置和 binary hash 的报告。

建议把实际部署配置复制到单独目录，避免后续构建更新构建树中的模板时覆盖它。配置字段和引用关系以 [Preview 配置](../preview/configuration.md)为准；不要把旧版 `Prism.exe` 的配置片段复制进来。

## 填入运行凭据

优先为 `Accounts` 中的账户设置 `SecretRef`，在启动进程的环境中提供对应 secret。当前入口生成环境变量名的方法是：前缀 `PRISM_PREVIEW_SECRET_`，再将 reference 中的字母转为大写、数字保留、其它字符换成下划线。例如 reference `proxy-password` 对应：

```powershell
$env:PRISM_PREVIEW_SECRET_PROXY_PASSWORD = '替换为实际密钥'
```

不要把生产密码留在仓库模板、命令历史、进程参数或普通日志中。若不同 reference 经规范化后会得到同一个环境变量名，请改用不冲突的 reference。凭据和协议专属格式见[配置说明](../preview/configuration.md)。

## 启动

在前台启动便于保留诊断输出。程序默认从可执行文件同目录读取 `PreviewConfiguration.json`；提供第一个位置参数时使用该路径：

```powershell
Set-Location 'C:\Prism'
& '.\PrismPreview.exe' '.\PreviewConfiguration.json'
```

```bash
cd /opt/prism
./PrismPreview /etc/prism/PreviewConfiguration.json
```

入口把第一个位置参数作为配置路径；它没有 `--config` 参数解析。Native TLS 证书和私钥的相对路径按配置文件所在目录解析。配置模型、平台可执行入口和路径合同应以[配置页](../preview/configuration.md)与 [Preview 总览](../preview/README.md)为准。

启动成功后会输出 `PrismPreview READY`，其中分别包含 TCP 端口、UDP readiness 与 QUIC readiness 字段。READY 表示启动阶段发布了该进程的就绪状态；它不代表客户端认证、目标拨号或每种传输都已经完成实际请求验证。

## 发送一条请求

先从配置中确认启用的 protocol、binding、监听地址/端口和账户 credential，再选择匹配的独立 client。以下是 SOCKS5 场景的命令形状；用配置中真实账户和目标替换占位符：

```powershell
curl.exe --proxy 'socks5h://127.0.0.1:1080' --proxy-user 'USER:PASSWORD' --connect-timeout 5 --max-time 15 'https://example.com/'
```

命令成功后还需检查响应内容、字节数和 server 输出。另用错误凭据执行一个负向请求，确认认证结果符合预期。此操作只验证所用配置、binary、client 和请求路径；HTTP、WebSocket、QUIC 等其它场景应按 [Preview 总览](../preview/README.md)中的对应协议页与验收场景分别检查。

## 正常停机

前台运行时按 Ctrl+C 发送停止请求；受进程管理器控制时发送 SIGTERM。等待程序自然退出，再核对 listener 端口释放。若进程未退出，先保存原始输出、进程信息及配置/binary hash，再按故障流程处理；不要把强制终止结果记作正常 drain。

## 下一步

- 查阅[部署指南](deployment.md)、[配置操作指南](configuration.md)、[故障排查](troubleshooting.md)和[常见问题](faq.md)。
- 需要判断实现责任时看[仓库架构](../ARCHITECTURE.md)，需要确认字段时看 [Preview 配置](../preview/configuration.md)。
- 源码/CMake/test target 的说明不是执行结果；验收时记录本次源码 revision、配置 hash 和 binary hash，再按对应层级执行。
