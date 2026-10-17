# Preview 部署指南

本指南说明如何部署一个已为目标平台构建、并与配置版本对应的 `PrismPreview` 程序。构建约束和 Preview 文档入口见 [Preview 总览](../preview/README.md)，字段与路径合同见 [Preview 配置](../preview/configuration.md)，资源关闭责任见[仓库架构](../ARCHITECTURE.md)。本页提供部署步骤，不登记特定平台的构建或运行结果；通过结论应由绑定目标平台、源码 revision、配置和 binary hash 的报告支持。

## 准备可回滚的部署包

从同一个已核对的 build/revision 收集可执行文件和其运行资源。将部署配置、证书、私钥及可选运行资源放在权限合适的位置；具体目录布局以打包方式和配置中的资源字段为准。避免直接把正在运行的实例配置指向仓库内可能被构建命令更新的模板。

上线前保存：

- 源码 revision 与工作树状态；
- `PrismPreview` 和 `PreviewConfiguration.json` 的 SHA-256；
- 运行平台、运行库、监听地址/端口和 secret reference 名称；
- 上一版程序与配置的回滚路径。

版本号或文件名相同不足以证明 binary 与配置匹配。

## 前台启动与检查

先用前台方式运行并保留 stdout/stderr。用第一个位置参数显式指定配置路径：

```powershell
& 'C:\Prism\PrismPreview.exe' 'C:\Prism\config\PreviewConfiguration.json'
```

```bash
/usr/local/bin/PrismPreview /etc/prism/PreviewConfiguration.json
```

若不传位置参数，程序从 executable 同目录读取 `PreviewConfiguration.json`。相对 Native TLS 证书/私钥路径从配置文件目录解析。将 SecretRef 对应环境变量配置在服务进程的环境中，避免依赖交互式管理员 shell 的临时状态。

启动输出包含 TCP 端口、UDP readiness 和 QUIC readiness。将 READY 中报告的状态与本次配置和预期入口逐项比对；已绑定端口不代表对应 UDP/QUIC 协议已经完成真实数据面请求。

## 进程管理

在上线服务管理器之前，先验证目标平台可执行文件、运行库、配置资源和自然停机。应用注册 SIGINT 与 SIGTERM；Linux 进程管理器通常可用 SIGTERM 请求收尾。受控环境下配置一个足以覆盖实际 drain 的停止等待时间，并在目标平台观察自然退出及端口释放。

Windows 可先以前台控制台实例进行试运行。需要隐藏窗口或托管进程时，使用组织已有的进程管理方式保存 stdout/stderr、PID、启动参数和退出码。当前入口是普通可执行程序；不要仅因它可以在后台运行就把它描述成平台原生服务。

任何 systemd/unit 或服务管理器示例都必须使用本机真实部署路径、服务账户和退出预算，并先在目标平台单独验证；本指南不提供未经本机验证的 unit 作为已测试配置。

## 网络与凭据

从 loopback 或受限网段开始部署。只有在确认 protocol binding、credential、主机防火墙和上游路由后，才打开对外监听。Operations 管理端点应与代理接入分别控制访问；不要将就绪输出或日志当作访问控制。

使用 SecretRef 时，将规范化后的 `PRISM_PREVIEW_SECRET_...` 环境变量注入服务进程。Native TLS 证书与私钥应只允许服务账户读取；记录轮转窗口，并按配置页验证相对路径的基准。

## 发布与回滚

1. 在非生产实例以相同平台、配置形状和目标协议启动候选包。
2. 检查 stderr、READY 端口和各 readiness 字段。
3. 用独立 client 做认证正负例、固定目标请求、需要的 stream/datagram 场景以及关闭验证。
4. 保存源码 revision、binary/config hashes、输入、响应和退出信息。
5. 切换生产流量后观察错误与资源使用；若合同不匹配，恢复上一版程序和配置并重新验证。

构建 target、CTest 映射、外部互操作和运行态检查属于不同证据层；按 [Preview 总览](../preview/README.md)中当前指南执行，不以旧报告或单一 READY 行替代当前部署验收。
