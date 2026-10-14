# Preview 部署指南

本页按当前 `PrismPreview` 的入口、配置和停止合同说明部署。构建步骤见[快速开始](getting-started.md)，字段见[配置说明](configuration.md)。当前完整重构仍在实施，各平台和协议的实际验收见[执行状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 程序与配置布局

构建统一使用仓库 `build/`，target 为 `PrismPreview`。Windows 产物在 `build/src/PrismPreview.exe`；Linux 产物为 `build/src/PrismPreview`。依赖运行库按实际编译器/链接结果部署，当前 MinGW target 仅显式设置 `-static-libgcc`，不能假定所有 C++ 运行库已静态链接。

推荐把部署配置放在独立目录并使用位置参数，避免再次构建时被源模板复制覆盖：

```text
C:\Prism\
  PrismPreview.exe
  PreviewConfiguration.json
  cert.pem
  key.pem
  logs\
```

```powershell
Set-Location 'C:\Prism'
.\PrismPreview.exe 'C:\Prism\PreviewConfiguration.json'
```

证书按配置文件目录解析，日志相对目录按进程工作目录解析。更换工作目录时应核对日志路径。部署用账户应能读取配置/密钥并写入指定日志目录。

## Windows 运行

先在前台启动，确认 READY、认证正负例、实际响应内容、Ctrl+C 退出与端口释放。需要后台进程时可以使用 PowerShell，保留进程对象和 stdout/stderr，便于追踪退出原因：

```powershell
$PreviewProcess = Start-Process -FilePath 'C:\Prism\PrismPreview.exe' -ArgumentList 'C:\Prism\PreviewConfiguration.json' -WorkingDirectory 'C:\Prism' -WindowStyle Hidden -RedirectStandardOutput 'C:\Prism\preview.stdout.log' -RedirectStandardError 'C:\Prism\preview.stderr.log' -PassThru
```

示例路径没有空格。实际含空格的配置路径需要正确引用。后台运行属于普通进程管理；当前 main 未实现 Windows ServiceMain，不能直接用 `sc create` 把该 console 程序当作原生 Windows 服务。后台停机需使用已有的受控进程管理或实际 Operations 命令合同，并核对取消/drain 完成。

## Linux 进程管理示例

在具有可用 C++23 工具链的环境构建并验证对应平台，再安装实际产物。下面仅给出 systemd unit 的配置示例，本轮 Windows 工作区尚未取得 Linux 构建/运行验收：

```ini
[Unit]
Description=Prism Preview
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=prism
Group=prism
WorkingDirectory=/var/lib/prism
ExecStart=/usr/local/bin/PrismPreview /etc/prism/PreviewConfiguration.json
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
```

用户、目录、程序、运行库、证书与权限应先实际准备；`Logging.Directory` 可设置为 `/var/log/prism`，日志目录需允许服务用户写入。当前入口注册 SIGINT/SIGTERM，收到停止请求后由应用关闭 owner 并 drain。实际服务超时与 `Shutdown.Timeout` 应配合真实停机验收确认。

## 接入与部署验证

默认 SOCKS5 模板使用 `127.0.0.1:1080`。扩大监听地址前配置独立凭据，并只开放实际使用的 TCP/UDP 端口。Operations Endpoint 必须保持 loopback，和代理接入端口分别管理。

部署验收应记录程序、配置和源码版本，并按顺序验证：

1. 启动输出 READY，核对实际 tcp/udp/quic 端口和状态。
2. 正确凭据执行固定目标请求并核对字节；错误凭据被拒绝且无后端拨号。
3. 针对启用协议执行 TCP/UDP、多流、半关闭和取消场景。
4. 请求停止，等待 drain 与自然退出，确认端口和本轮进程释放。

端口探测与一次 HTTP 200 只提供该层观察，完整真实链路证据按执行计划分别保存。性能容量应依据当前源码、配置、相同输入的实测结果确定，旧版性能报告不作为本次 Preview 部署容量承诺。
