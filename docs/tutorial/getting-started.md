# Preview 快速开始

本页使用当前 `Preview/` 实现。详细配置见[配置说明](configuration.md)，实施与验收进度见[当前状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 构建程序

在仓库根目录使用现有 `build/`。首次配置需要 C++23 编译器、CMake 3.23+、Git 及依赖下载条件：

```powershell
cmake -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
cmake --build build --config Release --target PrismPreview -j 16
```

上海时间 22:00–08:00 将 `-j 16` 改为 `-j 1`；08:00–22:00 使用 `-j 16`。target 产物为 `build/src/PrismPreview.exe`，默认配置从 [PreviewConfiguration.json](../../Preview/Application/Configuration/PreviewConfiguration.json) 复制到 `build/src/PreviewConfiguration.json`。Linux 产物没有 `.exe` 后缀。

## 准备配置并启动

默认模板启用 SOCKS5，TCP 监听 `127.0.0.1:1080`。先替换 `Accounts[0].Credential` 中的示例密码。若保留 Operations，其默认端口是 `127.0.0.1:9090`。需要长期使用的配置可以复制到独立部署目录，避免被 target 的配置复制覆盖。

```powershell
.\build\src\PrismPreview.exe
```

默认读取程序同目录的 `PreviewConfiguration.json`；显式指定文件使用第一个位置参数：

```powershell
.\build\src\PrismPreview.exe 'C:\Prism\PreviewConfiguration.json'
```

入口没有 `--config` 参数解析。相对配置路径按启动工作目录解析；Native TLS 的相对证书路径按配置文件所在目录解析。配置字段严格区分大小写，未知字段和缺失必填根字段会导致启动失败。

## 验证一次请求与停机

终端出现 `PrismPreview READY tcp_port=...` 后，用替换后的密码发 SOCKS5 请求；下面命令中的 `YOUR_PASSWORD` 是占位值：

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 --proxy-user 'user:YOUR_PASSWORD' --connect-timeout 5 --max-time 15 https://example.com/
```

核对响应内容和实际字节，再使用错误密码确认认证拒绝。浏览器需选择 SOCKS5 代理类型，并使用同一端口与凭据。默认模板没有开启 HTTP 代理。

在前台终端按 Ctrl+C 请求停机，等进程退出后确认监听端口释放。一次请求成功仅证明这次场景；完整多协议、半关闭、取消、drain 和互操作验收按[执行计划](../preview-refactor/2026-10-03-preview-no-compat-execution.md)分别记录。本页命令为操作说明，没有替代当前版本的执行证据。
