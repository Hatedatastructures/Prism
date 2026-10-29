# 快速开始

本指南从仓库源码构建 `Prism`，用附带的 SOCKS5 示例启动服务，并通过 `curl` 发出一个真实请求。示例只监听本机回环地址，账户密码是 `change-me`，只能用于本机验证。

完成后，你会看到 Prism 在本机 `127.0.0.1:1080` 等待 SOCKS5 连接，并用客户端发出一个 HTTPS 请求。这里的 Prism 是代理服务端；`curl` 是临时使用的代理客户端。两者运行在同一台机器上，不需要先配置路由器或公网端口。

## 环境

- CMake 3.23 或更高版本。
- C++23 编译器；Windows 使用项目支持的 MinGW 工具链，Linux 使用 GCC 13 或更高版本。
- 首次配置需要网络，以便 CMake FetchContent 获取核心依赖。
- Node.js 和 npm 只用于可选的 Web 控制台资源，不是构建 `Prism` 的前置条件。

在仓库根目录配置并构建：

```powershell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
# 上海时间 08:00–22:00：
cmake --build build --config Release --target Prism -j 16
# 上海时间 22:00–08:00：将上一条命令的线程数改成 -j 1。
```

第一条让 CMake 检查源码、编译器和依赖，并把生成文件放入 `build/`；第二条检查当前时间；最后一条只构建名为 `Prism` 的服务端程序。每次构建前都要检查上海时间：08:00–22:00 使用 16 个线程，22:00–08:00 使用 1 个线程。第一次配置可能需要下载依赖，所以需要网络并可能花一些时间。CMake 或编译器报错时，先从输出中第一条 `error` 开始处理；后续错误有时只是前一条错误引起的。

Windows 产物为 `build/src/Prism.exe`；Linux 产物为 `build/src/Prism`。仓库维护者的时间、线程和 CTest 规则见[构建与测试](../Testing.md)。

## 启动示例配置

示例配置位于 [`Examples/Socks5.json`](Examples/Socks5.json)。它只开启 `127.0.0.1:1080` 上的 SOCKS5 TCP，不启用 UDP、QUIC、Operations 或 Web 页面。日志会输出到控制台并写入当前工作目录下的 `logs/prism.log`。

PowerShell：

```powershell
& '.\build\src\Prism.exe' '.\Docs\Tutorial\Examples\Socks5.json'
```

Linux：

```bash
./build/src/Prism ./Docs/Tutorial/Examples/Socks5.json
```

程序的第一个位置参数是配置文件路径；不支持 `--config`。示例使用 `change-me` 演示凭据，服务只允许它用于回环 TCP listener。部署前必须按[配置说明](Configuration.md)换成 `SecretRef`，并重新检查监听地址。

启动命令所在的窗口会持续显示服务日志。看到类似下面的 `Prism READY` 行，表示启动流程已完成；其中 `tcp_port=1080` 是当前 TCP 入口端口：

```text
Prism READY tcp_port=1080 ...
```

保持这个窗口打开，服务才能继续运行。按 `Ctrl+C` 会请求正常停止服务；如果窗口一启动就返回命令提示符，说明程序已退出，请查看它上方的第一条错误。示例中的日志文件按当前工作目录解析，通常会写到仓库根目录下的 `logs/prism.log`。

## 发出第一个请求

保持 Prism 在第一个终端运行，在第二个终端执行请求。示例会连接外部 HTTPS 站点；需要本机 DNS、网络策略和目标站点都可用。

PowerShell：

```powershell
curl.exe --proxy socks5h://127.0.0.1:1080 `
  --proxy-user 'local:change-me' `
  --head --fail --show-error https://example.com/
```

Linux：

```bash
curl --proxy socks5h://127.0.0.1:1080 \
  --proxy-user 'local:change-me' \
  --head --fail --show-error https://example.com/
```

命令里的地址和密码必须与示例配置对应：`127.0.0.1:1080` 是 Prism 的监听地址，`local` 是账户 `Id`，`change-me` 是演示密码。`socks5h://` 表示让代理服务器解析目标域名；`--head` 只请求 HTTP 响应头，因此不会下载整个网页。Windows PowerShell 中使用 `curl.exe`，可以明确调用系统里的 curl 程序。

请求应返回目标站点的 HTTP 响应头。`--fail` 会让 HTTP 4xx/5xx 返回失败状态；如果连接失败，先确认 Prism 仍在运行、端口 1080 已监听，再查看 Prism 控制台和 `logs/prism.log`。错误排查步骤见[故障排查](Troubleshooting.md)。

这个外部请求同时依赖远端网络，因此失败可能来自 Prism 之前的 DNS、出站网络或目标站点。要验证本机具体协议与客户端组合，请参阅[协议支持说明](Protocols.md)和[互操作测试说明](../Testing.md)。
