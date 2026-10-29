# 故障排查

先记录启动命令、实际配置路径和首条错误。Prism 的配置错误通常包含字段路径；优先按该路径检查 JSON 中对应的字段，不要把旧版本配置字段直接复制到当前配置。

## 先判断问题发生在哪一步

| 看到的现象 | 说明 | 接下来做什么 |
| --- | --- | --- |
| 程序启动后很快退出，没有 `Prism READY` | 配置解析、启动校验、文件权限或端口绑定可能失败。 | 从控制台输出最上方的第一条错误开始；确认启动时使用的配置路径。 |
| 出现 `Prism READY`，但客户端连不上 | Prism 的启动阶段完成了，但这不证明客户端地址、协议、认证和目标网络都正确。 | 先检查 TCP 端口和监听地址，再检查客户端协议及账号。 |
| 客户端连上，但请求目标失败 | 代理握手可能已成功，问题也可能在 DNS、上游网络或目标站点。 | 用已知可访问的目标重试，并结合 Prism 日志区分 DNS、拨号和目标响应。 |
| 页面打不开，但管理 API 可访问 | Web 静态资源通常未构建、未部署或路径设置错误。 | 检查 `catalog.json` 和 `Operations.WebDirectory`。 |

每次只改一个因素并重试，例如先确认端口，再检查账号密码。这样能判断是哪一步改变了结果。

## 服务没有启动或 listener 不可用

1. 显式传入配置文件，确认不是误读可执行文件旁另一份 `PrismConfiguration.json`：

   ```powershell
   & '.\build\src\Prism.exe' '.\path\to\PrismConfiguration.json'
   ```

   ```bash
   ./build/src/Prism ./path/to/PrismConfiguration.json
   ```

2. 检查 `Listeners.Tcp[0].Address` 是否属于当前主机、端口是否已被占用。用 `127.0.0.1` 只能从本机连接。
3. Windows 可查看端口监听者：

   ```powershell
   Get-NetTCPConnection -LocalPort 1080 -State Listen -ErrorAction SilentlyContinue |
     Select-Object LocalAddress, LocalPort, OwningProcess
   ```

   Linux 可查看监听 socket：

   ```bash
   ss -ltnp 'sport = :1080'
   ```

   如果端口被占用，命令会显示占用端口的进程 ID（PID）。先确认它属于哪个程序，再选择关闭该程序或为 Prism 配置另一个空闲端口；不要直接结束不认识的进程。

4. 若错误指出 listener 冲突或配置字段不合法，先修正配置；不要用扩大监听地址或增加 timeout 来掩盖错误。

## 配置被拒绝

- 检查错误中的 JSON 字段路径、字段类型、重复 ID 和被引用的 ID。
- `Protocols` 声明实例后，还需要由 `ProtocolBindings` 引用；确认每个 `ProtocolId`、可选的 `CarrierId` 都存在。
- 当前只能配置一个 TCP listener，UDP 和 QUIC listener 各最多一个。
- `Routes` 必须保持空数组。当前非空 `Routes` 会被启动 service validation 拒绝。
- 启用 TLS/QUIC 时确认证书、私钥和协议专属配置齐全，并指向主机上可读的文件。

## SOCKS5 认证失败

在[`快速开始`](GettingStarted.md)的示例中，客户端用户名为 `local`，本机演示密码为 `change-me`。更换为 `SecretRef` 后，确认变量在启动 Prism 的同一进程环境里存在，但不要输出变量值：

PowerShell：

```powershell
if ([string]::IsNullOrEmpty($env:PRISM_SECRET_OPERATOR)) { 'missing' } else { 'set' }
```

Linux shell：

```bash
test -n "${PRISM_SECRET_OPERATOR:-}" && echo set || echo missing
```

SecretRef 到环境变量名的规则见[配置说明](Configuration.md)。在另一个终端设置变量不会更新已运行的服务；修改服务环境后需要由服务管理器重新启动进程。

还要检查客户端是否把用户名和密码放在正确字段中，以及账户 `Id` 与客户端用户名是否一致。不要把“TCP 端口可连接”当成“认证已通过”；它们是不同检查步骤。

## Prism 已启动，但代理请求失败

用 `curl` 的 SOCKS5 示例把失败层次分开检查：本机端口可连接、代理认证成功、DNS 解析成功、目标连接成功，最后是上游 TLS/HTTP 响应。`socks5h://` 让代理端解析目标主机名；外部目标不可达时，先换成本机网络允许访问的目标再判断 Prism 的 listener。

检查 Console 输出和配置中的 `Logging.Directory` / `Logging.FileName`。使用相对日志目录时，它相对于进程工作目录解析；systemd 部署见[部署说明](Deployment.md)。

如果客户端不在运行 Prism 的同一台机器上，`127.0.0.1` 会指向客户端自己的设备。此时应连接 Prism 主机的实际可达地址，同时确保 Prism listener 绑定到该地址或可接收连接的网卡，并检查主机防火墙和中间网络策略。

## Web 页面或 catalog 缺失

默认 `Prism` target 不生成 Web catalog。只有需要控制台静态资源时才安装 Node.js/npm 并构建 `PrismWeb`：

```powershell
npm ci --prefix Web
Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz'
# 上海时间 08:00–22:00：
cmake --build build --config Release --target PrismWeb -j 16
# 上海时间 22:00–08:00：使用 -j 1。
```

确认 `build/Web/catalog.json` 和页面资源存在，并确认 `Operations.WebDirectory` 指向部署后包含完整资源的目录。Node/npm 不影响仅启用 Operations API 的 `Prism` 服务端。

## CTest 通过，但真实客户端仍失败

CTest 只覆盖本次实际构建并运行的注册用例。确认服务、配置和客户端模板版本匹配；协议互操作需单独运行 Mihomo/Clash runner，并记录客户端版本、配置、返回内容和 Prism 日志。命令及 runner 的平台和目录限制见[构建与测试](../Testing.md)。
