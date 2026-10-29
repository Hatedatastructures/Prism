# 部署

部署目录至少需要 Prism 可执行文件、配置文件，以及配置引用的证书和密钥。启用 Web 控制台时，还要部署 `PrismWeb` 生成的完整资源目录。确认二进制和配置来自同一版本；程序以第一个位置参数读取配置，不传参数时读取可执行文件旁的 `PrismConfiguration.json`。

下面的步骤以 Linux `systemd` 为例。部署时要把路径、账户和端口替换为自己的值；不要把仓库里的回环演示配置不经修改就当成生产配置。

## 部署前先确定四件事

1. **服务从哪里运行**：安装二进制的位置，例如 `/opt/prism/Prism`。
2. **服务读取哪份配置**：建议使用明确的绝对路径，例如 `/etc/prism/PrismConfiguration.json`，这样不会误读可执行文件旁的另一份配置。
3. **运行账户能访问什么**：服务账户应能读取配置、证书和私钥，并且只在需要的位置写日志和运行数据。
4. **哪些端口对谁开放**：检查代理 listener、管理 endpoint 和防火墙规则。只有明确要提供远程代理服务时，才将代理入口绑定到可远程访问的地址；管理入口通常只应留在本机或受控管理网。

示例配置中的 `127.0.0.1` 只能接受本机连接。若客户端在另一台设备上，需按你的网络环境配置服务器可达地址和防火墙；改监听地址后务必更换演示密码并确认认证已启用。

## 生产环境检查

- 将 `Accounts[].Credential` 中的示例值替换为 `SecretRef`，通过服务管理器的环境变量或 secret store 注入秘密。不要把生产凭据放进配置仓库、容器镜像或命令参数。
- `change-me` 等演示凭据只允许用于回环 TCP listener。部署前确认所有监听地址、端口、防火墙规则和容器端口映射；需要远程访问时，只开放确实需要的入口。
- 确认证书、私钥、日志和 `Storage.Directory` 对运行 Prism 的账户有最小必要读写权限。优先使用绝对目录，避免服务的工作目录变化导致相对路径落到意外位置。
- 启用 Operations 前先确定 endpoint 的网络可达范围。启用静态 Web 页面还需配置 `Operations.WebDirectory` 指向包含 catalog 和资源文件的完整目录；具体步骤见[管理 API 与 Web 控制台指南](Operations.md)。
- 停机服务管理器应发送 `SIGTERM` 或等效正常停止信号；`TimeoutStopSec` 等等待期限应长于配置里的 `Shutdown.Timeout`，为 drain 留出时间。

## Linux systemd 示例

先准备一个专用的系统账户和目录。下面命令适用于常见 Linux 发行版；如果系统已有 `prism` 服务账户，可跳过创建账户的一步：

```bash
sudo useradd --system --user-group --no-create-home --shell /usr/sbin/nologin prism
sudo install -d -o root -g prism -m 0750 /etc/prism
sudo install -d -o root -g prism -m 0750 /etc/prism/certs
sudo install -d -o root -g root -m 0755 /opt/prism
sudo install -d -o prism -g prism -m 0750 /var/lib/prism
sudo install -d -o prism -g prism -m 0750 /var/lib/prism/logs
```

将经过检查的二进制、配置和所需证书安装到对应目录。示例命令只安装二进制；**不要把仍含有演示凭据的配置直接复制到生产环境**：

```bash
sudo install -o root -g root -m 0755 build/src/Prism /opt/prism/Prism
```

按[配置说明](Configuration.md)准备生产配置：账户使用 `SecretRef`，证书/密钥路径指向服务器上的真实文件，日志和存储目录对 `prism` 用户可写。配置文件可由 `root` 拥有并只授予 `prism` 组读取权限，例如 `root:prism`、模式 `0640`。私钥权限应尽量收紧，同时允许服务账户读取。

把准备好的配置和证书安装到服务会读取的位置。以下源路径只是占位符，需要替换成你已经检查过的文件：

```bash
sudo install -o root -g prism -m 0640 /path/to/PrismConfiguration.json /etc/prism/PrismConfiguration.json
sudo install -o root -g prism -m 0640 /path/to/server.crt /etc/prism/certs/server.crt
sudo install -o root -g prism -m 0640 /path/to/server.key /etc/prism/certs/server.key
```

若配置没有使用 TLS 证书，可跳过证书命令；如果文件名或配置路径不同，请同步修改配置里的路径。

环境文件 `/etc/prism/prism.env` 应由 `root` 拥有，并限制为服务账户可读；它的内容使用 `NAME=value`，不要写 shell 的 `export`：

```text
PRISM_SECRET_OPERATOR=replace-with-secret-from-secure-store
```

将上面的占位值替换为真实秘密，不要原样照抄；不要把包含真实值的环境文件提交到版本库。

将安全准备好的文件安装到 unit 使用的绝对路径，并保持 `root` 拥有、`prism` 组可读：

```bash
sudo install -o root -g prism -m 0640 /path/to/prism.env /etc/prism/prism.env
```

然后将下面内容保存为 `/etc/systemd/system/prism.service`，再按实际安装位置调整路径、账户和停止等待时间：

```ini
[Unit]
Description=Prism proxy service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=prism
Group=prism
WorkingDirectory=/var/lib/prism
EnvironmentFile=/etc/prism/prism.env
ExecStart=/opt/prism/Prism /etc/prism/PrismConfiguration.json
Restart=on-failure
KillSignal=SIGTERM
TimeoutStopSec=15s

[Install]
WantedBy=multi-user.target
```

配置中的 `SecretRef` 例如 `operator` 对应 `prism.env` 中的 `PRISM_SECRET_OPERATOR`。限制凭据文件读取权限，并确保 Prism 账户只能访问所需的配置、证书、日志和数据目录。若配置使用相对日志路径，日志会相对于 `WorkingDirectory` 解析。

安装 unit 后可用以下命令加载并启动服务、查看日志或正常停止：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now prism
sudo journalctl -u prism -f
sudo systemctl stop prism
```

`daemon-reload` 让 systemd 重新读取 unit 文件；`enable --now` 会设置开机启动并立即启动；`journalctl -f` 会持续显示新日志；`stop` 只停止当前运行的服务，不会取消开机启动。

可用下面两条命令检查服务是否仍在运行，以及最近的启动日志：

```bash
sudo systemctl status prism --no-pager
sudo journalctl -u prism -n 100 --no-pager
```

`EnvironmentFile` 必须存在，否则 systemd 不会按此 unit 启动服务。示例配置里的 `Shutdown.Timeout` 单位是毫秒；systemd 的 `TimeoutStopSec` 单位是秒，后者应长于前者，给活动连接留出正常退出时间。

首次部署建议先以前台方式启动同一二进制和配置，确认配置校验与监听成功，再交给 systemd 管理。`Restart=on-failure` 不会修复配置错误；若反复重启，先检查 `journalctl -u prism` 中首个配置错误。

如果前台启动正常、systemd 启动失败，优先比较两种启动方式的**配置路径、工作目录、环境变量、文件权限和用户身份**。systemd 使用 `User=prism`，它看不到只在管理员交互式终端里设置的环境变量，也不能读取权限不足的证书或配置。

## Web 资源

`PrismWeb` 是可选 CMake target。构建它需要 Node.js 和 npm；核心 `Prism` target 不需要前端依赖。资源默认生成在构建目录 `Web/`，将 `Operations.WebDirectory` 配置到部署后的资源目录。未构建或未配置 Web 资源时，Operations API 可以独立运行。

## Windows 服务

Windows 发行包仍通过同一个可执行文件和配置路径启动。若使用第三方 Windows 服务管理器，将 `Prism.exe` 设为程序、配置文件路径设为第一个参数，并通过服务环境配置 `SecretRef`。服务管理器的停止等待时间需覆盖 `Shutdown.Timeout`；请按所用服务管理器的文档设置账户权限和停止策略。
