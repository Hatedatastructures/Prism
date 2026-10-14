# Preview 故障排查

先记录源码 revision/工作树、配置路径和 hash、`PrismPreview` binary hash、启动时间和原始错误。字段合同见[配置说明](configuration.md)，当前已验证与未完成责任见[执行状态](../preview-refactor/2026-10-03-preview-no-compat-status.md)。

## 启动失败

在终端运行 `build/src/PrismPreview.exe` 或给出配置路径位置参数，查看 stderr 的 `code/path/message`。按 Path 定位：

| 错误位置或现象 | 先检查 |
| --- | --- |
| 配置文件打开失败 | 默认 executable 同目录是否有 PreviewConfiguration.json；位置参数和工作目录 |
| UnknownField / MissingField / InvalidType | 严格 PascalCase、14 个必填根字段、JSON 值类型；旧版 agent/pool 字段不适用 |
| Accounts / SecretRef / Generation | 凭据格式、secret reference 与环境变量是否存在；UUID、16-byte PSK 合同 |
| NativeTls | 相对配置目录的证书/私钥路径、文件读取权限、PEM 格式和匹配关系 |
| Listeners / Bind | 地址是否属于本机、端口范围及占用、UDP/QUIC 是否共享入口 |
| Routes | 当前非空 `Routes` 会被 `ConfigurationStartup` 以 `UnsupportedService` 拒绝；保留为空，直到 startup 接线完成 |
| Logging | 日志目录可写、FileName 是纯文件名、Level 与 RenderMode 名称 |
| 程序尚未输出业务错误就无法加载 | 实际 MinGW/C++ runtime DLL 与 PATH，而非假定全部静态链接 |

只读检查端口和进程，核对 PID 后再决定操作：

```powershell
Get-NetTCPConnection -State Listen -LocalPort 1080 -ErrorAction SilentlyContinue
Get-Process -Name PrismPreview -ErrorAction SilentlyContinue
Get-FileHash -Algorithm SHA256 '.\build\src\PrismPreview.exe'
Get-FileHash -Algorithm SHA256 '.\build\src\PreviewConfiguration.json'
```

端口可能属于用户的其他服务，不能只按名称杀进程或删除 `build/tests` 来排查。

## 已 READY 但请求失败

核对 READY 中实际端口、客户端代理类型、凭据和目标。默认是 SOCKS5，使用 `socks5h://` 时域名解析发生在代理侧。正确密码与错误密码分别发请求；记录认证结果、后端是否实际 dial、literal payload/response、字节数和关闭结果。

TLS 场景同时检查协议 binding、carrier、SNI/ALPN、证书和 secret。DNS 场景检查目标域名、当前 Dns.Servers、Timeout 与服务器可达性。TCP listener 可连只说明接入成功，UDP/QUIC 则需要实际数据报/握手证据。

## 日志与观察

临时将 `Logging.Level` 设置为 `Debug`、`Console` 设置为 true；每次修改后重启实际使用这份配置的进程。日志相对目录按进程工作目录解释，结构化输出需要 `RenderMode: Structured`。完整模块说明见 [Diagnose 指南](../../Preview/Foundation/Utility/Diagnose/README.md)。

普通日志是有界非阻塞观察，可因竞争或队列容量被丢弃。日志行缺席需与提交/丢弃指标、请求结果一起判断；输出失败不得进入业务错误处理路径。

## 卡住、连接断开或速度下降

先定位发生阶段：识别/认证、dial、读写、半关闭、child admission、root cancel 或 drain。保留 typed error、线程/任务身份和原始输出，使用有界测试复现。旧版 `pool.max_cache_per_endpoint`、`multiplex.*` 调优片段不属于当前 Preview JSON，不能靠加入未知字段修复。

比较同源码、配置、payload、并发与目标条件下的直连/代理结果。单次吞吐、Perf label 或 overload 丢弃不足以说明改善；分配、p50/p95/p99、CPU 和内存须按当前性能卡测量。

## 停机与测试定位

前台用 Ctrl+C 请求停止，等待自然退出，再查对应端口和 PID。若有 cancel/drain 错误，保存错误并与强杀清理分别记录。测试只使用已经构建的 binary；先查看当前真实 suite：

```powershell
ctest --test-dir build -N -R '^(ConfiguredMuxSession|ProviderAcceptPath|BindingLifetime)\.'
```

不能把一个模块的旧绿灯或 factory 通过当作当前 listener 和完整重构通过。发现生产缺陷时同步问题台账 `logs/issues.md`，保留失败输入和版本，再按同一场景验证修复。
