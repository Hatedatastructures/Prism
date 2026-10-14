# Preview 六路生产交付记录

日期：2026-10-14，上海时间。当前阶段已停止，等待用户测试生产。

## 交付结论

Mux/AnyTLS、QUIC/TUIC/Hysteria2、TCP/UDP 协议、TLS/HTTP carrier、Runtime/管理/配置、Web 六路本轮生产改动已写入正式目录，统一构建成功。此次签收到源码结构检查、生产编译链接和 Web 资源生成；当前版本没有启动 Main、浏览器、CTest、互操作或性能验收。完整 M00–M42 质量任务仍保留这些后续验收与测试接口迁移工作。

唯一修改与构建目录：`C:\Users\C1373\.codex\worktrees\preview-quality\Prism`。生产源码在该树的 `Preview`，前端源码在 `Web`；`.superpowers/sdd` 保存记录和哈希。本阶段没有新增 Original/Candidate/源码备份，没有向 `I:\code\Prism` 迁入，也没有提交或推送。

## 运行文件

| 内容 | 完整路径 |
| --- | --- |
| 当前可执行文件 | `C:\Users\C1373\.codex\worktrees\preview-quality\Prism\build\src\PrismPreview.exe` |
| 当前运行配置 | `C:\Users\C1373\.codex\worktrees\preview-quality\Prism\build\src\PreviewConfiguration.json` |
| 配置源码 | `C:\Users\C1373\.codex\worktrees\preview-quality\Prism\Preview\Application\Configuration\PreviewConfiguration.json` |
| 前端源码 | `C:\Users\C1373\.codex\worktrees\preview-quality\Prism\Web` |
| 页面资源和清单 | `C:\Users\C1373\.codex\worktrees\preview-quality\Prism\build\Web` |

在 PowerShell 中由用户启动：

```powershell
Set-Location -LiteralPath 'C:\Users\C1373\.codex\worktrees\preview-quality\Prism'
& '.\build\src\PrismPreview.exe' '.\build\src\PreviewConfiguration.json'
```

当前默认配置的 TCP 入口为 `127.0.0.1:1080`，启用 SOCKS5；Operations 与页面入口为 `http://127.0.0.1:9090/`。Native TLS 关闭，QUIC listener 列表为空。其它协议的生产代码已包含在构建中，其真实请求需要对应的协议、入口和凭据配置，不能以默认 SOCKS5 配置代表它们的运行验收。日志目录当前配置为相对于运行工作目录的 `logs`。

## 本轮生产修改

| 领域 | 实际修改 |
| --- | --- |
| Mux/AnyTLS | 注册票据覆盖根发布至请求移交；先进入生命周期再消费 lease；子流等待两向 relay 与完整传输链实际退栈后归还资源；AnyTLS 区分帧边界 EOF 和截断并保留唯一 writer 的失败。 |
| QUIC/TUIC/Hysteria2 | Server MaxStreams 接入真实 peer 双向流 credit，原生 stream close 才归还；open/accept 唯一 expected 结果保留 ngtcp2 category/value；失败流由原连接关闭；本地 UDP 工厂拥有协程输入并沿 Close/Activity 清理失败资源。 |
| TCP/UDP 协议 | SOCKS5/SS2022 工厂和回复保留完整 Failure；UDP 回复来源与期限校验；VLESS 固定长度帧与 XUDP 分开处理；SS2022 gateway 使用有界 packet admission，认证重试精确区分协议认证错误和 OS I/O。 |
| TLS/HTTP carrier | H1/H3 消费完整失败值并迁移 QUIC expected 调用链；H3 每流 FIN 与连接关闭分离；WS writer gate 序列化整帧写入，保留控制与资源 owner。 |
| Runtime/管理/配置 | Pipeline/Dial/Relay/Pad 使用完整 Failure；后续安装/回复错误不覆盖更早首因；禁止使用已拒绝的 carrier 回复；管理终态发布区分提交与通知，异常触发实际 shutdown；Ban 使用固定容量表、strand 和 TTL。 |
| Web | 对齐进程、配置版本和目标身份；配置草稿验证/应用约束；未知命令不自动重发；真实空统计、懒加载错误恢复、键盘与窄屏访问；完成正式 bundle 和 catalog。 |

共享契约、错误枚举迁移、Lifecycle 依赖清理、新头文件登记和真实 Composition/Native 依赖由 Root 集成。生产编译中发现的两处 catch 内 co_await 和一处错误枚举混用已修复，再构建成功。

## 当前证据

- C6Production99Configure：退出 0，配置期间源码未漂移；核对的 BoringSSL 输入内容和修改时间未变。后续编译修复仅涉及生产 header，CMake 输入与缓存未变。
- C6Production100Build：19:55:06 开始，20:07:05 完成，上海白天 `-j 16`，只请求 PrismPreview 及其实际依赖；退出 0，PrismPreview target 完成，编译链接期间源码未漂移。
- 891 个生产 header 的 AST 结构检查：文件超过 600 行、函数超过 120 行、lambda 超过 10 行、参数超过 3 个均为 0；解析错误 0，49 项第三方 ABI 按精确接口登记。
- 173 条 CMake 依赖边检查通过；生产登记缺失、磁盘未登记、不可达 target、悬空 include 和生产 CPP 均为 0。该检查仍列出旧测试路径的 3 个一级大小写分歧、16 个展开分歧和 6 条未登记测试失效 include，未当作整项门禁全过。
- Web 类型检查和 Vite bundle 通过；catalog 的 14 个资源逐项大小和 SHA-256 相符，共 454958 字节。
- 运行配置与源码配置哈希一致；两个生产构建冻结点之间的 747 个测试输入哈希完全一致。本阶段未修改或运行这些测试。
- 自本阶段启动的配置和构建进程均已退出；没有启动生产服务或测试进程。六路子代理均已冻结，旧待初始化代理已中断。

源码输入聚合 SHA-256：`6b9d748f89655b9e7c3110c234cf3319178865680ea3128287ef649af9f1a4e4`。

当前 EXE SHA-256：`A43E1466E3558E1CE80D0481337C4B7222D25A4969ABB9E038E09E65F51D692A`，68893107 字节。

当前配置 SHA-256：`900E300D2CC7CBA61EFF93672436D4E92C87C8D530FC57622EE91E2832FC0712`。

Web catalog SHA-256：`E845292BC1646CD6068CACAF549ABABD9F074270E27D735E269CF511DE95A912`。

原始构建结果：[C6Production100Build-Result.json](/C:/Users/C1373/.codex/worktrees/preview-quality/Prism/.superpowers/sdd/2026-10-09-preview-quality-modification-plan/Review-20261012/C6Production100Build-Result.json)。当前结构证据：[Production100-Frozen-Style.json](/C:/Users/C1373/.codex/worktrees/preview-quality/Prism/.superpowers/sdd/2026-10-09-preview-quality-modification-plan/Review-20261013-Takeover/Continuation6/Root/Production100-Frozen-Style.json)。资源核对：[Production100-WebResources.json](/C:/Users/C1373/.codex/worktrees/preview-quality/Prism/.superpowers/sdd/2026-10-09-preview-quality-modification-plan/Review-20261013-Takeover/Continuation6/Root/Production100-WebResources.json)。

## 后续边界

按用户要求，本阶段到此停止。当前 EXE 是完成生产构建的交付版本，运行是否通由用户接下来测试。旧测试的 typed API 调用、目录迁移、focused/全量 CTest、真实请求、互操作、性能、Linux、浏览器及迁回 I 主目录均后置；没有把历史 Main96 或旧回归结果当作当前版本通过。
