# Prism Preview 本机管理页面

本目录保存正式管理界面的 React、TypeScript 与样式源码。当前授权工作树为 `C:\Users\C1373\.codex\worktrees\preview-quality\Prism`，页面源码位于该工作树的 `Web/`。

## 页面能力

- 概览展示当前进程的健康、入口就绪状态、Worker 当前页统计和真实统计数据。
- Worker 页面查看运行状态与流量，并在服务发布该能力时请求优雅排空。
- 账户页面查看撤销状态和统计数据；撤销确认会区分保留现有会话或同时关闭会话。
- 会话页面按当前进程列出 Session，并在选择后读取对应 Stream 与 Task；取消、重置等命令会先显示具体目标并要求确认。
- 事件页面按服务端游标读取当前保留窗口，呈现事件缺口、丢弃计数及真实操作状态。服务端不支持的跨页筛选会明确显示为不可用。
- 统计页面呈现真实累计值、已采样历史和识别延迟。延迟单位为微秒，百分位数是直方图桶下界近似值，最大值为实测值；未采到样本时保持空值，不补零。统计 collector 未安装时，Worker、Account 与 Session 流量显示为“未采集”；指标查询不可用时不会构造零值。
- 配置页面保留草稿并展示差异；只有当前配置版本下同一配置草稿的 ValidateOnly 操作得到完成确认后，才允许应用。服务端返回需重启的变更时，页面显示受影响字段，不会当作热更新成功。
- 操作中心恢复当前管理进程已取得编号的操作。进程更换、进度查询失败、操作记录不再保留及浏览器会话存储不可用时，页面会保留其能确认的事实并标出未知状态。

页面按 Bootstrap 声明的能力控制入口。命令需要明确确认；页面不会自动重发命令。命令响应丢失且没有取得可查询操作编号时，会明确显示结果未知，不能通过不存在的编号确认结果。

## 运行入口与访问约束

正式页面由 Preview 的 Operations HTTP 服务提供。当前 `Preview/Application/Configuration/PreviewConfiguration.json` 将 Operations 绑定到 `127.0.0.1:9090`；构建运行时页面资源目录为 `build/Web`，目录清单也由 Preview CMake 构建流程生成。使用已构建的 `PrismPreview` 和对应的 `build/src/PreviewConfiguration.json` 后，从同一地址打开：

```text
http://127.0.0.1:9090/
```

Bootstrap API 地址为同源的 `/Operations/Bootstrap`。命令凭据只由页面 API 客户端保存在内存并随同源 Bearer 请求发送；页面不把凭据写入浏览器存储、日志或界面。客户端仅允许本机 loopback HTTP 同源访问，不配置跨源代理或 CORS fallback。Vite 开发服务器的地址不是正式 API 入口。

## 检查与构建

需要 Node.js `>=24.14.1`。在 `Web/` 目录执行：

```powershell
npm ci
npm run check
npm run build
```

`npm run check` 执行 `tsc --noEmit`。`npm run build` 先运行同一类型检查，再由 Vite 生成页面资源到工作树根目录的 `build/Web`。Preview 的 CMake `PrismWeb` 目标会生成该目录的正式 catalog；`PrismPreview` 依赖此目标，运行时从可执行文件对应的 `build/Web` 读取完整性校验后的资源。

## 验收记录

本次 ProductionWeb99 源码检查覆盖实际 Operations API 解码、进程与配置版本范围、命令状态、空统计值、页面加载错误恢复、键盘操作与窄屏表格访问。`npm run check` 已通过。

Root 的 C6Production100Build 于 2026-10-14 20:07 上海时间完成：PrismPreview 编译链接成功，其 PrismWeb 依赖的类型检查、Vite bundle 和 catalog 生成通过；14 个页面资源的大小和 SHA-256 已逐项核对。按用户要求，当前版本尚未启动 Main、浏览器或测试，生产阶段现已停止，等待用户测试。完整路径、启动命令和证据见 [生产交付记录](/C:/Users/C1373/.codex/worktrees/preview-quality/Prism/docs/preview-refactor/2026-10-14-preview-production-delivery.md)。
