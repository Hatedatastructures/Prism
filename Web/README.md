# Prism 运维控制台

默认读取同源 `/Operations/*` 的 API v2；明确选择 `/?source=demo` 可以预览本页演示夹具。演示模式顶部持续显示提示，失败不会触发演示回退。`VITE_OPERATIONS_MODE=demo` 仅用于明确的开发或验收资源构建。

## 工作台交互

工作台使用暖灰外框、白色内容面与黑色主操作，状态颜色只表达实际运行语义。概览围绕实时流量、连接活动和资源占用组织：即时上下行速率明确标注快照时间，历史图表使用所选区间，TCP、UDP、QUIC 计数分别呈现，未采集的数据保持未知。Worker 默认使用列表，也可切换网格。手动刷新会明确反馈更新成功或失败，自动采样保持原有节奏。

全站共用 Inter / Noto Sans SC 字体、单层内容面、搜索清除、键盘选择和成组表单字段。账户关联的组/连接查询失败会显示为待核实；用户组成员先预览换组结果再显式保存。确认弹窗有安全初始焦点、提交进度与未决结果保护。配置使用编辑器与发布检查器，JSON 错误与编辑器关联，准确文本的校验结果随修改失效；Apply 必须返回终态并通过 Generation 与读回内容核对。当前选型依据及逐页评审见 [DESIGN_REVIEW.md](DESIGN_REVIEW.md)。

桌面导航可收起为图标栏，并在本机记住偏好；窄屏使用独立抽屉，关闭后恢复触发位置的焦点。`Ctrl+K` / `⌘K` 打开资源搜索；图表支持方向键查看采样、`Enter` 固定读数、`Escape` 清除。深浅主题、键盘焦点和减少动态效果偏好均受支持。

## 检查与浏览器测试

前端质量要求与验收边界以 [CONSTRAINTS.md](CONSTRAINTS.md) 为准；修改前先阅读 [AGENTS.md](AGENTS.md)。

- `npm run check`：TypeScript 严格检查。
- `npm test`：Node 原生行为测试，验证实际 wire 形状、64 位保真、配置往返、操作请求和统计口径。
- `npm run test:e2e -- --project=edge-2265`：对已经运行的服务执行浏览器验收；配置不会自行启停服务器。`PRISM_WEB_URL` 可指向专用验收实例。
- 六个固定视口为 2265×1244、1920×1080、1440×900、1280×800、768×1024、390×844，DPR=1。测试包含 Edge 与 Chromium 项目；运行前安装对应浏览器。结果写入仓库 `build/WebQa/`。
- 正式资源由 CMake 的 `PrismWeb` target 生成。构建遵守根 AGENTS 的同意、目录与时间线程要求。
- `npm run check:palette`：通过 PostCSS 验证主题色的唯一归属，并检查浅深主题的文字、图形和控件对比度；也包含在 `npm test` 内。
- `npm run test:a11y`：对已启动的服务执行桌面与手机 axe 扫描，包含浅深色主题和交互状态；完整结果保留在测试附件中，不能把工具的 `incomplete` 当成自动通过。
- `node scripts/MeasurePreview.mjs`：测量三个页面的本机加载候选、位移总和、长任务数量和资源传输量，写入 `build/WebQa/preview-performance.json`；开发环境、单次实验室观察及真实用户 Web Vitals 分开报告。
- [Web Quality 工作流](../.github/workflows/web-quality.yml) 对前端改动单独检查类型、行为、颜色、依赖与生产预览。需要真实 CI 运行结果才能确认这条链路通过；它不替代 Prism 服务和 catalog 联调。

## 当前接线边界

Bootstrap 只接受 API v2。命令 token 只在 datasource 的私有内存中，不写 Query 缓存、URL、localStorage 或日志。每次 POST 使用幂等标识和启动 incarnation；无正文的 Drain/Revoke/Cancel/Reset 不发送空 JSON。Reload 使用编辑时固定的 `base_generation`，保留原始 JSON 整数 token。

正式部署使用管理端同源资源。开发代理仅在请求 Origin 与实际本机 Host 同源、且目标为固定 loopback HTTP 后端时映射 Origin；外部来源、畸形 Origin、带凭据来源与任意远端目标不会被提升为可信请求。此校验由 `scripts/ProxyOrigin.ts` 和对应行为测试覆盖，不放宽 C++ 管理端安全校验。HTTP 请求形状和代理检查由确定性测试验证，不能据此声称生产后端操作已经联调。

当前后端仍在独立任务中修改。前端只使用 Bootstrap 公布的能力：`history.read`、`accounts.usage.read`、`accounts.usage.adjust`、`search.read`、`accounts.policy.write` 等未提供时明确说明不可用。未公布 `<collection>.filter` 时，搜索/状态仅筛选已载入记录，不发送被后端忽略或拒绝的参数。Events 的 process/generation 筛选同样受能力约束，并在已载入窗口核对身份。

旧账户 `active_sessions` 当前表示根连接租约，页面据此标记；独立活动 Session 数不可从这一字段推导。旧协议记录可能共享类型计数，页面标记共享覆盖；新增 `kind=type/instance` 后按类型行计算分布，不能把实例数据重复相加。

可靠额度执行、30 天持久历史、所有协议预算覆盖、持久操作幂等与动态健康，需要后端正式装配并分别验收。前端能力面板和演示夹具不能替代这些验收。
