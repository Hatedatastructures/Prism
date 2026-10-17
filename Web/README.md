# Prism 运维控制台

默认读取同源 `/Operations/*` 的 API v2；明确选择 `/?source=demo` 可以预览本页演示夹具。演示模式顶部持续显示提示，失败不会触发演示回退。`VITE_OPERATIONS_MODE=demo` 仅用于明确的开发或验收资源构建。

## 检查与浏览器测试

- `npm run check`：TypeScript 严格检查。
- `npm test`：Node 原生行为测试，验证实际 wire 形状、64 位保真、配置往返、操作请求和统计口径。
- `npm run test:e2e -- --project=edge-2265`：对已经运行的服务执行浏览器验收；配置不会自行启停服务器。`PRISM_WEB_URL` 可指向专用验收实例。
- 六个固定视口为 2265×1244、1920×1080、1440×900、1280×800、768×1024、390×844，DPR=1。测试包含 Edge 与 Chromium 项目；运行前安装对应浏览器。结果写入仓库 `build/WebQa/`。
- 正式资源由 CMake 的 `PrismWeb` target 生成。构建遵守根 AGENTS 的同意、目录与时间线程要求。

## 当前接线边界

Bootstrap 只接受 API v2。命令 token 只在 datasource 的私有内存中，不写 Query 缓存、URL、localStorage 或日志。每次 POST 使用幂等标识和启动 incarnation；无正文的 Drain/Revoke/Cancel/Reset 不发送空 JSON。Reload 使用编辑时固定的 `base_generation`，保留原始 JSON 整数 token。

正式部署使用管理端同源资源。开发代理仅在请求 Origin 与实际本机 Host 同源、且目标为固定 loopback HTTP 后端时映射 Origin；外部来源、畸形 Origin、带凭据来源与任意远端目标不会被提升为可信请求。此校验由 `scripts/ProxyOrigin.ts` 和对应行为测试覆盖，不放宽 C++ 管理端安全校验。修改开发配置会让既有 Vite 自动重载，本次没有手工终止或替换用户的 Node 进程。HTTP 请求形状和代理检查由确定性测试验证，不能据此声称生产后端操作已经联调。

当前后端仍在独立任务中修改。前端只使用 Bootstrap 公布的能力：`history.read`、`accounts.usage.read`、`accounts.usage.adjust`、`search.read`、`accounts.policy.write` 等未提供时明确说明不可用。未公布 `<collection>.filter` 时，搜索/状态仅筛选已载入记录，不发送被后端忽略或拒绝的参数。Events 的 process/generation 筛选同样受能力约束，并在已载入窗口核对身份。

旧账户 `active_sessions` 当前表示根连接租约，页面据此标记；独立活动 Session 数不可从这一字段推导。旧协议记录可能共享类型计数，页面标记共享覆盖；新增 `kind=type/instance` 后按类型行计算分布，不能把实例数据重复相加。

可靠额度执行、30 天持久历史、所有协议预算覆盖、持久操作幂等与动态健康，需要后端正式装配并分别验收。前端能力面板和演示夹具不能替代这些验收。
