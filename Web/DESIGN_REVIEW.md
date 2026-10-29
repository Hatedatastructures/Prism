# Prism 页面与配色研究

## 2026-10-24 全页面桌面打磨

本轮沿用首页已落地的灰紫画布、白色内容面与克制强调色。实际逐页打开全部 11 个路由，在 1440×1000 和 1280×1000 下采集并查看页面；主工作范围是其余 10 页。组件、信息顺序、选中与展开状态一起复核，未进行生产构建或重启现有 Vite/Prism。所有视觉截图均为演示数据。

| 页面 | 本轮调整 | 桌面实图 |
| --- | --- | --- |
| 资源分析 | Worker 比较和质量明细并排；数值右对齐，1280px 五列完整显示；统计范围保持区块弹层。 | [1440px](../build/WebQa/CurrentReview/pages-final-resources-1440.png) |
| 代理入口 | 数字、传输图标、ID 分层；入口按钮可选择流量，保留来源和时间范围。 | [1440px](../build/WebQa/CurrentReview/pages-final-ingresses-1440.png) |
| 协议分析 | 类型分布与实例速览合为连续分析面；缩短目录行高；趋势支持直接切换目标且刷新保持 URL。 | [1440px](../build/WebQa/CurrentReview/pages-final-protocols-1440.png) |
| Worker | 收紧目录宽度与条目间距，扩大详情宽度；对象标题、任务统计、全宽页签保持明确层级。 | [1440px](../build/WebQa/CurrentReview/pages-final-workers-1440.png) |
| Session | 主从区增加稳定分隔，累计上下行分层；完整身份使用可键盘关闭并恢复焦点的弹层。 | [1440px](../build/WebQa/CurrentReview/pages-final-sessions-1440.png) |
| 代理账户 | 搜索与状态筛选对齐；紧凑身份头、双向速率、余额分区、两列账本及额度调整单选组件。余额缺测和零总额均不画假百分比。 | [1440px](../build/WebQa/CurrentReview/pages-final-accounts-1440.png) |
| 用户组 | 成员操作对齐；趋势移入选中组的独立页签；目录、统计与成员范围保留在邻近弹层。 | [1440px](../build/WebQa/CurrentReview/pages-final-user-groups-1440.png) |
| 事件流 | 搜索、级别与资源过滤对齐；缺口保持可见，游标放入窗口说明；展开证据按字段对齐。 | [1440px](../build/WebQa/CurrentReview/pages-final-events-1440.png) |
| 配置 | 添加文件标题与同步行号，长文档滚动和文本编辑保持准确；差异展开、发布流程及焦点边界统一。 | [1440px](../build/WebQa/CurrentReview/pages-final-configuration-1440.png) |
| 操作中心 | 连续清单与结果检查区并列；状态、读取时间与重新查询对齐；身份展开和结果核对说明保持明确。 | [1440px](../build/WebQa/CurrentReview/pages-final-operations-1440.png) |

1280px 对应图位于相同目录的 `pages-final-<route>-1280.png`。额外实际操作并记录了 15 个状态：范围弹层、入口流量、协议目标切换、Worker 排空状态/空筛选、Session 阶段/身份、账户额度表单、组趋势/设置、事件展开/窗口说明、配置差异和操作身份/说明。独立浏览器没有发现页面 JS 错误；编辑器底部滚动时行号与文本 scrollTop 都为 4433。

验证：类型检查通过；单元与 Palette 共 100/100；依赖声明一致，审计 0 漏洞。完整 1440/1280/390 套件初次为 228 通过、6 个原有视口专用跳过、3 个旧首页 DOM 断言失败。采样时间原本就在新页头，检查更新为新位置及新标签，同时保留时间、缺测、历史区间和跳转上下文断言。最终受影响无障碍、修复项与新增行为共 45/45 通过；768/1920/2265 中间宽度与桌面布局另有 9/9 通过。未删除、跳过或放宽原有行为断言。完整记录见 [pages-validation.json](../build/WebQa/CurrentReview/pages-validation.json) 和 [交互记录](../build/WebQa/CurrentReview/pages-interactions.json)。

本轮是开发预览的实现与检查，不代表生产打包、真实后端联调或用户审美验收通过。

2026-10-23 逐页复审。范围：当前开发预览的 11 个路由，以及列表、详情、筛选、空值和错误状态。现行浅色主题是微冷中性画布（`#f3f3f6`）、白色导航与内容面、深墨文字，紫色 `#5749e9` 只负责品牌强调、选中状态和主图表；绿、琥珀、红分别保留成功、告警和失败含义。早期文稿里的暖白/石油青描述已经过时，以 `src/Styles/Palette.css` 为唯一现状。

## 2026-10-23 桌面视觉重设

这次以用户提供的 Magpie 图为主要依据，重新处理画布与白色内容面的关系、共享组件层级与各页阅读顺序。`awesome-design-md` 的 Linear 文档提供组件约束；生成概念只作构图参考，其中虚构的导航、连接记录和状态未加入产品。这一版尚待用户视觉验收，不把自动化通过表述为审美签收。

| 页面 | 当前调整与实图审查 |
| --- | --- |
| 运行概览 | 重排为四项核心读数带、流量与协议合并分析面、入口与资源容量两列；接入依据改为页头弹层，保留完整诊断和下一步入口。当前快照与历史窗口仍标明各自范围。 |
| 资源分析 | 图标标题、大读数与小单位；BytePool 明确占用块容量；Worker 当前值配相对自身峰值的比例条，不引入假历史。 |
| 协议分析 | 类型总数、分布总览和分项使用一致图例；目录给身份与覆盖说明完整宽度，绑定数靠右，1280px 无孤字换行。 |
| Worker | 连续可比较目录替换嵌套的小卡片；身份边界改为说明弹层，无匹配结果时详情区给出选择指引。 |
| Session | 白色指标带和详情工作区统一；范围提示降为中性行，连接阶段仍保留键盘展开与真实证据。 |
| 代理账户 | 额度余额与周期总额组成读数区；调整入口有图标、箭头旋转和明确展开状态；两类调整仍使用可操作的选择组件。 |
| 用户组 | 共用新指标带、紫色主操作与选中态；复核目录、成员选择、保存及组策略视图。 |
| 代理入口 | 共用指标带；承载与协议改为轻量标签，配置地址和实际绑定继续并列。 |
| 事件流 | 错误读数用失败色，警告与观测缺口用警告色；筛选、展开与当前窗口边界保持邻近。 |
| 配置 | 编辑器与发布检查器共享新面板层级；空差异区域收紧，保留编辑、校验、应用与读回顺序。 |
| 操作中心 | 状态未知的核对提示移入操作面板，与记录和重新查询操作放在同一区域。 |

视觉比对覆盖六点：灰紫画布/白面分层、白色导航与紫色选中、标题/读数/单位字阶、紧凑控件与分区、桌面列宽与对齐、语义状态和缺测数据。1440px 与 1280px 的 11 路由实图位于 `build/WebQa/CurrentReview/redesign-<route>-<width>.png`，使用演示数据。开发预览未发生整页横向溢出或页面脚本异常。

开发预览验证：类型检查通过；单元测试 100/100；Palette 4/4。完整 `edge-1440` / `edge-390` 套件首轮 150 通过、4 个按视口预期跳过，4 个检查发现同一处首页未选中标签对比度为 4.26:1；改为更深的语义文字色后，这 4 项复查全部通过。768/1280/1920/2265px 布局回归 12/12；资源零峰值不绘制比例条的专项与浅深色检查 8/8。保留全部原有断言与阈值。没有执行生产构建，没有重启 Vite 或 Prism。

实际复核了调额展开、统计说明弹层、Worker 键盘焦点/空结果和深色首页。截图与紧凑验证记录均位于 `build/WebQa/CurrentReview/`。以下保留先前迭代依据，不作为这次重设的验收数字。

首页最新构图以 `composition-overview-1440.png` 和 `composition-overview-1280.png` 为准。核心读数保留缺测；当前 RSS 与下方 RSS 峰值分别呈现；入口摘要显示真实绑定，配置监听地址在入口详情继续核对。状态依据弹层已验证键盘关闭后的焦点恢复。首页在 1440/1280/390px 的分区、刷新失败、缺测、浅深色及交互检查 24/24 通过；类型检查、100 项单测和差异空白检查通过。此次没有把首页专项结果当作全站重新验收。

## 先前迭代记录

- **颜色按面积和职责分配。** 浅色画布为 `#f3f3f6`，白色导航/内容面为 `#ffffff`，正文为 `#222229`；紫色 `#5749e9` 用于当前选择和主图表，青蓝 `#078bb8` 只用于次级曲线。边框和辅助文字保持中性，深色单独校准明度；未知、等待、警告与成功保留各自语义色。
- **文字重新分工。** Inter Variable 负责拉丁字母和界面数字，Noto Sans SC Variable 负责中文，JetBrains Mono 只用于 ID、地址、时间和代码。保留正文 16px、表格单元格 15px；大读数的数字与单位拆分层级，金额、字节和速率值仍使用原有格式化结果。
- **结构降低嵌套。** 208px 侧栏、52px 顶栏、24px 桌面内容边距。面板使用单层白色内容面、轻边框与统一内距；汇总读数采用连续统计带，目录和详情根据实际对象关系组织，不把每一行都装进卡片。
- **控件统一。** 搜索支持一键清除并恢复输入焦点；筛选和时间范围共用带键盘导航、选中标识、Escape 关闭及焦点恢复的 Radix Select。额度字段和其他表单项复用显式标签、帮助文本与错误关联；确认对话框展示当前操作、进度状态，并区分明确失败和结果待核实。无数据读取失败提供重试；旧数据刷新失败会标明它是上次成功读取的快照。原生复选框使用主题色。
- **操作流程可解释。** 用户组的成员选择先形成草稿，显示原组与目标组，再显式保存；切换对象不会携带旧组的改名草稿。配置页由编辑器和发布检查器构成，显示编辑、校验、应用步骤以及字段差异。等待服务端结果时不把已受理标为完成，读回期间保护草稿。
- **图表遵循数据类型。** 实时流量、延迟和活动数按各自的单位绘制；计数图使用整数量尺，避免把小数四舍五入后出现重复轴标签。鼠标和键盘均能定位采样点。

## React 组件方案

React 负责把状态组合成界面，本身不附带有主题样式的控件库。Prism 已使用 Radix Primitives 的选择器、页签和对话框；这个包提供的是无样式交互构件，焦点管理和键盘行为交由组件处理，界面需要产品自己的样式。[Radix Primitives 介绍](https://www.radix-ui.com/primitives/docs/overview/introduction)

Radix Themes 则是另一个包含整套样式、theme tokens、全局 CSS 和 `Theme` 容器的现成组件库。[Radix Themes 安装与使用](https://www.radix-ui.com/themes/docs/overview/getting-started)把它与目前 `Palette.css` 的中性色、布局面板、语义状态层叠，会引入第二个表层系统；目前保留 Radix 的交互构件，在上面建立少量带明确业务接口的共享 React 组件，并由唯一 Palette 决定颜色。对输入项按 Label、说明、错误和禁用状态组合；按钮、弹窗和下拉框按同一尺寸、焦点与进度状态处理。它参考 shadcn/ui 常见的组合方式，但没有把其 Tailwind 依赖引入这个没有 Tailwind 的代码库。[shadcn/ui 组件清单](https://ui.shadcn.com/docs/components)

实际实施完成情况与待复核组件状态以当前浏览器截图和验收记录为准；库的名字本身不能作为视觉质量证据。

生成的视觉概念只用于验证材料、版面和信息层级。实际页面不采用生成图中的虚构资源容量、统计值或不存在的操作；实际浏览器截图才是实现证据。

## 配色研究的结论

不能从“网络工具”直接推出“应该使用蓝色”。界面颜色首先服务阅读层级、对象定位、状态识别和操作反馈。产品识别色是后续选择，不应同时染色背景、文字、边框和全部图表。

1. **先确定灰阶的用途与面积。** Radix 区分中性灰与有色相的灰；它明确提醒多种彩色状态控件可能与饱和背景冲突。初版蓝灰候选的问题是把同一种色相扩散到太多界面层。原参考图的可借鉴点是暖冷极轻的底材、清楚的深色内容，以及局部状态色，不是整页套色。[Radix 配色组合](https://www.radix-ui.com/colors/docs/palette-composition/composing-a-palette)
2. **背景、交互状态、边框、正文需要不同的明度角色。** Radix 的 12 阶色板分别对应背景、hover/selected、边框、实色和文字。它是一种职责分配方法，不意味着直接取任意阶数就能通过项目全部对比度约束。[Radix 色阶用途](https://www.radix-ui.com/colors/docs/palette-composition/understanding-the-scale)
3. **降低辅助结构的视觉重量。** Linear 2026 年的实际改版降低了侧栏显著程度，减少边框和额外图标装饰，并把偏蓝基底往低饱和、稍暖的灰色调整；该团队也指出过暖会显得浑浊。这支持减少色偏与结构噪声，不证明某个 Hex 就一定适合 Prism。[Linear 2026 改版](https://linear.app/now/behind-the-latest-design-refresh)
4. **用感知明度检查色阶。** RGB/HSL 数字等距不代表视觉等距。Oklab 把感知明度、色度与色相分开，适合比较浅深主题的层次。它不能代替 WCAG 对比度计算，也不能给出“美观合格分”。[Oklab 原始说明](https://bottosson.github.io/posts/oklab/)、[Linear 主题生成经验](https://linear.app/now/how-we-redesigned-the-linear-ui)
5. **品牌、数据与状态各有语义。** Spectrum 强调有目的地分配颜色，并要求状态有文字或图标配合。Carbon 将分类数据、连续数值和告警颜色分别处理。Prism 的上行/下行不应被误读为成功/失败，线型和图例仍需保留。[Adobe Spectrum](https://spectrum.adobe.com/page/color/)、[Carbon 图表配色](https://www.carbondesignsystem.com/building-blocks/data-visualization/color-palettes)

## 当前设计边界

- 内容面保持清楚的中性白或低色偏深灰，背景只负责分层。正文、单位、辅助说明不统一染成品牌色。
- 主操作、键盘焦点、当前选择与曲线不必共用一个实色 token；先定义角色，再决定是否共享颜色。
- 状态色始终保留“正常、警告、失败”含义；未知、已受理、等待完成不能用成功色。
- 图表基色先按系列辨识与层级检查，深色主题单独调明度与色度，不把浅色主题简单反相。
- 文字可读性维持既有正文 16px、表格单元格 15px 合同。局部标签可以紧凑，不能靠全站缩字获得密度。
- 在账户列表、连接详情、资源图表和告警场景中同时验证背景与颜色面积；单个首页不能作为最终设计证据。
- 新主题必须在完整页面中复核，不将“对比度通过”描述为“用户已认可外观”。

## 逐页复审结果

以 1440px 桌面整页为主要设计验收视口，逐一复查 11 个路由；390px 窄屏只做兼容回归，不反过来决定桌面版式。短列表保持真实高度，不添加演示记录填空；所有页面继续使用一致的白色导航、页面标题、低对比分隔线、状态色与表单焦点规则。最终验收以开发预览的逐页截图和交互验证为准。

| 路由 | 当前问题 / 数据边界 | 本轮优化 |
| --- | --- | --- |
| `/` 运行概览 | 一页中流量、Worker、入口、账户、延迟、协议、事件、质量同时争夺注意力，首页滚动过长。首页首要任务是观察流量、连接与资源。 | 将内容分为「实时运行」「代理资源」「诊断记录」三组键盘可操作页签。默认只呈现流量、连接、资源占用与入口状态，其他数据仍在同页可达。 |
| `/events` 事件流 | 示例只有 5 条记录，表格下面留白明显；这些空白来自短列表，不能靠假数据补足。实时事件已有暂停追随和手动刷新。 | 保留高密度表格、覆盖/丢弃缺口提示和显式记录范围；后续只在真实记录增多时验证分页与自动追随，不增加占位图表。 |
| `/resources` 资源分析 | RSS、受追踪分配、BytePool、观测完整性口径不同；实时 API 没有公开历史窗口查询，不能让趋势面板反复请求不存在的接口。 | 保留按资源域组织的摘要、Worker 分配表和覆盖说明；历史组件按 Bootstrap capability 决定是否请求，未开放时显示紧凑的中性说明，时间范围控件也明确禁用，不画虚构曲线。 |
| `/ingresses` 代理入口 | 监听表和下方三张配置卡重复展示传输与代理协议，让单一入口信息分散在两处。 | 把配置 ID、传输、配置监听、实际绑定、连接数、承载方式、代理协议、状态收在同一条记录中，移除重复卡组。窄屏卡片保留相同字段。 |
| `/protocols` 协议分析 | 同名配置实例会共享协议类型统计；实例流量不能当成可相加的独立值。真实历史 API 当前未开放。 | 保持「类型分布」与「配置实例」两层，明确类型共享与覆盖范围；趋势面板对未支持实例显示实际能力状态。 |
| `/workers` Worker | 列表用于横向比较，详情包含任务、Session、账户和操作；当前数据不提供 CPU 负载。历史窗口接口未开放。 | 桌面保留比较表；手机将状态卡片与详情切为两步视图，选择后聚焦返回入口，返回后复位目录焦点。主卡只留接收状态、活动任务和邮箱容量，累计拒绝/失败/丢弃收进展开区。 |
| `/sessions` Session 追踪 | 实时接口只返回活动 Session，并按单调递增 ID 游标从较早记录开始；短连接若在读取前结束就不会进入该清单。实时 `Draining` 是进程阶段，不是连接独立状态。 | 新增列表轮询暂停/恢复、手动刷新和最近成功读取时间；手机详情切为单独视图，收起只服务列表的搜索/筛选与范围说明，但保留刷新入口和快照时间；选择与返回均有明确焦点落点。最新优先/已结束 Session 仍需后端新查询契约。 |
| `/accounts` 代理账户 | 主从结构清楚；额度账本字段与额度读写能力未由当前实时 API 提供。 | 未开放时不请求额度、不显示零额度、不允许提交。手机先显示目录，选择后单独呈现用量/策略/连接/趋势与撤销确认；返回保留筛选和账户身份。 |
| `/user-groups` 用户组 | 成员搜索和计数只覆盖已载入账户范围；历史归属无法从当前 API 还原。 | 保留成员预览、待保存归属与策略配置；手机目录与组详情切为两步视图，返回保留当前组及草稿上下文；已载入范围持续提示，未开放历史统一呈现中性能力说明。 |
| `/configuration` 配置 | 编辑、差异、校验和应用需要保持严格顺序，无法通过“漂亮”动画掩盖结果未知。 | 保留编辑器与发布检查器两栏，差异紧邻校验/应用流程；草稿来源改变、错误与未决结果继续锁定正确操作边界。 |
| `/operations` 操作中心 | 示例只有 2 条近期操作；未知终态需要核对，不能因列表稀疏而制造总览指标。 | 保留操作 ID、目标身份、重新查询与未知状态说明；手机将详情和记录列表分开，返回入口不再挤压面板标题，列表/详情焦点可键盘连续追踪。 |

### 跨页面接口边界

- Bootstrap 当前没有 `history.read`、`search.read`、`accounts.usage.read` 或 `accounts.usage.adjust`；实时管理路由也没有 History、Search、AccountUsage、UsageAdjustments。HistoryPanel 与全局搜索只在能力已确认后发请求；历史时间范围会明确显示不可用；额度组件已有相同的能力门控。内部存储或额度账本不等于 Web API。
- 账户、Worker、Session、组和协议筛选大多只作用于已载入游标页；文字和计数必须标出局部范围。界面不把它们说成全局查询。
- 实时 Session 列表并非最新优先。前端重新排序已载入页面无法改变服务端首批游标，因此当前使用范围提示；不要加一个看似可用但实际无效的“最新”排序按钮。
- 行内/趋势的缺测值、请求错误、未开放能力和真实零值继续分别呈现；不通过紫色/绿色等颜色单独表达状态。

### 字体与动效

字体资源采用 Inter Variable、Noto Sans SC Variable 与 JetBrains Mono Variable。中文变量字体文件名中的内部家族名包含 Thin 字样，不能据此推断渲染字重；需结合实际 CSS 字重和浏览器字体检查。新增页签和状态提示沿用可见焦点、键盘切换与 `prefers-reduced-motion`，不增加列表重排动画。

## 验收边界

### 2026-10-23 逐页截图复核与本轮修订

本轮以当前 Vite 开发预览对 11 个路由分别检查了 1440px 桌面和 390px 手机布局，再对有具体问题的页面改组件并重截。最新桌面、手机首屏与五个手机详情截图保存在 `build/WebQa/CurrentReview/current-*.png`。下表把浏览器观察与实现决定合在一起，避免用通过测试数量代替视觉判断。

| 路由 | 复审结果与本轮决定 |
| --- | --- |
| `/` | 三个任务页签保留；事件缓冲从较早序号开始，诊断页改称“事件首批样本”，明确它不是最新记录。手机端示例提示改为两行栅格，说明和“切换真实实例”不会挤在一行造成尾字孤行。 |
| `/events` | 桌面保留便于比较的高密度表格；手机改为事件记录卡片，时间、级别、内容、关联资源和详情展开集中在一条记录中，避免 840px 表格挤进 320px 容器。 |
| `/resources` | 移除把同一 ResidentBytes 分别展示成 RSS 与工作集的重复读数；详情合并为“资源质量”下的内存和观测两个分区。补充真实 DTO 提供的 BytePool 可用块与单块大小。手机 Worker 分配改为卡片，覆盖说明可逐行展开。 |
| `/ingresses` | 保留按入口汇总配置监听、实际绑定、连接数、承载、协议和状态的单行结构；桌面表格与手机记录卡字段一致，没有再次拆回重复能力卡片。 |
| `/protocols` | 同类实例共用的活动量和流量不能显示成各实例独立用量；未提供统计归属时表格只显示实例身份与绑定数。类型、实例、趋势改用可访问页签切换，窄屏实例改为记录卡片。 |
| `/workers` | 桌面比较表与手机 Worker 卡使用一致字段；手机详情独立呈现，选择后焦点移到返回，返回后回到清单。累计量放在展开区，避免首屏塞满数字。 |
| `/sessions` | 桌面主从布局与完整身份深链保留；手机详情独立呈现，列表搜索/筛选收起，刷新按钮、成功快照时间、精确身份和返回路径仍可用。快速离开活动清单的连接仅在前后同一实例和过滤范围都被采样时进入本页留存，并继续精确核对身份；UI 不宣称它已经关闭。 |
| `/accounts` | 目录与所选详情、用量页签及撤销确认保留；手机从目录进入详情，返回保留 q/filter 和 account ID；未开放额度读写能力时不显示假额度。 |
| `/user-groups` | 组目录、成员归属草稿、明确保存和策略来源边界均保留；手机从目录进入详情，返回保留组 ID 和上下文，已载入范围说明贴近搜索与成员列表。 |
| `/configuration` | JSON 编辑、差异、校验和应用顺序清楚；演示配置为空差异时有明确下一步说明。未加入会遮挡长 JSON 编辑的固定操作条。 |
| `/operations` | 记录列表和所选操作状态形成主从关系，手机详情用独立的返回行避免挤压标题；受理、待终态、失败与结果未知继续区分，短列表不补造记录或指标。 |

本轮实时预览响应为 HTTP 200；另用开发预览浏览器逐页截图和检查新卡片、协议视图切换。未重启 Vite 或 Prism，也未执行生产构建。`/resources` 与 `/protocols` 在开发预览可打开，但 C++ [Catalog.cpp](../Src/Prism/Operations/Web/Catalog.cpp) 的 `IsPage` allowlist 尚未包含这两个路径；生产静态资源直达/刷新需要单独修正此路由并按仓库规则验收。

### 桌面优先续审

纠偏后的这一轮先用 1440px 桌面整页截图复核全部 11 个路由，再抽查运行概览的 1280px 桌面断点；窄屏没有承担设计决策。桌面复核发现首页连接活动和资源占用分处不同网格行，导致主流量图旁出现空洞。现将两项摘要收为右侧纵向区域，并让入口状态横跨内容区；同时修正 1180px 以下首页网格断点的覆盖优先级，防止固定桌面列在中间宽度继续挤压内容。短列表继续按真实条数显示。

本轮更新截图保存在 `build/WebQa/CurrentReview/round2-*-desktop.png` 与 `round3-overview-1440.png`、`round3-overview-1280.png`。首页改动后 `npm run check`、`npm run check:palette`（4/4）和 `git diff --check -- Web` 通过；`edge-1440` 与 `edge-1280` 的概览交互/主题无障碍定向套件各 6/6 通过。较早的完整桌面/手机 E2E 套件为 148 项通过、2 项按视口预期跳过，浅/深主题无障碍套件 48 项通过；首页网格修改后另对两个桌面断点定向复核。截图使用演示数据，未重启 Vite 或 Prism，也未执行生产构建。

未执行生产构建：仓库 `AGENTS.md` 要求构建前取得明确同意，前次用户授权范围限定为开发预览验收；未重启 Prism 或 Vite，也未发送真实后端写操作。自动化结果只证明已覆盖的行为与布局，不代替用户对视觉结果的评价，也不等同生产资源服务或真实管理 API 验收。

### 2026-10-23 桌面 Session 快速变化复核

在 1440px 桌面画面中，连接目录增加「当前活动 / 本页最近离开」页签；后者只保存本次打开页面实际观察到、随后从相同实例和相同过滤范围快照中消失的最多 20 条，5 分钟后过期。切换过滤范围、Prism 实例或进程 incarnation 会立即清除旧范围记录；手动清空则以当前活动集合建立新基线，避免下一次轮询把已清记录重新加回。

从当前快照消失只显示「未见于最新快照」。选中记录后按完整 Process、Generation、Worker、Account、Session 身份重读；只有精确查询确认不在活动清单中，详情才显示已退出当前活动清单并隐藏取消操作。该页面记录不等同持久历史，不会补回两次采样之间创建并结束的短连接，也不会把活动列表缺项直接当成连接关闭。

实际桌面截图位于 `build/WebQa/Playwright/ProductionQuality-Session--4a023--a-missed-session-as-closed-edge-1440/session-observed-exit.png`。新增路径覆盖 1280、1440、1920、2265px 桌面 E2E，并验证 Radix 页签方向键、Popover Escape 焦点恢复、清空留存后的下一轮轮询、列表范围变更和精确身份复核；更新后的设计合同见 [DESIGN.md](DESIGN.md)。

最终开发预览验收：`npm run check` 通过，`npm test` 100/100，`npm run check:palette` 4/4，`git diff --check -- Web` 通过；当前完整桌面 `edge-1440` E2E 为 74 通过、2 个手机专用用例按视口跳过，Session 快速变化场景在 1280/1440/1920/2265px 为 4/4，Session 浅/深色无障碍场景在 edge-1440/edge-390 为 4/4。没有执行生产构建；Vite 与 Prism 均未重启。

### 2026-10-23 awesome-design-md 桌面组件复核

本轮确认本机已安装 `awesome-design-md`，实际采用它的 `design-md/linear.app/DESIGN.md` 作为组件层级参考：保留 Prism 的浅色白工作区与现有主题色，借鉴克制强调色、紧凑数字层级、细分隔和减少重复控件；不套用 Linear 的深色品牌画布，也不照搬品牌布局。1440px 是主复核视口，1280px 只用于桌面断点回归。

- `/protocols` 默认视图把活动 TCP Session 类型分布与已载入实例目录并排放置，避免为比对两个口径来回切页。实例搜索同步 `protocol_q`，随 URL 保存；清空后焦点回到搜索框。覆盖范围改为 ID 旁直接可读的文字；当整批接口都未标出实例独立统计时，由区块说明一次表达，移除每行重复的“统计范围”和“实例统计未提供”按钮/标签。分布仍只使用协议类型数据，实例统计只在接口明确标识 `Kind=instance` 时展示；没有扩大或估算任何统计归属。
- `/resources` Worker 分配范围移至区块级说明入口，弹层内按 Worker 展示真实覆盖文字；比较表保留 Worker、当前、峰值、分配次数和释放次数，不再为每一行重复打开相同范围控件。资源域仍分开显示，不把 RSS、PMR 与 BytePool 合并成一个数值。
- 桌面截图使用演示数据，实际检查了 [资源页](../build/WebQa/CurrentReview/resources-scopes-refined-1440.png) 和 [协议页](../build/WebQa/CurrentReview/protocol-scope-refined-1440.png)。协议页短列表保留真实四项，不补造行数来填充页面；完整目录及后续游标仍可通过目录视图访问。

本轮验证：`npm run check` 通过，`npm test` 100/100，`npm run check:palette` 4/4；协议与 Worker 资源口径用例在 `edge-1280` 与 `edge-1440` 共 4/4 通过；完整 `edge-1440` E2E 为 75 通过、2 个手机专用用例按视口跳过，无失败。截图为本地演示数据，不代表 Prism 后端的实际统计；未构建生产资源，也未重启 Vite 或 Prism。

随后修正共享流量历史图：每个纵轴刻度现在明确使用 `B/s`、`KiB/s` 或 `MiB/s`，保留以 1024 换算的既有数值口径；刻度栏加宽以容纳完整单位。实际截图检查了 [1440px](../build/WebQa/CurrentReview/protocol-trends-units-1440.png) 与 [1280px](../build/WebQa/CurrentReview/protocol-trends-units-1280.png)，标签可读且图线未被挤压。新增浏览器断言验证流量轴单位。最终 `npm run check` 通过、`npm test` 100/100、`npm run check:palette` 4/4；包含该共享图表改动后的完整 `edge-1440` E2E 再次为 75 通过、2 个手机专用用例按视口跳过，无失败。未执行构建，开发服务器与 Prism 均保持原进程。

### 2026-10-23 桌面主从与证据密度续审

本轮再次按本地 `awesome-design-md` 的 Linear 参考检查 11 个路由，以 1440px 作为版式判断视口、1280px 作为第二桌面断点，窄屏只做既有流程回归。Linear 参考文档指导克制强调色、对齐、分隔和数字层级；Prism 仍使用自身 Palette 与浅色工作面。没有把“使用参考”当成外观验收结论，以下调整都在浏览器截图里复核。

- `/workers` 默认改为桌面主从工作区：左侧紧凑可选清单显示状态、活动任务、邮箱占用和累计拒绝/失败/丢弃；右侧首屏显示所选 Worker 的完整代次、队列、派发、任务、Session/账户关联和排空入口。完整横向比较表放到同页“完整对比”页签；选择比较行会回到详情工作区，`worker_view=compare` 可分享。1440px 下两张趋势图并排；1280px 将图表纵向排列，避免轴单位和标题挤压。手机继续使用原来的列表/详情步骤。
- `/sessions` 将重复的长时间线与二次展开明细合成逐阶段摘要行。时间、阶段名称、状态和耗时在一行对齐；键盘或点击展开单条记录后查看相对时间、Span、Parent、Worker、Account、Stream、Task 与实际属性。耗时缺失仍显示“未提供”，没有估算填充。
- `/protocols` 类型分布在并列面板内改为四行纵向排列，与右侧四条实例目录采用一致节奏，避免两行分布下方的大块空洞。统计仍按类型而非配置实例归属。
- `/resources` 将直接影响数据含义的摘要、覆盖和观测质量说明提升到 13px；主读数、采样身份及口径仍分区呈现，没有添加无来源的历史曲线。

实际开发预览截图：[1440px Worker 工作区](../build/WebQa/CurrentReview/desktop-workers-1440-final.png)、[1280px Worker 工作区](../build/WebQa/CurrentReview/desktop-workers-1280-final.png)、[1440px Session 阶段行](../build/WebQa/CurrentReview/session-trace-compact-1440-final.png)、[1440px 协议分布](../build/WebQa/CurrentReview/protocol-distribution-1440-final.png) 和 [1440px 资源页](../build/WebQa/CurrentReview/resources-1440-final.png)。这些截图使用演示数据。

最终验证：`npm run check` 通过，`npm test` 100/100，`npm run check:palette` 4/4，`git diff --check -- Web` 通过；桌面 Worker/Session/协议精修用例在 `edge-1280` 与 `edge-1440` 为 6/6 通过；完整 `edge-1440` 与 `edge-390` E2E 为 154 通过、4 个按视口设计预期跳过，无失败。该完整套件包含 11 路由的浅色/深色无障碍检查。未运行生产构建；未重启 Vite 或 Prism。


### 2026-10-24 桌面组件续作

本轮承接关联聊天中断前的账户页设计稿，依据用户的白侧栏、灰紫画布和克制紫色方向，以及 awesome-design-md 的 Cal.com / Linear 组件层级参考，落实连续工作面和分段控件。没有重新替换框架或安装组件库；复用已存在的 Radix 行为基础，参照 [shadcn/ui Tabs](https://ui.shadcn.com/docs/components/radix/tabs) 与 [Radix Tabs](https://www.radix-ui.com/primitives/docs/components/tabs) 的结构和键盘约定。

账户目录改为首字头像、名称、ID、组与连接数和状态组成的整行按钮；短名称通过 aria-describedby 关联完整状态，选择、读屏和键盘操作一致。账户头、分段页签、余额与上下行速率形成顺序；1280px 仍并排显示余额和速率，1180px 以下分行。额度调整按类型选择、字节量、原因、确认排列，未改变 revision、能力与结果核对。零额度或缺失余额仍不绘制虚假占用比例。

用户组的目录与详情使用同一工作面；成员默认展示身份、流量与当前组，按需展开分组编辑，取消清除本次草稿并恢复入口焦点。Worker 目录放大身份与关键读数；操作中心移除内部目录外框及重复的命令/目标事实。共享详情页签使用白色选中面、紫色标记与明确焦点；其他页面沿用自身任务结构。

Session 的指定目标未解析时仍在右侧核对原始身份和留存证据，活跃详情与待核对区保持独立语义；不放宽 Process、Generation、Worker、Account 的匹配。事件没有完整操作来源身份时仅显示原操作 ID 和操作中心核对入口，不用当前实例补造历史身份。

视觉复核使用 Playwright CLI + 本机 Edge：本会话没有可用 Browser/IAB 工具。11 个路由均实际打开并逐页查看截图；1440px 全页横向溢出均为 0；额外查看了 1280px 账户、用户组、Worker 与协议页，以及额度展开、成员换组、Session 未命中和深色账户状态。原设计稿尺寸 1505 × 1045；已按同尺寸采集并与稿件在 view_image 中对照。

| 比较点 | 本轮处理与保留差异 |
| --- | --- |
| 工作面 | 账户目录与详情合为一个白色平面，以竖线分隔；去掉重复的账户详情标题。 |
| 对象头 | 首字头像、主名称、ID、组与连接数逐级排列；目录保留真实上下文，未省略身份信息。 |
| 页签 | 分段容器、独立选中面和高对比紫色标记，保留方向键、焦点和减少动态效果。 |
| 数值与单位 | 余额主读数、周期总额、速率并排；不按设计示例伪造更宽的极小使用比例。 |
| 控件与表单 | 调额入口按需展开，类型选择、输入和确认对齐；危险操作单独保留在底部。 |
| 配色与文字 | 沿用唯一 Palette；保留演示数据提示、统计范围和完整身份说明；没有采用稿件中的装饰性汇总图标或更宽侧栏。 |

首屏文字核对：保留生产页面的标题、导航、字段和演示提示；去除重复标题与重复事实；“到操作中心核对”是修正不可验证深链后明确的新入口。没有新增业务指标或产品宣称。对应实际截图为 [账户](../build/WebQa/CurrentReview/continued-accounts-1440.png)、[用户组](../build/WebQa/CurrentReview/continued-user-groups-1440.png)、[Worker](../build/WebQa/CurrentReview/continued-workers-1440.png) 和 [Session 指定目标](../build/WebQa/CurrentReview/continued-session-missing-1440.png)。

验证过程保留原断言：换组测试增加显式展开和取消的用户步骤，继续验证受理到终态期间所有写控件锁定；初次整体验收发现 Session 状态区错误复用活跃详情类，随后拆分，既有“不存在活跃 inspector”的断言保持不变。完整最终结果另列于下方。

源码基线：HEAD 8bb25db380cb3a2ff25421c62833e9137d635178 加现有工作树；99 个 Web 源码、测试和依赖登记文件的集合 SHA-256 为 66bf379469b18a64b5a04e2eeaee9f501f758b39e0a897cd30defb0a3ff6c0ac，逐文件记录见 [源码清单](../build/WebQa/CurrentReview/continued-source-manifest.json)。本轮使用 source=demo 与独立 API mock 验证前端，不代表真实 Prism 后端联调、生产构建或生产性能验收。




最终验证：资源采样范围的语义角色收尾前，Edge 155 完整 E2E 为 176 项（172 通过、4 项按视口预期跳过、0 失败或不稳定）；之后给采样元数据补上具名 group 角色，桌面/手机、浅/深色组合6/6通过。完整测试原始报告保存在[完整 E2E 基线](../build/WebQa/CurrentReview/continued-full-playwright-results-before-resource-group-fix.json)，资源修正后的补测报告见[资源页补充结果](../build/WebQa/CurrentReview/continued-resource-a11y-playwright-results.json)。完整 E2E 报告中58次 axe 扫描无自动违规；资源语义修正后4次 axe 扫描也无自动违规。修正后的报告没有再标记资源快照为 aria-prohibited-attr，剩余2条是运行态 Process 与 Generation 之间的装饰分隔点导致的 Axe 无法自动裁定项；分隔点不承载身份值或状态，两侧身份正文仍有对比度，截图与 Palette 计算已人工复核。图轴文字人工核对了真实截图与Palette对比度；焦点隐藏提示来自模态框和导航抽屉打开时的焦点守卫，Tab陷阱和Escape焦点恢复由交互测试覆盖。结果不构成完整WCAG认证。

类型检查、npm test（100/100）、Palette（4/4）、npm ls和高严重级npm audit（0个漏洞）通过。768、1280、1920、2265px的全工作区与Session回归20/20，概览断点4/4。1440px逐页检查的11个路由整页横向溢出均为0px。源码指纹与逐文件哈希见[清单](../build/WebQa/CurrentReview/continued-source-manifest.json)，机器可读摘要见[验证结果](../build/WebQa/CurrentReview/continued-verification.json)。未运行生产构建或真实Prism后端联调。


### 2026-10-24 账户页第二轮桌面重构

再次按用户的方向重做账户页首屏。使用 Magpie 截图的白色内容面、冷灰画布和克制紫色作为外观参考，沿用 Prism 的白侧栏与颜色 Palette；本次重点是拆掉四块汇总卡，改为无边框范围读数，并让账户身份、余额和速率构成主体。账户页详情从外框卡片变为平面工作区，仅在目录与详情之间保留竖向边界。详情页签使用文字加紫色细下划线，桌面中间尺寸仍保持主从结构。

账户统计及目录范围保持可见，加载失败和总数未知状态有自己的说明。可用额度条改为显示剩余比例（Remaining/Limit），不再显示已用比例而与巨大的余额值冲突。零额度或余额缺测仍不绘制误导性进度。组策略、连接、账本、时间范围与完整身份信息均保留。额度调整仍以展开方式开始，继续使用表单校验和确认对话框；撤销仍独立展示，并保留撤销时是否关闭活动连接的选择。

本轮视觉对照：对象层级、目录项目、统计信息密度、账本定义列表、页签状态和调额展开区均与[1505 × 1045 概念稿](C:/Users/C1373/.codex/generated_images/01a169c1-06f3-7751-bd5e-04b1265c942d/exec-dd47673d-afed-43ca-b7c8-35b0539b4ab5.png)和相同原生宽度的[实际截图](../build/WebQa/CurrentReview/round2-accounts-concept-size.png)逐项检查。实际画面保留了稿中摘要行所承载的必要统计范围，但移除卡片背景与分隔；账号编辑仍折叠，危险操作独立靠下，避免把可直接改账本的控件误作普通读数。另查看了[1440px浅色账户页](../build/WebQa/CurrentReview/round2-accounts-1440.png)、[1280px桌面页](../build/WebQa/CurrentReview/round2-accounts-1280.png)、[深色状态](../build/WebQa/CurrentReview/round2-accounts-dark-1440.png)和[调额展开](../build/WebQa/CurrentReview/round2-accounts-adjustment-1440.png)。颜色、文字、焦点在浅深色页面保持同一套 Palette。没有改用户数据或任何操作API合同。

最新账户定向验证：1440、1280、390px 项目共18项通过，覆盖摘要范围、账户整行的读屏描述、过期/失败数据提示、账户目录关联错误、只显示真实可用比例、方向键切换调额类型及 Session 列表行距。新增账户主题 axe 桌面/手机和浅/深色 4项通过，零自动检测违规。类型检查通过，单测100/100，Palette4/4；本轮没有增加依赖。上轮仍有效的全11路由检查与会话/事件状态修复结果见前一节。当前开发预览运行在 http://127.0.0.1:5174；没有在 5173 上覆盖或重启其它服务。完整浏览器命令和此次源码指纹见[验证摘要](../build/WebQa/CurrentReview/round2-verification.json)及[逐文件清单](../build/WebQa/CurrentReview/round2-source-manifest.json)。本轮仍不包含生产构建或真实后端联调。


### 2026-10-24 账户页第三轮重构

用户反馈前一轮即使改了卡片与对齐，视觉仍像传统后台。本轮换掉首屏构图，而不是继续叠样式：四块白底摘要卡删除，账户状态作为无边框数字行保留其加载范围和错误文案。详情与目录连成整块白色工作区，撤去外层大圆角和投影。选中账户用名称、ID、用户组、Generation 和租约数组成标题身份；页签回归文字加短紫线。额度仍先显示实际余额及周期上限，实时上/下行速率与其并列，账本事实保持两列；进度条改为填充真实剩余额度比例，使99.9/100 GiB 对应近满的可用余额。

这轮对照 Magpie 色彩参考与此前生成的账户概念稿：[1505 × 1045 概念](C:/Users/C1373/.codex/generated_images/01a169c1-06f3-7751-bd5e-04b1265c942d/exec-dd47673d-afed-43ca-b7c8-35b0539b4ab5.png) 和 [实现截图](../build/WebQa/CurrentReview/round2-accounts-concept-size.png)。检查的五个主要对照点为账户名、用户组和状态是否一眼可读；目录是否保持连续对齐；选中标签是否清楚；余额、周期上限、单位与进度条是否指向同一口径；账本细项与危险操作是否各有位置。危险操作仍在独立页脚栏，调额仍折叠并要求完整表单及二次确认；这两项与概念示例的直接展示不同，按真实安全操作流保留。上行/下行和账本口径文字也仍在余额块下，免得丢失数据边界。

本轮同一页面实看了 [1440px浅色](../build/WebQa/CurrentReview/round2-accounts-1440.png)、[1280px桌面](../build/WebQa/CurrentReview/round2-accounts-1280.png)、[1440px深色](../build/WebQa/CurrentReview/round2-accounts-dark-1440.png) 与 [调额展开](../build/WebQa/CurrentReview/round2-accounts-adjustment-1440.png)。账户功能回归 18/18 通过，包含额度缺测/零额度、余额显示真实可用比例、搜索范围、对象身份、连接表和方向键单选；账户桌面/手机浅深主题 Axe 测试4/4通过。TypeScript检查、单测100/100、Palette4/4和 git diff --check 通过。新增规则使用端口5174的本机开发预览，端口5173原先已无监听。依赖未添加。逐文件指纹与可复核测试结果见[源码清单](../build/WebQa/CurrentReview/round2-source-manifest.json)和[验证摘要](../build/WebQa/CurrentReview/round2-verification.json)。


本次第二轮的账户详情和摘要布局为最终版本：1440px标题下改成无边界统计读数行、搜索目录与对象详情连续铺开；通过见[1440px](../build/WebQa/CurrentReview/round2-accounts-1440.png)、[1280px](../build/WebQa/CurrentReview/round2-accounts-1280.png)、[深色](../build/WebQa/CurrentReview/round2-accounts-dark-1440.png)和[调额表单](../build/WebQa/CurrentReview/round2-accounts-adjustment-1440.png)。测试结果18/18通过，账户 axe 浅深色和双视口4/4通过；TypeScript、100项单测、4项 Palette 与 diff check 均通过。逐文件基线见[源码清单](../build/WebQa/CurrentReview/round2-source-manifest.json)，可复核机器报告见[验证摘要](../build/WebQa/CurrentReview/round2-verification.json)。临时Vite服务端口5174保持打开供预览，本次未触碰5173；不包括生产构建或后端联调。


真实实例边界核查：Web 的 live 数据源通过 Vite 代理到 127.0.0.1:9090。查询本机监听与 Prism.exe 进程均未发现服务；只读 GET /Operations/Bootstrap 经现有预览代理返回 HTTP 502，未读取或显示任何凭据。用户选择继续用演示数据，因此本轮页面数值仍明确来自 source=demo，不作为真实运行数据。开发预览服务在127.0.0.1:5174供用户查看，不重启或占用原来没有监听的5173。


### 2026-10-24 生产数据所有者复核

本轮先沿 C++ 的状态所有者、持久化所有者和 snapshot 构造一路追到 Web decoder、页面与 Demo source；Bootstrap/route 只用来确认管理投影边界，没有把字段声明当作运行值。生产实现的核对点如下：

| 区域 | 项目内数据所有者 | 页面必须保留的范围 |
| --- | --- | --- |
| 概览 | `OperationsManagementQueries.cpp::MakeOverview` 组合活动 Generation、Listener、Process、QUIC registry 与 `Traffic` | TCP 当前连接、可选 QUIC、明确未知的 UDP、实际采样间隔和相邻计数差。生产 Overview 已携带有界 `History`；本轮改为缺少 `history.read` 时消费这份快照，标题显示样本数、计数差换算和间隔。 |
| 入口 | `OperationsManagementQueries.cpp::MakeIngresses` 组合配置、Listener 绑定与运行健康 | 配置地址与真实绑定地址分开；UDP 活动数未知时不显示为零。配置未提供的 `Reason`/`StateSince` 不当作真实诊断。 |
| 协议 | `MakeProtocolSnapshots` 读取活动 Generation 的协议/绑定，再关联 Listener 和 `Traffic` | 当前生产行代表配置协议类型及绑定；活动 TCP Session 可关联；QUIC 活动数/流量不可用。没有生产协议实例目录或每协议历史查询。 |
| 资源 | `PopulateMemorySnapshot` 读取 Process、PMR、Worker allocator、BytePool | RSS、PMR 和 BytePool 保留各自 owner 与覆盖范围；是快照/累计计数，不拼成假的历史曲线。 |
| Worker | `OperationsSnapshotQueries.cpp::MakeOperationsWorkers` 读取 `Process::Snapshot()` | 队列、任务、派发和命令计数来自运行时；`Worker <id>` 是前端名称，`LoadPercent` 没有生产测量字段，显示未知。 |
| Session | `MakeOperationsSessions` 读取 `Listener::Registry()` | 列表是当前活动 TCP Session，不是已关闭会话档案；Trace、Streams、Tasks 通过独立 owner 查询，Trace 保留丢失区间。 |
| 账户 | `MakeOperationsAccounts` 读取活动 Generation 的 Account Store、Admission publication 和 `Statistics::Scope::Account` | 当前投影是 ID、Generation、标签、组、撤销状态、根连接租约和累计流量。活动子流、实时账户速率、有效策略、来源和 `AccountKey` 不在这个 C++ snapshot 中。 |
| 用户组 | 活动 Generation 的 AccountGroups 配置为目录，账户 snapshot 供计数与流量聚合 | 成员范围跟随当前已加载账户页；不能把已载入成员数描述成永久完整目录，也没有用户组历史接口。 |
| 事件 | `RuntimeState::Events` 的 `EventRing` 有界保存并报告丢弃/覆盖范围 | 这是运行中保留窗口，不是持久审计归档；搜索和筛选只覆盖可读取范围。 |
| 操作 | `MakeOperations` 由事件环内 operation ID 对受理与终态事件聚合 | 结果只能确认仍留在事件环内的操作，不包装成持久操作账本。 |
| 配置 | 活动 `ConfigurationGeneration` 序列化当前公开配置和 `SecretRef` | 当前代次快照不是配置历史；秘密值不应从界面或日志泄露。 |

配额是需要区分的另一条 owner 链：`StorageLifecycle` 把 `SqliteUsagePersistence` 接到账户 runtime；SQLite owner executor 中的 `UsageLedger` 执行读、预约、结算和调整。相关持久化与预算行为有 C++ 测试源码覆盖。可是当前 Operations bootstrap 能力和路由没有 `accounts.usage.read`/`accounts.usage.adjust`、策略读写、`history.read` 或 `search.read`。`LiveAdminDataSource` 预备了部分客户端方法，不等于后端已提供合同。额度 UI 的数值由 `DemoAdminDataSource` 的示例账本支持；Live 模式按能力门控，不能把 Demo 的余额/策略/速率字段报告成现网字段。

本轮的两处数据呈现修改都沿用了这些 owner 边界：账户详情新增账户维度累计上/下行统计，并明确与周期账本已结算量分开；概览在生产实例未公告 `history.read` 时，改用已随 `/Overview` 返回的有界样本画速率图，不额外请求缺失路由。历史样本少于两个时显示样本不足，不补零或合成曲线。页面截图和定向测试使用真实接口形状的浏览器 mock 或明确的 `source=demo`，没有接入在线 Prism 实例。

本轮逐文件清单与测试报告见[生产来源复核清单](../build/WebQa/CurrentReview/source-owner-audit-manifest.json)和[验证记录](../build/WebQa/CurrentReview/source-owner-audit-verification.json)。实看截图：[账户累计统计与账本](../build/WebQa/CurrentReview/account-traffic-1440.png)、[Overview 有界流量样本回退](../build/WebQa/CurrentReview/live-overview-bounded-history-1440.png)。其中账户使用 Demo 样例；Overview 使用与 live decoder 对齐的 mock，不是真实实例值。

### 2026-10-24 信息密度与 Trace 口径收口

这轮直接沿 C++ 责任所有者核对页面可用信息：`PolicyConfiguration::CompilePolicy` 编译账户/用户组策略，`RuntimeRegistry` 把预算与 `UsagePersistence` 接到账户 runtime，`StorageLifecycle` 再接 SQLite 额度账本；可对照 [UsageModels.hpp](../Include/Prism/Account/UsageModels.hpp)、[RuntimeRegistry.cpp](../Src/Prism/Account/RuntimeRegistry.cpp) 与 [StorageLifecycle.hpp](../Src/Prism/Application/StorageLifecycle.hpp)。但 [OperationsSnapshotQueries.cpp](../Src/Prism/Application/OperationsSnapshotQueries.cpp) 的账户快照仍只发布身份、Generation、标签、分组、撤销、根连接租约和累计流量，未发布 `AccountKey`、有效策略、子流或实时账户速率；当前管理投影也没有开放账户额度查询能力。因此 Live 页面不把 Demo 账本/策略/速率当作生产值，Live 模式保留明确的未提供状态。复核时对 `127.0.0.1:9090/Operations/Bootstrap` 发起无凭据只读 GET，连接被拒绝；页面继续使用用户指定的演示数据。

- `/accounts` 的范围统计成为一条分隔数据带；当前关联 Session 移到余额和速率之后，首屏显示五列记录：Session/协议、状态/Worker、任务/开始时间、来源/目标、累计上下行。完整连接表仍保留所有详细字段。
- `/protocols` 默认只显示生产实现有依据的协议类型数据：绑定数、活动 TCP Session、累计上下行与覆盖口径。生产实现没有协议实例目录或协议历史查询，Live 页不会凭可选 Web 字段显示假的实例/趋势标签。
- Session Trace 的 [`elapsed_ns`](../Src/Prism/Runtime/SessionTraceRing.cpp) 是从 TCP 接收到事件的相对偏移；`OperationsManagementQueries.cpp` 明确不填阶段持续时间。折叠行现在显示“自 TCP 接入”偏移，同时保留“耗时未提供”；展开内容显示事件序号与有值时的父任务 ID，没有把偏移误作耗时。
- 事件窗口来自运行时有界 `EventRing`；操作状态由仍留在该事件环内的 operation ID 聚合，继续明确保留窗口范围，不包装成永久审计历史。

整体视觉把导航轨、白色数据工作区和浅灰紫画布分开，指标保留为一条分隔数据带，主要表格/图表恢复明确的面板边界。全部 11 个桌面路由均在 1440×900 实际截图并检查页面错误、控制台错误与请求失败，三项均为空。最终截图保存在 `build/WebQa/CurrentReview/redesign-v8-*-1440.png`；重点截图：[账户与首屏关联连接](../build/WebQa/CurrentReview/redesign-v8-accounts-1440.png)、[Session 阶段偏移与耗时状态](../build/WebQa/CurrentReview/redesign-v8-sessions-1440.png)、[协议类型运行表](../build/WebQa/CurrentReview/redesign-v8-protocols-1440.png)。

最终验证：`npm run check` 通过，`npm test` 100/100，`npm run check:palette` 4/4；全量 `edge-1440` 与 `edge-390` E2E 为 182 通过、4 个按视口条件跳过、0 失败；另有一轮 48/48 浅/深主题无障碍检查通过。未运行生产构建；没有 Prism 在 9090 端口提供真实 Operations 数据，截图均为 `source=demo`，开发预览由本轮启动并保持在 5174。

### 2026-10-24 高对比控制台重构

用户指出前一轮仍像原来的通用后台。这轮直接改变可见骨架：所有路由切换成午夜蓝导航轨、选中项使用蓝紫状态色；概览、账户、入口、Worker、事件和操作页的跨页摘要统一成为深色数据带，主分析面仍保持浅色，图表与明细不被整页暗背景吞没。深色导航文字和数据带状态色有独立 Palette token，并在 Palette 测试中分别校验对比度。

这轮在 1440×900 重新打开并截图全部 11 个路由；`redesign-v10-<page>-1440.png` 为当前统一截图。实际检查 Overview 流量单位、账户 Session 列和深色指标带，浏览器脚本错误、控制台错误、失败请求均为 0。`127.0.0.1:9090/Operations/Bootstrap` 当前仍连接被拒绝，页面继续使用 `source=demo`，没有把演示数值写成实时状态。

回归结果：类型检查通过，单测 100/100，Palette 对比度检查 4/4；edge-1440 与 edge-390 全量浏览器套件为 182 通过、4 个按视口条件跳过、0 失败。未执行生产构建。Vite 开发预览保持在 [127.0.0.1:5174](http://127.0.0.1:5174/accounts?source=demo)。

### 2026-10-24 浅色版回正

用户明确不接受默认黑色导航与暗色指标带后，已将默认主题恢复为浅色。导航轨改为浅灰紫，选中项使用更清楚的淡紫焦点；运行指标带使用浅紫表面和深色读数，分析表格、图表与白色工作面保持浅色。深色主题仍只是页面手动切换选项，不作为默认预览。

重新截图全部 11 个路由到 `build/WebQa/CurrentReview/redesign-v12-*-1440.png`；逐页检查没有页面错误、控制台错误或失败请求。重新验收后 `npm run check` 通过、`npm test` 100/100、`npm run check:palette` 4/4；`edge-1440` 与 `edge-390` 全量 E2E 为 182 通过、4 个按视口预期跳过、0 失败。没有运行生产构建；本地预览继续用演示数据。
