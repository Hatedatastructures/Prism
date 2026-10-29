import { expect, test, type Page } from '@playwright/test';

const Timestamp = '2026-10-17T00:00:00.000Z';
const TrafficZero = { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' };

test('入口与协议历史保留选择身份和时间范围', async ({ page }) => {
    await page.goto('/ingresses?source=demo&range=1h');
    const Entry = page.getByRole('button', { name: /tcp-main/ });
    await Entry.click();
    const EntryDetails = page.getByRole('region', { name: 'tcp-main 入口详情', exact: true });
    await expect(EntryDetails).toBeVisible();
    await expect(EntryDetails.getByText('TCP 上下行速率', { exact: true })).toBeVisible();
    await expect(EntryDetails.getByText('识别准入延迟', { exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('ingress')).toBe('tcp-main');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    await Entry.click();
    expect(new URL(page.url()).searchParams.has('ingress')).toBe(false);
    expect(new URL(page.url()).searchParams.get('source')).toBe('demo');

    await page.goto('/protocols?source=demo&range=1h');
    const ProtocolTable = page.getByRole('table', { name: '协议类型运行明细表', exact: true });
    await ProtocolTable.getByRole('row').filter({ hasText: 'VLESS' }).getByRole('button').click();
    const ProtocolDetails = page.getByRole('region', { name: 'VLESS 协议详情', exact: true });
    await expect(ProtocolDetails.getByText('VLESS 上下行速率', { exact: true })).toBeVisible();
    await expect(ProtocolDetails.getByText('VLESS 识别准入延迟', { exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('protocol')).toBe('vless');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    await page.reload();
    await expect(page.getByRole('region', { name: 'VLESS 协议详情', exact: true })).toBeVisible();
});

test('用户组活动范围限于已载入关系，Session 深链按完整身份核验', async ({ page }) => {
    await page.goto('/user-groups?source=demo&group=group-core&mobile_view=detail');
    const GroupInspector = page.getByRole('region', { name: '用户组详情', exact: true });
    await GroupInspector.getByRole('tab', { name: '活动范围', exact: true }).click();
    await expect(GroupInspector).toContainText('历史期间的组归属不由当前接口追溯');
    await GroupInspector.getByRole('tab', { name: /成员/ }).click();
    await expect(GroupInspector.getByRole('table')).toContainText('northstar');
    await page.goto('/sessions?source=demo&session=session-1001&process=PRISM-DEMO-01&identity_worker=worker-01&identity_account=acct-northstar&generation=42');
    const SessionDetails = page.getByRole('region', { name: 'Session session-1001 详情', exact: true });
    await expect(SessionDetails).toContainText('认证身份');
    await expect(SessionDetails).toContainText('northstar');
    await expect(SessionDetails).toContainText('acct-northstar');
    await expect(SessionDetails).toContainText('worker-01');
    await expect(SessionDetails).toContainText('Generation 42');
});

test('配置长文档可滚动，编辑会显示准确差异', async ({ page }) => {
    await page.goto('/configuration?source=demo');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toContainText('WorkerCount');
    await Editor.focus();
    await page.keyboard.press('Control+End');
    await expect.poll(async () => Editor.evaluate(Element => (Element as HTMLTextAreaElement).scrollTop)).toBeGreaterThan(0);
    await Editor.fill((await Editor.inputValue()).replace('"WorkerCount": 4', '"WorkerCount": 5'));
    const Difference = page.getByRole('table').getByRole('row').filter({ hasText: 'Runtime' });
    await expect(Difference).toContainText('"WorkerCount": 4');
    await expect(Difference).toContainText('"WorkerCount": 5');
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
});

test('低计数任务趋势使用不重复的整数刻度', async ({ page }) => {
    await page.goto('/workers?source=demo');
    const WorkerDirectory = page.getByRole('region', { name: 'Worker 清单', exact: true });
    const WorkerTable = WorkerDirectory.getByRole('table', { name: 'Worker 列表', exact: true });
    if ((page.viewportSize()?.width ?? 0) <= 767) await WorkerTable.getByRole('row').nth(1).click();
    const WorkerDetail = page.getByRole('region', { name: 'Worker 详情', exact: true });
    await WorkerDetail.getByRole('tab', { name: '连接与账户', exact: true }).click();
    const WorkerChart = page.getByRole('group', { name: /演示模拟的 Worker 活动连接与唯一账户趋势/ });
    const Labels = WorkerChart.locator('.time-series-chart__axis > text[text-anchor="end"]');
    await expect(Labels.nth(0)).toHaveText('0');
    await expect(Labels.nth(1)).toHaveText('1');
    await expect(Labels.nth(2)).toHaveText('2');
});

test('错误 JSON 不会显示为零差异且修复后恢复比较', async ({ page }) => {
    await page.goto('/configuration?source=demo');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    const Original = await Editor.inputValue();
    await Editor.fill('{ invalid');
    await expect(page.getByRole('alert').filter({ hasText: 'JSON 格式错误' })).toBeVisible();
    await expect(page.getByText('修正 JSON 后查看差异', { exact: true })).toBeVisible();
    await expect(page.getByText('草稿格式有误；校验与应用已暂停。', { exact: true })).toBeVisible();
    await expect(page.getByText(/暂无字段差异/)).toHaveCount(0);
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await Editor.fill(Original);
    await expect(page.getByText('与运行配置一致', { exact: true })).toBeVisible();
    await expect(page.getByText(/暂无字段差异/)).toBeVisible();
});

test('清除入口定位只移除定位参数并保留演示与时间范围', async ({ page }) => {
    await page.goto('/ingresses?source=demo&range=1h&ingress=tcp-main&transport=tcp');
    const Selected = page.getByRole('button', { name: /tcp-main/ });
    await expect(Selected).toBeVisible();
    await Selected.click();

    const CurrentUrl = new URL(page.url());
    expect(CurrentUrl.searchParams.get('ingress')).toBeNull();
    expect(CurrentUrl.searchParams.get('transport')).toBeNull();
    expect(CurrentUrl.searchParams.get('source')).toBe('demo');
    expect(CurrentUrl.searchParams.get('range')).toBe('1h');
});

test('入口身份、承载与协议集中在单一记录，不重复展示能力卡片', async ({ page }) => {
    await page.goto('/ingresses?source=demo');
    const Width = page.viewportSize()?.width ?? 0;
    await expect(page.getByRole('heading', { name: '配置覆盖', exact: true })).toHaveCount(0);
    const IngressTable = page.getByRole('table');
    await expect(IngressTable.getByRole('columnheader', { name: '传输 / 入口 ID', exact: true })).toBeVisible();
    await expect(IngressTable.getByRole('columnheader', { name: '承载方式', exact: true })).toBeVisible();
    const FirstIngress = IngressTable.getByRole('row').filter({ hasText: 'tcp-main' });
    await expect(FirstIngress).toContainText('TCP');
    await expect(FirstIngress).toContainText('tcp-main');
    const PageWidth = await page.locator('body').evaluate(Element => Element.scrollWidth);
    expect(PageWidth).toBeLessThanOrEqual(Width);
    await page.screenshot({ path: `../build/WebQa/ingresses-${Width}.png`, fullPage: true });
});

test('概览按工作目标分组，并从运行状态开始', async ({ page }) => {
    await page.goto('/?source=demo');

    await expect(page.getByRole('heading', { name: '运行概览', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: '运行趋势', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '连接活动', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worker 运行面', exact: true })).toHaveCount(0);
    const IngressAndScheduling = page.getByRole('region', { name: '入口和调度', exact: true });
    await expect(IngressAndScheduling.getByRole('heading', { name: '监听端口', exact: true })).toBeVisible();
    await expect(IngressAndScheduling.getByRole('heading', { name: 'Worker 调度', exact: true })).toBeVisible();
    const AccountsAndProtocols = page.getByRole('region', { name: '账户和协议', exact: true });
    await expect(AccountsAndProtocols.getByRole('heading', { name: '账户使用', exact: true })).toBeVisible();
    await expect(AccountsAndProtocols.getByRole('heading', { name: '协议使用', exact: true })).toBeVisible();
});

test('实时 Session 可暂停列表轮询并说明活动快照的游标范围', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?source=live');

    await expect(page.getByText('当前接口按 ID 从早到晚分页；已结束的短连接不在活动清单中，较新的活动连接需继续载入。')).toBeVisible();
    await page.screenshot({ path: `../build/WebQa/sessions-live-${page.viewportSize()?.width ?? 0}.png`, fullPage: true });
    const Pause = page.getByRole('button', { name: '暂停刷新', exact: true });
    await expect(Pause).toHaveAttribute('aria-pressed', 'false');
    await Pause.click();
    await expect(page.getByRole('button', { name: '继续刷新', exact: true })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('alert')).toContainText('自动刷新已暂停');
    expect(Mock.Unexpected).toEqual([]);
    expect(Mock.Mutations).toEqual([]);
});

test('实时资源页不请求未开放的历史接口', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/resources?source=live');
    await expect(page.getByText('实时资源采样', { exact: true })).toBeVisible();
    await expect(page.getByText('本页已采集 1 个快照；断线不连接曲线。', { exact: true })).toBeVisible();
    await expect(page.getByText('此实例未开放窗口历史')).toHaveCount(0);
    await expect(page.getByRole('combobox', { name: '分析时间范围', exact: true })).toHaveCount(0);
    await expect(page.locator('.resource-snapshot-meta')).toContainText(/采样间隔\s*5,000 ms/);
    await expect(page.getByText('BytePool 容量', { exact: true }).locator('xpath=../..'))
        .toContainText('分配 / 释放');
    await page.screenshot({ path: '../build/WebQa/resources-live-unsupported.png', fullPage: true });
    expect(Mock.Unexpected).toEqual([]);
});

test('Worker 分配口径在区块内统一说明，不重复占用每一行', async ({ page }) => {
    await page.goto('/resources?source=demo');
    const WorkerRegion = page.getByRole('region', { name: 'Worker 受追踪分配表', exact: true });
    const WorkerTable = WorkerRegion.getByRole('table', { name: 'Worker 受追踪分配表', exact: true });
    await expect(WorkerTable.locator('thead th')).toHaveText(['Worker', '当前请求量', '峰值请求量', '成功分配次数', '释放次数', '统计范围']);
    await expect(WorkerRegion.getByRole('button', { name: '统计范围', exact: true })).toHaveCount(0);
    const RowScope = WorkerTable.locator('tbody tr').first().getByText('范围', { exact: true });
    await RowScope.click();
    await expect(WorkerTable.locator('tbody tr').first()).toContainText('仅计通过 WorkerResources TrackingResource');
    const ProcessScope = page.getByText('Process PMR 调用与统计范围', { exact: true });
    await ProcessScope.click();
    await expect(ProcessScope.locator('xpath=..')).toContainText('峰值');
});

test('桌面 Worker 清单与选中详情保持身份对应', async ({ page }, TestInfo) => {
    const Width = page.viewportSize()?.width ?? 0;
    test.skip(Width <= 1180, '桌面主从布局只在桌面断点验收。');
    await page.goto('/workers?source=demo');

    const Directory = page.getByRole('region', { name: 'Worker 清单', exact: true });
    const Inspector = page.getByRole('region', { name: 'Worker 详情', exact: true });
    await expect(Directory).toBeVisible();
    await expect(Inspector).toBeVisible();
    const WorkerTable = Directory.getByRole('table', { name: 'Worker 列表', exact: true });
    await expect(WorkerTable.locator('tbody tr')).toHaveCount(4);
    await expect(Inspector.getByRole('heading', { name: 'worker-01', exact: true })).toBeVisible();

    const DirectoryBounds = await Directory.boundingBox();
    const InspectorBounds = await Inspector.boundingBox();
    expect(DirectoryBounds).not.toBeNull();
    expect(InspectorBounds).not.toBeNull();
    expect(DirectoryBounds!.width).toBeGreaterThanOrEqual(300);
    expect(InspectorBounds!.width).toBeGreaterThanOrEqual(300);
    expect(DirectoryBounds!.x + DirectoryBounds!.width).toBeLessThanOrEqual(Width + 1);
    expect(InspectorBounds!.x + InspectorBounds!.width).toBeLessThanOrEqual(Width + 1);

    await page.screenshot({ path: TestInfo.outputPath(`worker-workspace-${Width}.png`), fullPage: true, animations: 'disabled' });
    await WorkerTable.getByRole('row').filter({ hasText: 'worker-02' }).click();
    await expect(page.getByRole('heading', { name: 'worker-02', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('worker')).toBe('worker-02');
});

test('Session 阶段按紧凑可展开行呈现，身份和真实证据仍可核对', async ({ page }, TestInfo) => {
    test.skip((page.viewportSize()?.width ?? 0) <= 767, 'Session 时间线只在桌面详情视图中展示。');
    await page.goto('/sessions?source=demo');
    const SessionTable = page.getByRole('table', { name: 'Session 列表', exact: true });
    await SessionTable.getByRole('row').nth(1).getByRole('button').click();
    const Inspector = page.getByRole('region', { name: /^Session .* 详情$/ });
    await Inspector.getByRole('tab', { name: /阶段/ }).click();
    const TraceTable = Inspector.getByRole('table');
    await expect(TraceTable.locator('tbody tr')).toHaveCount(6);
    await expect(TraceTable.locator('tbody tr').first()).toContainText('入口接收');
    await expect(TraceTable.getByRole('columnheader', { name: '阶段 / Span', exact: true })).toBeVisible();
    await expect(TraceTable.getByRole('columnheader', { name: '关联资源', exact: true })).toBeVisible();
    await page.screenshot({ path: TestInfo.outputPath('session-trace-compact.png'), fullPage: true, animations: 'disabled' });
});

test('全局资源搜索先核对能力，不向未开放的接口发送请求', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?source=live');
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('dialog', { name: '搜索资源' })).toBeVisible();
    await page.getByRole('combobox', { name: '资源搜索关键字' }).fill('northstar');
    await expect(page.getByText('服务端未开放全局搜索；请尝试页面名称。', { exact: true })).toBeVisible();
    await expect(page.getByText('当前实例未开放全局资源搜索；仍可搜索页面', { exact: true })).toBeVisible();
    expect(Mock.Unexpected).toEqual([]);
});

test('协议类型运行表同时显示绑定、活动数、累计流量与覆盖范围', async ({ page }, TestInfo) => {
    await page.goto('/protocols?source=demo');
    await expect(page.getByText('协议与配置', { exact: true })).toBeVisible();
    const TypeTable = page.getByRole('region', { name: '协议类型运行明细表，可横向滚动查看覆盖范围', exact: true });
    await expect(TypeTable.locator('tbody tr')).toHaveCount(4);
    await expect(TypeTable).toContainText('绑定数');
    await expect(TypeTable).toContainText('活动 Session');
    await expect(TypeTable).toContainText('累计上行');
    await expect(TypeTable).toContainText('统计覆盖');
    await expect(TypeTable).toContainText('按已接受 TCP Session 归属');
    await expect(page.getByRole('tab', { name: /配置实例/ })).toHaveCount(0);
    await page.screenshot({ path: TestInfo.outputPath('protocol-overview-desktop.png'), animations: 'disabled' });
    const PreviewSearch = page.getByRole('textbox', { name: '搜索协议', exact: true });
    await PreviewSearch.fill('VLESS');
    await expect(TypeTable.locator('tbody tr')).toHaveCount(1);
    await expect(TypeTable.locator('tbody tr')).toContainText('VLESS');
    expect(new URL(page.url()).searchParams.get('protocol_q')).toBe('VLESS');
    await PreviewSearch.fill('没有这个协议');
    await expect(page.getByText('当前范围没有协议', { exact: true })).toBeVisible();
    await PreviewSearch.fill('');
    await expect(PreviewSearch).toBeFocused();
    await expect(TypeTable.locator('tbody tr')).toHaveCount(4);
    await TypeTable.getByRole('row').filter({ hasText: 'VLESS' }).getByRole('button').click();
    const VlessDetails = page.getByRole('region', { name: 'VLESS 协议详情', exact: true });
    await expect(VlessDetails.getByText('VLESS 上下行速率', { exact: true })).toBeVisible();
    await expect(VlessDetails.getByText('VLESS 识别准入延迟', { exact: true })).toBeVisible();
});

test('手机端事件、Worker、资源和协议使用完整记录组件', async ({ page }) => {
    test.skip((page.viewportSize()?.width ?? 0) > 767, '记录卡片只替代窄屏下的横向数据表。');
    await page.goto('/events?source=demo');
    const EventTable = page.getByRole('table');
    await expect(EventTable).toBeVisible();
    await expect(EventTable.locator('tbody tr')).toHaveCount(5);
    const EventDetails = EventTable.getByRole('button', { name: '详情', exact: true }).first();
    await EventDetails.click();
    const ExpandedEvent = EventTable.getByRole('button', { name: '收起', exact: true }).first();
    await expect(ExpandedEvent).toHaveAttribute('aria-expanded', 'true');
    await expect(EventTable).toContainText('类型 / 范围');

    await page.goto('/workers?source=demo');
    const WorkerDirectory = page.getByRole('region', { name: 'Worker 清单', exact: true });
    await expect(WorkerDirectory.getByRole('table', { name: 'Worker 列表', exact: true }).locator('tbody tr')).toHaveCount(4);
    await expect(page.getByRole('region', { name: 'Worker 详情', exact: true })).toBeHidden();

    await page.goto('/resources?source=demo');
    const ResourceWorkers = page.getByRole('region', { name: 'Worker 受追踪分配表', exact: true });
    await expect(ResourceWorkers).toBeVisible();
    await expect(ResourceWorkers.getByRole('table', { name: 'Worker 受追踪分配表', exact: true })).toBeVisible();
    const ResourcePageWidth = await page.locator('body').evaluate(Element => Element.scrollWidth);
    expect(ResourcePageWidth).toBeLessThanOrEqual(page.viewportSize()?.width ?? 0);
    await expect(page.locator('.detail-kv dt', { hasText: '进程工作集' })).toHaveCount(0);

    await page.goto('/protocols?source=demo');
    const ProtocolTable = page.getByRole('region', { name: '协议类型运行明细表，可横向滚动查看覆盖范围', exact: true });
    await expect(ProtocolTable).toBeVisible();
    await expect(ProtocolTable.locator('tbody tr')).toHaveCount(4);
    const ProtocolPageWidth = await page.locator('body').evaluate(Element => Element.scrollWidth);
    expect(ProtocolPageWidth).toBeLessThanOrEqual(page.viewportSize()?.width ?? 0);
});

test('手机端主从页面切换视图时保留当前对象与列表筛选', async ({ page }) => {
    test.skip((page.viewportSize()?.width ?? 0) > 767, '主从视图切换只在窄屏下替代并排布局。');

    await page.goto('/accounts?source=demo&q=northstar');
    const AccountDirectory = page.getByRole('region', { name: '账户目录', exact: true });
    const AccountInspector = page.getByRole('region', { name: '账户详情', exact: true });
    await expect(AccountInspector).toBeHidden();
    await page.getByRole('list', { name: '账户列表', exact: true }).getByRole('listitem').first().getByRole('button').click();
    await expect(AccountInspector).toBeVisible();
    await expect(AccountDirectory).toBeHidden();
    await expect(page.getByRole('button', { name: '返回账户目录', exact: true })).toBeFocused();
    await page.getByRole('button', { name: '返回账户目录' }).click();
    await expect(AccountDirectory).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('q')).toBe('northstar');
    expect(new URL(page.url()).searchParams.get('account')).toBeTruthy();

    await page.goto('/sessions?source=demo');
    const SessionDirectory = page.getByRole('region', { name: 'Session 连接列表', exact: true });
    const SessionInspector = page.getByRole('region', { name: /^Session .* 详情$/ });
    await expect(SessionInspector).toBeHidden();
    await SessionDirectory.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').first().click();
    await expect(SessionInspector).toBeVisible();
    await expect(page.getByRole('button', { name: '返回连接列表', exact: true })).toBeFocused();
    await expect(SessionDirectory).toBeHidden();
    await expect(SessionDirectory.getByRole('searchbox', { name: '搜索 Session', exact: true })).toBeHidden();
    const SessionId = new URL(page.url()).searchParams.get('session');
    await page.getByRole('button', { name: '返回连接列表' }).click();
    await expect(SessionDirectory).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('session')).toBe(SessionId);

    await page.goto('/user-groups?source=demo');
    const GroupDirectory = page.getByRole('region', { name: '用户组目录', exact: true });
    const GroupInspector = page.getByRole('region', { name: '用户组详情', exact: true });
    await expect(GroupInspector).toBeHidden();
    await GroupDirectory.getByRole('list', { name: '用户组列表', exact: true }).getByRole('listitem').first().getByRole('button').click();
    await expect(GroupInspector).toBeVisible();
    await expect(GroupDirectory).toBeHidden();
    await expect(page.getByRole('button', { name: '返回分组目录', exact: true })).toBeFocused();
    const GroupId = new URL(page.url()).searchParams.get('group');
    await page.getByRole('button', { name: '返回分组目录' }).click();
    await expect(GroupDirectory).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('group')).toBe(GroupId);

    await page.goto('/workers?source=demo');
    const WorkerDirectory = page.getByRole('region', { name: 'Worker 清单', exact: true });
    const WorkerDetail = page.getByRole('region', { name: 'Worker 详情', exact: true });
    await expect(WorkerDetail).toBeHidden();
    await WorkerDirectory.getByRole('table', { name: 'Worker 列表', exact: true }).locator('tbody tr').first().click();
    await expect(WorkerDetail).toBeVisible();
    await expect(WorkerDirectory).toBeHidden();
    await expect(page.getByRole('button', { name: '返回 Worker 列表', exact: true })).toBeFocused();
    const WorkerId = new URL(page.url()).searchParams.get('worker');
    await page.getByRole('button', { name: '返回 Worker 列表' }).click();
    await expect(WorkerDirectory).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('worker')).toBe(WorkerId);

    await page.goto('/operations?source=demo');
    const Operations = page.getByText('近期操作', { exact: true });
    await expect(Operations.last()).toBeVisible();
    const OperationTable = page.getByRole('table');
    const OperationButton = OperationTable.getByRole('button').first();
    const OperationName = (await OperationButton.innerText()).split('\n')[0];
    await OperationButton.click();
    expect(new URL(page.url()).searchParams.get('operation')).toBeTruthy();
    await expect(page.getByText(OperationName, { exact: true })).toBeVisible();
    await expect(page.getByRole('tab', { name: '结果', exact: true })).toBeVisible();
    await expect(page.getByRole('tab', { name: '作用范围', exact: true })).toBeVisible();
});

test('Session 详情在列表缺页、刷新失败与空搜索时保持可见', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?source=live&session=55&process=42&identity_worker=7&identity_account=8&generation=6');

    const Width = page.viewportSize()?.width ?? 0;
    const Inspector = page.getByRole('region', { name: /^Session .* 详情$/ });
    await expect(Inspector.getByRole('heading', { level: 2 })).toHaveText('55');
    await expect(Inspector.getByRole('note')).toContainText('不在当前列表结果中');
    if (Width <= 767) await page.getByRole('button', { name: '返回连接列表', exact: true }).click();

    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').first().getByRole('button')).toHaveText(['56']);

    Mock.SetListUnavailable(true);
    await page.getByRole('button', { name: '刷新列表', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: '当前仍显示上次成功读取的数据' })).toBeVisible();
    const RetrySessions = page.getByRole('button', { name: '重试读取', exact: true });
    await expect(RetrySessions).toBeVisible();
    const Directory = page.getByRole('region', { name: 'Session 连接列表', exact: true });
    await expect(Directory.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').first().getByRole('button')).toHaveText(['56']);

    if (Width > 900) {
        await expect(Inspector.getByRole('heading', { level: 2 })).toHaveText('55');
        const DirectoryBounds = await Directory.boundingBox();
        const InspectorBounds = await Inspector.boundingBox();
        expect(DirectoryBounds).not.toBeNull();
        expect(InspectorBounds).not.toBeNull();
        expect(DirectoryBounds!.x).toBeLessThan(InspectorBounds!.x);
        expect(DirectoryBounds!.x + DirectoryBounds!.width).toBeLessThanOrEqual(InspectorBounds!.x + 1);
        expect(Math.abs(DirectoryBounds!.y - InspectorBounds!.y)).toBeLessThanOrEqual(1);
        expect(InspectorBounds!.x + InspectorBounds!.width).toBeLessThanOrEqual(Width + 1);
    } else {
        const HorizontalOverflow = await page.evaluate(() =>
            document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(HorizontalOverflow).toBeLessThanOrEqual(1);
    }

    Mock.SetListUnavailable(false);
    await RetrySessions.click();
    await expect(page.getByRole('alert').filter({ hasText: '当前仍显示上次成功读取的数据' })).toHaveCount(0);
    await expect(Directory.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').first().getByRole('button')).toHaveText(['56']);
    const FilteredUrl = new URL(page.url());
    FilteredUrl.searchParams.set('q', 'no-session-matches-this');
    await page.goto(FilteredUrl.pathname + FilteredUrl.search);

    await expect(Inspector.getByRole('heading', { level: 2 })).toHaveText('55');
    await expect(Inspector.getByRole('note')).toContainText('不在当前列表结果中');
    if (Width <= 767) {
        await page.getByRole('button', { name: '返回连接列表' }).click();
        await expect(page.getByText('当前范围没有 Session', { exact: true })).toBeVisible();
        await expect(Inspector).toBeHidden();
    } else {
        await expect(page.getByText('当前范围没有 Session', { exact: true })).toBeVisible();
    }
    expect(Mock.Unexpected).toEqual([]);
    expect(Mock.Mutations).toEqual([]);
});

type SessionMockLog = Readonly<{
    Unexpected: string[]; Mutations: string[]; SetListUnavailable: (Value: boolean) => void;
}>;

async function InstallSessionOperationsMock(PageValue: Page): Promise<SessionMockLog> {
    const Log = { Unexpected: [] as string[], Mutations: [] as string[] };
    let ListUnavailable = false;
    await PageValue.route('**/Operations/**', async Route => {
        const Request = Route.request();
        const Url = new URL(Request.url());
        if (!Url.pathname.startsWith('/Operations/')) {
            await Route.continue();
            return;
        }
        if (Request.method() !== 'GET') {
            Log.Mutations.push(`${Request.method()} ${Url.pathname}`);
            await Route.fulfill({ status: 405, contentType: 'application/json', body: JSON.stringify({
                status: 'error', message: 'This test blocks management commands.',
            }) });
            return;
        }

        let Body: unknown;
        if (Url.pathname === '/Operations/Bootstrap') Body = BootstrapWire();
        else if (Url.pathname === '/Operations/Overview') Body = Ok(OverviewWire());
        else if (Url.pathname === '/Operations/Sessions') {
            const Id = Url.searchParams.get('id');
            if (!Id && ListUnavailable) {
                await Route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({
                    status: 'error', message: 'Fixture session list unavailable.',
                }) });
                return;
            }
            Body = Ok(PageWire([SessionWire(Id === '55' ? '55' : '56')]));
        } else if (Url.pathname === '/Operations/Events') Body = Ok(EventPageWire());
        else if (Url.pathname.endsWith('/Trace')) Body = Ok(TracePageWire());
        else if (Url.pathname.endsWith('/Streams') || Url.pathname.endsWith('/Tasks')) Body = Ok(PageWire([]));
        else {
            Log.Unexpected.push(`${Url.pathname}${Url.search}`);
            Body = { status: 'error', message: 'Unexpected Operations read in test fixture.' };
        }
        await Route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(Body) });
    });
    return { ...Log, SetListUnavailable: (Value: boolean): void => { ListUnavailable = Value; } };
}

function BootstrapWire(): unknown {
    return { api_version: '2', instance_key: 'page-refinements-instance', process_id: '42',
        process_incarnation: 'a'.repeat(32), command_token: 'c'.repeat(64),
        capabilities: ['events.filter.process', 'events.filter.generation'] };
}

function Ok(Value: unknown): unknown { return { status: 'ok', value: Value }; }

function PageWire(Items: readonly unknown[]): unknown {
    return { items: Items, next_cursor: '0', has_more: false };
}

function SessionWire(Id: string): unknown {
    return { id: Id, process: '42', worker: '7', account: '8', generation: '6', traffic: TrafficZero,
        started_at: Timestamp, transport: 'tcp', identity: `fixture-account-${Id}`, source_address: '192.0.2.10:48000',
        protocol: 'vless', target: '198.51.100.20:443', active: true, draining: false, active_tasks: '1' };
}

function EventPageWire(): unknown {
    return { ...PageWire([]), earliest_cursor: '0', lost: false, lost_ranges: [], dropped: '0',
        terminal_dropped: '0', overwritten: '0', severity_filter_supported: true };
}

function TracePageWire(): unknown {
    return { ...PageWire([]), lost: false, cursors: [], lost_ranges: [] };
}

function OverviewWire(): unknown {
    return {
        sampled_at: Timestamp, sample_interval_ms: '5000', process: { id: '42', generation: '6', phase: 'ready' },
        health: { status: 'healthy', checked_at: Timestamp, ready: true, tcp_ready: true, udp_ready: true,
            udp_socket_ready: true, quic_ready: false, quic_socket_ready: false, quic_handshake_ready: false,
            quic_protocol_ready: false, active: '0', errors: '0' },
        counts: { configured_accounts: '2', active_accounts: '1', ungrouped_accounts: '1', tcp_sessions: '1',
            udp_connections: null, quic_connections: null, workers_total: '1', workers_accepting: '1' },
        traffic: { available: true, up_bytes: '0', down_bytes: '0', events: '0', errors: '0',
            up_bytes_per_second: '0', down_bytes_per_second: '0' },
        latency: { recognition_admission: { name: 'recognition_admission', available: false, sample_count: '0',
            p50_ms: null, p95_ms: null, p99_ms: null, max_ms: null, worker_id: null, protocol: null }, stages: [] },
        memory: { process_available: false, process_rss_bytes: null, process_peak_rss_bytes: null, working_set_bytes: null,
            byte_pool: { available: false, used_bytes: null, capacity_bytes: null, available_blocks: null, block_size: null,
                peak_used_bytes: null, allocation_count: null, release_count: null },
            allocations: { available: false, current_bytes: null, peak_bytes: null, allocation_count: null,
                release_count: null, coverage: 'browser GET fixture' }, worker_allocations: [] },
        observations: { accepted: '0', consumed: '0', dropped: '0', aggregation_failures: '0' }, history: [], protocols: [],
    };
}
