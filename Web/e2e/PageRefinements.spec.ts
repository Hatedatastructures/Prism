import { expect, test, type Page } from '@playwright/test';

const Timestamp = '2026-10-17T00:00:00.000Z';
const TrafficZero = { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' };

test('入口流量选择与协议趋势选择保留桌面工作区上下文', async ({ page }) => {
    await page.goto('/ingresses?source=demo&range=1h');
    const Entry = page.getByRole('button', { name: '查看 tcp-main 流量', exact: true }).filter({ visible: true });
    await Entry.click();
    await expect(Entry).toHaveAttribute('aria-pressed', 'true');
    await expect(page.getByRole('heading', { name: 'tcp-main 接入流量历史', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    await Entry.click();
    expect(new URL(page.url()).searchParams.has('ingress')).toBe(false);
    expect(new URL(page.url()).searchParams.get('source')).toBe('demo');

    await page.goto('/protocols?source=demo&range=1h');
    await page.getByRole('tab', { name: '流量趋势', exact: true }).click();
    await page.getByRole('combobox', { name: '选择趋势协议', exact: true }).click();
    await page.getByRole('option', { name: 'VLESS · vless', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'VLESS 类型流量', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'vless 实例流量', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('protocol_view')).toBe('trends');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    await page.reload();
    await expect(page.getByRole('combobox', { name: '选择趋势协议', exact: true })).toContainText('VLESS');
});

test('用户组趋势在所选组内查看，身份说明弹层关闭后恢复焦点', async ({ page }) => {
    await page.goto('/user-groups?source=demo&group=group-core&mobile_view=detail');
    await page.getByRole('tab', { name: '组趋势', exact: true }).click();
    await expect(page.getByRole('heading', { name: '核心线路 · group-core 流量历史', exact: true })).toBeVisible();
    await page.getByRole('tab', { name: '概览 / 成员', exact: true }).click();
    await expect(page.locator('.group-member')).toContainText('northstar');
    await page.goto('/sessions?source=demo&session=session-1001&process=PRISM-DEMO-01&identity_worker=worker-01&identity_account=acct-northstar&generation=42');
    const Identity = page.getByRole('button', { name: '完整身份', exact: true });
    await Identity.click();
    await expect(page.getByRole('dialog', { name: '完整身份', exact: true })).toContainText('acct-northstar');
    await page.keyboard.press('Escape');
    await expect(Identity).toBeFocused();
    await expect(page.getByRole('dialog', { name: '完整身份', exact: true })).toHaveCount(0);
});

test('配置长文档行号跟随滚动，编辑仍产生准确差异', async ({ page }) => {
    await page.goto('/configuration?source=demo');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toContainText('WorkerCount');
    await Editor.focus();
    await page.keyboard.press('Control+End');
    await expect.poll(async () => Editor.evaluate(Element => (Element as HTMLTextAreaElement).scrollTop)).toBeGreaterThan(0);
    await expect.poll(async () => page.locator('.configuration-code-body').evaluate(Element => Math.abs(
        Element.querySelector('textarea')!.scrollTop - Element.querySelector('.configuration-line-numbers')!.scrollTop))).toBeLessThanOrEqual(1);
    await Editor.fill((await Editor.inputValue()).replace('"WorkerCount": 4', '"WorkerCount": 5'));
    const Difference = page.locator('.configuration-change').filter({ hasText: 'Runtime' });
    await Difference.locator('summary').click();
    await expect(Difference.locator('pre').first()).toContainText('"WorkerCount": 4');
    await expect(Difference.locator('pre').last()).toContainText('"WorkerCount": 5');
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
});

test('低计数任务趋势使用不重复的整数刻度', async ({ page }) => {
    await page.goto('/workers?source=demo');
    if ((page.viewportSize()?.width ?? 0) <= 767) await page.locator('.worker-mobile-card .table-link').first().click();
    const Labels = page.locator('.history-plot-active .time-series-chart__axis > text[text-anchor="end"]');
    await expect(Labels.nth(0)).toHaveText('0');
    await expect(Labels.nth(1)).toHaveText('1');
    await expect(Labels.nth(2)).toHaveText('2');
});

test('错误 JSON 不会显示为零差异且修复后恢复比较', async ({ page }) => {
    await page.goto('/configuration?source=demo');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    const Original = await Editor.inputValue();
    await Editor.fill('{ invalid');
    await expect(page.locator('.configuration-status-bar')).toContainText('JSON 格式错误');
    await expect(page.locator('.configuration-diff-panel')).toContainText('暂时无法比较差异');
    await expect(page.locator('.configuration-diff-panel')).not.toContainText('暂无字段差异');
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await Editor.fill(Original);
    await expect(page.locator('.configuration-status-bar')).toContainText('与快照一致');
    await expect(page.locator('.configuration-diff-panel')).toContainText('暂无字段差异');
});

test('清除入口定位只移除定位参数并保留演示与时间范围', async ({ page }) => {
    await page.goto('/ingresses?source=demo&range=1h&ingress=ingress-tcp&transport=tcp');
    await expect(page.getByRole('button', { name: '清除定位', exact: true })).toBeVisible();

    await page.getByRole('button', { name: '清除定位', exact: true }).click();

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
    if (Width > 767) {
        await expect(page.getByRole('columnheader', { name: '入口', exact: true })).toBeVisible();
        await expect(page.getByRole('columnheader', { name: '承载 / 协议', exact: true })).toBeVisible();
        await expect(page.locator('.ingress-table tbody tr').first().getByText('tcp-main', { exact: true })).toBeVisible();
    } else {
        const FirstIngress = page.locator('.ingress-mobile-list .ingress-mobile-card').first();
        await expect(FirstIngress.getByText('承载方式', { exact: true })).toBeVisible();
        await expect(FirstIngress.getByText('tcp-main', { exact: true })).toBeVisible();
    }
    await page.screenshot({ path: `../build/WebQa/ingresses-${Width}.png`, fullPage: true });
});

test('概览按工作目标分组，并从运行状态开始', async ({ page }) => {
    await page.goto('/?source=demo');

    await expect(page.getByRole('tab', { name: /实时运行/ })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: '网络流量', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '连接活动', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worker 运行面', exact: true })).toHaveCount(0);

    const EvidenceButton = page.getByRole('button', { name: '查看依据', exact: true });
    await EvidenceButton.click();
    const Evidence = page.getByRole('dialog', { name: '查看依据', exact: true });
    await expect(Evidence).toContainText('接入状态依据');
    await expect(Evidence).toContainText('诊断记录');
    await page.keyboard.press('Escape');
    await expect(Evidence).toHaveCount(0);
    await expect(EvidenceButton).toBeFocused();

    await page.getByRole('tab', { name: /代理资源/ }).click();
    await expect(page.getByRole('heading', { name: 'Worker 运行面', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '协议分布', exact: true })).toBeVisible();

    await page.getByRole('tab', { name: /诊断记录/ }).click();
    await expect(page.getByRole('heading', { name: '事件首批样本', exact: true })).toBeVisible();
    await expect(page.getByText('事件游标从较早序号开始；此处不代表最新事件')).toBeVisible();
    await expect(page.getByRole('heading', { name: '观测质量', exact: true })).toBeVisible();
});

test('实时 Session 可暂停列表轮询并说明活动快照的游标范围', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?source=live');

    await expect(page.getByText('当前接口按 ID 从早到晚分页；已结束的短连接不在活动清单中，较新的活动连接需继续载入。')).toBeVisible();
    await page.screenshot({ path: `../build/WebQa/sessions-live-${page.viewportSize()?.width ?? 0}.png`, fullPage: true });
    await expect(page.getByRole('button', { name: '暂停列表更新' })).toHaveAttribute('aria-pressed', 'false');
    await page.getByRole('button', { name: '暂停列表更新' }).click();
    await expect(page.getByRole('button', { name: '恢复自动更新' })).toHaveAttribute('aria-pressed', 'true');
    await expect(page.locator('.session-refresh-status')).toContainText('自动刷新已暂停');
    expect(Mock.Unexpected).toEqual([]);
    expect(Mock.Mutations).toEqual([]);
});

test('实时资源页不请求未开放的历史接口', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/resources?source=live');
    await expect(page.getByText('当前接口未提供 RSS、PMR 或 BytePool 的历史采样；页面只展示本次快照、峰值和累计计数。', { exact: true })).toBeVisible();
    await expect(page.getByText('此实例未开放窗口历史')).toHaveCount(0);
    await expect(page.getByRole('combobox', { name: '分析时间范围', exact: true })).toHaveCount(0);
    await expect(page.locator('.resource-snapshot-meta')).toContainText(/采样间隔\s*5,000 ms/);
    await expect(page.locator('.resource-quality-section').first()).toContainText('BytePool 分配 / 释放');
    await page.screenshot({ path: '../build/WebQa/resources-live-unsupported.png', fullPage: true });
    expect(Mock.Unexpected).toEqual([]);
});

test('Worker 分配口径在区块内统一说明，不重复占用每一行', async ({ page }) => {
    await page.goto('/resources?source=demo');
    await expect(page.locator('.resource-worker-table thead th')).toHaveText(['Worker', '当前', '峰值', '分配次数', '释放次数']);
    const Scope = page.getByRole('button', { name: '统计范围', exact: true });
    await expect(Scope).toHaveCount(1);
    await Scope.click();
    await expect(page.getByRole('dialog', { name: '统计范围', exact: true }))
        .toContainText('仅计通过 WorkerResources TrackingResource');
});

test('桌面 Worker 工作区并列显示目录与详情，对比表独立切换', async ({ page }, TestInfo) => {
    const Width = page.viewportSize()?.width ?? 0;
    test.skip(Width <= 1180, '桌面主从布局只在桌面断点验收。');
    await page.goto('/workers?source=demo');

    const Workspace = page.locator('.worker-desktop-workspace');
    const Directory = page.locator('.worker-list-responsive');
    const Inspector = page.locator('.worker-detail-responsive');
    await expect(page.getByRole('tab', { name: '工作区', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(Directory).toBeVisible();
    await expect(Inspector).toBeVisible();
    await expect(Directory.locator('.worker-directory-card')).toHaveCount(4);
    await expect(page.locator('.worker-mobile-list')).toBeHidden();
    await expect(Inspector.locator('.worker-inspector')).toContainText('worker-01');

    const DirectoryBounds = await Directory.boundingBox();
    const InspectorBounds = await Inspector.boundingBox();
    expect(DirectoryBounds).not.toBeNull();
    expect(InspectorBounds).not.toBeNull();
    expect(DirectoryBounds!.x).toBeLessThan(InspectorBounds!.x);
    expect(Math.abs(DirectoryBounds!.y - InspectorBounds!.y)).toBeLessThanOrEqual(1);
    expect(DirectoryBounds!.width).toBeGreaterThanOrEqual(300);
    expect(InspectorBounds!.width).toBeGreaterThan(DirectoryBounds!.width);
    const ChartColumns = await Inspector.locator('.analysis-split').evaluate(Element =>
        getComputedStyle(Element).gridTemplateColumns.trim().split(/\s+/).length);
    expect(ChartColumns).toBe(Width <= 1320 ? 1 : 2);

    await page.screenshot({ path: TestInfo.outputPath(`worker-workspace-${Width}.png`), fullPage: true, animations: 'disabled' });
    await page.getByRole('tab', { name: '完整对比', exact: true }).click();
    await expect(page.locator('.worker-comparison-table-scroll')).toBeVisible();
    expect(new URL(page.url()).searchParams.get('worker_view')).toBe('compare');

    await page.locator('.worker-comparison-table tbody tr').nth(1).getByRole('button').click();
    await expect(page.getByRole('tab', { name: '工作区', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByRole('heading', { name: 'worker-02', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.has('worker_view')).toBe(false);

    await page.getByRole('tab', { name: '完整对比', exact: true }).click();
    await page.getByRole('tab', { name: '工作区', exact: true }).click();
    await expect(Directory).toBeVisible();
    await expect(Inspector).toBeVisible();
    await expect(page.getByRole('heading', { name: 'worker-02', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.has('worker_view')).toBe(false);
});

test('Session 阶段按紧凑可展开行呈现，身份和真实证据仍可核对', async ({ page }, TestInfo) => {
    test.skip((page.viewportSize()?.width ?? 0) <= 767, 'Session 时间线只在桌面详情视图中展示。');
    await page.goto('/sessions?source=demo');
    const Stages = page.locator('.trace-event');
    await expect(Stages).toHaveCount(6);
    await expect(Stages.first().locator('summary')).toBeVisible();
    await expect(Stages.first()).not.toHaveAttribute('open', '');
    await expect(Stages.first()).toContainText('入口接收');
    await expect(Stages.first().locator('.trace-event-offset')).toContainText('自 TCP 接入');
    await expect(Stages.first()).toContainText('耗时未提供');
    await page.screenshot({ path: TestInfo.outputPath('session-trace-compact.png'), fullPage: true, animations: 'disabled' });

    const FirstSummary = Stages.first().locator('summary');
    await FirstSummary.focus();
    await page.keyboard.press('Enter');
    await expect(Stages.first()).toHaveAttribute('open', '');
    await expect(Stages.first()).toContainText('Span');
    await expect(Stages.first()).toContainText('事件序号');
    await expect(Stages.first()).toContainText('Worker');
});

test('全局资源搜索先核对能力，不向未开放的接口发送请求', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?source=live');
    await page.keyboard.press('Control+k');
    await expect(page.getByRole('dialog', { name: '搜索资源' })).toBeVisible();
    await page.getByRole('combobox', { name: '资源搜索关键字' }).fill('northstar');
    await expect(page.getByText('此实例未开放全局资源搜索；可以尝试页面名称。', { exact: true })).toBeVisible();
    await expect(page.getByText('当前实例未开放全局资源搜索；可搜索页面名称', { exact: true })).toBeVisible();
    expect(Mock.Unexpected).toEqual([]);
});

test('协议类型运行表同时显示绑定、活动数、累计流量与覆盖范围', async ({ page }, TestInfo) => {
    await page.goto('/protocols?source=demo');
    await expect(page.getByRole('heading', { name: '协议类型运行明细', exact: true })).toBeVisible();
    const TypeTable = page.getByRole('region', { name: '协议类型运行明细表，可横向滚动查看覆盖范围', exact: true });
    await expect(TypeTable.locator('tbody tr')).toHaveCount(4);
    await expect(TypeTable).toContainText('配置绑定');
    await expect(TypeTable).toContainText('活动 TCP Session');
    await expect(TypeTable).toContainText('累计上行');
    await expect(TypeTable).toContainText('统计覆盖');
    await expect(TypeTable).toContainText('按已接受 TCP Session 归属');
    await expect(page.getByRole('tab', { name: /配置实例/ })).toHaveCount(0);
    await page.screenshot({ path: TestInfo.outputPath('protocol-overview-desktop.png'), animations: 'disabled' });
    const PreviewSearch = page.getByRole('searchbox', { name: '搜索协议类型' });
    await PreviewSearch.fill('VLESS');
    await expect(TypeTable.locator('tbody tr')).toHaveCount(1);
    await expect(TypeTable.locator('tbody tr')).toContainText('VLESS');
    expect(new URL(page.url()).searchParams.get('protocol_q')).toBe('VLESS');
    await PreviewSearch.fill('没有这个协议');
    await expect(page.getByText('当前已载入范围没有匹配的协议类型', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '清除搜索协议类型' }).click();
    await expect(PreviewSearch).toBeFocused();
    await expect(TypeTable.locator('tbody tr')).toHaveCount(4);
    await page.getByRole('tab', { name: '流量趋势' }).click();
    await expect(page.locator('.analysis-split')).toBeVisible();
    await expect(page.locator('.history-plot-traffic .time-series-chart__axis text')
        .filter({ hasText: /\/s$/ }).first()).toBeVisible();
});

test('手机端事件、Worker、资源和协议使用完整记录组件', async ({ page }) => {
    test.skip((page.viewportSize()?.width ?? 0) > 767, '记录卡片只替代窄屏下的横向数据表。');
    await page.goto('/events?source=demo');
    await expect(page.locator('.event-desktop-table')).toBeHidden();
    await expect(page.locator('.event-mobile-list')).toBeVisible();
    await expect(page.locator('.event-mobile-card')).toHaveCount(5);
    const EventDetails = page.locator('.event-mobile-detail-button').first();
    await EventDetails.click();
    await expect(EventDetails).toHaveAttribute('aria-expanded', 'true');

    await page.goto('/workers?source=demo');
    await expect(page.locator('.worker-comparison-table-scroll')).toBeHidden();
    await expect(page.locator('.worker-mobile-list')).toBeVisible();
    await expect(page.locator('.worker-mobile-card')).toHaveCount(4);

    await page.goto('/resources?source=demo');
    await expect(page.locator('.resource-worker-table')).toBeHidden();
    await expect(page.locator('.resource-worker-cards')).toBeVisible();
    await expect(page.locator('.resource-worker-card')).toHaveCount(4);
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
    await expect(page.locator('.account-layout[data-mobile-view="list"] .account-inspector')).toBeHidden();
    await page.locator('.account-directory-table tbody tr').first().getByRole('button').click();
    await expect(page.locator('.account-inspector')).toBeVisible();
    await expect(page.locator('.account-directory-column')).toBeHidden();
    await expect(page.locator('.mobile-master-back')).toBeFocused();
    await page.getByRole('button', { name: '返回账户目录' }).click();
    await expect(page.locator('.account-directory-column')).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('q')).toBe('northstar');
    expect(new URL(page.url()).searchParams.get('account')).toBeTruthy();

    await page.goto('/sessions?source=demo');
    await expect(page.locator('.session-inspector')).toBeHidden();
    await page.locator('.session-item').first().click();
    await expect(page.locator('.session-inspector')).toBeVisible();
    await expect(page.locator('.mobile-master-back')).toBeFocused();
    await expect(page.locator('.session-directory')).toBeHidden();
    await expect(page.locator('.session-list-controls')).toBeHidden();
    const SessionId = new URL(page.url()).searchParams.get('session');
    await page.getByRole('button', { name: '返回连接列表' }).click();
    await expect(page.locator('.session-directory')).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('session')).toBe(SessionId);

    await page.goto('/user-groups?source=demo');
    await expect(page.locator('.group-inspector')).toBeHidden();
    await page.locator('.group-select').first().click();
    await expect(page.locator('.group-inspector')).toBeVisible();
    await expect(page.locator('.group-directory-column')).toBeHidden();
    await expect(page.locator('.mobile-master-back')).toBeFocused();
    const GroupId = new URL(page.url()).searchParams.get('group');
    await page.getByRole('button', { name: '返回分组目录' }).click();
    await expect(page.locator('.group-directory-column')).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('group')).toBe(GroupId);

    await page.goto('/workers?source=demo');
    await expect(page.locator('.worker-detail-responsive')).toBeHidden();
    await page.locator('.worker-mobile-card .table-link').first().click();
    await expect(page.locator('.worker-detail-responsive')).toBeVisible();
    await expect(page.locator('.worker-list-responsive')).toBeHidden();
    await expect(page.locator('.mobile-master-back')).toBeFocused();
    const WorkerId = new URL(page.url()).searchParams.get('worker');
    await page.getByRole('button', { name: '返回 Worker 列表' }).click();
    await expect(page.locator('.worker-list-responsive')).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('worker')).toBe(WorkerId);

    await page.goto('/operations?source=demo');
    await expect(page.locator('.operation-layout[data-mobile-view="list"] .operation-list')).toBeVisible();
    await page.locator('.operation-record').first().click();
    await expect(page.locator('.operation-layout[data-mobile-view="detail"] .operation-list')).toBeHidden();
    await expect(page.locator('.operation-inspector')).toBeVisible();
    await expect(page.locator('.mobile-master-back')).toBeFocused();
    await expect(page.locator('.operation-mobile-detail-nav')).toBeVisible();
    await expect(page.locator('.operation-list-actions .button-quiet')).toBeHidden();
    const OperationId = new URL(page.url()).searchParams.get('operation');
    await page.getByRole('button', { name: '返回操作列表' }).click();
    await expect(page.locator('.operation-list')).toBeVisible();
    await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    expect(new URL(page.url()).searchParams.get('operation')).toBe(OperationId);
});

test('Session 详情在列表缺页、刷新失败与空搜索时保持可见', async ({ page }) => {
    const Mock = await InstallSessionOperationsMock(page);
    await page.goto('/sessions?session=55&process=42&identity_worker=7&identity_account=8&generation=6');

    const Inspector = page.locator('.session-inspector');
    await expect(Inspector.locator('h2')).toHaveText('55');
    await expect(page.locator('.session-item .session-item-head strong')).toHaveText(['56']);
    await expect(Inspector.locator('.session-selection-context')).toContainText('不在当前列表结果中');

    Mock.SetListUnavailable(true);
    await page.getByRole('button', { name: '刷新列表', exact: true }).click();
    const StaleError = 'Session 列表查询刷新失败，当前仍显示上次成功读取的数据。';
    const Width = page.viewportSize()?.width ?? 0;
    if (Width <= 767) await expect(page.locator('.session-mobile-list-status')).toContainText('当前仍显示上次成功读取的 Session 快照。');
    else await expect(page.getByText(StaleError, { exact: true })).toBeVisible();
    const RetrySessions = page.getByRole('button', { name: '重试读取', exact: true });
    await expect(RetrySessions).toBeVisible();
    const Directory = page.locator('.session-directory');
    await expect(Directory.locator('.session-item .session-item-head strong')).toHaveText(['56']);
    await expect(Inspector.locator('h2')).toHaveText('55');

    if (Width > 900) {
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
    await expect(page.getByText(StaleError, { exact: true })).toHaveCount(0);
    await expect(Directory.locator('.session-item .session-item-head strong')).toHaveText(['56']);
    const FilteredUrl = new URL(page.url());
    FilteredUrl.searchParams.set('q', 'no-session-matches-this');
    await page.goto(FilteredUrl.pathname + FilteredUrl.search);

    await expect(Inspector.locator('h2')).toHaveText('55');
    await expect(Inspector.locator('.session-selection-context')).toContainText('不在当前列表结果中');
    if (Width <= 767) {
        await page.getByRole('button', { name: '返回连接列表' }).click();
        await expect(page.getByText('没有匹配的 Session', { exact: true })).toBeVisible();
        await expect(Inspector).toBeHidden();
    } else {
        await expect(page.getByText('没有匹配的 Session', { exact: true })).toBeVisible();
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
