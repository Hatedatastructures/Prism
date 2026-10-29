import { expect, test, type Page, type Route } from '@playwright/test';

async function OpenDemoPage(PageValue: Page, Path: string): Promise<void> {
    const Target = new URL(Path, 'http://127.0.0.1');
    Target.searchParams.set('source', 'demo');
    await PageValue.goto(`${Target.pathname}${Target.search}`);
    await expect(PageValue.getByText('演示模式', { exact: true })).toBeVisible();
}

async function FulfillLiveOverviewRoute(RouteValue: Route, Now: number): Promise<void> {
    const Path = new URL(RouteValue.request().url()).pathname;
    if (Path.endsWith('/Bootstrap')) {
        await RouteValue.fulfill({ json: { api_version: '2', instance_key: 'live-fixture', process_id: '17',
            process_incarnation: '0123456789abcdef0123456789abcdef', command_token: 'a'.repeat(64), capabilities: [] } });
        return;
    }
    if (Path.endsWith('/Overview')) {
        const Sample = (Offset: number, Up: number, Down: number) => ({
            timestamp: new Date(Now + Offset).toISOString(), traffic: { up_bytes: String(Up), down_bytes: String(Down), events: '1', errors: '0' },
        });
        await RouteValue.fulfill({ json: { status: 'ok', value: {
            sampled_at: new Date(Now).toISOString(), sample_interval_ms: '5000',
            process: { id: '17', generation: '42', phase: 'ready' },
            health: { status: 'ready', checked_at: new Date(Now).toISOString(), ready: true, tcp_ready: true,
                udp_ready: false, udp_socket_ready: false, quic_ready: false, quic_socket_ready: false,
                quic_handshake_ready: false, quic_protocol_ready: false, active: '0', errors: '0' },
            counts: { tcp_sessions: '0', udp_connections: null, quic_connections: null,
                configured_accounts: '0', active_accounts: '0', ungrouped_accounts: '0', workers_total: '0', workers_accepting: '0' },
            traffic: { available: true, up_bytes: '35000', down_bytes: '200000', events: '3', errors: '0', up_bytes_per_second: '3000', down_bytes_per_second: '18000' },
            latency: { recognition_admission: { name: 'recognition_admission', available: false, sample_count: '0' }, stages: [] },
            memory: { process_available: false, byte_pool: { available: false },
                allocations: { available: false, coverage: '' }, worker_allocations: [] },
            history: [Sample(-10000, 10000, 50000), Sample(-5000, 20000, 110000), Sample(0, 35000, 200000)],
            observations: { accepted: '0', consumed: '0', dropped: '0', aggregation_failures: '0' },
            protocols: [
                { id: 'socks5', name: 'SOCKS5', configured_bindings: '2', active_sessions: '0',
                    traffic: { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' }, coverage: 'TCP Session 按已接受的连接归属' },
                { id: 'hysteria2', name: 'Hysteria2', configured_bindings: '1', active_sessions: null,
                    traffic: null, coverage: 'QUIC admission 尚未发布协议关联统计' },
            ],
        } } });
        return;
    }
    if (Path.endsWith('/Events')) {
        await RouteValue.fulfill({ json: { status: 'ok', value: { items: [], next_cursor: '0', has_more: false,
            earliest_cursor: '0', lost: false, lost_ranges: [], dropped: '0', terminal_dropped: '0', overwritten: '0',
            severity_filter_supported: true } } });
        return;
    }
    await RouteValue.fulfill({ json: { status: 'ok', value: { items: [], next_cursor: '0', has_more: false } } });
}

test('账户选择行的可访问说明包含用户组连接数与状态', async ({ page }) => {
    await OpenDemoPage(page, '/accounts');
    const Account = page.getByRole('button', { name: 'northstar acct-northstar', exact: true });
    await expect(Account).toHaveAccessibleDescription('核心线路 · 2 根连接租约 使用中');
    const Revoked = page.getByRole('button', { name: 'retired-key acct-retired-key', exact: true });
    await expect(Revoked).toHaveAccessibleDescription('未分组 · 0 根连接租约 已撤销');
    await Revoked.focus();
    await Revoked.press('Enter');
    const Inspector = page.getByRole('region', { name: '账户详情', exact: true });
    await expect(Inspector).toContainText('retired-key');
    await expect(Inspector).toContainText('已撤销');
    await expect(page.getByRole('button', { name: '撤销账户', exact: true })).toHaveCount(0);
});

test('账户总览只用一行范围摘要，给主从工作区让出首屏', async ({ page }) => {
    await OpenDemoPage(page, '/accounts');
    await expect(page.getByRole('heading', { name: '代理账户', exact: true })).toBeVisible();
    await expect(page.locator('.account-summary-bar')).toHaveCount(0);
    const Snapshot = page.getByRole('group', { name: '账户状态汇总', exact: true });
    await expect(Snapshot.locator('dt')).toHaveCount(4);
    await expect(Snapshot).toContainText('不含已撤销账户');
    await expect(Snapshot).toContainText('当前已载入账户');
    await expect(Snapshot).toContainText('当前已载入范围');
    await expect(Snapshot).toContainText('用户组');
    await expect(page.getByRole('region', { name: '账户目录', exact: true })).toBeVisible();
    const AccountInspector = page.getByRole('region', { name: '账户详情', exact: true });
    if ((page.viewportSize()?.width ?? 0) <= 767) await expect(AccountInspector).toBeHidden();
    else await expect(AccountInspector).toContainText('northstar');
});

test('账户概览首屏显示完整的关联 Session 对照', async ({ page }, TestInfo) => {
    await OpenDemoPage(page, '/accounts?account=acct-northstar&mobile_view=detail');
    const Preview = page.getByRole('table', { name: '账户关联 Session 摘要', exact: true });
    await expect(Preview.locator('thead th')).toHaveCount(5);
    await expect(Preview).toContainText('session-1001');
    await expect(Preview).toContainText('TCP / VLESS');
    await expect(Preview).toContainText('worker-01');
    await expect(Preview).toContainText('2');
    await expect(Preview).toContainText('198.51.100.24:51842');
    await expect(Preview).toContainText('203.0.113.18:443');
    await expect(Preview).toContainText('23.7 MiB');
    await expect(Preview).toContainText('46.9 MiB');
    if (TestInfo.project.name === 'edge-1440') {
        const FirstRow = await Preview.locator('tbody tr').first().boundingBox();
        expect(FirstRow).not.toBeNull();
        expect(FirstRow!.y + FirstRow!.height).toBeLessThan(900);
    }
});

test('账户详情显示统计流量且与周期账本分开', async ({ page }) => {
    await OpenDemoPage(page, '/accounts?account=acct-northstar&mobile_view=detail');
    await expect(page.getByRole('heading', { name: 'northstar', exact: true })).toBeVisible();
    const Traffic = page.locator('dl[aria-label="账户维度流量计数"]');
    await expect(Traffic).toContainText('32.3 MiB');
    await expect(Traffic).toContainText('58.6 MiB');
    await expect(Traffic).toContainText('完成传输事件');
    await expect(Traffic).toContainText('824');
    await expect(Traffic).toContainText('失败传输事件');
    await expect(Traffic).toContainText('3');
    await expect(page.getByRole('region', { name: '账户详情', exact: true })).toContainText('周期账本中的已结算量分开计算');
    const Sessions = page.getByRole('region', { name: '账户当前关联 Session', exact: true });
    await expect(Sessions).toContainText('session-1001');
    await expect(Sessions).toContainText('TCP / VLESS');
    await expect(Sessions).toContainText('worker-01');
    await expect(Sessions).toContainText('203.0.113.18:443');
});

test('概览在未开放历史查询时使用随快照返回的流量样本', async ({ page }) => {
    const Now = Date.now();
    let HistoryRequests = 0;
    page.on('request', Request => {
        if (new URL(Request.url()).pathname.endsWith('/History')) HistoryRequests += 1;
    });
    await page.route('**/Operations/**', Route => FulfillLiveOverviewRoute(Route, Now));

    await page.goto('/?source=live');
    const Readings = page.getByRole('region', { name: '运行指标', exact: true });
    await expect(Readings).toContainText('17.6 KiB/s');
    await expect(Readings).toContainText('2.9 KiB/s');
    await expect(page.getByText('流量趋势', { exact: true })).toBeVisible();
    await expect(page.locator('.overview-history-control')).toHaveCount(0);
    expect(HistoryRequests).toBe(0);
    if (page.viewportSize()?.width === 1440)
        await page.screenshot({ path: '../build/WebQa/CurrentReview/live-overview-bounded-history-1440.png', fullPage: true });
});

test('资源采样范围以具名分组保留采样时间间隔与实例身份', async ({ page }) => {
    await OpenDemoPage(page, '/resources');
    const SnapshotMeta = page.getByRole('group', { name: '资源快照采样范围', exact: true });
    await expect(SnapshotMeta).toContainText('采样于');
    await expect(SnapshotMeta).toContainText('采样间隔');
    await expect(SnapshotMeta).toContainText('PRISM-DEMO-01');
});

test('搜索框清除后恢复焦点并清空列表筛选', async ({ page }) => {
    await OpenDemoPage(page, '/sessions');

    const Search = page.getByRole('searchbox', { name: '搜索 Session', exact: true });
    await Search.fill('session-1001');
    await expect(Search).toHaveValue('session-1001');
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(1);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('session-1001');
    expect(new URL(page.url()).searchParams.get('q')).toBe('session-1001');

    await page.getByRole('button', { name: '清除搜索 Session', exact: true }).click();

    await expect(Search).toHaveValue('');
    await expect(Search).toBeFocused();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(5);
    expect(new URL(page.url()).searchParams.has('q')).toBe(false);
});

test('事件缺少操作来源身份时明确进入操作中心核对', async ({ page }) => {
    await OpenDemoPage(page, '/events');
    const Row = page.getByRole('table').getByRole('row').filter({ hasText: 'TCP 入口已就绪' });
    await Row.getByRole('button', { name: /详情/ }).click();
    const Link = page.getByRole('link', { name: '到操作中心核对', exact: true });
    await expect(Link).toBeVisible();
    const Target = new URL((await Link.getAttribute('href'))!, page.url());
    expect(Target.pathname).toBe('/operations');
    expect(Target.searchParams.has('operation')).toBe(false);
    await Link.click();
    await expect(page.getByText('近期操作', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('操作链接未包含来源实例', { exact: false })).toHaveCount(0);
});

test('Session 协议下拉支持键盘选择、Escape 恢复焦点并同步 URL', async ({ page }) => {
    await OpenDemoPage(page, '/sessions');

    const Protocol = page.getByRole('combobox', { name: '按协议筛选', exact: true });
    await Protocol.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('option', { name: '全部协议', exact: true })).toBeVisible();
    await expect(page.getByRole('option', { name: 'VLESS', exact: true })).toBeVisible();
    await expect(page.getByRole('option', { name: '全部协议', exact: true })).toBeFocused();
    await page.keyboard.press('End');
    const VlessOption = page.getByRole('option', { name: 'VLESS', exact: true });
    await expect(VlessOption).toBeVisible();
    await page.keyboard.press('Enter');

    await expect(Protocol).toContainText('VLESS');
    await expect(page).toHaveURL(/protocol=VLESS/);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(1);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('VLESS');

    await Protocol.focus();
    await page.keyboard.press('Enter');
    await expect(page.getByRole('option', { name: 'VLESS', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');

    await expect(page.getByRole('option', { name: 'VLESS', exact: true })).toHaveCount(0);
    await expect(Protocol).toBeFocused();
    await expect(page).toHaveURL(/protocol=VLESS/);
});

test('Session 状态选项正确筛选排空中的连接', async ({ page }) => {
    await OpenDemoPage(page, '/sessions');
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(5);

    const State = page.getByRole('combobox', { name: '按 Session 状态筛选', exact: true });
    await State.click();
    await expect(page.getByRole('option', { name: '排空中', exact: true })).toBeVisible();
    await page.getByRole('option', { name: '排空中', exact: true }).click();

    await expect(State).toContainText('排空中');
    await expect(page).toHaveURL(/state=draining/);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(1);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('session-1003');
});

test('账户额度调整类型用分段单选清晰呈现并支持方向键切换', async ({ page }) => {
    await OpenDemoPage(page, '/accounts?account=acct-northstar&mobile_view=detail');
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    await page.locator('details.usage-adjustment > summary').click();

    const Kind = page.getByRole('radiogroup', { name: '调整类型', exact: true });
    const AddAllowance = Kind.getByRole('radio', { name: '增加本周期额度' });
    const ReleaseUncertain = Kind.getByRole('radio', { name: '释放异常占额' });
    await expect(AddAllowance).toBeChecked();
    await expect(Kind).toContainText('提高当前周期可用上限');
    await expect(Kind).toContainText('核对后释放未结清占额');
    await AddAllowance.focus();
    await page.keyboard.press('ArrowRight');
    await expect(ReleaseUncertain).toBeChecked();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    if ((page.viewportSize()?.width ?? 0) > 900) {
        const DesktopColumnCount = await Kind.locator('div.grid').evaluate(Element => getComputedStyle(Element).gridTemplateColumns.trim().split(/\s+/).length);
        expect(DesktopColumnCount).toBe(2);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    const MobileColumnCount = await Kind.locator('div.grid').evaluate(Element => getComputedStyle(Element).gridTemplateColumns.trim().split(/\s+/).length);
    expect(MobileColumnCount).toBe(1);
});

test('资源与协议统计口径集中呈现，记录行不重复放置范围按钮', async ({ page }) => {
    await OpenDemoPage(page, '/resources');
    const SnapshotMeta = page.getByRole('group', { name: '资源快照采样范围', exact: true });
    await expect(SnapshotMeta).toContainText(/采样间隔\s*5,000 ms/);
    const PmrScope = page.getByText('Process PMR 调用与统计范围', { exact: true });
    await PmrScope.focus();
    await page.keyboard.press('Enter');
    await expect(PmrScope.locator('xpath=..')).toContainText('分配');
    await expect(PmrScope.locator('xpath=..')).toContainText('释放');
    await expect(PmrScope.locator('xpath=..')).toContainText('峰值');

    const WorkerRegion = page.getByRole('region', { name: 'Worker 受追踪分配表', exact: true });
    const WorkerTable = WorkerRegion.getByRole('table', { name: 'Worker 受追踪分配表', exact: true });
    await expect(WorkerTable.locator('tbody tr')).toHaveCount(4);
    await expect(WorkerTable.getByRole('columnheader', { name: '统计范围', exact: true })).toBeVisible();
    const WorkerRow = WorkerTable.locator('tbody tr').filter({ hasText: 'worker-01' });
    await WorkerRow.getByText('范围', { exact: true }).click();
    await expect(WorkerRow).toContainText('仅计通过 WorkerResources TrackingResource');
    await expect(WorkerRegion.getByRole('button', { name: '统计范围', exact: true })).toHaveCount(0);

    await OpenDemoPage(page, '/protocols');
    const Protocols = page.getByRole('region', { name: '协议类型运行明细表，可横向滚动查看覆盖范围', exact: true });
    await expect(Protocols).toBeVisible();
    await expect(Protocols.locator('tbody tr')).toHaveCount(4);
    await expect(Protocols).toContainText('活动 Session');
    await expect(Protocols).toContainText('绑定数');
    await expect(Protocols).toContainText('统计覆盖');
    await expect(page.getByRole('tab', { name: /配置实例/ })).toHaveCount(0);

    await expect(Protocols.locator('tbody tr').filter({ hasText: 'SOCKS5' })).toContainText('按已接受 TCP Session 归属');
});

test('成员换组与添加候选都只在明确提交后改变演示归属', async ({ page }) => {
    await OpenDemoPage(page, '/user-groups?group=group-core');
    const CoreMembers = page.getByRole('region', { name: '用户组详情', exact: true }).getByRole('table');
    await expect(CoreMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toHaveCount(0);
    await page.getByRole('button', { name: '添加账户', exact: true }).click();
    const CoreDialog = page.getByRole('dialog', { name: '添加账户到 核心线路', exact: true });
    await CoreDialog.getByRole('combobox', { name: '选择账户', exact: true }).click();
    await page.getByRole('option', { name: 'blue-hour · acct-blue-hour', exact: true }).click();
    await expect(CoreMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toHaveCount(0);
    await CoreDialog.getByRole('button', { name: '取消', exact: true }).click();
    await expect(CoreDialog).toHaveCount(0);
    await expect(CoreMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toHaveCount(0);
    await page.getByRole('button', { name: '添加账户', exact: true }).click();
    const CoreConfirmDialog = page.getByRole('dialog', { name: '添加账户到 核心线路', exact: true });
    await CoreConfirmDialog.getByRole('combobox', { name: '选择账户', exact: true }).click();
    await page.getByRole('option', { name: 'blue-hour · acct-blue-hour', exact: true }).click();
    await CoreConfirmDialog.getByRole('button', { name: '确认分配', exact: true }).click();
    await expect(CoreMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('演示：账户已归入「核心线路」。');

    if ((page.viewportSize()?.width ?? 0) <= 767) await page.getByRole('button', { name: '返回分组目录' }).click();
    await page.getByRole('button', { name: /标准用户/ }).click();
    const StandardMembers = page.getByRole('region', { name: '用户组详情', exact: true }).getByRole('table');
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toHaveCount(0);
    await page.getByRole('button', { name: '添加账户', exact: true }).click();
    const StandardDialog = page.getByRole('dialog', { name: '添加账户到 标准用户', exact: true });
    await StandardDialog.getByRole('combobox', { name: '选择账户', exact: true }).click();
    await page.getByRole('option', { name: 'blue-hour · acct-blue-hour', exact: true }).click();
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toHaveCount(0);
    await StandardDialog.getByRole('button', { name: '确认分配', exact: true }).click();
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-blue-hour' })).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('演示：账户已归入「标准用户」。');

    await page.getByRole('button', { name: '添加账户', exact: true }).click();
    const PaperPlaneDialog = page.getByRole('dialog', { name: '添加账户到 标准用户', exact: true });
    await PaperPlaneDialog.getByRole('combobox', { name: '选择账户', exact: true }).click();
    await page.getByRole('option', { name: 'paper-plane · acct-paper-plane', exact: true }).click();
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-paper-plane' })).toHaveCount(0);
    await PaperPlaneDialog.getByRole('button', { name: '确认分配', exact: true }).click();
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-paper-plane' })).toBeVisible();
    await expect(page.getByRole('alert')).toContainText('演示：账户已归入「标准用户」。');

    await StandardMembers.getByRole('row').filter({ hasText: 'acct-paper-plane' }).getByRole('button', { name: '移出', exact: true }).click();
    const RemoveDialog = page.getByRole('dialog', { name: '移出用户组？', exact: true });
    await expect(RemoveDialog).toContainText('paper-plane');
    await RemoveDialog.getByRole('button', { name: '确认移出', exact: true }).click();
    await expect(StandardMembers.getByRole('row').filter({ hasText: 'acct-paper-plane' })).toHaveCount(0);
});

test('用户组从页头新建，取消后恢复焦点，提交后显示反馈', async ({ page }) => {
    await OpenDemoPage(page, '/user-groups?group=group-standard&mobile_view=detail');
    const Trigger = page.getByRole('button', { name: '新建用户组', exact: true });
    await Trigger.click();

    const Dialog = page.getByRole('dialog', { name: '新建用户组', exact: true });
    const Name = Dialog.getByRole('textbox', { name: '新用户组名称', exact: true });
    await expect(Name).toBeVisible();
    await Name.fill('页面体验组');
    await page.keyboard.press('Escape');
    await expect(Dialog).toHaveCount(0);
    await expect(Trigger).toBeFocused();

    await Trigger.click();
    await Dialog.getByRole('textbox', { name: '新用户组名称', exact: true }).fill('页面体验组');
    await Dialog.getByRole('button', { name: '创建用户组', exact: true }).click();
    await expect(Dialog).toHaveCount(0);
    await expect(page.getByText('演示：已创建用户组「页面体验组」。', { exact: true })).toBeVisible();
});

test('切换用户组会丢弃旧组的改名草稿并载入新组名称', async ({ page }) => {
    await OpenDemoPage(page, '/user-groups?group=group-core');

    await page.getByRole('button', { name: '改名', exact: true }).click();
    const RenameDialog = page.getByRole('dialog', { name: '重命名 核心线路', exact: true });
    const RenameInput = RenameDialog.getByRole('textbox', { name: '新用户组名称', exact: true });
    await RenameInput.fill('核心线路改名草稿');
    await expect(RenameDialog.getByRole('button', { name: '确认改名', exact: true })).toBeEnabled();
    await RenameDialog.getByRole('button', { name: '取消', exact: true }).click();
    await expect(RenameDialog).toHaveCount(0);

    if ((page.viewportSize()?.width ?? 0) <= 767) await page.getByRole('button', { name: '返回分组目录' }).click();
    await page.getByRole('button', { name: /标准用户/ }).click();
    await page.getByRole('button', { name: '改名', exact: true }).click();
    const StandardRename = page.getByRole('dialog', { name: '重命名 标准用户', exact: true });
    const StandardInput = StandardRename.getByRole('textbox', { name: '新用户组名称', exact: true });
    await expect(StandardInput).toHaveValue('标准用户');
    await expect(StandardInput).not.toHaveValue('核心线路改名草稿');
    await expect(StandardRename.getByRole('button', { name: '确认改名', exact: true })).toBeEnabled();
    await StandardRename.getByRole('button', { name: '取消', exact: true }).click();
    if ((page.viewportSize()?.width ?? 0) <= 767) await page.getByRole('button', { name: '返回分组目录' }).click();
    await expect(page.getByRole('button', { name: /核心线路/ })).toBeVisible();
    await expect(page.getByRole('button', { name: /标准用户/ })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('group')).toBe('group-standard');
});

test('配置校验绑定当前文本，编辑后校验步骤回退', async ({ page }) => {
    await OpenDemoPage(page, '/configuration');

    const Workflow = page.getByRole('list', { name: '配置应用流程', exact: true });
    const EditStep = Workflow.locator('.configuration-workflow-step').filter({ hasText: '编辑草稿' });
    const ValidateStep = Workflow.locator('.configuration-workflow-step').filter({ hasText: '校验草稿' });
    const ApplyStep = Workflow.locator('.configuration-workflow-step').filter({ hasText: '应用配置' });
    const ActiveStep = Workflow.locator('.configuration-workflow-step[aria-current="step"]');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });

    await expect(ActiveStep.locator('strong')).toHaveText('编辑草稿');
    const Draft = JSON.parse(await Editor.inputValue()) as { Runtime: { WorkerCount: number } };
    Draft.Runtime.WorkerCount += 1;
    await Editor.fill(JSON.stringify(Draft, null, 2));
    await expect(ActiveStep.locator('strong')).toHaveText('校验草稿');
    await expect(EditStep).toHaveClass(/is-complete/);
    await expect(ValidateStep).toHaveClass(/is-current/);

    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    const ValidationMessage = page.getByRole('alert').filter({ hasText: 'Validate Only 通过；未修改运行配置或配置文件。' });
    await expect(ValidationMessage).toBeVisible();
    await expect(ActiveStep.locator('strong')).toHaveText('应用配置');
    await expect(ValidateStep).toHaveClass(/is-complete/);
    await expect(ApplyStep).not.toHaveClass(/is-complete/);

    Draft.Runtime.WorkerCount += 1;
    await Editor.fill(JSON.stringify(Draft, null, 2));

    await expect(ActiveStep.locator('strong')).toHaveText('校验草稿');
    await expect(ValidationMessage).toHaveCount(0);
    await expect(ValidateStep).toHaveClass(/is-current/);
    await expect(ValidateStep).not.toHaveClass(/is-complete/);
    await expect(ApplyStep).not.toHaveClass(/is-complete/);
    await expect(page.getByRole('status'))
        .toContainText('请先校验当前这份准确文本；任何编辑都会使校验失效。');
});
