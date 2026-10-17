import { expect, test, type Page } from '@playwright/test';

type FixtureReply = Readonly<{ Status?: number; Body: unknown; Abort?: boolean }>;
type FixtureHandler = (Url: URL) => FixtureReply | Promise<FixtureReply>;
type FixturePostHandler = (Url: URL, Body: unknown) => FixtureReply | Promise<FixtureReply>;
type RequestRecord = Readonly<{ Method: string; Path: string; Search: string }>;
type MockLog = Readonly<{ Requests: RequestRecord[]; Unexpected: string[]; NonGet: string[] }>;
type BootstrapIdentity = Readonly<{ InstanceKey: string; ProcessId: string; Incarnation: string }>;

const Timestamp = '2026-10-17T00:00:00.000Z';
const OtherTimestamp = '2026-10-17T00:00:05.000Z';
const CurrentIncarnation = 'a'.repeat(32);
const PreviousIncarnation = 'b'.repeat(32);
const TrafficZero = { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' };
const EmptyCollection = { items: [], next_cursor: '0', has_more: false };

function Bootstrap(Capabilities: readonly string[] = [], Identity: Partial<BootstrapIdentity> = {}): unknown {
    return { api_version: '2', instance_key: Identity.InstanceKey ?? 'browser-quality-instance', process_id: Identity.ProcessId ?? '42',
        process_incarnation: Identity.Incarnation ?? CurrentIncarnation, command_token: 'c'.repeat(64), capabilities: Capabilities };
}
function Ok(Value: unknown): unknown { return { status: 'ok', value: Value }; }
function PageWire(Items: readonly unknown[], NextCursor = '0', HasMore = false): unknown {
    return { items: Items, next_cursor: NextCursor, has_more: HasMore };
}
function EventPageWire(Items: readonly unknown[] = []): unknown {
    return { ...PageWire(Items), earliest_cursor: '0', lost: false, lost_ranges: [], dropped: '0',
        terminal_dropped: '0', overwritten: '0', severity_filter_supported: true };
}
function EventWire(Sequence: string, Severity: string, Detail: string): unknown {
    return { kind: 'data', sequence: Sequence, timestamp: Timestamp, correlation: '77',
        generation: '6', process: '42', worker: '7', account: '8', session: '55', stream: '0', task: '0',
        parent_task: '0', operation: '0', severity: Severity, scope: 'session', detail: Detail, terminal: false, truncated: false };
}
function AccountWire(Id: string, Label: string, GroupId: string | null = null): unknown {
    return { id: Id, generation: '6', label: Label, revoked: false, active_sessions: '0', group_id: GroupId,
        traffic: TrafficZero, account_key: `key-${Id}`, active_connections: null, active_streams: null,
        upload_bytes_per_second: null, download_bytes_per_second: null };
}
function GroupWire(Id: string, Name: string, ActiveSessions: string | null, Traffic: unknown | null): unknown {
    return { id: Id, name: Name, configured_account_count: '0', active_account_count: '0',
        active_sessions: ActiveSessions, traffic: Traffic };
}
function SessionWire(Input: Readonly<{ Process?: string; Generation?: string; Active?: boolean }> = {}): unknown {
    return { id: '55', process: Input.Process ?? '42', worker: '7', account: '8', generation: Input.Generation ?? '6',
        traffic: TrafficZero, started_at: Timestamp, transport: 'tcp', identity: 'fixture-account',
        source_address: '192.0.2.10:48000', protocol: 'vless', target: '198.51.100.20:443',
        active: Input.Active ?? true, draining: false, active_tasks: '1' };
}
function StreamWire(): unknown {
    return { id: '31', task: '61', parent_task: '60', process: '42', session: '55', account: '8', worker: '7',
        generation: '6', traffic: { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' }, protocol: 'vless', state: 'active' };
}
function TaskWire(): unknown {
    return { id: '61', process: '42', worker: '7', session: '55', stream: '31', generation: '6', parent_task: '60',
        status: 'running', started_at: Timestamp, completed_at: null, cancel_requested: false, cancellable: true,
        drain_blocked: false, failure: null, drain_failure: null };
}
function TracePageWire(): unknown {
    return { ...PageWire([]), lost: false, cursors: [], lost_ranges: [] };
}
function WorkerWire(Generation = '6'): unknown {
    return { id: '7', process: '42', generation: Generation, health: { status: 'healthy' },
        queue: { depth: '0', capacity: '0' }, tasks: { started: '1', completed: '0', cancelled: '0' },
        dispatch: { accepted: '1', full: '0', closed: '0', unavailable: '0', generation_rejected: '0' },
        commands: { executed: '0', failed: '0' }, running: true, accepting: true, active_tasks: '1',
        dropped_events: '0', traffic: null };
}
function OperationWire(Status = 'accepted'): unknown {
    return { id: '17', status: Status, command: 'DrainWorker', accepted_at: Timestamp, updated_at: OtherTimestamp,
        message: 'Mock operation record', correlation: '77', generation: '6', process: '42', worker: '7', account: '8',
        session: '55', stream: '0', task: '0', parent_task: '0', failure: null };
}
function HistoryWire(): unknown {
    return { sampled_at: OtherTimestamp, from: Timestamp, to: OtherTimestamp, resolution_ms: '1000',
        coverage: 'browser GET fixture', gaps: [], items: [{ time: Timestamp, up_bytes: '0', down_bytes: '0', active: null,
            p50_us: null, p95_us: null, p99_us: null, sample_count: '1', quality: null }] };
}
function OverviewWire(): unknown {
    return {
        sampled_at: Timestamp, sample_interval_ms: '5000',
        process: { id: '42', generation: '6', phase: 'ready' },
        health: { status: 'healthy', checked_at: Timestamp, ready: true, tcp_ready: true, udp_ready: true,
            udp_socket_ready: true, quic_ready: false, quic_socket_ready: false, quic_handshake_ready: false,
            quic_protocol_ready: false, active: '0', errors: '0' },
        counts: { configured_accounts: '2', active_accounts: '1', ungrouped_accounts: '1', tcp_sessions: '0',
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
        observations: { accepted: '0', consumed: '0', dropped: '0', aggregation_failures: '0' },
        history: [], protocols: [],
    };
}
function PublicConfiguration(HistoryMaxBytes: number): Readonly<Record<string, unknown>> {
    return { SchemaVersion: 1, Runtime: {}, Listeners: {}, NativeTls: {}, Builtins: {}, Protocols: [], Carriers: {},
        ProtocolBindings: {}, Recognition: {}, Routes: {}, Dns: {}, Logging: {}, Trace: {}, Statistics: {}, Operations: {},
        HotReload: {}, Shutdown: {}, AccountGroups: [], Accounts: [],
        Storage: { Directory: 'data', HistoryMaxBytes } };
}
async function NavigatePrimary(Page: Page, Name: string): Promise<void> {
    const MobileNavigation = Page.getByRole('button', { name: '打开导航', exact: true });
    if (await MobileNavigation.isVisible()) await MobileNavigation.click();
    await Page.locator('.primary-nav').getByRole('link', { name: Name, exact: true }).click();
}

async function InstallOperationsGetMock(Page: Page, Handler: FixtureHandler, PostHandler?: FixturePostHandler): Promise<MockLog> {
    const Log = { Requests: [] as RequestRecord[], Unexpected: [] as string[], NonGet: [] as string[] };
    await Page.route('**/Operations/**', async Route => {
        const Request = Route.request();
        const Url = new URL(Request.url());
        // Vite's lazy-loaded OperationsPage module also contains `/Operations/` in its source path.
        // Keep this wire mock scoped to the API so it cannot replace application modules with JSON.
        if (!Url.pathname.startsWith('/Operations/')) {
            await Route.continue();
            return;
        }
        Log.Requests.push({ Method: Request.method(), Path: Url.pathname, Search: Url.search });
        if (Url.pathname === '/Operations/Overview' && Request.method() === 'GET') {
            await Route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(Ok(OverviewWire())) });
            return;
        }
        if (Request.method() !== 'GET') {
            const RequestName = `${Request.method()} ${Url.pathname}${Url.search}`;
            Log.NonGet.push(RequestName);
            if (PostHandler) {
                let Reply: FixtureReply;
                try { Reply = await PostHandler(Url, Request.postDataJSON()); }
                catch (Failure: unknown) {
                    const Detail = RequestName + ': ' + (Failure instanceof Error ? Failure.message : String(Failure));
                    Log.Unexpected.push(Detail);
                    console.warn('Unexpected mocked Operations command: ' + Detail);
                    Reply = { Status: 500, Body: { status: 'error', message: 'Unexpected QA command fixture.' } };
                }
                if (Reply.Abort) { await Route.abort('timedout'); return; }
                await Route.fulfill({ status: Reply.Status ?? 200, contentType: 'application/json', body: JSON.stringify(Reply.Body) });
                return;
            }
            await Route.fulfill({ status: 405, contentType: 'application/json',
                body: JSON.stringify({ status: 'error', message: 'This test intentionally blocks mutations.' }) });
            return;
        }
        let Reply: FixtureReply;
        try { Reply = await Handler(Url); }
        catch (Failure: unknown) {
            const Detail = Url.pathname + Url.search + ': ' + (Failure instanceof Error ? Failure.message : String(Failure));
            Log.Unexpected.push(Detail);
            console.warn('Unexpected mocked Operations read: ' + Detail);
            Reply = { Status: 500, Body: { status: 'error', message: 'Unexpected QA fixture request.' } };
        }
        await Route.fulfill({ status: Reply.Status ?? 200, contentType: 'application/json', body: JSON.stringify(Reply.Body) });
    });
    return Log;
}
function ExpectMockWasReadOnly(Log: MockLog): void {
    expect(Log.NonGet, `Unexpected non-GET management request: ${Log.NonGet.join(', ')}`).toEqual([]);
    expect(Log.Unexpected, `Unexpected management read: ${Log.Unexpected.join(', ')}`).toEqual([]);
}
function AccountRelatedReply(Url: URL): FixtureReply | null {
    if (Url.pathname === '/Operations/Sessions') return { Body: Ok(EmptyCollection) };
    return null;
}
function SessionRelatedReply(Url: URL): FixtureReply | null {
    if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['events.filter.process', 'events.filter.generation']) };
    if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
    if (Url.pathname.endsWith('/Trace')) return { Body: Ok(TracePageWire()) };
    if (Url.pathname.endsWith('/Streams')) return { Body: Ok(PageWire([StreamWire()])) };
    if (Url.pathname.endsWith('/Tasks')) return { Body: Ok(PageWire([TaskWire()])) };
    return null;
}

// All live-source browser tests below run against a local, explicit GET-only wire mock.
// The demo adjustment test is separately labeled and uses only DemoAdminDataSource's in-memory state.
test('Events pause freezes its loaded window, then severity and Back/Forward clear the freeze', async ({ page }) => {
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['events.filter.process', 'events.filter.generation']) };
        if (Url.pathname === '/Operations/Events') {
            const Severity = Url.searchParams.get('severity');
            return { Body: Ok(EventPageWire([Severity === 'error' ? EventWire('92', 'error', 'error-row') : EventWire('91', 'warning', 'warning-row')])) };
        }
        throw new Error('No Events fixture for this endpoint.');
    });
    await page.goto('/events?source=live&range=15m&severity=warning');
    await expect(page.getByText('warning-row', { exact: true })).toBeVisible();
    const WorkerLink = page.locator('.event-resource-links a[href^="/workers"]').first();
    const WorkerHref = await WorkerLink.getAttribute('href');
    const WorkerTarget = new URL(WorkerHref ?? '', page.url());
    expect(WorkerTarget.searchParams.get('worker')).toBe('7');
    expect(WorkerTarget.searchParams.get('process')).toBe('42');
    expect(WorkerTarget.searchParams.get('generation')).toBe('6');
    await page.getByRole('button', { name: '暂停追随', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: '已暂停：固定显示暂停时已载入' })).toBeVisible();

    await page.locator('.state-filters').getByRole('button', { name: '错误', exact: true }).click();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=error/);
    await expect(page.getByText('error-row', { exact: true })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: '已暂停：固定显示暂停时已载入' })).toHaveCount(0);
    await page.goBack();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=warning/);
    await expect(page.getByText('warning-row', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '暂停追随', exact: true })).toBeVisible();
    await page.goForward();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=error/);
    await expect(page.getByText('error-row', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '暂停追随', exact: true })).toBeVisible();
    ExpectMockWasReadOnly(Log);
});

test('invalid user-group ID stays pinned across pages and partial metrics do not become zero', async ({ page }) => {
    const KnownZero = { ...TrafficZero };
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = AccountRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['history.read']) };
        if (Url.pathname === '/Operations/Groups') {
            if (Url.searchParams.get('cursor') === '50')
                return { Body: Ok(PageWire([GroupWire('target-late', '目标晚到组', '0', KnownZero)])) };
            return { Body: Ok(PageWire([
                GroupWire('group-without-metrics', '指标缺测组', null, null),
                GroupWire('group-known-zero', '已知零值组', '0', KnownZero),
            ], '50', true)) };
        }
        if (Url.pathname === '/Operations/Accounts') return { Body: Ok(EmptyCollection) };
        if (Url.pathname === '/Operations/History') return { Body: Ok(HistoryWire()) };
        throw new Error('No user-group fixture for this endpoint.');
    });
    await page.goto('/user-groups?source=live&range=1h&group=target-late');
    await expect(page.getByText('未在当前已载入范围找到指定组', { exact: true })).toBeVisible();
    await expect(page.locator('.group-inspector')).not.toContainText('用户组默认策略');
    await expect(page.locator('.group-inspector')).not.toContainText('目标晚到组');
    await expect(page.getByText('部分缺测', { exact: true }).first()).toBeVisible();
    expect(new URL(page.url()).searchParams.get('group')).toBe('target-late');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');

    await page.getByRole('button', { name: '载入更多', exact: true }).click();
    await expect(page.locator('.group-inspector')).toContainText('目标晚到组');
    await expect(page.locator('.group-inspector .group-summary-row')).toContainText('根连接租约');
    await expect(page.locator('.group-inspector .group-summary-row')).toContainText('0');
    await expect(page.getByText('部分缺测', { exact: true }).first()).toBeVisible();
    await expect(page).toHaveURL(/source=live.*range=1h.*group=target-late/);
    ExpectMockWasReadOnly(Log);
});

test('account query error differs from a successful empty search and clearing q restores loaded accounts', async ({ page }) => {
    let AccountReadCount = 0;
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = AccountRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap() };
        if (Url.pathname === '/Operations/Groups') return { Body: Ok(EmptyCollection) };
        if (Url.pathname === '/Operations/Accounts') {
            AccountReadCount += 1;
            if (AccountReadCount === 1) return { Status: 503, Body: { status: 'error', message: 'Fixture account query unavailable.' } };
            return { Body: Ok(PageWire([AccountWire('8', 'northstar'), AccountWire('9', 'blue-hour')])) };
        }
        throw new Error('No account directory fixture for this endpoint.');
    });
    await page.goto('/accounts?source=live&q=missing');
    await expect(page.getByText('账户目录暂时无法载入', { exact: true })).toBeVisible();
    await expect(page.getByText('没有匹配账户', { exact: true })).toHaveCount(0);

    await page.reload();
    await expect(page.getByText('没有匹配账户', { exact: true })).toBeVisible();
    await expect(page.getByText('账户目录暂时无法载入', { exact: true })).toHaveCount(0);
    await page.getByRole('textbox', { name: '搜索账户' }).fill('northstar');
    await expect(page.locator('.account-table tbody tr')).toHaveCount(1);
    await expect(page).toHaveURL(/source=live.*q=northstar/);
    await page.getByRole('textbox', { name: '搜索账户' }).fill('');
    await expect(page).toHaveURL(/source=live/);
    expect(new URL(page.url()).searchParams.has('q')).toBe(false);
    await expect(page.locator('.account-table tbody tr')).toHaveCount(2);
    ExpectMockWasReadOnly(Log);
});

test('account without live usage/history capability issues neither ledger nor history GET', async ({ page }) => {
    const Account = AccountWire('8', 'northstar');
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = AccountRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['accounts.filter', 'groups.filter', 'sessions.filter']) };
        if (Url.pathname === '/Operations/Groups') return { Body: Ok(EmptyCollection) };
        if (Url.pathname === '/Operations/Accounts') return { Body: Ok(PageWire([Account])) };
        throw new Error('No account-capability fixture for this endpoint.');
    });
    await page.goto('/accounts?source=live&range=15m&account=8');
    await expect(page.locator('.account-inspector')).toContainText('northstar');
    await expect(page.locator('.usage-section')).toContainText('accounts.usage.read');
    await expect(page.getByRole('tab', { name: '趋势', exact: true })).toBeVisible();
    await page.getByRole('tab', { name: '趋势', exact: true }).click();
    await expect(page.locator('.account-inspector')).toContainText('history.read');
    expect(Log.Requests.filter(Request => Request.Path === '/Operations/AccountUsage')).toHaveLength(0);
    expect(Log.Requests.filter(Request => Request.Path === '/Operations/History')).toHaveLength(0);
    ExpectMockWasReadOnly(Log);
});

test('demo account adjustment reads back the new balance and advances the in-memory revision', async ({ page }) => {
    const ManagementRequests: RequestRecord[] = [];
    page.on('request', Request => {
        const Url = new URL(Request.url());
        if (Url.pathname.startsWith('/Operations/'))
            ManagementRequests.push({ Method: Request.method(), Path: Url.pathname, Search: Url.search });
    });
    await page.goto('/accounts?source=demo&range=15m&account=acct-northstar');
    await expect(page.locator('.usage-remaining strong')).toBeVisible();
    const InitialBalance = await page.locator('.usage-remaining strong').innerText();
    const Adjustment = async (Reason: string): Promise<string> => {
        const BalanceBefore = await page.locator('.usage-remaining strong').innerText();
        const Form = page.locator('.usage-adjustment');
        if (!(await Form.locator('summary').getAttribute('aria-expanded')) && !(await Form.evaluate(Element => Element.hasAttribute('open'))))
            await Form.locator('summary').click();
        await page.getByLabel('字节量').fill('1073741824');
        await page.getByLabel('调整原因').fill(Reason);
        await page.getByRole('button', { name: '提交调整', exact: true }).click();
        const Dialog = page.getByRole('dialog');
        await expect(Dialog).toBeVisible();
        await Dialog.getByRole('button', { name: '确认调整', exact: true }).click();
        await expect(Dialog).toHaveCount(0);
        await expect(page.locator('.usage-section')).toContainText(`演示：${Reason}`);
        await expect(page.locator('.usage-remaining strong')).not.toHaveText(BalanceBefore);
        return page.locator('.usage-remaining strong').innerText();
    };
    const AfterFirstAdjustment = await Adjustment('browser QA readback one');
    const AfterSecondAdjustment = await Adjustment('browser QA readback two');
    expect(AfterFirstAdjustment).not.toBe(InitialBalance);
    expect(AfterSecondAdjustment).not.toBe(AfterFirstAdjustment);
    await expect(page.locator('.usage-section')).not.toContainText('账本修订冲突');
    expect(ManagementRequests).toEqual([]);
});

test('configuration draft is source-bound, rebase rechecks Generation, and an unconfirmed Apply is not repeated', async ({ page }, TestInfo) => {
    let TargetSource = false;
    let ChangedBootstrapReads = 0;
    let CandidatePrepared = false;
    let ConfigurationGeneration = 'generation-old';
    let ConfigurationValue = PublicConfiguration(1_000);
    const OldIdentity = { InstanceKey: 'fixture-old-instance', ProcessId: '42', Incarnation: CurrentIncarnation };
    const TargetIdentity = { InstanceKey: 'fixture-current-instance', ProcessId: '42', Incarnation: 'c'.repeat(32) };
    const CommandBodies: unknown[] = [];
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') {
            if (TargetSource) ChangedBootstrapReads += 1;
            return { Body: Bootstrap(['configuration.reload.validate', 'configuration.reload.apply'], TargetSource ? TargetIdentity : OldIdentity) };
        }
        if (Url.pathname === '/Operations/Configuration')
            return { Body: Ok({ configuration: ConfigurationValue, generation: ConfigurationGeneration, reloadable: true }) };
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error('No Configuration fixture for this endpoint.');
    }, (Url, Body) => {
        if (Url.pathname !== '/Operations/Reload') throw new Error('Only the explicit Reload mock may receive a POST.');
        CommandBodies.push(Body);
        const Request = Body as Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>;
        if (Request.mode === 'validate_only' && ['generation-old', 'generation-current'].includes(Request.base_generation ?? ''))
            return { Body: { operation: '0', status: 'completed', message: 'Mock Validate Only passed.' } };
        if (Request.mode === 'apply' && Request.base_generation === 'generation-current')
            return { Abort: true, Body: null };
        throw new Error(`Unexpected mocked reload mode/generation: ${Request.mode}/${Request.base_generation}`);
    });

    await page.goto('/configuration?source=live&range=1h');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toBeVisible();
    const DraftValue = JSON.parse(JSON.stringify(PublicConfiguration(2_000))) as Readonly<Record<string, unknown>>;
    const DraftText = JSON.stringify(DraftValue, null, 2);
    await Editor.fill(DraftText);
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeEnabled();
    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeEnabled();
    expect(CommandBodies).toHaveLength(1);
    expect(CommandBodies[0]).toMatchObject({ mode: 'validate_only', base_generation: 'generation-old' });

    await NavigatePrimary(page, '事件流');
    await expect(page.getByRole('heading', { name: '事件流', exact: true })).toBeVisible();
    TargetSource = true;
    ConfigurationGeneration = 'generation-candidate';
    ConfigurationValue = PublicConfiguration(3_000);
    const NewIdentityBootstrap = page.waitForResponse(Response => {
        const Url = new URL(Response.url());
        return Url.pathname === '/Operations/Bootstrap' && Response.request().method() === 'GET';
    }, { timeout: 8_000 });
    await NavigatePrimary(page, '配置');
    await NewIdentityBootstrap;
    await expect.poll(() => ChangedBootstrapReads, { timeout: 5_000 }).toBeGreaterThan(0);

    expect(new URL(page.url()).searchParams.get('source')).toBe('live');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    const StaleDraft = page.locator('#stale-configuration-draft');
    await expect(StaleDraft).toHaveValue(DraftText);
    await expect(StaleDraft).toHaveAttribute('readonly', '');
    await expect(Editor).toHaveAttribute('readonly', '');
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '读取当前基线并准备重基线', exact: true })).toBeVisible();

    const PreparationStart = Log.Requests.length;
    await page.getByRole('button', { name: '读取当前基线并准备重基线', exact: true }).click();
    await expect(page.locator('.configuration-stale-draft')).toContainText('已读取目标实例配置；请核对下方来源与 Generation 后确认重基线。');
    const PreparationReads = Log.Requests.slice(PreparationStart).filter(Request => Request.Method === 'GET' &&
        ['/Operations/Bootstrap', '/Operations/Configuration'].includes(Request.Path)).map(Request => Request.Path);
    const ConfigurationReadIndex = PreparationReads.lastIndexOf('/Operations/Configuration');
    expect(ConfigurationReadIndex).toBeGreaterThan(0);
    expect(PreparationReads[ConfigurationReadIndex - 1]).toBe('/Operations/Bootstrap');
    expect(PreparationReads[ConfigurationReadIndex + 1]).toBe('/Operations/Bootstrap');
    await expect(page.locator('.configuration-stale-draft')).toContainText('Generation generation-candidate');
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('configuration-stale-candidate.png'), fullPage: true });

    CandidatePrepared = true;
    ConfigurationGeneration = 'generation-current';
    ConfigurationValue = PublicConfiguration(4_000);
    const ConfirmRebase = async (): Promise<void> => {
        await page.getByRole('button', { name: '确认以该基线重建草稿', exact: true }).click();
        await page.getByRole('dialog').getByRole('button', { name: '确认重建并重新校验', exact: true }).click();
    };
    await ConfirmRebase();
    await expect(page.getByText('目标配置在确认期间已变化；已刷新候选基线，请再次核对新 Generation 并确认。', { exact: true })).toBeVisible();
    await expect(page.locator('.configuration-stale-draft')).toContainText('Generation generation-current');
    await expect(StaleDraft).toHaveValue(DraftText);
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('configuration-generation-conflict.png'), fullPage: true });
    expect(CandidatePrepared).toBe(true);

    await ConfirmRebase();
    await expect(page.locator('.configuration-stale-draft')).toHaveCount(0);
    await expect(Editor).toHaveValue(DraftText);
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeEnabled();
    expect(CommandBodies).toHaveLength(2);
    expect(CommandBodies[1]).toMatchObject({ mode: 'validate_only', base_generation: 'generation-current' });

    await page.getByRole('button', { name: '应用配置', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: '确认发布', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: '操作结果待核对' })).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: '请求结果未确认' })).toHaveCount(2);
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('configuration-apply-unknown.png'), fullPage: true });
    await expect(Editor).toHaveAttribute('readonly', '');
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeDisabled();
    await expect.poll(() => CommandBodies.length).toBe(3);
    expect(CommandBodies[2]).toMatchObject({ mode: 'apply', base_generation: 'generation-current' });
    expect(Log.NonGet).toEqual(['POST /Operations/Reload', 'POST /Operations/Reload', 'POST /Operations/Reload']);
    expect(Log.Unexpected).toEqual([]);
});

test('incomplete Session identity cannot select a same-ID row; exact empty lookup preserves retired target and reads Trace', async ({ page }) => {
    let ExactSessionReads = 0;
    let TraceReads = 0;
    const Collision = SessionWire({ Process: '41', Generation: '5' });
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname.endsWith('/Trace')) TraceReads += 1;
        const Common = SessionRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Sessions') {
            if (Url.searchParams.has('id')) {
                ExactSessionReads += 1;
                return { Body: Ok(PageWire([])) };
            }
            return { Body: Ok(PageWire([Collision])) };
        }
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        if (Url.pathname.endsWith('/Trace')) return { Body: Ok(TracePageWire()) };
        throw new Error('No Session identity fixture for this endpoint.');
    });
    await page.goto('/sessions?source=live&range=1h&session=55');
    await expect(page.getByText('Session 身份字段不足', { exact: true })).toBeVisible();
    expect(ExactSessionReads).toBe(0);
    expect(TraceReads).toBe(0);
    expect(new URL(page.url()).searchParams.get('session')).toBe('55');
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Streams') || Request.Path.endsWith('/Tasks'))).toEqual([]);

    await page.goto('/sessions?source=live&range=1h&session=55&process=42&identity_worker=7&identity_account=8&generation=6');
    await expect(page.getByText('Session 已退出当前活动清单', { exact: true })).toBeVisible();
    await expect(page.getByText(/留存 Trace/)).toBeVisible();
    await expect(page.locator('.session-inspector')).toHaveCount(0);
    await expect(page).toHaveURL(/session=55.*process=42.*identity_worker=7.*identity_account=8.*generation=6/);
    expect(ExactSessionReads).toBeGreaterThan(0);
    expect(TraceReads).toBeGreaterThan(0);
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Streams') || Request.Path.endsWith('/Tasks'))).toEqual([]);
    ExpectMockWasReadOnly(Log);
});

test('verified active Session exposes guarded actions, keeps last success during poll, then marks a failed poll unknown', async ({ page }, TestInfo) => {
    let ExactReadCount = 0;
    let ExactStatusFailed = false;
    let NotifyInitialRead: (() => void) | null = null;
    let ReleaseInitialRead: ((Reply: FixtureReply) => void) | null = null;
    const InitialReadStarted = new Promise<void>(Resolve => { NotifyInitialRead = Resolve; });
    let NotifySecondRead: (() => void) | null = null;
    let ReleaseSecondRead: ((Reply: FixtureReply) => void) | null = null;
    const SecondReadStarted = new Promise<void>(Resolve => { NotifySecondRead = Resolve; });
    const ActiveSession = SessionWire();
    const Log = await InstallOperationsGetMock(page, async Url => {
        if (ExactStatusFailed && (Url.pathname.endsWith('/Streams') || Url.pathname.endsWith('/Tasks')))
            throw new Error('Session child GET must stop after exact status becomes unknown.');
        const Common = SessionRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Sessions') {
            if (Url.searchParams.has('id')) {
                ExactReadCount += 1;
                if (ExactReadCount === 1) {
                    NotifyInitialRead?.();
                    return await new Promise<FixtureReply>(Resolve => { ReleaseInitialRead = Resolve; });
                }
                if (ExactReadCount === 2) {
                    NotifySecondRead?.();
                    return await new Promise<FixtureReply>(Resolve => { ReleaseSecondRead = Resolve; });
                }
                ExactStatusFailed = true;
                return { Status: 503, Body: { status: 'error', message: 'Fixture status revalidation failed.' } };
            }
            return { Body: Ok(PageWire([ActiveSession])) };
        }
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error('No active Session fixture for this endpoint.');
    });
    await page.goto('/sessions?source=live&session=55&process=42&identity_worker=7&identity_account=8&generation=6');
    await InitialReadStarted;
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Streams') || Request.Path.endsWith('/Tasks'))).toEqual([]);
    await expect(page.locator('.session-inspector').getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
    ReleaseInitialRead?.({ Body: Ok(PageWire([ActiveSession])) });
    await page.locator('.session-inspector').waitFor();
    await expect(page.locator('.session-inspector')).toContainText('活动中');
    await expect(page.locator('.session-inspector').getByRole('button', { name: '取消 Session', exact: true })).toBeVisible();
    const Tabs = page.locator('.session-detail-tabs [role=tab]');
    await Tabs.nth(1).click();
    const StreamReads = Log.Requests.filter(Request => Request.Path.endsWith('/Streams')).length;
    expect.soft(StreamReads, `Verified Session should load its exact Streams fixture; observed requests: ${JSON.stringify(Log.Requests)}`).toBeGreaterThan(0);
    if (StreamReads > 0) {
        expect(Log.Requests.find(Request => Request.Path.endsWith('/Streams'))).toMatchObject({
            Method: 'GET', Path: '/Operations/Processes/42/Sessions/55/Streams',
            Search: '?cursor=0&limit=50&generation=6&worker=7',
        });
        await expect(page.locator('.session-detail-tabs')).toContainText('Streams 1');
        await expect(page.getByRole('button', { name: '重置', exact: true })).toBeVisible();
    }
    await Tabs.nth(2).click();
    const TaskReads = Log.Requests.filter(Request => Request.Path.endsWith('/Tasks')).length;
    expect.soft(TaskReads, `Verified Session should load its exact Tasks fixture; observed requests: ${JSON.stringify(Log.Requests)}`).toBeGreaterThan(0);
    if (TaskReads > 0) {
        expect(Log.Requests.find(Request => Request.Path.endsWith('/Tasks'))).toMatchObject({
            Method: 'GET', Path: '/Operations/Processes/42/Workers/7/Sessions/55/Tasks',
            Search: '?cursor=0&limit=50&generation=6',
        });
        await expect(page.locator('.session-detail-tabs')).toContainText('Tasks 1');
        await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toBeVisible();
    }

    await SecondReadStarted;
    try {
        await expect(page.locator('.session-inspector')).toContainText('活动中');
        await expect(page.locator('.session-inspector').getByText('正在复核 Session', { exact: true })).toBeVisible({ timeout: 1_500 });
        await expect(page.getByText('当前 Session 状态无法确认', { exact: true })).toHaveCount(0);
        await expect(page.locator('.session-inspector').getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '重置', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toHaveCount(0);
        if (TestInfo.project.name === 'chromium-1920')
            await page.screenshot({ path: TestInfo.outputPath('session-refreshing.png'), fullPage: true });
    } finally {
        ReleaseSecondRead?.({ Status: 503, Body: { status: 'error', message: 'Fixture status revalidation failed.' } });
    }
    await expect(page.locator('.session-inspector')).toContainText('当前 Session 状态无法确认');
    await expect(page.locator('.session-inspector')).toContainText('精确查询失败');
    await expect(page.locator('.session-inspector')).toContainText('最后观察到的状态：活动中');
    await expect(page.locator('.session-inspector')).toContainText('读取时间');
    await expect(page.locator('.session-inspector')).toContainText('Streams 待核实');
    await expect(page.locator('.session-inspector')).toContainText('Tasks 待核实');
    await expect(page.locator('.session-inspector').getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toHaveCount(0);
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('session-status-unknown.png'), fullPage: true });
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Streams')).length).toBeGreaterThan(0);
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Tasks')).length).toBeGreaterThan(0);
    ExpectMockWasReadOnly(Log);
});

test('old Worker generation is not selected until user opens current generation; zero capacity has no usage bar', async ({ page }) => {
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = AccountRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap() };
        if (Url.pathname === '/Operations/Workers') return { Body: Ok(PageWire([WorkerWire('6')])) };
        if (Url.pathname === '/Operations/Sessions') return { Body: Ok(EmptyCollection) };
        throw new Error('No Worker target fixture for this endpoint.');
    });
    await page.goto('/workers?source=live&range=1h&worker=7&process=42&generation=5');
    await expect(page.getByText('Worker 目标已变更', { exact: true })).toBeVisible();
    await expect(page.locator('.worker-inspector')).toHaveCount(0);
    await expect(page.getByRole('link', { name: '打开当前代次的 Worker', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('generation')).toBe('5');

    await page.getByRole('link', { name: '打开当前代次的 Worker', exact: true }).click();
    await expect(page).toHaveURL(/worker=7.*process=42.*generation=6/);
    await expect(page.locator('.worker-inspector')).toBeVisible();
    await expect(page.getByText('容量为 0，使用率不可计算。', { exact: true })).toBeVisible();
    await expect(page.locator('.worker-comparison-table .progress-bar')).toHaveCount(0);
    ExpectMockWasReadOnly(Log);
});

test('operation from a previous incarnation is not queried in the current process until explicit navigation', async ({ page }) => {
    let StatusReads = 0;
    const Operation = OperationWire();
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap() };
        if (Url.pathname === '/Operations/Operations') return { Body: Ok(PageWire([Operation])) };
        if (Url.pathname === '/Operations/Operations/17') { StatusReads += 1; return { Body: Operation }; }
        throw new Error('No operation identity fixture for this endpoint.');
    });
    await page.goto(`/operations?source=live&range=1h&operation=17&process=42&incarnation=${PreviousIncarnation}`);
    if (await page.getByText('页面显示异常', { exact: true }).count()) {
        await page.locator('details summary').filter({ hasText: '开发诊断' }).click();
        throw new Error('Operations page render failed: ' + await page.locator('details code').innerText());
    }
    await expect(page.getByText('来源实例已变，未查询同号操作', { exact: true })).toBeVisible();
    expect(StatusReads).toBe(0);
    expect(new URL(page.url()).searchParams.get('incarnation')).toBe(PreviousIncarnation);

    await page.getByRole('link', { name: '查看当前实例操作列表' }).click();
    await expect(page).toHaveURL(new RegExp(`operation=17.*process=42.*incarnation=${CurrentIncarnation}`));
    await expect(page.locator('.operation-inspector')).toBeVisible();
    await expect(page.locator('.operation-inspector')).toContainText('当前状态 · 最近成功读取');
    expect(StatusReads).toBeGreaterThan(0);
    ExpectMockWasReadOnly(Log);
});
