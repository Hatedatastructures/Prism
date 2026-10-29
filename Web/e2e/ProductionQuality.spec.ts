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
function OperationWire(Status = 'accepted', Id = '17', Process = '42', Generation = '6'): unknown {
    return { id: Id, status: Status, command: 'DrainWorker', accepted_at: Timestamp, updated_at: OtherTimestamp,
        message: 'Mock operation record', correlation: '77', generation: Generation, process: Process, worker: '7', account: '8',
        session: '55', stream: '0', task: '0', parent_task: '0', failure: null };
}
function HistoryWire(): unknown {
    return { sampled_at: OtherTimestamp, from: Timestamp, to: OtherTimestamp, resolution_ms: '1000',
        coverage: 'browser GET fixture', gaps: [], items: [{ time: Timestamp, up_bytes: '0', down_bytes: '0', active: null,
            p50_us: null, p95_us: null, p99_us: null, sample_count: '1', quality: null }] };
}
function MetricsWire(Generation = '6'): unknown {
    return { process: '42', generation: Generation, checked_at: Timestamp, traffic: TrafficZero,
        observations: { accepted: '100', consumed: '98', dropped: '2', aggregation_failures: '1', recognition_latency_queue_dropped: '1',
            recognition_latency_aggregation_failures: '1', retirement_failures: { session: '3', stream: '2', task: '1' } },
        sample_interval_ms: '1000', history_ready: false, history: [], recognition_latency: { sample_boundary: 'recognition_admission', unit: 'microseconds',
            generation: Generation, ready: true, sample_count: '10', tracer_written: '9', tracer_dropped: '1', histogram_range_exceeded: '0',
            recent_us: ['55', '0'], p50_bucket_lower_bound_us: '0', p95_bucket_lower_bound_us: '32', p99_bucket_lower_bound_us: '32', max_observed_us: '70' } };
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
    const MobileNavigation = Page.getByRole('button', { name: '展开或收起导航', exact: true });
    if ((Page.viewportSize()?.width ?? 0) < 768 && await MobileNavigation.isVisible()) await MobileNavigation.click();
    const NavigationName = Name === '事件流' ? '事件' : Name;
    await Page.getByRole('link', { name: NavigationName, exact: true }).click();
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
    if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['sessions.filter', 'events.filter.process', 'events.filter.generation']) };
    if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
    if (Url.pathname.endsWith('/Trace')) return { Body: Ok(TracePageWire()) };
    if (Url.pathname.endsWith('/Streams')) return { Body: Ok(PageWire([StreamWire()])) };
    if (Url.pathname.endsWith('/Tasks')) return { Body: Ok(PageWire([TaskWire()])) };
    return null;
}

test('Session relations show failures, recover and paginate without inventing an empty trace', async ({ page }) => {
    let TraceRequests = 0;
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Sessions') return { Body: Ok(PageWire([SessionWire()])) };
        if (Url.pathname.endsWith('/Trace')) {
            TraceRequests += 1;
            if (TraceRequests === 1) return { Status: 503, Body: { status: 'error', message: 'trace unavailable' } };
            return { Body: Ok({ ...PageWire([], 'cursor-next', TraceRequests === 2), lost: true, cursors: [], lost_ranges: [] }) };
        }
        const Related = SessionRelatedReply(Url);
        if (Related) return Related;
        throw new Error(`No Session fixture for ${Url.pathname}.`);
    });
    await page.goto('/sessions?source=live');
    await page.getByRole('button', { name: '暂停刷新', exact: true }).click();
    await page.getByRole('row').filter({ has: page.getByRole('button', { name: '55', exact: true }) })
        .click({ position: { x: 300, y: 10 } });
    await expect(page).toHaveURL(/session=55.*process=42.*identity_worker=7.*identity_account=8.*generation=6/);
    const SessionDetail = page.getByRole('region', { name: 'Session 55 详情', exact: true });
    await expect(SessionDetail).toBeVisible();
    await expect(SessionDetail.getByRole('tab', { name: /^阶段/ })).toBeVisible();
    await page.getByRole('tab', { name: /^阶段/ }).click();
    await expect(page.getByText('阶段记录暂时无法载入')).toBeVisible();
    await expect(page.getByText('没有留存阶段')).toHaveCount(0);
    await page.getByRole('button', { name: '重试读取' }).click();
    await expect(page.getByText('阶段记录存在缺口')).toBeVisible();
    await page.getByRole('button', { name: '载入更多', exact: true }).click();
    await expect.poll(() => TraceRequests).toBeGreaterThanOrEqual(3);
    await expect(page.getByRole('button', { name: '载入更多', exact: true })).toHaveCount(0);
    await page.getByRole('tab', { name: /^概览/ }).click();
    await expect(page.getByRole('button', { name: '取消 Session' })).toBeDisabled();
    ExpectMockWasReadOnly(Log);
});

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
    const VisibleEventList = page.getByRole('table');
    await expect(VisibleEventList.getByText('warning-row', { exact: true })).toBeVisible();
    const WorkerLink = VisibleEventList.getByRole('link', { name: '7', exact: true }).first();
    const WorkerHref = await WorkerLink.getAttribute('href');
    const WorkerTarget = new URL(WorkerHref ?? '', page.url());
    expect(WorkerTarget.searchParams.get('worker')).toBe('7');
    expect(WorkerTarget.searchParams.get('process')).toBe('42');
    expect(WorkerTarget.searchParams.get('generation')).toBe('6');
    await page.getByRole('button', { name: '暂停追随', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: '事件追随已暂停' })).toBeVisible();

    await page.getByRole('group', { name: '按严重级别筛选', exact: true }).getByRole('button', { name: '错误', exact: true }).click();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=error/);
    await expect(VisibleEventList.getByText('error-row', { exact: true })).toBeVisible();
    await expect(page.getByRole('alert').filter({ hasText: '事件追随已暂停' })).toHaveCount(0);
    await page.goBack();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=warning/);
    await expect(VisibleEventList.getByText('warning-row', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '暂停追随', exact: true })).toBeVisible();
    await page.goForward();
    await expect(page).toHaveURL(/source=live.*range=15m.*severity=error/);
    await expect(VisibleEventList.getByText('error-row', { exact: true })).toBeVisible();
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
    const IsMobile = (page.viewportSize()?.width ?? 0) <= 767;
    await page.goto(`/user-groups?source=live&range=1h&group=target-late${IsMobile ? '&mobile_view=list' : ''}`);
    const Directory = page.getByRole('region', { name: '用户组目录', exact: true });
    const Inspector = page.getByRole('region', { name: '用户组详情', exact: true });
    if (!IsMobile) {
        await expect(page.getByText('未在当前已载入范围找到指定组', { exact: true })).toBeVisible();
        await expect(Inspector).toContainText('选择一个用户组');
        await expect(Inspector).not.toContainText('目标晚到组');
        await expect(page.getByText('已载入组中 1 / 2 提供计数', { exact: true }).first()).toBeVisible();
    } else {
        await expect(Directory).toBeVisible();
        await expect(Inspector).toBeHidden();
    }
    expect(new URL(page.url()).searchParams.get('group')).toBe('target-late');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');

    await Directory.getByRole('button', { name: '载入更多用户组', exact: true }).click();
    if (IsMobile) await Directory.getByRole('button', { name: /目标晚到组/ }).click();
    await expect(Inspector).toContainText('目标晚到组');
    await Inspector.getByRole('tab', { name: '活动范围', exact: true }).click();
    await expect(Inspector).toContainText('组快照根连接');
    await expect(Inspector).toContainText('0');
    await expect(page.getByText('已载入组中 2 / 3 提供计数', { exact: true }).first()).toBeVisible();
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
    await page.getByRole('searchbox', { name: '搜索账户' }).fill('northstar');
    const AccountRows = page.getByRole('list', { name: '账户列表', exact: true }).getByRole('listitem');
    await expect(AccountRows).toHaveCount(1);
    await expect(page).toHaveURL(/source=live.*q=northstar/);
    await page.getByRole('searchbox', { name: '搜索账户' }).fill('');
    await expect(page).toHaveURL(/source=live/);
    expect(new URL(page.url()).searchParams.has('q')).toBe(false);
    await expect(AccountRows).toHaveCount(2);
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
    await page.goto(`/accounts?source=live&range=15m&account=8${(page.viewportSize()?.width ?? 0) <= 767 ? '&mobile_view=detail' : ''}`);
    await expect(page.getByRole('region', { name: '账户详情', exact: true })).toContainText('northstar');
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    await expect(page.locator('.usage-section')).toContainText('accounts.usage.read');
    expect(Log.Requests.filter(Request => Request.Path === '/Operations/AccountUsage')).toHaveLength(0);
    expect(Log.Requests.filter(Request => Request.Path === '/Operations/History')).toHaveLength(0);
    ExpectMockWasReadOnly(Log);
});

test('账户余额缺测与零额度不伪装成满额使用率', async ({ page }) => {
    let Remaining: string | null = null;
    let Limit = '100';
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = AccountRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['accounts.usage.read']) };
        if (Url.pathname === '/Operations/Groups') return { Body: Ok(EmptyCollection) };
        if (Url.pathname === '/Operations/Accounts') return { Body: Ok(PageWire([AccountWire('8', 'northstar')])) };
        if (Url.pathname === '/Operations/AccountUsage') return { Body: Ok({ account_key: 'key-8', revision: '1',
            cycle_start: Timestamp, cycle_end: OtherTimestamp, limit_bytes: Limit, remaining_bytes: Remaining,
            settled_bytes: '0', reserved_bytes: '0', uncertain_bytes: '0', overage_bytes: '0', available: true, failure: null }) };
        throw new Error('Unexpected account usage endpoint');
    });
    await page.goto('/accounts?source=live&account=8&mobile_view=detail');
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    await expect(page.getByText('余额未提供，无法计算占用比例。', { exact: true })).toBeVisible();
    await expect(page.getByRole('progressbar', { name: '额度已占用比例', exact: true })).toHaveCount(0);
    Limit = '0'; Remaining = '0';
    await page.reload();
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    await expect(page.getByText('周期额度为 0，不计算占用比例。', { exact: true })).toBeVisible();
    await expect(page.getByRole('progressbar', { name: '额度已占用比例', exact: true })).toHaveCount(0);
    Limit = '100'; Remaining = '90';
    await page.reload();
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    await expect(page.getByRole('progressbar', { name: '额度已占用比例', exact: true })).toHaveAttribute('aria-valuenow', '10');
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
    await page.getByRole('tab', { name: '周期额度', exact: true }).click();
    const Balance = page.getByText('可用余额', { exact: true }).locator('..').locator('p').last();
    await expect(Balance).toBeVisible();
    const InitialBalance = await Balance.innerText();
    const Adjustment = async (Reason: string): Promise<string> => {
        const BalanceBefore = await Balance.innerText();
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
        await expect(Balance).not.toHaveText(BalanceBefore);
        return Balance.innerText();
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
    await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
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
    const StaleNotice = page.getByRole('alert').filter({ has: page.getByRole('textbox', { name: '旧来源草稿，只读', exact: true }) });
    await expect(StaleNotice).toContainText('已读取目标实例配置；请核对下方来源与 Generation 后确认重基线。');
    const PreparationReads = Log.Requests.slice(PreparationStart).filter(Request => Request.Method === 'GET' &&
        ['/Operations/Bootstrap', '/Operations/Configuration'].includes(Request.Path)).map(Request => Request.Path);
    const ConfigurationReadIndex = PreparationReads.lastIndexOf('/Operations/Configuration');
    expect(ConfigurationReadIndex).toBeGreaterThan(0);
    expect(PreparationReads[ConfigurationReadIndex - 1]).toBe('/Operations/Bootstrap');
    expect(PreparationReads[ConfigurationReadIndex + 1]).toBe('/Operations/Bootstrap');
    await expect(StaleNotice).toContainText('Generation generation-candidate');
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('configuration-stale-candidate.png'), fullPage: true });

    CandidatePrepared = true;
    ConfigurationGeneration = 'generation-current';
    ConfigurationValue = PublicConfiguration(4_000);
    const ConfirmRebase = async (): Promise<void> => {
        await page.getByRole('button', { name: '确认以该基线重建', exact: true }).click();
        await page.getByRole('dialog').getByRole('button', { name: '确认重建并重新校验', exact: true }).click();
    };
    await ConfirmRebase();
    await expect(page.getByText('目标配置在确认期间已变化；已刷新候选基线，请再次核对新 Generation 并确认。', { exact: true })).toBeVisible();
    await expect(StaleNotice).toContainText('Generation generation-current');
    await expect(StaleDraft).toHaveValue(DraftText);
    if (TestInfo.project.name === 'chromium-1920')
        await page.screenshot({ path: TestInfo.outputPath('configuration-generation-conflict.png'), fullPage: true });
    expect(CandidatePrepared).toBe(true);

    await ConfirmRebase();
    await expect(StaleNotice).toHaveCount(0);
    await expect(Editor).toHaveValue(DraftText);
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeEnabled();
    expect(CommandBodies).toHaveLength(2);
    expect(CommandBodies[1]).toMatchObject({ mode: 'validate_only', base_generation: 'generation-current' });

    await page.getByRole('button', { name: '应用配置', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: '确认发布', exact: true }).click();
    await expect(page.getByRole('status').filter({ hasText: 'Apply 已受理或结果未核实' })).toBeVisible();
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(page.getByRole('alert').filter({ hasText: '请求结果未确认' })).toHaveCount(2);
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

test('Session snapshots retain observed exits for review without treating a missed session as closed', async ({ page }, TestInfo) => {
    let ListReads = 0;
    let ExactReads = 0;
    let RefreshRequested = false;
    let SessionNoLongerActive = false;
    const FirstSession = SessionWire();
    const NextSession = { ...SessionWire(), id: '56', started_at: OtherTimestamp,
        source_address: '192.0.2.11:48001', target: '198.51.100.21:443' };
    const Log = await InstallOperationsGetMock(page, Url => {
        const Common = SessionRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Sessions') {
            if (Url.searchParams.has('id')) {
                ExactReads += 1;
                return { Body: Ok(PageWire(SessionNoLongerActive ? [] : [FirstSession])) };
            }
            ListReads += 1;
            if (RefreshRequested) SessionNoLongerActive = true;
            return { Body: Ok(PageWire(RefreshRequested ? [NextSession] : [FirstSession])) };
        }
        throw new Error('No Session snapshot fixture for this endpoint.');
    });
    await page.goto('/sessions?source=live');
    await page.getByRole('button', { name: '暂停刷新', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(1);
    await page.getByRole('row').filter({ has: page.getByRole('button', { name: '55', exact: true }) })
        .click({ position: { x: 300, y: 10 } });
    const SelectedDetail = page.getByRole('region', { name: 'Session 55 详情', exact: true });
    await expect(SelectedDetail).toContainText('Process 42 · Generation 6');
    await expect(SelectedDetail).toContainText('活动中');

    const Width = page.viewportSize()?.width ?? 0;
    if (Width <= 767) {
        await page.getByRole('button', { name: '返回连接列表', exact: true }).click();
        await page.getByRole('button', { name: '55', exact: true }).click();
    }
    RefreshRequested = true;
    await page.getByRole('button', { name: '刷新列表', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('56');
    const RecentTab = page.getByRole('tab', { name: /最近离开.*1/ });
    await expect(RecentTab).toBeVisible();
    await RecentTab.click();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(1);
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('55');
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toContainText('未见于最新快照');
    if (Width <= 767) {
        await page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')
            .filter({ has: page.getByRole('button', { name: '55', exact: true }) }).click();
        await expect(page.getByRole('region', { name: 'Session 55 详情', exact: true })).toBeVisible();
    }
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('已退出当前活动清单');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
    await page.screenshot({ path: TestInfo.outputPath('session-observed-exit.png'), animations: 'disabled' });
    if (Width <= 767) {
        await page.getByRole('button', { name: '返回连接列表', exact: true }).click();
        await expect(page.locator('[data-mobile-master-list]')).toBeFocused();
    }
    const CurrentTab = page.getByRole('tab', { name: /当前活动/ });
    await RecentTab.focus();
    await expect(RecentTab).toBeFocused();
    await page.keyboard.press('ArrowLeft');
    await expect(CurrentTab).toHaveAttribute('aria-selected', 'true');
    await page.keyboard.press('ArrowRight');
    await expect(RecentTab).toHaveAttribute('aria-selected', 'true');
    const ScopeButton = page.getByRole('button', { name: '留存范围', exact: true });
    await ScopeButton.click();
    await expect(page.getByRole('dialog'))
        .toContainText('两次采样之间建立并结束的连接没有出现在任何快照中');
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toHaveCount(0);
    await expect(ScopeButton).toBeFocused();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).not.toContainText('已结束');
    await page.getByRole('button', { name: '清空本页留存', exact: true }).click();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(0);
    await expect(page.getByText('本页暂无最近离开的连接', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '刷新列表', exact: true }).click();
    await expect(page.getByRole('tab', { name: /最近离开.*0/ })).toBeVisible();
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(0);
    expect(ListReads).toBe(4);
    expect(ExactReads).toBeGreaterThan(Width <= 767 ? 0 : 1);
    ExpectMockWasReadOnly(Log);
});

test('incomplete Session identity cannot select a same-ID row or read child resources', async ({ page }) => {
    let ExactSessionReads = 0;
    let TraceReads = 0;
    const Collision = SessionWire({ Process: '41', Generation: '5' });
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname.endsWith('/Trace')) TraceReads += 1;
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire([EventWire('42', 'warning', '留存事件详情')])) };
        const Common = SessionRelatedReply(Url);
        if (Common) return Common;
        if (Url.pathname === '/Operations/Sessions') {
            if (Url.searchParams.has('id')) {
                ExactSessionReads += 1;
                return { Body: Ok(PageWire([])) };
            }
            return { Body: Ok(PageWire([Collision])) };
        }
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
    const Detail = page.getByRole('region', { name: 'Session 55 详情', exact: true });
    await expect(Detail).toBeVisible();
    await expect(Detail).toContainText('没有精确身份匹配的活动 Session');
    await expect(Detail.getByRole('button', { name: '重新核对此 Session', exact: true })).toBeVisible();
    await expect(page).toHaveURL(/session=55.*process=42.*identity_worker=7.*identity_account=8.*generation=6/);
    expect(ExactSessionReads).toBeGreaterThan(0);
    expect(TraceReads).toBe(0);
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Streams') || Request.Path.endsWith('/Tasks'))).toEqual([]);
    expect(Log.Requests.filter(Request => Request.Path.endsWith('/Trace'))).toEqual([]);
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
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
    ReleaseInitialRead?.({ Body: Ok(PageWire([ActiveSession])) });
    await page.getByRole('region', { name: /^Session .* 详情$/ }).waitFor();
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('活动中');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('button', { name: '取消 Session', exact: true })).toBeVisible();
    const Detail = page.getByRole('region', { name: /^Session .* 详情$/ });
    const Tabs = Detail.getByRole('tablist').getByRole('tab');
    await Tabs.nth(2).click();
    const StreamReads = Log.Requests.filter(Request => Request.Path.endsWith('/Streams')).length;
    expect.soft(StreamReads, `Verified Session should load its exact Streams fixture; observed requests: ${JSON.stringify(Log.Requests)}`).toBeGreaterThan(0);
    if (StreamReads > 0) {
        expect(Log.Requests.find(Request => Request.Path.endsWith('/Streams'))).toMatchObject({
            Method: 'GET', Path: '/Operations/Processes/42/Sessions/55/Streams',
            Search: '?cursor=0&limit=50&generation=6&worker=7',
        });
        await expect(Detail.getByRole('tablist')).toContainText('Streams 1');
        await expect(page.getByRole('button', { name: '重置', exact: true })).toBeVisible();
    }
    await Tabs.nth(3).click();
    const TaskReads = Log.Requests.filter(Request => Request.Path.endsWith('/Tasks')).length;
    expect.soft(TaskReads, `Verified Session should load its exact Tasks fixture; observed requests: ${JSON.stringify(Log.Requests)}`).toBeGreaterThan(0);
    if (TaskReads > 0) {
        expect(Log.Requests.find(Request => Request.Path.endsWith('/Tasks'))).toMatchObject({
            Method: 'GET', Path: '/Operations/Processes/42/Workers/7/Sessions/55/Tasks',
            Search: '?cursor=0&limit=50&generation=6',
        });
        await expect(Detail.getByRole('tablist')).toContainText('Tasks 1');
        await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toBeVisible();
    }

    await SecondReadStarted;
    try {
        await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('活动中');
        await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByText('正在复核 Session', { exact: true })).toBeVisible({ timeout: 1_500 });
        await expect(page.getByText('当前 Session 状态无法确认', { exact: true })).toHaveCount(0);
        await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '重置', exact: true })).toHaveCount(0);
        await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toBeDisabled();
        if (TestInfo.project.name === 'chromium-1920')
            await page.screenshot({ path: TestInfo.outputPath('session-refreshing.png'), fullPage: true });
    } finally {
        ReleaseSecondRead?.({ Status: 503, Body: { status: 'error', message: 'Fixture status revalidation failed.' } });
    }
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('当前 Session 状态无法确认');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('精确查询失败');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('最后观察到的状态：活动中');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('读取时间');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('Streams 待核实');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ })).toContainText('Tasks 待核实');
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('button', { name: '取消 Session', exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '取消 Task', exact: true })).toBeDisabled();
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
    const Directory = page.getByRole('region', { name: 'Worker 清单', exact: true });
    const Inspector = page.getByRole('region', { name: 'Worker 详情', exact: true });
    await expect(Inspector).toContainText('深链目标未通过身份核验，不会用同号槽位代替原目标。');
    if ((page.viewportSize()?.width ?? 0) <= 767)
        await Inspector.getByRole('button', { name: '返回 Worker 列表', exact: true }).click();
    await expect(Directory.getByRole('button', { name: /Worker 7.*Gen 6/ })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('generation')).toBe('5');

    await Directory.getByRole('button', { name: /Worker 7.*Gen 6/ }).click();
    await expect(page).toHaveURL(/worker=7.*process=42.*generation=6/);
    await expect(Inspector.getByText('容量为 0，无法计算使用率。', { exact: true })).toBeVisible();
    await expect(Inspector.getByRole('progressbar')).toHaveCount(0);
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
    await expect(page.getByRole('alert')).toContainText('操作来源实例已变化或链接范围不完整');
    expect(StatusReads).toBe(0);
    expect(new URL(page.url()).searchParams.get('incarnation')).toBe(PreviousIncarnation);

    await page.goto('/operations?source=live&range=1h');
    await page.getByRole('button', { name: /DrainWorker/ }).click();
    await expect(page).toHaveURL(new RegExp(`operation=17.*process=42.*incarnation=${CurrentIncarnation}`));
    const SelectedOperation = page.getByRole('row').filter({ has: page.getByRole('button', { name: 'DrainWorker 17', exact: true }) });
    await expect(SelectedOperation).toContainText('已接收');
    await expect(page.getByRole('tabpanel', { name: '结果', exact: true })).toContainText('Mock operation record');
    await expect(page.getByRole('tab', { name: '结果', exact: true })).toBeVisible();
    expect(StatusReads).toBeGreaterThan(0);
    ExpectMockWasReadOnly(Log);
});

test('Overview manual refresh reports a collection failure without claiming an update', async ({ page }) => {
    let FailAccounts = false;
    let AccountReads = 0;
    let AccountFailures = 0;
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['history.read']) };
        if (Url.pathname === '/Operations/History') return { Body: Ok(HistoryWire()) };
        if (Url.pathname === '/Operations/Workers') return { Body: Ok(PageWire([WorkerWire()])) };
        if (Url.pathname === '/Operations/Ingresses') return { Body: Ok(PageWire([])) };
        if (Url.pathname === '/Operations/Accounts') {
            AccountReads += 1;
            if (FailAccounts) {
                AccountFailures += 1;
                return { Status: 503, Body: { status: 'error', message: 'Fixture account collection failure.' } };
            }
            return { Body: Ok(PageWire([AccountWire('8', 'refresh-fixture-account')])) };
        }
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error(`No Overview refresh fixture for ${Url.pathname}.`);
    });

    await page.goto('/?source=live&range=1h');
    await expect(page.locator('main h1')).toHaveText('运行概览');
    const RefreshButton = page.locator('.overview-refresh-button');
    await expect(RefreshButton).toBeEnabled();
    await expect(RefreshButton).toHaveText('刷新');
    expect(AccountReads).toBeGreaterThan(0);

    FailAccounts = true;
    await RefreshButton.click();
    await expect(RefreshButton).toHaveAttribute('data-refresh-state', 'error');
    await expect(RefreshButton).toHaveText('刷新失败');
    const Feedback = page.locator('.overview-refresh-feedback');
    await expect(Feedback).toHaveAttribute('role', 'status');
    await expect(Feedback).toHaveAttribute('aria-live', 'polite');
    await expect(Feedback).toHaveText('刷新失败，请重试。');
    await expect(RefreshButton).not.toHaveText('已更新');
    expect(AccountFailures).toBeGreaterThan(0);
    ExpectMockWasReadOnly(Log);
});

test('overview shows scoped backend readings and marks stale samples', async ({ page }) => {
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap() };
        if (Url.pathname === '/Operations/Workers') return { Body: Ok(PageWire([WorkerWire()])) };
        if (Url.pathname === '/Operations/Ingresses') return { Body: Ok(PageWire([])) };
        if (Url.pathname === '/Operations/Accounts') return { Body: Ok(PageWire([AccountWire('8', 'northstar')])) };
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error(`No overview fixture for ${Url.pathname}.`);
    });
    await page.goto('/?source=live');
    const Status = page.getByRole('region', { name: '运行状态与数据质量' });
    await expect(Status).toContainText('运行快照已过期');
    await expect(Status).toContainText('Process 42 · G6');
    await expect(Status).toContainText('识别样本 未提供');
    await expect(Status).toContainText('进程 RSS 未提供');
    const Metrics = page.getByRole('region', { name: '运行指标' });
    const DownRate = Metrics.getByText('下行速率', { exact: true }).locator('..').locator('dd');
    await expect(DownRate.nth(0)).toHaveText('0 B/s');
    await expect(DownRate.nth(1)).toHaveText('累计 0 B');
    await expect(Metrics).toContainText('UDP 未提供 · QUIC 未提供');
    await expect(page.getByRole('columnheader', { name: '派发队列满（累计）' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: '命令失败（累计）' })).toBeVisible();
    const Overview = OverviewWire() as { [Key: string]: unknown; traffic: Record<string, unknown> };
    await page.route('**/Operations/Overview', async Route => {
        const Value = { ...Overview, traffic: { ...Overview.traffic, available: false, up_bytes_per_second: '123', down_bytes_per_second: '456' } };
        await Route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(Ok(Value)) });
    });
    await page.reload();
    await expect(DownRate.nth(0)).toHaveText('—');
    await expect(DownRate.nth(1)).toHaveText('累计 未提供');
    const UpRate = page.getByRole('region', { name: '运行指标' })
        .getByText('上行速率', { exact: true }).locator('..').locator('dd');
    await expect(UpRate.nth(0)).toHaveText('—');
    await expect(UpRate.nth(1)).toHaveText('累计 未提供');
    await expect(page.getByRole('region', { name: '运行指标' })).not.toContainText('456 B/s');
    ExpectMockWasReadOnly(Log);
});

test('resource charts use verified live samples for allocator rates and admission latency', async ({ page }) => {
    let MetricsReads = 0;
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['metrics.read']) };
        if (Url.pathname === '/Operations/Metrics') return { Body: Ok({ ...(MetricsWire() as Record<string, unknown>), checked_at: new Date(Date.parse(Timestamp) + ++MetricsReads * 5000).toISOString() }) };
        throw new Error(`No resource fixture for ${Url.pathname}.`);
    });
    let Reads = 0;
    await page.route('**/Operations/Overview', async Route => {
        Reads += 1;
        const Base = OverviewWire() as { memory: Record<string, unknown>; latency: Record<string, unknown> };
        const Allocation = { available: true, current_bytes: '65536', peak_bytes: '131072', allocation_count: String(1000 + Reads * 200), release_count: String(800 + Reads * 100), coverage: 'Process TrackingResource' };
        const Value = { ...Base, sampled_at: new Date(Date.parse(Timestamp) + Reads * 5000).toISOString(),
            memory: { ...Base.memory, process_available: true, process_rss_bytes: '1048576', process_peak_rss_bytes: '2097152', allocations: Allocation,
                worker_allocations: [{ worker_id: '7', allocation: { ...Allocation, coverage: 'Worker TrackingResource' } }],
                byte_pool: { available: true, used_bytes: '65536', capacity_bytes: '131072', available_blocks: '1', block_size: '65536', peak_used_bytes: '65536', allocation_count: String(500 + Reads * 100), release_count: String(400 + Reads * 50) } },
            latency: { ...Base.latency, recognition_admission: { name: 'recognition_admission', available: true, sample_count: '10', p50_ms: '1', p95_ms: '4', p99_ms: '8', max_ms: '10' } } };
        await Route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(Ok(Value)) });
    });
    await page.goto('/resources?source=live');
    await expect(page.getByText('内存分配耗时未采集；分位值为整数毫秒桶下界。')).toBeVisible();
    const WorkerCoverage = page.locator('details').filter({ hasText: 'Worker TrackingResource' });
    await WorkerCoverage.locator('summary').click();
    await expect(WorkerCoverage).toContainText('Worker TrackingResource');
    await page.locator('details').filter({ hasText: '诊断明细' }).locator('summary').click();
    await expect(page.getByText('32 µs', { exact: true })).toHaveCount(2);
    await expect(page.getByRole('list', { name: '近期识别准入样本（新到旧）' })).toContainText('55 µs');
    await expect(page.getByText('其中识别延迟丢弃', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '刷新指标' }).click();
    const LatencyChart = page.getByRole('group', { name: /识别准入累计延迟分位桶下界，单位微秒/ });
    await expect(LatencyChart).toBeVisible();
    await LatencyChart.focus();
    await page.keyboard.press('ArrowRight');
    await expect(LatencyChart.getByRole('status')).toContainText('P95：32 µs');
    await page.getByRole('button', { name: '刷新快照' }).click();
    await expect(page.getByRole('group', { name: /资源采样：三个值覆盖范围不同/ })).toBeVisible();
    await page.getByRole('tab', { name: 'PMR 次数 / 秒' }).click();
    const Chart = page.getByRole('group', { name: /资源采样：相邻快照的成功分配/ });
    await Chart.focus();
    await page.keyboard.press('ArrowRight');
    await expect(Chart.getByRole('status')).toContainText('分配：未采集');
    await page.keyboard.press('ArrowRight');
    await expect(Chart.getByRole('status')).toContainText('分配：40 次/秒');
    await expect(Chart.getByRole('status')).toContainText('释放：20 次/秒');
    await page.getByRole('tab', { name: '识别准入延迟' }).click();
    await expect(page.getByText('不是内存分配耗时', { exact: false })).toBeVisible();
    ExpectMockWasReadOnly(Log);
});

test('resource metrics do not display a different generation', async ({ page }) => {
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap(['metrics.read']) };
        if (Url.pathname === '/Operations/Metrics') return { Body: Ok(MetricsWire('7')) };
        throw new Error(`No resource fixture for ${Url.pathname}.`);
    });
    await page.goto('/resources?source=live');
    await page.locator('details').filter({ has: page.getByText('诊断明细', { exact: false }) }).locator('summary').click();
    await expect(page.getByText('指标与资源快照的进程或代次不同', { exact: false })).toBeVisible();
    await expect(page.getByRole('list', { name: '近期识别准入样本（新到旧）' })).toHaveCount(0);
    ExpectMockWasReadOnly(Log);
});

test('unavailable Overview traffic stays unknown in live rate and resource readings', async ({ page }) => {
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap') return { Body: Bootstrap() };
        if (Url.pathname === '/Operations/Workers') return { Body: Ok(PageWire([WorkerWire()])) };
        if (Url.pathname === '/Operations/Ingresses') return { Body: Ok(PageWire([])) };
        if (Url.pathname === '/Operations/Accounts') return { Body: Ok(PageWire([AccountWire('8', 'resource-fixture-account')])) };
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error(`No unavailable Overview fixture for ${Url.pathname}.`);
    });
    const Overview = OverviewWire() as {
        [Key: string]: unknown;
        traffic: Record<string, unknown>;
    };
    const UnavailableOverview = {
        ...Overview,
        traffic: { ...Overview.traffic, available: false, down_bytes_per_second: null, up_bytes_per_second: null },
    };
    await page.route('**/Operations/Overview', async Route => {
        const Request = Route.request();
        const Url = new URL(Request.url());
        Log.Requests.push({ Method: Request.method(), Path: Url.pathname, Search: Url.search });
        if (Request.method() !== 'GET') {
            Log.NonGet.push(`${Request.method()} ${Url.pathname}${Url.search}`);
            await Route.fulfill({ status: 405, contentType: 'application/json',
                body: JSON.stringify({ status: 'error', message: 'Overview reads only in this test.' }) });
            return;
        }
        await Route.fulfill({ status: 200, contentType: 'application/json',
            body: JSON.stringify(Ok(UnavailableOverview)) });
    });

    await page.goto('/?source=live&range=1h');
    await expect(page.locator('main h1')).toHaveText('运行概览');
    const Readings = page.getByRole('region', { name: '运行指标', exact: true });
    await expect(Readings.getByText('下行速率', { exact: true }).locator('..').locator('dd').first()).toHaveText('—');
    await expect(Readings.getByText('上行速率', { exact: true }).locator('..').locator('dd').first()).toHaveText('—');
    const Trends = page.getByRole('region', { name: '运行趋势', exact: true });
    await expect(Trends.getByText('延迟趋势', { exact: true })).toBeVisible();
    await expect(Trends.getByText('进程 RSS', { exact: true })).toBeVisible();
    await expect(Trends).toContainText('未采集');
    expect(Log.Requests.filter(Request => Request.Path === '/Operations/Overview').length).toBeGreaterThan(0);
    ExpectMockWasReadOnly(Log);
});

test('failed account association reads stay unknown and recover within their current read scopes', async ({ page }) => {
    let GroupsUnavailable = true;
    let SessionsUnavailable = true;
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap')
            return { Body: Bootstrap(['accounts.read', 'groups.read', 'sessions.read']) };
        if (Url.pathname === '/Operations/Accounts')
            return { Body: Ok(PageWire([AccountWire('8', 'northstar', '99')])) };
        if (Url.pathname === '/Operations/Groups') {
            if (GroupsUnavailable) return { Status: 503, Body: { status: 'error', message: 'Fixture group directory unavailable.' } };
            return { Body: Ok(PageWire([GroupWire('99', '核心线路', '2', TrafficZero)])) };
        }
        if (Url.pathname === '/Operations/Sessions') {
            if (SessionsUnavailable) return { Status: 503, Body: { status: 'error', message: 'Fixture Session directory unavailable.' } };
            return { Body: Ok(PageWire([SessionWire()])) };
        }
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        if (Url.pathname.endsWith('/Trace') || Url.pathname.endsWith('/Streams') || Url.pathname.endsWith('/Tasks'))
            return { Body: Ok(PageWire([])) };
        throw new Error(`No account association fixture for ${Url.pathname}.`);
    });

    const InitialGroupsRead = page.waitForResponse(Response => new URL(Response.url()).pathname === '/Operations/Groups');
    await page.goto(`/accounts?source=live&account=8${(page.viewportSize()?.width ?? 0) <= 767 ? '&mobile_view=detail' : ''}`);
    await InitialGroupsRead;
    await expect(page.getByRole('region', { name: '账户详情', exact: true })).toContainText('northstar');
    const GroupCount = page.getByRole('group', { name: '账户状态汇总', exact: true })
        .locator('dt').filter({ hasText: '用户组' }).locator('xpath=..').locator('dd').first();
    await expect(GroupCount).toHaveText('—');
    const Details = page.getByRole('region', { name: '账户详情', exact: true });
    const GroupIdentity = Details.locator('dl[aria-label="账户维度流量计数"] dd').first();
    await expect(GroupIdentity).toHaveText('99');
    await expect(Details).toContainText('会话读取失败：HTTP 503 · Fixture Session directory unavailable.');

    GroupsUnavailable = false;
    await page.getByRole('button', { name: '刷新快照', exact: true }).click();
    await expect(GroupCount).toHaveText('1');
    await expect(GroupIdentity).toHaveText('核心线路');

    await page.getByRole('tab', { name: '关联 Session', exact: true }).click();
    const SessionLoadError = page.getByRole('alert').filter({ hasText: '账户关联 Session暂时无法载入' });
    await expect(SessionLoadError).toBeVisible();
    await expect(page.getByText('当前已载入 Session 样本中没有关联记录。', { exact: true })).toHaveCount(0);

    SessionsUnavailable = false;
    await page.getByRole('button', { name: '刷新快照', exact: true }).click();
    await expect(page.getByRole('link', { name: /55/ })).toBeVisible();
    expect(Log.Unexpected).toEqual([]);
    expect(Log.NonGet).toEqual([]);
});

test('configuration Apply stays locked through terminal status and unlocks only after matching Generation readback', async ({ page }) => {
    const InitialConfiguration = PublicConfiguration(1_000);
    const DraftConfiguration = PublicConfiguration(2_000);
    const DraftText = JSON.stringify(DraftConfiguration);
    let ConfigurationGeneration = '6';
    let ConfigurationValue: unknown = InitialConfiguration;
    let HoldConfigurationReadback = false;
    let DelayedConfigurationReads = 0;
    let ReleaseConfigurationReadback: (() => void) | undefined;
    const ConfigurationReadbackGate = new Promise<void>(Resolve => { ReleaseConfigurationReadback = Resolve; });
    const CommandBodies: Array<Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>> = [];
    const Log = await InstallOperationsGetMock(page, async Url => {
        if (Url.pathname === '/Operations/Bootstrap')
            return { Body: Bootstrap(['configuration.reload.validate', 'configuration.reload.apply']) };
        if (Url.pathname === '/Operations/Configuration') {
            if (HoldConfigurationReadback) {
                DelayedConfigurationReads += 1;
                await ConfigurationReadbackGate;
            }
            return { Body: Ok({ configuration: ConfigurationValue, generation: ConfigurationGeneration, reloadable: true }) };
        }
        if (Url.pathname === '/Operations/Operations/17') {
            HoldConfigurationReadback = true;
            ConfigurationGeneration = '7';
            ConfigurationValue = DraftConfiguration;
            return { Body: OperationWire('completed', '17', '42', '7') };
        }
        throw new Error(`No configuration Apply fixture for ${Url.pathname}.`);
    }, (Url, Body) => {
        if (Url.pathname !== '/Operations/Reload') throw new Error('Only the explicit Reload mock may receive a POST.');
        const Request = Body as Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>;
        CommandBodies.push(Request);
        if (Request.mode === 'validate_only')
            return { Body: { status: 'completed', operation: '0', message: 'Mock Validate Only passed.' } };
        if (Request.mode === 'apply') {
            const Operation = OperationWire('accepted', '17', '42', '7') as Record<string, unknown>;
            return { Body: { ...Operation, command: 'Reload', operation: '17', message: 'Mock Apply accepted.' } };
        }
        throw new Error(`Unexpected mocked Reload mode: ${Request.mode}`);
    });

    await page.goto('/configuration?source=live&range=1h');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toBeVisible();
    await Editor.fill(DraftText);
    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
    await page.getByRole('button', { name: '应用配置', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: '确认发布', exact: true }).click();

    await expect.poll(() => DelayedConfigurationReads).toBeGreaterThan(0);
    await expect(Editor).toHaveAttribute('readonly', '');
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeDisabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    await expect(page.locator('.configuration-workflow-step.is-complete')).toHaveCount(2);

    expect(ReleaseConfigurationReadback).toBeDefined();
    ReleaseConfigurationReadback?.();

    await expect(Editor).toHaveValue(JSON.stringify(DraftConfiguration, null, 2));
    await expect(Editor).not.toHaveAttribute('readonly', '');
    await expect(page.locator('.configuration-workflow-step.is-complete')).toHaveCount(3);
    await expect(page.getByText('基于 Generation 7；已有连接继续持有其所属版本。', { exact: true })).toBeVisible();
    expect(CommandBodies).toHaveLength(2);
    expect(CommandBodies[0]).toMatchObject({ mode: 'validate_only', base_generation: '6', configuration: DraftConfiguration });
    expect(CommandBodies[1]).toMatchObject({ mode: 'apply', base_generation: '6', configuration: DraftConfiguration });

    const NextDraftText = JSON.stringify(PublicConfiguration(3_000), null, 2);
    await Editor.fill(NextDraftText);
    await expect(Editor).toHaveValue(NextDraftText);
    await expect(page.locator('.configuration-workflow-step').filter({ hasText: '应用配置' })).not.toHaveClass(/is-complete/);
    await expect(page.getByText('本次准确文本已通过校验并应用。', { exact: true })).toHaveCount(0);
    await expect(page.getByRole('button', { name: '校验草稿', exact: true })).toBeEnabled();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
    expect(Log.NonGet).toEqual(['POST /Operations/Reload', 'POST /Operations/Reload']);
    expect(Log.Unexpected).toEqual([]);
});

test('configuration Apply preserves its draft when completed-operation readback belongs to a newer Generation', async ({ page }) => {
    const InitialConfiguration = PublicConfiguration(1_000);
    const DraftConfiguration = PublicConfiguration(2_000);
    const ConcurrentConfiguration = PublicConfiguration(3_000);
    const DraftText = JSON.stringify(DraftConfiguration, null, 2);
    let ConfigurationGeneration = '6';
    let ConfigurationValue: unknown = InitialConfiguration;
    const CommandBodies: Array<Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>> = [];
    const Log = await InstallOperationsGetMock(page, Url => {
        if (Url.pathname === '/Operations/Bootstrap')
            return { Body: Bootstrap(['configuration.reload.validate', 'configuration.reload.apply']) };
        if (Url.pathname === '/Operations/Configuration')
            return { Body: Ok({ configuration: ConfigurationValue, generation: ConfigurationGeneration, reloadable: true }) };
        if (Url.pathname === '/Operations/Operations/17') {
            ConfigurationGeneration = '8';
            ConfigurationValue = ConcurrentConfiguration;
            return { Body: OperationWire('completed', '17', '42', '7') };
        }
        throw new Error(`No concurrent configuration fixture for ${Url.pathname}.`);
    }, (Url, Body) => {
        if (Url.pathname !== '/Operations/Reload') throw new Error('Only the explicit Reload mock may receive a POST.');
        const Request = Body as Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>;
        CommandBodies.push(Request);
        if (Request.mode === 'validate_only')
            return { Body: { status: 'completed', operation: '0', message: 'Mock Validate Only passed.' } };
        if (Request.mode === 'apply') {
            const Operation = OperationWire('accepted', '17', '42', '7') as Record<string, unknown>;
            return { Body: { ...Operation, command: 'Reload', operation: '17', message: 'Mock Apply accepted.' } };
        }
        throw new Error(`Unexpected mocked Reload mode: ${Request.mode}`);
    });

    await page.goto('/configuration?source=live&range=1h');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toBeVisible();
    await Editor.fill(DraftText);
    await page.getByRole('button', { name: '校验草稿', exact: true }).click();
    await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
    await page.getByRole('button', { name: '应用配置', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: '确认发布', exact: true }).click();

    const PublishConflict = page.getByRole('alert').filter({ hasText: '运行配置已更新到 Generation 8' });
    await expect(PublishConflict).toContainText('当前草稿仍基于 6');
    await expect(Editor).toHaveValue(DraftText);
    await expect(page.getByRole('alert').filter({ hasText: '草稿已保留' }).first()).toBeVisible();
    await expect(page.getByText('本次准确文本已通过校验并应用。', { exact: true })).toHaveCount(0);
    expect(CommandBodies).toHaveLength(2);
    expect(CommandBodies[1]).toMatchObject({ mode: 'apply', base_generation: '6', configuration: DraftConfiguration });
    expect(Log.NonGet).toEqual(['POST /Operations/Reload', 'POST /Operations/Reload']);
    expect(Log.Unexpected).toEqual([]);
});

test('late readback from an older incarnation preserves the rebased draft and its validation', async ({ page }) => {
    const IdentityA = { InstanceKey: 'fixture-configuration-a', ProcessId: '42', Incarnation: 'a'.repeat(32) };
    const IdentityB = { InstanceKey: 'fixture-configuration-b', ProcessId: '42', Incarnation: 'b'.repeat(32) };
    let CurrentIdentity: BootstrapIdentity = IdentityA;
    let ApplyCompleted = false;
    let AppliedConfigurationReads = 0;
    let SignalReadbackStarted!: () => void;
    let ReleaseReadback!: () => void;
    const ReadbackStarted = new Promise<void>(Resolve => { SignalReadbackStarted = Resolve; });
    const ReadbackGate = new Promise<void>(Resolve => { ReleaseReadback = Resolve; });
    const InitialA = PublicConfiguration(1_000);
    const AppliedA = PublicConfiguration(2_000);
    const InitialB = PublicConfiguration(3_000);
    const AppliedText = JSON.stringify(AppliedA, null, 2);
    const NewDraftText = JSON.stringify(PublicConfiguration(4_000), null, 2);
    const Log = await InstallOperationsGetMock(page, async Url => {
        if (Url.pathname === '/Operations/Bootstrap')
            return { Body: Bootstrap(['configuration.reload.validate', 'configuration.reload.apply'], CurrentIdentity) };
        if (Url.pathname === '/Operations/Configuration') {
            if (ApplyCompleted) {
                AppliedConfigurationReads += 1;
                if (AppliedConfigurationReads === 2) {
                    SignalReadbackStarted();
                    await ReadbackGate;
                    return { Body: Ok({ configuration: AppliedA, generation: '7', reloadable: true }) };
                }
                const IsA = CurrentIdentity.InstanceKey === IdentityA.InstanceKey;
                return { Body: Ok({ configuration: IsA ? AppliedA : InitialB,
                    generation: IsA ? '7' : 'generation-b', reloadable: true }) };
            }
            const IsA = CurrentIdentity.InstanceKey === IdentityA.InstanceKey;
            return { Body: Ok({ configuration: IsA ? InitialA : InitialB,
                generation: IsA ? 'generation-a' : 'generation-b', reloadable: true }) };
        }
        if (Url.pathname === '/Operations/Events') return { Body: Ok(EventPageWire()) };
        throw new Error('No delayed-configuration fixture for this endpoint.');
    }, (Url, Body) => {
        if (Url.pathname !== '/Operations/Reload') throw new Error('Only the explicit Reload fixture may receive a POST.');
        const Request = Body as Readonly<{ mode?: string; base_generation?: string }>;
        if (Request.mode === 'validate_only')
            return { Body: { operation: '0', status: 'completed', message: 'Mock Validate Only passed.' } };
        if (Request.mode === 'apply' && Request.base_generation === 'generation-a') {
            ApplyCompleted = true;
            return { Body: { operation: '71', status: 'completed', command: 'Reload', accepted_at: Timestamp,
                updated_at: OtherTimestamp, process: '42', generation: '7', message: 'Mock Apply completed.' } };
        }
        throw new Error(`Unexpected mocked Reload mode/generation: ${Request.mode}/${Request.base_generation}`);
    });
    try {
        await page.goto('/configuration?source=live');
        const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
        await expect(Editor).toBeVisible();
        await Editor.fill(AppliedText);
        await page.getByRole('button', { name: '校验草稿', exact: true }).click();
        await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
        await page.getByRole('button', { name: '应用配置', exact: true }).click();
        await page.getByRole('dialog').getByRole('button', { name: '确认发布', exact: true }).click();
        await ReadbackStarted;

        const PreviousBootstrapReads = Log.Requests.filter(Request => Request.Method === 'GET' && Request.Path === '/Operations/Bootstrap').length;
        CurrentIdentity = IdentityB;
        await page.evaluate(() => {
            window.dispatchEvent(new Event('focus'));
            document.dispatchEvent(new Event('visibilitychange'));
        });
        await expect.poll(() => Log.Requests.filter(Request => Request.Method === 'GET' && Request.Path === '/Operations/Bootstrap').length,
            { timeout: 8_000 }).toBeGreaterThan(PreviousBootstrapReads);
        const StaleDraft = page.getByRole('alert').filter({ has: page.getByRole('textbox', { name: '旧来源草稿，只读', exact: true }) });
        await expect(StaleDraft).toContainText('存在来自其他来源的未保存草稿');
        await expect(page.getByText('生效配置 · Generation generation-b', { exact: true })).toBeVisible();
        await page.getByRole('button', { name: '读取当前基线并准备重基线', exact: true }).click();
        await expect(StaleDraft).toContainText('已读取目标实例配置；请核对下方来源与 Generation 后确认重基线。');
        await page.getByRole('button', { name: '确认以该基线重建', exact: true }).click();
        await page.getByRole('dialog').getByRole('button', { name: '确认重建并重新校验', exact: true }).click();
        await expect(StaleDraft).toHaveCount(0);
        await expect(Editor).toHaveValue(AppliedText);

        await Editor.fill(NewDraftText);
        await page.getByRole('button', { name: '校验草稿', exact: true }).click();
        await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
        const ApplyButton = page.getByRole('button', { name: '应用配置', exact: true });
        await expect(ApplyButton).toBeDisabled();

        ReleaseReadback();
        await page.waitForTimeout(200);
        await expect(ApplyButton).toBeEnabled();
        await expect(Editor).toHaveValue(NewDraftText);
        await expect(page.getByRole('alert').filter({ hasText: 'Validate Only 通过' })).toBeVisible();
        expect(Log.NonGet).toEqual(['POST /Operations/Reload', 'POST /Operations/Reload', 'POST /Operations/Reload']);
        expect(Log.Unexpected).toEqual([]);
    } finally { ReleaseReadback(); }
});

test('accepted user-group edits lock all mutation controls until matching operation scope and ID are terminal', async ({ page }) => {
    const Configuration = {
        ...PublicConfiguration(1_000),
        AccountGroups: [{ Id: 'core', Name: '核心组', Policy: {} }, { Id: 'spare', Name: '备用组', Policy: {} }],
        Accounts: [
            { Id: '8', GroupId: 'core', SecretRef: 'fixture-core', Policy: {} },
            { Id: '9', GroupId: 'spare', SecretRef: 'fixture-spare', Policy: {} },
        ],
    };
    const StatusReplies: readonly FixtureReply[] = [
        { Status: 503, Body: { status: 'error', message: 'Fixture status temporarily unavailable.' } },
        { Body: OperationWire('accepted', '18', '42', '7') },
        { Body: OperationWire('completed', '17', '99', '7') },
        { Body: OperationWire('accepted', '17', '42', '7') },
        { Body: OperationWire('completed', '17', '42', '7') },
    ];
    let OperationStatusReads = 0;
    let Operation19StatusReads = 0;
    let ApplyCount = 0;
    const PendingStatusReleases: Array<() => void> = [];
    const CommandBodies: Array<Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>> = [];
    let ReleaseApply: ((Reply: FixtureReply) => void) | null = null;
    let NotifyApplyStarted: (() => void) | null = null;
    const ApplyStarted = new Promise<void>(Resolve => { NotifyApplyStarted = Resolve; });
    const ApplyGate = new Promise<FixtureReply>(Resolve => { ReleaseApply = Resolve; });
    const Log = await InstallOperationsGetMock(page, async Url => {
        if (Url.pathname === '/Operations/Bootstrap')
            return { Body: Bootstrap(['configuration.reload.validate', 'configuration.reload.persist']) };
        if (Url.pathname === '/Operations/Groups')
            return { Body: Ok(PageWire([
                GroupWire('core', '核心组', '1', TrafficZero), GroupWire('spare', '备用组', '0', TrafficZero),
            ])) };
        if (Url.pathname === '/Operations/Accounts')
            return { Body: Ok(PageWire([
                AccountWire('8', '核心账户', 'core'), AccountWire('9', '备用账户', 'spare'),
            ])) };
        if (Url.pathname === '/Operations/Sessions') return { Body: Ok(EmptyCollection) };
        if (Url.pathname === '/Operations/Configuration')
            return { Body: Ok({ configuration: Configuration, generation: '6', reloadable: true }) };
        if (Url.pathname === '/Operations/Operations/17') {
            const ReadIndex = OperationStatusReads;
            const Reply = StatusReplies[Math.min(ReadIndex, StatusReplies.length - 1)]!;
            OperationStatusReads += 1;
            if (ReadIndex > 0) await new Promise<void>(Resolve => PendingStatusReleases.push(Resolve));
            return Reply;
        }
        if (Url.pathname === '/Operations/Operations/19') {
            Operation19StatusReads += 1;
            const State = Operation19StatusReads === 1 ? 'accepted' : 'completed';
            return { Body: OperationWire(State, '19', '42', '8') };
        }
        throw new Error('No user-group edit fixture for ' + Url.pathname + '.');
    }, async (Url, Body) => {
        if (Url.pathname !== '/Operations/Reload') throw new Error('Only configuration reload is expected.');
        const Request = Body as Readonly<{ mode?: string; base_generation?: string; configuration?: unknown }>;
        CommandBodies.push(Request);
        if (Request.mode === 'validate_only')
            return { Body: { status: 'completed', operation: '0', message: 'Mock group validation passed.' } };
        if (Request.mode === 'apply_and_persist') {
            ApplyCount += 1;
            if (ApplyCount === 1) {
                NotifyApplyStarted?.();
                return ApplyGate;
            }
            const RenameOperation = OperationWire('accepted', '19', '42', '8') as Record<string, unknown>;
            return { Body: { ...RenameOperation, command: 'Reload', operation: '19', message: 'Mock rename accepted.' } };
        }
        throw new Error('Unexpected mocked Reload mode: ' + Request.mode);
    });

    try {
        await page.goto('/user-groups?source=live&range=1h&group=core');
        const Details = page.getByRole('region', { name: '用户组详情', exact: true });
        const CreateAction = page.getByRole('button', { name: '新建用户组', exact: true });
        const RenameAction = Details.getByRole('button', { name: '改名', exact: true });
        const AddAccountAction = Details.getByRole('button', { name: '添加账户', exact: true });
        await expect(Details).toContainText('核心组');
        await expect(RenameAction).toBeEnabled();
        await expect(AddAccountAction).toBeEnabled();
        await CreateAction.click();
        const Dialog = page.getByRole('dialog');
        await Dialog.getByRole('textbox', { name: '新用户组名称', exact: true }).fill('新建组');
        const Create = Dialog.getByRole('button', { name: /创建用户组|正在创建/ });
        await Create.click();
        await ApplyStarted;
        await expect(Create).toBeDisabled();
        await expect.poll(() => CommandBodies.length).toBe(2);
        expect(CommandBodies.map(Value => Value.mode)).toEqual(['validate_only', 'apply_and_persist']);
        expect(CommandBodies[0]?.base_generation).toBe('6');
        expect(CommandBodies[1]?.base_generation).toBe('6');
        expect(CommandBodies[1]?.configuration).toMatchObject({
            AccountGroups: expect.arrayContaining([expect.objectContaining({ Name: '新建组' })]),
        });

        const Operation = OperationWire('accepted', '17', '42', '7') as Record<string, unknown>;
        ReleaseApply?.({ Body: { ...Operation, command: 'Reload', operation: '17', message: 'Mock group update accepted.' } });
        const Accepted = page.getByRole('alert').filter({ hasText: '操作已受理，等待核验' });
        await expect(Accepted).toContainText('Mock group update accepted.');
        await expect(page.getByText('操作已完成', { exact: true })).toHaveCount(0);
        await expect(Dialog).toHaveCount(0);
        await expect.poll(() => OperationStatusReads).toBeGreaterThan(0);

        const ExpectMutationControlsLocked = async (): Promise<void> => {
            await expect(CreateAction).toBeDisabled();
            await expect(Details.getByRole('button', { name: '改名', exact: true })).toBeDisabled();
            await expect(Details.getByRole('button', { name: '添加账户', exact: true })).toBeDisabled();
            await expect(Details.getByRole('table').getByRole('button', { name: '移出', exact: true })).toBeDisabled();
        };
        const ExpectNeedsReviewLocked = async (): Promise<void> => {
            await expect(page.getByRole('status').filter({ hasText: '用户组配置结果尚未核实' })).toBeVisible();
            await expect(page.getByRole('alert').filter({ hasText: '操作已完成' })).toHaveCount(0);
            await ExpectMutationControlsLocked();
        };
        const WaitForNextStatus = async (PreviousReadCount: number): Promise<void> => {
            await expect.poll(() => OperationStatusReads).toBeGreaterThan(PreviousReadCount);
            const Release = PendingStatusReleases.shift();
            expect(Release).toBeDefined();
            const NextResponse = page.waitForResponse(Response => {
                const Url = new URL(Response.url());
                return Url.pathname === '/Operations/Operations/17' && Response.request().method() === 'GET';
            });
            Release?.();
            await NextResponse;
        };
        await ExpectNeedsReviewLocked();
        await WaitForNextStatus(1);
        await ExpectNeedsReviewLocked();
        await WaitForNextStatus(2);
        await ExpectNeedsReviewLocked();

        const Directory = page.getByRole('region', { name: '用户组目录', exact: true });
        const IsMobile = (page.viewportSize()?.width ?? 0) <= 767;
        if (IsMobile) await Details.getByRole('button', { name: '返回分组目录', exact: true }).click();
        const SpareGroup = Directory.getByRole('button', { name: /备用组/ });
        await expect(SpareGroup).toBeEnabled();
        await SpareGroup.click();
        await expect(page).toHaveURL(/group=spare/);
        if (IsMobile) await page.getByRole('region', { name: '用户组详情', exact: true })
            .getByRole('button', { name: '返回分组目录', exact: true }).click();
        const CoreGroup = Directory.getByRole('button', { name: /核心组/ });
        await expect(CoreGroup).toBeEnabled();
        await CoreGroup.click();
        await expect(page).toHaveURL(/group=core/);
        await ExpectMutationControlsLocked();

        await WaitForNextStatus(3);
        await expect(page.getByRole('status').filter({ hasText: '用户组配置命令正在处理' })).toBeVisible();
        await ExpectMutationControlsLocked();
        await WaitForNextStatus(4);
        await expect(page.getByRole('alert').filter({ hasText: '操作已完成' })).toBeVisible();
        await expect(CreateAction).toBeEnabled();
        await expect(RenameAction).toBeEnabled();
        await expect(AddAccountAction).toBeEnabled();
        await expect(Details.getByRole('table').getByRole('button', { name: '移出', exact: true })).toBeEnabled();

        await RenameAction.click();
        const RenameDialog = page.getByRole('dialog', { name: '重命名 核心组', exact: true });
        const RenameInput = RenameDialog.getByRole('textbox', { name: '新用户组名称', exact: true });
        await expect(RenameInput).toBeEnabled();
        await RenameInput.fill('核心组改名草稿');
        const ConfirmRename = RenameDialog.getByRole('button', { name: '确认改名', exact: true });
        await expect(ConfirmRename).toBeEnabled();
        await ConfirmRename.click();
        await expect.poll(() => CommandBodies.length).toBe(4);
        await expect.poll(() => Operation19StatusReads).toBeGreaterThan(0);
        await expect(page.getByRole('status').filter({ hasText: '用户组配置命令正在处理' })).toBeVisible();
        await ExpectMutationControlsLocked();
        await expect.poll(() => Operation19StatusReads).toBeGreaterThan(1);
        await expect(page.getByRole('alert').filter({ hasText: '操作已完成' })).toBeVisible();
        await expect(CreateAction).toBeEnabled();
        await expect(RenameAction).toBeEnabled();
        await expect(AddAccountAction).toBeEnabled();
        await AddAccountAction.click();
        const AddAccountDialog = page.getByRole('dialog', { name: '添加账户到 核心组', exact: true });
        await expect(AddAccountDialog.getByRole('combobox', { name: '选择账户', exact: true })).toBeEnabled();
        await expect(AddAccountDialog.getByRole('button', { name: '确认分配', exact: true })).toBeDisabled();

        expect(OperationStatusReads).toBe(5);
        expect(Operation19StatusReads).toBe(2);
        expect(CommandBodies.map(Request => Request.mode)).toEqual([
            'validate_only', 'apply_and_persist', 'validate_only', 'apply_and_persist',
        ]);
        expect(CommandBodies[1]).toMatchObject({ base_generation: '6' });
        expect(CommandBodies[3]).toMatchObject({ base_generation: '6' });
        expect(Log.NonGet).toEqual([
            'POST /Operations/Reload', 'POST /Operations/Reload',
            'POST /Operations/Reload', 'POST /Operations/Reload',
        ]);
        expect(Log.Unexpected).toEqual([]);
    } finally {
        ReleaseApply?.({ Body: { status: 'accepted', operation: '17', command: 'Reload', message: 'Fixture released.' } });
        for (const Release of PendingStatusReleases) Release();
    }
});
