import { OperationScopeChangedError } from './AdminDataSource.ts';
import { WorkerIdentityChangedError } from './AdminDataSource.ts';
import type { AdminDataSource, AdminActionResult, BootstrapReadOptions, BootstrapSnapshot, ConfigurationSnapshot, ConfigurationValidation, EventsFilter, OperationScope, PageRequest, SessionIdentity, StreamIdentity, TaskIdentity, HistoryRequest, UsageAdjustment, SearchResult, CursorPage, WorkerIdentity } from './AdminDataSource.ts';
import { Bool, DecodeBootstrap, DecodeCommand, DecodeOperation, DecodePage, DecodeTracePage, FailureText, List, RecordValue, Text } from '../Api/Wire.ts';
import { DecodeAccount, DecodeEvents, DecodeGroup, DecodeHistory, DecodeIngress, DecodeOverview, DecodeProtocol, DecodeSession, DecodeStream, DecodeTask, DecodeUsage, DecodeWorker } from '../Api/ResourceDecoders.ts';
import { ParseJsonDocument, FormatJsonDocument } from '../Api/JsonDocument.ts';
import { ChangeConfiguration } from '../Api/ConfigurationMutations.ts';
import { DecodeMetrics } from '../Api/MetricsDecoder.ts';

export class OperationsError extends Error {
    public Status: number;
    public constructor(Message: string, Status = 0) { super(Message); this.name = 'OperationsError'; this.Status = Status; }
}
type FetchFunction = (Input: RequestInfo | URL, Init?: RequestInit) => Promise<Response>;
type ClientOptions = Readonly<{ Fetch?: FetchFunction; TimeoutMs?: number }>;
/** @brief 唯一真实管理边界。凭据仅在当前实例私有内存中，失败不会读取演示数据。 */
export class LiveAdminDataSource implements AdminDataSource {
    #Token = '';
    #Bootstrap: BootstrapSnapshot | null = null;
    #PendingBootstrap: Promise<BootstrapSnapshot> | null = null;
    #BootstrapRequestSequence = 0;
    #AppliedBootstrapSequence = 0;
    #Fetch: FetchFunction;
    #TimeoutMs: number;
    public constructor(Options: ClientOptions = {}) {
        this.#Fetch = Options.Fetch ?? fetch.bind(globalThis);
        this.#TimeoutMs = Options.TimeoutMs ?? 20_000;
    }
    public GetBootstrap(Options: BootstrapReadOptions = {}): Promise<BootstrapSnapshot> {
        if (Options.Fresh) return this.FetchBootstrap();
        if (this.#Bootstrap) return Promise.resolve(this.#Bootstrap);
        if (this.#PendingBootstrap) return this.#PendingBootstrap;
        const Pending = this.FetchBootstrap();
        this.#PendingBootstrap = Pending;
        void Pending.then(() => {
            if (this.#PendingBootstrap === Pending) this.#PendingBootstrap = null;
        }, () => {
            if (this.#PendingBootstrap === Pending) this.#PendingBootstrap = null;
        });
        return Pending;
    }
    private async FetchBootstrap(): Promise<BootstrapSnapshot> {
        const RequestSequence = ++this.#BootstrapRequestSequence;
        const Response = await this.ReadRaw('/Bootstrap');
        const Value = DecodeBootstrap(JSON.parse(Response));
        const Snapshot = { ApiVersion: Value.ApiVersion, InstanceKey: Value.InstanceKey, ProcessId: Value.ProcessId,
            Incarnation: Value.Incarnation, Capabilities: Value.Capabilities };
        if (RequestSequence >= this.#AppliedBootstrapSequence) {
            this.#AppliedBootstrapSequence = RequestSequence;
            this.#Token = Value.CommandToken;
            this.#Bootstrap = Snapshot;
        }
        return RequestSequence < this.#AppliedBootstrapSequence ? this.#Bootstrap ?? Snapshot : Snapshot;
    }
    public async GetOverview() { return DecodeOverview(await this.Query('/Overview')); }
    public async GetMetrics() { await this.Require('metrics.read'); return DecodeMetrics(await this.Query('/Metrics')); }
    public async GetIngresses(Page: PageRequest) { return this.Collection('Ingresses', Page, DecodeIngress); }
    public async GetWorkers(Page: PageRequest) { return this.Collection('Workers', Page, DecodeWorker); }
    public async GetAccounts(Page: PageRequest) { return this.Collection('Accounts', Page, DecodeAccount); }
    public async GetGroups(Page: PageRequest) { return this.Collection('Groups', Page, DecodeGroup); }
    public async GetSessions(Page: PageRequest) { return this.Collection('Sessions', Page, DecodeSession); }
    public async GetProtocols(Page: PageRequest) { return this.Collection('Protocols', Page, DecodeProtocol); }
    public async GetOperations(Page: PageRequest, Scope: OperationScope) {
        await this.RequireOperationScope(Scope);
        const Value = await this.Collection('Operations', Page, DecodeOperation);
        await this.RequireOperationScope(Scope);
        return Value;
    }
    public async GetOperationStatus(Id: string, Scope: OperationScope) {
        await this.RequireOperationScope(Scope);
        const Value = JSON.parse(await this.ReadRaw(`/Operations/${encodeURIComponent(Id)}`));
        await this.RequireOperationScope(Scope);
        return DecodeOperation(Value);
    }
    public async GetSessionTrace(Identity: SessionIdentity, Page: PageRequest) {
        return DecodeTracePage(await this.Query(`${this.SessionPath(Identity)}/Trace${this.PageQuery(Page)}`));
    }
    public async GetStreams(Identity: SessionIdentity, Page: PageRequest) {
        return DecodePage(await this.Query(`${this.SessionPath(Identity)}/Streams${this.PageQuery(Page, { generation: Identity.GenerationId, worker: Identity.WorkerId })}`), DecodeStream);
    }
    public async GetTasks(Identity: SessionIdentity, Page: PageRequest) {
        const Path = `/Processes/${encodeURIComponent(Identity.ProcessId)}/Workers/${encodeURIComponent(Identity.WorkerId)}/Sessions/${encodeURIComponent(Identity.Id)}/Tasks`;
        return DecodePage(await this.Query(`${Path}${this.PageQuery(Page, { generation: Identity.GenerationId })}`), DecodeTask);
    }
    public async GetEvents(Page: PageRequest, Filter: EventsFilter = {}) {
        const Bootstrap = await this.GetBootstrap();
        const Fields: Record<string, string> = { include_details: 'true' };
        for (const [Key, Value] of Object.entries({ session_id: Filter.SessionId, worker_id: Filter.WorkerId, account_id: Filter.AccountId, severity: Filter.Severity })) if (Value) Fields[Key] = Value;
        if (Filter.ProcessId && Bootstrap.Capabilities.includes('events.filter.process')) Fields.process_id = Filter.ProcessId;
        if (Filter.GenerationId && Bootstrap.Capabilities.includes('events.filter.generation')) Fields.generation_id = Filter.GenerationId;
        return DecodeEvents(await this.Query(`/Events${this.PageQuery(Page, Fields)}`));
    }
    public async GetConfiguration(): Promise<ConfigurationSnapshot> {
        await this.GetBootstrap();
        const Raw = await this.ReadRaw('/Configuration');
        this.Unwrap(JSON.parse(Raw));
        const Parsed = ParseJsonDocument({ Text: Raw, MaxBytes: 4 * 1024 * 1024 });
        const Root = Parsed.Ok && Parsed.Value.Kind === 'object' ? Parsed.Value.Members.get('value') : null;
        if (!Root || Root.Kind !== 'object') throw new Error('配置快照结构无效');
        const Configuration = Root.Members.get('configuration');
        const Generation = Root.Members.get('generation');
        const Reloadable = Root.Members.get('reloadable');
        if (!Configuration || !Generation || Generation.Kind !== 'string' || !Reloadable) throw new Error('配置快照缺少字段');
        return { Generation: Generation.Text, Reloadable: Bool(JSON.parse(Reloadable.Raw)), Text: FormatJsonDocument(Configuration), UpdatedAt: '' };
    }
    public async GetHistory(Request: HistoryRequest) {
        await this.Require('history.read');
        const Params = new URLSearchParams({ scope: Request.Scope, key: Request.Key, from: Request.From, to: Request.To, metric: Request.Metric ?? 'traffic', max_points: String(Math.min(1200, Request.MaxPoints ?? 1200)) });
        return DecodeHistory(await this.Query(`/History?${Params}`));
    }
    public async GetAccountUsage(AccountKey: string) {
        await this.Require('accounts.usage.read');
        return DecodeUsage(await this.Query(`/AccountUsage?${new URLSearchParams({ account_key: AccountKey, cycle: 'current' })}`));
    }
    public async Search(QueryText: string, Signal?: AbortSignal): Promise<readonly SearchResult[]> {
        await this.Require('search.read');
        const Value = await this.Query(`/Search?${new URLSearchParams({ q: QueryText, limit: '20' })}`, Signal);
        return List(RecordValue(Value).items).map(Input => {
            const Item = RecordValue(Input), Kind = Text(Item.kind), Id = Text(Item.id);
            const Allowed: Record<string, string> = { account: '/accounts?account=', worker: '/workers?worker=', ingress: '/ingresses?ingress=', protocol: '/protocols?protocol=', group: '/user-groups?group=', session: '/sessions?session=' };
            const Base = Allowed[Kind];
            if (!Base) throw new Error('搜索返回未知资源类型');
            let Path = `${Base}${encodeURIComponent(Id)}`;
            if (Kind === 'session') {
                const Params = new URLSearchParams({ session: Id, process: Text(Item.process), generation: Text(Item.generation), identity_worker: Text(Item.worker) });
                if (Item.account) Params.set('identity_account', Text(Item.account));
                Path = `/sessions?${Params}`;
            }
            return { Id, Kind, Label: Text(Item.label), Detail: Text(Item.detail), Path };
        });
    }
    public async AdjustUsage(Adjustment: UsageAdjustment) {
        await this.Require('accounts.usage.adjust');
        return this.Command('/UsageAdjustments', { account_key: Adjustment.AccountKey, revision: Adjustment.Revision,
            kind: Adjustment.Kind, bytes: Adjustment.Bytes, reason: Adjustment.Reason });
    }
    public async DrainWorker(Worker: WorkerIdentity) {
        const Bootstrap = await this.GetBootstrap({ Fresh: true });
        if (!Bootstrap.Capabilities.includes('workers.drain')) throw new OperationsError('当前实例尚未提供此能力：workers.drain', 501);
        if (Bootstrap.ProcessId !== Worker.ProcessId) throw new WorkerIdentityChangedError();
        const Current = await this.Collection('Workers', { Cursor: '0', Limit: 1, Id: Worker.Id,
            ProcessId: Worker.ProcessId, GenerationId: Worker.GenerationId }, DecodeWorker);
        const Exact = Current.Items.find(Value => Value.Id === Worker.Id);
        if (Current.Items.length !== 1 || Exact?.ProcessId !== Worker.ProcessId || Exact.GenerationId !== Worker.GenerationId)
            throw new WorkerIdentityChangedError();
        const Confirmed = await this.GetBootstrap({ Fresh: true });
        if (Confirmed.ProcessId !== Bootstrap.ProcessId || Confirmed.Incarnation !== Bootstrap.Incarnation)
            throw new WorkerIdentityChangedError();
        if (!Confirmed.Capabilities.includes('workers.drain')) throw new OperationsError('当前实例尚未提供此能力：workers.drain', 501);
        const Scope: OperationScope = { ProcessId: Confirmed.ProcessId, Incarnation: Confirmed.Incarnation };
        return this.Command(`/Drain?${new URLSearchParams({ worker: Worker.Id, force: 'false' })}`, undefined, Scope);
    }
    public async RevokeAccount(Id: string, CloseSessions: boolean) {
        await this.Require('accounts.revoke'); return this.Command(`/Accounts/${encodeURIComponent(Id)}/Revoke?close_sessions=${CloseSessions}`);
    }
    public async CancelSession(Identity: SessionIdentity) { await this.Require('sessions.cancel'); return this.Command(`${this.SessionPath(Identity)}/Cancel`); }
    public async ResetStream(Identity: StreamIdentity) {
        await this.Require('streams.reset');
        if (!Identity.ParentTaskId) throw new Error('缺少父任务身份，不能重置子流');
        const Params = new URLSearchParams({ generation: Identity.GenerationId, worker: Identity.WorkerId, parent_task: Identity.ParentTaskId, task: Identity.TaskId });
        return this.Command(`/Processes/${Identity.ProcessId}/Sessions/${Identity.SessionId}/Streams/${Identity.Id}/Reset?${Params}`);
    }
    public async CancelTask(Identity: TaskIdentity) {
        await this.Require('tasks.cancel');
        const Params = new URLSearchParams({ generation: Identity.GenerationId, stream: Identity.StreamId, parent_task: Identity.ParentTaskId ?? '0' });
        return this.Command(`/Processes/${Identity.ProcessId}/Workers/${Identity.WorkerId}/Sessions/${Identity.SessionId}/Tasks/${Identity.Id}/Cancel?${Params}`);
    }
    public async ValidateConfiguration(TextValue: string, BaseGeneration?: string): Promise<ConfigurationValidation> {
        await this.Require('configuration.reload.validate');
        if (!BaseGeneration) throw new Error('缺少配置基线，请重新读取配置');
        const Result = await this.Reload(TextValue, BaseGeneration, 'validate_only');
        return { Valid: Result.Status === 'completed', Issues: Result.ConfigurationIssues?.map(Issue => `${Issue.Path}: ${Issue.Message}`) ?? [Result.Message], CheckedAt: new Date().toISOString() };
    }
    public async ApplyConfiguration(TextValue: string, Persist: boolean, BaseGeneration?: string) {
        await this.Require(Persist ? 'configuration.reload.persist' : 'configuration.reload.apply');
        if (!BaseGeneration) throw new Error('缺少配置基线，请重新读取配置');
        return this.Reload(TextValue, BaseGeneration, Persist ? 'apply_and_persist' : 'apply');
    }
    public async CreateGroup(Name: string) { return this.EditConfiguration({ Kind: 'create-group', Name }); }
    public async RenameGroup(Id: string, Name: string) { return this.EditConfiguration({ Kind: 'rename-group', Id, Name }); }
    public async SetAccountGroup(AccountId: string, GroupId: string | null) {
        const Match = await this.GetAccounts({ Cursor: '0', Limit: 1, Id: AccountId });
        const Account = Match.Items.find(Item => Item.Id === AccountId);
        if (!Account) throw new Error('目标账户已不存在，请刷新');
        return this.EditConfiguration({ Kind: 'account-group', Id: Account.AccountKey ?? Account.Label, GroupId });
    }
    private async EditConfiguration(Change: Parameters<typeof ChangeConfiguration>[1]): Promise<AdminActionResult> {
        const Configuration = await this.GetConfiguration();
        const Updated = ChangeConfiguration(Configuration.Text, Change);
        const Validation = await this.ValidateConfiguration(Updated, Configuration.Generation);
        if (!Validation.Valid) return { Ok: false, Operation: null, Message: Validation.Issues.join('；'), Status: 'invalid' };
        return this.ApplyConfiguration(Updated, true, Configuration.Generation);
    }
    private async Reload(TextValue: string, Generation: string, Mode: string) {
        const Parsed = ParseJsonDocument({ Text: TextValue, MaxBytes: 256 * 1024 });
        if (!Parsed.Ok || Parsed.Value.Kind !== 'object') throw new Error('配置 JSON 无效');
        return this.Command('/Reload', `{"mode":${JSON.stringify(Mode)},"base_generation":${JSON.stringify(Generation)},"configuration":${Parsed.Value.Raw}}`);
    }
    private async Require(Capability: string): Promise<void> {
        const Bootstrap = await this.GetBootstrap();
        if (!Bootstrap.Capabilities.includes(Capability)) throw new OperationsError(`当前实例尚未提供此能力：${Capability}`, 501);
    }
    private async RequireOperationScope(Scope: OperationScope): Promise<void> {
        const Current = await this.GetBootstrap({ Fresh: true });
        if (Current.ProcessId !== Scope.ProcessId || Current.Incarnation !== Scope.Incarnation)
            throw new OperationScopeChangedError();
    }
    private async Query(Path: string, Signal?: AbortSignal): Promise<unknown> {
        await this.GetBootstrap();
        return this.Unwrap(JSON.parse(await this.ReadRaw(Path, Signal)));
    }
    private Unwrap(Input: unknown): unknown {
        const Result = RecordValue(Input);
        if (Result.status !== 'ok') throw new OperationsError(`${typeof Result.message === 'string' ? Result.message : '查询失败'}${FailureText(Result.failure) ? ` · ${FailureText(Result.failure)}` : ''}`);
        return Result.value;
    }
    private async Command(Path: string, Body?: unknown, ExpectedScope?: OperationScope): Promise<AdminActionResult> {
        const Bootstrap = await this.GetBootstrap({ Fresh: true });
        if (ExpectedScope && (Bootstrap.ProcessId !== ExpectedScope.ProcessId || Bootstrap.Incarnation !== ExpectedScope.Incarnation))
            throw new WorkerIdentityChangedError();
        const Scope: OperationScope = { ProcessId: Bootstrap.ProcessId, Incarnation: Bootstrap.Incarnation };
        const RequestId = crypto.randomUUID();
        const Headers: Record<string, string> = { Authorization: `Bearer ${this.#Token}`, 'Idempotency-Key': RequestId, 'X-Prism-Incarnation': Bootstrap.Incarnation };
        if (Body !== undefined) Headers['Content-Type'] = 'application/json';
        try {
            const Raw = await this.ReadRaw(Path, undefined, { method: 'POST', headers: Headers,
                ...(Body === undefined ? {} : { body: typeof Body === 'string' ? Body : JSON.stringify(Body) }) });
            return { ...DecodeCommand(JSON.parse(Raw)), OperationScope: Scope };
        } catch (Failure: unknown) {
            if (Failure instanceof OperationsError && Failure.Status !== 0) throw Failure;
            return { Ok: false, Status: 'unknown', Operation: null, OperationId: null,
                Message: '请求结果未确认。请按目标与时间核对操作记录，确认前不要重复发送。',
                LocalAttemptId: RequestId, OperationScope: Scope };
        }
    }
    private async ReadRaw(Path: string, Signal?: AbortSignal, Init: RequestInit = {}): Promise<string> {
        const Controller = new AbortController();
        const Timer = setTimeout(() => Controller.abort(), this.#TimeoutMs);
        const Abort = (): void => Controller.abort();
        Signal?.addEventListener('abort', Abort, { once: true });
        if (Signal?.aborted) Controller.abort();
        try {
            const Response = await this.#Fetch(`/Operations${Path}`, { cache: 'no-store', credentials: 'same-origin', ...Init, signal: Controller.signal });
            const Raw = await Response.text();
            if (Raw.length > 4 * 1024 * 1024) throw new OperationsError('管理响应超过大小预算', Response.status);
            let Parsed: unknown;
            try { Parsed = JSON.parse(Raw); } catch { throw new OperationsError('管理接口返回非 JSON 响应，请检查本机 Operations 服务', Response.status); }
            const Value = RecordValue(Parsed);
            if (!Response.ok && !(Init.method === 'POST' && typeof Value.status === 'string')) {
                if (Response.status === 403) { this.#Bootstrap = null; this.#Token = ''; }
                throw new OperationsError(`HTTP ${Response.status} · ${typeof Value.message === 'string' ? Value.message : typeof Value.error === 'string' ? Value.error : '管理请求失败'}`, Response.status);
            }
            return Raw;
        } catch (Failure: unknown) {
            if (Failure instanceof OperationsError) throw Failure;
            throw new OperationsError(Controller.signal.aborted ? '管理请求已取消或超时' : '无法连接本机 Operations 服务');
        } finally { clearTimeout(Timer); Signal?.removeEventListener('abort', Abort); }
    }
    private SessionPath(Identity: SessionIdentity): string { return `/Processes/${encodeURIComponent(Identity.ProcessId)}/Sessions/${encodeURIComponent(Identity.Id)}`; }
    private async Collection<Value>(Path: string, Page: PageRequest, Decode: (Input: unknown) => Value): Promise<CursorPage<Value>> {
        const Bootstrap = await this.GetBootstrap();
        const Supported = Bootstrap.Capabilities.includes(`${Path.toLowerCase()}.filter`);
        return DecodePage(await this.Query(`/${Path}${this.PageQuery(Page, {}, Supported)}`), Decode);
    }
    private PageQuery(Page: PageRequest, Extra: Readonly<Record<string, string>> = {}, FiltersSupported = false): string {
        const Params = new URLSearchParams({ cursor: Page.Cursor, limit: String(Math.max(1, Math.min(200, Page.Limit))), ...Extra });
        if (Page.Id) Params.set('id', Page.Id);
        if (FiltersSupported) for (const [Key, Value] of Object.entries({ q: Page.Query, state: Page.State, worker_id: Page.WorkerId, account_id: Page.AccountId,
            protocol: Page.Protocol, group_id: Page.GroupId, process_id: Page.ProcessId, generation_id: Page.GenerationId, sort: Page.Sort })) if (Value && Value !== 'all') Params.set(Key, Value);
        return `?${Params}`;
    }
}
