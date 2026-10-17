import { ParsePublicConfiguration } from '../Api/ConfigurationDocument.ts';
import { DemoHistory } from './DemoHistory.ts';
import { OperationScopeChangedError, WorkerIdentityChangedError } from './AdminDataSource.ts';
import type {
    AccountRecord, AdminDataSource, AdminActionResult, BootstrapReadOptions, ConfigurationSnapshot, ConfigurationValidation,
    CursorPage, DemoActionResult, EventPage, EventRecord, EventsFilter, GroupRecord,
    IngressRecord, OperationRecord, OverviewSnapshot, PageRequest, ProtocolRecord,
    SessionIdentity, SessionRecord, SessionTraceSpan, StreamIdentity, StreamRecord, TaskIdentity,
    TaskRecord, TrafficSample, WorkerRecord, WorkerIdentity, HistoryRequest, AccountUsage, UsageAdjustment, BootstrapSnapshot, OperationScope, SearchResult,
} from './AdminDataSource.ts';

const ProcessId = 'PRISM-DEMO-01';
const InitialGeneration = '42';
const InitialConfigurationFields = {
    SchemaVersion: 1,
    Runtime: { WorkerCount: 4, RequiredCapabilities: [], SessionTimeout: 30000 },
    Listeners: {
        Tcp: [{ Id: 'tcp-main', Address: '127.0.0.1', Port: 1080, Timeout: 5000 }],
        Udp: [{ Id: 'udp-main', Address: '127.0.0.1', Port: 1080, Timeout: 5000 }],
        Quic: [{ Id: 'quic-edge', Address: '127.0.0.1', Port: 1081, Timeout: 5000 }], Timeout: 5000,
    },
    NativeTls: { Enabled: false, CertificateFile: '', PrivateKeyFile: '' },
    Builtins: [],
    Protocols: [
        { Id: 'protocol-socks5', Name: 'socks5', Builtin: 'socks5', Requires: [] },
        { Id: 'protocol-vless', Name: 'vless', Builtin: 'vless', Requires: [] },
        { Id: 'protocol-trojan', Name: 'trojan', Builtin: 'trojan', Requires: [] },
        { Id: 'protocol-shadowsocks', Name: 'shadowsocks', Builtin: 'shadowsocks', Requires: [] },
    ],
    Carriers: [],
    ProtocolBindings: [
        { Id: 'binding-socks5', ProtocolId: 'protocol-socks5', TcpEnabled: true, UdpEnabled: true,
            MuxModes: [], Priority: 0, Recognition: {} },
        { Id: 'binding-socks5-direct', ProtocolId: 'protocol-socks5', TcpEnabled: true, UdpEnabled: false,
            MuxModes: [], Priority: 1, Recognition: {} },
        { Id: 'binding-vless-main', ProtocolId: 'protocol-vless', TcpEnabled: true, UdpEnabled: true,
            MuxModes: [], Priority: 2, Recognition: {} },
        { Id: 'binding-vless-edge', ProtocolId: 'protocol-vless', TcpEnabled: true, UdpEnabled: false,
            MuxModes: [], Priority: 3, Recognition: {} },
        { Id: 'binding-vless-relay', ProtocolId: 'protocol-vless', TcpEnabled: false, UdpEnabled: true,
            MuxModes: [], Priority: 4, Recognition: {} },
        { Id: 'binding-trojan', ProtocolId: 'protocol-trojan', TcpEnabled: true, UdpEnabled: true,
            MuxModes: [], Priority: 5, Recognition: {} },
        { Id: 'binding-shadowsocks', ProtocolId: 'protocol-shadowsocks', TcpEnabled: true, UdpEnabled: true,
            MuxModes: [], Priority: 6, Recognition: {} },
    ],
    AccountGroups: [
        { Id: 'group-core', Name: '核心线路' },
        { Id: 'group-standard', Name: '标准用户' },
    ],
    Accounts: [
        { Id: 'acct-northstar', GroupId: 'group-core', SecretRef: 'secret://demo/northstar' },
        { Id: 'acct-blue-hour', GroupId: 'group-standard', SecretRef: 'secret://demo/blue-hour' },
        { Id: 'acct-quiet-line', GroupId: 'group-standard', SecretRef: 'secret://demo/quiet-line' },
        { Id: 'acct-paper-plane', GroupId: null, SecretRef: 'secret://demo/paper-plane' },
        { Id: 'acct-retired-key', GroupId: null, SecretRef: 'secret://demo/retired-key' },
    ],
    Routes: [], Dns: { Servers: ['1.1.1.1'], Timeout: 1000 }, Recognition: {},
    Logging: { Level: 'Info', RenderMode: 'CompactHuman' },
    Trace: { IncludeCorrelation: true, IncludeWorker: true, IncludeSession: true, IncludeStream: false },
    Statistics: { Enabled: true, Interval: 1000 },
    Operations: { Enabled: true, Endpoint: '127.0.0.1:9090', Timeout: 1000, WebDirectory: null },
    HotReload: { Enabled: true, AckTimeout: 5000 }, Shutdown: { Timeout: 5000 },
};

const InitialConfiguration = JSON.stringify(InitialConfigurationFields, null, 2);
const EmptyTraffic = { Up: 0, Down: 0 } as const;

function RelativeTimestamp(MinutesAgo: number): string {
    return new Date(Date.now() - MinutesAgo * 60_000).toISOString();
}

function Clone<Value>(Input: Value): Value { return structuredClone(Input); }

function PageOf<Value>(Items: readonly Value[], Page: PageRequest): CursorPage<Value> {
    const Offset = Math.max(0, Number.parseInt(Page.Cursor, 10) || 0);
    const Limit = Math.max(1, Math.min(200, Page.Limit));
    const Values = Items.slice(Offset, Offset + Limit);
    return { Items: Clone(Values), NextCursor: String(Offset + Values.length), HasMore: Offset + Values.length < Items.length };
}
function FilterPage<Value extends { Id: string }>(Items: readonly Value[], Page: PageRequest): readonly Value[] {
    return Items.filter(Item => (!Page.Id || Item.Id === Page.Id) && (!Page.Query || JSON.stringify(Item).toLowerCase().includes(Page.Query.toLowerCase())));
}

function NumberOf(Value: string | number | null | undefined): number {
    const Parsed = Number(Value ?? 0);
    return Number.isFinite(Parsed) ? Parsed : 0;
}

function Sum(Value: readonly (string | number)[]): number {
    return Value.reduce<number>((Total, Item) => Total + NumberOf(Item), 0);
}

function SumTraffic(Items: readonly (Readonly<{ Up: string | number; Down: string | number }> | null)[]):
    Readonly<{ Up: number; Down: number }> {
    return {
        Up: Sum(Items.map(Item => Item?.Up ?? 0)),
        Down: Sum(Items.map(Item => Item?.Down ?? 0)),
    };
}

function LastSampleRate(Direction: 'Up' | 'Down'): string | null {
    const Previous = InitialHistory[InitialHistory.length - 2];
    const Last = InitialHistory[InitialHistory.length - 1];
    if (!Previous || !Last) return null;
    const Elapsed = Date.parse(Last.Time) - Date.parse(Previous.Time);
    const Delta = BigInt(String(Last.Traffic[Direction])) - BigInt(String(Previous.Traffic[Direction]));
    if (Elapsed <= 0 || Delta < 0n) return null;
    return (Delta * 1000n / BigInt(Elapsed)).toString();
}

function BuildTcpSessionHistory(Current: number, SampledAt: string): Array<{ Time: string; Count: string }> {
    const Offsets = [-3, -3, -2, -2, -2, -1, -1, -1, 0, 0, 0, 0, 0];
    const SampleTime = Date.parse(SampledAt);
    return Offsets.map((Offset, Index) => ({
        Time: new Date(SampleTime - (Offsets.length - Index - 1) * 5_000).toISOString(),
        Count: String(Math.max(0, Current + Offset)),
    }));
}

function Timestamp(MinutesAgo: number): string { return RelativeTimestamp(MinutesAgo); }

const InitialWorkers: WorkerRecord[] = [
    { Id: 'worker-01', Name: 'worker-01', ProcessId, GenerationId: InitialGeneration,
        State: 'running', Health: 'healthy', Running: true, Accepting: true, ActiveTasks: 2, DroppedEvents: 0,
        LoadPercent: 64,
        Traffic: { Up: 31_100_000, Down: 63_200_000 }, QueueDepth: 28, QueueCapacity: 512,
        StartedTasks: 4218, CompletedTasks: 4216, CancelledTasks: 0, DispatchAccepted: 4381,
        DispatchFull: 0, DispatchClosed: 3, DispatchUnavailable: 0, DispatchGenerationRejected: 1,
        CommandsExecuted: 12, CommandsFailed: 0 },
    { Id: 'worker-02', Name: 'worker-02', ProcessId, GenerationId: InitialGeneration,
        State: 'running', Health: 'healthy', Running: true, Accepting: true, ActiveTasks: 1, DroppedEvents: 3,
        LoadPercent: 41,
        Traffic: { Up: 18_100_000, Down: 37_600_000 }, QueueDepth: 19, QueueCapacity: 512,
        StartedTasks: 3862, CompletedTasks: 3861, CancelledTasks: 0, DispatchAccepted: 4022,
        DispatchFull: 2, DispatchClosed: 1, DispatchUnavailable: 0, DispatchGenerationRejected: 0,
        CommandsExecuted: 8, CommandsFailed: 1 },
    { Id: 'worker-03', Name: 'worker-03', ProcessId, GenerationId: InitialGeneration,
        State: 'draining', Health: 'degraded', Running: true, Accepting: false, ActiveTasks: 1, DroppedEvents: 9,
        LoadPercent: 82,
        Traffic: { Up: 9_100_000, Down: 12_200_000 }, QueueDepth: 4, QueueCapacity: 512,
        StartedTasks: 3108, CompletedTasks: 3107, CancelledTasks: 0, DispatchAccepted: 3271,
        DispatchFull: 0, DispatchClosed: 0, DispatchUnavailable: 2, DispatchGenerationRejected: 3,
        CommandsExecuted: 7, CommandsFailed: 0 },
    { Id: 'worker-04', Name: 'worker-04', ProcessId, GenerationId: InitialGeneration,
        State: 'offline', Health: 'unknown', Running: false, Accepting: false, ActiveTasks: 0, DroppedEvents: 0,
        LoadPercent: null,
        Traffic: null, QueueDepth: 0, QueueCapacity: 512, StartedTasks: 0, CompletedTasks: 0, CancelledTasks: 0,
        DispatchAccepted: 0, DispatchFull: 0, DispatchClosed: 0, DispatchUnavailable: 0,
        DispatchGenerationRejected: 0, CommandsExecuted: 0, CommandsFailed: 0 },
];

function MakeStream(Input: Readonly<{
    Id: string; TaskId: string; ParentTaskId: string | null; SessionId: string; AccountId: string;
    WorkerId: string; Traffic: Readonly<{ Up: number; Down: number }>; Protocol: string;
    State?: 'active' | 'draining';
}>): StreamRecord {
    return { ...Input, ProcessId, GenerationId: InitialGeneration, State: Input.State ?? 'active' };
}

function MakeTask(Input: Readonly<{
    Id: string; SessionId: string; WorkerId: string; StreamId: string; ParentTaskId: string | null;
    Status: TaskRecord['Status']; StartedMinutesAgo: number; CompletedMinutesAgo?: number;
    Cancellable: boolean; DrainBlocked?: boolean; DrainFailure?: string | null;
}>): TaskRecord {
    return {
        Id: Input.Id, ProcessId, WorkerId: Input.WorkerId, SessionId: Input.SessionId,
        StreamId: Input.StreamId, GenerationId: InitialGeneration, ParentTaskId: Input.ParentTaskId,
        Status: Input.Status, StartedAt: Timestamp(Input.StartedMinutesAgo),
        CompletedAt: Input.CompletedMinutesAgo === undefined ? null : Timestamp(Input.CompletedMinutesAgo),
        CancelRequested: false, Cancellable: Input.Cancellable,
        DrainBlocked: Input.DrainBlocked ?? false, Failure: null, DrainFailure: Input.DrainFailure ?? null,
    };
}

const InitialSessions: SessionRecord[] = [
    { Id: 'session-1001', ProcessId, WorkerId: 'worker-01', AccountId: 'acct-northstar', GenerationId: InitialGeneration,
        Identity: 'northstar', SourceAddress: '198.51.100.24:51842', Transport: 'tcp', Target: '203.0.113.18:443',
        Protocol: 'VLESS', Active: true, Draining: false, ActiveTasks: 2, StartedAt: Timestamp(72),
        Traffic: { Up: 24_800_000, Down: 49_200_000 },
        Streams: [
            MakeStream({ Id: 'stream-7001', TaskId: 'task-9001', ParentTaskId: null, SessionId: 'session-1001',
                AccountId: 'acct-northstar', WorkerId: 'worker-01', Traffic: { Up: 18_000_000, Down: 34_000_000 }, Protocol: 'TCP' }),
            MakeStream({ Id: 'stream-7002', TaskId: 'task-9002', ParentTaskId: 'task-9001', SessionId: 'session-1001',
                AccountId: 'acct-northstar', WorkerId: 'worker-01', Traffic: { Up: 6_800_000, Down: 15_200_000 }, Protocol: 'UDP' }),
        ],
        Tasks: [
            MakeTask({ Id: 'task-9001', SessionId: 'session-1001', WorkerId: 'worker-01', StreamId: 'stream-7001',
                ParentTaskId: null, Status: 'running', StartedMinutesAgo: 72, Cancellable: false }),
            MakeTask({ Id: 'task-9002', SessionId: 'session-1001', WorkerId: 'worker-01', StreamId: 'stream-7002',
                ParentTaskId: 'task-9001', Status: 'running', StartedMinutesAgo: 58, Cancellable: true }),
        ],
    },
    { Id: 'session-1002', ProcessId, WorkerId: 'worker-02', AccountId: 'acct-blue-hour', GenerationId: InitialGeneration,
        Identity: 'blue-hour', SourceAddress: '203.0.113.54:60411', Transport: 'tcp', Target: '192.0.2.41:8443',
        Protocol: 'Trojan', Active: true, Draining: false, ActiveTasks: 1, StartedAt: Timestamp(50),
        Traffic: { Up: 18_100_000, Down: 37_600_000 },
        Streams: [MakeStream({ Id: 'stream-7003', TaskId: 'task-9003', ParentTaskId: null, SessionId: 'session-1002',
            AccountId: 'acct-blue-hour', WorkerId: 'worker-02', Traffic: { Up: 18_100_000, Down: 37_600_000 }, Protocol: 'TCP' })],
        Tasks: [MakeTask({ Id: 'task-9003', SessionId: 'session-1002', WorkerId: 'worker-02', StreamId: 'stream-7003',
            ParentTaskId: null, Status: 'running', StartedMinutesAgo: 50, Cancellable: true })],
    },
    { Id: 'session-1003', ProcessId, WorkerId: 'worker-03', AccountId: 'acct-northstar', GenerationId: InitialGeneration,
        Identity: 'northstar', SourceAddress: '198.51.100.87:44108', Transport: 'tcp', Target: '192.0.2.76:443',
        Protocol: 'Shadowsocks', Active: true, Draining: true, ActiveTasks: 1, StartedAt: Timestamp(108),
        Traffic: { Up: 9_100_000, Down: 12_200_000 },
        Streams: [MakeStream({ Id: 'stream-7004', TaskId: 'task-9004', ParentTaskId: null, SessionId: 'session-1003',
            AccountId: 'acct-northstar', WorkerId: 'worker-03', Traffic: { Up: 9_100_000, Down: 12_200_000 },
            Protocol: 'TCP', State: 'draining' })],
        Tasks: [MakeTask({ Id: 'task-9004', SessionId: 'session-1003', WorkerId: 'worker-03', StreamId: 'stream-7004',
            ParentTaskId: null, Status: 'running', StartedMinutesAgo: 108, Cancellable: true, DrainBlocked: true,
            DrainFailure: '等待协议流正常关闭' })],
    },
    { Id: 'session-1004', ProcessId, WorkerId: 'worker-01', AccountId: 'acct-quiet-line', GenerationId: InitialGeneration,
        Identity: 'quiet-line', SourceAddress: '198.51.100.115:52291', Transport: 'tcp', Target: '203.0.113.62:443',
        Protocol: 'SOCKS5', Active: true, Draining: false, ActiveTasks: 0, StartedAt: Timestamp(3),
        Traffic: { Up: 4_200_000, Down: 7_600_000 }, Streams: [], Tasks: [],
    },
    { Id: 'session-0998', ProcessId, WorkerId: 'worker-01', AccountId: 'acct-blue-hour', GenerationId: InitialGeneration,
        Identity: 'blue-hour', SourceAddress: '203.0.113.22:49001', Transport: 'tcp', Target: '192.0.2.10:443',
        Protocol: 'Trojan', Active: false, Draining: false, ActiveTasks: 0, StartedAt: Timestamp(132),
        Traffic: { Up: 2_100_000, Down: 6_400_000 }, Streams: [], Tasks: [],
    },
];

const InitialAccounts: AccountRecord[] = [
    { Id: 'acct-northstar', GenerationId: InitialGeneration, Label: 'northstar', GroupId: 'group-core', Revoked: false,
        ActiveSessions: 2, Traffic: { Up: 33_900_000, Down: 61_400_000 } },
    { Id: 'acct-blue-hour', GenerationId: InitialGeneration, Label: 'blue-hour', GroupId: 'group-standard', Revoked: false,
        ActiveSessions: 1, Traffic: { Up: 20_200_000, Down: 44_000_000 } },
    { Id: 'acct-quiet-line', GenerationId: InitialGeneration, Label: 'quiet-line', GroupId: 'group-standard', Revoked: false,
        ActiveSessions: 1, Traffic: { Up: 4_200_000, Down: 7_600_000 } },
    { Id: 'acct-paper-plane', GenerationId: InitialGeneration, Label: 'paper-plane', GroupId: null, Revoked: false,
        ActiveSessions: 0, Traffic: EmptyTraffic },
    { Id: 'acct-retired-key', GenerationId: InitialGeneration, Label: 'retired-key', GroupId: null, Revoked: true,
        ActiveSessions: 0, Traffic: EmptyTraffic },
];

const InitialIngresses: IngressRecord[] = [
    { Id: 'tcp-main', Transport: 'tcp', ConfiguredAddress: '127.0.0.1:1080', BoundAddress: '127.0.0.1:1080',
        Ready: true, ActiveConnections: 4, Protocols: ['SOCKS5', 'VLESS', 'Trojan', 'Shadowsocks'], Carriers: ['TCP'] },
    { Id: 'udp-main', Transport: 'udp', ConfiguredAddress: '127.0.0.1:1080', BoundAddress: '127.0.0.1:1080',
        Ready: true, ActiveConnections: null, Protocols: ['SOCKS5', 'VLESS'], Carriers: ['UDP datagram'] },
    { Id: 'quic-edge', Transport: 'quic', ConfiguredAddress: '127.0.0.1:1081', BoundAddress: null,
        Ready: false, ActiveConnections: null, Protocols: ['VLESS'], Carriers: ['QUIC'] },
];

const HistorySampledAt = Date.now();
let TotalUpBytes = 21_300_000;
let TotalDownBytes = 41_000_000;
const InitialHistory: TrafficSample[] = Array.from({ length: 61 }, (_, Index) => {
    const Progress = Index / 60;
    const UpRate = Math.max(220_000, 470_000 + 155_000 * Math.sin(Progress * Math.PI * 4.4) +
        72_000 * Math.sin(Progress * Math.PI * 10.2 + 0.4));
    const DownRate = Math.max(340_000, 770_000 + 260_000 * Math.sin(Progress * Math.PI * 3.5 + 0.7) +
        118_000 * Math.cos(Progress * Math.PI * 8.4));
    if (Index > 0) {
        TotalUpBytes += Math.round(UpRate);
        TotalDownBytes += Math.round(DownRate);
    }
    return {
        Time: new Date(HistorySampledAt - (60 - Index) * 1000).toISOString(),
        Traffic: {
            Up: TotalUpBytes,
            Down: TotalDownBytes,
            Events: 0, Errors: 0,
        },
    };
});

const ProtocolSamples: readonly ProtocolRecord[] = [
    { Id: 'socks5', Name: 'SOCKS5', ConfiguredBindings: 2, ActiveSessions: 1,
        Traffic: { Up: 4_200_000, Down: 7_600_000, Events: 0, Errors: 0 }, Latency: null,
        Coverage: '按已接受 TCP Session 归属' },
    { Id: 'vless', Name: 'VLESS', ConfiguredBindings: 3, ActiveSessions: 1,
        Traffic: { Up: 24_800_000, Down: 49_200_000, Events: 0, Errors: 0 }, Latency: null,
        Coverage: 'TCP Session 可关联；QUIC admission 未关联' },
    { Id: 'trojan', Name: 'Trojan', ConfiguredBindings: 1, ActiveSessions: 1,
        Traffic: { Up: 20_200_000, Down: 44_000_000, Events: 0, Errors: 0 }, Latency: null,
        Coverage: '按已接受 TCP Session 归属' },
    { Id: 'shadowsocks', Name: 'Shadowsocks', ConfiguredBindings: 1, ActiveSessions: 1,
        Traffic: { Up: 9_100_000, Down: 12_200_000, Events: 0, Errors: 0 }, Latency: null,
        Coverage: '按已接受 TCP Session 归属' },
];

const InitialObservations = { Accepted: 2486, Consumed: 2474, Dropped: 12, AggregationFailures: 0 } as const;
const GroupDefinitions = [
    { Id: 'group-core', Name: '核心线路' },
    { Id: 'group-standard', Name: '标准用户' },
] as const;

type EventContext = Partial<Pick<EventRecord,
    'Scope' | 'WorkerId' | 'AccountId' | 'SessionId' | 'StreamId' | 'TaskId' | 'ParentTaskId' | 'OperationId'>>;

function MakeEvent(Input: Readonly<{
    Sequence: number; MinutesAgo: number; Severity: EventRecord['Severity']; Kind: string;
    Scope: EventRecord['Scope']; Message: string; Detail: string; Context?: EventContext;
}>): EventRecord {
    const Context = Input.Context ?? {};
    return {
        Id: `event-${Input.Sequence}`, Sequence: Input.Sequence, Time: RelativeTimestamp(Input.MinutesAgo),
        CorrelationId: `corr-${Input.Sequence}`, GenerationId: InitialGeneration, ProcessId,
        WorkerId: Context.WorkerId ?? null, AccountId: Context.AccountId ?? null,
        SessionId: Context.SessionId ?? null, StreamId: Context.StreamId ?? null,
        TaskId: Context.TaskId ?? null, ParentTaskId: Context.ParentTaskId ?? null,
        OperationId: Context.OperationId ?? null, Severity: Input.Severity, Kind: Input.Kind, Scope: Input.Scope,
        Message: Input.Message, Detail: Input.Detail, Terminal: false, Truncated: false,
    };
}

function MakeTrace(Session: SessionRecord): readonly SessionTraceSpan[] {
    const Start = new Date(Session.StartedAt).getTime();
    const Stages = [
        { Id: 'ingress', Name: '入口接收', Offset: 0, Duration: 0.18, Status: 'ok',
            Attributes: { 'net.transport': Session.Transport, 'net.peer.ip': Session.SourceAddress } },
        { Id: 'dispatch', Name: 'Worker 派发', Offset: 0.18, Duration: 0.42, Status: 'ok',
            Attributes: { 'worker.id': Session.WorkerId, 'dispatch.queue_depth': '28' } },
        { Id: 'auth', Name: '协议识别与认证', Offset: 0.6, Duration: 7.6, Status: 'ok',
            Attributes: { 'proxy.protocol': Session.Protocol, 'enduser.id': Session.Identity } },
        { Id: 'dial', Name: '出站解析与拨号', Offset: 8.2, Duration: 12.4, Status: 'ok',
            Attributes: { 'server.address': Session.Target.split(':')[0] ?? Session.Target,
                'server.port': Session.Target.split(':')[1] ?? '' } },
        { Id: 'first-write', Name: '首批下行有效载荷写出', Offset: 20.6, Duration: null, Status: 'ok',
            Attributes: { stage: 'relay.first_download_byte', outcome: 'written' } },
        { Id: 'relay', Name: '双向转发', Offset: 25.4, Duration: null as number | null,
            Status: Session.Draining ? 'draining' : Session.Active ? 'active' : 'ended',
            Attributes: { 'proxy.upstream': Session.Target, 'proxy.transfer': 'bidirectional' } },
    ];
    return Stages.map((Stage, Index) => ({
        SpanId: `event-${Session.Id}-${Stage.Id}`, ParentSpanId: null,
        Sequence: Index + 1, Name: Stage.Name, StartTime: new Date(Start + Stage.Offset).toISOString(),
        DurationMs: null, Status: Stage.Status, SessionId: Session.Id, WorkerId: Session.WorkerId,
        AccountId: Session.AccountId, TaskId: Session.Tasks[Index === 2 ? 0 : Index > 2 ? 1 : 0]?.Id ?? null,
        ParentTaskId: Session.Tasks[Index === 2 ? 0 : Index > 2 ? 1 : 0]?.ParentTaskId ?? null,
        StreamId: Session.Streams[0]?.Id ?? null, Attributes: { ...Stage.Attributes, elapsed_ns: String(Math.round(Stage.Offset * 1_000_000)) },
    }));
}

export class DemoAdminDataSource implements AdminDataSource {
    private Workers = Clone(InitialWorkers);
    private Sessions = Clone(InitialSessions);
    private Accounts = Clone(InitialAccounts);
    private Groups: Array<{ Id: string; Name: string }> = GroupDefinitions.map(Value => ({ ...Value }));
    private MemorySampleIndex = 0;
    private Events: EventRecord[] = [
        MakeEvent({ Sequence: 618, MinutesAgo: 1, Severity: 'info', Kind: 'listener_ready', Scope: 'process',
            Message: 'TCP 入口已就绪', Detail: 'tcp-main 已绑定 127.0.0.1:1080，可接收代理连接' }),
        MakeEvent({ Sequence: 617, MinutesAgo: 2, Severity: 'warning', Kind: 'operation_accepted', Scope: 'worker',
            Message: 'Worker 正在排空', Detail: '等待 1 个活动任务完成', Context: { WorkerId: 'worker-03', OperationId: 'op-6399' } }),
        MakeEvent({ Sequence: 616, MinutesAgo: 3, Severity: 'info', Kind: 'session_started', Scope: 'session',
            Message: 'SOCKS5 Session 已建立', Detail: 'TCP · quiet-line · worker-01',
            Context: { WorkerId: 'worker-01', AccountId: 'acct-quiet-line', SessionId: 'session-1004' } }),
        MakeEvent({ Sequence: 611, MinutesAgo: 10, Severity: 'error', Kind: 'stream_closed', Scope: 'stream',
            Message: '出站 Stream 提前关闭', Detail: '上游在半关闭后断开；Session 保持可追踪状态',
            Context: { WorkerId: 'worker-02', AccountId: 'acct-blue-hour', SessionId: 'session-1002', StreamId: 'stream-7003' } }),
        MakeEvent({ Sequence: 610, MinutesAgo: 12, Severity: 'info', Kind: 'generation_reloaded', Scope: 'process',
            Message: '配置 Generation 已加载', Detail: '当前运行版本为 Generation 42' }),
    ];
    private Operations: OperationRecord[] = [
        { Id: 'op-6399', Name: '排空 Worker', Target: 'worker-03', State: 'running',
            StartedAt: RelativeTimestamp(2), UpdatedAt: RelativeTimestamp(1), Message: '等待 1 个活动任务完成',
            CorrelationId: 'corr-op-6399', GenerationId: InitialGeneration, Failure: null, ProcessId,
            WorkerId: 'worker-03' },
        { Id: 'op-6398', Name: '配置校验', Target: 'generation-42', State: 'completed',
            StartedAt: RelativeTimestamp(12), UpdatedAt: RelativeTimestamp(12), Message: '演示配置校验通过',
            CorrelationId: 'corr-op-6398', GenerationId: InitialGeneration, Failure: null, ProcessId },
    ];
    private Configuration: ConfigurationSnapshot = {
        Generation: InitialGeneration, Reloadable: true, Text: InitialConfiguration, UpdatedAt: RelativeTimestamp(12),
    };
    private NextOperation = 6400;
    private NextEvent = 619;
    private UsageAdjustments = new Map<string, { Added: bigint; Released: bigint; Revision: bigint }>();

    public async GetBootstrap(_Options: BootstrapReadOptions = {}): Promise<BootstrapSnapshot> {
        return { ApiVersion: '2', InstanceKey: 'demo-instance', ProcessId, Incarnation: 'demo-incarnation',
            Capabilities: ['history.read', 'accounts.usage.read', 'accounts.usage.adjust', 'search.read', 'workers.drain', 'accounts.revoke', 'sessions.cancel', 'streams.reset', 'tasks.cancel', 'configuration.read', 'configuration.reload.validate', 'configuration.reload.apply', 'configuration.reload.persist'] };
    }
    public async GetHistory(Request: HistoryRequest) { return DemoHistory(Request); }
    public async GetProtocols(Page: PageRequest) { return PageOf((await this.GetOverview()).Protocols, Page); }
    public async GetAccountUsage(AccountKey: string): Promise<AccountUsage> {
        const Account = this.Accounts.find(Item => Item.Id === AccountKey || Item.Label === AccountKey);
        if (!Account) throw new Error('演示账户不存在');
        const Adjustment = this.UsageAdjustments.get(Account.Id) ?? { Added: 0n, Released: 0n, Revision: 1n };
        const Limit = Account.GroupId === 'group-core' ? 107374182400n : Account.GroupId ? 21474836480n : null;
        const Settled = BigInt(Account.Traffic?.Up ?? 0) + BigInt(Account.Traffic?.Down ?? 0), Reserved = 1048576n, Uncertain = 524288n - Adjustment.Released;
        const Total = Limit === null ? null : Limit + Adjustment.Added;
        const Available = Total === null ? null : Total - Settled - Reserved - Uncertain;
        const Now = new Date(), Start = new Date(Date.UTC(Now.getUTCFullYear(), Now.getUTCMonth(), 1) - 8 * 3600000), End = new Date(Date.UTC(Now.getUTCFullYear(), Now.getUTCMonth() + 1, 1) - 8 * 3600000);
        return { AccountKey: Account.Id, Revision: Adjustment.Revision.toString(), CycleStart: Start.toISOString(), CycleEnd: End.toISOString(), LimitBytes: Total?.toString() ?? null,
            SettledBytes: Settled.toString(), ReservedBytes: Reserved.toString(), UncertainBytes: Uncertain.toString(), RemainingBytes: Available === null ? null : (Available > 0n ? Available : 0n).toString(),
            OverageBytes: Total !== null && Settled > Total ? (Settled - Total).toString() : '0', Available: true, Failure: null };
    }
    public async AdjustUsage(Input: UsageAdjustment): Promise<AdminActionResult> {
        const Usage = await this.GetAccountUsage(Input.AccountKey);
        if (Usage.Revision !== Input.Revision) return this.Reject('账本修订冲突，请重新读取', Input.AccountKey);
        const Previous = this.UsageAdjustments.get(Usage.AccountKey) ?? { Added: 0n, Released: 0n, Revision: 1n };
        const Bytes = BigInt(Input.Bytes);
        if (Bytes <= 0n || !Input.Reason.trim()) return this.Reject('调整必须包含正字节数与原因', Input.AccountKey);
        if (Input.Kind === 'release_uncertain' && Bytes > BigInt(Usage.UncertainBytes)) return this.Reject('释放量超过异常占额', Input.AccountKey);
        this.UsageAdjustments.set(Usage.AccountKey, { Added: Previous.Added + (Input.Kind === 'add_allowance' ? Bytes : 0n), Released: Previous.Released + (Input.Kind === 'release_uncertain' ? Bytes : 0n), Revision: Previous.Revision + 1n });
        return this.Record('额度调整', Input.AccountKey, `演示：${Input.Reason}`, 'info', { Scope: 'account', AccountId: Usage.AccountKey }, 'completed');
    }
    public async Search(Query: string, Signal?: AbortSignal): Promise<readonly SearchResult[]> {
        Signal?.throwIfAborted();
        const Rows: SearchResult[] = [
            ...this.Accounts.map(Item => ({ Id: Item.Id, Kind: 'account', Label: Item.Label, Detail: `账户 · ${Item.Id}`, Path: `/accounts?account=${Item.Id}` })),
            ...this.Workers.map(Item => ({ Id: Item.Id, Kind: 'worker', Label: Item.Name, Detail: `Worker · ${Item.State}`,
                Path: `/workers?${new URLSearchParams({ worker: Item.Id, process: Item.ProcessId, generation: Item.GenerationId })}` })),
            ...this.Sessions.map(Item => ({ Id: Item.Id, Kind: 'session', Label: Item.Id, Detail: `${Item.Protocol} · ${Item.Target}`, Path: `/sessions?${new URLSearchParams({ session: Item.Id, process: Item.ProcessId, generation: Item.GenerationId, identity_worker: Item.WorkerId, identity_account: Item.AccountId })}` })),
        ];
        return Rows.filter(Item => `${Item.Id} ${Item.Label} ${Item.Detail}`.toLowerCase().includes(Query.toLowerCase())).slice(0, 20);
    }

    public async GetOverview(): Promise<OverviewSnapshot> {
        const ActiveSessions = this.Sessions.filter(Session => Session.Active);
        const ActiveAccounts = this.Accounts.filter(Account => !Account.Revoked && NumberOf(Account.ActiveSessions) > 0);
        const Traffic = SumTraffic(this.Sessions.map(Session => Session.Traffic));
        const WorkersAccepting = this.Workers.filter(Worker => Worker.Running && Worker.Accepting).length;
        const TcpSessionCount = ActiveSessions.filter(Session => Session.Transport === 'tcp').length;
        const GenerationId = this.Configuration.Generation;
        const Now = new Date().toISOString();
        this.MemorySampleIndex += 1;
        const PmrAllocations = 882_410 + this.MemorySampleIndex * 1_800;
        const PmrReleases = 880_993 + this.MemorySampleIndex * 1_760;
        const PoolAllocations = 119_204 + this.MemorySampleIndex * 1_260;
        const PoolReleases = 118_778 + this.MemorySampleIndex * 1_240;
        return Clone({
            SampledAt: Now, SampleIntervalMs: 5000,
            Process: { Id: ProcessId, GenerationId, Phase: 'ready' },
            Health: { Status: 'degraded', CheckedAt: Now, Ready: true, TcpReady: true, UdpReady: true,
                UdpSocketReady: true, QuicReady: false, QuicSocketReady: false, QuicHandshakeReady: false,
                QuicProtocolReady: false, Active: ActiveSessions.length, Errors: 0 },
            Counts: { ConfiguredAccounts: this.Accounts.length, ActiveAccounts: ActiveAccounts.length,
                UngroupedAccounts: this.Accounts.filter(Account => !Account.GroupId).length,
                TcpSessions: TcpSessionCount,
                UdpConnections: null, QuicConnections: null,
                WorkersTotal: this.Workers.length, WorkersAccepting },
            Traffic: { Available: true, UpBytes: Traffic.Up, DownBytes: Traffic.Down, Events: 0, Errors: 0,
                UpBytesPerSecond: LastSampleRate('Up'), DownBytesPerSecond: LastSampleRate('Down') },
            Latency: {
                RecognitionAdmission: { Available: true, SampleCount: 24380, P50Ms: '8', P95Ms: '18',
                    P99Ms: '61', MaxMs: '121' },
                Stages: [],
            },
            Memory: {
                ProcessAvailable: true, ProcessRssBytes: 642_252_800, ProcessPeakRssBytes: 711_983_104,
                WorkingSetBytes: 642_252_800,
                BytePool: { Available: true, UsedBytes: 168_820_736, CapacityBytes: 268_435_456,
                    AvailableBlocks: 18240, BlockSize: 16384, PeakUsedBytes: 193_986_560,
                    AllocationCount: PoolAllocations, ReleaseCount: PoolReleases },
                Allocations: { Available: true, CurrentBytes: 91_307_008, PeakBytes: 142_606_336,
                    AllocationCount: PmrAllocations, ReleaseCount: PmrReleases,
                    Coverage: '仅计通过 Preview ProcessResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配' },
                WorkerAllocations: [
                    { WorkerId: 'worker-01', Allocation: { Available: true, CurrentBytes: 38_797_312,
                        PeakBytes: 52_428_800, AllocationCount: 31024, ReleaseCount: 30986,
                        Coverage: '仅计通过 WorkerResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配' } },
                    { WorkerId: 'worker-02', Allocation: { Available: true, CurrentBytes: 27_262_976,
                        PeakBytes: 35_651_584, AllocationCount: 22410, ReleaseCount: 22383,
                        Coverage: '仅计通过 WorkerResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配' } },
                    { WorkerId: 'worker-03', Allocation: { Available: true, CurrentBytes: 25_165_824,
                        PeakBytes: 38_797_312, AllocationCount: 19618, ReleaseCount: 19592,
                        Coverage: '仅计通过 WorkerResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配' } },
                    { WorkerId: 'worker-04', Allocation: { Available: true, CurrentBytes: 0,
                        PeakBytes: 0, AllocationCount: 0, ReleaseCount: 0,
                        Coverage: '仅计通过 WorkerResources TrackingResource 的 PMR 请求；不含全局堆或第三方分配' } },
                ],
            },
            Observations: InitialObservations,
            History: InitialHistory,
            TcpSessionHistory: BuildTcpSessionHistory(TcpSessionCount, Now),
            Protocols: ProtocolSamples.map(Protocol => ({ ...Protocol,
                ActiveSessions: ActiveSessions.filter(Session => Session.Protocol.toLowerCase() === Protocol.Name.toLowerCase()).length })),
        });
    }

    public async GetIngresses(Page: PageRequest): Promise<CursorPage<IngressRecord>> {
        return PageOf(InitialIngresses, Page);
    }

    public async GetWorkers(Page: PageRequest): Promise<CursorPage<WorkerRecord>> {
        return PageOf(FilterPage(this.Workers, Page), Page);
    }

    public async GetAccounts(Page: PageRequest): Promise<CursorPage<AccountRecord>> {
        return PageOf(FilterPage(this.Accounts, Page).map(Account => ({ ...Account, AccountKey: Account.Id,
            UploadBytesPerSecond: BigInt(Account.ActiveSessions) > 0n ? '184320' : '0', DownloadBytesPerSecond: BigInt(Account.ActiveSessions) > 0n ? '307200' : '0',
            EffectivePolicy: { max_connections: Account.GroupId === 'group-core' ? '64' : '16', max_streams: '128', limit_bytes: Account.GroupId === 'group-core' ? '107374182400' : Account.GroupId ? '21474836480' : null,
                upload_bytes_per_second: '10485760', download_bytes_per_second: '20971520', cycle: 'month', utc_offset_minutes: 480 },
            PolicySources: { max_connections: Account.GroupId ?? 'system', max_streams: 'account', limit_bytes: Account.GroupId ?? 'system', upload_bytes_per_second: 'account', download_bytes_per_second: 'account', cycle: 'system', utc_offset_minutes: 'system' } })), Page);
    }

    public async GetGroups(Page: PageRequest): Promise<CursorPage<GroupRecord>> {
        const Groups = this.Groups.map(Definition => {
            const Members = this.Accounts.filter(Account => Account.GroupId === Definition.Id);
            const AccountIds = new Set(Members.map(Account => Account.Id));
            const GroupSessions = this.Sessions.filter(Session => Session.Active && AccountIds.has(Session.AccountId));
            const GroupTraffic = SumTraffic(Members.map(Account => Account.Traffic));
            return {
                ...Definition,
                ConfiguredAccountCount: Members.length,
                ActiveAccountCount: Members.filter(Account => !Account.Revoked && NumberOf(Account.ActiveSessions) > 0).length,
                ActiveSessions: GroupSessions.length,
                Traffic: { ...GroupTraffic, Events: GroupSessions.length * 2840, Errors: GroupSessions.length > 0 ? 1 : 0 },
            } satisfies GroupRecord;
        });
        return PageOf(Groups, Page);
    }

    public async CreateGroup(Name: string): Promise<AdminActionResult> {
        const Value = Name.trim();
        if (Value.length < 2 || Value.length > 40)
            return this.Reject('用户组名称长度应为 2 至 40 个字符', Value || '新用户组');
        if (this.Groups.some(Group => Group.Name.toLocaleLowerCase() === Value.toLocaleLowerCase()))
            return this.Reject('已存在同名用户组', Value);
        const Id = `group-demo-${this.Groups.length + 1}`;
        this.Groups.push({ Id, Name: Value });
        return this.Record('创建用户组', Id, `演示：已创建用户组「${Value}」。`, 'info', { Scope: 'process' }, 'completed');
    }

    public async RenameGroup(Id: string, Name: string): Promise<AdminActionResult> {
        const Value = Name.trim();
        const Group = this.Groups.find(Item => Item.Id === Id);
        if (!Group) return this.Reject('用户组不存在', Id);
        if (Value.length < 2 || Value.length > 40)
            return this.Reject('用户组名称长度应为 2 至 40 个字符', Id);
        if (this.Groups.some(Item => Item.Id !== Id && Item.Name.toLocaleLowerCase() === Value.toLocaleLowerCase()))
            return this.Reject('已存在同名用户组', Value);
        Group.Name = Value;
        return this.Record('重命名用户组', Id, `演示：用户组已改名为「${Value}」。`, 'info', { Scope: 'process' }, 'completed');
    }

    public async SetAccountGroup(AccountId: string, GroupId: string | null): Promise<AdminActionResult> {
        const Account = this.Accounts.find(Value => Value.Id === AccountId);
        if (!Account) return this.Reject('账户不存在', AccountId);
        if (GroupId !== null && !this.Groups.some(Group => Group.Id === GroupId))
            return this.Reject('目标用户组不存在', GroupId);
        const GroupName = GroupId === null ? '未分组' : this.Groups.find(Group => Group.Id === GroupId)?.Name ?? GroupId;
        this.Accounts = this.Accounts.map(Value => Value.Id === AccountId ? { ...Value, GroupId } : Value);
        return this.Record('调整账户分组', AccountId, `演示：账户已归入「${GroupName}」。`, 'info',
            { Scope: 'account', AccountId }, 'completed');
    }

    public async GetSessions(Page: PageRequest): Promise<CursorPage<SessionRecord>> {
        return PageOf(FilterPage(this.Sessions, Page).filter(Item => (!Page.WorkerId || Item.WorkerId === Page.WorkerId) && (!Page.AccountId || Item.AccountId === Page.AccountId) && (!Page.Protocol || Page.Protocol === 'all' || Item.Protocol === Page.Protocol)), Page);
    }

    public async GetSessionTrace(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<SessionTraceSpan>> {
        const Session = this.Sessions.find(Value => MatchesSession(Value, Identity));
        return PageOf(Session ? MakeTrace(Session) : [], Page);
    }

    public async GetStreams(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<StreamRecord>> {
        const Session = this.Sessions.find(Value => MatchesSession(Value, Identity));
        return PageOf(Session?.Streams ?? [], Page);
    }

    public async GetTasks(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<TaskRecord>> {
        const Session = this.Sessions.find(Value => MatchesSession(Value, Identity));
        return PageOf(Session?.Tasks ?? [], Page);
    }

    public async GetEvents(Page: PageRequest, Filter: EventsFilter = {}): Promise<EventPage> {
        const Filtered = this.Events.filter(Event =>
            (Filter.SessionId === undefined || Event.SessionId === Filter.SessionId) &&
            (Filter.WorkerId === undefined || Event.WorkerId === Filter.WorkerId) &&
            (Filter.AccountId === undefined || Event.AccountId === Filter.AccountId) &&
            (Filter.Severity === undefined || Event.Severity === Filter.Severity));
        const Window = PageOf(Filtered, Page);
        const Sequences = Filtered.map(Event => NumberOf(Event.Sequence));
        return Clone({ ...Window, EarliestCursor: String(Math.min(...Sequences, this.NextEvent)), Lost: true,
            LostRanges: [{ First: 612, Last: 615 }], Dropped: 12, TerminalDropped: 2, Overwritten: 8,
            SeverityFilterSupported: true });
    }

    public async GetConfiguration(): Promise<ConfigurationSnapshot> { return Clone(this.Configuration); }

    public async GetOperations(Page: PageRequest, Scope: OperationScope): Promise<CursorPage<OperationRecord>> {
        this.RequireOperationScope(Scope);
        const Value = PageOf(this.Operations, Page);
        this.RequireOperationScope(Scope);
        return Value;
    }

    public async GetOperationStatus(Id: string, Scope: OperationScope): Promise<OperationRecord> {
        this.RequireOperationScope(Scope);
        const Operation = this.Operations.find(Value => Value.Id === Id);
        if (Operation === undefined) throw new Error(`演示操作 ${Id} 不存在`);
        this.RequireOperationScope(Scope);
        return Clone(Operation);
    }

    public async DrainWorker(Identity: WorkerIdentity): Promise<AdminActionResult> {
        const Bootstrap = await this.GetBootstrap({ Fresh: true });
        const Worker = this.Workers.find(Value => Value.Id === Identity.Id);
        if (Bootstrap.ProcessId !== Identity.ProcessId || Worker === undefined ||
            Worker.ProcessId !== Identity.ProcessId || Worker.GenerationId !== Identity.GenerationId)
            throw new WorkerIdentityChangedError();
        if (!Worker.Running || !Worker.Accepting) return this.Reject('Worker 当前不可排空', Identity.Id);
        this.Workers = this.Workers.map(Value => Value.Id === Identity.Id
            ? { ...Value, State: 'draining', Health: 'draining', Accepting: false } : Value);
        return this.Record('排空 Worker', Identity.Id, '演示：Worker 已停止接收新 Session，等待现有任务完成。', 'warning',
            { Scope: 'worker', WorkerId: Identity.Id }, 'accepted');
    }

    public async RevokeAccount(Id: string, CloseSessions: boolean): Promise<AdminActionResult> {
        const Account = this.Accounts.find(Value => Value.Id === Id);
        if (Account === undefined || Account.Revoked) return this.Reject('账户不存在或已撤销', Id);
        if (CloseSessions) this.Sessions = this.Sessions.map(Value => Value.AccountId === Id
            ? { ...Value, Active: false, Draining: true } : Value);
        this.Accounts = this.Accounts.map(Value => Value.Id === Id ? { ...Value, Revoked: true } : Value);
        this.RefreshAccountCounts();
        const Detail = CloseSessions ? '演示：账户已撤销，关联 Session 正在关闭。' : '演示：账户已撤销，现有 Session 保留。';
        return this.Record('撤销账户', Id, Detail, 'warning', { Scope: 'account', AccountId: Id }, 'completed');
    }

    public async CancelSession(Identity: SessionIdentity): Promise<AdminActionResult> {
        const Session = this.Sessions.find(Value => MatchesSession(Value, Identity));
        if (Session === undefined || !Session.Active || Session.Draining)
            return this.Reject('Session 不存在、已结束或正在排空', Identity.Id);
        this.Sessions = this.Sessions.map(Value => Value.Id === Session.Id
            ? { ...Value, Active: false, Draining: true } : Value);
        this.RefreshAccountCounts();
        return this.Record('取消 Session', Session.Id, '演示：Session 已进入排空，等待资源关闭。', 'warning',
            { Scope: 'session', WorkerId: Session.WorkerId, AccountId: Session.AccountId, SessionId: Session.Id }, 'accepted');
    }

    public async ResetStream(Identity: StreamIdentity): Promise<AdminActionResult> {
        const Session = this.Sessions.find(Value => Value.Id === Identity.SessionId && Value.ProcessId === Identity.ProcessId &&
            Value.WorkerId === Identity.WorkerId && Value.AccountId === Identity.AccountId && Value.GenerationId === Identity.GenerationId);
        const Stream = Session?.Streams.find(Value => Value.Id === Identity.Id && Value.TaskId === Identity.TaskId &&
            Value.ParentTaskId === Identity.ParentTaskId);
        if (Session === undefined || Stream === undefined || Stream.State === 'draining')
            return this.Reject('Stream 不存在或已经在关闭', Identity.Id);
        this.Sessions = this.Sessions.map(Value => Value.Id === Session.Id ? { ...Value,
            Streams: Value.Streams.map(Item => Item.Id === Stream.Id ? { ...Item, State: 'draining' } : Item) } : Value);
        return this.Record('重置 Stream', Stream.Id, '演示：Stream 已进入关闭流程。', 'warning',
            { Scope: 'stream', WorkerId: Session.WorkerId, AccountId: Session.AccountId, SessionId: Session.Id,
                StreamId: Stream.Id, TaskId: Stream.TaskId, ParentTaskId: Stream.ParentTaskId }, 'accepted');
    }

    public async CancelTask(Identity: TaskIdentity): Promise<AdminActionResult> {
        const Session = this.Sessions.find(Value => Value.Id === Identity.SessionId && Value.ProcessId === Identity.ProcessId &&
            Value.WorkerId === Identity.WorkerId && Value.GenerationId === Identity.GenerationId);
        const Task = Session?.Tasks.find(Value => Value.Id === Identity.Id && Value.StreamId === Identity.StreamId &&
            Value.ParentTaskId === Identity.ParentTaskId);
        if (Session === undefined || Task === undefined) return this.Reject('Task 不存在', Identity.Id);
        if (!Task.Cancellable || Task.Status !== 'running' && Task.Status !== 'pending')
            return this.Reject('Task 当前不可取消', Task.Id);
        this.Sessions = this.Sessions.map(Value => Value.Id === Session.Id ? { ...Value,
            ActiveTasks: Math.max(0, NumberOf(Value.ActiveTasks) - 1),
            Tasks: Value.Tasks.map(Item => Item.Id === Task.Id
                ? { ...Item, Status: 'canceled', CancelRequested: true, CompletedAt: new Date().toISOString() } : Item) } : Value);
        this.Workers = this.Workers.map(Worker => Worker.Id === Session.WorkerId
            ? { ...Worker, ActiveTasks: Math.max(0, NumberOf(Worker.ActiveTasks) - 1) } : Worker);
        return this.Record('取消 Task', Task.Id, '演示：Task 已取消并记录完成状态。', 'warning',
            { Scope: 'task', WorkerId: Session.WorkerId, AccountId: Session.AccountId, SessionId: Session.Id,
                StreamId: Task.StreamId, TaskId: Task.Id, ParentTaskId: Task.ParentTaskId }, 'completed');
    }

    public async ValidateConfiguration(Text: string): Promise<ConfigurationValidation> {
        const Parsed = ParsePublicConfiguration(Text);
        return { Valid: Parsed.Ok, Issues: Parsed.Ok ? [] : [Parsed.Message], CheckedAt: new Date().toISOString() };
    }

    public async ApplyConfiguration(Text: string, Persist: boolean): Promise<AdminActionResult> {
        const Validation = await this.ValidateConfiguration(Text);
        if (!Validation.Valid) return this.Reject(Validation.Issues[0] ?? '配置校验失败', 'draft');
        const Previous = this.Configuration.Generation;
        const Next = String(Number(Previous) + 1);
        this.Configuration = { Generation: Next, Reloadable: true, Text, UpdatedAt: new Date().toISOString() };
        return this.Record(Persist ? '应用并保存配置' : '应用配置', `generation-${Previous}`,
            `演示：草稿已通过本地校验并模拟应用，当前 Generation 为 ${Next}。`, 'info',
            { Scope: 'process' }, 'completed');
    }

    private RefreshAccountCounts(): void {
        this.Accounts = this.Accounts.map(Account => ({ ...Account,
            ActiveSessions: this.Sessions.filter(Session => Session.AccountId === Account.Id && Session.Active).length }));
    }

    private Reject(Message: string, Target: string): DemoActionResult {
        const Operation = this.AddOperation('演示操作', Target, 'rejected', Message, Message);
        return { Ok: false, Operation, Message, Status: 'rejected', OperationId: Operation.Id, Failure: Message,
            OperationScope: { ProcessId, Incarnation: 'demo-incarnation' } };
    }

    private RequireOperationScope(Scope: OperationScope): void {
        if (Scope.ProcessId !== ProcessId || Scope.Incarnation !== 'demo-incarnation')
            throw new OperationScopeChangedError();
    }

    private Record(Name: string, Target: string, Message: string, Severity: EventRecord['Severity'],
        Context: EventContext, State: OperationRecord['State']): DemoActionResult {
        const Operation = this.AddOperation(Name, Target, State, Message, null, Context);
        this.Events = [this.MakeActionEvent(Name, Message, Severity, Context, Operation), ...this.Events].slice(0, 50);
        return { Ok: State === 'accepted' || State === 'completed', Operation, Message, Status: State, OperationId: Operation.Id,
            OperationScope: { ProcessId, Incarnation: 'demo-incarnation' } };
    }

    private AddOperation(Name: string, Target: string, State: OperationRecord['State'], Message: string,
        Failure: string | null, Context: EventContext = {}): OperationRecord {
        const Id = `op-${this.NextOperation++}`;
        const Operation: OperationRecord = {
            Id, Name, Target, State, StartedAt: new Date().toISOString(), UpdatedAt: new Date().toISOString(), Message,
            CorrelationId: `corr-${Id}`, GenerationId: this.Configuration.Generation, Failure, ProcessId,
            WorkerId: Context.WorkerId ?? null, AccountId: Context.AccountId ?? null,
            SessionId: Context.SessionId ?? null, StreamId: Context.StreamId ?? null,
            TaskId: Context.TaskId ?? null, ParentTaskId: Context.ParentTaskId ?? null,
        };
        this.Operations = [Operation, ...this.Operations].slice(0, 50);
        return Operation;
    }

    private MakeActionEvent(Name: string, Message: string, Severity: EventRecord['Severity'],
        Context: EventContext, Operation: OperationRecord): EventRecord {
        const NewEvent = MakeEvent({ Sequence: this.NextEvent++, MinutesAgo: 0, Severity,
            Kind: Operation.State === 'completed' ? 'operation_completed' : 'operation_accepted',
            Scope: Context.Scope ?? 'process', Message: Name, Detail: Message, Context: {
                ...Context, OperationId: Operation.Id,
            } });
        return { ...NewEvent, CorrelationId: Operation.CorrelationId, GenerationId: Operation.GenerationId ?? InitialGeneration };
    }
}

function MatchesSession(Session: SessionRecord, Identity: SessionIdentity): boolean {
    return Session.Id === Identity.Id && Session.ProcessId === Identity.ProcessId &&
        Session.WorkerId === Identity.WorkerId && Session.AccountId === Identity.AccountId &&
        Session.GenerationId === Identity.GenerationId;
}
