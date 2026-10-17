export type HealthState = 'unknown' | 'healthy' | 'degraded' | 'unhealthy' | 'draining';
export type WorkerState = 'running' | 'draining' | 'offline';
export type EventSeverity = 'debug' | 'info' | 'warning' | 'error';
export type TaskStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'canceled' | 'quarantined';
export type OperationStatus = 'accepted' | 'running' | 'completed' | 'rejected' | 'unavailable' |
    'failed' | 'timed_out' | 'blocked' | 'restart_required' | 'conflict' | 'invalid' | 'unknown' | 'interrupted';

/** @brief 真实 Operations 数值按十进制文本保真；number 仅供保留的旧演示样本使用。 */
export type UInt64Value = string | number;
export type TrafficValue = Readonly<{ Up: UInt64Value; Down: UInt64Value }>;
export type MetricsTraffic = TrafficValue & Readonly<{ Events: UInt64Value; Errors: UInt64Value }>;
export type TrafficSample = Readonly<{ Time: string; Traffic: MetricsTraffic }>;
export type TcpSessionSample = Readonly<{ Time: string; Count: UInt64Value }>;
export type LatencySummary = Readonly<{
    Name: string; Available: boolean; SampleCount: UInt64Value;
    P50Ms: string | null; P95Ms: string | null; P99Ms: string | null; MaxMs: string | null;
    WorkerId: string | null; Protocol: string | null;
}>;
export type MemoryAllocationSnapshot = Readonly<{
    Available: boolean; CurrentBytes: UInt64Value | null; PeakBytes: UInt64Value | null;
    AllocationCount: UInt64Value | null; ReleaseCount: UInt64Value | null; Coverage: string;
}>;
export type WorkerAllocationSnapshot = Readonly<{ WorkerId: string; Allocation: MemoryAllocationSnapshot }>;
export type FailureCounts = Readonly<{ Sessions: UInt64Value; Streams: UInt64Value; Tasks: UInt64Value }>;
export type GenerationSnapshot = Readonly<{
    Id: string; CreatedAt: string; Active: boolean; Retiring: boolean; Health: HealthState;
}>;
export type HealthSnapshot = Readonly<{
    Status: HealthState; CheckedAt: string; Active: UInt64Value; Errors: UInt64Value; Ready: UInt64Value;
    TcpReady: boolean; UdpReady: boolean; QuicReady: boolean;
    UdpSocketReady: boolean; QuicSocketReady: boolean;
    QuicHandshakeReady: boolean; QuicProtocolReady: boolean;
    RetirementFailures: FailureCounts;
}>;
export type ObservationCounts = Readonly<{
    Accepted: UInt64Value; Consumed: UInt64Value; Dropped: UInt64Value; AggregationFailures: UInt64Value;
}>;
export type RecognitionLatency = Readonly<{
    Boundary: 'recognition_admission'; Unit: 'microseconds'; GenerationId: string;
    Ready: boolean; SampleCount: UInt64Value; TracerWritten: UInt64Value; TracerDropped: UInt64Value;
    HistogramRangeExceeded: UInt64Value; RecentUs: readonly UInt64Value[];
    P50Us: UInt64Value | null; P95Us: UInt64Value | null; P99Us: UInt64Value | null; MaxObservedUs: UInt64Value | null;
}>;
export type MetricsSnapshot = Readonly<{
    CheckedAt: string; GenerationId: string; Traffic: MetricsTraffic; Observations: ObservationCounts;
    RecognitionLatency: RecognitionLatency; SampleIntervalMs: UInt64Value;
    History: readonly TrafficSample[]; HistoryReady: boolean; RetirementFailures: FailureCounts;
}>;
export type WorkerRecord = Readonly<{
    Id: string; Name: string; ProcessId: string; GenerationId: string; State: WorkerState;
    Health: HealthState; Running: boolean; Accepting: boolean; ActiveTasks: UInt64Value;
    LoadPercent: number | null;
    DroppedEvents: UInt64Value; Traffic: TrafficValue | null;
    QueueDepth: UInt64Value; QueueCapacity: UInt64Value;
    StartedTasks: UInt64Value; CompletedTasks: UInt64Value; CancelledTasks: UInt64Value;
    DispatchAccepted: UInt64Value; DispatchFull: UInt64Value; DispatchClosed: UInt64Value;
    DispatchUnavailable: UInt64Value; DispatchGenerationRejected: UInt64Value;
    CommandsExecuted: UInt64Value; CommandsFailed: UInt64Value;
}>;
export type WorkerIdentity = Pick<WorkerRecord, 'Id' | 'ProcessId' | 'GenerationId'>;
export type TaskRecord = Readonly<{
    Id: string; ProcessId: string; WorkerId: string; SessionId: string; StreamId: string;
    GenerationId: string; ParentTaskId: string | null; Status: TaskStatus;
    StartedAt: string | null; CompletedAt: string | null; CancelRequested: boolean; Cancellable: boolean;
    DrainBlocked: boolean; Failure: string | null; DrainFailure: string | null;
}>;
export type StreamRecord = Readonly<{
    Id: string; TaskId: string; ParentTaskId: string | null; ProcessId: string; SessionId: string;
    AccountId: string; WorkerId: string; GenerationId: string; Traffic: TrafficValue | null;
    Protocol: string; State: 'active' | 'draining';
}>;
export type SessionRecord = Readonly<{
    Id: string; ProcessId: string; WorkerId: string; AccountId: string; GenerationId: string;
    Traffic: TrafficValue | null; StartedAt: string; Identity: string; SourceAddress: string;
    Transport: string; Protocol: string; Target: string;
    Active: boolean; Draining: boolean; ActiveTasks: UInt64Value | null;
    Streams: readonly StreamRecord[]; Tasks: readonly TaskRecord[];
}>;
export type SessionIdentity = Pick<SessionRecord, 'Id' | 'ProcessId' | 'WorkerId' | 'AccountId' | 'GenerationId'>;
export type StreamIdentity = Pick<StreamRecord,
    'Id' | 'TaskId' | 'ParentTaskId' | 'ProcessId' | 'SessionId' | 'AccountId' | 'WorkerId' | 'GenerationId'>;
export type TaskIdentity = Pick<TaskRecord,
    'Id' | 'ProcessId' | 'WorkerId' | 'SessionId' | 'StreamId' | 'GenerationId' | 'ParentTaskId'>;
export type AccountRecord = Readonly<{
    Id: string; GenerationId: string; Label: string; Revoked: boolean;
    ActiveSessions: UInt64Value; Traffic: TrafficValue | null; GroupId?: string | null;
    AccountKey?: string; EffectivePolicy?: EffectivePolicy | null;
    PolicySources?: Readonly<Record<string, string>>; ActiveConnections?: UInt64Value | null;
    ActiveStreams?: UInt64Value | null;
    UploadBytesPerSecond?: UInt64Value | null; DownloadBytesPerSecond?: UInt64Value | null;
}>;
export type EventRecord = Readonly<{
    Id: string; Sequence: UInt64Value; Time: string; CorrelationId: string;
    GenerationId: string; ProcessId: string; WorkerId: string | null; AccountId: string | null;
    SessionId: string | null; StreamId: string | null; TaskId: string | null;
    ParentTaskId: string | null; OperationId: string | null;
    Severity: EventSeverity; Kind: string; Scope: 'process' | 'worker' | 'account' | 'session' | 'stream' | 'task';
    Message: string; Detail: string; Terminal: boolean; Truncated: boolean;
}>;
export type LostRange = Readonly<{ First: UInt64Value; Last: UInt64Value }>;
export type EventPage = Readonly<{
    Items: readonly EventRecord[]; NextCursor: string; HasMore: boolean;
    EarliestCursor: string; Lost: boolean; LostRanges: readonly LostRange[];
    Dropped: UInt64Value; TerminalDropped: UInt64Value; Overwritten: UInt64Value;
    SeverityFilterSupported: boolean;
}>;
export type OperationRecord = Readonly<{
    Id: string; Name: string; Target: string; State: OperationStatus;
    StartedAt: string | null; UpdatedAt?: string | null; Message: string; CorrelationId: string;
    GenerationId: string | null; Failure: string | null;
    ProcessId?: string | null; WorkerId?: string | null; AccountId?: string | null;
    SessionId?: string | null; StreamId?: string | null; TaskId?: string | null; ParentTaskId?: string | null;
}>;
export type PageRequest = Readonly<{ Cursor: string; Limit: number; Id?: string; Query?: string;
    State?: string; WorkerId?: string; AccountId?: string; Protocol?: string; GroupId?: string;
    ProcessId?: string; GenerationId?: string; Sort?: string }>;
export type CursorPage<Value> = Readonly<{
    Items: readonly Value[]; NextCursor: string; HasMore: boolean;
}>;

export type IngressRecord = Readonly<{
    Id: string; Transport: string; ConfiguredAddress: string; BoundAddress: string | null;
    Ready: boolean; ActiveConnections: UInt64Value | null;
    Protocols: readonly string[]; Carriers: readonly string[];
    ExpectedState?: string; ActualState?: string; Reason?: string; StateSince?: string | null;
}>;
export type GroupRecord = Readonly<{
    Id: string; Name: string; ConfiguredAccountCount: UInt64Value; ActiveAccountCount: UInt64Value;
    ActiveSessions: UInt64Value | null; Traffic: MetricsTraffic | null;
}>;
export type SessionTraceSpan = Readonly<{
    SpanId: string; ParentSpanId: string | null; Sequence: UInt64Value; Name: string;
    StartTime: string; DurationMs: UInt64Value | null; Status: string; SessionId: string;
    WorkerId: string | null; AccountId: string | null; TaskId: string | null;
    ParentTaskId: string | null; StreamId: string | null;
    Attributes: Readonly<Record<string, string | boolean | null>>;
}>;
export type EventsFilter = Readonly<{
    SessionId?: string; WorkerId?: string; AccountId?: string; Severity?: EventSeverity;
    ProcessId?: string; GenerationId?: string;
}>;
export type DemoActionResult = Readonly<{
    Ok: boolean; Operation: OperationRecord | null; Message: string;
    Status?: OperationStatus; Failure?: string | null; OperationId?: string | null;
    LocalAttemptId?: string; OperationScope?: OperationScope;
    ConfigurationIssues?: readonly ConfigurationIssue[]; RestartRequiredFields?: readonly string[];
}>;
export type AdminActionResult = DemoActionResult;
export type ConfigurationIssue = Readonly<{ Code: string; Path: string; Message: string }>;
export type ConfigurationSnapshot = Readonly<{
    Generation: string; Reloadable: boolean; Text: string; UpdatedAt: string;
}>;
export type BootstrapSnapshot = Readonly<{ ApiVersion: string; InstanceKey: string; ProcessId: string;
    Incarnation: string; Capabilities: readonly string[] }>;
export type BootstrapReadOptions = Readonly<{ Fresh?: boolean }>;
export type OperationScope = Pick<BootstrapSnapshot, 'ProcessId' | 'Incarnation'>;
export class OperationScopeChangedError extends Error {
    public readonly Code = 'operation-scope-changed';
    public readonly Status = 409;
    public constructor() { super('来源实例已变，未查询同号记录'); this.name = 'OperationScopeChangedError'; }
}
export class WorkerIdentityChangedError extends Error {
    public readonly Code = 'worker-identity-changed';
    public readonly Status = 409;
    public constructor() { super('Worker 当前身份已变，未发送排空请求'); this.name = 'WorkerIdentityChangedError'; }
}
export type EffectivePolicy = Readonly<Record<string, unknown>>;
export type AccountUsage = Readonly<{ AccountKey: string; Revision: string; CycleStart: string;
    CycleEnd: string | null; LimitBytes: string | null; SettledBytes: string; ReservedBytes: string;
    UncertainBytes: string; RemainingBytes: string | null; OverageBytes: string; Available: boolean; Failure: string | null }>;
export type UsageAdjustment = Readonly<{ AccountKey: string; Revision: string; Kind: 'add_allowance' | 'release_uncertain'; Bytes: string; Reason: string }>;
export type HistoryScope = 'process' | 'worker' | 'account' | 'group' | 'ingress' | 'protocol_type' | 'protocol_instance';
export type HistoryRequest = Readonly<{ Scope: HistoryScope; Key: string; From: string; To: string; MaxPoints?: number; Metric?: 'traffic' | 'recognition_admission' | 'active' }>;
export type HistoryPoint = Readonly<{ Time: string; UpBytes: string | null; DownBytes: string | null;
    Active: string | null; P50Us: string | null; P95Us: string | null; P99Us: string | null; SampleCount: string;
    Quality: string }>;
export type HistorySnapshot = Readonly<{ SampledAt: string; From: string; To: string; ResolutionMs: string;
    Coverage: string; Gaps: readonly Readonly<{ From: string; To: string; Reason: string }>[]; Items: readonly HistoryPoint[] }>;
export type SearchResult = Readonly<{ Id: string; Kind: string; Label: string; Path: string; Detail: string }>;
export type TracePage = CursorPage<SessionTraceSpan> & Readonly<{ Lost: boolean;
    Cursors: readonly Readonly<{ WorkerId: string; Sequence: string }>[];
    Loss: readonly Readonly<{ WorkerId: string; Overwritten: string; LostSinceCursor: string; ConcurrentReadSkips: string }>[] }>;
export type ConfigurationValidation = Readonly<{
    Valid: boolean; Issues: readonly string[]; CheckedAt: string;
}>;
export type OverviewSnapshot = Readonly<{
    SampledAt: string; SampleIntervalMs: UInt64Value;
    Process: Readonly<{ Id: string; GenerationId: string; Phase: string }>;
    Health: Readonly<{
        Status: HealthState; CheckedAt: string; Ready: boolean; TcpReady: boolean; UdpReady: boolean;
        UdpSocketReady: boolean; QuicReady: boolean; QuicSocketReady: boolean;
        QuicHandshakeReady: boolean; QuicProtocolReady: boolean; Active: UInt64Value; Errors: UInt64Value;
    }>;
    Counts: Readonly<{
        ConfiguredAccounts: UInt64Value; ActiveAccounts: UInt64Value; UngroupedAccounts: UInt64Value;
        TcpSessions: UInt64Value;
        UdpConnections: UInt64Value | null; QuicConnections: UInt64Value | null; WorkersTotal: UInt64Value;
        WorkersAccepting: UInt64Value;
    }>;
    Traffic: Readonly<{
        Available: boolean; UpBytes: UInt64Value | null; DownBytes: UInt64Value | null;
        Events: UInt64Value | null; Errors: UInt64Value | null;
        UpBytesPerSecond: UInt64Value | null; DownBytesPerSecond: UInt64Value | null;
    }>;
    Latency: Readonly<{
        RecognitionAdmission: Readonly<{
            Available: boolean; SampleCount: UInt64Value; P50Ms: string | null;
            P95Ms: string | null; P99Ms: string | null; MaxMs: string | null;
        }>;
        Stages: readonly Readonly<{ Name: string; Available: boolean; SampleCount: UInt64Value;
            P50Ms: string | null; P95Ms: string | null; P99Ms: string | null; MaxMs: string | null;
            WorkerId: string | null; Protocol: string | null }>[];
    }>;
    Memory: Readonly<{
        ProcessAvailable: boolean; ProcessRssBytes: UInt64Value | null; ProcessPeakRssBytes: UInt64Value | null;
        WorkingSetBytes: UInt64Value | null;
        BytePool: Readonly<{ Available: boolean; UsedBytes: UInt64Value | null; CapacityBytes: UInt64Value | null;
            AvailableBlocks: UInt64Value | null; BlockSize: UInt64Value | null; PeakUsedBytes: UInt64Value | null;
            AllocationCount: UInt64Value | null; ReleaseCount: UInt64Value | null }>;
        Allocations: MemoryAllocationSnapshot; WorkerAllocations: readonly WorkerAllocationSnapshot[];
    }>;
    Observations: ObservationCounts;
    History: readonly TrafficSample[];
    TcpSessionHistory: readonly TcpSessionSample[];
    Protocols: readonly ProtocolRecord[];
}>;

export type ProtocolRecord = Readonly<{
    Id: string; Name: string; ConfiguredBindings: UInt64Value; ActiveSessions: UInt64Value | null;
    Traffic: MetricsTraffic | null; Latency: LatencySummary | null; Coverage: string;
    Kind?: 'type' | 'instance'; TypeKey?: string;
}>;

export interface AdminDataSource {
    GetBootstrap(Options?: BootstrapReadOptions): Promise<BootstrapSnapshot>;
    GetProtocols?(Page: PageRequest): Promise<CursorPage<ProtocolRecord>>;
    GetHistory?(Request: HistoryRequest): Promise<HistorySnapshot>;
    GetAccountUsage?(AccountKey: string): Promise<AccountUsage>;
    AdjustUsage?(Adjustment: UsageAdjustment): Promise<AdminActionResult>;
    Search?(Query: string, Signal?: AbortSignal): Promise<readonly SearchResult[]>;
    GetOverview(): Promise<OverviewSnapshot>;
    GetIngresses(Page: PageRequest): Promise<CursorPage<IngressRecord>>;
    GetWorkers(Page: PageRequest): Promise<CursorPage<WorkerRecord>>;
    GetAccounts(Page: PageRequest): Promise<CursorPage<AccountRecord>>;
    GetGroups(Page: PageRequest): Promise<CursorPage<GroupRecord>>;
    CreateGroup(Name: string): Promise<AdminActionResult>;
    RenameGroup(Id: string, Name: string): Promise<AdminActionResult>;
    SetAccountGroup(AccountId: string, GroupId: string | null): Promise<AdminActionResult>;
    GetSessions(Page: PageRequest): Promise<CursorPage<SessionRecord>>;
    GetSessionTrace(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<SessionTraceSpan> & Partial<Omit<TracePage, keyof CursorPage<SessionTraceSpan>>>>;
    GetStreams(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<StreamRecord>>;
    GetTasks(Identity: SessionIdentity, Page: PageRequest): Promise<CursorPage<TaskRecord>>;
    GetEvents(Page: PageRequest, Filter?: EventsFilter): Promise<EventPage>;
    GetConfiguration(): Promise<ConfigurationSnapshot>;
    GetOperations(Page: PageRequest, Scope: OperationScope): Promise<CursorPage<OperationRecord>>;
    GetOperationStatus(Id: string, Scope: OperationScope): Promise<OperationRecord>;
    DrainWorker(Worker: WorkerIdentity): Promise<AdminActionResult>;
    RevokeAccount(Id: string, CloseSessions: boolean): Promise<AdminActionResult>;
    CancelSession(Identity: SessionIdentity): Promise<AdminActionResult>;
    ResetStream(Identity: StreamIdentity): Promise<AdminActionResult>;
    CancelTask(Identity: TaskIdentity): Promise<AdminActionResult>;
    ValidateConfiguration(Text: string, BaseGeneration?: string): Promise<ConfigurationValidation>;
    ApplyConfiguration(Text: string, Persist: boolean, BaseGeneration?: string): Promise<AdminActionResult>;
}
