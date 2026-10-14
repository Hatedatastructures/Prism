import { ParseJsonDocument } from './JsonDocument';
import type { JsonNode } from './JsonDocument';
import { ParsePublicConfiguration } from './ConfigurationDocument';
import { ContractFailure } from './Decode';
import type { Decoder } from './Decode';
import type { Decimal } from './Decimal';
import { DecodeDecimal } from './Decimal';
import type { HttpResponseData, ResponseDecoder } from './ApiClient';
import { Fail, Success } from './Result';
import type { Result } from './Result';

export type QueryStatus = 'ok' | 'unavailable' | 'not_found' | 'failed' | 'invalid';
export type CommandStatus = 'accepted' | 'completed' | 'rejected' | 'unavailable' |
    'failed' | 'timed_out' | 'blocked' | 'invalid' | 'restart_required' | 'conflict';
export type HealthStatus = 'healthy' | 'degraded' | 'unhealthy' | 'draining' | 'unknown';
export type QueryEnvelope<Value> = Readonly<{
    Status: QueryStatus; Value: Value | null; Message: string; Failure: NativeFailure | null;
}>;
export type CommandEnvelope = Readonly<{
    Status: CommandStatus; Operation: Decimal; Process: Decimal | null;
    Generation: Decimal; Worker: Decimal;
    Account: Decimal; Session: Decimal; Stream: Decimal; Task: Decimal;
    ParentTask: Decimal | null;
    Message: string; Failure: NativeFailure | null;
    ConfigurationIssues: readonly ConfigurationIssue[]; RestartRequiredFields: readonly string[];
}>;
export type ConfigurationIssue = Readonly<{ Code: string; Path: string; Message: string }>;
export type ConfigurationSnapshot = Readonly<{ Generation: Decimal; Reloadable: boolean; Node: JsonNode; Text: string }>;
export type NativeFailure = Readonly<{
    Code: string; NativeCategory: string | null; NativeValue: number | null;
}>;
export type Traffic = Readonly<{
    UpBytes: Decimal; DownBytes: Decimal; Events: Decimal; Errors: Decimal;
}>;
export type RetirementFailures = Readonly<{
    Session: Decimal; Stream: Decimal; Task: Decimal;
}>;
export type TrafficSample = Readonly<{ Timestamp: Decimal; Traffic: Traffic }>;
export type RecognitionLatency = Readonly<{
    Ready: boolean; SampleBoundary: 'recognition_admission'; Unit: 'microseconds';
    Generation: Decimal; SampleCount: Decimal; TracerWritten: Decimal; TracerDropped: Decimal;
    HistogramRangeExceeded: Decimal; RecentUs: readonly Decimal[];
    P50BucketLowerBoundUs: Decimal | null; P95BucketLowerBoundUs: Decimal | null;
    P99BucketLowerBoundUs: Decimal | null; MaxObservedUs: Decimal | null;
}>;
/** @brief 当前 Operations 历史序列的真实固定环容量，与 TrafficHistory owner 对齐。 */
export const MaxMetricHistorySamples = 1024;
export type Metrics = Readonly<{
    Process: Decimal; Generation: Decimal; CheckedAt: Decimal; Traffic: Traffic;
    Accepted: Decimal; Consumed: Decimal; Dropped: Decimal; AggregationFailures: Decimal;
    RecognitionLatencyQueueDropped: Decimal; RecognitionLatencyAggregationFailures: Decimal;
    RecognitionLatency: RecognitionLatency;
    RetirementFailures: RetirementFailures; SampleInterval: Decimal;
    HistoryReady: boolean; History: readonly TrafficSample[];
}>;
export type Health = Readonly<{
    Status: HealthStatus; CheckedAt: Decimal; Active: Decimal; Errors: Decimal;
    Ready: boolean; TcpReady: boolean; UdpReady: boolean; UdpSocketReady: boolean;
    QuicReady: boolean; QuicSocketReady: boolean; QuicHandshakeReady: boolean;
    QuicProtocolReady: boolean; RetirementFailures: RetirementFailures | null;
}>;
export type Generation = Readonly<{
    Id: Decimal; CreatedAt: Decimal; Active: boolean; Retiring: boolean; Health: Health;
}>;
export type Worker = Readonly<{
    Process: Decimal; Id: Decimal; Generation: Decimal; Health: Health; Traffic: Traffic | null;
    Running: boolean; Accepting: boolean; ActiveTasks: Decimal; DroppedEvents: Decimal;
}>;
export type Account = Readonly<{
    Id: Decimal; Generation: Decimal; Traffic: Traffic | null; ActiveSessions: Decimal;
    Label: string; Revoked: boolean;
}>;
export type Session = Readonly<{
    Id: Decimal; Process: Decimal; Worker: Decimal; Account: Decimal; Generation: Decimal;
    Traffic: Traffic | null; StartedAt: Decimal; Protocol: string; Target: string;
    Active: boolean; Draining: boolean; ActiveTasks: Decimal | null;
}>;
export type Stream = Readonly<{
    Id: Decimal; Process: Decimal; Session: Decimal; Account: Decimal; Worker: Decimal;
    Generation: Decimal; Task: Decimal; ParentTask: Decimal;
    Traffic: Traffic | null; Protocol: string; State: 'active' | 'draining';
}>;
export type TaskStatus = 'pending' | 'running' | 'succeeded' | 'failed' | 'canceled' | 'quarantined';
export type Task = Readonly<{
    Id: Decimal; Process: Decimal; Worker: Decimal; Session: Decimal; Stream: Decimal;
    Generation: Decimal; ParentTask: Decimal; Status: TaskStatus; StartedAt: Decimal;
    CompletedAt: Decimal; CancelRequested: boolean; Cancellable: boolean; DrainBlocked: boolean;
    Failure: NativeFailure | null; DrainFailure: NativeFailure | null;
}>;
export type EventSeverity = 'debug' | 'info' | 'warning' | 'error' | 'unknown';
export type EventKind = 'data' | 'started' | 'failed' | 'session_closed' | 'stream_closed' |
    'task_completed' | 'task_canceled' | 'worker_drained' | 'generation_reloaded' |
    'operation_accepted' | 'operation_completed' | 'operation_failed';
export type EventScope = 'process' | 'worker' | 'account' | 'session' | 'stream' | 'task';
export type Event = Readonly<{
    Sequence: Decimal; Timestamp: Decimal; Correlation: Decimal; Generation: Decimal;
    Process: Decimal; Worker: Decimal; Account: Decimal; Session: Decimal;
    Stream: Decimal; Task: Decimal; ParentTask: Decimal; Operation: Decimal;
    Scope: EventScope; Kind: EventKind; Severity: EventSeverity;
    Terminal: boolean; Truncated: boolean; Detail: string | null;
}>;
export type Page<Value> = Readonly<{
    Items: readonly Value[]; NextCursor: Decimal; HasMore: boolean;
}>;
export type EventPage = Readonly<{
    Items: readonly Event[]; NextCursor: Decimal; HasMore: boolean;
    EarliestCursor: Decimal; Lost: boolean; Dropped: Decimal; TerminalDropped: Decimal;
    Overwritten: Decimal; SeverityFilterSupported: boolean;
    LostRanges: readonly Readonly<{ First: Decimal; Last: Decimal }>[];
}>;

type JsonObject = Readonly<Record<string, unknown>>;
const QueryStatuses: readonly QueryStatus[] = ['ok', 'unavailable', 'not_found', 'failed', 'invalid'];
const CommandStatuses: readonly CommandStatus[] = [
    'accepted', 'completed', 'rejected', 'unavailable', 'failed', 'timed_out', 'blocked', 'invalid', 'restart_required', 'conflict',
];
const HealthStatuses: readonly HealthStatus[] = ['healthy', 'degraded', 'unhealthy', 'draining', 'unknown'];
const TaskStatuses: readonly TaskStatus[] = [
    'pending', 'running', 'succeeded', 'failed', 'canceled', 'quarantined',
];
export const EventKindValues: readonly EventKind[] = [
    'data', 'started', 'failed', 'session_closed', 'stream_closed', 'task_completed',
    'task_canceled', 'worker_drained', 'generation_reloaded', 'operation_accepted',
    'operation_completed', 'operation_failed',
];
const EventScopes: readonly EventScope[] = ['process', 'worker', 'account', 'session', 'stream', 'task'];

function ReadObject(Input: unknown): JsonObject | null {
    if (Input === null || typeof Input !== 'object' || Array.isArray(Input)) return null;
    return Input as JsonObject;
}

function ReadString(Input: unknown): string | null {
    if (typeof Input !== 'string') return null;
    return Input;
}

function ReadBoolean(Input: unknown): boolean | null {
    if (typeof Input !== 'boolean') return null;
    return Input;
}

function ReadDecimal(Input: unknown): Decimal | null {
    const Value = DecodeDecimal(Input);
    if (!Value.Ok) return null;
    return Value.Value;
}

function ReadEnum<const Values extends readonly string[]>(
    Input: unknown, Allowed: Values,
): Values[number] | null {
    if (typeof Input !== 'string' || !Allowed.includes(Input)) return null;
    return Input as Values[number];
}

function DecodeFailure(Input: unknown): NativeFailure | null | undefined {
    if (Input === null) return null;
    const Value = ReadObject(Input);
    if (Value === null) return undefined;
    const Code = ReadString(Value.code);
    if (Code === null || Code.length === 0) return undefined;
    const Category = Value.native_category;
    const NativeValue = Value.native_value;
    if (Category === undefined && NativeValue === undefined) {
        return { Code, NativeCategory: null, NativeValue: null };
    }
    if (typeof Category !== 'string' || typeof NativeValue !== 'number' ||
        !Number.isSafeInteger(NativeValue)) return undefined;
    return { Code, NativeCategory: Category, NativeValue };
}

function DecodeTraffic(Input: unknown): Result<Traffic> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const UpBytes = ReadDecimal(Value.up_bytes);
    const DownBytes = ReadDecimal(Value.down_bytes);
    const Events = ReadDecimal(Value.events);
    const Errors = ReadDecimal(Value.errors);
    if (UpBytes === null || DownBytes === null || Events === null || Errors === null) {
        return ContractFailure();
    }
    return Success({ UpBytes, DownBytes, Events, Errors });
}

function DecodeNullableTraffic(Input: unknown): Result<Traffic | null> {
    if (Input === null) return Success(null);
    return DecodeTraffic(Input);
}

function DecodeRetirementFailures(Input: unknown): Result<RetirementFailures> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Session = ReadDecimal(Value.session);
    const Stream = ReadDecimal(Value.stream);
    const Task = ReadDecimal(Value.task);
    if (Session === null || Stream === null || Task === null) return ContractFailure();
    return Success({ Session, Stream, Task });
}

function DecodeMetrics(Input: unknown): Result<Metrics> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Observations = ReadObject(Value.observations);
    if (Observations === null || !Array.isArray(Value.history) ||
        Value.history.length > MaxMetricHistorySamples) return ContractFailure();
    const Process = ReadDecimal(Value.process);
    const Generation = ReadDecimal(Value.generation);
    const CheckedAt = ReadDecimal(Value.checked_at);
    const SampleInterval = ReadDecimal(Value.sample_interval_ms);
    const HistoryReady = ReadBoolean(Value.history_ready);
    const TrafficResult = DecodeTraffic(Value.traffic);
    const Accepted = ReadDecimal(Observations.accepted);
    const Consumed = ReadDecimal(Observations.consumed);
    const Dropped = ReadDecimal(Observations.dropped);
    const AggregationFailures = ReadDecimal(Observations.aggregation_failures);
    const RecognitionLatencyQueueDropped = ReadDecimal(Observations.recognition_latency_queue_dropped);
    const RecognitionLatencyAggregationFailures = ReadDecimal(Observations.recognition_latency_aggregation_failures);
    const RecognitionLatencyResult = DecodeRecognitionLatency(Value.recognition_latency, Generation);
    const RetirementResult = DecodeRetirementFailures(Observations.retirement_failures);
    if (Process === null || Process === '0' || Generation === null || Generation === '0' ||
        CheckedAt === null || SampleInterval === null || SampleInterval === '0' || HistoryReady === null ||
        Accepted === null || Consumed === null || Dropped === null || AggregationFailures === null ||
        RecognitionLatencyQueueDropped === null || RecognitionLatencyAggregationFailures === null ||
        !RecognitionLatencyResult.Ok ||
        !TrafficResult.Ok || !RetirementResult.Ok) return ContractFailure();
    const History: TrafficSample[] = [];
    let PreviousTimestamp = -1n;
    for (const Item of Value.history) {
        const Sample = ReadObject(Item);
        if (Sample === null) return ContractFailure();
        const Timestamp = ReadDecimal(Sample.timestamp);
        const SampleTraffic = DecodeTraffic(Sample.traffic);
        if (Timestamp === null || BigInt(Timestamp) <= PreviousTimestamp || !SampleTraffic.Ok) return ContractFailure();
        PreviousTimestamp = BigInt(Timestamp);
        History.push({ Timestamp, Traffic: SampleTraffic.Value });
    }
    if (HistoryReady !== (History.length > 0)) return ContractFailure();
    return Success({ Process, Generation, CheckedAt, Traffic: TrafficResult.Value,
        Accepted, Consumed, Dropped, AggregationFailures, RetirementFailures: RetirementResult.Value,
        RecognitionLatencyQueueDropped, RecognitionLatencyAggregationFailures,
        RecognitionLatency: RecognitionLatencyResult.Value,
        SampleInterval, HistoryReady, History });
}

function ReadNullableDecimal(Input: unknown): Decimal | null | undefined {
    if (Input === null) return null;
    const Value = ReadDecimal(Input);
    if (Value === null) return undefined;
    return Value;
}

function DecodeRecognitionLatency(Input: unknown, SnapshotGeneration: Decimal | null): Result<RecognitionLatency> {
    const Value = ReadObject(Input);
    if (Value === null || !Array.isArray(Value.recent_us) || Value.recent_us.length > 8) {
        return ContractFailure();
    }
    const Ready = ReadBoolean(Value.ready);
    const SampleBoundary = ReadString(Value.sample_boundary);
    const Unit = ReadString(Value.unit);
    const Generation = ReadDecimal(Value.generation);
    const SampleCount = ReadDecimal(Value.sample_count);
    const TracerWritten = ReadDecimal(Value.tracer_written);
    const TracerDropped = ReadDecimal(Value.tracer_dropped);
    const HistogramRangeExceeded = ReadDecimal(Value.histogram_range_exceeded);
    const P50BucketLowerBoundUs = ReadNullableDecimal(Value.p50_bucket_lower_bound_us);
    const P95BucketLowerBoundUs = ReadNullableDecimal(Value.p95_bucket_lower_bound_us);
    const P99BucketLowerBoundUs = ReadNullableDecimal(Value.p99_bucket_lower_bound_us);
    const MaxObservedUs = ReadNullableDecimal(Value.max_observed_us);
    if (Ready === null || SampleBoundary !== 'recognition_admission' || Unit !== 'microseconds' ||
        Generation === null || Generation === '0' || SampleCount === null || TracerWritten === null ||
        TracerDropped === null || HistogramRangeExceeded === null || P50BucketLowerBoundUs === undefined ||
        P95BucketLowerBoundUs === undefined || P99BucketLowerBoundUs === undefined || MaxObservedUs === undefined ||
        Ready !== (SampleCount !== '0')) return ContractFailure();
    if (SnapshotGeneration === null || Generation !== SnapshotGeneration) {
        return Fail({ Kind: 'contract', Message: '识别延迟样本与指标快照的配置版本不一致，已拒绝该响应',
            HttpStatus: null, MayHaveExecuted: false });
    }
    const RecentUs: Decimal[] = [];
    for (const Item of Value.recent_us) {
        const Sample = ReadDecimal(Item);
        if (Sample === null) return ContractFailure();
        RecentUs.push(Sample);
    }
    if (BigInt(TracerWritten) > BigInt(SampleCount) ||
        BigInt(TracerDropped) > BigInt(SampleCount) ||
        BigInt(HistogramRangeExceeded) > BigInt(SampleCount)) return ContractFailure();
    if (!Ready) {
        if (TracerWritten !== '0' || TracerDropped !== '0' || HistogramRangeExceeded !== '0' ||
            RecentUs.length > 0 || P50BucketLowerBoundUs !== null || P95BucketLowerBoundUs !== null ||
            P99BucketLowerBoundUs !== null || MaxObservedUs !== null) return ContractFailure();
    } else {
        if (P50BucketLowerBoundUs === null || P95BucketLowerBoundUs === null ||
            P99BucketLowerBoundUs === null || MaxObservedUs === null ||
            BigInt(RecentUs.length) > BigInt(TracerWritten) ||
            BigInt(P50BucketLowerBoundUs) > BigInt(P95BucketLowerBoundUs) ||
            BigInt(P95BucketLowerBoundUs) > BigInt(P99BucketLowerBoundUs) ||
            BigInt(P99BucketLowerBoundUs) > BigInt(MaxObservedUs) ||
            RecentUs.some(Sample => BigInt(Sample) > BigInt(MaxObservedUs))) return ContractFailure();
    }
    return Success({ Ready, SampleBoundary, Unit, Generation, SampleCount, TracerWritten,
        TracerDropped, HistogramRangeExceeded, RecentUs, P50BucketLowerBoundUs,
        P95BucketLowerBoundUs, P99BucketLowerBoundUs, MaxObservedUs });
}

function DecodeHealthObject(Value: JsonObject): Result<Health> {
    const Status = ReadEnum(Value.status, HealthStatuses);
    const CheckedAt = ReadDecimal(Value.checked_at);
    const Active = ReadDecimal(Value.active);
    const Errors = ReadDecimal(Value.errors);
    const Ready = ReadBoolean(Value.ready);
    const TcpReady = ReadBoolean(Value.tcp_ready);
    const UdpReady = ReadBoolean(Value.udp_ready);
    const UdpSocketReady = ReadBoolean(Value.udp_socket_ready);
    const QuicReady = ReadBoolean(Value.quic_ready);
    const QuicSocketReady = ReadBoolean(Value.quic_socket_ready);
    const QuicHandshakeReady = ReadBoolean(Value.quic_handshake_ready);
    const QuicProtocolReady = ReadBoolean(Value.quic_protocol_ready);
    if (Status === null || CheckedAt === null || Active === null || Errors === null ||
        Ready === null || TcpReady === null || UdpReady === null || UdpSocketReady === null ||
        QuicReady === null || QuicSocketReady === null || QuicHandshakeReady === null ||
        QuicProtocolReady === null) return ContractFailure();
    let Retirement: RetirementFailures | null = null;
    if (Value.retirement_failures !== undefined) {
        const Decoded = DecodeRetirementFailures(Value.retirement_failures);
        if (!Decoded.Ok) return Decoded;
        Retirement = Decoded.Value;
    }
    return Success({ Status, CheckedAt, Active, Errors, Ready, TcpReady, UdpReady,
        UdpSocketReady, QuicReady, QuicSocketReady, QuicHandshakeReady,
        QuicProtocolReady, RetirementFailures: Retirement });
}

function DecodeHealth(Input: unknown): Result<Health> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    return DecodeHealthObject(Value);
}

function DecodeGeneration(Input: unknown): Result<Generation> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Id = ReadDecimal(Value.id);
    const CreatedAt = ReadDecimal(Value.created_at);
    const Active = ReadBoolean(Value.active);
    const Retiring = ReadBoolean(Value.retiring);
    const HealthResult = DecodeHealth(Value.health);
    if (Id === null || CreatedAt === null || Active === null || Retiring === null || !HealthResult.Ok) {
        return ContractFailure();
    }
    return Success({ Id, CreatedAt, Active, Retiring, Health: HealthResult.Value });
}

function DecodeWorker(Input: unknown): Result<Worker> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Process = ReadDecimal(Value.process);
    const Id = ReadDecimal(Value.id);
    const Generation = ReadDecimal(Value.generation);
    const HealthResult = DecodeHealth(Value.health);
    const TrafficResult = DecodeNullableTraffic(Value.traffic);
    const Running = ReadBoolean(Value.running);
    const Accepting = ReadBoolean(Value.accepting);
    const ActiveTasks = ReadDecimal(Value.active_tasks);
    const DroppedEvents = ReadDecimal(Value.dropped_events);
    if (Process === null || Id === null || Generation === null || !HealthResult.Ok ||
        !TrafficResult.Ok || Running === null || Accepting === null || ActiveTasks === null ||
        DroppedEvents === null) return ContractFailure();
    return Success({ Process, Id, Generation, Health: HealthResult.Value, Traffic: TrafficResult.Value,
        Running, Accepting, ActiveTasks, DroppedEvents });
}

function DecodeAccount(Input: unknown): Result<Account> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Id = ReadDecimal(Value.id);
    const Generation = ReadDecimal(Value.generation);
    const TrafficResult = DecodeNullableTraffic(Value.traffic);
    const ActiveSessions = ReadDecimal(Value.active_sessions);
    const Label = ReadString(Value.label);
    const Revoked = ReadBoolean(Value.revoked);
    if (Id === null || Generation === null || !TrafficResult.Ok || ActiveSessions === null ||
        Label === null || Revoked === null) return ContractFailure();
    return Success({ Id, Generation, Traffic: TrafficResult.Value, ActiveSessions, Label, Revoked });
}

function DecodeSession(Input: unknown): Result<Session> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Id = ReadDecimal(Value.id);
    const Process = ReadDecimal(Value.process);
    const Worker = ReadDecimal(Value.worker);
    const AccountId = ReadDecimal(Value.account);
    const Generation = ReadDecimal(Value.generation);
    const TrafficResult = DecodeNullableTraffic(Value.traffic);
    const StartedAt = ReadDecimal(Value.started_at);
    const Protocol = ReadString(Value.protocol);
    const Target = ReadString(Value.target);
    const Active = ReadBoolean(Value.active);
    const Draining = ReadBoolean(Value.draining);
    let ActiveTasks: Decimal | null = null;
    if (Value.active_tasks !== null) {
        ActiveTasks = ReadDecimal(Value.active_tasks);
        if (ActiveTasks === null) return ContractFailure();
    }
    if (Id === null || Process === null || Worker === null || AccountId === null ||
        Generation === null || !TrafficResult.Ok || StartedAt === null || Protocol === null ||
        Target === null || Active === null || Draining === null) return ContractFailure();
    return Success({ Id, Process, Worker, Account: AccountId, Generation,
        Traffic: TrafficResult.Value, StartedAt, Protocol, Target, Active, Draining, ActiveTasks });
}

function DecodeStream(Input: unknown): Result<Stream> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Id = ReadDecimal(Value.id);
    const Process = ReadDecimal(Value.process);
    const SessionId = ReadDecimal(Value.session);
    const AccountId = ReadDecimal(Value.account);
    const Worker = ReadDecimal(Value.worker);
    const Generation = ReadDecimal(Value.generation);
    const Protocol = ReadString(Value.protocol);
    const State = ReadEnum(Value.state, ['active', 'draining'] as const);
    const Task = ReadDecimal(Value.task);
    const ParentTask = ReadDecimal(Value.parent_task);
    let Traffic: Traffic | null = null;
    if (Value.traffic !== null) {
        const TrafficResult = DecodeTraffic(Value.traffic);
        if (!TrafficResult.Ok) return TrafficResult;
        Traffic = TrafficResult.Value;
    }
    if (Id === null || Process === null || SessionId === null || AccountId === null ||
        Worker === null || Generation === null || Protocol === null || State === null ||
        Task === null || ParentTask === null) {
        return ContractFailure();
    }
    return Success({ Id, Process, Session: SessionId, Account: AccountId, Worker,
        Generation, Task, ParentTask, Traffic, Protocol, State });
}

function DecodeTask(Input: unknown): Result<Task> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Id = ReadDecimal(Value.id);
    const Process = ReadDecimal(Value.process);
    const Worker = ReadDecimal(Value.worker);
    const SessionId = ReadDecimal(Value.session);
    const StreamId = ReadDecimal(Value.stream);
    const Generation = ReadDecimal(Value.generation);
    const ParentTask = ReadDecimal(Value.parent_task);
    const Status = ReadEnum(Value.status, TaskStatuses);
    const StartedAt = ReadDecimal(Value.started_at);
    const CompletedAt = ReadDecimal(Value.completed_at);
    const CancelRequested = ReadBoolean(Value.cancel_requested);
    const Cancellable = ReadBoolean(Value.cancellable);
    const DrainBlocked = ReadBoolean(Value.drain_blocked);
    const Failure = DecodeFailure(Value.failure);
    const DrainFailure = DecodeFailure(Value.drain_failure);
    if (Id === null || Process === null || Worker === null || SessionId === null ||
        StreamId === null || Generation === null || ParentTask === null || Status === null ||
        StartedAt === null || CompletedAt === null || CancelRequested === null || Cancellable === null ||
        DrainBlocked === null || Failure === undefined || DrainFailure === undefined) {
        return ContractFailure();
    }
    return Success({ Id, Process, Worker, Session: SessionId, Stream: StreamId,
        Generation, ParentTask, Status, StartedAt, CompletedAt, CancelRequested, Cancellable,
        DrainBlocked, Failure, DrainFailure });
}

function DecodeEvent(Input: unknown): Result<Event> {
    const Value = ReadObject(Input);
    if (Value === null) return ContractFailure();
    const Sequence = ReadDecimal(Value.sequence);
    const Timestamp = ReadDecimal(Value.timestamp);
    const Correlation = ReadDecimal(Value.correlation);
    const Generation = ReadDecimal(Value.generation);
    const Process = ReadDecimal(Value.process);
    const Worker = ReadDecimal(Value.worker);
    const AccountId = ReadDecimal(Value.account);
    const SessionId = ReadDecimal(Value.session);
    const StreamId = ReadDecimal(Value.stream);
    const TaskId = ReadDecimal(Value.task);
    const ParentTask = ReadDecimal(Value.parent_task);
    const Operation = ReadDecimal(Value.operation);
    const Scope = ReadEnum(Value.scope, EventScopes);
    const Kind = ReadEnum(Value.kind, EventKindValues);
    const Severity = ReadEnum(Value.severity, ['debug', 'info', 'warning', 'error', 'unknown'] as const);
    const Terminal = ReadBoolean(Value.terminal);
    const Truncated = ReadBoolean(Value.truncated);
    let Detail: string | null = null;
    if (Value.detail !== undefined) {
        Detail = ReadString(Value.detail);
        if (Detail === null) return ContractFailure();
    }
    if (Sequence === null || Timestamp === null || Correlation === null || Generation === null ||
        Process === null || Worker === null || AccountId === null || SessionId === null ||
        StreamId === null || TaskId === null || ParentTask === null || Operation === null ||
        Scope === null || Kind === null || Severity === null || Terminal === null || Truncated === null) {
        return ContractFailure();
    }
    return Success({ Sequence, Timestamp, Correlation, Generation, Process, Worker,
        Account: AccountId, Session: SessionId, Stream: StreamId, Task: TaskId, ParentTask,
        Operation, Scope, Kind, Severity, Terminal, Truncated, Detail });
}

function DecodePage<Value>(Input: unknown, Decode: Decoder<Value>): Result<Page<Value>> {
    const ValueObject = ReadObject(Input);
    if (ValueObject === null || !Array.isArray(ValueObject.items) || ValueObject.items.length > 1024) {
        return ContractFailure();
    }
    const Items: Value[] = [];
    for (const Item of ValueObject.items) {
        const Decoded = Decode(Item);
        if (!Decoded.Ok) return Decoded;
        Items.push(Decoded.Value);
    }
    const NextCursor = ReadDecimal(ValueObject.next_cursor);
    const HasMore = ReadBoolean(ValueObject.has_more);
    if (NextCursor === null || HasMore === null) return ContractFailure();
    return Success({ Items, NextCursor, HasMore });
}

function DecodeEventPage(Input: unknown): Result<EventPage> {
    const Value = ReadObject(Input);
    if (Value === null || !Array.isArray(Value.items) || Value.items.length > 1024 ||
        !Array.isArray(Value.lost_ranges) || Value.lost_ranges.length > 1024) return ContractFailure();
    const Items: Event[] = [];
    for (const Item of Value.items) {
        const Decoded = DecodeEvent(Item);
        if (!Decoded.Ok) return Decoded;
        Items.push(Decoded.Value);
    }
    const LostRanges: { First: Decimal; Last: Decimal }[] = [];
    for (const Item of Value.lost_ranges) {
        const Range = ReadObject(Item);
        if (Range === null) return ContractFailure();
        const First = ReadDecimal(Range.first);
        const Last = ReadDecimal(Range.last);
        if (First === null || Last === null || BigInt(First) > BigInt(Last)) return ContractFailure();
        LostRanges.push({ First, Last });
    }
    const NextCursor = ReadDecimal(Value.next_cursor);
    const HasMore = ReadBoolean(Value.has_more);
    const EarliestCursor = ReadDecimal(Value.earliest_cursor);
    const Lost = ReadBoolean(Value.lost);
    const Dropped = ReadDecimal(Value.dropped);
    const TerminalDropped = ReadDecimal(Value.terminal_dropped);
    const Overwritten = ReadDecimal(Value.overwritten);
    const SeverityFilterSupported = ReadBoolean(Value.severity_filter_supported);
    if (NextCursor === null || HasMore === null || EarliestCursor === null || Lost === null ||
        Dropped === null || TerminalDropped === null || Overwritten === null ||
        SeverityFilterSupported === null) {
        return ContractFailure();
    }
    return Success({ Items, NextCursor, HasMore, EarliestCursor, Lost, Dropped, TerminalDropped,
        Overwritten, LostRanges, SeverityFilterSupported });
}

function QueryStatusHttp(Status: QueryStatus): number {
    if (Status === 'ok') return 200;
    if (Status === 'unavailable') return 503;
    if (Status === 'not_found') return 404;
    if (Status === 'failed') return 500;
    return 400;
}

function DecodeQueryEnvelope<Value>(
    Response: HttpResponseData, Decode: Decoder<Value>,
): Result<QueryEnvelope<Value>> {
    const ValueObject = ReadObject(Response.Payload);
    if (ValueObject === null) return ContractFailure();
    const Correlation = ReadDecimal(ValueObject.correlation);
    const Status = ReadEnum(ValueObject.status, QueryStatuses);
    const Message = ReadString(ValueObject.message);
    const Failure = DecodeFailure(ValueObject.failure);
    if (Correlation === null || Correlation === '0' || Status === null || Message === null || Failure === undefined ||
        QueryStatusHttp(Status) !== Response.Status) return ContractFailure();
    if (Status !== 'ok') {
        if (ValueObject.value !== null || Failure === null && Status === 'failed') return ContractFailure();
        return Success({ Status, Value: null, Message, Failure });
    }
    const Decoded = Decode(ValueObject.value);
    if (!Decoded.Ok || Failure !== null || Message.length > 0) return ContractFailure();
    return Success({ Status, Value: Decoded.Value, Message, Failure });
}

function CommandStatusHttp(Status: CommandStatus): number {
    if (Status === 'accepted') return 202;
    if (Status === 'completed') return 200;
    if (Status === 'rejected' || Status === 'invalid') return 400;
    if (Status === 'unavailable') return 503;
    if (Status === 'failed') return 500;
    if (Status === 'timed_out') return 504;
    return 409;
}

function DecodeConfigurationIssues(Input: unknown): readonly ConfigurationIssue[] | null {
    if (!Array.isArray(Input) || Input.length > 64) return null;
    const Issues: ConfigurationIssue[] = [];
    for (const Item of Input) {
        const Value = ReadObject(Item);
        if (Value === null) return null;
        const Code = ReadString(Value.code);
        const Path = ReadString(Value.path);
        const Message = ReadString(Value.message);
        if (Code === null || Code.length === 0 || Path === null || Message === null) return null;
        Issues.push({ Code, Path, Message });
    }
    return Issues;
}

function DecodeRestartFields(Input: unknown): readonly string[] | null {
    if (!Array.isArray(Input) || Input.length > 64 ||
        !Input.every(Item => typeof Item === 'string' && Item.length > 0 && Item.length <= 256) ||
        new Set(Input).size !== Input.length) return null;
    return Input as readonly string[];
}

/** @brief 解码同一响应的完整配置原文；JSON 数值不通过已解析的浮点 Payload 往返。 */
export const DecodeConfigurationQuery: ResponseDecoder<QueryEnvelope<ConfigurationSnapshot>> = Response => {
    const Document = ParseJsonDocument({ Text: Response.Text, MaxBytes: 131072 });
    if (!Document.Ok || Document.Value.Kind !== 'object') return ContractFailure();
    const ValueNode = Document.Value.Members.get('value');
    return DecodeQueryEnvelope(Response, Input => {
        const Value = ReadObject(Input);
        if (Value === null || ValueNode?.Kind !== 'object') return ContractFailure();
        const Generation = ReadDecimal(Value.generation);
        const Reloadable = ReadBoolean(Value.reloadable);
        const Configuration = ValueNode.Members.get('configuration');
        if (Generation === null || Generation === '0' || Reloadable === null || Configuration === undefined) return ContractFailure();
        const Parsed = ParsePublicConfiguration(Configuration.Raw);
        if (!Parsed.Ok) return ContractFailure();
        return Success({ Generation, Reloadable, Node: Parsed.Value, Text: Configuration.Raw });
    });
};

function DecodeCommandEnvelope(Response: HttpResponseData): Result<CommandEnvelope> {
    const Value = ReadObject(Response.Payload);
    if (Value === null) return ContractFailure();
    const Correlation = ReadDecimal(Value.correlation);
    const Status = ReadEnum(Value.status, CommandStatuses);
    const Operation = ReadDecimal(Value.operation);
    let Process: Decimal | null = null;
    if (Value.process !== undefined) {
        Process = ReadDecimal(Value.process);
        if (Process === null || Process === '0') return ContractFailure();
    }
    const Generation = ReadDecimal(Value.generation);
    const Worker = ReadDecimal(Value.worker);
    const AccountId = ReadDecimal(Value.account);
    const SessionId = ReadDecimal(Value.session);
    const StreamId = ReadDecimal(Value.stream);
    const TaskId = ReadDecimal(Value.task);
    let ParentTask: Decimal | null = null;
    if (Value.parent_task !== undefined) {
        ParentTask = ReadDecimal(Value.parent_task);
        if (ParentTask === null || ParentTask === '0') return ContractFailure();
    }
    const Message = ReadString(Value.message);
    const ConfigurationIssues = DecodeConfigurationIssues(Value.configuration_issues);
    const RestartRequiredFields = DecodeRestartFields(Value.restart_required_fields);
    let Failure: NativeFailure | null = null;
    if (Value.failure !== undefined) {
        const DecodedFailure = DecodeFailure(Value.failure);
        if (DecodedFailure === undefined) return ContractFailure();
        Failure = DecodedFailure;
    }
    if (Correlation === null || Correlation === '0' || Status === null || Operation === null || Generation === null || Worker === null ||
        AccountId === null || SessionId === null || StreamId === null || TaskId === null ||
        Message === null || Failure === undefined || ConfigurationIssues === null || RestartRequiredFields === null || CommandStatusHttp(Status) !== Response.Status) {
        return ContractFailure();
    }
    if (Status === 'accepted' && Operation === '0') return ContractFailure();
    if (Status === 'completed' && Failure !== null) return ContractFailure();
    if ((Status === 'failed' || Status === 'timed_out' || Status === 'blocked') && Failure === null) {
        return ContractFailure();
    }
    return Success({ Status, Operation, Process, Generation, Worker, Account: AccountId,
        Session: SessionId, Stream: StreamId, Task: TaskId, ParentTask,
        Message, Failure, ConfigurationIssues, RestartRequiredFields });
}

/** @brief 仅在响应携带进程目标时校验其与当前管理进程一致。 */
export function VerifyCommandProcess(
    ResultValue: Result<CommandEnvelope>, ExpectedProcess: Decimal, MayHaveExecuted: boolean,
): Result<CommandEnvelope> {
    if (!ResultValue.Ok || ResultValue.Value.Process === null ||
        ResultValue.Value.Process === ExpectedProcess) return ResultValue;
    return Fail({ Kind: 'contract', Message: '命令响应中的进程编号与当前管理进程不一致，无法确认操作范围',
        HttpStatus: null, MayHaveExecuted });
}

function QueryDecoder<Value>(Decode: Decoder<Value>): ResponseDecoder<QueryEnvelope<Value>> {
    return Response => DecodeQueryEnvelope(Response, Decode);
}

export const DecodeHealthQuery = QueryDecoder(DecodeHealth);
export const DecodeMetricsQuery = QueryDecoder(DecodeMetrics);
export const DecodeGenerationQuery = QueryDecoder(DecodeGeneration);
export const DecodeWorkersQuery = QueryDecoder(Input => DecodePage(Input, DecodeWorker));
export const DecodeAccountsQuery = QueryDecoder(Input => DecodePage(Input, DecodeAccount));
export const DecodeSessionsQuery = QueryDecoder(Input => DecodePage(Input, DecodeSession));
export const DecodeStreamsQuery = QueryDecoder(Input => DecodePage(Input, DecodeStream));
export const DecodeTasksQuery = QueryDecoder(Input => DecodePage(Input, DecodeTask));
export const DecodeEventsQuery = QueryDecoder(DecodeEventPage);
export const DecodeCommandResponse: ResponseDecoder<CommandEnvelope> = DecodeCommandEnvelope;

/** @brief 验证当前进程集合查询中的每一项都属于 Bootstrap 所确认的进程。 */
export function VerifyProcessScope<Value extends Readonly<{ Process: Decimal }>,
    Collection extends Readonly<{ Items: readonly Value[] }>>(
    ResultValue: Result<QueryEnvelope<Collection>>, Process: Decimal,
): Result<QueryEnvelope<Collection>> {
    if (!ResultValue.Ok || ResultValue.Value.Status !== 'ok' || ResultValue.Value.Value === null) {
        return ResultValue;
    }
    if (ResultValue.Value.Value.Items.some(Item => Item.Process !== Process)) return ContractFailure();
    return ResultValue;
}

export function QueryFailureMessage<Value>(Response: QueryEnvelope<Value>): string {
    if (Response.Message.length > 0) return Response.Message;
    if (Response.Status === 'unavailable') return '当前查询处理器不可用';
    if (Response.Status === 'not_found') return '目标已不存在';
    if (Response.Status === 'invalid') return '查询参数无效';
    return '查询失败';
}

export function PagePath(Path: string, Cursor: string, Limit: number): string {
    const Query = new URLSearchParams({ cursor: Cursor, limit: String(Limit) });
    return `${Path}?${Query.toString()}`;
}

