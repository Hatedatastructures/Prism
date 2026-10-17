import type { AccountRecord, EventPage, IngressRecord, GroupRecord, WorkerRecord, SessionRecord, StreamRecord, TaskRecord, ProtocolRecord, OverviewSnapshot, LatencySummary, MemoryAllocationSnapshot, MetricsTraffic, AccountUsage, HistorySnapshot, EffectivePolicy } from '../Services/AdminDataSource.ts';
import { Bool, Decimal, FailureText, List, NullableDecimal, NullableText, RecordValue, Text, DecodePage, OptionalId } from './Wire.ts';
import { CanonicalProtocol } from './ProtocolIdentity.ts';
import { EventLabel } from './EventIdentity.ts';

export function DecodeTraffic(Input: unknown): MetricsTraffic | null {
    if (Input === undefined || Input === null) return null;
    const Value = RecordValue(Input);
    return { Up: Decimal(Value.up_bytes), Down: Decimal(Value.down_bytes), Events: Decimal(Value.events), Errors: Decimal(Value.errors) };
}
export function DecodeWorker(Input: unknown): WorkerRecord {
    const Value = RecordValue(Input), Health = RecordValue(Value.health), Queue = RecordValue(Value.queue), Tasks = RecordValue(Value.tasks), Dispatch = RecordValue(Value.dispatch), Commands = RecordValue(Value.commands);
    const Running = Bool(Value.running), Accepting = Bool(Value.accepting);
    return { Id: Decimal(Value.id), Name: `Worker ${Decimal(Value.id)}`, ProcessId: Decimal(Value.process), GenerationId: Decimal(Value.generation),
        Health: Text(Health.status) as WorkerRecord['Health'], State: Accepting ? 'running' : Running ? 'draining' : 'offline', Running, Accepting,
        ActiveTasks: Decimal(Value.active_tasks), DroppedEvents: Decimal(Value.dropped_events), Traffic: DecodeTraffic(Value.traffic), LoadPercent: null,
        QueueDepth: Decimal(Queue.depth), QueueCapacity: Decimal(Queue.capacity), StartedTasks: Decimal(Tasks.started), CompletedTasks: Decimal(Tasks.completed),
        CancelledTasks: Decimal(Tasks.cancelled), DispatchAccepted: Decimal(Dispatch.accepted), DispatchFull: Decimal(Dispatch.full), DispatchClosed: Decimal(Dispatch.closed),
        DispatchUnavailable: Decimal(Dispatch.unavailable), DispatchGenerationRejected: Decimal(Dispatch.generation_rejected),
        CommandsExecuted: Decimal(Commands.executed), CommandsFailed: Decimal(Commands.failed) };
}
export function DecodeAccount(Input: unknown): AccountRecord {
    const Value = RecordValue(Input);
    return { Id: Decimal(Value.id), GenerationId: Decimal(Value.generation), Label: Text(Value.label), Revoked: Bool(Value.revoked),
        ActiveSessions: Decimal(Value.active_sessions), GroupId: NullableText(Value.group_id), Traffic: DecodeTraffic(Value.traffic),
        ...(Value.account_key === undefined ? {} : { AccountKey: Text(Value.account_key) }),
        EffectivePolicy: Value.effective_policy ? RecordValue(Value.effective_policy) as EffectivePolicy : null,
        PolicySources: Value.policy_sources ? Object.fromEntries(Object.entries(RecordValue(Value.policy_sources)).map(([Key, Item]) => [Key, Text(Item)])) : {},
        ActiveConnections: NullableDecimal(Value.active_connections), ActiveStreams: NullableDecimal(Value.active_streams),
        UploadBytesPerSecond: NullableDecimal(Value.upload_bytes_per_second), DownloadBytesPerSecond: NullableDecimal(Value.download_bytes_per_second) };
}
export function DecodeIngress(Input: unknown): IngressRecord {
    const Value = RecordValue(Input);
    return { Id: Text(Value.id), Transport: Text(Value.transport), ConfiguredAddress: Text(Value.configured_address), BoundAddress: NullableText(Value.bound_address),
        Ready: Bool(Value.ready), ActiveConnections: NullableDecimal(Value.active_connections), Protocols: List(Value.protocols).map(Text), Carriers: List(Value.carriers).map(Text),
        ...(Value.expected_state === undefined ? {} : { ExpectedState: Text(Value.expected_state) }),
        ...(Value.actual_state === undefined ? {} : { ActualState: Text(Value.actual_state) }),
        Reason: NullableText(Value.reason) ?? '', StateSince: NullableText(Value.state_since) };
}
export function DecodeGroup(Input: unknown): GroupRecord {
    const Value = RecordValue(Input);
    return { Id: Text(Value.id), Name: Text(Value.name), ConfiguredAccountCount: Decimal(Value.configured_account_count),
        ActiveAccountCount: Decimal(Value.active_account_count), ActiveSessions: NullableDecimal(Value.active_sessions), Traffic: DecodeTraffic(Value.traffic) };
}
export function DecodeSession(Input: unknown): SessionRecord {
    const Value = RecordValue(Input);
    return { Id: Decimal(Value.id), ProcessId: Decimal(Value.process), WorkerId: Decimal(Value.worker), AccountId: Decimal(Value.account), GenerationId: Decimal(Value.generation),
        Traffic: DecodeTraffic(Value.traffic), StartedAt: Text(Value.started_at), Transport: Text(Value.transport), Identity: Text(Value.identity), SourceAddress: Text(Value.source_address),
        Protocol: CanonicalProtocol(Text(Value.protocol)), Target: Text(Value.target), Active: Bool(Value.active), Draining: Bool(Value.draining), ActiveTasks: NullableDecimal(Value.active_tasks), Streams: [], Tasks: [] };
}
export function DecodeStream(Input: unknown): StreamRecord {
    const Value = RecordValue(Input);
    return { Id: Decimal(Value.id), TaskId: Decimal(Value.task), ParentTaskId: NullableDecimal(Value.parent_task), ProcessId: Decimal(Value.process), SessionId: Decimal(Value.session),
        AccountId: Decimal(Value.account), WorkerId: Decimal(Value.worker), GenerationId: Decimal(Value.generation), Traffic: DecodeTraffic(Value.traffic),
        Protocol: Text(Value.protocol), State: Text(Value.state) as StreamRecord['State'] };
}
export function DecodeTask(Input: unknown): TaskRecord {
    const Value = RecordValue(Input);
    return { Id: Decimal(Value.id), ProcessId: Decimal(Value.process), WorkerId: Decimal(Value.worker), SessionId: Decimal(Value.session), StreamId: Decimal(Value.stream),
        GenerationId: Decimal(Value.generation), ParentTaskId: NullableDecimal(Value.parent_task), Status: Text(Value.status) as TaskRecord['Status'],
        StartedAt: NullableText(Value.started_at), CompletedAt: NullableText(Value.completed_at), CancelRequested: Bool(Value.cancel_requested), Cancellable: Bool(Value.cancellable),
        DrainBlocked: Bool(Value.drain_blocked), Failure: FailureText(Value.failure), DrainFailure: FailureText(Value.drain_failure) };
}
export function DecodeLatency(Input: unknown): LatencySummary {
    const Value = RecordValue(Input);
    return { Name: Text(Value.name), Available: Bool(Value.available), SampleCount: Decimal(Value.sample_count),
        P50Ms: NullableDecimal(Value.p50_ms), P95Ms: NullableDecimal(Value.p95_ms), P99Ms: NullableDecimal(Value.p99_ms), MaxMs: NullableDecimal(Value.max_ms),
        WorkerId: NullableDecimal(Value.worker_id), Protocol: NullableText(Value.protocol) };
}
export function DecodeProtocol(Input: unknown): ProtocolRecord {
    const Value = RecordValue(Input);
    return { Id: Text(Value.id), Name: Text(Value.name), ConfiguredBindings: Decimal(Value.configured_bindings), ActiveSessions: NullableDecimal(Value.active_sessions),
        Traffic: DecodeTraffic(Value.traffic), Latency: Value.latency ? DecodeLatency(Value.latency) : null, Coverage: Text(Value.coverage),
        ...(Value.kind === undefined ? {} : { Kind: Text(Value.kind) as ProtocolRecord['Kind'] & string }),
        ...(Value.type_key === undefined ? {} : { TypeKey: Text(Value.type_key) }) };
}
export function DecodeAllocation(Input: unknown): MemoryAllocationSnapshot {
    const Value = RecordValue(Input);
    return { Available: Bool(Value.available), CurrentBytes: NullableDecimal(Value.current_bytes), PeakBytes: NullableDecimal(Value.peak_bytes),
        AllocationCount: NullableDecimal(Value.allocation_count), ReleaseCount: NullableDecimal(Value.release_count), Coverage: Text(Value.coverage) };
}
export function DecodeOverview(Input: unknown): OverviewSnapshot {
    const Value = RecordValue(Input), Process = RecordValue(Value.process), Health = RecordValue(Value.health), Counts = RecordValue(Value.counts), Traffic = RecordValue(Value.traffic),
        Latency = RecordValue(Value.latency), Memory = RecordValue(Value.memory), Pool = RecordValue(Memory.byte_pool), Observations = RecordValue(Value.observations);
    return { SampledAt: Text(Value.sampled_at), SampleIntervalMs: Decimal(Value.sample_interval_ms),
        Process: { Id: Decimal(Process.id), GenerationId: Decimal(Process.generation), Phase: Text(Process.phase) },
        Health: { Status: Text(Health.status) as OverviewSnapshot['Health']['Status'], CheckedAt: Text(Health.checked_at), Ready: Bool(Health.ready),
            TcpReady: Bool(Health.tcp_ready), UdpReady: Bool(Health.udp_ready), UdpSocketReady: Bool(Health.udp_socket_ready), QuicReady: Bool(Health.quic_ready),
            QuicSocketReady: Bool(Health.quic_socket_ready), QuicHandshakeReady: Bool(Health.quic_handshake_ready), QuicProtocolReady: Bool(Health.quic_protocol_ready),
            Active: Decimal(Health.active), Errors: Decimal(Health.errors) },
        Counts: { ConfiguredAccounts: Decimal(Counts.configured_accounts), ActiveAccounts: Decimal(Counts.active_accounts), UngroupedAccounts: Decimal(Counts.ungrouped_accounts),
            TcpSessions: Decimal(Counts.tcp_sessions), UdpConnections: NullableDecimal(Counts.udp_connections), QuicConnections: NullableDecimal(Counts.quic_connections),
            WorkersTotal: Decimal(Counts.workers_total), WorkersAccepting: Decimal(Counts.workers_accepting) },
        Traffic: { Available: Bool(Traffic.available), UpBytes: NullableDecimal(Traffic.up_bytes), DownBytes: NullableDecimal(Traffic.down_bytes),
            Events: NullableDecimal(Traffic.events), Errors: NullableDecimal(Traffic.errors), UpBytesPerSecond: NullableDecimal(Traffic.up_bytes_per_second), DownBytesPerSecond: NullableDecimal(Traffic.down_bytes_per_second) },
        Latency: { RecognitionAdmission: DecodeLatency(Latency.recognition_admission), Stages: List(Latency.stages).map(DecodeLatency) },
        Memory: { ProcessAvailable: Bool(Memory.process_available), ProcessRssBytes: NullableDecimal(Memory.process_rss_bytes), ProcessPeakRssBytes: NullableDecimal(Memory.process_peak_rss_bytes),
            WorkingSetBytes: NullableDecimal(Memory.working_set_bytes), BytePool: { Available: Bool(Pool.available), UsedBytes: NullableDecimal(Pool.used_bytes), CapacityBytes: NullableDecimal(Pool.capacity_bytes),
                AvailableBlocks: NullableDecimal(Pool.available_blocks), BlockSize: NullableDecimal(Pool.block_size), PeakUsedBytes: NullableDecimal(Pool.peak_used_bytes),
                AllocationCount: NullableDecimal(Pool.allocation_count), ReleaseCount: NullableDecimal(Pool.release_count) }, Allocations: DecodeAllocation(Memory.allocations),
            WorkerAllocations: List(Memory.worker_allocations).map(Item => { const Allocation = RecordValue(Item); return { WorkerId: Decimal(Allocation.worker_id), Allocation: DecodeAllocation(Allocation.allocation) }; }) },
        Observations: { Accepted: Decimal(Observations.accepted), Consumed: Decimal(Observations.consumed), Dropped: Decimal(Observations.dropped), AggregationFailures: Decimal(Observations.aggregation_failures) },
        History: List(Value.history).map(Item => { const Sample = RecordValue(Item); const TrafficValue = DecodeTraffic(Sample.traffic); if (!TrafficValue) throw new Error('历史流量缺失'); return { Time: Text(Sample.timestamp), Traffic: TrafficValue }; }),
        TcpSessionHistory: [], Protocols: List(Value.protocols).map(DecodeProtocol) };
}
export function DecodeEvents(Input: unknown): EventPage {
    const Value = RecordValue(Input);
    return { ...DecodePage(Value, InputItem => {
        const Item = RecordValue(InputItem);
        const Kind = Text(Item.kind), Sequence = Decimal(Item.sequence);
        return { Id: Sequence, Sequence, Time: Text(Item.timestamp), CorrelationId: Decimal(Item.correlation), GenerationId: Decimal(Item.generation), ProcessId: Decimal(Item.process),
            WorkerId: OptionalId(Item.worker), AccountId: OptionalId(Item.account), SessionId: OptionalId(Item.session), StreamId: OptionalId(Item.stream),
            TaskId: OptionalId(Item.task), ParentTaskId: OptionalId(Item.parent_task), OperationId: OptionalId(Item.operation),
            Severity: Text(Item.severity) as EventPage['Items'][number]['Severity'], Kind, Scope: Text(Item.scope) as EventPage['Items'][number]['Scope'],
            Message: EventLabel(Kind), Detail: NullableText(Item.detail) ?? '', Terminal: Bool(Item.terminal), Truncated: Bool(Item.truncated) };
    }), EarliestCursor: Text(Value.earliest_cursor), Lost: Bool(Value.lost), LostRanges: List(Value.lost_ranges).map(Item => {
        const Range = RecordValue(Item); return { First: Decimal(Range.first), Last: Decimal(Range.last) };
    }), Dropped: Decimal(Value.dropped), TerminalDropped: Decimal(Value.terminal_dropped), Overwritten: Decimal(Value.overwritten), SeverityFilterSupported: Bool(Value.severity_filter_supported) };
}
export function DecodeUsage(Input: unknown): AccountUsage {
    const Value = RecordValue(Input);
    return { AccountKey: Text(Value.account_key), Revision: Decimal(Value.revision), CycleStart: Text(Value.cycle_start), CycleEnd: NullableText(Value.cycle_end),
        LimitBytes: NullableDecimal(Value.limit_bytes), SettledBytes: Decimal(Value.settled_bytes), ReservedBytes: Decimal(Value.reserved_bytes), UncertainBytes: Decimal(Value.uncertain_bytes),
        RemainingBytes: NullableDecimal(Value.remaining_bytes), OverageBytes: Decimal(Value.overage_bytes), Available: Bool(Value.available), Failure: FailureText(Value.failure) };
}
export function DecodeHistory(Input: unknown): HistorySnapshot {
    const Value = RecordValue(Input);
    return { SampledAt: Text(Value.sampled_at), From: Text(Value.from), To: Text(Value.to), ResolutionMs: Decimal(Value.resolution_ms), Coverage: Text(Value.coverage),
        Gaps: List(Value.gaps).map(InputGap => { const Gap = RecordValue(InputGap); return { From: Text(Gap.from), To: Text(Gap.to), Reason: Text(Gap.reason) }; }),
        Items: List(Value.items).map(InputPoint => { const Point = RecordValue(InputPoint); return { Time: Text(Point.time), UpBytes: NullableDecimal(Point.up_bytes),
            DownBytes: NullableDecimal(Point.down_bytes), Active: NullableDecimal(Point.active), P50Us: NullableDecimal(Point.p50_us), P95Us: NullableDecimal(Point.p95_us),
            P99Us: NullableDecimal(Point.p99_us), SampleCount: Decimal(Point.sample_count), Quality: NullableText(Point.quality) ?? '' }; }) };
}
