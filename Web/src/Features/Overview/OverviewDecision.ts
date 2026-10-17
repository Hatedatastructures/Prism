import type {
    CursorPage,
    EventPage,
    IngressRecord,
    OverviewSnapshot,
    UInt64Value,
} from '../../Services/AdminDataSource.ts';

export type OverviewQueryState = 'success' | 'pending' | 'error';
export type OverviewAvailabilityState = 'normal' | 'affected' | 'limited';
export type OverviewObservationState = 'reported' | 'gaps' | 'unavailable' | 'pending';

export type OverviewAvailabilityCode =
    | 'ready'
    | 'tcp-unready'
    | 'udp-unready'
    | 'runtime-not-ready'
    | 'process-failed'
    | 'planned-draining'
    | 'phase-unavailable'
    | 'overview-pending'
    | 'overview-unavailable'
    | 'snapshot-invalid'
    | 'snapshot-stale'
    | 'health-conflict'
    | 'ingresses-pending'
    | 'ingresses-unavailable'
    | 'ingresses-empty'
    | 'ingresses-partial';

export type OverviewDecision = Readonly<{
    Availability: Readonly<{
        State: OverviewAvailabilityState;
        Code: OverviewAvailabilityCode;
        Title: string;
        Detail: string;
        Evidence: readonly string[];
        NextPath: string;
        NextLabel: string;
    }>;
    Observation: Readonly<{
        State: OverviewObservationState;
        Detail: string;
    }>;
}>;

export type OverviewDecisionInput = Readonly<{
    NowMs: number;
    Snapshot: OverviewSnapshot | null;
    Ingresses: CursorPage<IngressRecord> | null;
    Events: EventPage | null;
    Queries: Readonly<{
        Overview: OverviewQueryState;
        Ingresses: OverviewQueryState;
        Events: OverviewQueryState;
    }>;
}>;

const MaximumSampleAgeMs = 20_000;

/** @brief 将核心接入可用性与事件/观测完整性分开决策。 */
export function DecideOverview(Input: OverviewDecisionInput): OverviewDecision {
    const Availability = DecideAvailability(Input);
    const Observation = DecideObservation(Input);
    return { Availability, Observation };
}

function DecideAvailability(Input: OverviewDecisionInput): OverviewDecision['Availability'] {
    if (Input.Queries.Overview === 'pending' || Input.Snapshot === null) {
        return MakeAvailability(
            'limited',
            'overview-pending',
            '正在确认当前接入状态',
            '等待最新运行快照；此时不对服务状态作全局判断。',
            [],
        );
    }
    if (Input.Queries.Overview === 'error') {
        return MakeAvailability(
            'limited',
            'overview-unavailable',
            '当前接入状态暂不可核对',
            '最新运行快照查询失败；保留的数据只能作为上次记录。',
            [],
        );
    }

    const Snapshot = Input.Snapshot;
    const SampledAtMs = Date.parse(Snapshot.SampledAt);
    if (!Number.isFinite(SampledAtMs) || SampledAtMs > Input.NowMs) {
        return MakeAvailability(
            'limited',
            'snapshot-invalid',
            '运行快照时间无效',
            '采样时间无法与当前时间核对；请刷新快照后再判断接入状态。',
            [Snapshot.SampledAt],
        );
    }
    if (Input.NowMs - SampledAtMs > MaximumSampleAgeMs) {
        return MakeAvailability(
            'limited',
            'snapshot-stale',
            '运行快照已过期',
            '快照超过 20 秒；请刷新并重新核对入口状态。',
            [Snapshot.SampledAt],
        );
    }

    const CurrentIngresses = Input.Queries.Ingresses === 'success' ? Input.Ingresses : null;
    const Phase = Snapshot.Process.Phase.toLowerCase();
    if (Phase === 'failed') {
        return MakeAvailability(
            'affected',
            'process-failed',
            '运行进程报告失败',
            '当前运行状态报告失败，不能据此确认任何接入能力可用。',
            HealthEvidence(Snapshot, CurrentIngresses),
            '/events',
        );
    }
    if (Phase === 'stopping') {
        return MakeAvailability(
            'limited',
            'planned-draining',
            '实例正在计划排空',
            '实例正在计划排空；排空过程不作为 listener 故障或正常运行判断。',
            HealthEvidence(Snapshot, CurrentIngresses),
            '/operations',
        );
    }
    if (Phase !== 'ready') {
        return MakeAvailability(
            'limited',
            'phase-unavailable',
            '当前阶段无法确认接入状态',
            '当前运行阶段尚不能证明接入能力可用；等待状态更新后再核对。',
            HealthEvidence(Snapshot, CurrentIngresses),
        );
    }

    const Transports = new Set((CurrentIngresses?.Items ?? []).map(Row => Row.Transport.toLowerCase()));
    const HasUdp = Transports.has('udp');
    const Health = Snapshot.Health;
    const KnownFailures = KnownConfiguredFailures(Health, HasUdp);

    if (Health.Ready && KnownFailures.length > 0) {
        return MakeAvailability(
            'limited',
            'health-conflict',
            '运行状态需核对',
            '实例报告的就绪信号相互矛盾，暂无法确认整体接入状态。',
            HealthEvidence(Snapshot, CurrentIngresses),
            TransportPath(CurrentIngresses, KnownFailures[0] ?? ''),
        );
    }

    if (Health.Ready && Health.Status !== 'healthy') {
        return MakeAvailability(
            'limited',
            'health-conflict',
            '运行状态需核对',
            '实例报告的就绪信号相互矛盾，暂无法确认整体接入状态。',
            HealthEvidence(Snapshot, CurrentIngresses),
            '/ingresses',
        );
    }

    if (!Health.Ready && Health.Status !== 'degraded' && Health.Status !== 'unhealthy') {
        return MakeAvailability(
            'limited',
            'health-conflict',
            '运行状态需核对',
            '实例报告的就绪信号相互矛盾，暂无法确认整体接入状态。',
            HealthEvidence(Snapshot, CurrentIngresses),
            '/ingresses',
        );
    }

    if (Health.Ready) {
        const ScopeProblem = IngressScopeProblem(Input);
        if (ScopeProblem !== null) {
            return ScopeProblem;
        }
        return MakeAvailability(
            'normal',
            'ready',
            '当前已确认的入口范围就绪',
            '当前运行快照报告接入就绪；此结论只覆盖当前完整返回的入口配置。',
            HealthEvidence(Snapshot, CurrentIngresses),
        );
    }

    if (!Health.TcpReady) {
        return MakeAvailability(
            'affected',
            'tcp-unready',
            'TCP 接入未就绪',
            '当前报告的 TCP listener 未就绪；请核对 TCP 入口和恢复路径。',
            HealthEvidence(Snapshot, CurrentIngresses),
            TransportPath(CurrentIngresses, 'TCP'),
        );
    }
    if (HasUdp && (!Health.UdpReady || !Health.UdpSocketReady)) {
        return MakeAvailability(
            'affected',
            'udp-unready',
            'UDP 接入未就绪',
            '当前返回的配置包含 UDP 入口；运行状态报告对应 listener 或 socket 尚未就绪。',
            HealthEvidence(Snapshot, CurrentIngresses),
            TransportPath(CurrentIngresses, 'UDP'),
        );
    }
    return MakeAvailability(
        'affected',
        'runtime-not-ready',
        '整体接入受损',
        '实例报告整体接入未就绪，但当前字段不能定位到具体传输或入口原因。',
        HealthEvidence(Snapshot, CurrentIngresses),
        '/ingresses',
    );
}

function IngressScopeProblem(Input: OverviewDecisionInput): OverviewDecision['Availability'] | null {
    if (Input.Queries.Ingresses === 'pending') {
        return MakeAvailability(
            'limited',
            'ingresses-pending',
            '入口范围仍在载入',
            '运行 Health 当前报告就绪，但入口列表尚未载入；现在不能说明完整配置覆盖。',
            [],
        );
    }
    if (Input.Queries.Ingresses === 'error' || Input.Ingresses === null) {
        return MakeAvailability(
            'limited',
            'ingresses-unavailable',
            '入口范围暂不可核对',
            '运行 Health 当前报告就绪，但入口查询失败；现在不能说明完整配置覆盖。',
            [],
        );
    }
    if (Input.Ingresses.Items.length === 0) {
        return MakeAvailability(
            'limited',
            'ingresses-empty',
            '没有可核对的入口记录',
            'Health 报告整体就绪，但当前没有入口配置记录；不能据此确认代理入口范围。',
            [],
        );
    }
    if (Input.Ingresses.HasMore) {
        return MakeAvailability(
            'limited',
            'ingresses-partial',
            '入口范围只覆盖已载入记录',
            '首页已读取 ' + Input.Ingresses.Items.length + ' 条入口，仍有未载入记录；不能将局部结果称为完整入口范围。',
            [],
        );
    }
    return null;
}

function KnownConfiguredFailures(
    Health: OverviewSnapshot['Health'],
    HasUdp: boolean,
): string[] {
    const Failures: string[] = [];
    if (!Health.TcpReady) {
        Failures.push('TCP');
    }
    if (HasUdp && (!Health.UdpReady || !Health.UdpSocketReady)) {
        Failures.push('UDP');
    }
    return Failures;
}

function HealthEvidence(
    Snapshot: OverviewSnapshot,
    Ingresses: CursorPage<IngressRecord> | null,
): string[] {
    const Evidence = [
        'Phase ' + Snapshot.Process.Phase,
        'Health.Status ' + Snapshot.Health.Status,
        'Health.Ready ' + String(Snapshot.Health.Ready),
        'TCP listener readiness ' + (Snapshot.Health.TcpReady ? 'true' : 'false'),
        'UDP Health readiness ' + (Snapshot.Health.UdpReady ? 'true' : 'false'),
        'UDP socket readiness ' + (Snapshot.Health.UdpSocketReady ? 'true' : 'false'),
        'QUIC socket readiness ' + (Snapshot.Health.QuicSocketReady ? 'true' : 'false'),
        'QUIC handshake/protocol readiness ' + (Snapshot.Health.QuicHandshakeReady ? 'true' : 'false') + '/' + (Snapshot.Health.QuicProtocolReady ? 'true' : 'false'),
        'QUIC aggregate readiness ' + (Snapshot.Health.QuicReady ? 'true' : 'false') + '（响应未提供 QUIC 配置标记，不能单独定性）',
        'Health.CheckedAt ' + Snapshot.Health.CheckedAt,
        'Overview.SampledAt ' + Snapshot.SampledAt,
    ];
    if (Ingresses !== null) {
        Evidence.push(Ingresses.HasMore
            ? '入口范围：已载入 ' + Ingresses.Items.length + ' 条，仍有未载入记录'
            : '入口范围：完整返回 ' + Ingresses.Items.length + ' 条配置');
    } else {
        Evidence.push('入口范围：当前查询未提供');
    }
    return Evidence;
}

function TransportPath(
    Ingresses: CursorPage<IngressRecord> | null,
    Transport: string,
): string {
    const Row = Ingresses?.Items.find(Value => Value.Transport.toLowerCase() === Transport.toLowerCase());
    return Row ? '/ingresses?ingress=' + encodeURIComponent(Row.Id) : '/ingresses';
}

function MakeAvailability(
    State: OverviewAvailabilityState,
    Code: OverviewAvailabilityCode,
    Title: string,
    Detail: string,
    Evidence: readonly string[],
    NextPath = '/ingresses',
): OverviewDecision['Availability'] {
    const NextLabel = State === 'normal' ? '查看入口范围'
        : NextPath === '/events' ? '查看近期事件'
        : NextPath === '/operations' ? '查看操作状态'
        : NextPath === '/configuration' ? '核对配置'
        : '核对入口状态';
    return { State, Code, Title, Detail, Evidence, NextPath, NextLabel };
}

function DecideObservation(Input: OverviewDecisionInput): OverviewDecision['Observation'] {
    const Reasons: string[] = [];
    if (Input.Queries.Events === 'success' && Input.Events?.Lost) {
        Reasons.push('事件缓冲报告了记录覆盖');
    }

    const HasCurrentObservationSnapshot =
        Input.Queries.Overview === 'success' && Input.Snapshot !== null;
    if (HasCurrentObservationSnapshot) {
        if (IsPositive(Input.Snapshot.Observations.Dropped)) {
            Reasons.push('累计观测丢弃 ' + Input.Snapshot.Observations.Dropped);
        }
        if (IsPositive(Input.Snapshot.Observations.AggregationFailures)) {
            Reasons.push('累计聚合失败 ' + Input.Snapshot.Observations.AggregationFailures);
        }
    }
    if (Reasons.length > 0) {
        return { State: 'gaps', Detail: Reasons.join('；') + '；这限制诊断证据，不改变接入 readiness。' };
    }

    if (Input.Queries.Events === 'pending') {
        return { State: 'pending', Detail: '事件窗口正在载入；接入 readiness 独立判定。' };
    }
    if (Input.Queries.Events === 'error' || Input.Events === null || !HasCurrentObservationSnapshot) {
        return { State: 'unavailable', Detail: '事件或观测摘要暂不可用；接入 readiness 独立判定。' };
    }
    return {
        State: 'reported',
        Detail: '当前事件响应未报告缓冲覆盖；累计观测丢弃与聚合失败均为 0。',
    };
}

function IsPositive(Value: UInt64Value): boolean {
    try {
        return BigInt(Value) > 0n;
    } catch {
        return true;
    }
}
