import assert from 'node:assert/strict';
import test from 'node:test';
import type { CursorPage, EventPage, IngressRecord, OverviewSnapshot } from '../src/Services/AdminDataSource.ts';
import { DecideOverview } from '../src/Features/Overview/OverviewDecision.ts';
import { DecideIngressRowPresentation } from '../src/Features/Ingresses/IngressPresentation.ts';

const Now = Date.parse('2026-10-17T06:00:00.000Z');
const FreshSample = new Date(Now - 5_000).toISOString();

type SnapshotOptions = Readonly<{
    SampledAt?: string;
    Phase?: string;
    HealthStatus?: OverviewSnapshot['Health']['Status'];
    Ready?: boolean;
    TcpReady?: boolean;
    UdpReady?: boolean;
    UdpSocketReady?: boolean;
    QuicReady?: boolean;
    QuicSocketReady?: boolean;
    QuicHandshakeReady?: boolean;
    QuicProtocolReady?: boolean;
    Dropped?: string;
    AggregationFailures?: string;
}>;

function Snapshot(Options: SnapshotOptions = {}): OverviewSnapshot {
    return {
        SampledAt: Options.SampledAt ?? FreshSample,
        Process: { Id: '1', GenerationId: '2', Phase: Options.Phase ?? 'ready' },
        Health: {
            Status: Options.HealthStatus ?? 'healthy',
            CheckedAt: FreshSample,
            Active: '0',
            Errors: '0',
            Ready: Options.Ready ?? true,
            TcpReady: Options.TcpReady ?? true,
            UdpReady: Options.UdpReady ?? true,
            UdpSocketReady: Options.UdpSocketReady ?? true,
            QuicReady: Options.QuicReady ?? false,
            QuicSocketReady: Options.QuicSocketReady ?? false,
            QuicHandshakeReady: Options.QuicHandshakeReady ?? false,
            QuicProtocolReady: Options.QuicProtocolReady ?? false,
            RetirementFailures: { Sessions: '0', Streams: '0', Tasks: '0' },
        },
        Observations: {
            Accepted: '0',
            Consumed: '0',
            Dropped: Options.Dropped ?? '0',
            AggregationFailures: Options.AggregationFailures ?? '0',
        },
    } as unknown as OverviewSnapshot;
}

function Ingress(Transport: string, Ready: boolean, Id: string): IngressRecord {
    return {
        Id,
        Transport,
        ConfiguredAddress: '127.0.0.1:1080',
        BoundAddress: Ready ? '127.0.0.1:1080' : null,
        Ready,
        ActiveConnections: null,
        Protocols: [],
        Carriers: [],
    };
}

function IngressPage(Rows: readonly IngressRecord[], HasMore = false): CursorPage<IngressRecord> {
    return { Items: Rows, NextCursor: HasMore ? '50' : '0', HasMore };
}

function EventPage(Lost = false): EventPage {
    return {
        Items: [],
        NextCursor: '0',
        HasMore: false,
        EarliestCursor: '0',
        Lost,
        LostRanges: [],
        Dropped: '0',
        TerminalDropped: '0',
        Overwritten: '0',
        SeverityFilterSupported: true,
    };
}

type InputOverrides = Readonly<{
    Snapshot?: OverviewSnapshot | null;
    Ingresses?: CursorPage<IngressRecord> | null;
    Events?: EventPage | null;
    Queries?: Readonly<{
        Overview?: 'success' | 'pending' | 'error';
        Ingresses?: 'success' | 'pending' | 'error';
        Events?: 'success' | 'pending' | 'error';
    }>;
    NowMs?: number;
}>;

function Decide(Overrides: InputOverrides = {}) {
    return DecideOverview({
        NowMs: Overrides.NowMs ?? Now,
        Snapshot: Overrides.Snapshot === undefined ? Snapshot() : Overrides.Snapshot,
        Ingresses: Overrides.Ingresses === undefined ? IngressPage([Ingress('tcp', true, 'tcp-0')]) : Overrides.Ingresses,
        Events: Overrides.Events === undefined ? EventPage() : Overrides.Events,
        Queries: {
            Overview: Overrides.Queries?.Overview ?? 'success',
            Ingresses: Overrides.Queries?.Ingresses ?? 'success',
            Events: Overrides.Queries?.Events ?? 'success',
        },
    });
}

test('later ingress rows do not turn schema placeholders into unready socket claims', () => {
    const Presentation = DecideIngressRowPresentation(Ingress('tcp', false, 'tcp-1'), false);
    assert.equal(Presentation.Label, '未单独观测');
    assert.equal(Presentation.Tone, 'neutral');
    assert.equal(Presentation.Binding, '绑定状态未单独采集');
});

test('the first ingress row reports its readiness value without inventing a cause', () => {
    const Presentation = DecideIngressRowPresentation(Ingress('tcp', false, 'tcp-0'), true);
    assert.equal(Presentation.Label, '运行态报告未就绪');
    assert.equal(Presentation.Tone, 'neutral');
    assert.equal(Presentation.Binding, '当前无绑定地址');
});

test('unconfigured QUIC readiness false does not negate a healthy fresh overall readiness', () => {
    const Value = Decide({ Snapshot: Snapshot({ QuicReady: false }) });
    assert.equal(Value.Availability.State, 'normal');
    assert.equal(Value.Observation.State, 'reported');
});

test('ready aggregate with degraded status stays limited as contradictory evidence', () => {
    const Value = Decide({ Snapshot: Snapshot({ HealthStatus: 'degraded', QuicReady: false }) });
    assert.equal(Value.Availability.State, 'limited');
    assert.equal(Value.Availability.Code, 'health-conflict');
    assert.equal(Value.Availability.Title, '运行状态需核对');
    assert.match(Value.Availability.Detail, /就绪信号相互矛盾/);
    assert.ok(Value.Availability.Evidence.some(Evidence => Evidence === 'Health.Status degraded'));
});

test('an extra configured ingress row with Ready=false is not treated as a socket failure', () => {
    const Value = Decide({
        Ingresses: IngressPage([
            Ingress('tcp', true, 'tcp-0'),
            Ingress('tcp', false, 'tcp-1'),
        ]),
    });
    assert.equal(Value.Availability.State, 'normal');
    assert.equal(Value.Availability.Code, 'ready');
});

test('a configured UDP ingress that contradicts the ready aggregate requires verification', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Ready: true, UdpReady: false }),
        Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0'), Ingress('udp', false, 'udp-0')]),
    });
    assert.equal(Value.Availability.State, 'limited');
    assert.equal(Value.Availability.Code, 'health-conflict');
    assert.ok(Value.Availability.Evidence.some(Evidence => Evidence === 'UDP Health readiness false'));
});

test('a QUIC ingress row does not prove QUIC protocol configuration or negate ready aggregate', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Ready: true, QuicReady: false }),
        Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0'), Ingress('quic', false, 'quic-0')]),
    });
    assert.equal(Value.Availability.State, 'normal');
    assert.equal(Value.Availability.Code, 'ready');
    assert.ok(Value.Availability.Evidence.some(Evidence => /QUIC.*未提供 QUIC 配置标记/.test(Evidence)));
});

test('a ready aggregate that contradicts the mandatory TCP substatus stays limited', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Ready: true, TcpReady: false }),
    });
    assert.equal(Value.Availability.State, 'limited');
    assert.equal(Value.Availability.Code, 'health-conflict');
    assert.ok(Value.Availability.Evidence.some(Evidence => Evidence === 'TCP listener readiness false'));
});

test('a current ready-phase TCP listener failure reports the affected capability', () => {
    const Value = Decide({ Snapshot: Snapshot({ Ready: false, TcpReady: false, HealthStatus: 'unhealthy' }) });
    assert.equal(Value.Availability.State, 'affected');
    assert.equal(Value.Availability.Code, 'tcp-unready');
    assert.match(Value.Availability.Detail, /TCP/);
});

test('a current ready-phase UDP failure reports UDP when the configuration identifies it', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Ready: false, TcpReady: true, UdpReady: false, UdpSocketReady: false, HealthStatus: 'degraded' }),
        Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0'), Ingress('udp', false, 'udp-0')]),
    });
    assert.equal(Value.Availability.State, 'affected');
    assert.equal(Value.Availability.Code, 'udp-unready');
});

test('a fresh overall not-ready state stays affected when known TCP and UDP components are ready', () => {
    const Value = Decide({
        Snapshot: Snapshot({
            Ready: false,
            TcpReady: true,
            UdpReady: true,
            QuicReady: true,
            HealthStatus: 'degraded',
        }),
        Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0'), Ingress('udp', true, 'udp-0')]),
    });
    assert.equal(Value.Availability.State, 'affected');
    assert.equal(Value.Availability.Code, 'runtime-not-ready');
    assert.match(Value.Availability.Detail, /不能定位到具体传输或入口原因/);
});

test('an incomplete ingress scope does not hide a fresh overall not-ready state', () => {
    const Value = Decide({
        Snapshot: Snapshot({
            Ready: false,
            TcpReady: true,
            UdpReady: true,
            UdpSocketReady: true,
            QuicReady: false,
            HealthStatus: 'degraded',
        }),
        Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0')], true),
    });
    assert.equal(Value.Availability.State, 'affected');
    assert.equal(Value.Availability.Code, 'runtime-not-ready');
    assert.doesNotMatch(Value.Availability.Title + Value.Availability.Detail, /QUIC 接入未就绪/);
});

test('planned stopping is a drain state, not an ingress fault', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Phase: 'stopping', Ready: false, TcpReady: false, HealthStatus: 'draining' }),
    });
    assert.equal(Value.Availability.State, 'limited');
    assert.equal(Value.Availability.Code, 'planned-draining');
});

test('a failed process is reported as an affected runtime', () => {
    const Value = Decide({
        Snapshot: Snapshot({ Phase: 'failed', Ready: false, TcpReady: false, HealthStatus: 'unhealthy' }),
    });
    assert.equal(Value.Availability.State, 'affected');
    assert.equal(Value.Availability.Code, 'process-failed');
});

test('created and stopped phases do not claim current socket health', () => {
    for (const Phase of ['created', 'stopped']) {
        const Value = Decide({ Snapshot: Snapshot({ Phase, Ready: false }) });
        assert.equal(Value.Availability.State, 'limited');
        assert.equal(Value.Availability.Code, 'phase-unavailable');
    }
});

test('a stale or invalid sample cannot produce a ready judgment', () => {
    const Stale = Decide({ Snapshot: Snapshot({ SampledAt: new Date(Now - 20_001).toISOString() }) });
    assert.equal(Stale.Availability.State, 'limited');
    assert.equal(Stale.Availability.Code, 'snapshot-stale');

    const Invalid = Decide({ Snapshot: Snapshot({ SampledAt: 'not-a-time' }) });
    assert.equal(Invalid.Availability.State, 'limited');
    assert.equal(Invalid.Availability.Code, 'snapshot-invalid');
});

test('an overview query error overrides cached data for the current judgment', () => {
    const Value = Decide({ Queries: { Overview: 'error' } });
    assert.equal(Value.Availability.State, 'limited');
    assert.equal(Value.Availability.Code, 'overview-unavailable');
});

test('failed, empty, and partial ingress queries do not produce a full ready claim', () => {
    const Pending = Decide({ Queries: { Ingresses: 'pending' }, Ingresses: null });
    const Failed = Decide({ Queries: { Ingresses: 'error' } });
    const Empty = Decide({ Ingresses: IngressPage([]) });
    const Partial = Decide({ Ingresses: IngressPage([Ingress('tcp', true, 'tcp-0')], true) });
    for (const Value of [Pending, Failed, Empty, Partial]) {
        assert.equal(Value.Availability.State, 'limited');
    }
    assert.equal(Pending.Availability.Code, 'ingresses-pending');
    assert.equal(Failed.Availability.Code, 'ingresses-unavailable');
    assert.equal(Empty.Availability.Code, 'ingresses-empty');
    assert.equal(Partial.Availability.Code, 'ingresses-partial');
});

test('event-buffer loss lowers observation quality without changing fresh socket readiness', () => {
    const Value = Decide({ Events: EventPage(true) });
    assert.equal(Value.Availability.State, 'normal');
    assert.equal(Value.Observation.State, 'gaps');
    assert.match(Value.Observation.Detail, /事件/);
});

test('cumulative observation drops lower observation quality without changing readiness', () => {
    const Value = Decide({ Snapshot: Snapshot({ Dropped: '2', AggregationFailures: '1' }) });
    assert.equal(Value.Availability.State, 'normal');
    assert.equal(Value.Observation.State, 'gaps');
    assert.match(Value.Observation.Detail, /丢弃/);
    assert.match(Value.Observation.Detail, /聚合失败/);
});

test('event query loading and failure remain separate from socket readiness', () => {
    const Pending = Decide({ Queries: { Events: 'pending' }, Events: null });
    const Failed = Decide({ Queries: { Events: 'error' }, Events: null });
    assert.equal(Pending.Availability.State, 'normal');
    assert.equal(Pending.Observation.State, 'pending');
    assert.equal(Failed.Availability.State, 'normal');
    assert.equal(Failed.Observation.State, 'unavailable');
});
