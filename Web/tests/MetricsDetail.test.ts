import assert from 'node:assert/strict';
import test from 'node:test';
import { DecodeMetrics } from '../src/Api/MetricsDecoder.ts';
import { ReadMetricsDetail } from '../src/Features/Resources/ReadMetricsDetail.ts';
import { AppendLatencyPoint } from '../src/Features/Resources/MetricsLatencyHistory.ts';
import { LiveAdminDataSource } from '../src/Services/LiveAdminDataSource.ts';

const Traffic = { up_bytes: '0', down_bytes: '0', events: '0', errors: '0' };
const Identity = { ApiVersion: '2', InstanceKey: 'instance', ProcessId: '42', Incarnation: 'a'.repeat(32), Capabilities: ['metrics.read'] };
function Wire() {
    return { process: '42', generation: '6', checked_at: '2026-10-28T00:00:00Z', traffic: Traffic,
        observations: { accepted: '18446744073709551615', consumed: '8', dropped: '2', aggregation_failures: '1',
            recognition_latency_queue_dropped: '1', recognition_latency_aggregation_failures: '1', retirement_failures: { session: '3', stream: '2', task: '1' } },
        sample_interval_ms: '1000', history_ready: false, history: [], recognition_latency: { sample_boundary: 'recognition_admission', unit: 'microseconds',
            generation: '6', ready: true, sample_count: '10', tracer_written: '9', tracer_dropped: '1', histogram_range_exceeded: '0',
            recent_us: ['55', '0'], p50_bucket_lower_bound_us: '0', p95_bucket_lower_bound_us: '32', p99_bucket_lower_bound_us: '32', max_observed_us: '70' } };
}

test('解码真实微秒样本、零值与完整 uint64 计数，不改变范围', () => {
    const Result = DecodeMetrics(Wire());
    assert.equal(Result.Observations.Accepted, '18446744073709551615');
    assert.equal(Result.Observations.RecognitionLatencyQueueDrops, '1');
    assert.deepEqual(Result.RecognitionLatency.RecentUs, ['55', '0']);
    assert.equal(Result.RecognitionLatency.P50Us, '0');
    assert.equal(Result.RetirementFailures.Sessions, '3');
});

test('无样本保持 null；错误代次、排序与不安全数值会拒绝', () => {
    const Empty = Wire();
    Empty.recognition_latency = { ...Empty.recognition_latency, ready: false, sample_count: '0', tracer_written: '0', tracer_dropped: '0', histogram_range_exceeded: '0',
        recent_us: [], p50_bucket_lower_bound_us: null as unknown as string, p95_bucket_lower_bound_us: null as unknown as string,
        p99_bucket_lower_bound_us: null as unknown as string, max_observed_us: null as unknown as string };
    assert.equal(DecodeMetrics(Empty).RecognitionLatency.P50Us, null);
    const Bad = Wire(); Bad.recognition_latency.generation = '7';
    assert.throws(() => DecodeMetrics(Bad), /代次/);
    Bad.recognition_latency.generation = '6'; Bad.recognition_latency.p95_bucket_lower_bound_us = '60';
    assert.throws(() => DecodeMetrics(Bad), /分布/);
    const Unsafe = Wire(); Unsafe.observations.accepted = 9007199254740992 as unknown as string;
    assert.throws(() => DecodeMetrics(Unsafe), /64 位/);
});

test('读取前后实例不同或能力缺失时不返回指标', async () => {
    let Calls = 0;
    const Metrics = DecodeMetrics(Wire());
    await assert.rejects(ReadMetricsDetail({ GetBootstrap: async () => ++Calls === 1 ? Identity : { ...Identity, Incarnation: 'b'.repeat(32) }, GetMetrics: async () => Metrics }), /实例已变化/);
    await assert.rejects(ReadMetricsDetail({ GetBootstrap: async () => ({ ...Identity, Capabilities: [] }), GetMetrics: async () => { throw new Error('unexpected'); } }), /metrics.read/);
});

test('微秒曲线只连接同实例的实际分位值，断线和代次变化保留边界', () => {
    const First = DecodeMetrics(Wire());
    const Second = { ...First, CheckedAt: '2026-10-28T00:00:05Z' };
    const Initial = AppendLatencyPoint(null, 'instance:6', First, false);
    assert.equal(Initial?.Points[0]?.P95, 32);
    const Interrupted = AppendLatencyPoint(Initial, 'instance:6', Second, true);
    assert.equal(Interrupted?.Points.length, 3);
    assert.equal(Interrupted?.Points[1]?.P95, null);
    assert.equal(Interrupted?.Points[2]?.P95, 32);
    assert.equal(AppendLatencyPoint(Interrupted, 'instance:6', Second, false), Interrupted);
    const NextGeneration = AppendLatencyPoint(Interrupted, 'instance:7', Second, false);
    assert.equal(NextGeneration?.Samples, 1);
    assert.equal(NextGeneration?.Points.length, 1);
    const Unsafe = { ...Second, CheckedAt: '2026-10-28T00:00:10Z', RecognitionLatency: { ...Second.RecognitionLatency, P95Us: '18446744073709551615' } };
    assert.equal(AppendLatencyPoint(NextGeneration, 'instance:7', Unsafe, false)?.Points[1]?.P95, null);
});

test('真实数据源走 Metrics 路由，保留服务端不支持和不可用错误', async () => {
    const Paths: string[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        Paths.push(String(Path));
        return String(Path).endsWith('Bootstrap') ? Response.json({ api_version: '2', instance_key: 'instance', process_id: '42',
            process_incarnation: 'a'.repeat(32), command_token: 'b'.repeat(64), capabilities: ['metrics.read'] }) : Response.json({ status: 'ok', value: Wire() });
    } });
    assert.equal((await Source.GetMetrics()).RecognitionLatency.P95Us, '32');
    assert.equal(Paths.at(-1), '/Operations/Metrics');
    const Unavailable = new LiveAdminDataSource({ Fetch: async Path => String(Path).endsWith('Bootstrap')
        ? Response.json({ api_version: '2', instance_key: 'instance', process_id: '42', process_incarnation: 'a'.repeat(32), command_token: 'b'.repeat(64), capabilities: ['metrics.read'] })
        : Response.json({ status: 'unavailable', message: 'handler_unavailable' }) });
    await assert.rejects(Unavailable.GetMetrics(), /handler_unavailable/);
});
