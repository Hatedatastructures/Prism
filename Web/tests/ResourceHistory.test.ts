import assert from 'node:assert/strict';
import test from 'node:test';
import { DemoAdminDataSource } from '../src/Services/DemoAdminDataSource.ts';
import type { BootstrapSnapshot, OverviewSnapshot } from '../src/Services/AdminDataSource.ts';
import { AppendResourceSample, ReadResourceSample } from '../src/Features/Resources/ResourceHistory.ts';

async function Snapshot(): Promise<OverviewSnapshot> { return new DemoAdminDataSource().GetOverview(); }
function WithCounters(Value: OverviewSnapshot, Time: string, Allocated: string, Released: string): OverviewSnapshot {
    return { ...Value, SampledAt: Time, Memory: { ...Value.Memory, Allocations: { ...Value.Memory.Allocations, AllocationCount: Allocated, ReleaseCount: Released } } };
}

test('相邻同实例快照先用 bigint 差分，再按真实时间间隔计算每秒次数', async () => {
    const Value = await Snapshot();
    const First = AppendResourceSample(null, 'instance-a', WithCounters(Value, '2026-10-28T00:00:00Z', '18446744073709550615', '100'), false);
    const Next = AppendResourceSample(First, 'instance-a', WithCounters(Value, '2026-10-28T00:00:02Z', '18446744073709551615', '150'), false);
    assert.equal(Next?.Points[1]?.PmrAllocateRate, 500);
    assert.equal(Next?.Points[1]?.PmrReleaseRate, 25);
    assert.equal(Next?.Points[0]?.PmrAllocateRate, null);
});

test('重置、断线、时间倒退和实例变化都不会连接错误的速率', async () => {
    const Value = await Snapshot();
    const First = AppendResourceSample(null, 'a', WithCounters(Value, '2026-10-28T00:00:00Z', '100', '90'), false);
    const Reset = AppendResourceSample(First, 'a', WithCounters(Value, '2026-10-28T00:00:05Z', '1', '2'), false);
    assert.equal(Reset?.Points.at(-1)?.PmrAllocateRate, null);
    const Gap = AppendResourceSample(Reset, 'a', WithCounters(Value, '2026-10-28T00:00:10Z', '11', '12'), true);
    assert.equal(Gap?.Points.at(-2)?.PmrBytes, null);
    assert.equal(Gap?.Points.at(-1)?.PmrAllocateRate, null);
    const NewScope = AppendResourceSample(Gap, 'b', WithCounters(Value, '2026-10-28T00:00:15Z', '20', '20'), false);
    assert.equal(NewScope?.Samples.length, 1);
    const Earlier = AppendResourceSample(NewScope, 'b', WithCounters(Value, '2026-10-28T00:00:01Z', '30', '30'), false);
    assert.equal(Earlier?.Samples.length, 1);
});

test('未采集的内存或延迟不显示为零', async () => {
    const Value = await Snapshot();
    const Missing: OverviewSnapshot = { ...Value, Memory: { ...Value.Memory, ProcessAvailable: false, Allocations: { ...Value.Memory.Allocations, Available: false } },
        Latency: { ...Value.Latency, RecognitionAdmission: { ...Value.Latency.RecognitionAdmission, Available: false } } };
    const Point = AppendResourceSample(null, 'a', Missing, false)?.Points[0];
    assert.equal(Point?.PmrBytes, null);
    assert.equal(Point?.RssBytes, null);
    assert.equal(Point?.P95Ms, null);
});

test('采样两端实例不一致时拒绝快照', async () => {
    const Source = new DemoAdminDataSource();
    const Identity = await Source.GetBootstrap();
    const Value = await Source.GetOverview();
    let Calls = 0;
    const IdentityAtCall = (): Promise<BootstrapSnapshot> => Promise.resolve({ ...Identity, Incarnation: ++Calls === 1 ? 'old' : 'new' });
    await assert.rejects(ReadResourceSample({ GetBootstrap: IdentityAtCall, GetOverview: async () => Value }), /实例已变化/);
});
