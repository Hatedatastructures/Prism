import type { AdminDataSource, BootstrapSnapshot, OverviewSnapshot, UInt64Value } from '../../Services/AdminDataSource.ts';

export type ResourcePoint = Readonly<{
    Time: number; PmrBytes: number | null; PoolBytes: number | null; RssBytes: number | null;
    PmrAllocateRate: number | null; PmrReleaseRate: number | null; PoolAllocateRate: number | null; PoolReleaseRate: number | null;
    P50Ms: number | null; P95Ms: number | null; P99Ms: number | null;
}>;
export type ResourceHistory = Readonly<{ Scope: string; Samples: readonly OverviewSnapshot[]; Points: readonly ResourcePoint[] }>;

/** @brief 采样前后核对进程实例，防止重启后同号进程的两个快照被连成一条曲线。 */
export async function ReadResourceSample(Source: Pick<AdminDataSource, 'GetBootstrap' | 'GetOverview'>): Promise<Readonly<{ Snapshot: OverviewSnapshot; Identity: BootstrapSnapshot }>> {
    const Before = await Source.GetBootstrap({ Fresh: true });
    const Snapshot = await Source.GetOverview();
    const After = await Source.GetBootstrap({ Fresh: true });
    if (Before.InstanceKey !== After.InstanceKey || Before.ProcessId !== After.ProcessId || Before.Incarnation !== After.Incarnation || Snapshot.Process.Id !== After.ProcessId)
        throw new Error('资源快照采样期间实例已变化，请重新读取');
    return { Snapshot, Identity: After };
}

function Numeric(Available: boolean, Value: UInt64Value | null): number | null {
    if (!Available || Value === null) return null;
    const NumberValue = Number(Value);
    return Number.isFinite(NumberValue) && NumberValue >= 0 ? NumberValue : null;
}

function Rate(Current: UInt64Value | null, Previous: UInt64Value | null, Milliseconds: number): number | null {
    if (Current === null || Previous === null || Milliseconds <= 0) return null;
    const Difference = BigInt(Current) - BigInt(Previous);
    if (Difference < 0n) return null;
    const Result = Number(Difference) * 1000 / Milliseconds;
    return Number.isFinite(Result) ? Result : null;
}

function Blank(Time: number): ResourcePoint {
    return { Time, PmrBytes: null, PoolBytes: null, RssBytes: null, PmrAllocateRate: null, PmrReleaseRate: null,
        PoolAllocateRate: null, PoolReleaseRate: null, P50Ms: null, P95Ms: null, P99Ms: null };
}

/** @brief 只连接同一实例和代次的成功快照；断线、计数回退和无效时间保留缺口。 */
export function AppendResourceSample(Previous: ResourceHistory | null, Scope: string, Snapshot: OverviewSnapshot, Gap: boolean): ResourceHistory | null {
    const Time = Date.parse(Snapshot.SampledAt);
    if (!Number.isFinite(Time)) return Previous;
    const SameScope = Previous?.Scope === Scope;
    const PreviousSample = SameScope ? Previous.Samples.at(-1) : undefined;
    const PreviousTime = PreviousSample ? Date.parse(PreviousSample.SampledAt) : 0;
    if (PreviousSample && Time === PreviousTime) return Previous;
    const Reset = !SameScope || PreviousSample !== undefined && Time < PreviousTime;
    const Before = Reset ? undefined : PreviousSample;
    const Elapsed = Before ? Time - PreviousTime : 0;
    const Pmr = Snapshot.Memory.Allocations, Pool = Snapshot.Memory.BytePool, Latency = Snapshot.Latency.RecognitionAdmission;
    const PreviousPmr = Before?.Memory.Allocations, PreviousPool = Before?.Memory.BytePool;
    const Interrupted = Gap || Elapsed > 15_000;
    const Point: ResourcePoint = { Time, PmrBytes: Numeric(Pmr.Available, Pmr.CurrentBytes),
        PoolBytes: Numeric(Pool.Available, Pool.UsedBytes), RssBytes: Numeric(Snapshot.Memory.ProcessAvailable, Snapshot.Memory.ProcessRssBytes),
        PmrAllocateRate: !Interrupted && Pmr.Available && PreviousPmr?.Available ? Rate(Pmr.AllocationCount, PreviousPmr.AllocationCount, Elapsed) : null,
        PmrReleaseRate: !Interrupted && Pmr.Available && PreviousPmr?.Available ? Rate(Pmr.ReleaseCount, PreviousPmr.ReleaseCount, Elapsed) : null,
        PoolAllocateRate: !Interrupted && Pool.Available && PreviousPool?.Available ? Rate(Pool.AllocationCount, PreviousPool.AllocationCount, Elapsed) : null,
        PoolReleaseRate: !Interrupted && Pool.Available && PreviousPool?.Available ? Rate(Pool.ReleaseCount, PreviousPool.ReleaseCount, Elapsed) : null,
        P50Ms: Numeric(Latency.Available, Latency.P50Ms), P95Ms: Numeric(Latency.Available, Latency.P95Ms), P99Ms: Numeric(Latency.Available, Latency.P99Ms) };
    const Points = Reset ? [] : [...(Previous?.Points ?? [])];
    if (Interrupted && Before && Time > PreviousTime) Points.push(Blank(PreviousTime + (Time - PreviousTime) / 2));
    Points.push(Point);
    return { Scope, Samples: [...(Reset ? [] : Previous?.Samples ?? []), Snapshot].slice(-60), Points: Points.slice(-120) };
}
