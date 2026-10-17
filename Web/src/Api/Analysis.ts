import type { HistoryPoint, ProtocolRecord, UInt64Value } from '../Services/AdminDataSource.ts';

export function CounterDelta(Current: UInt64Value | null, Previous: UInt64Value | null, ElapsedMs: number): number | null {
    if (Current === null || Previous === null || ElapsedMs <= 0 || !Number.isFinite(ElapsedMs)) return null;
    const Delta = BigInt(Current) - BigInt(Previous);
    return Delta < 0n ? null : Number(Delta) * 1000 / ElapsedMs;
}
export function Fraction(Numerator: UInt64Value | null, Denominator: UInt64Value | null): number | null {
    if (Numerator === null || Denominator === null || BigInt(Denominator) <= 0n) return null;
    return Number(BigInt(Numerator) * 10000n / BigInt(Denominator)) / 100;
}
/** @brief 精确指定目标未命中时保持空，不以另一资源替代。 */
export function SelectResource<Value extends Readonly<{ Id: string }>>(Rows: readonly Value[], Id: string): Value | null {
    return Id ? Rows.find(Row => Row.Id === Id) ?? null : Rows[0] ?? null;
}
export function ProtocolDistribution(Protocols: readonly ProtocolRecord[], Total: UInt64Value) {
    const HasKind = Protocols.some(Protocol => Protocol.Kind !== undefined);
    const Candidates = HasKind ? Protocols.filter(Protocol => Protocol.Kind === 'type') : Protocols;
    const Names = new Set<string>();
    const Rows: { Id: string; Name: string; Count: string; Percent: number | null }[] = [];
    for (const Protocol of Candidates) {
        const Key = Protocol.TypeKey ?? Protocol.Name.toLowerCase();
        if (Names.has(Key) || Protocol.ActiveSessions === null) continue;
        Names.add(Key);
        Rows.push({ Id: Protocol.Id, Name: Protocol.Name, Count: String(Protocol.ActiveSessions), Percent: Fraction(Protocol.ActiveSessions, Total) });
    }
    const Known = Rows.reduce((Sum, Row) => Sum + BigInt(Row.Count), 0n);
    const Unknown = BigInt(Total) - Known;
    if (Unknown > 0n) Rows.push({ Id: 'unattributed', Name: '未识别 / 未归属', Count: Unknown.toString(), Percent: Fraction(Unknown.toString(), Total) });
    return { Rows: Rows.sort((A, B) => BigInt(A.Count) > BigInt(B.Count) ? -1 : BigInt(A.Count) < BigInt(B.Count) ? 1 : 0),
        Available: !HasKind || Candidates.length > 0, Complete: Known <= BigInt(Total), DuplicateTypes: Candidates.filter(Protocol => Protocol.ActiveSessions !== null).length > Names.size };
}
export function HistoryChartPoints(Items: readonly HistoryPoint[], ResolutionMs: string, Gaps: readonly Readonly<{ From: string; To: string; Reason: string }>[] = []) {
    const Seconds = Number(ResolutionMs) / 1000;
    const Points = Items.map(Item => ({ Time: Date.parse(Item.Time), Up: Item.UpBytes === null || Seconds <= 0 ? null : Number(BigInt(Item.UpBytes)) / Seconds,
        Down: Item.DownBytes === null || Seconds <= 0 ? null : Number(BigInt(Item.DownBytes)) / Seconds,
        P50: Item.P50Us === null ? null : Number(BigInt(Item.P50Us)) / 1000,
        P95: Item.P95Us === null ? null : Number(BigInt(Item.P95Us)) / 1000,
        P99: Item.P99Us === null ? null : Number(BigInt(Item.P99Us)) / 1000,
        Samples: Item.SampleCount, Active: Item.Active === null ? null : Number(BigInt(Item.Active)) })).sort((Left, Right) => Left.Time - Right.Time);
    const Intervals = Gaps.map(Gap => ({ From: Date.parse(Gap.From), To: Date.parse(Gap.To) }));
    const EmptyPoint = (Time: number): typeof Points[number] => ({ Time, Up: null, Down: null, P50: null, P95: null, P99: null, Active: null, Samples: '0' });
    const Result: typeof Points = [];
    for (const Point of Points) {
        const Previous = Result[Result.length - 1];
        if (Previous && Point.Time > Previous.Time) {
            const Gap = Intervals.find(Interval => Interval.From < Point.Time && Interval.To > Previous.Time);
            if (Gap) {
                const Start = Math.max(Previous.Time, Gap.From), End = Math.min(Point.Time, Gap.To);
                Result.push(EmptyPoint(Start + (End - Start) / 2));
            } else if (Seconds > 0 && Point.Time - Previous.Time > Number(ResolutionMs)) {
                Result.push(EmptyPoint(Previous.Time + Number(ResolutionMs)));
            }
        }
        Result.push(Intervals.some(Gap => Point.Time >= Gap.From && Point.Time < Gap.To) ? EmptyPoint(Point.Time) : Point);
    }
    return Result;
}
