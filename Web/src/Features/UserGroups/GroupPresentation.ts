export type LoadedMetricSummary = Readonly<{
    State: 'empty' | 'unavailable' | 'partial' | 'complete';
    Total: string | null;
    Known: number;
    Count: number;
}>;

export function SummarizeLoadedMetric(Values: readonly (string | number | null)[]): LoadedMetricSummary {
    const KnownValues = Values.filter((Value): Value is string | number => Value !== null);
    if (Values.length === 0) return { State: 'empty', Total: null, Known: 0, Count: 0 };
    if (KnownValues.length === 0) return { State: 'unavailable', Total: null, Known: 0, Count: Values.length };
    if (KnownValues.length < Values.length) {
        return { State: 'partial', Total: null, Known: KnownValues.length, Count: Values.length };
    }
    const Total = KnownValues.reduce<bigint>((Sum, Value) => Sum + BigInt(Value), 0n).toString();
    return { State: 'complete', Total, Known: KnownValues.length, Count: Values.length };
}

export type GroupTarget = Readonly<{
    Id: string;
    Unassigned: boolean;
    MissingFromLoadedGroups: boolean;
}>;

export function ResolveGroupTarget(
    AvailableIds: readonly string[],
    RequestedId: string | null,
    DefaultId: string | null,
): GroupTarget {
    const TargetId = RequestedId?.trim() ? RequestedId : DefaultId ?? '__unassigned__';
    const Unassigned = TargetId === '__unassigned__';
    return {
        Id: TargetId,
        Unassigned,
        MissingFromLoadedGroups: !Unassigned && !AvailableIds.includes(TargetId),
    };
}

export type AccountReadStatus = 'loading' | 'error' | 'stale' | 'ready' | 'unknown';

export function ResolveAccountReadStatus(Input: Readonly<{
    HasData: boolean;
    Pending: boolean;
    Failed: boolean;
}>): AccountReadStatus {
    if (Input.HasData) return Input.Failed ? 'stale' : 'ready';
    if (Input.Pending) return 'loading';
    if (Input.Failed) return 'error';
    return 'unknown';
}
