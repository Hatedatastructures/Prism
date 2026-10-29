import type { SessionRecord } from '../../Services/AdminDataSource';

export type RecentSessionObservation = Readonly<{ Session: SessionRecord; LastObservedAt: number }>;

export type SessionSnapshotLedger = Readonly<{
    SourceScope: string;
    FilterScope: string;
    Current: readonly SessionRecord[];
    Recent: readonly RecentSessionObservation[];
}>;

type ReconcileSessionSnapshotInput = Readonly<{
    Previous: SessionSnapshotLedger | null;
    Current: readonly SessionRecord[];
    SourceScope: string;
    FilterScope: string;
    SampledAt: number;
    RetentionMs: number;
    Limit: number;
}>;

function SessionKey(Value: SessionRecord): string {
    return [Value.ProcessId, Value.GenerationId, Value.WorkerId, Value.AccountId, Value.Id].join('\u001f');
}

export function ReconcileSessionSnapshot(Input: ReconcileSessionSnapshotInput): SessionSnapshotLedger {
    const Previous = Input.Previous;
    if (!Previous || Previous.SourceScope !== Input.SourceScope || Previous.FilterScope !== Input.FilterScope) return {
        SourceScope: Input.SourceScope,
        FilterScope: Input.FilterScope,
        Current: Input.Current,
        Recent: [],
    };

    const CurrentKeys = new Set(Input.Current.map(SessionKey));
    const Recent = new Map<string, RecentSessionObservation>();
    const RetentionMs = Math.max(0, Input.RetentionMs);
    for (const Observation of Previous.Recent) {
        const Age = Input.SampledAt - Observation.LastObservedAt;
        const Key = SessionKey(Observation.Session);
        if (!CurrentKeys.has(Key) && Age <= RetentionMs) Recent.set(Key, Observation);
    }

    for (const Session of Previous.Current) {
        const Key = SessionKey(Session);
        if (!CurrentKeys.has(Key)) Recent.set(Key, { Session, LastObservedAt: Input.SampledAt });
    }

    return {
        SourceScope: Input.SourceScope,
        FilterScope: Input.FilterScope,
        Current: Input.Current,
        Recent: [...Recent.values()].sort((Left, Right) => Right.LastObservedAt - Left.LastObservedAt)
            .slice(0, Math.max(0, Input.Limit)),
    };
}
