import assert from 'node:assert/strict';
import test from 'node:test';
import type { SessionRecord } from '../src/Services/AdminDataSource.ts';
import { ReconcileSessionSnapshot, type SessionSnapshotLedger } from '../src/Features/Sessions/SessionSnapshotLedger.ts';

function Session(Id: string): SessionRecord {
    return { Id, ProcessId: 'process-1', WorkerId: 'worker-1', AccountId: 'account-1', GenerationId: 'generation-1',
        Traffic: null, StartedAt: '2026-10-23T10:00:00.000Z', Identity: 'account-1', SourceAddress: '192.0.2.1:8000',
        Transport: 'tcp', Protocol: 'vless', Target: '198.51.100.2:443', Active: true, Draining: false,
        ActiveTasks: null, Streams: [], Tasks: [] };
}

function Snapshot(Previous: SessionSnapshotLedger | null, Current: readonly SessionRecord[], At: number, FilterScope = 'all') {
    return ReconcileSessionSnapshot({ Previous, Current, SourceScope: 'live:process-1', FilterScope,
        SampledAt: At, RetentionMs: 300_000, Limit: 20 });
}

test('first Session snapshot establishes a baseline without claiming older connections ended', () => {
    const Result = Snapshot(null, [Session('session-1')], 1_000);
    assert.deepEqual(Result.Recent, []);
    assert.deepEqual(Result.Current.map(Value => Value.Id), ['session-1']);
});

test('a Session absent from the next same-scope sample is retained with its last observation time', () => {
    const First = Snapshot(null, [Session('session-1'), Session('session-2')], 1_000);
    const Next = Snapshot(First, [Session('session-2')], 6_000);
    assert.deepEqual(Next.Recent.map(Observation => [Observation.Session.Id, Observation.LastObservedAt]), [['session-1', 6_000]]);
});

test('filter changes clear old page observations and do not turn the new scope into Session exits', () => {
    const First = Snapshot(null, [Session('session-1')], 1_000);
    const Left = Snapshot(First, [], 6_000);
    const Filtered = Snapshot(Left, [Session('session-2')], 7_000, 'worker-2');
    assert.deepEqual(Filtered.Recent, []);
    assert.deepEqual(Filtered.Current.map(Value => Value.Id), ['session-2']);
});

test('reappearing Sessions leave the recent-observation list and old entries expire', () => {
    const First = Snapshot(null, [Session('session-1')], 1_000);
    const Left = Snapshot(First, [], 6_000);
    const Returned = Snapshot(Left, [Session('session-1')], 7_000);
    assert.deepEqual(Returned.Recent, []);
    const Expired = ReconcileSessionSnapshot({ Previous: Left, Current: [], SourceScope: 'live:process-1', FilterScope: 'all',
        SampledAt: 400_001, RetentionMs: 300_000, Limit: 20 });
    assert.deepEqual(Expired.Recent, []);
});

test('switching process scope clears recent observations instead of mixing instances', () => {
    const First = Snapshot(null, [Session('session-1')], 1_000);
    const Next = ReconcileSessionSnapshot({ Previous: First, Current: [], SourceScope: 'live:process-2', FilterScope: 'all',
        SampledAt: 6_000, RetentionMs: 300_000, Limit: 20 });
    assert.deepEqual(Next.Recent, []);
    assert.equal(Next.SourceScope, 'live:process-2');
});
