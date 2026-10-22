import assert from 'node:assert/strict';
import test from 'node:test';
import type { WorkerRecord } from '../src/Services/AdminDataSource.ts';
import { FilterOverviewWorkers } from '../src/Features/Overview/OverviewFleet.ts';

function Worker(Id: string, Name: string, State: string, Health: string): WorkerRecord {
    return {
        Id, Name, State, Health, ProcessId: '42', GenerationId: '7',
        Running: true, Accepting: State === 'running', ActiveTasks: '2', DroppedEvents: '0', Traffic: null,
        QueueDepth: '3', QueueCapacity: '9', StartedTasks: '2', CompletedTasks: '1',
        CancelledTasks: '0', DispatchAccepted: '2', DispatchFull: '0', DispatchClosed: '0',
        DispatchUnavailable: '0', DispatchGenerationRejected: '0', CommandsExecuted: '0', CommandsFailed: '0',
    };
}

const Workers = [
    Worker('worker-01', 'worker-01', 'running', 'healthy'),
    Worker('worker-02', 'edge-relay', 'draining', 'degraded'),
    Worker('worker-03', 'worker-03', 'offline', 'unknown'),
];

test('overview worker search matches identity and reported state without mutating the snapshot', () => {
    assert.deepEqual(FilterOverviewWorkers(Workers, 'edge'), [Workers[1]]);
    assert.deepEqual(FilterOverviewWorkers(Workers, 'DRAINING'), [Workers[1]]);
    assert.deepEqual(FilterOverviewWorkers(Workers, 'unknown'), [Workers[2]]);
    assert.equal(FilterOverviewWorkers(Workers, 'worker-03')[0], Workers[2]);
    assert.equal(Workers.length, 3);
});

test('overview worker search treats blank input as the full loaded range', () => {
    assert.equal(FilterOverviewWorkers(Workers, ''), Workers);
    assert.equal(FilterOverviewWorkers(Workers, '   '), Workers);
    assert.deepEqual(FilterOverviewWorkers(Workers, 'missing'), []);
});
