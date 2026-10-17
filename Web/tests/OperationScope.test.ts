import assert from 'node:assert/strict';
import test from 'node:test';
import { OperationScopeChangedError, WorkerIdentityChangedError } from '../src/Services/AdminDataSource.ts';
import type { OperationScope, WorkerIdentity } from '../src/Services/AdminDataSource.ts';
import { LiveAdminDataSource } from '../src/Services/LiveAdminDataSource.ts';
import { DemoAdminDataSource } from '../src/Services/DemoAdminDataSource.ts';

const ProcessId = '7';
const IncarnationA = 'a'.repeat(32);
const IncarnationB = 'b'.repeat(32);
const ScopeA: OperationScope = { ProcessId, Incarnation: IncarnationA };

function Bootstrap(Incarnation: string) {
    return { api_version: '2', instance_key: 'prism-instance', process_id: ProcessId,
        process_incarnation: Incarnation, command_token: 'c'.repeat(64), capabilities: ['operations.read', 'workers.drain', 'workers.filter'] };
}

function WorkerRecord(Identity: WorkerIdentity) {
    return { id: Identity.Id, process: Identity.ProcessId, generation: Identity.GenerationId,
        health: { status: 'healthy' }, queue: { depth: '0', capacity: '16' }, tasks: { started: '0', completed: '0', cancelled: '0' },
        dispatch: { accepted: '0', full: '0', closed: '0', unavailable: '0', generation_rejected: '0' },
        commands: { executed: '0', failed: '0' }, running: true, accepting: true, active_tasks: '0', dropped_events: '0', traffic: null };
}

function Operation(State: string) {
    return { status: State, id: '12', command: 'Drain Worker', process: ProcessId, worker: '3', generation: '4',
        accepted_at: '2026-10-17T00:00:00.000Z', updated_at: '2026-10-17T00:00:01.000Z', message: State };
}

test('operation status returns a record only when fresh Bootstrap matches before and after the GET', async () => {
    const Paths: string[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        Paths.push(String(Path));
        if (String(Path).endsWith('/Bootstrap')) return Response.json(Bootstrap(IncarnationA));
        return Response.json(Operation('completed'));
    } });

    const Value = await Source.GetOperationStatus('12', ScopeA);

    assert.equal(Value.State, 'completed');
    assert.deepEqual(Paths.map(Path => Path.endsWith('/Bootstrap') ? 'bootstrap' : 'status'), ['bootstrap', 'status', 'bootstrap']);
});

test('preflight incarnation mismatch refuses the reused operation number before its status GET', async () => {
    const Paths: string[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        Paths.push(String(Path));
        return Response.json(Bootstrap(IncarnationB));
    } });

    await assert.rejects(Source.GetOperationStatus('12', ScopeA), OperationScopeChangedError);
    assert.deepEqual(Paths, ['/Operations/Bootstrap']);
});

test('incarnation change during status GET discards even a completed response', async () => {
    let BootstrapReads = 0;
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        if (String(Path).endsWith('/Bootstrap')) {
            BootstrapReads += 1;
            return Response.json(Bootstrap(BootstrapReads === 1 ? IncarnationA : IncarnationB));
        }
        return Response.json(Operation('completed'));
    } });

    await assert.rejects(Source.GetOperationStatus('12', ScopeA), OperationScopeChangedError);
    assert.equal(BootstrapReads, 2);
});

test('fresh Bootstrap failure prevents operation lookup and does not invent an identity', async () => {
    let StatusReads = 0;
    const Source = new LiveAdminDataSource({ Fetch: async Path => {
        if (String(Path).endsWith('/Bootstrap')) throw new Error('offline');
        StatusReads += 1;
        return Response.json(Operation('completed'));
    } });

    await assert.rejects(Source.GetOperationStatus('12', ScopeA), /无法连接/);
    assert.equal(StatusReads, 0);
    await assert.rejects(Source.GetBootstrap({ Fresh: true }), /无法连接/);
});

test('a delayed older Bootstrap response cannot replace a newer fresh snapshot', async () => {
    let ResolveOlder!: (Value: Response) => void;
    const OlderResponse = new Promise<Response>(Resolve => { ResolveOlder = Resolve; });
    let Calls = 0;
    const Source = new LiveAdminDataSource({ Fetch: async () => {
        Calls += 1;
        return Calls === 1 ? OlderResponse : Response.json(Bootstrap(IncarnationB));
    } });

    const Older = Source.GetBootstrap({ Fresh: true });
    const Newer = await Source.GetBootstrap({ Fresh: true });
    ResolveOlder(Response.json(Bootstrap(IncarnationA)));
    const OlderResult = await Older;

    assert.equal(Calls, 2);
    assert.equal(Newer.Incarnation, IncarnationB);
    assert.equal(OlderResult.Incarnation, IncarnationB);
    assert.equal((await Source.GetBootstrap()).Incarnation, IncarnationB);
});

test('worker drain reads and checks the exact scoped Worker before sending once', async () => {
    const Identity: WorkerIdentity = { Id: '3', ProcessId, GenerationId: '4' };
    const Requests: { Path: string; Method: string }[] = [];
    const Source = new LiveAdminDataSource({ Fetch: async (Path, Init) => {
        Requests.push({ Path: String(Path), Method: Init?.method ?? 'GET' });
        if (String(Path).endsWith('/Bootstrap')) return Response.json(Bootstrap(IncarnationA));
        if (String(Path).includes('/Workers?')) return Response.json({ status: 'ok', value: {
            items: [WorkerRecord(Identity)], next_cursor: '0', has_more: false } });
        return Response.json({ status: 'accepted', operation: '19', message: 'queued' });
    } });

    const Result = await Source.DrainWorker(Identity);
    const WorkerRead = Requests.findIndex(Request => Request.Path.includes('/Workers?'));
    const DrainPost = Requests.findIndex(Request => Request.Method === 'POST');
    const Query = new URL(`http://localhost${Requests[WorkerRead]?.Path}`);

    assert.equal(Result.Status, 'accepted');
    assert.ok(WorkerRead >= 0 && DrainPost > WorkerRead);
    assert.equal(Query.searchParams.get('id'), Identity.Id);
    assert.equal(Query.searchParams.get('process_id'), Identity.ProcessId);
    assert.equal(Query.searchParams.get('generation_id'), Identity.GenerationId);
    assert.equal(Requests.filter(Request => Request.Method === 'POST').length, 1);
});

test('worker identity mismatch refuses drain before POST', async () => {
    const Identity: WorkerIdentity = { Id: '3', ProcessId, GenerationId: '4' };
    let Posts = 0;
    const Source = new LiveAdminDataSource({ Fetch: async (Path, Init) => {
        if (String(Path).endsWith('/Bootstrap')) return Response.json(Bootstrap(IncarnationA));
        if (String(Path).includes('/Workers?')) return Response.json({ status: 'ok', value: {
            items: [WorkerRecord({ ...Identity, GenerationId: '5' })], next_cursor: '0', has_more: false } });
        if (Init?.method === 'POST') Posts += 1;
        return Response.json({ status: 'accepted', operation: '19', message: 'queued' });
    } });

    await assert.rejects(Source.DrainWorker(Identity), WorkerIdentityChangedError);
    assert.equal(Posts, 0);
});

test('demo Worker drain refuses a stale generation without changing the current slot', async () => {
    const Source = new DemoAdminDataSource();
    const Current = (await Source.GetWorkers({ Cursor: '0', Limit: 1 })).Items[0];
    assert.ok(Current);

    await assert.rejects(Source.DrainWorker({ ...Current, GenerationId: 'stale' }), WorkerIdentityChangedError);
    const After = (await Source.GetWorkers({ Cursor: '0', Limit: 1, Id: Current.Id })).Items[0];
    assert.equal(After?.Accepting, true);
});
