import assert from 'node:assert/strict';
import test from 'node:test';
import { CheckWorkerIdentity, WorkerTargetPath } from '../src/Features/Workers/WorkerIdentity.ts';

const Current = { Id: 'worker-1', ProcessId: 'process-7', GenerationId: 'generation-9' } as const;

test('a complete current worker identity is verified', () => {
    assert.equal(CheckWorkerIdentity(Current, Current), 'verified');
});

test('a reused slot from an older generation is not the requested worker target', () => {
    assert.equal(CheckWorkerIdentity(Current, { ...Current, GenerationId: 'generation-8' }), 'changed');
});

test('a worker from another process is not the requested worker target', () => {
    assert.equal(CheckWorkerIdentity(Current, { ...Current, ProcessId: 'process-6' }), 'changed');
});

test('missing process or generation scope cannot verify a deep link', () => {
    assert.equal(CheckWorkerIdentity({ ...Current, GenerationId: null }, Current), 'scope-missing');
    assert.equal(CheckWorkerIdentity({ ...Current, ProcessId: null }, Current), 'scope-missing');
});

test('no current record is not proof that a generation-scoped target retired', () => {
    assert.equal(CheckWorkerIdentity(Current, null), 'unavailable');
});

test('worker resource links preserve the complete identity', () => {
    const Path = WorkerTargetPath('sessions', Current);
    const Params = new URL(Path, 'https://prism.invalid').searchParams;
    assert.equal(Params.get('worker'), Current.Id);
    assert.equal(Params.get('process'), Current.ProcessId);
    assert.equal(Params.get('generation'), Current.GenerationId);
});
