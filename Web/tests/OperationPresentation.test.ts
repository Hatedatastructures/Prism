import { test } from 'node:test';
import assert from 'node:assert/strict';
import { OperationPresentation } from '../src/Features/Operations/OperationPresentation.ts';

test('受理、执行和未知状态不会用成功或告警色冒充终态', () => {
    for (const State of ['accepted', 'running', 'unknown'] as const)
        assert.equal(OperationPresentation(State).Tone, 'neutral', State);
    assert.equal(OperationPresentation('running').Label, '等待终态');
    assert.deepEqual(OperationPresentation('completed'), { Label: '已完成', Tone: 'good' });
});

test('明确失败和需要核对的状态保留不同的提示语义', () => {
    for (const State of ['failed', 'rejected', 'invalid'] as const)
        assert.equal(OperationPresentation(State).Tone, 'danger', State);
    for (const State of ['timed_out', 'unavailable', 'blocked', 'restart_required', 'conflict', 'interrupted'] as const)
        assert.equal(OperationPresentation(State).Tone, 'warning', State);
});
