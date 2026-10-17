import assert from 'node:assert/strict';
import test from 'node:test';
import { Decimal, DecodeBootstrap, DecodePage, DecodeTracePage, DecodeCommand, RecordValue } from '../src/Api/Wire.ts';
import { TraceStageLabel } from '../src/Api/TraceIdentity.ts';

test('64 位数据保留十进制文本并拒绝已丢精度的数值', () => {
    assert.equal(Decimal('18446744073709551615'), '18446744073709551615');
    assert.throws(() => Decimal(9007199254740992), /十进制文本/);
    assert.throws(() => Decimal('-1'), /十进制文本/);
});
test('Bootstrap 只接受明确的 v2 合同且不将 token 放入领域快照', () => {
    const Value = DecodeBootstrap({ api_version: '2', process_id: '9', instance_key: 'instance-a', process_incarnation: 'b'.repeat(32), command_token: 'a'.repeat(64), capabilities: ['health.read'] });
    assert.equal(Value.InstanceKey, 'instance-a');
    assert.equal(Value.ProcessId, '9');
    assert.throws(() => DecodeBootstrap({ api_version: '1' }), /版本/);
});
test('Bootstrap拒绝空持久标识与畸形启动凭据，错误不回显凭据', () => {
    const Bootstrap = { api_version: '2', process_id: '9', instance_key: 'instance-a', process_incarnation: 'b'.repeat(32), command_token: 'a'.repeat(64), capabilities: [] };
    assert.throws(() => DecodeBootstrap({ ...Bootstrap, instance_key: '' }), /instance_key 字段无效/);
    assert.throws(() => DecodeBootstrap({ ...Bootstrap, process_incarnation: 'bad-incarnation' }), /process_incarnation 字段无效/);
    assert.throws(() => DecodeBootstrap({ ...Bootstrap, command_token: 'sensitive malformed token' }), Failure => Failure instanceof Error && Failure.message === 'Bootstrap command_token 字段无效' && !Failure.message.includes('sensitive'));
    assert.throws(() => DecodeBootstrap({ ...Bootstrap, command_token: 'g'.repeat(64) }), /command_token 字段无效/);
});
test('游标作为不透明文本传递，第一页不能替代不存在的目标', () => {
    const Page = DecodePage({ items: [{ id: '8' }], next_cursor: 'snapshot:53', has_more: true }, Value => Decimal(RecordValue(Value).id));
    assert.equal(Page.NextCursor, 'snapshot:53');
    assert.deepEqual(Page.Items, ['8']);
});
test('Trace 缺失持续时间和覆盖信息保持可见，不制造零耗时', () => {
    const Page = DecodeTracePage({ items: [{ span_id: '2-3', parent_span_id: null, sequence: '3', name: 'resolve_dial', start_time: '2026-10-16T00:00:00Z', duration_ms: null, status: 'begin', session: '7', worker: '2', process: '1', generation: '3', attributes: { elapsed_ns: '100', stage: 'resolve_dial', outcome: 'begin' } }], next_cursor: '2:3', has_more: false, lost: true, cursors: [{ worker_id: '2', sequence: '3' }], lost_ranges: [{ worker_id: '2', overwritten: '20', lost_since_cursor: '1', concurrent_read_skips: '0' }] });
    assert.equal(Page.Items[0]?.DurationMs, null);
    assert.equal(Page.Lost, true);
    assert.equal(Page.Loss[0]?.LostSinceCursor, '1');
});
test('Trace首批写出不是TTFB，已知阶段翻译且未知阶段保留', () => {
    assert.equal(TraceStageLabel('relay.first_download_byte'), '首批下行有效载荷写出');
    assert.equal(TraceStageLabel('relay.first_upload_byte'), '首批上行有效载荷写出');
    assert.equal(TraceStageLabel('future.phase'), 'future.phase');
});
test('命令已受理不是完成，typed failure 保留原因', () => {
    const Result = DecodeCommand({ status: 'accepted', operation: '45', correlation: '1', generation: '3', message: 'queued' });
    assert.equal(Result.Status, 'accepted');
    assert.equal(Result.OperationId, '45');
    assert.equal(Result.Operation?.State, 'accepted');
    const Failed = DecodeCommand({ status: 'blocked', operation: '0', message: 'drain blocked', failure: { code: 'resource unavailable', native_category: 'system', native_value: 5 } });
    assert.equal(Failed.Ok, false);
    assert.match(Failed.Failure ?? '', /system/);
});
test('操作目标优先最具体非零作用域，不能选账户零或用账户替代Session', () => {
    const Base = { status: 'accepted', operation: '5', message: 'queued', process: '1', account: '0', worker: '0', session: '0', stream: '0', task: '0' };
    assert.equal(DecodeCommand(Base).Operation?.Target, '进程 1');
    assert.equal(DecodeCommand({ ...Base, account: '7', session: '19' }).Operation?.Target, 'Session 19');
    assert.equal(DecodeCommand({ ...Base, account: '7', session: '19', task: '31' }).Operation?.Target, 'Task 31');
    assert.equal(DecodeCommand(Base).Operation?.AccountId, null);
});
