import assert from 'node:assert/strict';
import test from 'node:test';
import { CounterDelta, SelectResource, ProtocolDistribution, HistoryChartPoints } from '../src/Api/Analysis.ts';
test('先在 bigint 域做累计差分，重置和零间隔返回缺测', () => {
    assert.equal(CounterDelta('18446744073709551615', '18446744073709550615', 2000), 500);
    assert.equal(CounterDelta('1', '2', 1000), null);
    assert.equal(CounterDelta('2', '1', 0), null);
});
test('完整目标不在当前页时不选择其他资源', () => {
    assert.equal(SelectResource([{ Id: 'first' }], 'outside-page'), null);
    assert.equal(SelectResource([{ Id: 'first' }], '')?.Id, 'first');
});
test('同协议多实例不重复相加，未识别包含在活动分母', () => {
    const Shared = { Name: 'VLESS', ConfiguredBindings: '1', ActiveSessions: '2', Traffic: null, Latency: null, Coverage: 'TCP type shared' };
    const Distribution = ProtocolDistribution([{ ...Shared, Id: 'a' }, { ...Shared, Id: 'b' }], '4');
    assert.equal(Distribution.DuplicateTypes, true);
    assert.equal(Distribution.Rows.find(Row => Row.Id === 'a')?.Percent, 50);
    assert.equal(Distribution.Rows.find(Row => Row.Id === 'unattributed')?.Count, '2');
});
test('已标识type和instance时只用正式type行，实例不被Name合并冒充类型', () => {
    const Shared = { Name: 'vless', ConfiguredBindings: '1', Traffic: null, Latency: null, Coverage: 'TCP' };
    const Distribution = ProtocolDistribution([{ ...Shared, Id: 'type:vless', Kind: 'type', TypeKey: 'vless', ActiveSessions: '3' }, { ...Shared, Id: 'a', Kind: 'instance', ActiveSessions: '1' }, { ...Shared, Id: 'b', Kind: 'instance', ActiveSessions: '2' }], '4');
    assert.equal(Distribution.Rows[0]?.Count, '3'); assert.equal(Distribution.Rows[0]?.Percent, 75); assert.equal(Distribution.DuplicateTypes, false);
    assert.equal(ProtocolDistribution([{ ...Shared, Id: 'a', Kind: 'instance', ActiveSessions: '1' }], '1').Available, false);
});
test('历史窗口字节按真实分辨率转速率，null 延迟不变零', () => {
    const Points = HistoryChartPoints([{ Time: '2026-10-16T00:00:00Z', UpBytes: '1000', DownBytes: null, Active: null, P50Us: null, P95Us: '12500', P99Us: null, SampleCount: '5', Quality: '' }], '10000');
    assert.equal(Points[0]?.Up, 100);
    assert.equal(Points[0]?.Down, null);
    assert.equal(Points[0]?.P50, null);
    assert.equal(Points[0]?.P95, 12.5);
});
test('历史两端有值时显式缺测区间仍插入全系列null，不能跨缺测连线', () => {
    const Make = (Time: string) => ({ Time, UpBytes: '100', DownBytes: '200', Active: '2', P50Us: '3000', P95Us: '4000', P99Us: '5000', SampleCount: '10', Quality: '' });
    const Points = HistoryChartPoints([Make('2026-10-16T00:00:00Z'), Make('2026-10-16T00:00:10Z')], '10000', [{ From: '2026-10-16T00:00:03Z', To: '2026-10-16T00:00:07Z', Reason: 'storage gap' }]);
    assert.equal(Points.length, 3); assert.equal(Points[0]?.Up, 10); assert.equal(Points[2]?.Up, 10);
    assert.deepEqual(Points[1], { Time: Date.parse('2026-10-16T00:00:05Z'), Up: null, Down: null, P50: null, P95: null, P99: null, Active: null, Samples: '0' });
});
test('超过声明分辨率的实际断档即使无gaps元数据也断开', () => {
    const Make = (Time: string) => ({ Time, UpBytes: '100', DownBytes: null, Active: null, P50Us: null, P95Us: null, P99Us: null, SampleCount: '0', Quality: '' });
    const Points = HistoryChartPoints([Make('2026-10-16T00:00:00Z'), Make('2026-10-16T00:00:30Z')], '10000');
    assert.equal(Points.length, 3); assert.equal(Points[1]?.Time, Date.parse('2026-10-16T00:00:10Z')); assert.equal(Points[1]?.Up, null);
});
