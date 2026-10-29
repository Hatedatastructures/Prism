import assert from 'node:assert/strict';
import test from 'node:test';
import { DemoHistory } from '../src/Services/DemoHistory.ts';
import { HistoryChartPoints } from '../src/Api/Analysis.ts';

test('所有演示历史计数保持 UInt64 文本，账户/Worker/协议分析可转换', () => {
    for (const Scope of ['process', 'worker', 'account', 'group', 'ingress', 'protocol_type', 'protocol_instance'] as const) {
        for (const Metric of ['traffic', 'recognition_admission', 'active'] as const) {
            const History = DemoHistory({ Scope, Key: 'acct-northstar', Metric, From: '2026-10-16T00:00:00Z', To: '2026-10-16T00:15:00Z' });
            if (Metric === 'active') {
                assert.match(History.Coverage, /窗口有效载荷/);
                assert.ok(History.Items.every(Point => Point.Active === null));
            }
            if (Metric === 'recognition_admission') assert.match(History.Coverage, /延迟样本/);
            for (const Point of History.Items) for (const Field of ['UpBytes', 'DownBytes', 'Active', 'P50Us', 'P95Us', 'P99Us', 'SampleCount'] as const) {
                assert.ok(Point[Field] === null || /^(0|[1-9]\d*)$/.test(Point[Field]));
            }
            assert.equal(HistoryChartPoints(History.Items, History.ResolutionMs).length, History.Items.length);
        }
    }
});
