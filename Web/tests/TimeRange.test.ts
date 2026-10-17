import assert from 'node:assert/strict';
import test from 'node:test';
import { ResolveTimeRange } from '../src/Api/TimeRange.ts';
test('非法时间范围有可修正原因，不保持永久pending', () => {
    const Base = { Range: 'custom', Now: Date.parse('2026-10-16T00:00:00Z') };
    assert.match(ResolveTimeRange({ ...Base, From: 'invalid', To: '2026-10-16' }).InvalidReason ?? '', /时间无效/);
    assert.match(ResolveTimeRange({ ...Base, From: '2026-10-17', To: '2026-10-16' }).InvalidReason ?? '', /必须晚于/);
    assert.match(ResolveTimeRange({ ...Base, From: '2026-09-01', To: '2026-10-16' }).InvalidReason ?? '', /超过 30 天/);
    assert.equal(ResolveTimeRange({ ...Base, From: '2026-10-16T00:00:00Z', To: '2026-10-16T01:00:00Z' }).Valid, true);
});
