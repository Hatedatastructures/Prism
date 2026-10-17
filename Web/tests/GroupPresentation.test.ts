import assert from 'node:assert/strict';
import test from 'node:test';
import { ResolveAccountReadStatus, ResolveGroupTarget, SummarizeLoadedMetric } from '../src/Features/UserGroups/GroupPresentation.ts';

test('空的已载入组集合与所有组字段缺测区分开', () => {
    assert.deepEqual(SummarizeLoadedMetric([]), {
        State: 'empty', Total: null, Known: 0, Count: 0,
    });
    assert.deepEqual(SummarizeLoadedMetric([null, null]), {
        State: 'unavailable', Total: null, Known: 0, Count: 2,
    });
});

test('部分已载入组缺字段时不输出总计并保留覆盖数', () => {
    assert.deepEqual(SummarizeLoadedMetric(['12', null, '8']), {
        State: 'partial', Total: null, Known: 2, Count: 3,
    });
});

test('完整真零仍显示零而不是缺测', () => {
    assert.deepEqual(SummarizeLoadedMetric(['0', '0']), {
        State: 'complete', Total: '0', Known: 2, Count: 2,
    });
});

test('完整非零总计在整数域精确累加', () => {
    assert.deepEqual(SummarizeLoadedMetric(['18446744073709551615', '7']), {
        State: 'complete', Total: '18446744073709551622', Known: 2, Count: 2,
    });
});

test('组深链未命中时保留请求 ID 并标记为当前载入范围外', () => {
    assert.deepEqual(ResolveGroupTarget(['group-a'], 'group-removed', 'group-a'), {
        Id: 'group-removed', Unassigned: false, MissingFromLoadedGroups: true,
    });
});

test('继续载入命中深链目标后按原 ID 选中该组', () => {
    assert.deepEqual(ResolveGroupTarget(['group-a', 'group-removed'], 'group-removed', 'group-a'), {
        Id: 'group-removed', Unassigned: false, MissingFromLoadedGroups: false,
    });
});

test('未分组目标不会被当成未命中的用户组', () => {
    assert.deepEqual(ResolveGroupTarget(['group-a'], '__unassigned__', 'group-a'), {
        Id: '__unassigned__', Unassigned: true, MissingFromLoadedGroups: false,
    });
});

test('账户清单首次查询期间不是空成员状态', () => {
    assert.equal(ResolveAccountReadStatus({ HasData: false, Pending: true, Failed: false }), 'loading');
});

test('账户清单查询失败且无旧数据时不是空成员状态', () => {
    assert.equal(ResolveAccountReadStatus({ HasData: false, Pending: false, Failed: true }), 'error');
});

test('账户刷新失败但保留旧数据时标记为过期快照', () => {
    assert.equal(ResolveAccountReadStatus({ HasData: true, Pending: false, Failed: true }), 'stale');
});

test('成功载入但成员为零时才允许进入真实空集合判定', () => {
    assert.equal(ResolveAccountReadStatus({ HasData: true, Pending: false, Failed: false }), 'ready');
});

test('账户查询既无快照也无明确错误时保持未知而不伪装为空', () => {
    assert.equal(ResolveAccountReadStatus({ HasData: false, Pending: false, Failed: false }), 'unknown');
});
