import assert from 'node:assert/strict';
import test from 'node:test';
import type { ProtocolRecord } from '../src/Services/AdminDataSource.ts';
import { SummarizeProtocols } from '../src/Features/Protocols/ProtocolSummary.ts';

function Row(Id: string, Name: string, ActiveSessions: string | null, Kind?: 'type' | 'instance'): ProtocolRecord {
    return { Id, Name, ActiveSessions, Kind, ConfiguredBindings: '1', Traffic: null, Latency: null, Coverage: '' };
}

test('同类型的多条配置只累计一次，缺测类型明确标为部分统计', () => {
    assert.deepEqual(SummarizeProtocols([Row('a', 'vless', '7'), Row('b', 'VLESS', '7'), Row('c', 'tuic', null)], false),
        { Types: 2, Active: '7', Partial: true });
});

test('同类型计数冲突时不展示可能错误的总数', () => {
    assert.equal(SummarizeProtocols([Row('a', 'vless', '7'), Row('b', 'vless', '8')], false).Active, null);
});

test('显式实例不加入类型统计，分页中说明统计未完整', () => {
    assert.deepEqual(SummarizeProtocols([Row('a', 'vless', '0', 'type'), Row('b', 'vless', '5', 'instance')], true),
        { Types: 1, Active: '0', Partial: true });
    assert.deepEqual(SummarizeProtocols([Row('b', 'vless', '5', 'instance')], false),
        { Types: 0, Active: null, Partial: true });
});
