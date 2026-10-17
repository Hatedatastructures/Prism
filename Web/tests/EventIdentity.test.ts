import assert from 'node:assert/strict';
import test from 'node:test';
import { EventLabel } from '../src/Api/EventIdentity.ts';
test('已知事件安全翻译，未知事件保留真实名称', () => {
    assert.equal(EventLabel('operation_accepted'), '管理操作已受理');
    assert.equal(EventLabel('future_protocol_error'), 'future_protocol_error');
});
