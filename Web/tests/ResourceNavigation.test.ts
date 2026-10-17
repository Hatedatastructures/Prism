import assert from 'node:assert/strict';
import test from 'node:test';
import { ResourceDestination } from '../src/Api/ResourceNavigation.ts';

test('资源跳转保留时间与演示来源，hash不成为查询字段', () => {
    assert.equal(ResourceDestination('/workers?worker=7#tasks', new URLSearchParams('source=demo&range=1h')), '/workers?worker=7&range=1h&source=demo#tasks');
});
test('目标显式时间范围优先，不混入原页面的自定义起止', () => {
    const Current = new URLSearchParams('source=demo&range=custom&from=old-start&to=old-end');
    assert.equal(ResourceDestination('/accounts?account=a&range=24h', Current), '/accounts?account=a&range=24h&source=demo');
});
test('React Router对象To保持pathname/hash和已有搜索，外部URL不加入上下文', () => {
    assert.deepEqual(ResourceDestination({ pathname: '/sessions', search: '?session=9', hash: '#trace' }, new URLSearchParams('range=custom&from=start&to=end&source=demo')),
        { pathname: '/sessions', search: '?session=9&range=custom&from=start&to=end&source=demo', hash: '#trace' });
    assert.equal(ResourceDestination('https://example.com/', new URLSearchParams('source=demo')), 'https://example.com/');
});
