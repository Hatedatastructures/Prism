import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TrustedProxyOrigin } from '../scripts/ProxyOrigin.ts';

test('同源本机开发请求映射为后端的真实Origin', () => {
    assert.equal(TrustedProxyOrigin({ origin: 'http://127.0.0.1:5173', host: '127.0.0.1:5173' }, 'http://127.0.0.1:9090'), 'http://127.0.0.1:9090');
    assert.equal(TrustedProxyOrigin({ origin: 'http://localhost:5173', host: 'localhost:5173' }, 'http://127.0.0.1:9090'), 'http://127.0.0.1:9090');
    assert.equal(TrustedProxyOrigin({ origin: 'http://[::1]:5173', host: '[::1]:5173' }, 'http://127.0.0.1:9090'), 'http://127.0.0.1:9090');
});
test('外部网站与伪造本机Host不会获得同源身份', () => {
    assert.equal(TrustedProxyOrigin({ origin: 'https://evil.example', host: '127.0.0.1:5173' }, 'http://127.0.0.1:9090'), null);
    assert.equal(TrustedProxyOrigin({ origin: 'https://evil.example', host: 'evil.example' }, 'http://127.0.0.1:9090'), null);
    assert.equal(TrustedProxyOrigin({ origin: 'http://localhost:5174', host: 'localhost:5173' }, 'http://127.0.0.1:9090'), null);
    assert.equal(TrustedProxyOrigin({ origin: 'http://127.0.0.1:5173', host: 'localhost:5173' }, 'http://127.0.0.1:9090'), null);
});
test('缺省Origin与畸形或带凭据的Origin不被补成可信Origin', () => {
    for (const origin of [undefined, '', 'null', 'not-a-url', 'http://127.0.0.1:5173/path', 'http://a@127.0.0.1:5173'])
        assert.equal(TrustedProxyOrigin({ origin, host: '127.0.0.1:5173' }, 'http://127.0.0.1:9090'), null);
});
test('开发代理只为本机HTTP目标重写，不扩展到任意目标', () => {
    for (const target of ['https://evil.example', 'http://192.0.2.1:9090', 'file:///tmp/service', 'not-a-url'])
        assert.equal(TrustedProxyOrigin({ origin: 'http://127.0.0.1:5173', host: '127.0.0.1:5173' }, target), null);
});
