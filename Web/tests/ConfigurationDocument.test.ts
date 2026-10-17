import assert from 'node:assert/strict';
import test from 'node:test';
import { ParsePublicConfiguration, ValidatePolicy } from '../src/Api/ConfigurationDocument.ts';
import { ParseJsonDocument } from '../src/Api/JsonDocument.ts';
import { CanonicalProtocol } from '../src/Api/ProtocolIdentity.ts';

function Validate(Text: string): string | null {
    const Parsed = ParseJsonDocument({ Text, MaxBytes: 16384 });
    return Parsed.Ok ? ValidatePolicy(Parsed.Value) : Parsed.Message;
}
test('策略三态允许零额度与uint64最大值，继承不能隐藏非零限制', () => {
    assert.equal(Validate('{"TrafficBytes":{"Mode":"Finite","Value":0}}'), null);
    assert.equal(Validate('{"TrafficBytes":{"Mode":"Finite","Value":18446744073709551615}}'), null);
    assert.match(Validate('{"TrafficBytes":{"Mode":"Unlimited","Value":1}}') ?? '', /必须为 0/);
    assert.match(Validate('{"Connections":{"Mode":"Finite","Value":4294967296}}') ?? '', /范围/);
    assert.match(Validate('{"Cycle":{"Kind":"Month","OffsetMinutes":841}}') ?? '', /时区/);
    assert.match(Validate('{"TrafficBytes":{"Mode":"limited","Value":10}}') ?? '', /Mode/);
});
test('公开配置允许正式Storage及账户/组Policy，保留原始大整数', () => {
    const Config: Record<string, unknown> = Object.fromEntries(['Runtime','Listeners','NativeTls','Builtins','Protocols','Carriers','ProtocolBindings','Recognition','Routes','Dns','Logging','Trace','Statistics','Operations','HotReload','Shutdown'].map(Key => [Key, {}]));
    Config.SchemaVersion = 1; Config.Protocols = []; Config.AccountGroups = [{ Id: 'g', Name: '组', Policy: { Connections: { Mode: 'Finite', Value: 12 } } }];
    Config.Accounts = [{ Id: 'a', GroupId: 'g', SecretRef: 'env:SECRET', Policy: { Cycle: { Kind: 'Month', OffsetMinutes: 480 } } }];
    Config.Storage = { Directory: 'data', HistoryMaxBytes: 4294967296 };
    const Parsed = ParsePublicConfiguration(JSON.stringify(Config));
    assert.equal(Parsed.Ok, true);
    Config.Storage = { Directory: 'data', Unknown: true };
    assert.equal(ParsePublicConfiguration(JSON.stringify(Config)).Ok, false);
});
test('真实协议编码VLESS=4归一名称，未知码保留原始身份', () => {
    assert.equal(CanonicalProtocol('4'), 'vless');
    assert.equal(CanonicalProtocol('VLESS'), 'vless');
    assert.equal(CanonicalProtocol('255'), 'unknown (255)');
});
