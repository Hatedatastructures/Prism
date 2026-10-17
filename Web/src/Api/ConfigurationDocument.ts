import { FormatJsonDocument, ParseJsonDocument } from './JsonDocument.ts';
import type { JsonNode, JsonParseResult } from './JsonDocument.ts';

const Fields = ['SchemaVersion', 'Runtime', 'Listeners', 'NativeTls', 'Builtins', 'Protocols',
    'Carriers', 'ProtocolBindings', 'AccountGroups', 'Recognition', 'Accounts', 'Routes', 'Dns', 'Logging',
    'Trace', 'Statistics', 'Operations', 'HotReload', 'Shutdown', 'Storage'];

/** @brief 配置草稿沿用原始数值 token，保留字段顺序并验证公开配置边界。 */
export function ParsePublicConfiguration(Text: string): JsonParseResult {
    const Parsed = ParseJsonDocument({ Text, MaxBytes: 256 * 1024 });
    if (!Parsed.Ok) return Parsed;
    const Value = Parsed.Value;
    if (Value.Kind !== 'object' || [...Value.Members.keys()].some(Key => !Fields.includes(Key)) ||
        Fields.filter(Key => Key !== 'Storage').some(Key => !Value.Members.has(Key))) return { Ok: false, Message: '配置公共字段缺失或包含未公开字段' };
    if (Value.Members.get('SchemaVersion')?.Raw !== '1') return { Ok: false, Message: 'SchemaVersion 必须为 1' };
    const Accounts = Value.Members.get('Accounts');
    const Protocols = Value.Members.get('Protocols');
    if (Accounts?.Kind !== 'array' || Protocols?.Kind !== 'array') {
        return { Ok: false, Message: 'Accounts 和 Protocols 必须为数组' };
    }
    for (const Account of Accounts.Elements) {
        if (Account.Kind !== 'object' || [...Account.Members.keys()].some(Key =>
            Key !== 'Id' && Key !== 'GroupId' && Key !== 'SecretRef' && Key !== 'Policy') ||
            Account.Members.get('Id')?.Kind !== 'string' || Account.Members.get('SecretRef')?.Kind !== 'string') {
            return { Ok: false, Message: '账户只接受 Id、GroupId、SecretRef 和 Policy' };
        }
        const Failure = ValidatePolicy(Account.Members.get('Policy'));
        if (Failure) return { Ok: false, Message: `账户策略：${Failure}` };
    }
    const Groups = Value.Members.get('AccountGroups');
    if (Groups?.Kind !== 'array') return { Ok: false, Message: 'AccountGroups 必须为数组' };
    for (const Group of Groups.Elements) {
        if (Group.Kind !== 'object' || [...Group.Members.keys()].some(Key => !['Id', 'Name', 'Policy'].includes(Key)) ||
            Group.Members.get('Id')?.Kind !== 'string' || Group.Members.get('Name')?.Kind !== 'string') return { Ok: false, Message: '用户组只接受 Id、Name 和 Policy' };
        const Failure = ValidatePolicy(Group.Members.get('Policy'));
        if (Failure) return { Ok: false, Message: `用户组策略：${Failure}` };
    }
    const Storage = Value.Members.get('Storage');
    if (Storage) {
        if (Storage.Kind !== 'object' || [...Storage.Members.keys()].some(Key => !['Directory', 'HistoryMaxBytes'].includes(Key)) ||
            Storage.Members.has('Directory') && Storage.Members.get('Directory')?.Kind !== 'string' ||
            Storage.Members.has('HistoryMaxBytes') && !UnsignedNode(Storage.Members.get('HistoryMaxBytes'), 18446744073709551615n)) return { Ok: false, Message: 'Storage 字段无效' };
    }
    for (const Protocol of Protocols.Elements) {
        if (Protocol.Kind !== 'object') return { Ok: false, Message: 'Protocol 必须为对象' };
        const Quic = Protocol.Members.get('Quic');
        if (Quic?.Kind === 'object' && Quic.Members.has('Uuid')) {
            return { Ok: false, Message: 'QUIC 只能使用 CredentialSecretRef，不接受 inline UUID' };
        }
    }
    return Parsed;
}

const PolicyLimits = ['Connections', 'Streams', 'TrafficBytes', 'UploadBytesPerSecond', 'DownloadBytesPerSecond', 'AdmissionsPerSecond'];
function UnsignedNode(Value: JsonNode | undefined, Maximum: bigint): boolean {
    return Value?.Kind === 'number' && /^(0|[1-9]\d*)$/.test(Value.Raw) && BigInt(Value.Raw) <= Maximum;
}
/** @brief 对齐 AccountPolicyJson 的正式三态结构，直接检查 token，不做浮点转换。 */
export function ValidatePolicy(Value: JsonNode | undefined): string | null {
    if (!Value) return null;
    if (Value.Kind !== 'object' || [...Value.Members.keys()].some(Key => ![...PolicyLimits, 'Cycle'].includes(Key))) return '存在未知字段或不是对象';
    for (const Key of PolicyLimits) {
        const Limit = Value.Members.get(Key);
        if (!Limit) continue;
        if (Limit.Kind !== 'object' || [...Limit.Members.keys()].some(Member => Member !== 'Mode' && Member !== 'Value')) return `${Key} 必须包含 Mode / Value`;
        const ModeNode = Limit.Members.get('Mode');
        const Mode = ModeNode === undefined ? 'Inherit' : ModeNode.Kind === 'string' ? ModeNode.Text : '';
        if (!['Inherit', 'Unlimited', 'Finite'].includes(Mode)) return `${Key}.Mode 无效`;
        const Amount = Limit.Members.get('Value');
        const Max = Key === 'Connections' || Key === 'Streams' ? 4294967295n : 18446744073709551615n;
        if (Amount && !UnsignedNode(Amount, Max)) return `${Key}.Value 必须是范围内的非负整数`;
        if (Mode !== 'Finite' && Amount && Amount.Raw !== '0') return `${Key} 继承或不限时 Value 必须为 0`;
    }
    const Cycle = Value.Members.get('Cycle');
    if (Cycle && Cycle.Kind !== 'null') {
        if (Cycle.Kind !== 'object' || [...Cycle.Members.keys()].some(Key => Key !== 'Kind' && Key !== 'OffsetMinutes')) return 'Cycle 字段无效';
        const Kind = Cycle.Members.get('Kind');
        if (Kind && (Kind.Kind !== 'string' || !['Day', 'Week', 'Month', 'None'].includes(Kind.Text))) return 'Cycle.Kind 无效';
        const Offset = Cycle.Members.get('OffsetMinutes');
        if (Offset && (Offset.Kind !== 'number' || !/^-?(0|[1-9]\d*)$/.test(Offset.Raw) || BigInt(Offset.Raw) < -840n || BigInt(Offset.Raw) > 840n)) return '周期时区必须为 -840 至 840 的整数分钟';
    }
    return null;
}

export type ConfigurationChange = Readonly<{ Path: string; Before: string; After: string }>;

export function ConfigurationChanges(Before: JsonNode, After: JsonNode): readonly ConfigurationChange[] {
    if (Before.Kind !== 'object' || After.Kind !== 'object') return [];
    const Changes: ConfigurationChange[] = [];
    for (const Field of Fields) {
        const Old = Before.Members.get(Field);
        const New = After.Members.get(Field);
        if (Old === undefined || New === undefined) continue;
        const OldText = FormatJsonDocument(Old);
        const NewText = FormatJsonDocument(New);
        if (OldText !== NewText) Changes.push({ Path: Field, Before: OldText, After: NewText });
    }
    return Changes;
}
