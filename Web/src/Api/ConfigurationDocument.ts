import { DecodeDecimal } from './Decimal';
import type { Decimal } from './Decimal';
import { FormatJsonDocument, ParseJsonDocument } from './JsonDocument';
import type { JsonNode, JsonParseResult } from './JsonDocument';

const Fields = ['SchemaVersion', 'Runtime', 'Listeners', 'NativeTls', 'Builtins', 'Protocols',
    'Carriers', 'ProtocolBindings', 'Recognition', 'Accounts', 'Routes', 'Dns', 'Logging',
    'Trace', 'Statistics', 'Operations', 'HotReload', 'Shutdown'];

/** @brief 公共配置仅接受既有安全字段；秘密值仍由服务端当前代所有者保留。 */
export function ParsePublicConfiguration(Text: string): JsonParseResult {
    const Parsed = ParseJsonDocument({ Text, MaxBytes: 65536 });
    if (!Parsed.Ok) return Parsed;
    const Value = Parsed.Value;
    if (Value.Kind !== 'object' || [...Value.Members.keys()].some(Key => !Fields.includes(Key)) ||
        Fields.some(Key => !Value.Members.has(Key))) return { Ok: false, Message: '配置公共字段缺失或包含未公开字段' };
    if (Value.Members.get('SchemaVersion')?.Raw !== '1') return { Ok: false, Message: 'SchemaVersion 必须为 1' };
    const Accounts = Value.Members.get('Accounts');
    const Protocols = Value.Members.get('Protocols');
    if (Accounts?.Kind !== 'array' || Protocols?.Kind !== 'array') return { Ok: false, Message: 'Accounts 和 Protocols 必须为数组' };
    for (const Account of Accounts.Elements) {
        if (Account.Kind !== 'object' || [...Account.Members.keys()].some(Key => Key !== 'Id' && Key !== 'SecretRef') ||
            Account.Members.get('Id')?.Kind !== 'string' || Account.Members.get('SecretRef')?.Kind !== 'string') {
            return { Ok: false, Message: '账户只能编辑 Id 和 SecretRef；现存 inline credential 由服务端保留' };
        }
    }
    for (const Protocol of Protocols.Elements) {
        if (Protocol.Kind !== 'object') return { Ok: false, Message: 'Protocol 必须为对象' };
        const Quic = Protocol.Members.get('Quic');
        if (Quic?.Kind === 'object' && Quic.Members.has('Uuid')) {
            return { Ok: false, Message: 'QUIC 只能使用 CredentialSecretRef；不接受 inline UUID' };
        }
    }
    return Parsed;
}

export type ConfigurationChange = Readonly<{ Path: string; Before: string; After: string }>;

/** @brief 按真实公共字段比较有界差异；数值保持原始 token，不转换成浮点数。 */
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

export type ReloadMode = 'validate_only' | 'apply';
export type ReloadDocumentResult = Readonly<{ Ok: true; Value: ReloadDocument }> |
    Readonly<{ Ok: false; Message: string }>;

/** @brief 单次 Reload 请求拥有已验证公共配置原文及读取时的 BaseGeneration。 */
export class ReloadDocument {
    private constructor(private readonly Document: string) {}
    public Encode(): string { return this.Document; }
    public static Create(Input: Readonly<{ Text: string; BaseGeneration: Decimal; Mode: ReloadMode }>): ReloadDocumentResult {
        const Base = DecodeDecimal(Input.BaseGeneration);
        if (!Base.Ok || Base.Value === '0') return { Ok: false, Message: 'BaseGeneration 无效' };
        const Parsed = ParsePublicConfiguration(Input.Text);
        if (!Parsed.Ok) return Parsed;
        const Document = `{"mode":${JSON.stringify(Input.Mode)},"base_generation":${JSON.stringify(Base.Value)},"configuration":${Parsed.Value.Raw}}`;
        if (new TextEncoder().encode(Document).length > 65536) return { Ok: false, Message: '配置与命令外层合计超过 64 KiB' };
        return { Ok: true, Value: new ReloadDocument(Document) };
    }
}
