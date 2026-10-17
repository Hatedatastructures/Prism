/** @brief 有界 JSON 语法树只保存原始数值 token，配置往返不会经过浮点数。 */
export type JsonNode = Readonly<{ Raw: string }> & (
    Readonly<{ Kind: 'object'; Members: ReadonlyMap<string, JsonNode> }> |
    Readonly<{ Kind: 'array'; Elements: readonly JsonNode[] }> |
    Readonly<{ Kind: 'string'; Text: string }> |
    Readonly<{ Kind: 'number' | 'boolean' | 'null' }>
);

export type JsonParseResult = Readonly<{ Ok: true; Value: JsonNode }> |
    Readonly<{ Ok: false; Message: string }>;

class JsonReader {
    private Offset = 0;
    private readonly Source: string;
    public constructor(Source: string) { this.Source = Source; }
    public Read(): JsonNode {
        const Value = this.Value(0);
        this.Whitespace();
        if (this.Offset !== this.Source.length) throw new Error('JSON 正文后存在额外内容');
        return Value;
    }
    private Whitespace(): void {
        while (/^[\t\n\r ]$/.test(this.Source[this.Offset] || '')) ++this.Offset;
    }
    private String(): Readonly<{ Raw: string; Text: string }> {
        const Start = this.Offset;
        if (this.Source[this.Offset++] !== '"') throw new Error('JSON 属性名必须为字符串');
        let Escaped = false;
        while (this.Offset < this.Source.length) {
            const Character = this.Source[this.Offset++];
            if (Escaped) { Escaped = false; continue; }
            if (Character === '\\') { Escaped = true; continue; }
            if (Character !== '"') continue;
            const Raw = this.Source.slice(Start, this.Offset);
            const Text: unknown = JSON.parse(Raw);
            if (typeof Text !== 'string') throw new Error('JSON 字符串无效');
            return { Raw, Text };
        }
        throw new Error('JSON 字符串没有结束');
    }
    private Value(Depth: number): JsonNode {
        if (Depth > 32) throw new Error('JSON 嵌套超过 32 层');
        this.Whitespace();
        const Start = this.Offset;
        const Character = this.Source[this.Offset];
        if (Character === '{') return this.Object(Depth);
        if (Character === '[') return this.Array(Depth);
        if (Character === '"') return { Kind: 'string', ...this.String() };
        const Match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(this.Source.slice(Start));
        if (Match === null) throw new Error('JSON 值无效');
        this.Offset += Match[0].length;
        if (Match[0] === 'null') return { Kind: 'null', Raw: Match[0] };
        if (Match[0] === 'true' || Match[0] === 'false') return { Kind: 'boolean', Raw: Match[0] };
        return { Kind: 'number', Raw: Match[0] };
    }
    private Object(Depth: number): JsonNode {
        const Start = this.Offset++;
        const Members = new Map<string, JsonNode>();
        this.Whitespace();
        if (this.Source[this.Offset] === '}') {
            ++this.Offset;
            return { Kind: 'object', Members, Raw: this.Source.slice(Start, this.Offset) };
        }
        for (;;) {
            this.Whitespace();
            const Key = this.String().Text;
            if (Members.has(Key)) throw new Error(`JSON 属性重复：${Key}`);
            this.Whitespace();
            if (this.Source[this.Offset++] !== ':') throw new Error('JSON 属性缺少冒号');
            Members.set(Key, this.Value(Depth + 1));
            this.Whitespace();
            const Separator = this.Source[this.Offset++];
            if (Separator === '}') break;
            if (Separator !== ',') throw new Error('JSON 对象分隔符无效');
        }
        return { Kind: 'object', Members, Raw: this.Source.slice(Start, this.Offset) };
    }
    private Array(Depth: number): JsonNode {
        const Start = this.Offset++;
        const Elements: JsonNode[] = [];
        this.Whitespace();
        if (this.Source[this.Offset] === ']') {
            ++this.Offset;
            return { Kind: 'array', Elements, Raw: this.Source.slice(Start, this.Offset) };
        }
        for (;;) {
            Elements.push(this.Value(Depth + 1));
            this.Whitespace();
            const Separator = this.Source[this.Offset++];
            if (Separator === ']') break;
            if (Separator !== ',') throw new Error('JSON 数组分隔符无效');
        }
        return { Kind: 'array', Elements, Raw: this.Source.slice(Start, this.Offset) };
    }
}

export function ParseJsonDocument(Input: Readonly<{ Text: string; MaxBytes: number }>): JsonParseResult {
    if (new TextEncoder().encode(Input.Text).length > Input.MaxBytes) {
        return { Ok: false, Message: 'JSON 正文超过实际字节预算' };
    }
    try { return { Ok: true, Value: new JsonReader(Input.Text).Read() }; }
    catch (ErrorValue: unknown) {
        let Message = 'JSON 正文无效';
        if (ErrorValue instanceof Error) Message = ErrorValue.message;
        return { Ok: false, Message };
    }
}

/** @brief 只排版原始 token，不把数值、SecretRef 或字段顺序转成另一套配置。 */
export function FormatJsonDocument(Value: JsonNode, Depth = 0): string {
    if (Value.Kind !== 'object' && Value.Kind !== 'array') return Value.Raw;
    const Pad = '  '.repeat(Depth);
    const InnerPad = `${Pad}  `;
    if (Value.Kind === 'object') {
        const Members = [...Value.Members].map(([Key, Member]) =>
            `${InnerPad}${JSON.stringify(Key)}: ${FormatJsonDocument(Member, Depth + 1)}`);
        if (Members.length === 0) return '{}';
        return `{\n${Members.join(',\n')}\n${Pad}}`;
    }
    const Elements = Value.Elements.map(Member => `${InnerPad}${FormatJsonDocument(Member, Depth + 1)}`);
    if (Elements.length === 0) return '[]';
    return `[\n${Elements.join(',\n')}\n${Pad}]`;
}
