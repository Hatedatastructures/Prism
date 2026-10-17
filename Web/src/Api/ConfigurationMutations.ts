import { ParseJsonDocument } from './JsonDocument.ts';
import type { JsonNode } from './JsonDocument.ts';

type Change = Readonly<{ Kind: 'create-group'; Name: string }> | Readonly<{ Kind: 'rename-group'; Id: string; Name: string }> |
    Readonly<{ Kind: 'account-group'; Id: string; GroupId: string | null }> |
    Readonly<{ Kind: 'account-policy' | 'group-policy'; Id: string; Policy: string }>;
function ObjectText(Node: JsonNode, Replace: ReadonlyMap<string, string | null>): string {
    if (Node.Kind !== 'object') throw new Error('配置项必须是对象');
    const Entries = [...Node.Members].filter(([Key]) => !Replace.has(Key)).map(([Key, Value]) => `${JSON.stringify(Key)}:${Value.Raw}`);
    for (const [Key, Value] of Replace) if (Value !== null) Entries.push(`${JSON.stringify(Key)}:${Value}`);
    return `{${Entries.join(',')}}`;
}
function Identifier(Node: JsonNode): string {
    if (Node.Kind !== 'object') throw new Error('配置项必须是对象');
    const Id = Node.Members.get('Id');
    if (!Id || Id.Kind !== 'string') throw new Error('配置项缺少 Id');
    return Id.Text;
}
/** @brief 修改目标字段，保留其余原始 JSON token，避免 uint64 和保密字段损失。 */
export function ChangeConfiguration(Text: string, Input: Change): string {
    const Parsed = ParseJsonDocument({ Text, MaxBytes: 256 * 1024 });
    if (!Parsed.Ok || Parsed.Value.Kind !== 'object') throw new Error('公开配置不是有效对象');
    const Root = Parsed.Value;
    const Field = Input.Kind === 'account-group' || Input.Kind === 'account-policy' ? 'Accounts' : 'AccountGroups';
    const Array = Root.Members.get(Field);
    if (!Array || Array.Kind !== 'array') throw new Error(`配置快照缺少 ${Field}，请先修复服务端配置合同`);
    const Values: string[] = [];
    let Found = false;
    for (const Value of Array.Elements) {
        if (Input.Kind === 'create-group' || Identifier(Value) !== Input.Id) { Values.push(Value.Raw); continue; }
        Found = true;
        if (Input.Kind === 'rename-group') Values.push(ObjectText(Value, new Map([['Name', JSON.stringify(Input.Name.trim())]])));
        else if (Input.Kind === 'account-group') Values.push(ObjectText(Value, new Map([['GroupId', Input.GroupId === null ? null : JSON.stringify(Input.GroupId)]])));
        else {
            const Policy = ParseJsonDocument({ Text: Input.Policy, MaxBytes: 16 * 1024 });
            if (!Policy.Ok || Policy.Value.Kind !== 'object') throw new Error('策略必须是有效 JSON 对象');
            Values.push(ObjectText(Value, new Map([['Policy', Policy.Value.Raw]])));
        }
    }
    if (Input.Kind === 'create-group') {
        if (!Input.Name.trim()) throw new Error('用户组名称不能为空');
        Values.push(JSON.stringify({ Id: crypto.randomUUID(), Name: Input.Name.trim() }));
    } else if (!Found) throw new Error('目标配置项已不存在，请重新加载');
    return ObjectText(Root, new Map([[Field, `[${Values.join(',')}]`]]));
}
