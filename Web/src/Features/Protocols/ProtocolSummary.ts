import type { ProtocolRecord } from '../../Services/AdminDataSource';

/** @brief 按类型去重后汇总当前可用计数；冲突和缺测不能伪装成完整值。 */
export function SummarizeProtocols(Rows: readonly ProtocolRecord[], HasMore: boolean): Readonly<{ Types: number; Active: string | null; Partial: boolean }> {
    const HasExplicitKinds = Rows.some(Row => Row.Kind !== undefined);
    const Candidates = HasExplicitKinds ? Rows.filter(Row => Row.Kind === 'type') : Rows;
    const Types = new Map<string, bigint | null>();
    let Conflict = false;
    for (const Row of Candidates) {
        const Key = (Row.TypeKey ?? Row.Name).toLocaleLowerCase();
        const Count = Row.ActiveSessions === null ? null : BigInt(Row.ActiveSessions);
        if (Types.has(Key) && Types.get(Key) !== Count) Conflict = true;
        else Types.set(Key, Count);
    }
    const Values = [...Types.values()];
    const Partial = HasMore || Values.some(Value => Value === null) || HasExplicitKinds && Candidates.length === 0 && Rows.length > 0;
    return { Types: Types.size, Active: Conflict || Values.length === 0 || Values.every(Value => Value === null) ? null :
        Values.reduce<bigint>((Sum, Value) => Sum + (Value ?? 0n), 0n).toString(), Partial };
}
