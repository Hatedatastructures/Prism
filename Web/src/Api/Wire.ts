import type { AdminActionResult, BootstrapSnapshot, CursorPage, OperationRecord, OperationStatus, TracePage } from '../Services/AdminDataSource.ts';
import { TraceStageLabel } from './TraceIdentity.ts';

export type WireRecord = Record<string, unknown>;
export function RecordValue(Value: unknown): WireRecord {
    if (!Value || typeof Value !== 'object' || Array.isArray(Value)) throw new Error('管理接口返回了无效对象');
    return Value as WireRecord;
}
export function Text(Value: unknown): string {
    if (typeof Value !== 'string') throw new Error('管理接口文本字段不符合合同');
    return Value;
}
export function NullableText(Value: unknown): string | null { return Value === undefined || Value === null ? null : Text(Value); }
export function Decimal(Value: unknown): string {
    if (typeof Value !== 'string' || !/^(0|[1-9]\d*)$/.test(Value) || BigInt(Value) > 18446744073709551615n)
        throw new Error('64 位值必须是合法的无符号十进制文本');
    return Value;
}
export function NullableDecimal(Value: unknown): string | null { return Value === null || Value === undefined ? null : Decimal(Value); }
export function OptionalId(Value: unknown): string | null { const Id = NullableDecimal(Value); return Id === '0' ? null : Id; }
export function Bool(Value: unknown): boolean {
    if (typeof Value !== 'boolean') throw new Error('管理接口布尔字段不符合合同');
    return Value;
}
export function List(Value: unknown): unknown[] {
    if (!Array.isArray(Value)) throw new Error('管理接口列表字段不符合合同');
    return Value;
}
export function FailureText(Value: unknown): string | null {
    if (Value === undefined || Value === null) return null;
    const Item = RecordValue(Value);
    return `${Text(Item.code)}${Item.native_category ? ` (${Text(Item.native_category)}:${String(Item.native_value)})` : ''}`;
}
export function DecodeBootstrap(Value: unknown): BootstrapSnapshot & Readonly<{ CommandToken: string }> {
    const Item = RecordValue(Value);
    if (Item.api_version !== '2') throw new Error('Operations API 版本不匹配，需要版本 2');
    if (typeof Item.instance_key !== 'string' || !Item.instance_key.trim()) throw new Error('Bootstrap instance_key 字段无效');
    if (typeof Item.process_incarnation !== 'string' || !/^[0-9a-f]{32}$/i.test(Item.process_incarnation)) throw new Error('Bootstrap process_incarnation 字段无效');
    if (typeof Item.command_token !== 'string' || !/^[0-9a-f]{64}$/i.test(Item.command_token)) throw new Error('Bootstrap command_token 字段无效');
    return { ApiVersion: '2', InstanceKey: Text(Item.instance_key), ProcessId: Decimal(Item.process_id),
        Incarnation: Text(Item.process_incarnation), CommandToken: Text(Item.command_token),
        Capabilities: List(Item.capabilities).map(Text) };
}
export function DecodePage<Value>(Input: unknown, Decode: (Item: unknown) => Value): CursorPage<Value> {
    const Page = RecordValue(Input);
    return { Items: List(Page.items).map(Decode), NextCursor: Text(Page.next_cursor), HasMore: Bool(Page.has_more) };
}
export function DecodeTracePage(Input: unknown): TracePage {
    const Page = RecordValue(Input);
    return { ...DecodePage(Page, Value => {
        const Item = RecordValue(Value);
        const Attributes = RecordValue(Item.attributes);
        return { SpanId: Text(Item.span_id), ParentSpanId: NullableText(Item.parent_span_id), Sequence: Decimal(Item.sequence),
            Name: TraceStageLabel(Text(Item.name)), StartTime: Text(Item.start_time), DurationMs: NullableDecimal(Item.duration_ms),
            Status: Text(Item.status), SessionId: Decimal(Item.session), WorkerId: NullableDecimal(Item.worker),
            AccountId: NullableDecimal(Item.account), TaskId: NullableDecimal(Item.task), ParentTaskId: NullableDecimal(Item.parent_task),
            StreamId: NullableDecimal(Item.stream), Attributes: Object.fromEntries(Object.entries(Attributes).map(([Key, Value]) =>
                [Key, Value === null || typeof Value === 'string' || typeof Value === 'boolean' ? Value : String(Value)])) };
    }), Lost: Bool(Page.lost), Cursors: List(Page.cursors).map(Value => {
        const Item = RecordValue(Value); return { WorkerId: Decimal(Item.worker_id), Sequence: Decimal(Item.sequence) };
    }), Loss: List(Page.lost_ranges).map(Value => {
        const Item = RecordValue(Value); return { WorkerId: Decimal(Item.worker_id), Overwritten: Decimal(Item.overwritten),
            LostSinceCursor: Decimal(Item.lost_since_cursor), ConcurrentReadSkips: Decimal(Item.concurrent_read_skips) };
    }) };
}
const OperationStates: readonly string[] = ['accepted', 'completed', 'rejected', 'unavailable', 'failed', 'timed_out', 'blocked', 'restart_required', 'conflict', 'invalid', 'interrupted'];
export function DecodeOperation(Input: unknown): OperationRecord {
    const Item = RecordValue(Input);
    const State = Text(Item.status);
    if (!OperationStates.includes(State)) throw new Error('操作状态不符合合同');
    const Command = NullableText(Item.command) ?? '管理命令';
    const TargetScope = [['task', 'Task'], ['stream', 'Stream'], ['session', 'Session'], ['worker', 'Worker'], ['account', '账户'], ['process', '进程']]
        .find(([Key]) => Key !== undefined && Item[Key] !== undefined && Item[Key] !== null && Item[Key] !== '0');
    const Target = TargetScope?.[0] ? `${TargetScope[1]} ${Text(Item[TargetScope[0]])}` : '进程';
    return { Id: Decimal(Item.id ?? Item.operation), Name: Command, Target, State: State as OperationStatus,
        StartedAt: NullableText(Item.accepted_at), UpdatedAt: NullableText(Item.updated_at), Message: NullableText(Item.message) ?? '',
        CorrelationId: NullableDecimal(Item.correlation) ?? '', GenerationId: NullableDecimal(Item.generation), Failure: FailureText(Item.failure),
        ProcessId: OptionalId(Item.process), WorkerId: OptionalId(Item.worker), AccountId: OptionalId(Item.account),
        SessionId: OptionalId(Item.session), StreamId: OptionalId(Item.stream), TaskId: OptionalId(Item.task), ParentTaskId: OptionalId(Item.parent_task) };
}
export function DecodeCommand(Input: unknown): AdminActionResult {
    const Item = RecordValue(Input);
    const Operation = Item.operation && Item.operation !== '0' ? DecodeOperation(Item) : null;
    const State = Text(Item.status);
    if (!OperationStates.includes(State)) throw new Error('操作状态不符合合同');
    return { Ok: State === 'accepted' || State === 'completed', Status: State as OperationStatus,
        Operation, OperationId: Operation?.Id ?? null, Message: NullableText(Item.message) ?? State, Failure: FailureText(Item.failure),
        ConfigurationIssues: Item.configuration_issues ? List(Item.configuration_issues).map(Value => {
            const Issue = RecordValue(Value); return { Code: Text(Issue.code), Path: Text(Issue.path), Message: Text(Issue.message) };
        }) : [], RestartRequiredFields: Item.restart_required_fields ? List(Item.restart_required_fields).map(Text) : [] };
}
