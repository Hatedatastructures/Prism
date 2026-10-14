import { useSyncExternalStore } from 'react';
import type { Bootstrap } from '../../Api/Bootstrap';
import { DecodeDecimal } from '../../Api/Decimal';
import type { Decimal } from '../../Api/Decimal';

const StorageKey = 'prism-preview-operation-tickets-v1';
const MaximumTickets = 1024;
const MaximumStorageChars = 262144;
export type OperationTicket = Readonly<{
    Process: Decimal; Incarnation: string; Operation: Decimal; Label: string;
    Target: string; RecordedAt: string;
}>;
type StoredTickets = Readonly<{ Version: 1; Process: string; Incarnation: string; Tickets: readonly unknown[] }>;
type StoredRead = Readonly<{ Tickets: readonly OperationTicket[]; Notice: string | null }>;
let Current: readonly OperationTicket[] = [];
let CurrentNotice = '';
let BoundIdentity = '';
const Listeners = new Set<() => void>();

function Notify(): void {
    for (const Listener of Listeners) Listener();
}

function Identity(Bootstrap: Bootstrap): string {
    return `${Bootstrap.Process}:${Bootstrap.Incarnation}`;
}

function ReadTicket(Input: unknown, Bootstrap: Bootstrap): OperationTicket | null {
    if (Input === null || typeof Input !== 'object' || Array.isArray(Input)) return null;
    const Value = Input as Record<string, unknown>;
    const Operation = DecodeDecimal(Value.Operation);
    if (Value.Process !== Bootstrap.Process || Value.Incarnation !== Bootstrap.Incarnation ||
        !Operation.Ok || Operation.Value === '0' || typeof Value.Label !== 'string' ||
        typeof Value.Target !== 'string' || typeof Value.RecordedAt !== 'string') return null;
    return { Process: Bootstrap.Process, Incarnation: Bootstrap.Incarnation,
        Operation: Operation.Value, Label: Value.Label,
        Target: Value.Target, RecordedAt: Value.RecordedAt };
}

function EmptyStored(Notice: string): StoredRead {
    return { Tickets: [], Notice };
}

function ReadStored(Bootstrap: Bootstrap): StoredRead {
    let Text: string | null = null;
    try {
        Text = window.sessionStorage.getItem(StorageKey);
    } catch {
        return EmptyStored('浏览器会话存储无法读取；此标签页不能恢复已保存的操作编号。');
    }
    if (Text === null) return { Tickets: [], Notice: null };
    if (Text.length > MaximumStorageChars) {
        return RemoveStored('已保存的操作记录超过恢复上限，未恢复其中的编号。');
    }
    let Parsed: unknown;
    try {
        Parsed = JSON.parse(Text);
    } catch {
        return EmptyStored('已保存的操作记录无法解析，因此未恢复其中的编号。');
    }
    if (Parsed === null || typeof Parsed !== 'object' || Array.isArray(Parsed)) {
        return EmptyStored('已保存的操作记录格式无效，因此未恢复其中的编号。');
    }
    const Value = Parsed as Partial<StoredTickets>;
    if (Value.Version !== 1) {
        return EmptyStored('已保存的操作记录格式不受支持，因此未恢复其中的编号。');
    }
    if (typeof Value.Process !== 'string' || typeof Value.Incarnation !== 'string') {
        return EmptyStored('已保存的操作记录缺少进程信息，因此未恢复其中的编号。');
    }
    if (Value.Process !== Bootstrap.Process || Value.Incarnation !== Bootstrap.Incarnation) {
        return RemoveStored('管理进程已重启或更换；旧操作编号已清除，没有套用旧进度。');
    }
    if (!Array.isArray(Value.Tickets) || Value.Tickets.length > MaximumTickets) {
        return EmptyStored('已保存的操作记录列表无效，因此未恢复其中的编号。');
    }
    const Tickets = Value.Tickets.map(Item => ReadTicket(Item, Bootstrap));
    if (Tickets.some(Item => Item === null)) {
        return EmptyStored('已保存记录中包含无效的操作编号，因此未恢复任何记录。');
    }
    return { Tickets: Tickets as OperationTicket[], Notice: null };
}

function RemoveStored(Notice: string): StoredRead {
    try {
        window.sessionStorage.removeItem(StorageKey);
        return EmptyStored(Notice);
    } catch {
        return EmptyStored(`${Notice} 浏览器未能清除旧记录。`);
    }
}

function Persist(): void {
    if (BoundIdentity.length === 0) return;
    try {
        const [Process, Incarnation] = BoundIdentity.split(':');
        const Value = JSON.stringify({ Version: 1, Process, Incarnation, Tickets: Current });
        window.sessionStorage.setItem(StorageKey, Value);
    } catch {
        CurrentNotice = '浏览器会话存储无法写入；关闭或刷新后可能无法恢复操作进度。';
    }
}

export function Bind(Bootstrap: Bootstrap): void {
    const NextIdentity = Identity(Bootstrap);
    if (BoundIdentity === NextIdentity) return;
    const Stored = ReadStored(Bootstrap);
    Current = Stored.Tickets;
    BoundIdentity = NextIdentity;
    CurrentNotice = Stored.Notice || '';
    Persist();
    Notify();
}

export function Add(Ticket: OperationTicket): void {
    if (`${Ticket.Process}:${Ticket.Incarnation}` !== BoundIdentity) return;
    Current = [Ticket, ...Current.filter(Item => Item.Operation !== Ticket.Operation)].slice(0, MaximumTickets);
    Persist();
    Notify();
}

export function Remove(Operation: Decimal): void {
    Current = Current.filter(Item => Item.Operation !== Operation);
    Persist();
    Notify();
}

export function GetTickets(): readonly OperationTicket[] {
    return Current;
}

export function GetNotice(): string {
    return CurrentNotice;
}

export function Subscribe(Listener: () => void): () => void {
    Listeners.add(Listener);
    return () => Listeners.delete(Listener);
}

export function useOperationTickets(): readonly OperationTicket[] {
    return useSyncExternalStore(Subscribe, GetTickets, GetTickets);
}

export function useOperationNotice(): string {
    return useSyncExternalStore(Subscribe, GetNotice, GetNotice);
}
