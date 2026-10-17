import type { To } from 'react-router';

/** @brief 保留适用时间与显式演示选择；目标已经指定的参数优先，hash 与对象路径不丢失。 */
export function ResourceDestination(Target: To, Current: URLSearchParams): To {
    if (typeof Target === 'string') {
        if (/^[a-z][a-z\d+.-]*:/i.test(Target) || Target.startsWith('//')) return Target;
        const HashIndex = Target.indexOf('#');
        const Hash = HashIndex < 0 ? '' : Target.slice(HashIndex);
        const Path = HashIndex < 0 ? Target : Target.slice(0, HashIndex);
        const QueryIndex = Path.indexOf('?');
        const Params = new URLSearchParams(QueryIndex < 0 ? '' : Path.slice(QueryIndex + 1));
        Merge(Params, Current);
        return `${QueryIndex < 0 ? Path : Path.slice(0, QueryIndex)}${Params.size ? `?${Params}` : ''}${Hash}`;
    }
    const Params = new URLSearchParams(Target.search);
    Merge(Params, Current);
    return { ...Target, search: Params.size ? `?${Params}` : '' };
}
function Merge(Target: URLSearchParams, Current: URLSearchParams): void {
    const HasTime = ['range', 'from', 'to'].some(Key => Target.has(Key));
    if (!HasTime) for (const Key of ['range', 'from', 'to']) {
        const Value = Current.get(Key); if (Value !== null) Target.set(Key, Value);
    }
    if (!Target.has('source') && Current.has('source')) Target.set('source', Current.get('source') ?? '');
}
