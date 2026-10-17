import type { EventRecord, SessionIdentity } from '../Services/AdminDataSource';

/** @brief 连接深链保留完整复合身份，不用单个 Session ID 代替连接身份。 */
export function SessionPath(Value: SessionIdentity): string {
    const Params = new URLSearchParams({ session: Value.Id, process: Value.ProcessId, generation: Value.GenerationId,
        identity_worker: Value.WorkerId, identity_account: Value.AccountId });
    return `/sessions?${Params}`;
}

/** @brief 事件只携带部分身份时保留已有字段，不生成缺失身份。 */
export function EventSessionPath(Value: EventRecord): string {
    const Params = new URLSearchParams({ session: Value.SessionId ?? '', process: Value.ProcessId, generation: Value.GenerationId });
    if (Value.WorkerId) Params.set('identity_worker', Value.WorkerId);
    if (Value.AccountId) Params.set('identity_account', Value.AccountId);
    return `/sessions?${Params}`;
}
