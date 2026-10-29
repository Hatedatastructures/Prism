/**
 * @file GroupOperationSettlement.ts
 * @brief 用户组配置命令复用操作中心状态，直到核实终态后才解锁后续提交。
 */
import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';

import type { AdminActionResult, OperationRecord, OperationStatus } from '../../Services/AdminDataSource';
import { useAdminServices } from '../UseOperations';

export type GroupOperationSettlement = Readonly<{
    Pending: boolean;
    NeedsReview: boolean;
}>;

/** @brief 观察与 ActionFeedback 相同 query key 的操作终态，身份不完整或不匹配时保持未决。 */
export function useGroupOperationSettlement(Result: AdminActionResult | undefined): GroupOperationSettlement {
    const Services = useAdminServices();
    const OperationId = Result?.OperationId ?? Result?.Operation?.Id ?? null;
    const Scope = Result?.OperationScope;
    const HasScope = !!Scope?.ProcessId && !!Scope.Incarnation;
    const HasIdMismatch = Result?.OperationId != null && Result.Operation != null &&
        Result.OperationId !== Result.Operation.Id;
    const InitialState = Result?.Status ?? Result?.Operation?.State;
    const InitialTerminal = IsKnownTerminal(InitialState);
    const CanVerify = !!Result && !InitialTerminal && !HasIdMismatch && !!OperationId && HasScope;
    const [StartedAt, SetStartedAt] = useState(() => Date.now());

    useEffect(() => SetStartedAt(Date.now()), [OperationId, Scope?.ProcessId, Scope?.Incarnation]);

    const Query = useQuery<OperationRecord, Error>({
        queryKey: ['operations', 'operation-status', Scope?.ProcessId, Scope?.Incarnation, OperationId],
        enabled: CanVerify,
        retry: false,
        queryFn: () => {
            if (!OperationId || !Scope || !Scope.ProcessId || !Scope.Incarnation) {
                throw new Error('操作身份不完整，无法核对用户组配置结果');
            }
            return Services.Data.GetOperationStatus(OperationId, Scope);
        },
        refetchInterval: State => {
            const ErrorCode = (State.state.error as { Code?: string } | null)?.Code;
            if (ErrorCode === 'operation-scope-changed') return false;
            const Operation = State.state.data;
            if (!State.state.error && Operation !== undefined && Operation.Id === OperationId &&
                (Operation.ProcessId == null || Operation.ProcessId === Scope?.ProcessId) && IsKnownTerminal(Operation.State)) return false;
            return Date.now() - StartedAt < 30_000 ? 1_000 : 5_000;
        },
        refetchIntervalInBackground: false,
    });

    const Operation = Query.data;
    const OperationMatches = Operation !== undefined && Operation.Id === OperationId &&
        (Operation.ProcessId == null || Operation.ProcessId === Scope?.ProcessId);
    const VerifiedState = OperationMatches ? Operation?.State : undefined;
    const VerifiedTerminal = HasScope && !Query.error && IsKnownTerminal(VerifiedState);
    const QueryIdentityMismatch = Operation !== undefined && !OperationMatches;
    const Pending = !!Result && (HasIdMismatch || QueryIdentityMismatch || (!InitialTerminal && !VerifiedTerminal));
    const EffectiveState = VerifiedState ?? InitialState;
    const NeedsReview = Pending && (HasIdMismatch || QueryIdentityMismatch || !OperationId || !HasScope ||
        !!Query.error || EffectiveState === undefined || EffectiveState === 'unknown' || EffectiveState === 'interrupted');

    return { Pending, NeedsReview };
}

/** @brief 只有明确的完成或失败状态才表示配置命令已退出未决阶段。 */
function IsKnownTerminal(State: OperationStatus | undefined): boolean {
    return State !== undefined && State !== 'accepted' && State !== 'running' &&
        State !== 'unknown' && State !== 'interrupted';
}
