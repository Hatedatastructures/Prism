import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { AlertCircle, Check, RefreshCw } from 'lucide-react';

type RefreshState = 'idle' | 'pending' | 'success' | 'error';

/** @brief 刷新概览数据，并反馈本次手动刷新的结果。 */
export function OverviewRefresh(Input: Readonly<{
    OnRefresh: () => Promise<boolean>;
    Busy: boolean;
}>): ReactNode {
    const [State, SetState] = useState<RefreshState>('idle');

    useEffect(() => {
        if (State !== 'success') return;
        const Timer = window.setTimeout(() => SetState('idle'), 3_000);
        return () => window.clearTimeout(Timer);
    }, [State]);

    const HandleRefresh = async (): Promise<void> => {
        SetState('pending');
        try {
            SetState(await Input.OnRefresh() ? 'success' : 'error');
        } catch {
            SetState('error');
        }
    };

    const Icon = State === 'success' ? Check : State === 'error' ? AlertCircle : RefreshCw;
    const Label = State === 'pending' ? '刷新中' : State === 'success' ? '已更新'
        : State === 'error' ? '刷新失败' : '刷新';
    const StatusMessage = State === 'success' ? '刷新成功'
        : State === 'error' ? '刷新失败，请重试。' : '';
    return <>
        <button type="button" className="button button-secondary overview-refresh-button"
            data-refresh-state={State} disabled={Input.Busy || State === 'pending'}
            onClick={() => { void HandleRefresh(); }}>
            <Icon size={15} className={State === 'pending' ? 'spin' : ''} aria-hidden="true" />{Label}
        </button>
        <span className="sr-only overview-refresh-feedback" role="status" aria-live="polite"
            aria-atomic="true">{StatusMessage}</span>
    </>;
}
