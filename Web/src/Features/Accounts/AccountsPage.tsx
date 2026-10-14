import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { DecodeDecimal } from '../../Api/Decimal';
import { DecodeAccountsQuery } from '../../Api/OperationsApi';
import type { Account, Page } from '../../Api/OperationsApi';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { EmptyState, InlineCommandResult, QueryView, SectionHeading, StatusBadge, TrafficSummary } from '../../Components/ResultView';
import { HasCapability, useAdminServices, useCommandRunner } from '../UseOperations';

const PageSize = 100;

export default function AccountsPage(): ReactNode {
    const Services = useAdminServices();
    const Runner = useCommandRunner();
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const [FilterInput, SetFilterInput] = useState('');
    const [Filter, SetFilter] = useState('');
    const FilterValid = IsValidId(Filter);
    const FilterInputValid = IsValidId(FilterInput.trim());
    const Params = new URLSearchParams({ cursor: Cursor, limit: String(PageSize) });
    if (Filter.length > 0) Params.set('id', Filter);
    const Path = `/Operations/Accounts?${Params.toString()}`;
    const Query = useQuery({
        queryKey: ['accounts', Services.Bootstrap.Process, Services.Bootstrap.Incarnation, Cursor, Filter],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal, Decode: DecodeAccountsQuery }),
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
        enabled: FilterValid,
    });
    function ApplyFilter(Event: FormEvent<HTMLFormElement>): void {
        Event.preventDefault();
        const Value = FilterInput.trim();
        if (!IsValidId(Value)) return;
        SetHistory([]);
        SetCursor('0');
        SetFilter(Value);
    }
    function Next(Value: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(Value);
    }
    function Previous(): void {
        const Value = History[History.length - 1];
        if (Value === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(Value);
    }
    const CanRevoke = HasCapability(Services, 'accounts.revoke');
    return <>
        <SectionHeading Eyebrow="ACCOUNTS" Title="账户"
            Description="查看账户撤销状态、活动会话和流量；撤销时可选择是否同时关闭已有会话。" />
        <form className="toolbar" onSubmit={ApplyFilter} aria-label="账户查询条件">
            <label className="field">Account ID
                <input inputMode="numeric" value={FilterInput} onChange={Event => SetFilterInput(Event.target.value)}
                    placeholder="留空显示分页列表" aria-invalid={FilterInput.trim().length > 0 && !FilterInputValid} />
            </label>
            <button className="button button-secondary" type="submit">应用筛选</button>
        </form>
        {!FilterInputValid && <div className="notice notice-error" role="alert">Account ID 必须为大于 0 的 uint64 十进制字符串。</div>}
        {FilterValid && <section className="panel">
            <div className="panel-heading"><div><h2>账户快照</h2>
                <p>每 5 秒刷新；撤销确认会明确是否关闭已有 Session。</p></div></div>
            <div className="panel-body">
                <QueryView Query={Query} Label="账户列表" Children={Value => <AccountTable
                    Value={Value} CanRevoke={CanRevoke} Runner={Runner} OnNext={Next} /> } />
                <InlineCommandResult Result={Runner.Result} Process={Services.Bootstrap.Process} />
                {History.length > 0 && <button className="button button-secondary" onClick={Previous}>
                    上一页
                </button>}
            </div>
        </section>}
        {!FilterValid && <div className="notice notice-error" role="alert">Account ID 无效。</div>}
    </>;
}

function IsValidId(Value: string): boolean {
    if (Value.length === 0) return true;
    const Decoded = DecodeDecimal(Value);
    if (!Decoded.Ok) return false;
    return Decoded.Value !== '0';
}

function AccountTable(Input: Readonly<{
    Value: Page<Account>; CanRevoke: boolean; Runner: ReturnType<typeof useCommandRunner>;
    OnNext: (Cursor: string) => void;
}>): ReactNode {
    if (Input.Value.Items.length === 0) return <EmptyState Title="没有匹配的账户"
        Detail="当前筛选和分页范围内没有返回账户。" />;
    return <>
        <div className="data-table-wrap" role="region" tabIndex={0} aria-label="账户表格，可横向滚动">
            <table className="data-table">
            <thead><tr><th scope="col">Account</th><th scope="col">标签</th>
                <th scope="col">状态</th><th scope="col">活动 Session</th>
                <th scope="col">累计流量</th><th scope="col">操作</th></tr></thead>
            <tbody>{Input.Value.Items.map(AccountValue => <AccountRow key={AccountValue.Id}
                AccountValue={AccountValue} CanRevoke={Input.CanRevoke} Runner={Input.Runner} />)}</tbody>
        </table></div>
        <div className="pagination"><span>本页 {Input.Value.Items.length} 项
            {Input.Value.HasMore && ' · 存在后续页面'}</span>
            <button className="button button-secondary" disabled={!Input.Value.HasMore}
                onClick={() => Input.OnNext(Input.Value.NextCursor)}>下一页</button></div>
    </>;
}

function AccountRow(Input: Readonly<{
    AccountValue: Account; CanRevoke: boolean; Runner: ReturnType<typeof useCommandRunner>;
}>): ReactNode {
    const AccountValue = Input.AccountValue;
    let State = '已撤销';
    let Tone: 'good' | 'warn' = 'warn';
    if (!AccountValue.Revoked) {
        State = '未撤销';
        Tone = 'good';
    }
    async function Revoke(CloseSessions: boolean): Promise<unknown> {
        const CloseValue = String(CloseSessions);
        const Path = `/Operations/Accounts/${AccountValue.Id}/Revoke?close_sessions=${CloseValue}`;
        let Target = `账户 ${AccountValue.Id}，保留现有会话`;
        if (CloseSessions) Target = `账户 ${AccountValue.Id}，并关闭现有会话`;
        return Input.Runner.Submit({ Path, Body: null, Label: '账户撤销', Target });
    }
    async function KeepSessions(): Promise<unknown> {
        return Revoke(false);
    }
    async function CloseSessions(): Promise<unknown> {
        return Revoke(true);
    }
    return <tr>
        <td className="mono">{AccountValue.Id}</td><td>{AccountValue.Label || '未命名'}</td>
        <td><StatusBadge Label={State} Tone={Tone} /></td>
        <td className="mono">{AccountValue.ActiveSessions}</td>
        <td><TrafficSummary Value={AccountValue.Traffic} /></td>
        <td>{Input.CanRevoke && !AccountValue.Revoked && <div className="button-row">
            <ConfirmAction Label="撤销并保留会话" Title="撤销账户，保留现有会话？"
                Description={`账户 ${AccountValue.Id} 将被撤销，已有 Session 会继续存在。`}
                ConfirmLabel="撤销并保留" Tone="danger"
                Busy={Input.Runner.IsPending} OnConfirm={KeepSessions} />
            <ConfirmAction Label="撤销并关闭会话" Title="撤销账户并关闭现有会话？"
                Description={`账户 ${AccountValue.Id} 将被撤销，并请求关闭 ${AccountValue.ActiveSessions} 个活动会话。`}
                ConfirmLabel="撤销并关闭" Tone="danger"
                Busy={Input.Runner.IsPending} OnConfirm={CloseSessions} />
        </div>}{!Input.CanRevoke && <small className="muted">当前服务不允许撤销账户</small>}
            {Input.CanRevoke && AccountValue.Revoked && <small className="muted">账户已撤销</small>}</td>
    </tr>;
}
