import { TimeLink as Link } from '../TimeLink';
import * as Tabs from '@radix-ui/react-tabs';
import { FilterScopeNotice } from '../FilterScopeNotice';
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, Search } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { SelectField } from '../../Components/SelectField';
import {
    Badge, EmptyState, FormatBytes, FormatCount, LoadMoreButton, PageHeader, Panel, QueryState,
    StatusBadge, ToneForState,
} from '../../Components/Ui';
import type { AccountRecord, GroupRecord, SessionRecord } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery } from '../UseOperations';
import { TimeRangeControl } from '../TimeRange';
import { HistoryPanel } from '../HistoryPanel';
import { AccountUsagePanel } from './AccountUsagePanel';
import { PolicyEditor } from '../PolicyEditor';
import { ActionFeedback } from '../ActionFeedback';

export default function AccountsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const AccountsQuery = useAdminInfiniteQuery('accounts', (Source, Page) => Source.GetAccounts(Page));
    const GroupsQuery = useAdminInfiniteQuery('groups', (Source, Page) => Source.GetGroups(Page));
    const SessionsQuery = useAdminInfiniteQuery('sessions', (Source, Page) => Source.GetSessions(Page));
    const Revoke = useAdminMutation((Source, Input: Readonly<{ Id: string; CloseSessions: boolean }>) =>
        Source.RevokeAccount(Input.Id, Input.CloseSessions));
    const Accounts = AccountsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Groups = GroupsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Sessions = SessionsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const SearchText = Params.get('q') ?? '';
    const SelectedId = Params.get('account') ?? '';
    const StateFilter = Params.get('state') ?? 'all';
    const [CloseSessions, SetCloseSessions] = useState(true);
    const Update = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'q' });
    };
    const Filtered = useMemo(() => Accounts.filter(Account => {
        const Match = !SearchText || `${Account.Id} ${Account.Label} ${Account.GroupId ?? ''}`.toLowerCase().includes(SearchText.toLowerCase());
        return Match && (StateFilter === 'all' || StateFilter === 'revoked' && Account.Revoked ||
            StateFilter === 'active' && !Account.Revoked && Number(Account.ActiveSessions) > 0);
    }), [Accounts, SearchText, StateFilter]);
    const Exact = useAdminQuery('account-target', Source => Source.GetAccounts({ Cursor: '0', Limit: 1, Id: SelectedId }), { Enabled: !!SelectedId, Scope: [SelectedId] });
    const Selected = SelectedId ? Accounts.find(Account => Account.Id === SelectedId) ?? Exact.data?.Items.find(Account => Account.Id === SelectedId) ?? null : Filtered[0] ?? null;
    const Active = Accounts.filter(Account => !Account.Revoked).length;
    const Connected = Accounts.filter(Account => !Account.Revoked && Number(Account.ActiveSessions) > 0).length;
    const SelectedSessions = Sessions.filter(Session => Session.AccountId === Selected?.Id);
    const Group = Groups.find(Value => Value.Id === Selected?.GroupId) ?? null;

    return <>
        <PageHeader Title="代理账户"
            Description="认证身份、活动连接与流量，一处管理"
            Actions={<><TimeRangeControl /><Badge Tone="accent" Dot>{Accounts.length}{AccountsQuery.hasNextPage ? '+' : ''} 个已载入账户</Badge></>} />
        <div className="page-metric-strip" aria-label="账户状态汇总">
            <AccountMetric Label="有效账户" Value={FormatCount(Active)} Hint="不含已撤销账户" />
            <AccountMetric Label="有根连接租约" Value={FormatCount(Connected)} Hint="当前已载入账户" />
            <AccountMetric Label="已撤销" Value={FormatCount(Accounts.filter(Account => Account.Revoked).length)} Hint="当前已载入范围" />
            <AccountMetric Label="用户组" Value={FormatCount(Groups.length)} Hint="默认策略由账户逐项覆盖" />
        </div>
        <section className="account-layout">
            <div className="account-directory-column"><Panel Title="账户目录">
                <div className="toolbar">
                    <label className="search-field"><Search size={17} aria-hidden="true" /><input aria-label="搜索账户" placeholder="搜索账户 ID、名称或组…"
                        value={SearchText} onChange={Event => Update('q', Event.target.value)} /></label>
                    <SelectField Label="按账户状态筛选" Value={StateFilter} OnChange={Value => Update('state', Value)}
                        Options={[{ Value: 'all', Label: '全部状态' }, { Value: 'active', Label: '活动账户' }, { Value: 'revoked', Label: '已撤销' }]} />
                </div>
                <FilterScopeNotice Collection="accounts" />
                <QueryState Pending={AccountsQuery.isPending} Error={AccountsQuery.error} Label="账户目录" HasData={AccountsQuery.data !== undefined}
                    Children={Filtered.length === 0 ? <EmptyState Title="没有匹配账户" Detail="更改搜索或状态筛选后重试。" /> : <>
                        <div className="account-table-wrap table-scroll"><table className="data-table account-table">
                            <thead><tr><th scope="col">账户</th><th scope="col">用户组</th><th scope="col">根连接租约</th><th scope="col">流量 ↑ / ↓</th><th scope="col">状态</th></tr></thead>
                            <tbody>{Filtered.map(Account => <AccountRow key={Account.Id} Value={Account} Group={Groups.find(Item => Item.Id === Account.GroupId) ?? null}
                                Selected={Account.Id === Selected?.Id} OnSelect={() => Update('account', Account.Id)} />)}</tbody>
                        </table></div>
                        <LoadMoreButton HasMore={AccountsQuery.hasNextPage ?? false} Busy={AccountsQuery.isFetchingNextPage}
                            OnLoad={() => void AccountsQuery.fetchNextPage()} />
                        <p className="table-footnote">已显示 {Filtered.length} 条{AccountsQuery.hasNextPage ? '，可继续载入' : '记录'}</p>
                    </>} />
            </Panel>
            </div>
            {Selected && <Panel ClassName="detail-panel account-inspector" Title="账户详情"
                Action={<StatusBadge Label={Selected.Revoked ? '已撤销' : '有效'} Tone={ToneForState(Selected.Revoked ? 'revoked' : 'active')} />}>
                <div className="account-profile"><span className="account-profile-copy"><strong>{Selected.Label}</strong><small>{Selected.Id}</small></span></div>
                <div className="account-context"><span>{Group?.Name ?? '未分组'}</span><span>Generation {Selected.GenerationId}</span><span>{FormatCount(Selected.ActiveSessions)} 根连接租约</span></div>
                <Tabs.Root defaultValue="usage" key={Selected.Id} className="account-detail-tabs">
                    <Tabs.List className="detail-tabs" aria-label="账户详情视图"><Tabs.Trigger value="usage">用量</Tabs.Trigger><Tabs.Trigger value="policy">策略</Tabs.Trigger><Tabs.Trigger value="connections">连接</Tabs.Trigger><Tabs.Trigger value="history">趋势</Tabs.Trigger></Tabs.List>
                    <Tabs.Content value="usage"><AccountUsagePanel Account={Selected} /></Tabs.Content>
                    <Tabs.Content value="policy"><PolicyEditor Kind="account-policy" Id={Selected.AccountKey ?? Selected.Label} Title="有效策略与来源" Effective={Selected.EffectivePolicy ?? null} Sources={Selected.PolicySources ?? {}} /></Tabs.Content>
                    <Tabs.Content value="connections"><dl className="detail-kv"><div><dt>根连接租约</dt><dd>{FormatCount(Selected.ActiveSessions)}</dd></div>
                        {Selected.ActiveStreams !== null && Selected.ActiveStreams !== undefined && <div><dt>子流租约</dt><dd>{FormatCount(Selected.ActiveStreams)}</dd></div>}
                        <div><dt>累计上行</dt><dd>{FormatBytes(Selected.Traffic?.Up)}</dd></div><div><dt>累计下行</dt><dd>{FormatBytes(Selected.Traffic?.Down)}</dd></div></dl>
                        <div className="account-session-block"><div className="section-heading"><h2>已载入 Session</h2><Link className="text-link" to={'/sessions?account=' + encodeURIComponent(Selected.Id)}>查看追踪 <ArrowRight size={13} /></Link></div><AccountSessionList Sessions={SelectedSessions} /></div>
                    </Tabs.Content>
                    <Tabs.Content value="history"><p className="field-hint">时间范围只影响此历史图；用量视图显示的本周期账本快照不会随时间范围变化。</p>
                        <HistoryPanel Scope="account" ResourceKey={Selected.AccountKey ?? Selected.Id}
                            Title={`${Selected.Label} · ${Selected.Id} 流量历史`} />
                    </Tabs.Content>
                </Tabs.Root>
                {!Selected.Revoked && <div className="account-access-actions"><label className="check-row"><input type="checkbox" checked={CloseSessions} onChange={Event => SetCloseSessions(Event.target.checked)} /><span>撤销时关闭活动连接</span></label>
                    <ConfirmAction Label="撤销账户" Title={'撤销 ' + Selected.Label + '？'} Description={CloseSessions ? '阻止后续认证，并请求关闭关联 Session；已受理后继续核对实际结果。' : '阻止后续认证与新增子流，现有 Session 按当前生命周期运行。'} ConfirmLabel="确认撤销" Tone="danger" Busy={Revoke.isPending} OnConfirm={() => Revoke.mutateAsync({ Id: Selected.Id, CloseSessions })} />
                </div>}
                <ActionFeedback Result={Revoke.data} />
            </Panel>}
        </section>
        {SelectedId && !Selected && <QueryState Pending={Exact.isPending} Error={Exact.error} HasData={Exact.data !== undefined} Label="指定账户" Children={<EmptyState Title="指定账户已不在当前快照" Detail="保留原始目标，没有用其他账户替代；请核对实例或刷新。" />} />}
    </>;
}

function AccountMetric(Input: Readonly<{ Label: string; Value: string; Hint: string }>): ReactNode {
    return <div className="page-metric"><span>{Input.Label}</span><strong>{Input.Value}</strong><small>{Input.Hint}</small></div>;
}

function AccountRow(Input: Readonly<{ Value: AccountRecord; Group: GroupRecord | null; Selected: boolean; OnSelect: () => void }>): ReactNode {
    const Account = Input.Value;
    return <tr className={Input.Selected ? 'row-selected' : ''}>
        <td data-label="账户"><button type="button" className="table-link account-name" onClick={Input.OnSelect} aria-pressed={Input.Selected}>
            <strong>{Account.Label}</strong><small>{Account.Id}</small></button></td>
        <td data-label="用户组">{Input.Group?.Name ?? '未分组'}</td>
        <td data-label="根连接租约">{FormatCount(Account.ActiveSessions)}</td>
        <td data-label="流量 ↑ / ↓"><span className="account-traffic"><span>↑ {Account.Traffic ? FormatBytes(Account.Traffic.Up) : '—'}</span>
            <span>↓ {Account.Traffic ? FormatBytes(Account.Traffic.Down) : '—'}</span></span></td>
        <td data-label="状态"><StatusBadge Label={Account.Revoked ? '已撤销' : Number(Account.ActiveSessions) > 0 ? '使用中' : '未连接'}
            Tone={Account.Revoked ? 'danger' : Number(Account.ActiveSessions) > 0 ? 'good' : 'neutral'} /></td>
    </tr>;
}

function AccountSessionList(Input: Readonly<{ Sessions: readonly SessionRecord[] }>): ReactNode {
    if (Input.Sessions.length === 0) return <p className="field-hint">当前已载入 Session 样本中没有关联记录。</p>;
    return <div className="related-list">
        {Input.Sessions.slice(0, 5).map(Session => <Link className="related-row" key={`${Session.ProcessId}-${Session.Id}`}
            to={`/sessions?session=${encodeURIComponent(Session.Id)}&process=${encodeURIComponent(Session.ProcessId)}&identity_worker=${encodeURIComponent(Session.WorkerId)}&identity_account=${encodeURIComponent(Session.AccountId)}&generation=${encodeURIComponent(Session.GenerationId)}`}>
            <strong>{Session.Id}</strong><small>{Session.SourceAddress || '来源未提供'} → {Session.Target}</small>
        </Link>)}
    </div>;
}
