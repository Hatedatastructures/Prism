import { TimeLink as Link } from '../TimeLink';
import { useMemo, useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { ArrowRight, FolderPlus, Search, UsersRound } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { EmptyState, FormatBytes, FormatCount, LoadMoreButton, PageHeader, Panel, QueryState } from '../../Components/Ui';
import type { AccountRecord, AdminActionResult, GroupRecord, SessionRecord } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery, useAdminMutation } from '../UseOperations';
import { ResolveAccountReadStatus, ResolveGroupTarget, SummarizeLoadedMetric } from './GroupPresentation';
import type { LoadedMetricSummary } from './GroupPresentation';
import { PolicyEditor } from '../PolicyEditor';
import { TimeRangeControl } from '../TimeRange';
import { HistoryPanel } from '../HistoryPanel';
import { ActionFeedback } from '../ActionFeedback';

type GroupAssignmentFeedback = Readonly<{
    AccountId: string;
    AccountLabel: string;
    From: string;
    To: string;
    Pending: boolean;
    Result?: AdminActionResult;
    Failure?: string;
}>;

export default function UserGroupsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const GroupsQuery = useAdminInfiniteQuery('groups-directory', (Source, Page) => Source.GetGroups(Page));
    const AccountsQuery = useAdminInfiniteQuery('accounts-group-members', (Source, Page) => Source.GetAccounts(Page));
    const SessionsQuery = useAdminInfiniteQuery('sessions-group-members', (Source, Page) => Source.GetSessions(Page));
    const Create = useAdminMutation((Source, Name: string) => Source.CreateGroup(Name));
    const Rename = useAdminMutation((Source, Input: Readonly<{ Id: string; Name: string }>) => Source.RenameGroup(Input.Id, Input.Name));
    const Assign = useAdminMutation((Source, Input: Readonly<{ AccountId: string; GroupId: string | null }>) =>
        Source.SetAccountGroup(Input.AccountId, Input.GroupId));
    const Groups = GroupsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Accounts = AccountsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Sessions = SessionsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const RequestedGroupId = Params.get('group');
    const GroupTarget = ResolveGroupTarget(Groups.map(Group => Group.Id), RequestedGroupId, Groups[0]?.Id ?? null);
    const GroupId = GroupTarget.Id;
    const SearchText = Params.get('q') ?? '';
    const [NewName, SetNewName] = useState('');
    const [EditName, SetEditName] = useState('');
    const [AssignmentFeedback, SetAssignmentFeedback] = useState<GroupAssignmentFeedback | null>(null);
    const SelectedGroup = Groups.find(Group => Group.Id === GroupId) ?? null;
    const Unassigned = GroupTarget.Unassigned;
    const AccountsReadStatus = ResolveAccountReadStatus({
        HasData: AccountsQuery.data !== undefined,
        Pending: AccountsQuery.isPending,
        Failed: AccountsQuery.isError,
    });
    const HasRequestedGroup = !!RequestedGroupId && RequestedGroupId !== '__unassigned__';
    const GroupTargetPending = HasRequestedGroup && GroupsQuery.data === undefined && GroupsQuery.isPending;
    const GroupTargetUnavailable = HasRequestedGroup && GroupsQuery.data === undefined && GroupsQuery.isError;
    const MissingGroup = HasRequestedGroup && GroupsQuery.data !== undefined && GroupTarget.MissingFromLoadedGroups;
    const GroupTargetUnresolved = GroupTargetPending || GroupTargetUnavailable || MissingGroup;
    const Members = useMemo(() => Accounts.filter(Account => Unassigned ? !Account.GroupId : Account.GroupId === GroupId)
        .filter(Account => !SearchText || `${Account.Id} ${Account.Label}`.toLowerCase().includes(SearchText.toLowerCase())),
    [Accounts, GroupId, SearchText, Unassigned]);
    const SessionsSummary = SummarizeLoadedMetric(Groups.map(Group => Group.ActiveSessions));
    const TrafficSummary = SummarizeLoadedMetric(Groups.map(Group => Group.Traffic === null
        ? null : (BigInt(Group.Traffic.Up) + BigInt(Group.Traffic.Down)).toString()));
    const Update = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value) Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'q' });
    };
    const CreateGroup = async (Event: FormEvent<HTMLFormElement>): Promise<void> => {
        Event.preventDefault();
        const Result = await Create.mutateAsync(NewName);
        if (Result.Ok) { SetNewName(''); }
    };
    const RenameGroup = async (Event: FormEvent<HTMLFormElement>): Promise<void> => {
        Event.preventDefault();
        if (SelectedGroup === null) return;
        const Result = await Rename.mutateAsync({ Id: SelectedGroup.Id, Name: EditName });
        if (Result.Ok) SetEditName('');
    };
    const AssignAccount = async (Account: AccountRecord, NextGroupId: string | null): Promise<unknown> => {
        const Feedback: GroupAssignmentFeedback = {
            AccountId: Account.Id,
            AccountLabel: Account.Label,
            From: GroupName(Groups, Account.GroupId),
            To: GroupName(Groups, NextGroupId),
            Pending: true,
        };
        SetAssignmentFeedback(Feedback);
        try {
            const Result = await Assign.mutateAsync({ AccountId: Account.Id, GroupId: NextGroupId });
            SetAssignmentFeedback({ ...Feedback, Pending: false, Result });
            return Result;
        } catch (Failure: unknown) {
            const Message = Failure instanceof Error ? Failure.message : '无法提交组归属变更';
            SetAssignmentFeedback({ ...Feedback, Pending: false, Failure: Message });
            return null;
        }
    };

    return <>
        <PageHeader Title="用户组"
            Description="组提供默认策略，账户可逐项覆盖；每个账户独立计量，换组不会清空消耗。"
            Actions={<TimeRangeControl />} />
        <div className="page-metric-strip" aria-label="用户组汇总">
            <GroupMetric Label="用户组" Value={GroupsQuery.data === undefined ? '—' : FormatCount(Groups.length)}
                Hint={GroupsQuery.data === undefined ? '组目录尚未载入' : RangeHint(Groups.length, GroupsQuery.hasNextPage ?? false, '组')} />
            <GroupMetric Label="账户" Value={AccountsQuery.data === undefined ? '—' : FormatCount(Accounts.length)}
                Hint={AccountsQuery.data === undefined ? '账户目录尚未载入' : RangeHint(Accounts.length, AccountsQuery.hasNextPage ?? false, '账户')} />
            <GroupMetric Label="已分组根连接租约" Value={AggregateValue(SessionsSummary, FormatCount)}
                Hint={GroupsQuery.data === undefined ? '组目录尚未载入' : AggregateHint(SessionsSummary, GroupsQuery.hasNextPage ?? false, '根连接租约')} />
            <GroupMetric Label="已分组累计流量" Value={AggregateValue(TrafficSummary, FormatBytes)}
                Hint={`${GroupsQuery.data === undefined ? '组目录尚未载入' : AggregateHint(TrafficSummary, GroupsQuery.hasNextPage ?? false, '累计流量')}；不是历史归属流量`} />
        </div>
        <section className="group-layout">
            <div className="group-directory-column"><Panel Title="分组目录" Subtitle="选择一个组查看成员；未分组账户单独列出">
                <QueryState Pending={GroupsQuery.isPending}
                    Error={GroupsQuery.error} Label="用户组目录" HasData={GroupsQuery.data !== undefined}
                    Children={<>
                        <div className="group-rail">
                            {Groups.map(Group => <GroupOption key={Group.Id} Value={Group} Selected={Group.Id === GroupId}
                                OnSelect={() => Update('group', Group.Id)} />)}
                            <button type="button" className={`group-select ${Unassigned ? 'is-selected' : ''}`}
                                aria-pressed={Unassigned} onClick={() => Update('group', '__unassigned__')}>
                                <strong>未分组</strong><small>未关联 Group ID</small><span>{AccountsQuery.data === undefined ? '—' : Accounts.filter(Account => !Account.GroupId).length}</span>
                            </button>
                        </div>
                        <p className="field-hint">组目录、成员列表和候选账户都只覆盖已载入记录；每个“载入更多”只扩大对应列表。</p>
                        <LoadMoreButton HasMore={GroupsQuery.hasNextPage ?? false} Busy={GroupsQuery.isFetchingNextPage}
                            OnLoad={() => void GroupsQuery.fetchNextPage()} />
                        <form className="group-form" onSubmit={Event => void CreateGroup(Event)}>
                            <input className="field-input" aria-label="新用户组名称" placeholder="新建用户组名称" value={NewName}
                                onChange={Event => SetNewName(Event.target.value)} maxLength={40} />
                            <button className="button button-primary" type="submit" disabled={Create.isPending || NewName.trim().length < 2}>
                                <FolderPlus size={14} />创建
                            </button>
                        </form>
                        {Create.data && <div className={`notice ${Create.data.Ok ? 'notice-info' : 'notice-danger'}`} role="status">{Create.data.Message}</div>}
                    </>} />
            </Panel>
            </div>
            <Panel ClassName="group-inspector" Title={Unassigned ? '未分组账户' : SelectedGroup?.Name ?? '用户组详情'}
                Subtitle={Unassigned ? '为账户分配一个用户组，或继续保持未分组状态。' : `Group ID · ${SelectedGroup?.Id ?? '—'}`}>
                {SelectedGroup && <>
                    <PolicyEditor Kind="group-policy" Id={SelectedGroup.Id} Title="用户组默认策略" />
                    <p className="field-hint">默认策略按当前配置作用于此组全部账户；下方成员表只显示当前已载入且符合搜索条件的账户。</p>
                    <div className="group-summary-row">
                        <GroupFact Label="配置账户" Value={FormatCount(SelectedGroup.ConfiguredAccountCount)} />
                        <GroupFact Label="活动账户" Value={FormatCount(SelectedGroup.ActiveAccountCount)} />
                        <GroupFact Label="根连接租约" Value={SelectedGroup.ActiveSessions === null ? '未提供' : FormatCount(SelectedGroup.ActiveSessions)} />
                    </div>
                    <form className="group-rename" onSubmit={Event => void RenameGroup(Event)}>
                        <input className="field-input" aria-label="用户组新名称" placeholder={SelectedGroup.Name} value={EditName}
                            onChange={Event => SetEditName(Event.target.value)} maxLength={40} />
                        <button className="button button-secondary" type="submit" disabled={!EditName.trim() || Rename.isPending}>更新名称</button>
                    </form>
                    {Rename.data && <div className={`notice ${Rename.data.Ok ? 'notice-info' : 'notice-danger'}`} role="status">{Rename.data.Message}</div>}
                </>}
                <div className="toolbar">
                    <label className="search-field"><Search size={16} aria-hidden="true" /><input aria-label="搜索当前已载入成员账户"
                        placeholder="搜索成员账户 ID 或名称" value={SearchText} onChange={Event => Update('q', Event.target.value)} /></label>
                    {SearchText && <button className="button button-quiet" type="button" onClick={() => Update('q', '')}>清除搜索</button>}
                </div>
                <p className="filter-scope-note">成员搜索只筛选当前已载入账户；载入更多可扩大范围。</p>
                <p className="field-hint">从成员行或候选项选择新组会立即更新配置：目标组默认策略生效，账户级覆盖与本周期用量保留；提交后显示原组 → 新组及操作结果。</p>
                <div className="group-members-heading"><strong>账户成员</strong><span>{GroupTargetUnresolved ? '组目标待核对' :
                    AccountsReadStatus === 'ready' ? `${Members.length} 个匹配的已载入账户` :
                    AccountsReadStatus === 'stale' ? `${Members.length} 个匹配的账户（上次成功载入）` :
                    AccountsReadStatus === 'loading' ? '账户列表载入中' :
                    AccountsReadStatus === 'error' ? '账户列表不可用' : '账户范围待确认'}</span></div>
                {AccountsReadStatus === 'stale' && <div className="notice notice-warning" role="status">
                    账户查询刷新失败；当前显示上次成功载入的数据，分组变更已暂停。
                    <button className="button button-secondary" type="button" disabled={AccountsQuery.isFetching}
                        onClick={() => void AccountsQuery.refetch()}>重试账户查询</button>
                </div>}
                <div className="group-member-list">
                    {GroupTargetPending ? <EmptyState Title="正在载入指定组目录" Detail={`暂不显示组 ID ${GroupId} 的成员或编辑操作。`} /> :
                        GroupTargetUnavailable ? <EmptyState Title="暂时无法核对指定组" Detail={`已保留组 ID ${GroupId}；请查看左侧组目录错误，恢复读取后再核对。`} /> :
                        MissingGroup ? <EmptyState Title="未在当前已载入范围找到指定组"
                            Detail={`已保留组 ID ${GroupId}。这不表示组已删除；${GroupsQuery.hasNextPage ? '可以继续载入左侧组目录核对。' : '当前没有更多组页；可刷新目录后再次核对。'}`}
                            Action={!GroupsQuery.hasNextPage ? <button className="button button-secondary" type="button"
                                disabled={GroupsQuery.isFetching} onClick={() => void GroupsQuery.refetch()}>刷新组目录</button> : undefined} /> :
                        AccountsReadStatus === 'loading' ? <EmptyState Title="正在载入账户列表" Detail="暂不判断该组是否没有成员；账户加载完成后会显示当前已载入范围。" /> :
                        AccountsReadStatus === 'error' ? <EmptyState Title="无法读取账户列表" Detail={`暂不判断该组是否没有成员。${AccountsQuery.error?.message ?? '请重试账户查询。'}`}
                            Action={<button className="button button-secondary" type="button" disabled={AccountsQuery.isFetching}
                                onClick={() => void AccountsQuery.refetch()}>重试账户查询</button>} /> :
                        AccountsReadStatus === 'unknown' ? <EmptyState Title="账户范围尚未确认" Detail="当前没有可用账户数据；不会将未知状态显示为空成员列表。" /> :
                        Members.length === 0 ? <EmptyState Title="当前已载入账户中没有匹配成员"
                            Detail={SearchText ? `搜索“${SearchText}”仅作用于当前已载入账户；${AccountsQuery.hasNextPage ? '继续载入可扩大范围。' : '当前账户页已全部载入。'}`
                                : `当前已载入账户中没有此组成员；${AccountsQuery.hasNextPage ? '继续载入可扩大检查范围。' : '当前账户页已全部载入。'}`} /> :
                        Members.map(Account => <GroupMember key={Account.Id} Account={Account} Groups={Groups} Sessions={Sessions}
                            OnAssign={GroupValue => AssignAccount(Account, GroupValue)}
                            Busy={Assign.isPending || AccountsReadStatus !== 'ready'} />)}
                </div>
                {AssignmentFeedback && <>
                    <div className={`notice ${AssignmentFeedback.Pending ? 'notice-info' : AssignmentFeedback.Failure || AssignmentFeedback.Result?.Ok === false ? 'notice-danger' : 'notice-info'}`} role="status">
                        <strong>{AssignmentFeedback.AccountLabel} · {AssignmentFeedback.AccountId}</strong>
                        <p>{AssignmentFeedback.From} → {AssignmentFeedback.To}</p>
                        <p>{AssignmentFeedback.Pending ? '正在提交用户组归属变更。' : AssignmentFeedback.Failure ?? AssignmentFeedback.Result?.Message ?? '用户组归属变更状态待核对。'}</p>
                    </div>
                    <ActionFeedback Result={AssignmentFeedback.Result} />
                </>}
                {!GroupTargetUnresolved && AccountsReadStatus !== 'error' && AccountsReadStatus !== 'unknown' &&
                    <LoadMoreButton HasMore={AccountsReadStatus === 'ready' && (AccountsQuery.hasNextPage ?? false)} Busy={AccountsQuery.isFetchingNextPage}
                    OnLoad={() => void AccountsQuery.fetchNextPage()} />}
                {SelectedGroup ? <div className="group-add-members">
                    <label className="field-label" htmlFor="available-account">添加其他账户到此组</label>
                    {AccountsReadStatus === 'loading' && <p className="field-hint">正在载入账户候选项；暂不提供分组操作。</p>}
                    {AccountsReadStatus === 'error' && <p className="field-hint">账户查询失败，候选账户暂不可用；请重试账户查询。</p>}
                    {AccountsReadStatus === 'unknown' && <p className="field-hint">账户范围尚未确认，候选账户暂不可用。</p>}
                    {AccountsReadStatus === 'stale' && <p className="field-hint">账户列表刷新失败；候选列表暂不可用于变更。</p>}
                    {AccountsReadStatus === 'ready' && <select id="available-account" className="field-select" value="" disabled={Assign.isPending} onChange={Event => {
                        const Account = Accounts.find(Value => Value.Id === Event.target.value);
                        if (Account) void AssignAccount(Account, SelectedGroup.Id);
                    }}>
                        <option value="">选择账户…</option>
                        {Accounts.filter(Account => Account.GroupId !== SelectedGroup?.Id)
                            .map(Account => <option value={Account.Id} key={Account.Id}>{Account.Label} · {Account.Id}</option>)}
                    </select>}
                    {AccountsReadStatus === 'ready' && Accounts.filter(Account => Account.GroupId !== SelectedGroup.Id).length === 0 &&
                        <p className="field-hint">当前已载入范围没有可加入账户{AccountsQuery.hasNextPage ? '；继续载入账户可扩大候选范围。' : '。'}</p>}
                    <small className="field-hint">账户可以未分组，或归属一个组；换组继承新默认策略并保留本周期使用量；账户覆盖仍然有效。</small>
                </div> : Unassigned ? <p className="field-hint">在每个账户行中使用分组选择器，可以将其归入一个用户组。</p> : null}
            </Panel>
        </section>
        {SelectedGroup && <>
            <p className="field-hint">时间范围只影响下方历史图；当前正式接口未提供组维度历史，也不支持据此核对事件发生时的组归属。</p>
            <HistoryPanel Scope="group" ResourceKey={SelectedGroup.Id}
                Title={`${SelectedGroup.Name} · ${SelectedGroup.Id} 流量历史`} />
        </>}
        <ActionFeedback Result={Create.data} /><ActionFeedback Result={Rename.data} />
        <Panel Title="用户组与运行关系" Subtitle="通过账户、Session 和 Worker 关联定位流量来源" ClassName="page-surface">
            <div className="group-relationship-note"><UsersRound size={16} /><span>组级统计只聚合数据源已返回的账户与连接；缺失的流量或 Session 计数保持未提供。</span>
                <Link to="/accounts">打开代理账户 <ArrowRight size={13} /></Link></div>
        </Panel>
    </>;
}

function AggregateValue(Summary: LoadedMetricSummary, Format: (Value: string) => string): string {
    if (Summary.State === 'complete' && Summary.Total !== null) return Format(Summary.Total);
    if (Summary.State === 'partial') return '部分缺测';
    if (Summary.State === 'unavailable') return '未提供';
    return '—';
}

function AggregateHint(Summary: LoadedMetricSummary, HasMore: boolean, Label: string): string {
    if (Summary.State === 'empty') return `没有已载入组可统计${HasMore ? '；组目录还有未载入项' : ''}`;
    const Coverage = `${Summary.Known}/${Summary.Count} 个已载入组提供${Label}`;
    const Completeness = Summary.State === 'partial' ? '；不显示不完整总计' : '';
    return `${Coverage}${Completeness}${HasMore ? '；组目录还有未载入项' : ''}`;
}

function RangeHint(Count: number, HasMore: boolean, Label: string): string {
    return `${Count} 个已载入${Label}${HasMore ? '；还有未载入项' : ''}`;
}

function GroupName(Groups: readonly GroupRecord[], GroupId: string | null | undefined): string {
    if (GroupId === undefined) return '未提供';
    if (GroupId === null) return '未分组';
    return Groups.find(Group => Group.Id === GroupId)?.Name ?? `用户组 ${GroupId}`;
}

function GroupMetric(Input: Readonly<{ Label: string; Value: string; Hint: string }>): ReactNode {
    return <div className="page-metric"><span>{Input.Label}</span><strong>{Input.Value}</strong><small>{Input.Hint}</small></div>;
}

function GroupOption(Input: Readonly<{ Value: GroupRecord; Selected: boolean; OnSelect: () => void }>): ReactNode {
    return <button type="button" className={`group-select ${Input.Selected ? 'is-selected' : ''}`} aria-pressed={Input.Selected} onClick={Input.OnSelect}>
        <strong>{Input.Value.Name}</strong><small>{Input.Value.Id} · {FormatCount(Input.Value.ConfiguredAccountCount)} 个账户 · {FormatCount(Input.Value.ActiveSessions)} 个根连接租约</small>
        <span>{FormatCount(Input.Value.ConfiguredAccountCount)}</span>
    </button>;
}

function GroupFact(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="group-fact"><span>{Input.Label}</span><strong>{Input.Value}</strong></div>;
}

function GroupMember(Input: Readonly<{
    Account: AccountRecord; Groups: readonly GroupRecord[]; Sessions: readonly SessionRecord[];
    OnAssign: (GroupId: string | null) => Promise<unknown>; Busy: boolean;
}>): ReactNode {
    const Related = Input.Sessions.filter(Session => Session.AccountId === Input.Account.Id);
    const Traffic = Input.Account.Traffic;
    return <article className="group-member">
        <div className="group-member-main"><Link to={`/accounts?account=${encodeURIComponent(Input.Account.Id)}`}>
            <strong>{Input.Account.Label}</strong></Link>
            <small>{Input.Account.Id} · {FormatCount(Input.Account.ActiveSessions)} 个根连接租约</small>
            <small>{Related.length ? `来源 ${Related[0]?.SourceAddress || '未提供'} · Worker ${Related[0]?.WorkerId}` : '当前已载入列表中无关联 Session'}</small>
        </div>
        <div className="group-member-actions">
            <span className="group-member-traffic">{Traffic ? `${FormatBytes(Traffic.Up)} ↑ / ${FormatBytes(Traffic.Down)} ↓` : '流量未提供'}</span>
            <select className="field-select" aria-label={`调整 ${Input.Account.Label} 的用户组`} disabled={Input.Busy}
                value={Input.Account.GroupId ?? ''} onChange={Event => void Input.OnAssign(Event.target.value || null)}>
                <option value="">未分组</option>{Input.Groups.map(Group => <option value={Group.Id} key={Group.Id}>{Group.Name}</option>)}
            </select>
        </div>
    </article>;
}
