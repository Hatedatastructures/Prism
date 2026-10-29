/** @file Shadcn UI 代理账户管理页。 */
import { useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { ArrowRight, CircleAlert, RefreshCw, ShieldBan, UsersRound } from 'lucide-react';
import { NavLink, useSearchParams } from 'react-router';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from '@/Components/ui/dialog';
import { Input } from '@/Components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { OverviewStat } from '../../Components/OverviewStat';
import { Switch } from '@/Components/ui/switch';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/Components/ui/tabs';
import { Badge, EmptyState, FormatBytes, FormatCount, FormatRate, MobileMasterBack, PageHeader, QueryState, StatusBadge, useMobileMasterFocus } from '../../Components/Ui';
import type { AccountRecord, SessionRecord } from '../../Services/AdminDataSource';
import { WithTime } from '../TimeRange';
import { useAdminInfiniteQuery, useAdminMutation, useAdminQuery } from '../UseOperations';
import { AccountUsagePanel } from './AccountUsagePanel';

type AccountFilter = 'all' | 'active' | 'revoked';

export default function AccountsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const [MobileView, SetMobileView] = useState<'list' | 'detail'>(() => Params.has('account') ? 'detail' : 'list');
    useMobileMasterFocus(MobileView);
    const [RevokeOpen, SetRevokeOpen] = useState(false);
    const [CloseSessions, SetCloseSessions] = useState(true);
    const AccountsQuery = useAdminInfiniteQuery('accounts', (Source, Page) => Source.GetAccounts(Page));
    const GroupsQuery = useAdminInfiniteQuery('groups', (Source, Page) => Source.GetGroups(Page));
    const SessionsQuery = useAdminInfiniteQuery('sessions', (Source, Page) => Source.GetSessions(Page));
    const Revoke = useAdminMutation((Source, Input: Readonly<{ Id: string; CloseSessions: boolean }>) => Source.RevokeAccount(Input.Id, Input.CloseSessions));
    const Accounts = AccountsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Groups = GroupsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Sessions = SessionsQuery.data?.pages.flatMap(Page => Page.Items) ?? [];
    const Search = Params.get('q') ?? '';
    const CandidateFilter = Params.get('state') ?? 'all';
    const Filter: AccountFilter = CandidateFilter === 'active' || CandidateFilter === 'revoked' ? CandidateFilter : 'all';
    const SelectedId = Params.get('account') ?? '';
    const Filtered = useMemo(() => Accounts.filter(Account => {
        const Matches = !Search || `${Account.Id} ${Account.Label} ${Account.GroupId ?? ''}`.toLocaleLowerCase().includes(Search.toLocaleLowerCase());
        return Matches && (Filter === 'all' || Filter === 'active' && !Account.Revoked || Filter === 'revoked' && Account.Revoked);
    }), [Accounts, Filter, Search]);
    const Exact = useAdminQuery('account-target', Source => Source.GetAccounts({ Cursor: '0', Limit: 1, Id: SelectedId }), { Enabled: !!SelectedId, Scope: [SelectedId] });
    const Selected = SelectedId ? Accounts.find(Account => Account.Id === SelectedId) ?? Exact.data?.Items.find(Account => Account.Id === SelectedId) ?? null : Filtered[0] ?? null;
    const Update = (Key: string, Value: string): void => {
        const Next = new URLSearchParams(Params);
        if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key);
        SetParams(Next, { replace: Key === 'q' });
    };
    const Select = (Account: AccountRecord): void => { Update('account', Account.Id); SetMobileView('detail'); };
    const Refresh = async (): Promise<void> => { await Promise.all([AccountsQuery.refetch(), GroupsQuery.refetch(), SessionsQuery.refetch(), SelectedId ? Exact.refetch() : Promise.resolve()]); };
    const ExecuteRevoke = async (): Promise<void> => {
        if (!Selected) return;
        await Revoke.mutateAsync({ Id: Selected.Id, CloseSessions });
        SetRevokeOpen(false);
    };
    const Active = Accounts.filter(Account => !Account.Revoked).length;
    const InUse = Accounts.filter(Account => !Account.Revoked && BigInt(Account.ActiveSessions) > 0n).length;
    const Revoked = Accounts.filter(Account => Account.Revoked).length;

    return <div className="space-y-6">
        <PageHeader Title="代理账户" Description="认证身份、权限来源、活动连接与累计流量。"
            Actions={<Button type="button" variant="outline" onClick={() => void Refresh()} disabled={AccountsQuery.isFetching || GroupsQuery.isFetching || SessionsQuery.isFetching}><RefreshCw className={AccountsQuery.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新快照</Button>} />
        <section className="grid grid-cols-1 gap-3 sm:grid-cols-3" aria-label="账户摘要">
            <OverviewStat Label="有效账户" Value={FormatCount(Active)} Detail="可用于认证" Icon={<UsersRound aria-hidden="true" />} />
            <OverviewStat Label="有活动连接" Value={FormatCount(InUse)} Detail="存在根连接租约" Icon={<UsersRound aria-hidden="true" />} />
            <OverviewStat Label="已撤销" Value={FormatCount(Revoked)} Detail="拒绝后续认证" Icon={<ShieldBan aria-hidden="true" />} />
        </section>
        <div className="grid min-w-0 overflow-hidden rounded-xl border bg-card md:items-start md:grid-cols-[minmax(17rem,20rem)_minmax(0,1fr)]">
            <div className={MobileView === 'detail' ? 'hidden md:block' : ''} data-mobile-master-list tabIndex={-1}><Card className="rounded-none border-r py-4 ring-0"><CardHeader className="gap-4"><div className="flex items-start justify-between gap-3"><div><CardTitle>账户目录</CardTitle><CardDescription>选择账户查看详情。</CardDescription></div><Badge Tone="neutral">{Accounts.length}{AccountsQuery.hasNextPage ? '+' : ''}</Badge></div>
                <div className="flex flex-col gap-3"><Input value={Search} onChange={Event => Update('q', Event.target.value)} aria-label="搜索账户" placeholder="搜索账户 ID、名称或用户组" />
                    <div className="flex shrink-0 flex-wrap gap-2" role="group" aria-label="账户状态筛选">{(['all', 'active', 'revoked'] as const).map(Value => <Button key={Value} type="button" size="sm" variant={Filter === Value ? 'default' : 'outline'} onClick={() => Update('state', Value)}>{AccountFilterLabel(Value)}</Button>)}</div>
                </div></CardHeader>
                <CardContent><QueryState Pending={AccountsQuery.isPending} Error={AccountsQuery.error} Label="账户目录" HasData={AccountsQuery.data !== undefined} Retry={() => void AccountsQuery.refetch()} Retrying={AccountsQuery.isFetching}
                    Children={Filtered.length === 0 ? <EmptyState Title="没有匹配账户" Detail="调整搜索词或状态筛选，或者载入更多账户。" /> : <><AccountTable Rows={Filtered} Selected={Selected} Groups={Groups} OnSelect={Select} />

                        {AccountsQuery.hasNextPage && <div className="mt-4 flex justify-center"><Button variant="outline" disabled={AccountsQuery.isFetchingNextPage} onClick={() => void AccountsQuery.fetchNextPage()}>{AccountsQuery.isFetchingNextPage ? '正在载入…' : '载入更多账户'}</Button></div>}</>} />
                </CardContent>
            </Card></div>
            <div className={MobileView === 'list' ? 'hidden md:block' : ''}><div className="px-4 pt-4 md:hidden"><MobileMasterBack Label="返回账户目录" OnClick={() => SetMobileView('list')} /></div>
            <AccountInspector Account={Selected} ExactPending={!!SelectedId && Exact.isPending} Sessions={Sessions} SessionsPending={SessionsQuery.isPending} SessionsError={SessionsQuery.error} SessionsHasMore={SessionsQuery.hasNextPage ?? false} Params={Params} GroupName={Groups.find(Group => Group.Id === Selected?.GroupId)?.Name}
                RevokeOpen={RevokeOpen} SetRevokeOpen={SetRevokeOpen} CloseSessions={CloseSessions} SetCloseSessions={SetCloseSessions} Busy={Revoke.isPending} OnRevoke={ExecuteRevoke} ResultMessage={Revoke.data?.Message ?? null} ResultError={Revoke.error?.message} /></div>
        </div>
        {SelectedId && !Selected && !Exact.isPending && <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>指定账户不在当前快照</AlertTitle><AlertDescription>{Exact.error ? Exact.error.message : '精确读取没有返回该账户；系统没有用其他账户替代所选目标。'}</AlertDescription></Alert>}
    </div>;
}

function AccountTable(Input: Readonly<{ Rows: readonly AccountRecord[]; Selected: AccountRecord | null; Groups: readonly Readonly<{ Id: string; Name: string }>[]; OnSelect: (Account: AccountRecord) => void }>): ReactNode {
    return <ul className="space-y-0.5" aria-label="账户列表">{Input.Rows.map(Account => <li key={Account.Id}><button type="button" aria-pressed={Account.Id === Input.Selected?.Id} onClick={() => Input.OnSelect(Account)} className="w-full rounded-md px-3 py-2 text-left transition-colors hover:bg-muted focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring aria-pressed:bg-muted">
        <span className="flex items-center justify-between gap-2"><span className="truncate font-medium">{Account.Label}</span><span className="shrink-0 text-xs text-muted-foreground">{Account.Revoked ? '已撤销' : BigInt(Account.ActiveSessions) > 0n ? '活动中' : '有效'}</span></span>
        <span className="mt-0.5 block truncate text-xs text-muted-foreground">{Account.GroupId === null ? '未分组' : Input.Groups.find(Group => Group.Id === Account.GroupId)?.Name ?? Account.GroupId ?? '未提供'} · {FormatCount(Account.ActiveSessions)} 个根连接</span>
    </button></li>)}</ul>;
}

function AccountInspector(Input: Readonly<{
    Account: AccountRecord | null; ExactPending: boolean; Sessions: readonly SessionRecord[]; SessionsPending: boolean; SessionsError: Error | null; SessionsHasMore: boolean; Params: URLSearchParams; GroupName: string | undefined;
    RevokeOpen: boolean; SetRevokeOpen: (Open: boolean) => void; CloseSessions: boolean; SetCloseSessions: (Value: boolean) => void; Busy: boolean; OnRevoke: () => Promise<void>; ResultMessage: string | null; ResultError: string | undefined;
}>): ReactNode {
    if (Input.ExactPending) return <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">正在精确核验账户目标…</CardContent></Card>;
    if (!Input.Account) return <Card><CardContent className="py-12"><EmptyState Title="选择一个账户" Detail="从账户目录选择身份，查看其策略来源与当前连接。" /></CardContent></Card>;
    const Account = Input.Account;
    const AccountSessions = Input.Sessions.filter(Session => Session.AccountId === Account.Id);
    const Policy = Account.EffectivePolicy;
    return <Card className="rounded-none ring-0"><CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle>{Account.Label}</CardTitle><CardDescription className="mt-1 font-mono">{Account.Id} · Generation {Account.GenerationId}</CardDescription></div><div className="flex flex-wrap items-center justify-end gap-2"><StatusBadge Label={Account.Revoked ? '已撤销' : '有效'} Tone={Account.Revoked ? 'danger' : 'good'} />{!Account.Revoked && <Dialog open={Input.RevokeOpen} onOpenChange={Input.SetRevokeOpen}><DialogTrigger asChild><Button variant="destructive" type="button"><ShieldBan aria-hidden="true" />撤销账户</Button></DialogTrigger><DialogContent><DialogHeader><DialogTitle>撤销 {Account.Label}？</DialogTitle><DialogDescription>此请求会拒绝账户后续认证。可选择同时关闭当前活动连接。</DialogDescription></DialogHeader><label className="flex items-center justify-between gap-4 rounded-lg border p-3 text-sm"><span><strong className="block">关闭活动连接</strong><span className="text-muted-foreground">要求关联 Session 进入关闭流程。</span></span><Switch checked={Input.CloseSessions} onCheckedChange={Input.SetCloseSessions} aria-label="撤销时关闭活动连接" /></label><DialogFooter><Button variant="outline" onClick={() => Input.SetRevokeOpen(false)}>取消</Button><Button variant="destructive" disabled={Input.Busy} onClick={() => void Input.OnRevoke()}>{Input.Busy ? '正在提交…' : '确认撤销'}</Button></DialogFooter></DialogContent></Dialog>}</div></div></CardHeader>
        <CardContent className="space-y-5"><Tabs defaultValue="overview"><TabsList variant="line" className="max-w-full overflow-x-auto"><TabsTrigger value="overview">身份与流量</TabsTrigger><TabsTrigger value="usage">周期额度</TabsTrigger><TabsTrigger value="sessions">关联 Session</TabsTrigger><TabsTrigger value="policy">策略来源</TabsTrigger></TabsList>
            <TabsContent value="overview" className="mt-5 space-y-5">
                <dl className="grid grid-cols-2 gap-x-5 gap-y-4 border-b pb-5 sm:grid-cols-4">
                    <Fact Label="用户组" Value={Account.GroupId === null ? '未分组' : Input.GroupName ?? Account.GroupId ?? '未提供'} />
                    <Fact Label="根连接" Value={FormatCount(Account.ActiveSessions)} />
                    <Fact Label="累计上行" Value={FormatBytes(Account.Traffic?.Up)} />
                    <Fact Label="累计下行" Value={FormatBytes(Account.Traffic?.Down)} />
                    {Account.ActiveStreams != null && <Fact Label="活动子流" Value={FormatCount(Account.ActiveStreams)} />}
                    {Account.ActiveConnections != null && <Fact Label="活动连接" Value={FormatCount(Account.ActiveConnections)} />}
                    {Account.UploadBytesPerSecond != null && <Fact Label="上行速率" Value={FormatRate(Account.UploadBytesPerSecond)} />}
                    {Account.DownloadBytesPerSecond != null && <Fact Label="下行速率" Value={FormatRate(Account.DownloadBytesPerSecond)} />}
                </dl>
                <section><div className="flex items-center justify-between gap-2"><h3 className="text-sm font-semibold">关联 Session</h3><NavLink className="inline-flex items-center gap-1 text-sm font-medium hover:underline" to={WithTime(`/sessions?account=${encodeURIComponent(Account.Id)}`, Input.Params)}>查看会话<ArrowRight className="size-3" aria-hidden="true" /></NavLink></div>
                    <p className="mt-1 text-xs text-muted-foreground">{Input.SessionsPending ? '正在读取会话' : Input.SessionsError ? `会话读取失败：${Input.SessionsError.message}` : `已载入 ${AccountSessions.length} 条关联会话${Input.SessionsHasMore ? '，列表仍有更多分页' : ''}`}</p>
                    {!Input.SessionsPending && !Input.SessionsError && AccountSessions.length > 0 && <Table><TableHeader><TableRow><TableHead>Session</TableHead><TableHead>协议</TableHead><TableHead>目标</TableHead><TableHead>状态</TableHead></TableRow></TableHeader><TableBody>{AccountSessions.slice(0, 3).map(Session => <TableRow key={`${Session.ProcessId}-${Session.Id}`}><TableCell className="font-mono">{Session.Id}</TableCell><TableCell>{Session.Protocol}</TableCell><TableCell className="max-w-48 truncate" title={Session.Target}>{Session.Target || '未提供'}</TableCell><TableCell><StatusBadge Label={Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束'} /></TableCell></TableRow>)}</TableBody></Table>}
                </section>
                {Input.ResultError && <Alert variant="destructive"><CircleAlert aria-hidden="true" /><AlertTitle>撤销结果尚未确认</AlertTitle><AlertDescription>{Input.ResultError}</AlertDescription></Alert>}
                {Input.ResultMessage && <Alert><ShieldBan aria-hidden="true" /><AlertTitle>撤销请求已提交</AlertTitle><AlertDescription>{Input.ResultMessage} 请刷新快照确认最终状态。</AlertDescription></Alert>}
            </TabsContent>
            <TabsContent value="usage" className="mt-5"><AccountUsagePanel key={Account.AccountKey ?? Account.Id} Account={Account} /></TabsContent>
            <TabsContent value="sessions" className="mt-5"><QueryState Pending={Input.SessionsPending} Error={Input.SessionsError} Label="账户关联 Session" HasData={!Input.SessionsPending && !Input.SessionsError}
                Children={AccountSessions.length === 0 ? <EmptyState Title="当前已载入范围没有关联 Session" Detail="这不代表该账户没有更早的连接或其他分页中的记录。" /> : <div className="divide-y rounded-lg border">{AccountSessions.slice(0, 8).map(Session => <NavLink key={`${Session.ProcessId}-${Session.Id}`} to={`/sessions?session=${encodeURIComponent(Session.Id)}&process=${encodeURIComponent(Session.ProcessId)}&identity_worker=${encodeURIComponent(Session.WorkerId)}&identity_account=${encodeURIComponent(Session.AccountId)}&generation=${encodeURIComponent(Session.GenerationId)}`} className="block p-3 transition-colors hover:bg-muted/50"><div className="flex items-center justify-between gap-3"><code className="font-mono text-xs">{Session.Id}</code><StatusBadge Label={Session.Draining ? '排空中' : Session.Active ? '活动中' : '已结束'} /></div><p className="mt-1 text-sm text-muted-foreground">{Session.Transport.toUpperCase()} · {Session.Protocol} · {Session.Target}</p></NavLink>)}</div>} />
            </TabsContent>
            <TabsContent value="policy" className="mt-5 space-y-3">{Policy ? <><dl className="grid grid-cols-2 gap-2 text-sm min-[1920px]:grid-cols-3">{Object.entries(Policy).map(([Name, Value]) => <Fact key={Name} Label={Name} Value={PolicyValue(Value)} />)}</dl><div className="divide-y rounded-lg border">{Object.entries(Account.PolicySources ?? {}).map(([Name, Source]) => <div key={Name} className="flex items-center justify-between gap-3 p-3 text-sm"><span className="text-muted-foreground">{Name}</span><code className="font-mono text-xs">{Source}</code></div>)}</div></> : <EmptyState Title="没有可呈现的有效策略" Detail="当前快照没有提供账户策略；不会以用户组猜测或补造策略。" />}</TabsContent>
        </Tabs></CardContent>
    </Card>;
}

function AccountFilterLabel(Value: AccountFilter): string { return Value === 'active' ? '有效' : Value === 'revoked' ? '已撤销' : '全部'; }
function Fact(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div className="min-w-0 py-1"><dt className="text-sm text-muted-foreground">{Input.Label}</dt><dd className="mt-1 break-words font-medium">{Input.Value}</dd></div>; }
function PolicyValue(Value: unknown): string { return Value === null ? '未限制' : typeof Value === 'string' || typeof Value === 'number' || typeof Value === 'boolean' ? String(Value) : JSON.stringify(Value); }
