/** @file Shadcn UI 事件流页。 */
import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { AlertTriangle, Copy, Pause, Play, RefreshCw, SlidersHorizontal } from 'lucide-react';
import { NavLink, useSearchParams } from 'react-router';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Input } from '@/Components/ui/input';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Badge, EmptyState, FormatCount, FormatTime, PageHeader, QueryState, StatusBadge, ToneForState } from '../../Components/Ui';
import { EventSessionPath } from '../../Components/ResourcePaths';
import type { EventPage, EventRecord, EventSeverity } from '../../Services/AdminDataSource';
import { useAdminInfiniteQuery } from '../UseOperations';

type SeverityFilter = 'all' | EventSeverity;
const Severities = [{ Value: 'all', Label: '全部' }, { Value: 'error', Label: '错误' }, { Value: 'warning', Label: '警告' }, { Value: 'info', Label: '信息' }, { Value: 'debug', Label: '调试' }] as const;

export default function EventsPage(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const [Expanded, SetExpanded] = useState('');
    const [Advanced, SetAdvanced] = useState(false);
    const [Frozen, SetFrozen] = useState<Readonly<{ Pages: readonly EventPage[]; ScopeKey: string }> | null>(null);
    const SessionId = Params.get('session') ?? '', WorkerId = Params.get('worker') ?? '', AccountId = Params.get('account') ?? '';
    const ProcessId = Params.get('process') ?? '', GenerationId = Params.get('generation') ?? '', Search = Params.get('q') ?? '';
    const CandidateSeverity = Params.get('severity') ?? 'all';
    const Severity: SeverityFilter = CandidateSeverity === 'error' || CandidateSeverity === 'warning' || CandidateSeverity === 'info' || CandidateSeverity === 'debug' ? CandidateSeverity : 'all';
    const Filter = { ...(SessionId ? { SessionId } : {}), ...(WorkerId ? { WorkerId } : {}), ...(AccountId ? { AccountId } : {}), ...(ProcessId ? { ProcessId } : {}), ...(GenerationId ? { GenerationId } : {}), ...(Severity === 'all' ? {} : { Severity }) };
    const Scope = [SessionId, WorkerId, AccountId, ProcessId, GenerationId, Severity];
    const ScopeKey = JSON.stringify([...Scope, Search, Params.get('source') ?? '']);
    const PreviousScope = useRef(ScopeKey);
    useEffect(() => { if (PreviousScope.current !== ScopeKey) { PreviousScope.current = ScopeKey; SetFrozen(null); } }, [ScopeKey]);
    const Paused = Frozen?.ScopeKey === ScopeKey;
    const Query = useAdminInfiniteQuery('events', (Source, Page) => Source.GetEvents(Page, Filter), Scope, { Refresh: !Paused });
    const Pages = Paused && Frozen ? Frozen.Pages : Query.data?.pages ?? [];
    const Rows = Pages.flatMap(Page => Page.Items);
    const Last = Pages.at(-1), First = Pages[0], HasMore = Last?.HasMore ?? false;
    const Lost = Pages.some(Page => Page.Lost);
    const LostRanges = Pages.flatMap(Page => Page.LostRanges).filter((Range, Index, Items) => Items.findIndex(Item => Item.First === Range.First && Item.Last === Range.Last) === Index);
    const Visible = useMemo(() => Rows.filter(Event => !Search || [Event.Message, Event.Detail, Event.Kind, Event.Scope, Event.CorrelationId, Event.WorkerId, Event.SessionId, Event.AccountId].join(' ').toLocaleLowerCase().includes(Search.toLocaleLowerCase())).sort((Left, Right) => BigInt(Left.Sequence) > BigInt(Right.Sequence) ? -1 : 1), [Rows, Search]);
    const Update = (Key: string, Value: string): void => { const Next = new URLSearchParams(Params); if (Value && Value !== 'all') Next.set(Key, Value); else Next.delete(Key); SetFrozen(null); SetParams(Next, { replace: Key === 'q' }); };
    const Clear = (): void => { const Next = new URLSearchParams(Params); for (const Key of ['q', 'severity', 'session', 'worker', 'account', 'process', 'generation']) Next.delete(Key); SetFrozen(null); SetParams(Next); };
    const TogglePause = (): void => SetFrozen(Paused ? null : Query.data ? { Pages: Query.data.pages, ScopeKey } : null);
    const Summary = Last ?? First;
    const WindowAvailable = Paused && Frozen !== null || Query.data !== undefined;
    return <div className="space-y-6"><PageHeader Title="事件流" Description="按严重级别与关联资源过滤；暂停会固定当前已载入的窗口。" Actions={<><Button type="button" variant="outline" disabled={!Paused && (!Query.data || Query.isFetchingNextPage)} onClick={TogglePause}>{Paused ? <Play aria-hidden="true" /> : <Pause aria-hidden="true" />}{Paused ? '继续追随' : '暂停追随'}</Button><Button type="button" variant="outline" disabled={Query.isFetching || !!Paused} onClick={() => void Query.refetch()}><RefreshCw className={Query.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新事件</Button></>} />
        {Paused && <Alert><Pause aria-hidden="true" /><AlertTitle>事件追随已暂停</AlertTitle><AlertDescription>固定显示暂停时已载入的 {FormatCount(Rows.length)} 条记录；恢复后才会读取新的服务端窗口。</AlertDescription></Alert>}
        {Lost && <Alert variant="destructive"><AlertTriangle aria-hidden="true" /><AlertTitle>事件窗口报告缺口</AlertTitle><AlertDescription>不可恢复范围：{LostRanges.map(Range => `${Range.First}–${Range.Last}`).join('、') || '未提供'}。筛选结果不等于完整事件历史。</AlertDescription></Alert>}
        <section className="rounded-xl border bg-card" aria-label="事件窗口指标"><dl className="grid grid-cols-2 divide-y sm:grid-cols-3 xl:grid-cols-6">
            <WindowFact Label="已载入 / 匹配" Value={WindowAvailable ? `${Rows.length}${HasMore ? '+' : ''} / ${Visible.length}` : '—'} />
            <WindowFact Label="窗口错误" Value={WindowAvailable ? String(Rows.filter(Event => Event.Severity === 'error').length) : '—'} />
            <WindowFact Label="窗口警告" Value={WindowAvailable ? String(Rows.filter(Event => Event.Severity === 'warning').length) : '—'} />
            <WindowFact Label="累计覆盖" Value={FormatCount(Summary?.Overwritten)} />
            <WindowFact Label="事件丢弃" Value={FormatCount(Summary?.Dropped)} />
            <WindowFact Label="终态事件丢弃" Value={FormatCount(Summary?.TerminalDropped)} />
        </dl><p className="border-t px-4 py-2 text-xs text-muted-foreground">最早游标 {First?.EarliestCursor ?? '未提供'} · 错误和警告仅统计已载入窗口；覆盖与丢弃为服务端累计值。</p></section>
        <Card><CardHeader className="gap-3"><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><CardTitle>运行事件</CardTitle><CardDescription>搜索仅匹配已载入窗口，不会把没有读到的事件视为不存在。</CardDescription></div><Badge Tone={Paused ? 'warning' : 'good'}>{Paused ? '已暂停' : '追随中'}</Badge></div><div className="flex flex-wrap items-center gap-2"><Input className="min-w-48 flex-1" aria-label="搜索事件内容" value={Search} onChange={Event => Update('q', Event.target.value)} placeholder="搜索消息、详情、类型或关联 ID" /><div className="flex flex-wrap gap-2" role="group" aria-label="按严重级别筛选">{Severities.map(Item => <Button key={Item.Value} type="button" size="sm" variant={Severity === Item.Value ? 'default' : 'outline'} onClick={() => Update('severity', Item.Value)}>{Item.Label}</Button>)}</div><Button type="button" size="sm" variant="outline" onClick={() => SetAdvanced(Value => !Value)} aria-expanded={Advanced}><SlidersHorizontal aria-hidden="true" />资源筛选</Button></div>
            {Advanced && <div className="grid gap-3 rounded-lg border bg-muted/30 p-3 sm:grid-cols-3"><Input aria-label="按 Session ID 过滤" value={SessionId} onChange={Event => Update('session', Event.target.value)} placeholder="Session ID" /><Input aria-label="按 Worker ID 过滤" value={WorkerId} onChange={Event => Update('worker', Event.target.value)} placeholder="Worker ID" /><Input aria-label="按账户 ID 过滤" value={AccountId} onChange={Event => Update('account', Event.target.value)} placeholder="账户 ID" /></div>}</CardHeader>
            <CardContent><div className="mb-4 flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground"><span>匹配 {Visible.length} / 已载入 {Rows.length} 条 · 按序号倒序</span>{(Search || Severity !== 'all' || SessionId || WorkerId || AccountId || ProcessId || GenerationId) && <Button type="button" variant="ghost" size="sm" onClick={Clear}>清除筛选</Button>}</div><QueryState Pending={Query.isPending} Error={Query.error} Label="事件记录" HasData={Query.data !== undefined} Retry={() => void Query.refetch()} Retrying={Query.isFetching} Children={Visible.length === 0 ? <EmptyState Title="当前范围无匹配事件" Detail={HasMore && !Paused ? '继续载入可扩大检查范围。' : '调整筛选条件后再试。'} /> : <EventTable Rows={Visible} Expanded={Expanded} SetExpanded={SetExpanded} />} />
                {HasMore && !Paused && <div className="mt-4 flex justify-center"><Button variant="outline" disabled={Query.isFetchingNextPage} onClick={() => void Query.fetchNextPage()}>{Query.isFetchingNextPage ? '正在载入…' : '载入更早事件'}</Button></div>}</CardContent></Card>
    </div>;
}

function WindowFact(Input: Readonly<{ Label: string; Value: string }>): ReactNode { return <div className="min-w-0 px-4 py-2"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 font-semibold tabular-nums">{Input.Value}</dd></div>; }
function EventTable(Input: Readonly<{ Rows: readonly EventRecord[]; Expanded: string; SetExpanded: (Value: string) => void }>): ReactNode { return <Table><TableHeader><TableRow><TableHead>时间 / 序号</TableHead><TableHead>级别</TableHead><TableHead>事件内容</TableHead><TableHead>关联资源</TableHead><TableHead /></TableRow></TableHeader><TableBody>{Input.Rows.map(Event => { const Key = `${Event.ProcessId}:${Event.Id}`, Open = Input.Expanded === Key; return <Fragment key={Key}><TableRow data-state={Open ? 'selected' : undefined} className={Event.Severity === 'error' ? 'border-l-2 border-l-destructive' : undefined}><TableCell><time dateTime={Event.Time}>{FormatTime(Event.Time, true)}</time><p className="font-mono text-xs text-muted-foreground">#{FormatCount(Event.Sequence)}</p></TableCell><TableCell><StatusBadge Label={SeverityLabel(Event.Severity)} Tone={ToneForState(Event.Severity)} /></TableCell><TableCell className="max-w-xl whitespace-normal"><p className="font-medium">{Event.Message}</p><p className="mt-1 text-xs text-muted-foreground">{Event.Detail || Event.Kind}{Event.Truncated ? ' · 已截断' : ''}</p></TableCell><TableCell className="max-w-48 whitespace-normal"><ResourceLinks Event={Event} /></TableCell><TableCell><Button type="button" variant="ghost" size="sm" aria-expanded={Open} onClick={() => Input.SetExpanded(Open ? '' : Key)}>{Open ? '收起' : '详情'}</Button></TableCell></TableRow>{Open && <TableRow><TableCell colSpan={5} className="whitespace-normal"><EventDetail Event={Event} /></TableCell></TableRow>}</Fragment>; })}</TableBody></Table>; }

function ResourceLinks(Input: Readonly<{ Event: EventRecord }>): ReactNode { const Event = Input.Event; return <div className="flex flex-col gap-1 text-xs">{Event.WorkerId && <NavLink className="flex min-h-6 items-center underline-offset-3 hover:underline" to={`/workers?${new URLSearchParams({ worker: Event.WorkerId, process: Event.ProcessId, generation: Event.GenerationId })}`}>{Event.WorkerId}</NavLink>}{Event.SessionId && <NavLink className="flex min-h-6 items-center underline-offset-3 hover:underline" to={EventSessionPath(Event)}>{Event.SessionId}</NavLink>}{!Event.WorkerId && !Event.SessionId && Event.AccountId && <NavLink className="flex min-h-6 items-center underline-offset-3 hover:underline" to={`/accounts?account=${encodeURIComponent(Event.AccountId)}`}>{Event.AccountId}</NavLink>}{!Event.WorkerId && !Event.SessionId && !Event.AccountId && <span>Process · G{Event.GenerationId}</span>}</div>; }

function EventDetail(Input: Readonly<{ Event: EventRecord }>): ReactNode { const [Copied, SetCopied] = useState(false), Event = Input.Event; const CopyCorrelation = async (): Promise<void> => { try { await navigator.clipboard.writeText(Event.CorrelationId); SetCopied(true); } catch { SetCopied(false); } }; return <div className="grid gap-3 rounded-lg bg-muted/40 p-4 text-sm sm:grid-cols-2"><Fact Label="类型 / 范围" Value={`${Event.Kind} / ${Event.Scope}`} /><Fact Label="Process / Generation" Value={`${Event.ProcessId} / ${Event.GenerationId}`} /><Fact Label="关联 ID" Value={Event.CorrelationId} Action={<Button type="button" size="sm" variant="outline" onClick={() => void CopyCorrelation()}><Copy aria-hidden="true" />{Copied ? '已复制' : '复制'}</Button>} /><Fact Label="终止状态" Value={Event.Terminal ? '终止事件' : '非终止事件'} /><Fact Label="Stream / Task" Value={`${Event.StreamId ?? '—'} / ${Event.TaskId ?? '—'}`} /><Fact Label="父 Task / 操作" Value={`${Event.ParentTaskId ?? '—'} / ${Event.OperationId ?? '—'}`} /><div className="sm:col-span-2"><p className="text-xs text-muted-foreground">详情</p><p className="mt-1 whitespace-pre-wrap">{Event.Detail || '没有额外描述。'}</p></div></div>; }
function Fact(Input: Readonly<{ Label: string; Value: string; Action?: ReactNode }>): ReactNode { return <div><p className="text-xs text-muted-foreground">{Input.Label}</p><div className="mt-1 flex items-center gap-2 break-all"><span>{Input.Value}</span>{Input.Action}</div></div>; }
function SeverityLabel(Value: EventSeverity): string { return Value === 'error' ? '错误' : Value === 'warning' ? '警告' : Value === 'debug' ? '调试' : '信息'; }
