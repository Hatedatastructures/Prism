/**
 * @file Shadcn 风格的 Prism 运行概览。
 * @brief 只改变呈现层；所有统计仍来自 AdminDataSource 的真实概览、入口、Worker、账户和事件查询。
 */
import type { ReactNode } from 'react';
import { ArrowRight, Gauge, RefreshCw } from 'lucide-react';
import { useSearchParams } from 'react-router';
import { NavLink } from 'react-router';
import { Button } from '@/Components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { useQueryClient } from '@tanstack/react-query';
import { EmptyState, FormatBytes, FormatCount, FormatTime, PageHeader, Panel, QueryState, StatusBadge } from '../../Components/Ui';
import type { AccountRecord, IngressRecord, ProtocolRecord, WorkerRecord } from '../../Services/AdminDataSource';
import { WithTime } from '../TimeRange';
import { useAdminQuery } from '../UseOperations';
import { OverviewChart } from './OverviewChart';
import { OverviewReadingsPanel } from './OverviewReadingsPanel';
import { OverviewResourceCharts } from './OverviewResourceCharts';
import { OverviewConnectionsChart } from './OverviewConnectionsChart';
import { DecideIngressRowPresentation, PresentIngressRows } from '../Ingresses/IngressPresentation';

type PageLink = Readonly<{ Path: string; Params: URLSearchParams; Label: string }>;

function DetailLink(Input: PageLink): ReactNode {
    return <NavLink className="inline-flex items-center gap-1 text-sm font-medium text-primary hover:underline" to={WithTime(Input.Path, Input.Params)}>
        {Input.Label}<ArrowRight aria-hidden="true" />
    </NavLink>;
}

/** @brief 以趋势与资源清单组织代理运行概览。 */
export default function OverviewPage(): ReactNode {
    const [Params] = useSearchParams();
    const QueryClient = useQueryClient();
    const Overview = useAdminQuery('overview', Source => Source.GetOverview());
    const Workers = useAdminQuery('overview-workers', Source => Source.GetWorkers({ Cursor: '0', Limit: 12 }));
    const Ingresses = useAdminQuery('overview-ingresses', Source => Source.GetIngresses({ Cursor: '0', Limit: 12 }));
    const Accounts = useAdminQuery('overview-accounts', Source => Source.GetAccounts({ Cursor: '0', Limit: 8 }));
    const Snapshot = Overview.data;
    const Refresh = async (): Promise<void> => {
        await Promise.all([Overview.refetch(), Workers.refetch(), Ingresses.refetch(), Accounts.refetch(), QueryClient.invalidateQueries({ queryKey: ['operations', 'overview-resource-sample'] })]);
    };

    return <div className="space-y-4">
        <PageHeader Title="运行概览" Description={Snapshot ? `最近采样 ${FormatTime(Snapshot.SampledAt)} · 当前实例的代理接入、流量与资源` : '当前实例的代理接入、流量与资源。'}
            Actions={<Button type="button" variant="outline" onClick={() => void Refresh()} disabled={Overview.isFetching || Workers.isFetching || Ingresses.isFetching || Accounts.isFetching}>
                <RefreshCw className={Overview.isFetching ? 'animate-spin' : ''} aria-hidden="true" />刷新数据
            </Button>} />
        <QueryState Pending={Overview.isPending} Error={Overview.error} HasData={Snapshot !== undefined} Label="运行概览"
            Retry={() => void Refresh()} Retrying={Overview.isFetching} Children={Snapshot ? <>
                <OverviewReadingsPanel Snapshot={Snapshot} />
                <OverviewConnectionsChart Snapshot={Snapshot} Params={Params} />
                <section className="grid min-w-0 gap-4 md:grid-cols-2 xl:grid-cols-4" aria-label="运行趋势">
                    <OverviewChart History={Snapshot.History} ClassName="md:col-span-2" />
                    <OverviewResourceCharts Params={Params} />
                </section>
                <section className="grid min-w-0 items-start gap-4 xl:grid-cols-2" aria-label="入口和调度">
                    <Panel HeadingLevel={2} Title="监听端口" Subtitle="配置地址与实际绑定" Action={<DetailLink Path="/ingresses" Params={Params} Label="查看入口" />}>
                        <IngressTable Rows={Ingresses.data?.Items ?? []} Pending={Ingresses.isPending} Error={Ingresses.error} Params={Params} />
                    </Panel>
                    <Panel HeadingLevel={2} Title="Worker 调度" Subtitle="当前已载入范围内的执行槽位" Action={<DetailLink Path="/workers" Params={Params} Label="查看全部 Worker" />}>
                        <WorkerTable Rows={Workers.data?.Items ?? []} Pending={Workers.isPending} Error={Workers.error} Params={Params} />
                    </Panel>
                </section>
                <section className="grid min-w-0 items-start gap-4 xl:grid-cols-2" aria-label="账户和协议">
                    <Panel HeadingLevel={2} Title="账户使用" Subtitle="当前已载入的账户与流量" Action={<DetailLink Path="/accounts" Params={Params} Label="管理账户" />}>
                        <AccountTable Rows={Accounts.data?.Items ?? []} Pending={Accounts.isPending} Error={Accounts.error} Params={Params} />
                    </Panel>
                    <Panel HeadingLevel={2} Title="协议使用" Subtitle="同类型配置共享会话与流量统计" Action={<DetailLink Path="/protocols" Params={Params} Label="查看协议" />}>
                        <ProtocolTable Rows={Snapshot.Protocols} Params={Params} />
                    </Panel>
                </section>
            </> : null} />
    </div>;
}

function ProtocolTable(Input: Readonly<{ Rows: readonly ProtocolRecord[]; Params: URLSearchParams }>): ReactNode {
    if (!Input.Rows.length) return <EmptyState Title="暂无协议配置" Detail="后端返回协议配置后会显示其统计覆盖。" />;
    return <Table className="min-w-[620px]"><TableHeader><TableRow><TableHead>协议 / 统计范围</TableHead><TableHead>活动 Session</TableHead><TableHead>累计上行</TableHead><TableHead>累计下行</TableHead><TableHead>累计 P95</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(Row => <TableRow key={Row.Id}><TableCell className="whitespace-normal"><NavLink className="font-semibold hover:underline" to={WithTime(`/protocols?protocol=${encodeURIComponent(Row.Id)}`, Input.Params)}>{Row.Name}</NavLink><p className="text-xs text-muted-foreground">{FormatCount(Row.ConfiguredBindings)} 个绑定 · {Row.Coverage || '统计范围未提供'}</p></TableCell><TableCell>{FormatCount(Row.ActiveSessions)}</TableCell><TableCell>{FormatBytes(Row.Traffic?.Up)}</TableCell><TableCell>{FormatBytes(Row.Traffic?.Down)}</TableCell><TableCell>{Row.Latency?.Available && Row.Latency.P95Ms !== null ? `${FormatCount(Row.Latency.P95Ms)} ms` : '未提供'}</TableCell></TableRow>)}</TableBody>
    </Table>;
}

function IngressTable(Input: Readonly<{ Rows: readonly IngressRecord[]; Pending: boolean; Error: Error | null; Params: URLSearchParams }>): ReactNode {
    if (Input.Pending) return <OverviewBlank Label="正在读取入口状态…" />;
    if (Input.Error) return <OverviewFailure Detail={Input.Error.message} />;
    if (!Input.Rows.length) return <EmptyState Title="尚无入口记录" Detail="配置并发布监听后，这里会显示真实绑定能力。" />;
    const Rows = PresentIngressRows(Input.Rows);
    return <div className="overflow-x-auto"><Table className="min-w-[720px]"><TableHeader><TableRow><TableHead>入口</TableHead><TableHead>配置监听</TableHead><TableHead>实际绑定</TableHead><TableHead>活动连接</TableHead><TableHead>协议</TableHead><TableHead>状态</TableHead></TableRow></TableHeader>
        <TableBody>{Rows.map(({ Value: Row, HasRuntimeState }) => {
            const Presentation = DecideIngressRowPresentation(Row, HasRuntimeState);
            return <TableRow key={Row.Id}><TableCell><NavLink className="font-medium hover:underline" to={WithTime(`/ingresses?ingress=${encodeURIComponent(Row.Id)}`, Input.Params)}>{Row.Transport.toUpperCase()}<span className="block font-mono text-xs font-normal text-muted-foreground">{Row.Id}</span></NavLink></TableCell>
                <TableCell><code className="whitespace-nowrap font-mono text-xs">{Row.ConfiguredAddress}</code></TableCell><TableCell><code className="whitespace-nowrap font-mono text-xs">{Row.BoundAddress ?? '未提供'}</code></TableCell>
                <TableCell>{HasRuntimeState && Row.ActiveConnections !== null ? FormatCount(Row.ActiveConnections) : '未提供'}</TableCell><TableCell className="max-w-48 truncate">{Row.Protocols.join(' · ') || '未提供'}</TableCell>
                <TableCell><StatusBadge Label={Presentation.Label} Tone={Presentation.Tone} /></TableCell></TableRow>;
        })}</TableBody></Table></div>;
}

function WorkerTable(Input: Readonly<{ Rows: readonly WorkerRecord[]; Pending: boolean; Error: Error | null; Params: URLSearchParams }>): ReactNode {
    if (Input.Pending) return <OverviewBlank Label="正在读取 Worker 状态…" />;
    if (Input.Error) return <OverviewFailure Detail={Input.Error.message} />;
    if (!Input.Rows.length) return <EmptyState Title="尚无 Worker 记录" Detail="运行时返回 Worker 后会在此显示调度槽位。" />;
    return <Table><TableHeader><TableRow><TableHead>Worker</TableHead><TableHead>状态</TableHead><TableHead>活动任务</TableHead><TableHead>命令邮箱</TableHead><TableHead>派发队列满（累计）</TableHead><TableHead>命令失败（累计）</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(Row => <TableRow key={`${Row.ProcessId}-${Row.GenerationId}-${Row.Id}`}><TableCell><NavLink className="font-medium hover:underline" to={WithTime(`/workers?worker=${encodeURIComponent(Row.Id)}&process=${encodeURIComponent(Row.ProcessId)}&generation=${encodeURIComponent(Row.GenerationId)}`, Input.Params)}>{Row.Name}</NavLink><p className="mt-0.5 font-mono text-xs text-muted-foreground">{Row.Id}</p></TableCell>
            <TableCell><StatusBadge Label={Row.Accepting ? '接收中' : Row.State === 'draining' ? '排空中' : '已停止'} /></TableCell><TableCell>{FormatCount(Row.ActiveTasks)}</TableCell>
            <TableCell>{FormatCount(Row.QueueDepth)} / {FormatCount(Row.QueueCapacity)}</TableCell><TableCell>{FormatCount(Row.DispatchFull)}</TableCell><TableCell>{FormatCount(Row.CommandsFailed)}</TableCell></TableRow>)}</TableBody>
    </Table>;
}

function AccountTable(Input: Readonly<{ Rows: readonly AccountRecord[]; Pending: boolean; Error: Error | null; Params: URLSearchParams }>): ReactNode {
    if (Input.Pending) return <OverviewBlank Label="正在读取账户状态…" />;
    if (Input.Error) return <OverviewFailure Detail={Input.Error.message} />;
    if (!Input.Rows.length) return <EmptyState Title="尚无账户记录" Detail="配置代理账户后会在此显示其使用状态。" />;
    return <Table><TableHeader><TableRow><TableHead>账户 / 用户组</TableHead><TableHead>活动会话</TableHead><TableHead>累计上行</TableHead><TableHead>累计下行</TableHead><TableHead>状态</TableHead></TableRow></TableHeader>
        <TableBody>{Input.Rows.map(Row => <TableRow key={Row.Id}><TableCell><NavLink className="font-semibold hover:underline" to={WithTime(`/accounts?account=${encodeURIComponent(Row.Id)}`, Input.Params)}>{Row.Label}</NavLink><p className="text-xs text-muted-foreground">{Row.GroupId ?? '未分组'}</p></TableCell><TableCell>{FormatCount(Row.ActiveSessions)}</TableCell><TableCell>{FormatBytes(Row.Traffic?.Up)}</TableCell><TableCell>{FormatBytes(Row.Traffic?.Down)}</TableCell><TableCell><StatusBadge Label={Row.Revoked ? '已撤销' : '有效'} /></TableCell></TableRow>)}</TableBody>
    </Table>;
}

function OverviewBlank(Input: Readonly<{ Label: string }>): ReactNode { return <div className="py-8 text-center text-sm text-muted-foreground"><Gauge className="mx-auto mb-2 size-5 animate-pulse" aria-hidden="true" />{Input.Label}</div>; }
function OverviewFailure(Input: Readonly<{ Detail: string }>): ReactNode { return <div className="rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">读取失败：{Input.Detail}</div>; }
