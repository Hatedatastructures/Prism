import { useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { FormatTime } from '../../Api/Decimal';
import type { Health, Page, Worker } from '../../Api/OperationsApi';
import { DecodeHealthQuery, DecodeWorkersQuery, PagePath, VerifyProcessScope } from '../../Api/OperationsApi';
import { useAdminServices } from '../UseOperations';
import { MetricsPanel } from '../Metrics/MetricsPanel';
import { DataCell, QueryView, SectionHeading, StatusBadge } from '../../Components/ResultView';

export default function OverviewPage(): ReactNode {
    const Services = useAdminServices();
    const Process = Services.Bootstrap.Process;
    const Incarnation = Services.Bootstrap.Incarnation;
    const HealthQuery = useQuery({
        queryKey: ['health', Process, Incarnation],
        queryFn: ({ signal }) => Services.Client.Query({ Path: '/Operations/Health',
            Signal: signal, Decode: DecodeHealthQuery }),
        refetchInterval: 2000,
        refetchIntervalInBackground: false,
        retry: false,
    });
    const WorkerQuery = useQuery({
        queryKey: ['workers', Process, Incarnation, 'overview'],
        queryFn: ({ signal }) => Services.Client.Query({
            Path: PagePath('/Operations/Workers', '0', 100),
            Signal: signal, Decode: Response => VerifyProcessScope(
                DecodeWorkersQuery(Response), Process),
        }),
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
    });
    return <>
        <SectionHeading Eyebrow="SYSTEM OVERVIEW" Title="运行概览"
            Description="就绪层、活动连接和观察计数来自当前 Operations 快照；页面在后台隐藏时暂停轮询。" />
        <QueryView Query={HealthQuery} Label="健康快照" Children={Value => <HealthOverview Value={Value} />} />
        <section className="panel">
            <div className="panel-heading"><div><h2>Worker 当前页统计</h2>
                <p>只汇总本次返回的 Worker 页面；存在后续页时不代表全局总量。</p></div></div>
            <div className="panel-body"><QueryView Query={WorkerQuery} Label="Worker 快照"
                Children={Value => <WorkerOverview Value={Value} />} /></div>
        </section>
        <MetricsPanel />
    </>;
}

function HealthOverview(Input: Readonly<{ Value: Health }>): ReactNode {
    const StatusTone = HealthTone(Input.Value.Status);
    let Retirement = '未提供';
    if (Input.Value.RetirementFailures !== null) {
        const Value = Input.Value.RetirementFailures;
        Retirement = `Session ${Value.Session} · Stream ${Value.Stream} · Task ${Value.Task}`;
    }
    return <>
        <div className="metric-grid">
            <Metric Label="健康状态" Value={<StatusBadge Label={Input.Value.Status} Tone={StatusTone} />}
                Note={`检查时间 ${FormatTime(Input.Value.CheckedAt)}`} />
            <Metric Label="活动量" Value={Input.Value.Active} Note="进程健康快照中的 active 计数" />
            <Metric Label="错误计数" Value={Input.Value.Errors} Note="累计观察值；不代表最近窗口错误" />
            <Metric Label="退休失败" Value={Retirement} Note="统计键退休失败观察计数" />
        </div>
        <div className="panel">
            <div className="panel-heading"><div><h2>入口就绪层</h2>
                <p>协议、socket、握手和协议启动就绪分别呈现。</p></div></div>
            <div className="panel-body"><div className="readiness-grid">
                <Readiness Label="整体" Ready={Input.Value.Ready} />
                <Readiness Label="TCP" Ready={Input.Value.TcpReady} />
                <Readiness Label="UDP" Ready={Input.Value.UdpReady} />
                <Readiness Label="UDP socket" Ready={Input.Value.UdpSocketReady} />
                <Readiness Label="QUIC" Ready={Input.Value.QuicReady} />
                <Readiness Label="QUIC socket" Ready={Input.Value.QuicSocketReady} />
                <Readiness Label="QUIC handshake" Ready={Input.Value.QuicHandshakeReady} />
                <Readiness Label="QUIC protocol" Ready={Input.Value.QuicProtocolReady} />
            </div></div>
        </div>
    </>;
}

function WorkerOverview(Input: Readonly<{ Value: Page<Worker> }>): ReactNode {
    const Page = Input.Value;
    if (Page === null) return null;
    let UpBytes = 0n;
    let DownBytes = 0n;
    let DroppedEvents = 0n;
    let MissingTraffic = 0;
    for (const Worker of Page.Items) {
        if (Worker.Traffic === null) {
            ++MissingTraffic;
        } else {
            UpBytes += BigInt(Worker.Traffic.UpBytes);
            DownBytes += BigInt(Worker.Traffic.DownBytes);
        }
        DroppedEvents += BigInt(Worker.DroppedEvents);
    }
    let Up = FormatAggregateBytes(UpBytes);
    let Down = FormatAggregateBytes(DownBytes);
    if (MissingTraffic > 0) {
        const Notice = `${MissingTraffic} 个 Worker 未采集，合计不完整`;
        Up = Notice;
        Down = Notice;
    }
    return <div className="data-grid">
        <DataCell Label="返回 Worker" Value={Page.Items.length} />
        <DataCell Label="本页上行合计" Value={Up} />
        <DataCell Label="本页下行合计" Value={Down} />
        <DataCell Label="观察丢弃事件" Value={DroppedEvents.toString()} />
        <DataCell Label="下一页" Value={NextPageLabel(Page)} />
    </div>;
}

function NextPageLabel(PageValue: Page<Worker>): string {
    if (PageValue.HasMore) return `游标 ${PageValue.NextCursor}`;
    return '没有后续页';
}

function FormatAggregateBytes(Value: bigint): string {
    const Units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB'] as const;
    let Divisor = 1n;
    let Index = 0;
    while (Value / Divisor >= 1024n && Index < Units.length - 1) {
        Divisor *= 1024n;
        ++Index;
    }
    if (Index === 0) return `${Value.toLocaleString('zh-CN')} B`;
    const Whole = Value / Divisor;
    const Fraction = ((Value % Divisor) * 100n / Divisor).toString().padStart(2, '0');
    return `${Whole}.${Fraction} ${Units[Index]}`;
}

function Metric(Input: Readonly<{ Label: string; Value: ReactNode; Note: string }>): ReactNode {
    return <div className="metric-card metric-accent"><span className="metric-label">{Input.Label}</span>
        <strong className="metric-value">{Input.Value}</strong><small className="metric-note">{Input.Note}</small></div>;
}

function Readiness(Input: Readonly<{ Label: string; Ready: boolean }>): ReactNode {
    let Tone: 'good' | 'warn' = 'warn';
    let Label = '未就绪';
    if (Input.Ready) {
        Tone = 'good';
        Label = '就绪';
    }
    return <div className="readiness-item"><span>{Input.Label}</span>
        <StatusBadge Label={Label} Tone={Tone} /></div>;
}

function HealthTone(Value: Health['Status']): 'good' | 'warn' | 'bad' | 'neutral' {
    if (Value === 'healthy') return 'good';
    if (Value === 'degraded' || Value === 'draining') return 'warn';
    if (Value === 'unhealthy') return 'bad';
    return 'neutral';
}
