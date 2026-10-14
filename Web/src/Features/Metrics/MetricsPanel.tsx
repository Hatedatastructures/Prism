import { useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { FormatBytes, FormatTime } from '../../Api/Decimal';
import { ContractFailure } from '../../Api/Decode';
import { DecodeMetricsQuery, MaxMetricHistorySamples } from '../../Api/OperationsApi';
import type { Metrics, RecognitionLatency, TrafficSample } from '../../Api/OperationsApi';
import { DataCell, EmptyState, QueryView } from '../../Components/ResultView';
import { HasCapability, useAdminServices } from '../UseOperations';
import './Metrics.css';

export function MetricsPanel(): ReactNode {
    const Services = useAdminServices();
    const CanRead = HasCapability(Services, 'metrics.read');
    const Query = useQuery({
        queryKey: ['metrics', Services.Bootstrap.Process, Services.Bootstrap.Incarnation],
        queryFn: ({ signal }) => Services.Client.Query({ Path: '/Operations/Metrics', Signal: signal,
            Decode: Response => {
                const Decoded = DecodeMetricsQuery(Response);
                if (Decoded.Ok && Decoded.Value.Value !== null &&
                    Decoded.Value.Value.Process !== Services.Bootstrap.Process) return ContractFailure();
                return Decoded;
            } }),
        enabled: CanRead,
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
    });
    return <section className="panel">
        <div className="panel-heading"><div><h2>进程流量与采样历史</h2>
            <p>只显示后端实际记录的采样，进程累计包括仍在运行的旧代次会话。</p></div></div>
        <div className="panel-body">
            {!CanRead && <EmptyState Title="指标查询不可用" Detail="当前服务没有提供指标查询。" />}
            {CanRead && <QueryView Query={Query} Label="进程指标"
                Children={Value => <MetricsView Value={Value} />} />}
        </div>
    </section>;
}

function MetricsView(Input: Readonly<{ Value: Metrics }>): ReactNode {
    const Value = Input.Value;
    return <>
        <div className="data-grid">
            <DataCell Label="上传累计" Value={FormatBytes(Value.Traffic.UpBytes)} />
            <DataCell Label="下载累计" Value={FormatBytes(Value.Traffic.DownBytes)} />
            <DataCell Label="观察队列已接收 / 已处理" Value={`${Value.Accepted} / ${Value.Consumed}`} />
            <DataCell Label="观察队列丢弃 / 处理失败" Value={`${Value.Dropped} / ${Value.AggregationFailures}`} />
            <DataCell Label="识别延迟采样丢弃 / 处理失败"
                Value={`${Value.RecognitionLatencyQueueDropped} / ${Value.RecognitionLatencyAggregationFailures}`} />
            <DataCell Label="会话 / Stream / Task 收尾失败"
                Value={`${Value.RetirementFailures.Session} / ${Value.RetirementFailures.Stream} / ${Value.RetirementFailures.Task}`} />
            <DataCell Label="历史样本 / 固定容量" Value={`${Value.History.length} / ${MaxMetricHistorySamples}`} />
            <DataCell Label="实际采样周期" Value={`${Value.SampleInterval} ms`} />
            <DataCell Label="配置版本 / 读取时间" Value={`${Value.Generation} / ${FormatTime(Value.CheckedAt)}`} />
        </div>
        <p className="scope-note">历史值来自实际采样，最多保留 {MaxMetricHistorySamples} 个点；服务当前没有提供观察队列容量数值。</p>
        <p className="scope-note">识别延迟直方图上限为 300,000,000 µs；延迟采样队列丢弃已计入上方观察队列丢弃总数。</p>
        <RecognitionLatencyView Value={Value.RecognitionLatency}
            QueueDropped={Value.RecognitionLatencyQueueDropped}
            AggregationFailures={Value.RecognitionLatencyAggregationFailures} />
        {!Value.HistoryReady && <EmptyState Title="尚无采样记录" Detail="累计计数已可读取，等待下一次实际采样。" />}
        {Value.HistoryReady && <TrafficHistory Samples={Value.History} Interval={Value.SampleInterval} />}
    </>;
}

function RecognitionLatencyView(Input: Readonly<{
    Value: RecognitionLatency; QueueDropped: string; AggregationFailures: string;
}>): React.ReactNode {
    const Value = Input.Value;
    return <section className="scope-area" aria-label="识别准入延迟">
        <h3>识别准入延迟</h3>
        <div className="data-grid">
            <DataCell Label="采样范围 / 单位" Value="连接识别入口 · 微秒（µs）" />
            <DataCell Label="样本配置版本 / 样本数" Value={`${Value.Generation} / ${Value.SampleCount}`} />
            <DataCell Label="追踪采样已记录 / 丢弃" Value={`${Value.TracerWritten} / ${Value.TracerDropped}`} />
            <DataCell Label="超出采样范围" Value={Value.HistogramRangeExceeded} />
            <DataCell Label="队列丢弃 / 聚合失败" Value={`${Input.QueueDropped} / ${Input.AggregationFailures}`} />
            <DataCell Label="P50 估算下界" Value={FormatMicroseconds(Value.P50BucketLowerBoundUs)} />
            <DataCell Label="P95 估算下界" Value={FormatMicroseconds(Value.P95BucketLowerBoundUs)} />
            <DataCell Label="P99 估算下界" Value={FormatMicroseconds(Value.P99BucketLowerBoundUs)} />
            <DataCell Label="实测最大值" Value={FormatMicroseconds(Value.MaxObservedUs)} />
        </div>
        {!Value.Ready && <EmptyState Title="尚无实际识别延迟样本"
            Detail="百分位和最大值由服务端明确返回为空；页面不生成零样本。" />}
        {Value.Ready && <RecentLatency Samples={Value.RecentUs} />}
        <p className="scope-note">P50/P95/P99 是直方图桶下界的近似值；最大值来自实测样本。数据范围为当前管理进程。</p>
    </section>;
}

function RecentLatency(Input: Readonly<{ Samples: readonly string[] }>): React.ReactNode {
    if (Input.Samples.length === 0) return <EmptyState Title="当前没有最近样本"
        Detail="服务端历史计数已就绪，但没有提供可展示的最近实测值。" />;
    return <div className="status-detail">
        <strong>最近实测值（µs）</strong>
        <ol>{Input.Samples.map((Sample, Index) => <li key={`${Index}-${Sample}`}>{Sample} µs</li>)}</ol>
    </div>;
}

function FormatMicroseconds(Value: string | null): string {
    if (Value === null) return '未提供';
    return `${Value} µs`;
}

function TrafficHistory(Input: Readonly<{
    Samples: readonly TrafficSample[]; Interval: string;
}>): ReactNode {
    const [SelectedTimestamp, SetSelectedTimestamp] = useState<string | null>(null);
    const Last = Input.Samples[Input.Samples.length - 1];
    const First = Input.Samples[0];
    if (First === undefined || Last === undefined) return null;
    let SelectedIndex = Input.Samples.findIndex(Sample => Sample.Timestamp === SelectedTimestamp);
    if (SelectedIndex < 0) SelectedIndex = Input.Samples.length - 1;
    const Selected = Input.Samples[SelectedIndex];
    if (Selected === undefined) return null;
    const Width = 760, Height = 210, Left = 18, Top = 18;
    const TimeStart = BigInt(First.Timestamp);
    const TimeSpan = BigInt(Last.Timestamp) - TimeStart;
    const Maximum = Input.Samples.reduce((Max, Sample) => {
        const Up = BigInt(Sample.Traffic.UpBytes), Down = BigInt(Sample.Traffic.DownBytes);
        let Value = Max;
        if (Up > Value) Value = Up;
        if (Down > Value) Value = Down;
        return Value;
    }, 0n);
    function X(Sample: TrafficSample): number {
        if (TimeSpan === 0n) return Left + Width;
        return Left + Number((BigInt(Sample.Timestamp) - TimeStart) * BigInt(Width * 1000) / TimeSpan) / 1000;
    }
    function Y(Value: string): number {
        if (Maximum === 0n) return Top + Height;
        return Top + Height - Number(BigInt(Value) * BigInt(Height * 1000) / Maximum) / 1000;
    }
    const Groups: TrafficSample[][] = [];
    let Group: TrafficSample[] = [];
    let Previous: TrafficSample | undefined;
    for (const Sample of Input.Samples) {
        if (Previous !== undefined && BigInt(Sample.Timestamp) - BigInt(Previous.Timestamp) > BigInt(Input.Interval) * 3n) {
            Groups.push(Group);
            Group = [];
        }
        Group.push(Sample);
        Previous = Sample;
    }
    if (Group.length > 0) Groups.push(Group);
    return <div className="metrics-history">
        <div className="button-row"><span className="badge metrics-upload-label">上传累计</span>
            <span className="badge metrics-download-label">下载累计</span>
            <span className="muted">{Input.Samples.length} 个真实采样</span></div>
        <svg className="metrics-chart" viewBox={`0 0 ${Width + Left * 2} ${Height + Top * 2}`}
            role="img" aria-label="进程累计流量历史；下方滑块可查看每个采样的精确值">
            <path className="metrics-axis" d={`M ${Left} ${Top} V ${Top + Height} H ${Left + Width}`} />
            {Groups.map(Samples => <g key={Samples[0]?.Timestamp}>
                <polyline className="metrics-upload-line" points={Samples.map(Sample => `${X(Sample)},${Y(Sample.Traffic.UpBytes)}`).join(' ')} />
                <polyline className="metrics-download-line" points={Samples.map(Sample => `${X(Sample)},${Y(Sample.Traffic.DownBytes)}`).join(' ')} />
            </g>)}
            <path className="metrics-cursor" d={`M ${X(Selected)} ${Top} V ${Top + Height}`} />
            <circle className="metrics-upload-point" cx={X(Selected)} cy={Y(Selected.Traffic.UpBytes)} r="4" />
            <circle className="metrics-download-point" cx={X(Selected)} cy={Y(Selected.Traffic.DownBytes)} r="4" />
        </svg>
        <label className="field">查看真实采样
            <input type="range" min="0" max={Input.Samples.length - 1} step="1" value={SelectedIndex}
                aria-valuetext={FormatTime(Selected.Timestamp)} onChange={Event => {
                    const Sample = Input.Samples[Number(Event.target.value)];
                    if (Sample !== undefined) SetSelectedTimestamp(Sample.Timestamp);
                }} /></label>
        <div className="data-grid" aria-live="polite">
            <DataCell Label="采样时间" Value={FormatTime(Selected.Timestamp)} />
            <DataCell Label="上传精确字节" Value={Selected.Traffic.UpBytes} />
            <DataCell Label="下载精确字节" Value={Selected.Traffic.DownBytes} />
        </div>
        <p className="scope-note">折线连接实际采样；较长采样缺口保持断开。精确计数保留十进制整数，图中位置仅用于比较。</p>
    </div>;
}
