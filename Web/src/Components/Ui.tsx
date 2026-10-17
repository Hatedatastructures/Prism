import { useId } from 'react';
import type { ReactNode } from 'react';
import { ArrowDownRight, ArrowUpRight, ChevronDown, ChevronRight, LoaderCircle } from 'lucide-react';
import type { UInt64Value } from '../Services/AdminDataSource';

export type Tone = 'good' | 'warning' | 'danger' | 'info' | 'neutral' | 'accent' | 'mint' | 'blue';

export function FormatCount(Value: UInt64Value | null | undefined): string {
    if (Value === null || Value === undefined) return '—';
    try { return new Intl.NumberFormat('zh-CN').format(BigInt(Value)); }
    catch { return '—'; }
}

export function FormatBytes(Value: UInt64Value | null | undefined, Precision = 1): string {
    if (Value === null || Value === undefined) return '—';
    let Bytes: bigint;
    try { Bytes = typeof Value === 'number' ? BigInt(Math.round(Value)) : BigInt(Value); } catch { return '—'; }
    if (Bytes < 0n) return '—';
    const Units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let Divisor = 1n;
    let Index = 0;
    while (Bytes >= Divisor * 1024n && Index < Units.length - 1) { Divisor *= 1024n; Index += 1; }
    const Amount = Number(Bytes / Divisor) + Number(Bytes % Divisor) / Number(Divisor);
    return `${new Intl.NumberFormat('zh-CN', { maximumFractionDigits: Precision }).format(Amount)} ${Units[Index]}`;
}

export function FormatRate(Value: UInt64Value | null | undefined): string {
    if (Value === null || Value === undefined) return '—';
    return `${FormatBytes(Value)}/s`;
}

export function FormatTime(Value: string | null | undefined, IncludeDate = false): string {
    if (!Value) return '—';
    const DateValue = new Date(Value);
    if (Number.isNaN(DateValue.valueOf())) return '时间不可用';
    return DateValue.toLocaleString('zh-CN', IncludeDate
        ? { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }
        : { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function PageHeader(Input: Readonly<{
    Title: string; Description?: string; Actions?: ReactNode;
}>): ReactNode {
    return <div className="page-header">
        <div className="page-heading">
            <h1>{Input.Title}</h1>
            {Input.Description && <p>{Input.Description}</p>}
        </div>
        {Input.Actions && <div className="page-actions">{Input.Actions}</div>}
    </div>;
}

export function SectionHeading(Input: Readonly<{
    Title: string; Detail?: string; Action?: ReactNode; ClassName?: string;
}>): ReactNode {
    return <div className={`section-heading ${Input.ClassName ?? ''}`}>
        <div><h2>{Input.Title}</h2>{Input.Detail && <p>{Input.Detail}</p>}</div>
        {Input.Action && <div className="section-action">{Input.Action}</div>}
    </div>;
}

export function Panel(Input: Readonly<{
    Title?: string; Subtitle?: string; Action?: ReactNode; children: ReactNode; ClassName?: string;
    Variant?: 'open' | 'banded';
}>): ReactNode {
    const ClassName = `surface surface-${Input.Variant ?? 'open'} ${Input.ClassName ?? ''}`;
    return <section className={ClassName}>
        {(Input.Title || Input.Subtitle || Input.Action) && <SectionHeading Title={Input.Title ?? ''}
            {...(Input.Subtitle === undefined ? {} : { Detail: Input.Subtitle })}
            {...(Input.Action === undefined ? {} : { Action: Input.Action })} ClassName="surface-heading" />}
        <div className="surface-content">{Input.children}</div>
    </section>;
}

export function Badge(Input: Readonly<{ children: ReactNode; Tone?: Tone; Dot?: boolean; ClassName?: string }>): ReactNode {
    return <span className={`badge badge-${Input.Tone ?? 'neutral'} ${Input.ClassName ?? ''}`}>
        {Input.Dot && <span className="badge-dot" aria-hidden="true" />}{Input.children}
    </span>;
}

export function StatusBadge(Input: Readonly<{ Label: string; Tone?: Tone }>): ReactNode {
    return <Badge Tone={Input.Tone ?? ToneForState(Input.Label)} Dot>{Input.Label}</Badge>;
}

export function ToneForState(Value: string): Tone {
    const State = Value.toLocaleLowerCase();
    if (['healthy', 'active', 'running', 'ok', 'ready', '运行中', '活动中', '接收中', '就绪', '已就绪', '健康', '正常', '已完成', '有效'].includes(State)) return 'good';
    if (['degraded', 'draining', 'warning', 'accepted', 'pending', '降级', '排空中', '等待中', '处理中'].includes(State)) return 'warning';
    if (['unhealthy', 'failed', 'rejected', 'error', 'revoked', '异常', '失败', '已撤销'].includes(State)) return 'danger';
    if (['info', 'debug', 'completed', '已结束'].includes(State)) return 'info';
    return 'neutral';
}

export function Metric(Input: Readonly<{
    Label: string; Value: string; Unit?: string; Hint?: string; Tone?: Tone; Delta?: string;
    Icon?: ReactNode; OnClick?: () => void; ClassName?: string;
    TrendValues?: readonly number[]; TrendLabel?: string;
}>): ReactNode {
    const Content = <>
        <span className="metric-top">{Input.Icon && <span className={`metric-icon metric-icon-${Input.Tone ?? 'accent'}`}>{Input.Icon}</span>}
            <span className="metric-label">{Input.Label}</span></span>
        <span className="metric-value-row"><strong>{Input.Value}</strong>{Input.Unit && <small>{Input.Unit}</small>}
            {Input.Delta && <span className="metric-delta">{Input.Delta}</span>}</span>
        {Input.Hint && <span className="metric-hint">{Input.Hint}</span>}
        {Input.TrendValues && <span className="metric-trend">
            <small className="metric-trend-caption" aria-hidden="true">近 60 秒</small>
            <TrendMini Values={Input.TrendValues} {...(Input.Tone === undefined ? {} : { Tone: Input.Tone })}
                Label={Input.TrendLabel ?? `${Input.Label} 趋势`} />
        </span>}
    </>;
    return Input.OnClick
        ? <button className={`metric metric-action ${Input.ClassName ?? ''}`} type="button" onClick={Input.OnClick}>{Content}<ChevronRight size={15} aria-hidden="true" /></button>
        : <div className={`metric ${Input.ClassName ?? ''}`}>{Content}</div>;
}

export function TrendMini(Input: Readonly<{ Values: readonly number[]; Tone?: Tone; Label: string }>): ReactNode {
    const FillId = useId();
    if (Input.Values.length < 2) return null;
    const Width = 72;
    const Height = 25;
    const Values = Input.Values;
    const Min = Math.min(...Values);
    const Max = Math.max(...Values);
    const Range = Max - Min || 1;
    const Coordinates = Values.map((Value, Index) => ({
        X: Values.length < 2 ? Width / 2 : (Index / (Values.length - 1)) * Width,
        Y: Height - 3 - ((Value - Min) / Range) * (Height - 8),
    }));
    const Points = Coordinates.map(Point => `${Point.X},${Point.Y}`).join(' ');
    const First = Coordinates[0] ?? { X: 0, Y: Height - 3 };
    const Last = Coordinates[Coordinates.length - 1] ?? First;
    return <svg className={`trend-mini trend-mini-${Input.Tone ?? 'accent'}`} viewBox={`0 0 ${Width} ${Height}`} preserveAspectRatio="none"
        role="img" aria-label={Input.Label}>
        <defs><linearGradient id={FillId} x1="0" y1="0" x2="0" y2="1"><stop stopColor="currentColor" stopOpacity=".22" />
            <stop offset="1" stopColor="currentColor" stopOpacity=".01" /></linearGradient></defs>
        <polygon points={`${First.X},${Height} ${Points} ${Last.X},${Height}`} fill={`url(#${FillId})`} />
        <polyline points={Points} fill="none" stroke="currentColor" strokeWidth="1.8" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
    </svg>;
}

export function ProgressBar(Input: Readonly<{ Value: number; Tone?: Tone; Label: string }>): ReactNode {
    const Value = Math.max(0, Math.min(100, Input.Value));
    return <div className={`progress progress-${Input.Tone ?? 'accent'}`} role="progressbar"
        aria-label={Input.Label} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(Value)}>
        <span style={{ width: `${Value}%` }} />
    </div>;
}

export function EmptyState(Input: Readonly<{ Title: string; Detail: string; Action?: ReactNode }>): ReactNode {
    return <div className="empty-state">
        <span className="empty-mark" aria-hidden="true"><span /><span /><span /></span>
        <strong>{Input.Title}</strong><p>{Input.Detail}</p>{Input.Action && <div>{Input.Action}</div>}
    </div>;
}

export function QueryState(Input: Readonly<{
    Pending: boolean; Error: Error | null | undefined; Label: string; HasData: boolean; Children: ReactNode;
    Empty?: ReactNode;
}>): ReactNode {
    if (Input.Pending && !Input.HasData) return <div className="query-state" role="status">
        <LoaderCircle size={18} className="spin" aria-hidden="true" /><span>正在载入{Input.Label}…</span></div>;
    if (Input.Error && !Input.HasData) return <div className="notice notice-danger" role="alert">
        <div><strong>{Input.Label}暂时无法载入</strong><p>{Input.Error.message}</p></div></div>;
    return <>{Input.Error && Input.HasData && <div className="notice notice-warning" role="status">
        {Input.Label}采样失败，当前保留上次有效数据。请检查数据源后重试。</div>}{Input.Children}</>;
}

export function LoadMoreButton(Input: Readonly<{ HasMore: boolean; Busy: boolean; OnLoad: () => void }>): ReactNode {
    if (!Input.HasMore) return null;
    return <div className="load-more-wrap"><button type="button" className="button button-quiet"
        disabled={Input.Busy} onClick={Input.OnLoad}>
        {Input.Busy ? <LoaderCircle size={15} className="spin" /> : <ChevronDown size={15} />}
        {Input.Busy ? '正在载入' : '载入更多'}
    </button></div>;
}

export function DirectionValue(Input: Readonly<{ Value: string; Direction: 'up' | 'down'; Label: string }>): ReactNode {
    const Icon = Input.Direction === 'up' ? <ArrowUpRight size={13} /> : <ArrowDownRight size={13} />;
    return <span className={`direction-value direction-${Input.Direction}`} aria-label={`${Input.Label} ${Input.Value}`}>
        {Icon}{Input.Value}
    </span>;
}

export function CopyValue(Input: Readonly<{ Value: string; Label?: string }>): ReactNode {
    return <code className="copy-value" title={Input.Value}>{Input.Label ?? Input.Value}</code>;
}

export function FilterBar(Input: Readonly<{ children: ReactNode; ClassName?: string }>): ReactNode {
    return <div className={`filter-bar ${Input.ClassName ?? ''}`}>{Input.children}</div>;
}
