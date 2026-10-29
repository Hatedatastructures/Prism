import { useEffect, useId, useRef } from 'react';
import type { ReactNode } from 'react';
import { ArrowDownRight, ArrowLeft, ArrowUpRight, ChevronDown, Inbox, Info, LoaderCircle } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Badge as ShadcnBadge } from '@/Components/ui/badge';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Popover, PopoverContent, PopoverDescription, PopoverHeader, PopoverTitle, PopoverTrigger } from '@/Components/ui/popover';
import { Progress } from '@/Components/ui/progress';
import { Skeleton } from '@/Components/ui/skeleton';
import { cn } from '@/lib/utils';
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

/** @brief 将已格式化的测量值与单位按 Shadcn 排版层级显示。 */
export function MeasureValue(Input: Readonly<{ Value: string }>): ReactNode {
    const UnitStart = Input.Value.lastIndexOf(' ');
    if (UnitStart < 0) return Input.Value;
    return <>{Input.Value.slice(0, UnitStart)}<span className="ml-1 text-sm font-medium text-muted-foreground">{Input.Value.slice(UnitStart)}</span></>;
}

/** @brief 使用官方 Popover 容纳统计范围说明。 */
export function ScopePopover(Input: Readonly<{
    Label: string;
    Variant?: 'panel' | 'table';
    children: ReactNode;
}>): ReactNode {
    const HeadingId = useId();
    return <Popover>
        <PopoverTrigger asChild>
            <Button variant="ghost" size="sm" type="button" className="h-7 gap-1 text-muted-foreground" title={Input.Label}>
                <Info aria-hidden="true" /> <span>{Input.Label}</span>{Input.Variant === 'panel' && <ChevronDown aria-hidden="true" />}
            </Button>
        </PopoverTrigger>
        <PopoverContent align={Input.Variant === 'table' ? 'start' : 'end'} aria-labelledby={HeadingId}>
            <PopoverHeader><PopoverTitle id={HeadingId}>统计说明 · {Input.Label}</PopoverTitle>
                <PopoverDescription>仅基于当前已载入且可观测的数据范围。</PopoverDescription></PopoverHeader>
            <div className="text-sm leading-6 text-muted-foreground">{Input.children}</div>
        </PopoverContent>
    </Popover>;
}

export function CapabilityNotice(Input: Readonly<{ Title: string; Detail: string; Compact?: boolean }>): ReactNode {
    return <Alert className={cn('items-start', Input.Compact && 'px-3 py-2')}>
        <Info aria-hidden="true" /><AlertTitle>{Input.Title}</AlertTitle><AlertDescription>{Input.Detail}</AlertDescription>
    </Alert>;
}

export function FormatTime(Value: string | null | undefined, IncludeDate = false): string {
    if (!Value) return '—';
    const DateValue = new Date(Value);
    if (Number.isNaN(DateValue.valueOf())) return '时间不可用';
    return DateValue.toLocaleString('zh-CN', IncludeDate
        ? { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }
        : { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

export function PageHeader(Input: Readonly<{ Title: string; Description?: string; Actions?: ReactNode }>): ReactNode {
    return <header className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 space-y-1"><h1 className="text-2xl font-bold tracking-tight text-foreground">{Input.Title}</h1>
            {Input.Description && <p className="max-w-3xl text-sm leading-6 text-muted-foreground">{Input.Description}</p>}</div>
        {Input.Actions && <div className="flex shrink-0 flex-wrap items-center gap-2 sm:pt-1">{Input.Actions}</div>}
    </header>;
}

export function SectionHeading(Input: Readonly<{ Title: string; Detail?: string; Action?: ReactNode; ClassName?: string }>): ReactNode {
    return <div className={cn('flex min-w-0 items-start justify-between gap-4', Input.ClassName)}>
        <div className="min-w-0 space-y-1"><h2 className="text-base font-semibold tracking-tight">{Input.Title}</h2>
            {Input.Detail && <p className="text-sm text-muted-foreground">{Input.Detail}</p>}</div>
        {Input.Action && <div className="shrink-0">{Input.Action}</div>}
    </div>;
}

export function MobileMasterBack(Input: Readonly<{ Label: string; OnClick: () => void }>): ReactNode {
    const ButtonRef = useRef<HTMLButtonElement>(null);
    useEffect(() => {
        if (!window.matchMedia('(max-width: 767px)').matches) return;
        const Active = document.activeElement;
        if (!(Active instanceof HTMLElement) || Active === document.body || !Active.isConnected || Active.getClientRects().length === 0)
            ButtonRef.current?.focus();
    }, []);
    return <Button ref={ButtonRef} className="mobile-master-back" variant="outline" size="sm" type="button" onClick={Input.OnClick}>
        <ArrowLeft aria-hidden="true" />{Input.Label}
    </Button>;
}

export function FocusMobileMasterBack(): void {
    if (window.matchMedia('(max-width: 767px)').matches) window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
        document.querySelector<HTMLButtonElement>('.mobile-master-back')?.focus();
    }));
}

export function FocusMobileMasterList(): void {
    if (window.matchMedia('(max-width: 767px)').matches) window.requestAnimationFrame(() => window.requestAnimationFrame(() => {
        document.querySelector<HTMLElement>('[data-mobile-master-list]')?.focus();
    }));
}

/** @brief 仅在手机端列表/详情切换完成后移动焦点，不打断页面初次进入。 */
export function useMobileMasterFocus(View: 'list' | 'detail'): void {
    const PreviousView = useRef(View);
    useEffect(() => {
        if (PreviousView.current === View) return;
        PreviousView.current = View;
        if (View === 'detail') FocusMobileMasterBack();
        else FocusMobileMasterList();
    }, [View]);
}

/** @brief 所有业务区块统一委托给 Shadcn Card，而不是旧 surface CSS。 */
export function Panel(Input: Readonly<{
    Title?: string; Subtitle?: string; Action?: ReactNode; children: ReactNode; ClassName?: string;
    Variant?: 'open' | 'banded'; HeadingLevel?: 2 | 3;
}>): ReactNode {
    return <Card className={cn('surface min-w-0 gap-0 overflow-hidden py-0', Input.Variant === 'banded' && 'bg-muted/30', Input.ClassName)}>
        {(Input.Title || Input.Subtitle || Input.Action) && <CardHeader className="px-5 pt-4 pb-0">
            <div className="flex min-w-0 items-start justify-between gap-4"><div className="min-w-0 space-y-1"><CardTitle role={Input.HeadingLevel ? 'heading' : undefined} aria-level={Input.HeadingLevel}>{Input.Title ?? ''}</CardTitle>
                {Input.Subtitle && <CardDescription>{Input.Subtitle}</CardDescription>}</div>{Input.Action && <div className="shrink-0">{Input.Action}</div>}</div>
        </CardHeader>}
        <CardContent className="min-w-0 p-5 pt-4">{Input.children}</CardContent>
    </Card>;
}

function BadgePresentation(ToneValue: Tone): Readonly<{ Variant: 'default' | 'secondary' | 'outline' | 'destructive'; ClassName: string }> {
    if (ToneValue === 'good' || ToneValue === 'mint') return { Variant: 'outline', ClassName: 'border-emerald-200 bg-emerald-50 text-emerald-700 dark:border-emerald-900 dark:bg-emerald-950 dark:text-emerald-300' };
    if (ToneValue === 'warning') return { Variant: 'outline', ClassName: 'border-amber-200 bg-amber-50 text-amber-800 dark:border-amber-900 dark:bg-amber-950 dark:text-amber-200' };
    if (ToneValue === 'danger') return { Variant: 'destructive', ClassName: '' };
    if (ToneValue === 'info' || ToneValue === 'blue') return { Variant: 'outline', ClassName: 'border-sky-200 bg-sky-50 text-sky-700 dark:border-sky-900 dark:bg-sky-950 dark:text-sky-300' };
    if (ToneValue === 'accent') return { Variant: 'default', ClassName: '' };
    return { Variant: 'secondary', ClassName: '' };
}

/** @brief 状态标签使用官方 Badge 的 variants，业务 Tone 仅映射为语义状态。 */
export function Badge(Input: Readonly<{ children: ReactNode; Tone?: Tone; Dot?: boolean; ClassName?: string }>): ReactNode {
    const Presentation = BadgePresentation(Input.Tone ?? 'neutral');
    return <ShadcnBadge variant={Presentation.Variant} className={cn('gap-1.5', Presentation.ClassName, Input.ClassName)}>
        {Input.Dot && <span className="size-1.5 rounded-full bg-current" aria-hidden="true" />}{Input.children}
    </ShadcnBadge>;
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

function ToneText(ToneValue: Tone | undefined): string {
    if (ToneValue === 'good' || ToneValue === 'mint') return 'text-emerald-600 dark:text-emerald-400';
    if (ToneValue === 'warning') return 'text-amber-600 dark:text-amber-400';
    if (ToneValue === 'danger') return 'text-destructive';
    if (ToneValue === 'info' || ToneValue === 'blue') return 'text-sky-600 dark:text-sky-400';
    return 'text-primary';
}

export function Metric(Input: Readonly<{
    Label: string; Value: string; Unit?: string; Hint?: string; Tone?: Tone; Delta?: string;
    Icon?: ReactNode; OnClick?: () => void; ClassName?: string;
    TrendValues?: readonly number[]; TrendLabel?: string;
}>): ReactNode {
    const Content = <><div className="flex min-w-0 items-start gap-3">{Input.Icon && <span className="flex size-9 shrink-0 items-center justify-center rounded-md bg-muted text-muted-foreground [&_svg]:size-4">{Input.Icon}</span>}<div className="min-w-0 flex-1"><div className="flex min-w-0 items-start justify-between gap-2"><span className="text-sm font-medium text-muted-foreground">{Input.Label}</span>
        <div className="flex min-w-0 items-baseline gap-1 text-right"><strong className="break-words text-xl font-semibold tracking-tight tabular-nums">{Input.Value}</strong>{Input.Unit && <small className="text-sm text-muted-foreground">{Input.Unit}</small>}{Input.Delta && <span className={cn('text-xs font-medium', ToneText(Input.Tone))}>{Input.Delta}</span>}</div></div>
        {Input.Hint && <p className="mt-1 text-xs text-muted-foreground">{Input.Hint}</p>}</div></div>
        {Input.TrendValues && <div className={cn('mt-4 h-8', ToneText(Input.Tone))}><TrendMini Values={Input.TrendValues} Label={Input.TrendLabel ?? `${Input.Label} 趋势`} /></div>}</>;
    const ClassName = cn('min-w-0 rounded-lg border bg-card p-3 text-left text-card-foreground shadow-sm', Input.OnClick && 'transition-colors hover:bg-muted/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring', Input.ClassName);
    return Input.OnClick ? <button className={ClassName} type="button" onClick={Input.OnClick}>{Content}</button>
        : <div className={ClassName}>{Content}</div>;
}

export function TrendMini(Input: Readonly<{ Values: readonly number[]; Tone?: Tone; Label: string }>): ReactNode {
    const FillId = useId();
    if (Input.Values.length < 2) return null;
    const Width = 72, Height = 25;
    const Min = Math.min(...Input.Values), Max = Math.max(...Input.Values), Range = Max - Min || 1;
    const Coordinates = Input.Values.map((Value, Index) => ({ X: (Index / (Input.Values.length - 1)) * Width, Y: Height - 3 - ((Value - Min) / Range) * (Height - 8) }));
    const Points = Coordinates.map(Point => `${Point.X},${Point.Y}`).join(' ');
    const First = Coordinates[0] ?? { X: 0, Y: Height - 3 }, Last = Coordinates.at(-1) ?? First;
    return <svg className="size-full" viewBox={`0 0 ${Width} ${Height}`} preserveAspectRatio="none" role="img" aria-label={Input.Label}>
        <defs><linearGradient id={FillId} x1="0" y1="0" x2="0" y2="1"><stop stopColor="currentColor" stopOpacity=".22" /><stop offset="1" stopColor="currentColor" stopOpacity=".01" /></linearGradient></defs>
        <polygon points={`${First.X},${Height} ${Points} ${Last.X},${Height}`} fill={`url(#${FillId})`} />
        <polyline points={Points} fill="none" stroke="currentColor" strokeWidth="1.8" vectorEffect="non-scaling-stroke" strokeLinecap="round" strokeLinejoin="round" />
    </svg>;
}

export function ProgressBar(Input: Readonly<{ Value: number; Tone?: Tone; Label: string }>): ReactNode {
    const Value = Math.max(0, Math.min(100, Input.Value));
    return <Progress value={Value} aria-label={Input.Label} className={cn('progress', ToneText(Input.Tone), '[&_[data-slot=progress-indicator]]:bg-current')} />;
}

export function EmptyState(Input: Readonly<{ Title: string; Detail: string; Action?: ReactNode }>): ReactNode {
    return <Card className="border-dashed shadow-none"><CardContent className="flex flex-col items-center px-6 py-12 text-center">
        <Inbox className="mb-3 size-8 text-muted-foreground" strokeWidth={1.5} aria-hidden="true" /><strong className="text-sm font-medium">{Input.Title}</strong>
        <p className="mt-1 max-w-md text-sm text-muted-foreground">{Input.Detail}</p>{Input.Action && <div className="mt-4">{Input.Action}</div>}
    </CardContent></Card>;
}

export function QueryState(Input: Readonly<{
    Pending: boolean; Error: Error | null | undefined; Label: string; HasData: boolean; Children: ReactNode;
    Empty?: ReactNode; Retry?: () => void; Retrying?: boolean;
}>): ReactNode {
    if (Input.Pending && !Input.HasData) return <div className="space-y-3" role="status" aria-label={`正在载入${Input.Label}`}>
        <div className="flex items-center gap-2 text-sm text-muted-foreground"><LoaderCircle className="size-4 animate-spin" aria-hidden="true" />正在载入{Input.Label}…</div>
        <Skeleton className="h-28 w-full" /><Skeleton className="h-28 w-full" />
    </div>;
    const RetryAction = Input.Retry && <Button type="button" variant="outline" size="sm" disabled={Input.Retrying} onClick={Input.Retry}>
        {Input.Retrying ? <><LoaderCircle className="animate-spin" aria-hidden="true" />正在重试</> : '重试读取'}
    </Button>;
    if (Input.Error && !Input.HasData) return <Alert variant="destructive"><Info aria-hidden="true" /><AlertTitle>{Input.Label}暂时无法载入</AlertTitle><AlertDescription>{Input.Error.message}</AlertDescription>{RetryAction}</Alert>;
    return <>{Input.Error && Input.HasData && <Alert><Info aria-hidden="true" /><AlertTitle>{Input.Label}刷新失败</AlertTitle><AlertDescription>当前仍显示上次成功读取的数据。</AlertDescription>{RetryAction}</Alert>}{Input.Children}</>;
}

export function LoadMoreButton(Input: Readonly<{ HasMore: boolean; Busy: boolean; OnLoad: () => void }>): ReactNode {
    if (!Input.HasMore) return null;
    return <div className="flex justify-center pt-4"><Button type="button" variant="outline" disabled={Input.Busy} onClick={Input.OnLoad}>
        {Input.Busy ? <LoaderCircle className="animate-spin" aria-hidden="true" /> : <ChevronDown aria-hidden="true" />}{Input.Busy ? '正在载入' : '载入更多'}
    </Button></div>;
}

export function DirectionValue(Input: Readonly<{ Value: string; Direction: 'up' | 'down'; Label: string }>): ReactNode {
    const Icon = Input.Direction === 'up' ? ArrowUpRight : ArrowDownRight;
    return <span className={cn('inline-flex items-center gap-1 text-xs font-medium', Input.Direction === 'up' ? 'text-emerald-600 dark:text-emerald-400' : 'text-sky-600 dark:text-sky-400')} aria-label={`${Input.Label} ${Input.Value}`}><Icon aria-hidden="true" />{Input.Value}</span>;
}

export function CopyValue(Input: Readonly<{ Value: string; Label?: string }>): ReactNode {
    return <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs" title={Input.Value}>{Input.Label ?? Input.Value}</code>;
}

export function FilterBar(Input: Readonly<{ children: ReactNode; ClassName?: string }>): ReactNode {
    return <div className={cn('flex flex-wrap items-end gap-3 rounded-lg border bg-muted/30 p-3', Input.ClassName)}>{Input.children}</div>;
}
