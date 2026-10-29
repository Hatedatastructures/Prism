import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { CalendarRange } from 'lucide-react';
import { Input } from '@/Components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/Components/ui/select';
import { useAdminServices, useBootstrapIdentity } from './UseOperations';
import type { HistoryMetric, HistoryScope } from '../Services/AdminDataSource';
import { ResourceDestination } from '../Api/ResourceNavigation';
import { ResolveTimeRange, TimeRanges as Ranges } from '../Api/TimeRange';

export function useTimeRange() {
    const [Params] = useSearchParams();
    const Range = Params.get('range') ?? '15m';
    const From = Params.get('from') ?? '', To = Params.get('to') ?? '';
    return useMemo(() => ResolveTimeRange({ Range, From, To, Now: Date.now() }), [Range, From, To]);
}
export function TimeRangeControl(): ReactNode {
    const [Params, SetParams] = useSearchParams();
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const Range = Params.get('range') ?? '15m';
    const Resolved = useTimeRange();
    const HistoryAvailable = Services.Mode === 'demo' || Bootstrap.data?.Capabilities.includes('history.read') === true;
    function Update(Key: string, Value: string): void {
        const Next = new URLSearchParams(Params);
        if (Value) Next.set(Key, Value); else Next.delete(Key);
        if (Key === 'range' && Value === 'custom' && !Next.has('from')) {
            Next.set('from', new Date(Date.now() - 3_600_000).toISOString()); Next.set('to', new Date().toISOString());
        }
        SetParams(Next, { replace: true });
    }
    if (Services.Mode === 'live' && (!HistoryAvailable || Bootstrap.error || Bootstrap.isPending && !Bootstrap.data)) {
        const Label = Bootstrap.error ? '无法确认历史范围' : Bootstrap.isPending && !Bootstrap.data ? '正在确认历史范围' : '窗口历史未开放';
        return <span className="inline-flex h-8 items-center gap-2 rounded-md border px-2.5 text-xs text-muted-foreground" role="status" title="当前时间范围只影响历史曲线，不会筛选清单。">
            <CalendarRange size={15} aria-hidden="true" /><span>{Label}</span></span>;
    }
    return <div className="flex flex-wrap items-center gap-2"><CalendarRange className="size-4 text-muted-foreground" aria-hidden="true" />
        <Select value={Range} onValueChange={Value => Update('range', Value)}><SelectTrigger aria-label="分析时间范围" className="w-32"><SelectValue /></SelectTrigger><SelectContent>{Ranges.map(Value => <SelectItem key={Value.Id} value={Value.Id}>{Value.Label}</SelectItem>)}<SelectItem value="custom">自定义区间</SelectItem></SelectContent></Select>
        {Range === 'custom' && <><Input className="w-auto" type="datetime-local" aria-label="开始时间"
            aria-invalid={Resolved.InvalidReason ? true : undefined} aria-describedby={Resolved.InvalidReason ? 'time-range-error' : undefined}
            value={LocalValue(Params.get('from'))}
            onChange={Event => Update('from', Event.target.value ? new Date(Event.target.value).toISOString() : '')} />
            <span className="text-xs text-muted-foreground">至</span><Input className="w-auto" type="datetime-local" aria-label="结束时间"
                aria-invalid={Resolved.InvalidReason ? true : undefined} aria-describedby={Resolved.InvalidReason ? 'time-range-error' : undefined}
                value={LocalValue(Params.get('to'))}
                onChange={Event => Update('to', Event.target.value ? new Date(Event.target.value).toISOString() : '')} /></>}
        {Resolved.InvalidReason && <span id="time-range-error" className="text-xs text-destructive" role="alert">{Resolved.InvalidReason}</span>}
    </div>;
}
function LocalValue(Value: string | null): string {
    if (!Value) return '';
    const DateValue = new Date(Value);
    if (!Number.isFinite(DateValue.getTime())) return '';
    return new Date(DateValue.getTime() - DateValue.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
export function useHistory(Scope: HistoryScope, Key = '', Metric: HistoryMetric = 'traffic', Enabled = true) {
    const Services = useAdminServices(), Range = useTimeRange();
    return useQuery({ queryKey: ['operations', 'history', Scope, Key, Metric, Range.Key], enabled: Range.Valid && Enabled,
        queryFn: () => {
            if (!Services.Data.GetHistory) throw new Error('当前数据源尚未提供窗口历史；不会用累计 P95 或演示样本代替');
            const To = Range.Fixed ? Range.To : new Date().toISOString();
            const WindowMs = Date.parse(Range.To) - Date.parse(Range.From);
            return Services.Data.GetHistory({ Scope, Key, Metric, From: Range.Fixed ? Range.From : new Date(Date.parse(To) - WindowMs).toISOString(), To, MaxPoints: 1200 });
        }, refetchInterval: !Range.Fixed && Services.Mode === 'live' ? 5000 : false,
        refetchIntervalInBackground: false, refetchOnWindowFocus: !Range.Fixed, retry: false });
}
export function WithTime(Path: string, Params: URLSearchParams): string {
    const Target = ResourceDestination(Path, Params);
    return typeof Target === 'string' ? Target : Path;
}
