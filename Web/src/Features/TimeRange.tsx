import { useMemo } from 'react';
import type { ReactNode } from 'react';
import { useSearchParams } from 'react-router';
import { useQuery } from '@tanstack/react-query';
import { CalendarRange, ChevronDown } from 'lucide-react';
import { useAdminServices } from './UseOperations';
import type { HistoryScope } from '../Services/AdminDataSource';
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
    const Range = Params.get('range') ?? '15m';
    const Resolved = useTimeRange();
    function Update(Key: string, Value: string): void {
        const Next = new URLSearchParams(Params); Next.set(Key, Value);
        if (Key === 'range' && Value === 'custom' && !Next.has('from')) {
            Next.set('from', new Date(Date.now() - 3_600_000).toISOString()); Next.set('to', new Date().toISOString());
        }
        SetParams(Next, { replace: true });
    }
    return <div className="time-range-control"><CalendarRange size={15} aria-hidden="true" />
        <span className="time-range-select"><select aria-label="分析时间范围" value={Range} onChange={Event => Update('range', Event.target.value)}>
            {Ranges.map(Value => <option key={Value.Id} value={Value.Id}>{Value.Label}</option>)}<option value="custom">自定义区间</option>
        </select><ChevronDown size={14} aria-hidden="true" /></span>
        {Range === 'custom' && <><input type="datetime-local" aria-label="开始时间" value={LocalValue(Params.get('from'))}
            onChange={Event => { if (Event.target.value) Update('from', new Date(Event.target.value).toISOString()); }} />
            <span>至</span><input type="datetime-local" aria-label="结束时间" value={LocalValue(Params.get('to'))}
                onChange={Event => { if (Event.target.value) Update('to', new Date(Event.target.value).toISOString()); }} /></>}
        {Resolved.InvalidReason && <span className="time-range-error" role="alert">{Resolved.InvalidReason}</span>}
    </div>;
}
function LocalValue(Value: string | null): string {
    if (!Value) return '';
    const DateValue = new Date(Value);
    if (!Number.isFinite(DateValue.getTime())) return '';
    return new Date(DateValue.getTime() - DateValue.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
export function useHistory(Scope: HistoryScope, Key = '', Metric: 'traffic' | 'recognition_admission' | 'active' = 'traffic') {
    const Services = useAdminServices(), Range = useTimeRange();
    return useQuery({ queryKey: ['operations', 'history', Scope, Key, Metric, Range.Key], enabled: Range.Valid,
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
