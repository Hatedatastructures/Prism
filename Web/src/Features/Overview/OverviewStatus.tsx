import type { ReactNode } from 'react';
import { NavLink } from 'react-router';
import { Badge, FormatBytes, FormatCount, FormatTime } from '../../Components/Ui';
import type { CursorPage, EventPage, IngressRecord, OverviewSnapshot } from '../../Services/AdminDataSource';
import { WithTime } from '../TimeRange';
import { DecideOverview } from './OverviewDecision';
import type { OverviewQueryState } from './OverviewDecision';

/** @brief 显示后端现有健康、采样质量和识别准入指标，保留来源范围与缺测。 */
export function OverviewStatus(Input: Readonly<{
    Snapshot: OverviewSnapshot; Ingresses: CursorPage<IngressRecord> | null; Events: EventPage | null;
    OverviewState: OverviewQueryState; IngressState: OverviewQueryState; EventState: OverviewQueryState; Params: URLSearchParams;
}>): ReactNode {
    const Decision = DecideOverview({ NowMs: Date.now(), Snapshot: Input.Snapshot, Ingresses: Input.Ingresses, Events: Input.Events,
        Queries: { Overview: Input.OverviewState, Ingresses: Input.IngressState, Events: Input.EventState } });
    const Latency = Input.Snapshot.Latency.RecognitionAdmission;
    const Tone = Decision.Availability.State === 'normal' ? 'good' : Decision.Availability.State === 'affected' ? 'danger' : 'warning';
    return <section className="rounded-xl border bg-card text-card-foreground shadow-sm" aria-label="运行状态与数据质量">
        <div className="grid grid-cols-2 lg:grid-cols-4">
            <div className="col-span-2 min-w-0 border-b px-4 py-3 lg:border-r lg:border-b-0">
                <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold">接入状态</span><Badge Tone={Tone}>{Decision.Availability.Title}</Badge></div>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{Decision.Availability.Detail}</p>
                <NavLink className="mt-1 inline-block text-xs font-medium underline underline-offset-4" to={WithTime(Decision.Availability.NextPath, Input.Params)}>{Decision.Availability.NextLabel}</NavLink>
            </div>
            <div className="min-w-0 border-r px-4 py-3"><p className="text-sm font-semibold">实例身份</p>
                <p className="mt-1 break-all font-mono text-xs">Process {Input.Snapshot.Process.Id} · G{Input.Snapshot.Process.GenerationId}</p>
                <p className="mt-1 text-xs text-muted-foreground">阶段 {Input.Snapshot.Process.Phase} · 采样 <time dateTime={Input.Snapshot.SampledAt}>{FormatTime(Input.Snapshot.SampledAt)}</time></p>
            </div>
            <div className="min-w-0 px-4 py-3"><p className="text-sm font-semibold">观测质量</p>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">{Decision.Observation.Detail}</p>
                <p className="mt-1 text-xs">丢弃 {FormatCount(Input.Snapshot.Observations.Dropped)} · 聚合失败 {FormatCount(Input.Snapshot.Observations.AggregationFailures)}</p>
            </div>
        </div>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-1 border-t px-4 py-2 text-xs text-muted-foreground">
            <span title="后端将微秒桶下界向下取整为毫秒">识别准入 P95 桶下界（整数 ms） <strong className="font-medium text-foreground">{Latency.Available && Latency.P95Ms !== null ? `${Latency.P95Ms} ms` : '未提供'}</strong></span>
            <span>识别样本 <strong className="font-medium text-foreground">{Latency.Available ? FormatCount(Latency.SampleCount) : '未提供'}</strong></span>
            <span>进程 RSS <strong className="font-medium text-foreground">{Input.Snapshot.Memory.ProcessAvailable ? FormatMemory(Input.Snapshot.Memory.ProcessRssBytes) : '未提供'}</strong></span>
            <NavLink className="font-medium text-foreground underline underline-offset-4" to={WithTime('/resources', Input.Params)}>资源详情</NavLink>
        </div>
    </section>;
}

function FormatMemory(Value: OverviewSnapshot['Memory']['ProcessRssBytes']): string {
    return Value === null ? '未提供' : FormatBytes(Value);
}
