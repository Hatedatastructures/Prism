import { useState } from 'react';
import type { FormEvent, ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { DecodeDecimal } from '../../Api/Decimal';
import { DecodeWorkersQuery, VerifyProcessScope } from '../../Api/OperationsApi';
import type { Page, Worker } from '../../Api/OperationsApi';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { EmptyState, InlineCommandResult, QueryView, SectionHeading, StatusBadge, TrafficSummary } from '../../Components/ResultView';
import { HasCapability, useAdminServices, useCommandRunner } from '../UseOperations';

const PageSize = 100;

export default function WorkersPage(): ReactNode {
    const Services = useAdminServices();
    const Runner = useCommandRunner();
    const [Cursor, SetCursor] = useState('0');
    const [History, SetHistory] = useState<readonly string[]>([]);
    const [FilterInput, SetFilterInput] = useState('');
    const [Filter, SetFilter] = useState('');
    const FilterValid = IsValidId(Filter);
    const FilterInputValid = IsValidId(FilterInput.trim());
    const Path = MakePath(Cursor, Filter);
    const Query = useQuery({
        queryKey: ['workers', Services.Bootstrap.Process, Services.Bootstrap.Incarnation, Cursor, Filter],
        queryFn: ({ signal }) => Services.Client.Query({ Path, Signal: signal,
            Decode: Response => VerifyProcessScope(DecodeWorkersQuery(Response), Services.Bootstrap.Process) }),
        refetchInterval: 5000,
        refetchIntervalInBackground: false,
        retry: false,
        enabled: FilterValid,
    });
    function ApplyFilter(Event: FormEvent<HTMLFormElement>): void {
        Event.preventDefault();
        if (!FilterInputValid) return;
        SetHistory([]);
        SetCursor('0');
        SetFilter(FilterInput.trim());
    }
    function Next(NextCursor: string): void {
        SetHistory([...History, Cursor]);
        SetCursor(NextCursor);
    }
    function Previous(): void {
        const PreviousCursor = History[History.length - 1];
        if (PreviousCursor === undefined) return;
        SetHistory(History.slice(0, -1));
        SetCursor(PreviousCursor);
    }
    const CanDrain = HasCapability(Services, 'workers.drain');
    return <>
        <SectionHeading Eyebrow="WORKERS" Title="Worker"
            Description="按当前 Worker 快照查看运行、接收、排空、任务、流量与丢弃计数。Drain 命令只作用于确认的 Worker ID。" />
        <form className="toolbar" onSubmit={ApplyFilter} aria-label="Worker 查询条件">
            <label className="field">Worker ID
                <input inputMode="numeric" value={FilterInput} onChange={Event => SetFilterInput(Event.target.value)}
                    placeholder="留空显示分页列表" aria-describedby="worker-filter-help"
                    aria-invalid={FilterInput.trim().length > 0 && !FilterInputValid} />
            </label>
            <button className="button button-secondary" type="submit">应用筛选</button>
            <span id="worker-filter-help" className="muted">ID 以十进制字符串传递，不转为浮点数。</span>
        </form>
        {!FilterInputValid && <div className="notice notice-error" role="alert">Worker ID 必须为大于 0 的 uint64 十进制字符串。</div>}
        {FilterValid && <section className="panel">
            <div className="panel-heading"><div><h2>Worker 快照</h2>
                <p>每 5 秒刷新；页面不可见时暂停自动轮询。</p></div></div>
            <div className="panel-body">
                <QueryView Query={Query} Label="Worker 列表" Children={Value => <WorkerTable
                    Value={Value} CanDrain={CanDrain} Runner={Runner} OnNext={Next} /> } />
                <InlineCommandResult Result={Runner.Result} Process={Services.Bootstrap.Process} />
                {History.length > 0 && <button className="button button-secondary" onClick={Previous}>
                    上一页
                </button>}
            </div>
        </section>}
        {!FilterValid && <div className="notice notice-error" role="alert">Worker ID 无效。</div>}
    </>;
}

function MakePath(Cursor: string, Filter: string): string {
    const Params = new URLSearchParams({ cursor: Cursor, limit: String(PageSize) });
    if (Filter.length > 0) Params.set('id', Filter);
    return `/Operations/Workers?${Params.toString()}`;
}

function IsValidId(Value: string): boolean {
    if (Value.length === 0) return true;
    const Decoded = DecodeDecimal(Value);
    if (!Decoded.Ok) return false;
    return Decoded.Value !== '0';
}

function WorkerTable(Input: Readonly<{
    Value: Page<Worker>; CanDrain: boolean; Runner: ReturnType<typeof useCommandRunner>;
    OnNext: (Cursor: string) => void;
}>): ReactNode {
    if (Input.Value.Items.length === 0) return <EmptyState Title="没有匹配的 Worker"
        Detail="当前筛选和分页范围内没有返回 Worker。" />;
    return <>
        <div className="data-table-wrap" role="region" tabIndex={0} aria-label="Worker 表格，可横向滚动">
            <table className="data-table">
            <thead><tr><th scope="col">Worker</th><th scope="col">配置版本</th>
                <th scope="col">状态</th><th scope="col">活动任务</th><th scope="col">流量</th>
                <th scope="col">丢弃事件</th><th scope="col">操作</th></tr></thead>
            <tbody>{Input.Value.Items.map(Worker => <WorkerRow key={Worker.Id} Worker={Worker}
                CanDrain={Input.CanDrain} Runner={Input.Runner} />)}</tbody>
        </table></div>
        <div className="pagination"><span>本页 {Input.Value.Items.length} 项
            {Input.Value.HasMore && ' · 存在后续页面'}</span>
            <button className="button button-secondary" disabled={!Input.Value.HasMore}
                onClick={() => Input.OnNext(Input.Value.NextCursor)}>下一页</button></div>
    </>;
}

function WorkerRow(Input: Readonly<{
    Worker: Worker; CanDrain: boolean; Runner: ReturnType<typeof useCommandRunner>;
}>): ReactNode {
    const WorkerValue = Input.Worker;
    const DrainAvailable = Input.CanDrain && WorkerValue.Running &&
        WorkerValue.Health.Status !== 'draining';
    let State = '已停止';
    let Tone: 'good' | 'warn' | 'bad' | 'neutral' = 'neutral';
    if (WorkerValue.Health.Status === 'draining') { State = '排空中'; Tone = 'warn'; }
    else if (WorkerValue.Running && WorkerValue.Accepting) { State = '运行中 · 接收'; Tone = 'good'; }
    else if (WorkerValue.Running) { State = '运行中 · 停止接收'; Tone = 'warn'; }
    const Description = `只排空 Worker ${WorkerValue.Id}；请求优雅排空，不会关闭其他 Worker。`;
    async function Drain(): Promise<unknown> {
        return Input.Runner.Submit({ Path: `/Operations/Drain?worker=${WorkerValue.Id}&force=false`,
            Body: null, Label: 'Worker 排空', Target: `Worker ${WorkerValue.Id}` });
    }
    return <tr>
            <td className="mono">{WorkerValue.Id}</td><td className="mono">{WorkerValue.Generation}</td>
        <td><StatusBadge Label={State} Tone={Tone} /></td>
        <td className="mono">{WorkerValue.ActiveTasks}</td>
        <td><TrafficSummary Value={WorkerValue.Traffic} /></td>
        <td className="mono">{WorkerValue.DroppedEvents}</td>
        <td>
            {DrainAvailable && <ConfirmAction Label="优雅排空"
                Title="排空此 Worker？" Description={Description} ConfirmLabel="提交 Drain"
                Tone="danger" Busy={Input.Runner.IsPending} OnConfirm={Drain} />}
            {!Input.CanDrain && <small className="muted">当前服务不允许排空 Worker</small>}
            {Input.CanDrain && !WorkerValue.Running && <small className="muted">Worker 未运行</small>}
            {Input.CanDrain && WorkerValue.Running && WorkerValue.Health.Status === 'draining' &&
                <small className="muted">Worker 已在排空</small>}
        </td>
    </tr>;
}
