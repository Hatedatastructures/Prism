import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { Check, FileSliders, RotateCcw, ShieldCheck } from 'lucide-react';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { Badge, EmptyState, PageHeader, Panel, QueryState } from '../../Components/Ui';
import { ConfigurationChanges, ParsePublicConfiguration } from '../../Api/ConfigurationDocument';
import { FormatJsonDocument } from '../../Api/JsonDocument';
import type { JsonNode } from '../../Api/JsonDocument';
import type { ConfigurationChange } from '../../Api/ConfigurationDocument';
import { OperationScopeChangedError } from '../../Services/AdminDataSource';
import type { BootstrapSnapshot, ConfigurationSnapshot } from '../../Services/AdminDataSource';
import { ClearConfigurationDraft, IsConfigurationDraftFor, SetConfigurationDraft, useConfigurationDraft } from '../../App/ConfigurationDraft';
import type { ConfigurationDraftSource } from '../../App/ConfigurationDraft';
import { useAdminMutation, useAdminQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';
import { ActionFeedback } from '../ActionFeedback';
import { useQuery, useQueryClient } from '@tanstack/react-query';

type ConfigurationRebaseCandidate = Readonly<{
    Baseline: ConfigurationSnapshot; Source: ConfigurationDraftSource; SourceKey: string; DraftUpdatedAt: string;
}>;

export default function ConfigurationPage(): ReactNode {
    const Services = useAdminServices();
    const QueryClient = useQueryClient();
    const Bootstrap = useBootstrapIdentity();
    const CurrentSource = useMemo<ConfigurationDraftSource>(() => ({ Mode: Services.Mode,
        Identity: Bootstrap.isSuccess && Bootstrap.data ? { InstanceKey: Bootstrap.data.InstanceKey,
            ProcessId: Bootstrap.data.ProcessId, Incarnation: Bootstrap.data.Incarnation } : null }),
    [Services.Mode, Bootstrap.data, Bootstrap.isSuccess]);
    const CurrentSourceKey = useMemo(() => ConfigurationSourceKey(CurrentSource), [CurrentSource]);
    const Draft = useConfigurationDraft();
    const DraftIsCurrent = Draft !== null && IsConfigurationDraftFor(Draft, CurrentSource);
    const DraftIsStale = Draft !== null && !DraftIsCurrent;
    const Query = useAdminQuery('configuration', Source => Source.GetConfiguration(),
        { Enabled: CurrentSourceKey !== null, Scope: CurrentSourceKey ? [CurrentSourceKey] : [] });
    const DraftNeedsAttention = !!Draft && (DraftIsStale || CurrentSourceKey === null || Query.data === undefined);
    const Validate = useAdminMutation((Source, Input: Readonly<{ Text: string; Generation: string }>) => Source.ValidateConfiguration(Input.Text, Input.Generation));
    const Apply = useAdminMutation((Source, Input: Readonly<{ Text: string; Persist: boolean; Generation: string }>) =>
        Source.ApplyConfiguration(Input.Text, Input.Persist, Input.Generation));
    const [Baseline, SetBaseline] = useState<ConfigurationSnapshot | null>(null);
    const [BaselineSourceKey, SetBaselineSourceKey] = useState<string | null>(null);
    const [Text, SetText] = useState('');
    const [Validated, SetValidated] = useState<string | null>(null);
    const [Message, SetMessage] = useState('');
    const [DraftMessage, SetDraftMessage] = useState('');
    const [Persist, SetPersist] = useState(false);
    const [RebaseCandidate, SetRebaseCandidate] = useState<ConfigurationRebaseCandidate | null>(null);
    const [RebaseBusy, SetRebaseBusy] = useState(false);
    useEffect(() => {
        if (!Query.data || !CurrentSourceKey || BaselineSourceKey === CurrentSourceKey) return;
        if (Draft && DraftIsCurrent) { SetBaseline(Draft.Baseline); SetText(Draft.Text); }
        else { SetBaseline(Query.data); SetText(Query.data.Text); }
        SetBaselineSourceKey(CurrentSourceKey); SetValidated(null); SetMessage('');
    }, [Query.data, CurrentSourceKey, BaselineSourceKey, Draft, DraftIsCurrent]);
    const Parsed = useMemo(() => ParsePublicConfiguration(Text), [Text]);
    const Original = useMemo(() => Baseline ? ParsePublicConfiguration(Baseline.Text) : null, [Baseline]);
    const Changes = useMemo(() => Parsed.Ok && Original?.Ok ? PageConfigurationChanges(Original.Value, Parsed.Value) : [], [Parsed, Original]);
    const Dirty = Baseline !== null && Text !== Baseline.Text;
    const ValidatedCurrent = Parsed.Ok && Validated === Text;
    const BaselineIsCurrent = CurrentSourceKey !== null && BaselineSourceKey === CurrentSourceKey;
    const CurrentBaseline = BaselineIsCurrent ? Baseline : null;
    useEffect(() => { SetRebaseCandidate(null); }, [Draft?.UpdatedAt, CurrentSourceKey]);
    const ApplyScope = Apply.data?.OperationScope;
    const ApplyId = Apply.data?.OperationId ?? Apply.data?.Operation?.Id ?? '';
    const ApplyStatus = useQuery({ queryKey: ['operations', 'operation-status', ApplyScope?.ProcessId, ApplyScope?.Incarnation, ApplyId],
        enabled: !!ApplyId && !!ApplyScope && Apply.data?.Status === 'accepted', retry: false,
        queryFn: () => Services.Data.GetOperationStatus(ApplyId, ApplyScope!),
        refetchInterval: Value => Value.state.error instanceof OperationScopeChangedError ? false
            : Value.state.data && !['accepted', 'running'].includes(Value.state.data.State) ? false : 1000,
        refetchIntervalInBackground: false });
    const ApplyStatusMatches = ApplyStatus.data?.Id === ApplyId;
    const ApplyStillPending = Apply.data?.Status === 'unknown' || Apply.data?.Status === 'interrupted' ||
        Apply.data?.Status === 'accepted' && (!ApplyStatusMatches || ApplyStatus.data?.State === 'accepted' ||
            ApplyStatus.data?.State === 'running' || ApplyStatus.data?.State === 'unknown' ||
            ApplyStatus.data?.State === 'interrupted' || !!ApplyStatus.error);
    const CanEdit = Baseline !== null && BaselineIsCurrent && CurrentSourceKey !== null && !DraftIsStale && !ApplyStillPending;
    const CanApply = Dirty && ValidatedCurrent && CanEdit && !ApplyStillPending;
    const [HandledApplyId, SetHandledApplyId] = useState('');

    useEffect(() => {
        if (!ApplyId || !ApplyScope || HandledApplyId === ApplyId ||
            (Apply.data?.Status !== 'completed' && ApplyStatus.data?.State !== 'completed')) return;
        const DraftAtCompletion = Draft;
        if (!DraftAtCompletion || ApplyScope.ProcessId !== DraftAtCompletion.Source.Identity?.ProcessId ||
            ApplyScope.Incarnation !== DraftAtCompletion.Source.Identity?.Incarnation) return;
        SetHandledApplyId(ApplyId);
        void (async () => {
            try {
                const BeforeRead = await Services.Data.GetBootstrap({ Fresh: true });
                const BeforeSource = ConfigurationSource(Services.Mode, BeforeRead);
                if (!IsConfigurationDraftFor(DraftAtCompletion, BeforeSource)) { SetMessage('操作已完成，但来源实例已变；旧来源草稿保留为可复制内容。'); void Bootstrap.refetch(); return; }
                const Snapshot = await Services.Data.GetConfiguration();
                const AfterRead = await Services.Data.GetBootstrap({ Fresh: true });
                const AfterSource = ConfigurationSource(Services.Mode, AfterRead);
                if (!IsConfigurationDraftFor(DraftAtCompletion, AfterSource)) { SetMessage('操作已完成，但读回期间来源实例变化；草稿保留，请核对当前实例。'); void Bootstrap.refetch(); return; }
                const SnapshotScope = ConfigurationSourceKey(AfterSource);
                if (SnapshotScope) QueryClient.setQueryData(['operations', 'configuration', SnapshotScope], Snapshot);
                SetBaseline(Snapshot); SetText(Snapshot.Text); SetBaselineSourceKey(SnapshotScope);
                SetValidated(null); ClearConfigurationDraft(); SetMessage('操作已完成并读回当前配置快照。');
            } catch (Failure: unknown) { SetMessage(Failure instanceof Error ? `操作已完成，但配置读回失败：${Failure.message}；草稿已保留。` : '操作已完成，但配置读回失败；草稿已保留。'); }
        })();
    }, [ApplyId, ApplyScope?.ProcessId, ApplyScope?.Incarnation, Apply.data?.Status, ApplyStatus.data?.State,
        HandledApplyId, Draft, Services, Bootstrap.refetch, QueryClient]);

    const UpdateDraftText = (Value: string): void => {
        if (!CanEdit || !Baseline) return;
        if (Value !== Baseline.Text && !SetConfigurationDraft({ Text: Value, Baseline, Source: CurrentSource })) {
            SetMessage('草稿来源已变化，已停止保存编辑；请重新核对当前实例。'); void Bootstrap.refetch(); return;
        }
        if (Value === Baseline.Text) ClearConfigurationDraft();
        SetText(Value); SetValidated(null); SetMessage(''); SetDraftMessage('');
    };

    const ValidateDraft = async (): Promise<void> => {
        if (!Parsed.Ok) { SetValidated(null); SetMessage(Parsed.Message); return; }
        if (!Baseline || !CanEdit) return;
        try {
            const Fresh = await Services.Data.GetBootstrap({ Fresh: true });
            if (ConfigurationSourceKey(ConfigurationSource(Services.Mode, Fresh)) !== CurrentSourceKey) {
                SetMessage('Validate Only 前检测到来源实例变化；草稿保留，没有发送校验。'); void Bootstrap.refetch(); return;
            }
            const Result = await Validate.mutateAsync({ Text, Generation: Baseline.Generation });
            SetValidated(Result.Valid ? Text : null);
            SetMessage(Result.Valid ? 'Validate Only 通过；未修改运行配置或配置文件。发布前仍会核对基线 Generation。'
                : Result.Issues.join('；') || 'Validate Only 未通过。');
        } catch (Failure: unknown) { SetValidated(null); SetMessage(Failure instanceof Error ? Failure.message : '校验请求失败'); }
    };

    const ApplyDraft = async (): Promise<void> => {
        if (!Baseline || !CanApply || !Draft || !DraftIsCurrent) return;
        try {
            const Fresh = await Services.Data.GetBootstrap({ Fresh: true });
            if (!IsConfigurationDraftFor(Draft, ConfigurationSource(Services.Mode, Fresh))) {
                SetMessage('应用前检测到来源实例变化；旧来源草稿保留，没有发送 Apply。'); void Bootstrap.refetch(); return;
            }
            Apply.reset(); SetHandledApplyId('');
            const Result = await Apply.mutateAsync({ Text, Persist, Generation: Baseline.Generation });
            SetMessage(Result.Status === 'accepted' ? 'Apply 已受理；等待真实终态。草稿在终态确认前保留。' : Result.Message);
            if (Result.Status !== 'completed' && Result.Status !== 'accepted') return;
        } catch (Failure: unknown) { SetMessage(Failure instanceof Error ? Failure.message : 'Apply 请求失败；草稿已保留。'); }
    };

    const Restore = (): void => {
        if (!Baseline || !CanEdit) return;
        ClearConfigurationDraft(); SetText(Baseline.Text); SetValidated(null); SetMessage('已还原为编辑基线。'); SetDraftMessage('');
    };

    const CopyStaleDraft = async (): Promise<void> => {
        if (!DraftNeedsAttention || !Draft) return;
        try { await navigator.clipboard.writeText(Draft.Text); SetDraftMessage('保留的草稿已复制。'); }
        catch { SetDraftMessage('复制不可用；请在只读文本框中手动选择内容。'); }
    };

    const PrepareStaleDraftAdoption = async (): Promise<void> => {
        if (!DraftIsStale || !Draft || !CurrentSourceKey || ApplyStillPending) return;
        const SourceKeyAtStart = CurrentSourceKey;
        SetRebaseBusy(true); SetDraftMessage('正在核实目标来源并读取当前配置基线…');
        try {
            const BeforeRead = await Services.Data.GetBootstrap({ Fresh: true });
            const BeforeSource = ConfigurationSource(Services.Mode, BeforeRead);
            if (ConfigurationSourceKey(BeforeSource) !== SourceKeyAtStart) {
                SetRebaseCandidate(null); SetDraftMessage('目标实例来源已变化；旧稿保留，没有准备重基线。'); void Bootstrap.refetch(); return;
            }
            const FreshBaseline = await Services.Data.GetConfiguration();
            const AfterRead = await Services.Data.GetBootstrap({ Fresh: true });
            const AfterSource = ConfigurationSource(Services.Mode, AfterRead);
            if (ConfigurationSourceKey(AfterSource) !== SourceKeyAtStart) {
                SetRebaseCandidate(null); SetDraftMessage('读取配置期间实例来源发生变化；旧稿保留，没有准备重基线。'); void Bootstrap.refetch(); return;
            }
            SetRebaseCandidate({ Baseline: FreshBaseline, Source: AfterSource, SourceKey: SourceKeyAtStart,
                DraftUpdatedAt: Draft.UpdatedAt });
            SetDraftMessage('已读取目标实例配置；请核对下方来源与 Generation 后确认重基线。');
        } catch (Failure: unknown) {
            SetRebaseCandidate(null);
            SetDraftMessage(Failure instanceof Error ? `无法读取目标实例配置：${Failure.message}；旧稿保留。` : '无法读取目标实例配置；旧稿保留。');
        } finally { SetRebaseBusy(false); }
    };

    const AdoptStaleDraft = async (): Promise<void> => {
        if (!DraftIsStale || !Draft || !RebaseCandidate || !CurrentSourceKey || ApplyStillPending) return;
        if (Draft.UpdatedAt !== RebaseCandidate.DraftUpdatedAt || RebaseCandidate.SourceKey !== CurrentSourceKey) {
            SetRebaseCandidate(null); SetDraftMessage('草稿或目标来源已改变；旧稿保留，请重新读取并确认。'); return;
        }
        try {
            SetRebaseBusy(true);
            const BeforeRead = await Services.Data.GetBootstrap({ Fresh: true });
            const BeforeSource = ConfigurationSource(Services.Mode, BeforeRead);
            if (ConfigurationSourceKey(BeforeSource) !== RebaseCandidate.SourceKey) {
                SetRebaseCandidate(null); SetDraftMessage('目标实例来源已变化；旧稿保留，没有将它复制为当前草稿。'); void Bootstrap.refetch(); return;
            }
            const FreshBaseline = await Services.Data.GetConfiguration();
            const AfterRead = await Services.Data.GetBootstrap({ Fresh: true });
            const AfterSource = ConfigurationSource(Services.Mode, AfterRead);
            if (ConfigurationSourceKey(AfterSource) !== RebaseCandidate.SourceKey) {
                SetRebaseCandidate(null); SetDraftMessage('读取配置期间实例来源发生变化；旧稿保留，没有重基线。'); void Bootstrap.refetch(); return;
            }
            if (FreshBaseline.Generation !== RebaseCandidate.Baseline.Generation || FreshBaseline.Text !== RebaseCandidate.Baseline.Text ||
                FreshBaseline.Reloadable !== RebaseCandidate.Baseline.Reloadable) {
                SetRebaseCandidate({ ...RebaseCandidate, Baseline: FreshBaseline, Source: AfterSource });
                SetDraftMessage('目标配置在确认期间已变化；已刷新候选基线，请再次核对新 Generation 并确认。'); return;
            }
            const OldText = Draft.Text;
            QueryClient.setQueryData(['operations', 'configuration', RebaseCandidate.SourceKey], FreshBaseline);
            ClearConfigurationDraft(); SetBaseline(FreshBaseline); SetBaselineSourceKey(RebaseCandidate.SourceKey);
            SetText(OldText); SetValidated(null); SetMessage(''); SetRebaseCandidate(null);
            if (OldText !== FreshBaseline.Text && !SetConfigurationDraft({ Text: OldText, Baseline: FreshBaseline, Source: AfterSource })) {
                SetDraftMessage('无法绑定到当前实例；请复制保留的旧文本，草稿未应用。'); return;
            }
            SetDraftMessage('旧来源文本已基于刚读取的当前配置重新建立草稿；差异已更新，必须重新 Validate Only。');
        } catch (Failure: unknown) {
            SetDraftMessage(Failure instanceof Error ? `无法核实目标来源或读取配置：${Failure.message}；旧稿保留。` : '无法核实目标来源或读取配置；旧稿保留。');
        } finally { SetRebaseBusy(false); }
    };

    const DiscardStaleDraft = async (): Promise<void> => { ClearConfigurationDraft(); SetDraftMessage('已放弃旧来源草稿。'); };

    return <>
        <PageHeader Title="配置"
            Description="固定编辑基线；先 Validate Only，再按基线 Generation 应用运行配置或同时保存。"
            Actions={<Badge Tone="accent" Dot>{Services.Mode === 'demo' ? '演示配置' : '生效配置'} · Generation {CurrentBaseline?.Generation ?? '—'}</Badge>} />
        {DraftNeedsAttention && Draft && <section className="notice notice-warning configuration-stale-draft" aria-labelledby="stale-draft-title">
            <strong id="stale-draft-title">{DraftIsStale ? '存在来自其他来源的未保存草稿' : '未保存草稿暂不可编辑'}</strong>
            <p>来源：{Draft.Source.Mode} · Instance {Draft.Source.Identity?.InstanceKey ?? '未核实'} · Process {Draft.Source.Identity?.ProcessId ?? '未核实'} · Incarnation {Draft.Source.Identity?.Incarnation ?? '未核实'} · Generation {Draft.Baseline.Generation} · 更新于 {Draft.UpdatedAt}。{DraftIsStale
                ? '当前来源未匹配；此文本不会作为当前基线，也不能直接校验或应用。确认当前配置与来源后，可将文本复制成当前草稿并重新校验。'
                : '当前配置基线尚未载入；草稿仍保留在内存中，暂不能校验或应用。'}</p>
            <label className="field-label" htmlFor="stale-configuration-draft">旧来源草稿（只读，可手动复制）</label>
            <textarea id="stale-configuration-draft" className="configuration-editor" value={Draft.Text} readOnly spellCheck={false} />
            <div className="button-row">
                <button className="button button-secondary" type="button" onClick={() => void CopyStaleDraft()}>复制保留的草稿</button>
                {DraftIsStale && !RebaseCandidate && <button className="button button-secondary" type="button"
                    disabled={!CurrentSourceKey || ApplyStillPending || RebaseBusy} onClick={() => void PrepareStaleDraftAdoption()}>
                    {RebaseBusy ? '读取当前基线…' : '读取当前基线并准备重基线'}</button>}
                {DraftIsStale && RebaseCandidate && <>
                    <p>原稿来源：{DescribeConfigurationSource(Draft.Source, Draft.Baseline.Generation)}</p>
                    <p>目标来源与新基线：{DescribeConfigurationSource(RebaseCandidate.Source, RebaseCandidate.Baseline.Generation)}</p>
                    <button className="button button-secondary" type="button" disabled={RebaseBusy || ApplyStillPending}
                        onClick={() => void PrepareStaleDraftAdoption()}>重新读取当前基线</button>
                    <ConfirmAction Label="确认以该基线重建草稿" Title="按当前来源重建草稿？"
                        Description={`原稿：${DescribeConfigurationSource(Draft.Source, Draft.Baseline.Generation)} → 目标：${DescribeConfigurationSource(RebaseCandidate.Source, RebaseCandidate.Baseline.Generation)}。提交前会再次 Fresh 核验来源并读取配置；来源或 Generation 变化时保留旧稿并要求重新确认。`}
                        ConfirmLabel="确认重建并重新校验" Disabled={!CurrentSourceKey || RebaseBusy || ApplyStillPending} Busy={RebaseBusy}
                        OnConfirm={AdoptStaleDraft} />
                </>}
                <ConfirmAction Label="放弃旧草稿" Title="放弃旧来源草稿？" Description="这会从内存中删除该未保存文本，无法恢复。"
                    ConfirmLabel="确认放弃" Tone="danger" Disabled={RebaseBusy} OnConfirm={DiscardStaleDraft} />
            </div>
            {DraftMessage && <p role="status">{DraftMessage}</p>}
        </section>}
        {CurrentSourceKey === null && <div className="notice notice-warning" role="status">当前实例身份尚未核实，配置读取和编辑已暂停；请重试后再校验或应用。</div>}
        {CurrentBaseline && Query.data && CurrentBaseline.Generation !== Query.data.Generation && <div className="notice notice-warning">运行配置已变为 Generation {Query.data.Generation}。当前草稿仍基于 {CurrentBaseline.Generation}；提交会进行冲突检查。<button type="button" className="button button-secondary" onClick={() => { ClearConfigurationDraft(); SetBaseline(Query.data!); SetText(Query.data!.Text); SetBaselineSourceKey(CurrentSourceKey); SetValidated(null); SetMessage('已重新读取当前配置并放弃草稿。'); }}>重新读取并放弃草稿</button></div>}
        <QueryState Pending={CurrentSourceKey !== null && Query.isPending} Error={Query.error} Label="配置快照" HasData={CurrentBaseline !== null}
            Children={CurrentBaseline ? <>
                <div className="configuration-metrics" aria-label="配置状态">
                    <div><span>当前 Generation</span><strong>#{CurrentBaseline.Generation}</strong></div>
                    <div><span>热加载</span><strong>{CurrentBaseline.Reloadable ? '可重载' : '需重启'}</strong></div>
                    <div><span>当前草稿</span><strong>{Dirty ? `${Changes.length} 项差异` : '与快照一致'}</strong></div>
                </div>
                <section className="configuration-layout">
                    <Panel Title="配置草稿" Subtitle="公开字段校验 · 保留 JSON 数值原文 · Generation 冲突会阻止应用" ClassName="configuration-panel">
                        <label className="field-label" htmlFor="configuration-editor">配置 JSON</label>
                        <textarea id="configuration-editor" className="configuration-editor" spellCheck={false} readOnly={!CanEdit}
                            aria-invalid={!Parsed.Ok} value={Text} onChange={Event => UpdateDraftText(Event.target.value)} />
                        {!Parsed.Ok && <div className="notice notice-danger" role="alert">{Parsed.Message}</div>}
                        {Message && <div className={`notice ${ValidatedCurrent ? 'notice-info' : 'notice-warning'}`} role="status">
                            {ValidatedCurrent && <Check size={14} />}{Message}</div>}
                        <div className="button-row configuration-actions">
                            <button className="button button-secondary" type="button" disabled={!CanEdit || !Parsed.Ok} onClick={() => {
                                if (Parsed.Ok) UpdateDraftText(FormatJsonDocument(Parsed.Value));
                            }}>排版 JSON</button>
                            <button className="button button-secondary" type="button" disabled={!Dirty || !CanEdit} onClick={Restore}>
                                <RotateCcw size={14} />还原</button>
                            <button className="button button-secondary" type="button" disabled={!CanEdit || !Parsed.Ok || Validate.isPending}
                                onClick={() => void ValidateDraft()}>{Validate.isPending ? '校验中…' : '校验草稿'}</button>
                            <label className="check-row"><input type="checkbox" checked={Persist} disabled={!CanEdit} onChange={Event => SetPersist(Event.target.checked)} />同时保存到配置文件</label>
                            <ConfirmAction Label={Persist ? '应用并保存' : '应用配置'} Title="发布这份配置？"
                                Description={Persist ? '基线匹配后应用并保存配置文件；已有连接继续持有其所属 Generation。' : '仅发布运行配置，不替代磁盘配置；需要重启的字段会明确返回。'}
                                ConfirmLabel="确认发布" Disabled={!CanApply} Busy={Apply.isPending} OnConfirm={ApplyDraft} />
                        </div>
                        <ActionFeedback Result={Apply.data} />
                        <div className="configuration-notice"><ShieldCheck size={14} />敏感材料通过 SecretRef 引用；公开快照不包含保密正文。</div>
                    </Panel>
                    <Panel Title="字段差异" Subtitle={`${Changes.length} 个顶层配置字段变化`} ClassName="configuration-diff-panel">
                        {Changes.length === 0 ? <EmptyState Title="暂无字段差异" Detail="编辑公开 JSON 后，修改内容会出现在这里。" /> :
                            <div className="configuration-diff-list">{Changes.map(Change => <details className="configuration-change" key={Change.Path} open>
                                <summary>{Change.Path}</summary><div className="configuration-diff-values">
                                    <div><strong>之前</strong><pre>{Change.Before}</pre></div>
                                    <div><strong>之后</strong><pre>{Change.After}</pre></div>
                                </div>
                            </details>)}</div>}
                        <div className="configuration-diff-current"><FileSliders size={14} /><span>编辑基线 Generation {CurrentBaseline.Generation}{CurrentBaseline.UpdatedAt ? ` · ${CurrentBaseline.UpdatedAt}` : ' · 磁盘持久化状态以发布结果为准'}</span></div>
                    </Panel>
                </section>
            </> : <EmptyState Title={CurrentSourceKey ? '配置快照未载入' : '实例来源未核实'} Detail={CurrentSourceKey ? '检查本机 Operations 服务与配置读取能力。' : '无法核实当前 Process 与 Incarnation；不会把旧来源草稿作为当前配置。'} />} />
    </>;
}

function PageConfigurationChanges(Before: JsonNode, After: JsonNode): readonly ConfigurationChange[] {
    const Changes = [...ConfigurationChanges(Before, After)];
    if (Before.Kind !== 'object' || After.Kind !== 'object') return Changes;
    const OldStorage = Before.Members.get('Storage');
    const NewStorage = After.Members.get('Storage');
    const OldText = OldStorage ? FormatJsonDocument(OldStorage) : '未配置';
    const NewText = NewStorage ? FormatJsonDocument(NewStorage) : '未配置';
    if (OldText !== NewText && !Changes.some(Change => Change.Path === 'Storage')) {
        Changes.push({ Path: 'Storage', Before: OldText, After: NewText });
    }
    return Changes;
}

function ConfigurationSource(Mode: ConfigurationDraftSource['Mode'], Bootstrap: BootstrapSnapshot): ConfigurationDraftSource {
    return { Mode, Identity: { InstanceKey: Bootstrap.InstanceKey, ProcessId: Bootstrap.ProcessId, Incarnation: Bootstrap.Incarnation } };
}

function ConfigurationSourceKey(Source: ConfigurationDraftSource): string | null {
    const Identity = Source.Identity;
    if (!Identity || !Identity.InstanceKey || !Identity.ProcessId || !Identity.Incarnation) return null;
    return JSON.stringify([Source.Mode, Identity.InstanceKey, Identity.ProcessId, Identity.Incarnation]);
}

function DescribeConfigurationSource(Source: ConfigurationDraftSource, Generation: string): string {
    const Identity = Source.Identity;
    return `${Source.Mode} / Instance ${Identity?.InstanceKey ?? '未核实'} / Process ${Identity?.ProcessId ?? '未核实'} / Incarnation ${Identity?.Incarnation ?? '未核实'} / Generation ${Generation}`;
}
