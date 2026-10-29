import { useEffect, useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Check, FileCode2, FileSliders, RotateCcw, ShieldCheck } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Badge } from '@/Components/ui/badge';
import { Button } from '@/Components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/Components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/Components/ui/dialog';
import { Switch } from '@/Components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/Components/ui/table';
import { Textarea } from '@/Components/ui/textarea';
import { FormatTime } from '../../Components/Ui';
import { ConfigurationChanges, ParsePublicConfiguration } from '../../Api/ConfigurationDocument';
import { FormatJsonDocument } from '../../Api/JsonDocument';
import type { JsonNode } from '../../Api/JsonDocument';
import type { ConfigurationChange } from '../../Api/ConfigurationDocument';
import { OperationScopeChangedError } from '../../Services/AdminDataSource';
import type { AdminDataSource, BootstrapSnapshot, ConfigurationSnapshot } from '../../Services/AdminDataSource';
import { ClearConfigurationDraft, GetConfigurationDraft, IsConfigurationDraftFor, SetConfigurationDraft, useConfigurationDraft } from '../../App/ConfigurationDraft';
import type { ConfigurationDraftSource } from '../../App/ConfigurationDraft';
import { useAdminMutation, useAdminQuery, useAdminServices, useBootstrapIdentity } from '../UseOperations';
import { useQuery, useQueryClient } from '@tanstack/react-query';

type ConfigurationRebaseCandidate = Readonly<{
    Baseline: ConfigurationSnapshot; Source: ConfigurationDraftSource; SourceKey: string; DraftUpdatedAt: string;
}>;

type ConfigurationApplyAttempt = Readonly<{
    Token: number; Text: string; Generation: string; Source: ConfigurationDraftSource; SourceKey: string | null; Persist: boolean;
    OperationId: string | null; OperationGeneration: string | null;
    ReadbackState: 'not-started' | 'confirmed' | 'mismatch' | 'failed';
    ReadbackGeneration?: string; ReadbackText?: string;
}>;

let ApplyTokenSequence = 0;
let ActiveApplyToken = 0;

type ConfigurationApplyState = 'idle' | 'submitting' | 'pending' | 'reading' | 'completed' |
    'readback-mismatch' | 'readback-failed' | 'restart-required' | 'unavailable' | 'failed' | 'outdated';

type ConfigurationWorkflowStep = Readonly<{
    Number: number; Title: string; Detail: string;
    State: 'complete' | 'current' | 'waiting' | 'warning' | 'error'; Current: boolean;
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
    const [ApplyConfirmOpen, SetApplyConfirmOpen] = useState(false);
    const [RebaseConfirmOpen, SetRebaseConfirmOpen] = useState(false);
    const [DiscardConfirmOpen, SetDiscardConfirmOpen] = useState(false);
    const [RebaseCandidate, SetRebaseCandidate] = useState<ConfigurationRebaseCandidate | null>(null);
    const [RebaseBusy, SetRebaseBusy] = useState(false);
    const [ApplyAttempt, SetApplyAttempt] = useState<ConfigurationApplyAttempt | null>(null);
    const [ApplyRequestBusy, SetApplyRequestBusy] = useState(false);
    const [ApplyReadbackSettledId, SetApplyReadbackSettledId] = useState('');
    const ApplySubmissionLock = useRef(false);
    const ApplySubmissionPhase = useRef<'idle' | 'requesting' | 'awaiting-resolution'>('idle');
    const ApplyAttemptRef = useRef(ApplyAttempt);
    ApplyAttemptRef.current = ApplyAttempt;
    const CurrentSourceKeyRef = useRef(CurrentSourceKey);
    CurrentSourceKeyRef.current = CurrentSourceKey;
    const ApplyDataSourceRef = useRef<Readonly<{ Token: number; Data: AdminDataSource }> | null>(null);
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
    const ApplyDataSource = ApplyAttempt && ApplyDataSourceRef.current?.Token === ApplyAttempt.Token
        ? ApplyDataSourceRef.current.Data : null;
    const ApplyStatus = useQuery({ queryKey: ['operations', 'operation-status', ApplyAttempt?.Token, ApplyScope?.ProcessId, ApplyScope?.Incarnation, ApplyId],
        enabled: !!ApplyId && !!ApplyScope && !!ApplyDataSource && ApplyAttempt?.SourceKey === CurrentSourceKey &&
            Apply.data?.Status === 'accepted', retry: false,
        queryFn: () => ApplyDataSource!.GetOperationStatus(ApplyId, ApplyScope!),
        refetchInterval: Value => Value.state.error instanceof OperationScopeChangedError ? false
            : Value.state.data && !['accepted', 'running'].includes(Value.state.data.State) ? false : 1000,
        refetchIntervalInBackground: false });
    const ApplyReadbackContentMatches = useMemo(() => {
        if (ApplyAttempt?.ReadbackText === undefined) return false;
        return PublicConfigurationsEquivalent(ApplyAttempt.Text, ApplyAttempt.ReadbackText) &&
            CurrentBaseline !== null && Query.data !== undefined &&
            PublicConfigurationsEquivalent(CurrentBaseline.Text, ApplyAttempt.ReadbackText) &&
            PublicConfigurationsEquivalent(Query.data.Text, ApplyAttempt.ReadbackText) &&
            PublicConfigurationsEquivalent(Text, ApplyAttempt.ReadbackText);
    }, [ApplyAttempt?.Text, ApplyAttempt?.ReadbackText, CurrentBaseline?.Text, Query.data?.Text, Text]);
    const ApplyStatusProcessId = ApplyStatus.data && 'ProcessId' in ApplyStatus.data
        ? ApplyStatus.data.ProcessId : undefined;
    const ApplyAttemptOwnsOperation = !!ApplyAttempt && !!ApplyId && !!ApplyScope && ApplyAttempt.OperationId === ApplyId &&
        ApplyScope.ProcessId === ApplyAttempt.Source.Identity?.ProcessId &&
        ApplyScope.Incarnation === ApplyAttempt.Source.Identity?.Incarnation;
    const ApplyStatusMatches = ApplyAttemptOwnsOperation &&
        ApplyStatus.data?.Id === ApplyId &&
        !ApplyStatus.error && (ApplyStatusProcessId === undefined || ApplyStatusProcessId === null ||
            ApplyStatusProcessId === ApplyScope?.ProcessId);
    const ApplyScopeMatchesCurrent = !!ApplyScope && ApplyScope.ProcessId === CurrentSource.Identity?.ProcessId &&
        ApplyScope.Incarnation === CurrentSource.Identity?.Incarnation;
    const ApplyAttemptMatchesDraft = ApplyAttempt !== null && ApplyAttempt.SourceKey === CurrentSourceKey &&
        ApplyAttempt.Persist === Persist && (ApplyAttempt.Text === Text || ApplyAttempt.ReadbackText === Text);
    const ApplyAttemptMatchesOperation = ApplyAttemptMatchesDraft && ApplyAttemptOwnsOperation && ApplyScopeMatchesCurrent;
    const ApplyOutcomeStatus = ApplyAttemptMatchesOperation
        ? ApplyStatusMatches ? ApplyStatus.data?.State : Apply.data?.Status : undefined;
    const ApplyOwnsMutationResult = !!ApplyAttempt && (ApplyAttempt.OperationId ? ApplyAttempt.OperationId === ApplyId : !ApplyId);
    const ApplyStillPending = ApplyOwnsMutationResult && (Apply.data?.Status === 'unknown' || Apply.data?.Status === 'interrupted' ||
        Apply.data?.Status === 'accepted' && (!ApplyStatusMatches ||
            ['accepted', 'running', 'unknown', 'interrupted'].includes(ApplyStatus.data?.State ?? '') ||
            !ApplyStatus.data && !!ApplyStatus.error));
    const ApplyTerminalCompletedForAttempt = ApplyAttemptOwnsOperation && (Apply.data?.Status === 'completed' ||
        ApplyStatusMatches && ApplyStatus.data?.State === 'completed');
    const ApplyTerminalCompleted = ApplyAttemptMatchesOperation && ApplyTerminalCompletedForAttempt;
    const ApplyOperationGeneration = ApplyStatusMatches ? ApplyStatus.data?.GenerationId ?? ApplyAttempt?.OperationGeneration ?? null
        : ApplyAttempt?.OperationGeneration ?? null;
    const ApplyReadbackKey = ApplyAttempt && ApplyId ? `${ApplyAttempt.Token}:${ApplyId}` : '';
    const ApplyReadbackPendingForAttempt = ApplyTerminalCompletedForAttempt && ApplyReadbackSettledId !== ApplyReadbackKey;
    const ApplyReadbackPending = ApplyTerminalCompleted && ApplyReadbackPendingForAttempt;
    const ApplyReadbackConfirmed = ApplyAttemptMatchesOperation && ApplyAttempt?.ReadbackState === 'confirmed' &&
        ApplyOperationGeneration !== null && ApplyAttempt?.ReadbackGeneration === ApplyOperationGeneration &&
        ApplyReadbackContentMatches && CurrentBaseline?.Generation === ApplyAttempt?.ReadbackGeneration &&
        Query.data?.Generation === ApplyAttempt?.ReadbackGeneration;
    const ApplyReadbackMismatch = ApplyAttemptMatchesOperation && ApplyAttempt?.ReadbackState === 'mismatch';
    const ApplyReadbackFailed = ApplyTerminalCompleted && ApplyAttempt?.ReadbackState === 'failed';
    const ApplyRestartRequired = ApplyAttemptMatchesOperation && ApplyOutcomeStatus === 'restart_required' &&
        ApplyAttempt?.Generation === CurrentBaseline?.Generation;
    const ApplyUnavailable = ApplyAttemptMatchesOperation && ApplyOutcomeStatus === 'unavailable' &&
        ApplyAttempt?.Generation === CurrentBaseline?.Generation;
    const ApplyFailedForDraft = ApplyAttemptMatchesOperation && ApplyAttempt?.Generation === CurrentBaseline?.Generation &&
        (Apply.isError || !!ApplyOutcomeStatus &&
            !['accepted', 'running', 'completed', 'unknown', 'interrupted', 'restart_required', 'unavailable'].includes(ApplyOutcomeStatus));
    const ApplyResultOutdated = ApplyTerminalCompleted && !ApplyReadbackConfirmed && !ApplyReadbackMismatch && !ApplyReadbackFailed &&
        (ApplyAttempt?.Generation !== CurrentBaseline?.Generation || Query.data?.Generation !== CurrentBaseline?.Generation ||
            ApplyAttempt?.ReadbackGeneration !== undefined && ApplyAttempt.ReadbackGeneration !== CurrentBaseline?.Generation);
    const ApplyBusy = ApplyAttempt?.SourceKey === CurrentSourceKey &&
        (ApplyRequestBusy || ApplyStillPending || ApplyReadbackPendingForAttempt);
    const ApplyOutstanding = ApplyRequestBusy || ApplyStillPending || ApplyReadbackPendingForAttempt;
    const CanEdit = Baseline !== null && BaselineIsCurrent && CurrentSourceKey !== null && !DraftIsStale && !ApplyBusy;
    const CanApply = Dirty && ValidatedCurrent && CanEdit && !ApplyOutstanding;
    const DraftSourceReady = Baseline !== null && BaselineIsCurrent && CurrentSourceKey !== null && !DraftIsStale;
    const LineCount = useMemo(() => Text.split(/\r\n|\r|\n/).length, [Text]);
    const ApplyCompletedCurrent = ApplyReadbackConfirmed;
    const ApplyPendingForCurrentSource = ApplyAttempt?.SourceKey === CurrentSourceKey && ApplyStillPending;
    const ApplyRequestBusyForCurrentSource = ApplyAttempt?.SourceKey === CurrentSourceKey && ApplyRequestBusy;
    const ApplyWorkflowState: ConfigurationApplyState = ApplyReadbackPending ? 'reading' : ApplyPendingForCurrentSource ? 'pending' :
        ApplyRequestBusyForCurrentSource ? 'submitting' : ApplyReadbackConfirmed ? 'completed' : ApplyReadbackMismatch ? 'readback-mismatch' :
            ApplyReadbackFailed ? 'readback-failed' : ApplyRestartRequired ? 'restart-required' : ApplyUnavailable ? 'unavailable' :
                ApplyFailedForDraft ? 'failed' : ApplyResultOutdated ? 'outdated' : 'idle';
    const PublishCapability = Persist ? 'configuration.reload.persist' : 'configuration.reload.apply';
    const PublishCapabilitySupported = Bootstrap.data?.Capabilities.includes(PublishCapability) === true;
    const ApplyPendingForOtherSource = ApplyOutstanding && ApplyAttempt !== null && ApplyAttempt.SourceKey !== CurrentSourceKey;
    const ApplyDisabledReason = ApplyPendingForOtherSource
        ? `${DescribeConfigurationSource(ApplyAttempt.Source, ApplyAttempt.Generation)} 的配置操作仍在核实；当前草稿可以继续编辑，新 Apply 会在旧操作完成终态与读回核对后开放。` :
        !Parsed.Ok ? '修正 JSON 格式错误后才能应用。' :
        ApplyWorkflowState === 'reading' ? '应用操作已完成，正在读取当前配置并核对版本。' :
        ApplyStillPending ? 'Apply 已受理或结果未核实；确认真实终态前不能重复应用。' :
        ApplyRequestBusy || Apply.isPending ? '配置应用请求正在提交或核实来源，请等待结果。' :
        ApplyReadbackMismatch ? '操作已完成，但当前配置版本或内容与本次提交不一致；核对后重新校验。' :
        ApplyReadbackFailed ? 'Apply 已完成，但快照读回失败；核对当前实例后重新校验。' :
        !DraftSourceReady ? CurrentSourceKey === null ? '当前实例身份尚未核实，配置暂不可应用。' :
            DraftIsStale ? '草稿来自其他来源；先核对来源并重新建立当前草稿。' :
                '当前配置基线尚未载入或与实例来源不匹配。' :
        !Dirty ? '草稿与运行配置一致，没有需要应用的变更。' :
        !ValidatedCurrent ? '请先校验当前这份准确文本；任何编辑都会使校验失效。' : null;
    const ApplyCaution = ApplyReadbackMismatch ? '操作已完成，当前配置版本或内容与本次提交不一致，请核对。草稿已保留。' :
        ApplyReadbackFailed ? 'Apply 已完成，但快照读回未确认；草稿已保留。' :
        ApplyResultOutdated ? '上次 Apply 的完成结果不属于当前 Generation，请核对当前配置。' :
        ApplyRestartRequired ? `服务器要求重启后生效${Apply.data?.RestartRequiredFields?.length
        ? `：${Apply.data.RestartRequiredFields.join('、')}。` : '。'}` :
        ApplyUnavailable ? '服务端返回 unavailable；这次配置尚未应用。' :
        CurrentBaseline?.Reloadable === false ? '当前 Generation 已关闭热加载；在线应用会由服务端拒绝，请先启用热加载或重启服务。' :
        Dirty && !PublishCapabilitySupported ? `当前实例未声明 ${PublishCapability} 能力，应用请求可能被服务端拒绝。` : null;
    const ActiveStep = ApplyCompletedCurrent ? 0 : ApplyBusy || ApplyWorkflowState !== 'idle' ? 3 :
        !DraftSourceReady ? 1 : ValidatedCurrent ? 3 : Dirty && Parsed.Ok ? 2 : 1;
    const WorkflowSteps: readonly ConfigurationWorkflowStep[] = [
        { Number: 1, Title: '编辑草稿', State: ApplyCompletedCurrent || DraftSourceReady && Parsed.Ok && Dirty ? 'complete' :
            !Parsed.Ok ? 'error' : !DraftSourceReady ? 'warning' : 'current', Current: ActiveStep === 1,
            Detail: ApplyCompletedCurrent ? '提交文本与当前配置快照一致。' : !Parsed.Ok ? 'JSON 格式错误；修正后才能比较。' :
                !DraftSourceReady ? '当前来源或配置基线尚未核实，编辑已暂停。' :
                    Dirty ? `${Changes.length} 项差异已从当前基线计算。` : '草稿与运行配置一致；开始编辑以创建变更。' },
        { Number: 2, Title: '校验草稿', State: ApplyCompletedCurrent || ValidatedCurrent && DraftSourceReady ? 'complete' :
            !Parsed.Ok ? 'waiting' : Dirty && DraftSourceReady ? 'current' : 'waiting', Current: ActiveStep === 2,
            Detail: ApplyCompletedCurrent ? '本次准确文本已通过校验并应用。' : ValidatedCurrent ? '已校验当前准确文本。' :
                Validate.isPending ? '正在校验当前文本…' : !Parsed.Ok ? '先修正 JSON。' :
                    Dirty ? '校验将绑定到当前文本和 Generation。' : '有未保存变更后再校验。' },
        { Number: 3, Title: '应用配置', State: ApplyWorkflowState === 'completed' ? 'complete' :
            ['submitting', 'pending', 'reading'].includes(ApplyWorkflowState) ? 'current' :
                ['failed'].includes(ApplyWorkflowState) ? 'error' :
                    ['readback-mismatch', 'readback-failed', 'restart-required', 'unavailable', 'outdated'].includes(ApplyWorkflowState) ||
                        !DraftSourceReady || CurrentBaseline?.Reloadable === false || !PublishCapabilitySupported ? 'warning' :
                        !Parsed.Ok || !Dirty || !ValidatedCurrent ? 'waiting' : 'current', Current: ActiveStep === 3,
            Detail: ApplyWorkflowState === 'submitting' ? '正在核实来源并提交 Apply…' :
                ApplyWorkflowState === 'pending' ? '已受理或结果待核对；尚未完成。' :
                    ApplyWorkflowState === 'reading' ? 'Apply 已完成，正在核对操作 Generation 与配置快照。' :
                        ApplyWorkflowState === 'completed' ? '操作已完成，提交文本与目标 Generation 快照一致。' :
                            ApplyWorkflowState === 'readback-mismatch' ? '操作已完成，当前配置版本或内容与本次提交不一致，请核对。' :
                                ApplyWorkflowState === 'readback-failed' ? 'Apply 已完成，但配置快照读回失败。' :
                                    ApplyWorkflowState === 'restart-required' ? '服务器要求重启后生效。' :
                                        ApplyWorkflowState === 'unavailable' ? '服务端返回 unavailable；这次配置尚未应用。' :
                                            ApplyWorkflowState === 'failed' ? '应用未完成；请查看下方操作结果。' :
                                                ApplyWorkflowState === 'outdated' ? '上次结果不属于当前 Generation。' :
                                                    !DraftSourceReady ? '当前来源或配置基线尚未核实。' : !Parsed.Ok ? '修正 JSON 后继续。' :
                                                        !Dirty ? '无变更，无需应用。' : !ValidatedCurrent ? '先校验当前准确文本。' :
                                                            CurrentBaseline?.Reloadable === false ? '当前 Generation 未启用热加载。' :
                                                                !PublishCapabilitySupported ? `当前服务未声明 ${PublishCapability}。` :
                                                                    '校验通过，可按当前 Generation 应用。' },
    ];
    const [HandledApplyId, SetHandledApplyId] = useState('');
    const ClearCurrentApplyAttempt = (): void => {
        if (!ApplyAttempt || ApplyAttempt.SourceKey !== CurrentSourceKey) return;
        if (ActiveApplyToken === ApplyAttempt.Token) ActiveApplyToken = 0;
        if (ApplyDataSourceRef.current?.Token === ApplyAttempt.Token) ApplyDataSourceRef.current = null;
        Apply.reset(); SetApplyAttempt(null); SetApplyReadbackSettledId(''); SetHandledApplyId('');
    };

    useEffect(() => {
        if (!ApplyId || !ApplyScope || !ApplyTerminalCompletedForAttempt || !ApplyAttempt || !ApplyDataSource) return;
        const AttemptToken = ApplyAttempt.Token;
        const ReadbackKey = `${AttemptToken}:${ApplyId}`;
        if (HandledApplyId === ReadbackKey || ApplyReadbackSettledId === ReadbackKey) return;
        const DraftAtCompletion = Draft;
        const AttemptAtCompletion = ApplyAttempt;
        const ReadbackSource = ApplyDataSource;
        const StillOwnsAttempt = (): boolean => ActiveApplyToken === AttemptToken &&
            ApplyAttemptRef.current?.Token === AttemptToken;
        SetHandledApplyId(ReadbackKey);
        void (async () => {
            try {
                if (!AttemptAtCompletion || AttemptAtCompletion.OperationId !== ApplyId || !StillOwnsAttempt()) return;
                const BeforeRead = await ReadbackSource.GetBootstrap({ Fresh: true });
                if (!StillOwnsAttempt()) return;
                const BeforeSource = ConfigurationSource(AttemptAtCompletion.Source.Mode, BeforeRead);
                if (ConfigurationSourceKey(BeforeSource) !== AttemptAtCompletion.SourceKey) {
                    SetApplyAttempt(Attempt => Attempt?.Token === AttemptToken
                        ? { ...Attempt, ReadbackState: 'failed' } : Attempt);
                    if (CurrentSourceKeyRef.current === AttemptAtCompletion.SourceKey) {
                        SetValidated(null); SetMessage('操作已完成，但来源实例已变；旧来源草稿保留为可复制内容。');
                        void Bootstrap.refetch();
                    }
                    return;
                }
                const Snapshot = await ReadbackSource.GetConfiguration();
                if (!StillOwnsAttempt()) return;
                const AfterRead = await ReadbackSource.GetBootstrap({ Fresh: true });
                if (!StillOwnsAttempt()) return;
                const AfterSource = ConfigurationSource(AttemptAtCompletion.Source.Mode, AfterRead);
                if (ConfigurationSourceKey(AfterSource) !== AttemptAtCompletion.SourceKey) {
                    SetApplyAttempt(Attempt => Attempt?.Token === AttemptToken
                        ? { ...Attempt, ReadbackState: 'failed' } : Attempt);
                    if (CurrentSourceKeyRef.current === AttemptAtCompletion.SourceKey) {
                        SetValidated(null); SetMessage('操作已完成，但读回期间来源实例变化；草稿保留，请核对当前实例。');
                        void Bootstrap.refetch();
                    }
                    return;
                }
                const SnapshotScope = ConfigurationSourceKey(AfterSource);
                if (SnapshotScope) QueryClient.setQueryData(['operations', 'configuration', SnapshotScope], Snapshot);
                const SnapshotMatchesApply = SnapshotScope === AttemptAtCompletion.SourceKey &&
                    AttemptAtCompletion.OperationId === ApplyId && ApplyOperationGeneration !== null &&
                    Snapshot.Generation === ApplyOperationGeneration &&
                    PublicConfigurationsEquivalent(AttemptAtCompletion.Text, Snapshot.Text);
                SetApplyAttempt(Attempt => Attempt?.Token === AttemptToken
                    ? { ...Attempt, ReadbackState: SnapshotMatchesApply ? 'confirmed' : 'mismatch',
                        ReadbackGeneration: Snapshot.Generation, ReadbackText: Snapshot.Text } : Attempt);
                if (!SnapshotMatchesApply) {
                    if (CurrentSourceKeyRef.current === AttemptAtCompletion.SourceKey) {
                        SetValidated(null); SetMessage('操作已完成，当前配置版本或内容与本次提交不一致，请核对；草稿已保留。');
                    }
                    return;
                }
                if (CurrentSourceKeyRef.current === AttemptAtCompletion.SourceKey) {
                    SetBaseline(Snapshot); SetText(Snapshot.Text); SetBaselineSourceKey(SnapshotScope);
                    SetValidated(null);
                    if (DraftAtCompletion && GetConfigurationDraft() === DraftAtCompletion) ClearConfigurationDraft();
                    SetMessage('操作已完成，目标 Generation 快照与提交 JSON 内容一致。');
                }
            } catch (Failure: unknown) {
                if (!StillOwnsAttempt()) return;
                SetApplyAttempt(Attempt => Attempt?.Token === AttemptToken
                    ? { ...Attempt, ReadbackState: 'failed' } : Attempt);
                if (CurrentSourceKeyRef.current === AttemptAtCompletion.SourceKey) {
                    SetValidated(null);
                    SetMessage(Failure instanceof Error ? `操作已完成，但配置读回失败：${Failure.message}；草稿已保留。`
                        : '操作已完成，但配置读回失败；草稿已保留。');
                }
            } finally {
                if (StillOwnsAttempt()) {
                    SetApplyReadbackSettledId(ReadbackKey);
                    ApplySubmissionPhase.current = 'idle'; ApplySubmissionLock.current = false;
                    SetApplyRequestBusy(false);
                }
            }
        })();
    }, [ApplyId, ApplyScope?.ProcessId, ApplyScope?.Incarnation, ApplyTerminalCompletedForAttempt, ApplyAttempt, ApplyDataSource,
        ApplyOperationGeneration, ApplyReadbackSettledId, HandledApplyId, Draft, Bootstrap.refetch, QueryClient]);

    useEffect(() => {
        if (ApplySubmissionPhase.current !== 'awaiting-resolution' || ApplyStillPending || ApplyReadbackPendingForAttempt) return;
        ApplySubmissionPhase.current = 'idle'; ApplySubmissionLock.current = false;
        SetApplyRequestBusy(false);
    }, [ApplyStillPending, ApplyReadbackPendingForAttempt, ApplyTerminalCompletedForAttempt]);

    useEffect(() => {
        if (ApplyAttempt && ApplyAttempt.SourceKey !== CurrentSourceKey && !ApplyOutstanding) {
            if (ActiveApplyToken === ApplyAttempt.Token) ActiveApplyToken = 0;
            if (ApplyDataSourceRef.current?.Token === ApplyAttempt.Token) ApplyDataSourceRef.current = null;
            SetApplyAttempt(null);
        }
    }, [ApplyAttempt, CurrentSourceKey, ApplyOutstanding]);

    const UpdateDraftText = (Value: string): void => {
        if (!CanEdit || !Baseline) return;
        if (Value !== Baseline.Text && !SetConfigurationDraft({ Text: Value, Baseline, Source: CurrentSource })) {
            SetMessage('草稿来源已变化，已停止保存编辑；请重新核对当前实例。'); void Bootstrap.refetch(); return;
        }
        if (Value === Baseline.Text) ClearConfigurationDraft();
        ClearCurrentApplyAttempt();
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
        if (ApplySubmissionLock.current || !Baseline || !CanApply || !Draft || !DraftIsCurrent) return;
        const AttemptToken = ++ApplyTokenSequence;
        ActiveApplyToken = AttemptToken;
        ApplyDataSourceRef.current = { Token: AttemptToken, Data: Services.Data };
        ApplySubmissionLock.current = true; ApplySubmissionPhase.current = 'requesting';
        SetApplyRequestBusy(true); SetApplyReadbackSettledId('');
        Apply.reset(); SetHandledApplyId('');
        SetApplyAttempt({ Token: AttemptToken, Text, Generation: Baseline.Generation, Source: CurrentSource,
            SourceKey: CurrentSourceKey, Persist,
            OperationId: null, OperationGeneration: null, ReadbackState: 'not-started' });
        let KeepLocked = false;
        try {
            const Fresh = await Services.Data.GetBootstrap({ Fresh: true });
            if (ActiveApplyToken !== AttemptToken || ApplyAttemptRef.current?.Token !== AttemptToken) return;
            if (CurrentSourceKeyRef.current !== CurrentSourceKey ||
                !IsConfigurationDraftFor(Draft, ConfigurationSource(Services.Mode, Fresh))) {
                if (CurrentSourceKeyRef.current === CurrentSourceKey) {
                    SetMessage('应用前检测到来源实例变化；旧来源草稿保留，没有发送 Apply。'); void Bootstrap.refetch();
                }
                return;
            }
            const Result = await Apply.mutateAsync({ Text, Persist, Generation: Baseline.Generation });
            const ResultOperationId = Result.OperationId ?? Result.Operation?.Id ?? null;
            const HasOperationScope = !!ResultOperationId && !!Result.OperationScope;
            SetApplyAttempt(Attempt => Attempt && Attempt.Token === AttemptToken && Attempt.Text === Text && Attempt.Generation === Baseline.Generation &&
                Attempt.SourceKey === CurrentSourceKey && Attempt.Persist === Persist
                ? { ...Attempt, OperationId: ResultOperationId, OperationGeneration: Result.Operation?.GenerationId ?? null }
                : Attempt);
            KeepLocked = Result.Status === 'accepted' || Result.Status === 'unknown' || Result.Status === 'interrupted' ||
                Result.Status === 'completed' && HasOperationScope;
            ApplySubmissionPhase.current = KeepLocked ? 'awaiting-resolution' : 'idle';
            if (CurrentSourceKeyRef.current === CurrentSourceKey)
                SetMessage(Result.Status === 'accepted' ? 'Apply 已受理；等待真实终态。草稿在终态确认前保留。' : Result.Message);
            if (Result.Status !== 'completed' && Result.Status !== 'accepted') return;
        } catch (Failure: unknown) {
            if (CurrentSourceKeyRef.current === CurrentSourceKey)
                SetMessage(Failure instanceof Error ? Failure.message : 'Apply 请求失败；草稿已保留。');
        }
        finally {
            if (!KeepLocked && ActiveApplyToken === AttemptToken) {
                ApplySubmissionPhase.current = 'idle'; ApplySubmissionLock.current = false;
                SetApplyRequestBusy(false);
            }
        }
    };

    const Restore = (): void => {
        if (!Baseline || !CanEdit) return;
        ClearConfigurationDraft(); ClearCurrentApplyAttempt();
        SetText(Baseline.Text); SetValidated(null); SetMessage('已还原为编辑基线。'); SetDraftMessage('');
    };

    const CopyStaleDraft = async (): Promise<void> => {
        if (!DraftNeedsAttention || !Draft) return;
        try { await navigator.clipboard.writeText(Draft.Text); SetDraftMessage('保留的草稿已复制。'); }
        catch { SetDraftMessage('复制不可用；请在只读文本框中手动选择内容。'); }
    };

    const PrepareStaleDraftAdoption = async (): Promise<void> => {
        if (!DraftIsStale || !Draft || !CurrentSourceKey || ApplyBusy) return;
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
        if (!DraftIsStale || !Draft || !RebaseCandidate || !CurrentSourceKey || ApplyBusy) return;
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
            ClearCurrentApplyAttempt();
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

    return <div className="space-y-6">
        <header className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between"><div className="space-y-1"><h1 className="text-2xl font-bold tracking-tight">配置</h1><p className="max-w-3xl text-sm leading-6 text-muted-foreground">编辑公开配置草稿；每次发布都与实例来源、Generation 和读回结果绑定。</p></div><Badge variant="secondary" className="sm:mt-1">{Services.Mode === 'demo' ? '演示配置' : '生效配置'} · Generation {CurrentBaseline?.Generation ?? '—'}</Badge></header>
        {DraftNeedsAttention && Draft && <Alert variant="destructive"><FileCode2 aria-hidden="true" /><AlertTitle>{DraftIsStale ? '存在来自其他来源的未保存草稿' : '未保存草稿暂不可编辑'}</AlertTitle><AlertDescription className="space-y-4"><p>来源：{DescribeConfigurationSource(Draft.Source, Draft.Baseline.Generation)} · 更新于 {Draft.UpdatedAt}。{DraftIsStale ? '当前来源不匹配，不能直接校验或应用。' : '当前配置基线尚未载入；草稿已保留。'}</p><Textarea id="stale-configuration-draft" className="min-h-40 bg-background font-mono text-xs" value={Draft.Text} readOnly spellCheck={false} aria-label="旧来源草稿，只读" /><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={() => void CopyStaleDraft()}>复制保留的草稿</Button>{DraftIsStale && !RebaseCandidate && <Button variant="outline" disabled={!CurrentSourceKey || ApplyBusy || RebaseBusy} onClick={() => void PrepareStaleDraftAdoption()}>{RebaseBusy ? '读取当前基线…' : '读取当前基线并准备重基线'}</Button>}{DraftIsStale && RebaseCandidate && <><Button variant="outline" disabled={RebaseBusy || ApplyBusy} onClick={() => void PrepareStaleDraftAdoption()}>重新读取当前基线</Button><Button disabled={!CurrentSourceKey || RebaseBusy || ApplyBusy} onClick={() => SetRebaseConfirmOpen(true)}>确认以该基线重建</Button></>}<Button variant="destructive" disabled={RebaseBusy || ApplyBusy} onClick={() => SetDiscardConfirmOpen(true)}>放弃旧草稿</Button></div>{RebaseCandidate && <p className="text-xs">目标：{DescribeConfigurationSource(RebaseCandidate.Source, RebaseCandidate.Baseline.Generation)}</p>}{DraftMessage && <p className="text-sm">{DraftMessage}</p>}</AlertDescription></Alert>}
        {CurrentSourceKey === null && <Alert variant="destructive"><AlertTitle>实例来源尚未核实</AlertTitle><AlertDescription>配置读取和编辑已暂停；重试后再校验或应用。</AlertDescription></Alert>}
        {CurrentBaseline && Query.data && CurrentBaseline.Generation !== Query.data.Generation && <Alert><AlertTitle>运行配置已更新到 Generation {Query.data.Generation}</AlertTitle><AlertDescription className="flex flex-wrap items-center gap-3">当前草稿仍基于 {CurrentBaseline.Generation}，提交会进行冲突检查。<Button size="sm" variant="outline" disabled={ApplyBusy} onClick={() => { ClearConfigurationDraft(); ClearCurrentApplyAttempt(); SetBaseline(Query.data!); SetText(Query.data!.Text); SetBaselineSourceKey(CurrentSourceKey); SetValidated(null); SetMessage('已重新读取当前配置并放弃草稿。'); }}>重新读取并放弃草稿</Button></AlertDescription></Alert>}
        {Query.error && <Alert variant="destructive"><AlertTitle>配置快照不可用</AlertTitle><AlertDescription className="flex flex-wrap items-center gap-3">{Query.error.message}<Button size="sm" variant="outline" disabled={Bootstrap.isFetching || Query.isFetching} onClick={() => void Promise.all([Bootstrap.refetch(), Query.refetch()])}>重试</Button></AlertDescription></Alert>}
        {Query.isPending && !CurrentBaseline && <Card><CardContent className="py-12 text-center text-sm text-muted-foreground">正在读取当前配置快照…</CardContent></Card>}
        {CurrentBaseline && <><section className="grid gap-px overflow-hidden rounded-lg border bg-border md:grid-cols-3 [&>*]:rounded-none [&>*]:border-0 [&>*]:shadow-none"><StatusFact Label="当前 Generation" Value={`#${CurrentBaseline.Generation}`} Detail={CurrentBaseline.UpdatedAt ? FormatTime(CurrentBaseline.UpdatedAt, true) : '当前运行配置'} /><StatusFact Label="热加载" Value={CurrentBaseline.Reloadable ? '可重载' : '需重启'} Detail={CurrentBaseline.Reloadable ? '服务支持在线更新' : '服务端将拒绝在线应用'} /><StatusFact Label="当前草稿" Value={!Parsed.Ok ? 'JSON 格式错误' : Dirty ? `${Changes.length} 项差异` : '与快照一致'} Detail={`${LineCount} 行公开 JSON`} /></section>
            <section className="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(20rem,1fr)]"><Card><CardHeader><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><CardTitle>配置草稿</CardTitle><CardDescription>基于当前运行配置编辑，敏感内容不会出现在此页面。</CardDescription></div><div className="flex flex-wrap gap-2"><Button size="sm" variant="outline" disabled={!CanEdit || !Parsed.Ok} onClick={() => { if (Parsed.Ok) UpdateDraftText(FormatJsonDocument(Parsed.Value)); }}>排版 JSON</Button><Button size="sm" variant="outline" disabled={!Dirty || !CanEdit} onClick={Restore}><RotateCcw aria-hidden="true" />还原</Button></div></div></CardHeader><CardContent className="space-y-4"><div className="flex items-center justify-between rounded-md border bg-muted/30 px-3 py-2 text-xs text-muted-foreground"><span className="flex items-center gap-2 font-medium text-foreground"><FileCode2 aria-hidden="true" />PrismConfiguration.json</span><span>JSON · 基线 {CurrentBaseline.Generation}</span></div><Textarea id="configuration-editor" aria-label="配置 JSON" className="field-sizing-fixed h-[36rem] min-h-[24rem] resize-y overflow-auto bg-muted/20 font-mono text-xs leading-5" spellCheck={false} readOnly={!CanEdit} wrap="off" aria-invalid={Parsed.Ok ? undefined : true} aria-describedby={Parsed.Ok ? undefined : 'configuration-json-error'} value={Text} onChange={Event => UpdateDraftText(Event.target.value)} />{!Parsed.Ok && <Alert id="configuration-json-error" variant="destructive"><AlertTitle>JSON 格式错误</AlertTitle><AlertDescription>{Parsed.Message}</AlertDescription></Alert>}<div className="flex flex-wrap justify-between gap-2 text-xs text-muted-foreground"><span>{Dirty ? '未保存草稿' : '与运行配置一致'}</span><span>{LineCount} 行 · 基线 Generation {CurrentBaseline.Generation}</span></div><Alert role="note"><ShieldCheck aria-hidden="true" /><AlertTitle>发布保护已启用</AlertTitle><AlertDescription>应用前必须校验，发布时会核对版本冲突，完成后还会读回配置验证。</AlertDescription></Alert></CardContent></Card>
                <div className="space-y-4 xl:sticky xl:top-4 xl:self-start"><Card><CardHeader><CardTitle>发布流程</CardTitle><CardDescription>每一步均绑定当前实例和草稿精确文本。</CardDescription></CardHeader><CardContent className="space-y-3"><ol aria-label="配置应用流程" className="space-y-3">{WorkflowSteps.map(Step => <li key={Step.Number} className={`configuration-workflow-step flex gap-3 border-b pb-3 last:border-0 ${Step.Current ? 'is-current' : ''} ${Step.State === 'complete' ? 'is-complete' : ''}`} aria-current={Step.Current ? 'step' : undefined} data-state={Step.Current ? 'current' : Step.State}><div className="flex size-7 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-semibold">{Step.State === 'complete' ? <Check className="size-4" aria-label="已完成" /> : Step.Number}</div><div><strong className="text-sm font-medium">{Step.Title}</strong><p className="mt-1 text-xs text-muted-foreground">{Step.Detail}</p></div></li>)}</ol></CardContent></Card><Card><CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle>变更差异</CardTitle><CardDescription>{Parsed.Ok ? `${Changes.length} 个顶层配置字段变化` : '修正 JSON 后查看差异'}</CardDescription></div><Badge variant="outline">{Parsed.Ok ? `${Changes.length} 项` : '不可比较'}</Badge></div></CardHeader><CardContent>{!Parsed.Ok ? <p className="text-sm text-muted-foreground">草稿格式有误；校验与应用已暂停。</p> : Changes.length === 0 ? <p className="text-sm text-muted-foreground">暂无字段差异。编辑公开 JSON 后，修改内容会显示在此处。</p> : <div className="max-h-[24rem] overflow-auto rounded-md border"><Table><TableHeader><TableRow><TableHead>路径</TableHead><TableHead>之前</TableHead><TableHead>之后</TableHead></TableRow></TableHeader><TableBody>{Changes.map(Change => <TableRow key={Change.Path}><TableCell className="font-mono">{Change.Path}</TableCell><TableCell><pre className="max-w-40 overflow-auto whitespace-pre-wrap break-all text-xs text-muted-foreground">{Change.Before}</pre></TableCell><TableCell><pre className="max-w-40 overflow-auto whitespace-pre-wrap break-all text-xs">{Change.After}</pre></TableCell></TableRow>)}</TableBody></Table></div>}</CardContent></Card><Card><CardHeader><CardTitle>校验与应用</CardTitle><CardDescription>基于 Generation {CurrentBaseline.Generation}；已有连接继续持有其所属版本。</CardDescription></CardHeader><CardContent className="space-y-4"><div className="flex items-center justify-between gap-4 rounded-md border p-3"><div><p className="text-sm font-medium">同时保存到配置文件</p><p className="text-xs text-muted-foreground">关闭时仅发布运行配置。</p></div><Switch checked={Persist} disabled={!CanEdit} onCheckedChange={Value => { SetPersist(Value); ClearCurrentApplyAttempt(); }} aria-label="同时保存到配置文件" /></div><div className="flex flex-wrap gap-2"><Button variant="outline" disabled={!CanEdit || !Parsed.Ok || Validate.isPending} onClick={() => void ValidateDraft()}>{Validate.isPending ? '校验中…' : '校验草稿'}</Button><Button disabled={!CanApply} onClick={() => SetApplyConfirmOpen(true)}>{Persist ? '应用并保存' : '应用配置'}</Button></div>{ApplyDisabledReason && <p className="text-xs text-muted-foreground" role="status">{ApplyDisabledReason}</p>}{ApplyCaution && <Alert variant="destructive"><AlertTitle>需要处理</AlertTitle><AlertDescription>{ApplyCaution}</AlertDescription></Alert>}{Message && <Alert><AlertTitle>{ValidatedCurrent ? '校验结果' : '配置状态'}</AlertTitle><AlertDescription>{Message}</AlertDescription></Alert>}{ApplyAttemptMatchesDraft && Apply.data && <Alert><AlertTitle>应用操作状态</AlertTitle><AlertDescription>{Apply.data.Message}</AlertDescription></Alert>}<p className="flex items-center gap-2 text-xs text-muted-foreground"><FileSliders className="size-3" aria-hidden="true" />编辑基线 Generation {CurrentBaseline.Generation}{CurrentBaseline.UpdatedAt ? ` · ${FormatTime(CurrentBaseline.UpdatedAt, true)}` : ' · 磁盘持久化状态以发布结果为准'}</p></CardContent></Card></div></section></>}
        {!Query.isPending && !CurrentBaseline && !Query.error && <Card><CardContent className="py-12 text-center"><p className="font-medium">{CurrentSourceKey ? '配置快照未载入' : '实例来源未核实'}</p><p className="mt-1 text-sm text-muted-foreground">{CurrentSourceKey ? '检查 Operations 服务与配置读取能力。' : '不会把旧来源草稿作为当前配置。'}</p></CardContent></Card>}
        <Dialog open={RebaseConfirmOpen} onOpenChange={SetRebaseConfirmOpen}><DialogContent><DialogHeader><DialogTitle>按当前来源重建草稿？</DialogTitle><DialogDescription>{Draft && RebaseCandidate ? `原稿：${DescribeConfigurationSource(Draft.Source, Draft.Baseline.Generation)}。目标：${DescribeConfigurationSource(RebaseCandidate.Source, RebaseCandidate.Baseline.Generation)}。确认时会再次 Fresh 核验来源和 Generation。` : '确认后会重新核验目标配置。'}</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => SetRebaseConfirmOpen(false)}>取消</Button><Button disabled={!CurrentSourceKey || RebaseBusy || ApplyBusy} onClick={() => void AdoptStaleDraft().then(() => SetRebaseConfirmOpen(false))}>{RebaseBusy ? '正在核验…' : '确认重建并重新校验'}</Button></DialogFooter></DialogContent></Dialog>
        <Dialog open={DiscardConfirmOpen} onOpenChange={SetDiscardConfirmOpen}><DialogContent><DialogHeader><DialogTitle>放弃旧来源草稿？</DialogTitle><DialogDescription>这会从内存中删除这份未保存文本，无法恢复。</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => SetDiscardConfirmOpen(false)}>取消</Button><Button variant="destructive" disabled={RebaseBusy || ApplyBusy} onClick={() => void DiscardStaleDraft().then(() => SetDiscardConfirmOpen(false))}>确认放弃</Button></DialogFooter></DialogContent></Dialog>
        <Dialog open={ApplyConfirmOpen} onOpenChange={SetApplyConfirmOpen}><DialogContent><DialogHeader><DialogTitle>{Persist ? '应用并保存配置？' : '应用运行配置？'}</DialogTitle><DialogDescription>{Persist ? '基线匹配后会应用并保存配置文件；已有连接保持其原有 Generation。' : '只发布运行配置，不会替代磁盘配置；需要重启的字段会被明确返回。'}</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => SetApplyConfirmOpen(false)}>取消</Button><Button disabled={!CanApply || ApplyRequestBusy || Apply.isPending} onClick={() => void ApplyDraft().then(() => SetApplyConfirmOpen(false))}>{ApplyRequestBusy || Apply.isPending ? '正在发布…' : '确认发布'}</Button></DialogFooter></DialogContent></Dialog>
    </div>;
}

function StatusFact(Input: Readonly<{ Label: string; Value: string; Detail: string }>): ReactNode {
    return <Card className="py-0"><CardContent className="flex min-w-0 items-center justify-between gap-4 p-3"><div className="min-w-0"><p className="text-sm font-medium">{Input.Label}</p><p className="mt-1 text-xs text-muted-foreground">{Input.Detail}</p></div><p className="text-right text-lg font-semibold tracking-tight">{Input.Value}</p></CardContent></Card>;
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

function PublicConfigurationsEquivalent(SubmittedText: string, ReadbackText: string): boolean {
    const Submitted = ParsePublicConfiguration(SubmittedText);
    const Readback = ParsePublicConfiguration(ReadbackText);
    return Submitted.Ok && Readback.Ok && JsonNodesEquivalent(Submitted.Value, Readback.Value);
}

function JsonNodesEquivalent(Left: JsonNode, Right: JsonNode): boolean {
    if (Left.Kind !== Right.Kind) return false;
    switch (Left.Kind) {
        case 'object':
            if (Right.Kind !== 'object' || Left.Members.size !== Right.Members.size) return false;
            for (const [Name, Value] of Left.Members) {
                const Other = Right.Members.get(Name);
                if (!Other || !JsonNodesEquivalent(Value, Other)) return false;
            }
            return true;
        case 'array':
            return Right.Kind === 'array' && Left.Elements.length === Right.Elements.length &&
                Left.Elements.every((Value, Index) => {
                    const Other = Right.Elements[Index];
                    return Other !== undefined && JsonNodesEquivalent(Value, Other);
                });
        case 'string':
            return Right.Kind === 'string' && Left.Text === Right.Text;
        case 'number':
            return Right.Kind === 'number' && Left.Raw === Right.Raw;
        case 'boolean':
            return Right.Kind === 'boolean' && Left.Raw === Right.Raw;
        case 'null':
            return Right.Kind === 'null';
    }
    return false;
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
