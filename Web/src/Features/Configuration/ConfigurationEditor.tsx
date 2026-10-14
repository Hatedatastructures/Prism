import { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import type { Decimal } from '../../Api/Decimal';
import { ConfigurationChanges, ParsePublicConfiguration, ReloadDocument } from '../../Api/ConfigurationDocument';
import type { ConfigurationChange, ReloadMode } from '../../Api/ConfigurationDocument';
import { FormatJsonDocument } from '../../Api/JsonDocument';
import { DecodeCommandResponse, VerifyCommandProcess } from '../../Api/OperationsApi';
import type { CommandEnvelope, ConfigurationSnapshot } from '../../Api/OperationsApi';
import { Fail, Success } from '../../Api/Result';
import type { Result } from '../../Api/Result';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { FailureNotice, InlineCommandResult, StatusBadge } from '../../Components/ResultView';
import { HasCapability, useAdminServices, useCommandRunner } from '../UseOperations';
import './Configuration.css';

type Submission = Readonly<{
    Process: string; Incarnation: string; Operation: string; Mode: ReloadMode;
    Base: string; Text: string; ImmediateResult: CommandEnvelope | null;
}>;
type ConfirmedOperation = Readonly<{
    Process: string; Incarnation: string; Operation: string;
    Value: CommandEnvelope; CheckedAt: string;
}>;

export function ConfigurationEditor(Input: Readonly<{
    Snapshot: ConfigurationSnapshot; SnapshotIsCurrent: boolean; OnRefresh: () => Promise<unknown>;
}>): ReactNode {
    const Services = useAdminServices();
    const Runner = useCommandRunner();
    const [Base, SetBase] = useState(Input.Snapshot);
    const [Text, SetText] = useState(() => FormatJsonDocument(Input.Snapshot.Node));
    const [Error, SetError] = useState('');
    const [SubmissionValue, SetSubmission] = useState<Submission | null>(null);
    const [ConfirmedOperationValue, SetConfirmedOperation] = useState<ConfirmedOperation | null>(null);
    const Parsed = useMemo(() => ParsePublicConfiguration(Text), [Text]);
    const Changes = useMemo(() => {
        if (!Parsed.Ok) return [];
        return ConfigurationChanges(Base.Node, Parsed.Value);
    }, [Base, Parsed]);
    const SameGeneration = Base.Generation === Input.Snapshot.Generation;
    const CanValidateCapability = HasCapability(Services, 'configuration.reload.validate');
    const CanApplyCapability = HasCapability(Services, 'configuration.reload.apply');
    const CanReadOperationStatus = HasCapability(Services, 'operations.status');
    const CurrentSubmission = SubmissionValue !== null &&
        SubmissionValue.Process === Services.Bootstrap.Process &&
        SubmissionValue.Incarnation === Services.Bootstrap.Incarnation ? SubmissionValue : null;
    const Operation = CurrentSubmission?.Operation || '0';
    const SubmissionMatchesDraft = CurrentSubmission !== null &&
        CurrentSubmission.Text === Text && CurrentSubmission.Base === Base.Generation;
    const OperationQuery = useQuery({
        queryKey: ['configuration-operation', Services.Bootstrap.Process, Services.Bootstrap.Incarnation, Operation],
        queryFn: async ({ signal }) => {
            const ResultValue = await Services.Client.Query({
                Path: `/Operations/Operations/${Operation}`, Signal: signal, Decode: DecodeCommandResponse });
            return VerifyOperation(ResultValue, Operation, Services.Bootstrap.Process);
        },
        enabled: Operation !== '0' && CurrentSubmission?.ImmediateResult === null && CanReadOperationStatus,
        refetchInterval: State => {
            const Data = State.state.data;
            if (Data === undefined || !Data.Ok) return 3000;
            if (Data.Value.Status === 'accepted') return 1500;
            return false;
        },
        retry: false, refetchIntervalInBackground: false,
    });
    useEffect(() => {
        const ResultValue = OperationQuery.data;
        if (CurrentSubmission === null || Operation === '0' || CurrentSubmission.ImmediateResult !== null ||
            ResultValue === undefined || !ResultValue.Ok ||
            (ResultValue.Value.Status === 'invalid' && ResultValue.Value.Operation === '0')) return;
        SetConfirmedOperation({ Process: CurrentSubmission.Process,
            Incarnation: CurrentSubmission.Incarnation, Operation, Value: ResultValue.Value,
            CheckedAt: new Date().toLocaleString('zh-CN') });
    }, [CurrentSubmission, Operation, OperationQuery.data]);
    const ConfirmedOperation = CurrentSubmission?.ImmediateResult === null &&
        ConfirmedOperationValue?.Process === Services.Bootstrap.Process &&
        ConfirmedOperationValue.Incarnation === Services.Bootstrap.Incarnation &&
        ConfirmedOperationValue.Operation === Operation
        ? ConfirmedOperationValue : null;
    const ConfirmedResult = ConfirmedOperation === null ? null : Success(ConfirmedOperation.Value);
    let DisplayResult = ConfirmedResult;
    if (DisplayResult === null && CurrentSubmission?.ImmediateResult !== null &&
        CurrentSubmission?.ImmediateResult !== undefined) {
        DisplayResult = Success(CurrentSubmission.ImmediateResult);
    }
    if (DisplayResult === null && OperationQuery.data?.Ok) DisplayResult = OperationQuery.data;
    const ValidationResult = DisplayResult || OperationQuery.data;
    const Validated = IsValidated(CurrentSubmission, ValidationResult, {
        Text, Generation: Base.Generation, Process: Services.Bootstrap.Process,
        Incarnation: Services.Bootstrap.Incarnation,
    });
    const CurrentValidation = Validated && SameGeneration && Input.SnapshotIsCurrent;
    const OperationUnavailable = OperationQuery.data?.Ok === true &&
        OperationQuery.data.Value.Status === 'invalid' && OperationQuery.data.Value.Operation === '0';
    const CanValidate = Parsed.Ok && SameGeneration && Input.SnapshotIsCurrent && Base.Reloadable &&
        CanValidateCapability;
    const CanApply = CanValidate && CurrentValidation && Changes.length > 0 &&
        CanApplyCapability;

    async function Submit(Mode: ReloadMode): Promise<unknown> {
        if (Runner.IsPending || !CanValidate || Mode === 'apply' && !CanApply) return;
        const Document = ReloadDocument.Create({ Text, BaseGeneration: Base.Generation, Mode });
        if (!Document.Ok) { SetError(Document.Message); return; }
        SetError('');
        SetSubmission(null);
        let Label = '校验配置';
        if (Mode === 'apply') Label = '应用配置';
        const Outcome = await Runner.Submit({ Path: '/Operations/Reload', Body: Document.Value,
            Label, Target: `配置版本 ${Base.Generation}` });
        if (!Outcome.Ok) return Outcome;
        if (Outcome.Value.Status === 'accepted' || Outcome.Value.Status === 'completed') {
            SetSubmission({ Process: Services.Bootstrap.Process,
                Incarnation: Services.Bootstrap.Incarnation, Operation: Outcome.Value.Operation,
                Mode, Base: Base.Generation, Text,
                ImmediateResult: Outcome.Value.Status === 'completed' ? Outcome.Value : null });
        }
        return Outcome;
    }
    async function Validate(): Promise<unknown> { return Submit('validate_only'); }
    async function Apply(): Promise<unknown> { return Submit('apply'); }
    async function LoadLatest(): Promise<void> {
        SetBase(Input.Snapshot);
        SetText(FormatJsonDocument(Input.Snapshot.Node));
        SetSubmission(null);
        SetError('');
    }
    function Format(): void {
        if (Parsed.Ok) SetText(FormatJsonDocument(Parsed.Value));
    }
    return <>
        <div className="panel-heading"><div><h2>公共配置</h2>
            <p>草稿基于配置版本 {Base.Generation} · 当前读取版本 {Input.Snapshot.Generation}</p></div>
            <StatusBadge Label={CurrentValidation ? '当前草稿已通过校验' : '草稿尚未通过校验'}
                Tone={CurrentValidation ? 'good' : 'warn'} /></div>
        <div className="panel-body configuration-body">
            {!SameGeneration && <div className="notice notice-warn" role="status">
                当前配置版本已变化。旧草稿继续保留，请重新读取、比较并校验后再应用。</div>}
            {CurrentSubmission !== null && !SubmissionMatchesDraft && <div className="notice notice-info" role="status">
                下方操作属于此前提交的草稿或配置版本，不会用于当前内容；请重新校验当前草稿。</div>}
            {!Base.Reloadable && <div className="notice notice-unavailable" role="status">
                当前配置未启用热更新；配置仍可查看，变更需重启进程。</div>}
            {Base.Reloadable && CanValidateCapability && !CanReadOperationStatus && <div className="notice notice-unavailable" role="status">
                当前服务不提供操作进度查询。只有本次校验请求直接确认完成时才能应用；若服务返回“处理中”，页面无法确认异步结果。</div>}
            {Base.Reloadable && !CanValidateCapability && <div className="notice notice-unavailable" role="status">
                当前服务未发布配置校验能力；草稿可以查看和比较，但无法提交校验。</div>}
            {Base.Reloadable && CanValidateCapability && !CanApplyCapability && <div className="notice notice-unavailable" role="status">
                当前服务未发布配置应用能力；校验结果可以查看，但不能发布变更。</div>}
            <label className="field configuration-field">配置 JSON
                <textarea className="configuration-editor" spellCheck={false} value={Text}
                    onChange={Event => SetText(Event.target.value)} aria-invalid={!Parsed.Ok}
                    aria-describedby="configuration-secret-contract" /></label>
            <p id="configuration-secret-contract" className="muted">
                页面只显示公开配置和密钥引用，不显示现有密钥本身；现有凭据由服务安全保留。新增账户需引用可解析的密钥。
                草稿只留在当前页面，数值精度按原样提交。</p>
            {!Parsed.Ok && <div className="notice notice-error" role="alert">{Parsed.Message}</div>}
            {Error.length > 0 && <div className="notice notice-error" role="alert">{Error}</div>}
            <div className="button-row">
                <button className="button button-secondary" disabled={!Parsed.Ok || Runner.IsPending} onClick={Format}>排版 JSON</button>
                <button className="button button-secondary" disabled={Runner.IsPending} onClick={() => void Input.OnRefresh()}>读取当前版本</button>
                <ConfirmAction Label="用当前版本替换草稿" Title="替换当前草稿？"
                    Description={`将用已读取的配置版本 ${Input.Snapshot.Generation} 替换编辑器，未应用的改动会丢弃。`}
                    ConfirmLabel="替换草稿" Disabled={!Input.SnapshotIsCurrent}
                    Busy={Runner.IsPending} OnConfirm={LoadLatest} />
                <button className="button button-secondary" disabled={!CanValidate || Runner.IsPending}
                    onClick={() => void Validate()}>仅校验</button>
                <ConfirmAction Label="应用配置" Title="发布已校验的配置？"
                    Description={`以配置版本 ${Base.Generation} 为基准发布 ${Changes.length} 组字段变化。已建立的会话仍按原配置运行。`}
                    ConfirmLabel="发布配置" Disabled={!CanApply} Busy={Runner.IsPending} OnConfirm={Apply} />
            </div>
            <ConfigurationDiff Changes={Changes} />
            <InlineCommandResult Result={Runner.Result} Process={Services.Bootstrap.Process} />
            {Operation !== '0' && <div className="status-detail">
                <p>操作编号 {Operation}：只有服务端确认完成后，页面才会标记校验或发布成功。</p>
                {OperationUnavailable && <div className="notice notice-warn" role="status">
                    <strong>服务端当前无法查询此操作</strong>
                    <p>{ConfirmedOperation === null
                        ? '服务端没有返回此操作编号的记录，不能确认校验已完成；发布按钮保持禁用。'
                        : '本次查询没有返回原操作编号；下方保留最近一次成功查询的状态。页面只使用与当前草稿和配置版本绑定的已确认完成结果判断发布条件。'}</p>
                </div>}
                {OperationQuery.isError && <div className="notice notice-warn" role="status">
                    <strong>本次进度查询失败</strong>
                    <p>{ConfirmedOperation === null ? '尚无已确认的操作状态。' : '下方保留最近一次成功查询的状态；当前进度仍未知。'}</p>
                </div>}
                {OperationQuery.data && !OperationQuery.data.Ok && <FailureNotice
                    Failure={OperationQuery.data.Failure}
                    Heading={ConfirmedOperation === null ? '尚无已确认的操作状态' : '本次查询失败；保留最近一次确认状态'}
                    OnRetry={() => void OperationQuery.refetch()} />}
                {DisplayResult && <InlineCommandResult Result={DisplayResult} Process={Services.Bootstrap.Process} />}
                {ConfirmedOperation && <p className="muted">最近成功查询：{ConfirmedOperation.CheckedAt}</p>}
            </div>}
        </div>
    </>;
}

function VerifyOperation(
    ResultValue: Result<CommandEnvelope>, Operation: string, Process: Decimal,
): Result<CommandEnvelope> {
    const ProcessResult = VerifyCommandProcess(ResultValue, Process, false);
    if (!ProcessResult.Ok) return ProcessResult;
    const Value = ProcessResult.Value;
    if (Value.Status === 'invalid' && Value.Operation === '0') return ProcessResult;
    if (Value.Operation === Operation) return ProcessResult;
    return Fail({ Kind: 'contract', Message: '配置操作返回的编号与当前查询不匹配，无法确认处理状态',
        HttpStatus: null, MayHaveExecuted: false });
}

function IsValidated(SubmissionValue: Submission | null, ResultValue: Result<CommandEnvelope> | undefined,
    Draft: Readonly<{ Text: string; Generation: string; Process: string; Incarnation: string }>): boolean {
    if (SubmissionValue === null || SubmissionValue.Operation === '0' || SubmissionValue.Mode !== 'validate_only' ||
        SubmissionValue.Text !== Draft.Text || SubmissionValue.Base !== Draft.Generation ||
        SubmissionValue.Process !== Draft.Process || SubmissionValue.Incarnation !== Draft.Incarnation ||
        ResultValue?.Ok !== true || ResultValue.Value.Status !== 'completed' ||
        ResultValue.Value.Generation !== Draft.Generation) return false;
    if (SubmissionValue.ImmediateResult !== null) return ResultValue.Value === SubmissionValue.ImmediateResult &&
        ResultValue.Value.Operation === SubmissionValue.Operation;
    return SubmissionValue.Operation !== '0' && ResultValue.Value.Operation === SubmissionValue.Operation;
}

function ConfigurationDiff(Input: Readonly<{ Changes: readonly ConfigurationChange[] }>): ReactNode {
    if (Input.Changes.length === 0) return <div className="status-detail">公共配置字段没有变化。</div>;
    return <section className="configuration-diff" aria-label="配置字段差异">
        <h3>字段差异 · {Input.Changes.length} 组</h3>
        {Input.Changes.map(Change => <details key={Change.Path}>
            <summary>{Change.Path}</summary><div className="configuration-comparison">
                <div><h4>读取值</h4><pre>{Change.Before}</pre></div>
                <div><h4>草稿值</h4><pre>{Change.After}</pre></div>
            </div></details>)}
    </section>;
}
