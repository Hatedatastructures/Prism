import { useState } from 'react';
import type { ReactNode } from 'react';
import { Alert, AlertDescription, AlertTitle } from '@/Components/ui/alert';
import { Input as TextInput } from '@/Components/ui/input';
import { FormatBytes, FormatTime, QueryState, ProgressBar } from '../../Components/Ui';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { Fraction } from '../../Api/Analysis';
import type { AccountRecord, UsageAdjustment } from '../../Services/AdminDataSource';
import { useAdminMutation, useAdminQuery, useBootstrapIdentity } from '../UseOperations';
import { ActionFeedback } from '../ActionFeedback';

export function AccountUsagePanel(Input: Readonly<{ Account: AccountRecord; RelatedSessions?: ReactNode }>): ReactNode {
    const Bootstrap = useBootstrapIdentity();
    const AccountKey = Input.Account.AccountKey;
    const CurrentCapabilities = Bootstrap.error ? undefined : Bootstrap.data?.Capabilities;
    const CanReadUsage = CurrentCapabilities?.includes('accounts.usage.read') === true;
    const CanAdjustUsage = CurrentCapabilities?.includes('accounts.usage.adjust') === true;
    const Query = useAdminQuery('account-usage', Source => {
        if (!AccountKey) throw new Error('当前账户快照尚未提供账本关联标识');
        if (!Source.GetAccountUsage) throw new Error('当前数据源尚未提供可靠额度账本');
        return Source.GetAccountUsage(AccountKey);
    }, { Scope: [AccountKey ?? 'missing-account-key'], Enabled: CanReadUsage && !!AccountKey });
    const Adjust = useAdminMutation((Source, Value: UsageAdjustment) => {
        if (!Source.AdjustUsage) throw new Error('当前实例尚未提供额度调整能力');
        return Source.AdjustUsage(Value);
    });
    const [Kind, SetKind] = useState<'add_allowance' | 'release_uncertain'>('add_allowance');
    const [Bytes, SetBytes] = useState(''), [Reason, SetReason] = useState('');
    const Usage = Query.data;
    const RemainingPercent = Usage ? Fraction(Usage.RemainingBytes, Usage.LimitBytes) : null;
    const OccupiedPercent = RemainingPercent === null ? null : 100 - RemainingPercent;
    const OccupiedPercentLabel = OccupiedPercent === null ? '' : OccupiedPercent === 0 ? '0%' :
        OccupiedPercent < 0.01 ? '<0.01%' : `${OccupiedPercent.toFixed(2)}%`;
    const ShowBalance = CanReadUsage && !!AccountKey && Usage?.Available;
    const Valid = /^(0|[1-9]\d*)$/.test(Bytes) && BigInt(Bytes || '0') > 0n && BigInt(Bytes || '0') <= 18446744073709551615n && Reason.trim().length >= 2;
    const SubmitAdjustment = async () => {
        if (!Usage || !AccountKey) throw new Error('缺少已读取的账本身份或修订，无法提交调整');
        const Result = await Adjust.mutateAsync({ AccountKey: Usage.AccountKey, Revision: Usage.Revision, Kind, Bytes, Reason: Reason.trim() });
        if (Result.Status !== 'accepted' && Result.Status !== 'running') {
            const CurrentIdentity = await Bootstrap.refetch();
            if (!CurrentIdentity.error && CurrentIdentity.data?.Capabilities.includes('accounts.usage.read')) await Query.refetch();
        }
        return Result;
    };
    return <section className="usage-section space-y-5" aria-label="账户周期额度">
        {ShowBalance && <div className="grid gap-3 sm:grid-cols-2">
            <div className="rounded-lg border p-4"><p className="text-sm text-muted-foreground">可用余额</p><p className="mt-1 text-2xl font-semibold">{Usage.LimitBytes === null ? '不限额' : FormatBytes(Usage.RemainingBytes)}</p></div>
            <div className="rounded-lg border p-4"><p className="text-sm text-muted-foreground">本周期总额</p><p className="mt-1 text-2xl font-semibold">{Usage.LimitBytes === null ? '不限额' : FormatBytes(Usage.LimitBytes)}</p></div>
            {OccupiedPercent !== null && <div className="space-y-2 sm:col-span-2"><div className="flex justify-between text-sm"><span>额度已占用</span><span>{OccupiedPercentLabel}</span></div><ProgressBar Value={OccupiedPercent} Label="额度已占用比例" /><p className="text-xs text-muted-foreground">已结算、在途预约及异常未结清占额</p></div>}
            {OccupiedPercent === null && Usage.LimitBytes !== null && <p className="text-sm text-muted-foreground sm:col-span-2">{Usage.LimitBytes === '0' ? '周期额度为 0，不计算占用比例。' : '余额未提供，无法计算占用比例。'}</p>}
        </div>}
        {Input.RelatedSessions}
        {Bootstrap.isPending && !Bootstrap.data && <p role="status" className="text-sm text-muted-foreground">正在核对账户额度读取能力…</p>}
        {Bootstrap.error && <Alert variant="destructive"><AlertTitle>无法核对额度能力</AlertTitle><AlertDescription>{Bootstrap.error.message}。未请求账户额度或开放调整。</AlertDescription></Alert>}
        {Bootstrap.data && !Bootstrap.error && !CanReadUsage && <Alert role="note"><AlertTitle>额度读取不可用</AlertTitle><AlertDescription>当前实例未提供账户额度读取能力（accounts.usage.read）；未请求额度账本。</AlertDescription></Alert>}
        {Bootstrap.data && CanReadUsage && !AccountKey && <Alert role="note"><AlertTitle>缺少账本身份</AlertTitle><AlertDescription>当前账户快照未提供额度账本关联标识；未使用显示名称代替身份发起查询。</AlertDescription></Alert>}
        {CanReadUsage && !!AccountKey && <QueryState Pending={Query.isPending} Error={Query.error} HasData={Usage !== undefined} Label="账户额度账本" Children={Usage ? <>
            {!Usage.Available ? <Alert role="note"><AlertTitle>账本不可用</AlertTitle><AlertDescription>{Usage.Failure ?? '有限额度账户不能获取新传输信用'}</AlertDescription></Alert> : <>
                <dl className="grid grid-cols-2 gap-3 text-sm">
                    <UsageFact Label="已结算" Value={FormatBytes(Usage.SettledBytes)} /><UsageFact Label="在途预约" Value={FormatBytes(Usage.ReservedBytes)} />
                    <UsageFact Label="异常未结清占额" Value={FormatBytes(Usage.UncertainBytes)} /><UsageFact Label="超额" Value={FormatBytes(Usage.OverageBytes)} />
                    <UsageFact Label="周期开始" Value={FormatTime(Usage.CycleStart, true)} /><UsageFact Label="下次重置" Value={Usage.CycleEnd ? FormatTime(Usage.CycleEnd, true) : '不重置'} />
                </dl>
                {CanAdjustUsage ? <details className="usage-adjustment rounded-lg border">
                    <summary className="cursor-pointer px-4 py-3 text-sm font-medium">调整本周期额度</summary>
                    <div className="space-y-4 border-t p-4">
                        <fieldset role="radiogroup" aria-label="调整类型" className="space-y-2"><legend className="text-sm font-medium">调整类型</legend>
                            <div className="grid gap-2 sm:grid-cols-2">{([{ Value: 'add_allowance', Label: '增加本周期额度' }, { Value: 'release_uncertain', Label: '释放异常占额' }] as const).map(Option =>
                                <label key={Option.Value} className="flex cursor-pointer items-center gap-2 rounded-lg border p-3 text-sm has-checked:bg-muted">
                                    <input type="radio" name="usage-kind" value={Option.Value} checked={Kind === Option.Value} onChange={() => SetKind(Option.Value)} disabled={Adjust.isPending} className="accent-primary" /><span><span className="block">{Option.Label}</span><span className="block text-xs text-muted-foreground">{Option.Value === 'add_allowance' ? '提高当前周期可用上限' : '核对后释放未结清占额'}</span></span>
                                </label>)}</div>
                        </fieldset>
                        <div className="space-y-2"><label className="text-sm font-medium" htmlFor="usage-bytes">字节量</label><TextInput id="usage-bytes" value={Bytes} onChange={Event => SetBytes(Event.target.value)} inputMode="numeric" placeholder="例如 1073741824" disabled={Adjust.isPending} /></div>
                        <div className="space-y-2"><label className="text-sm font-medium" htmlFor="usage-reason">调整原因</label><TextInput id="usage-reason" value={Reason} onChange={Event => SetReason(Event.target.value)} maxLength={256} disabled={Adjust.isPending} /></div>
                        <ConfirmAction Label="提交调整" Title="确认调整账户账本？" Description={`${Input.Account.Label} · ${Kind === 'add_allowance' ? '增加额度' : '释放异常占额'} ${Valid ? FormatBytes(Bytes) : ''}。使用账本修订 ${Usage.Revision}，冲突时重新读取，不覆盖并发变化。`}
                            ConfirmLabel="确认调整" Disabled={!Valid} Busy={Adjust.isPending} OnConfirm={SubmitAdjustment} />
                    </div>
                </details> : <p className="text-sm text-muted-foreground">当前实例未提供额度调整能力（accounts.usage.adjust）；账本保持只读。</p>}
            </>}
        </> : null} />}
        {Adjust.data && <ActionFeedback Result={Adjust.data} />}
    </section>;
}

function UsageFact(Input: Readonly<{ Label: string; Value: string }>): ReactNode {
    return <div className="rounded-md bg-muted/50 p-3"><dt className="text-xs text-muted-foreground">{Input.Label}</dt><dd className="mt-1 font-medium">{Input.Value}</dd></div>;
}
