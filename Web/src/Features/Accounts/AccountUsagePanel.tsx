import { useState } from 'react';
import type { ReactNode } from 'react';

import { FormatBytes, FormatTime, QueryState, ProgressBar, FormatRate } from '../../Components/Ui';
import { ConfirmAction } from '../../Components/ConfirmAction';
import { Fraction } from '../../Api/Analysis';
import type { AccountRecord, UsageAdjustment } from '../../Services/AdminDataSource';
import { useAdminMutation, useAdminQuery, useBootstrapIdentity } from '../UseOperations';
import { ActionFeedback } from '../ActionFeedback';

export function AccountUsagePanel(Input: Readonly<{ Account: AccountRecord }>): ReactNode {
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
    return <section className="usage-section" aria-label="账户周期额度">
        <div className="account-rate-strip"><div><span>当前上行速率</span><strong>{Input.Account.UploadBytesPerSecond === null || Input.Account.UploadBytesPerSecond === undefined ? '当前账户快照未提供' : FormatRate(Input.Account.UploadBytesPerSecond)}</strong></div><div><span>当前下行速率</span><strong>{Input.Account.DownloadBytesPerSecond === null || Input.Account.DownloadBytesPerSecond === undefined ? '当前账户快照未提供' : FormatRate(Input.Account.DownloadBytesPerSecond)}</strong></div></div>
        <p className="field-hint">速率来自当前账户快照；下方累计流量与周期账本是不同口径。</p>
        {Bootstrap.isPending && !Bootstrap.data && <div className="query-state" role="status">正在核对账户额度读取能力…</div>}
        {Bootstrap.error && !Bootstrap.data && <div className="notice notice-danger" role="alert">暂时无法核对额度能力：{Bootstrap.error.message}。未请求账户额度。</div>}
        {Bootstrap.error && Bootstrap.data && <div className="notice notice-warning" role="status">最近一次能力读取失败：{Bootstrap.error.message}。当前能力快照可能过期，暂不请求额度或开放调整。</div>}
        {Bootstrap.data && !Bootstrap.error && !CanReadUsage && <div className="notice notice-warning" role="note">当前实例未提供账户额度读取能力（accounts.usage.read）；未请求额度账本。</div>}
        {Bootstrap.data && CanReadUsage && !AccountKey && <div className="notice notice-warning" role="note">当前账户快照未提供额度账本关联标识；未使用显示名称代替身份发起查询。</div>}
        {CanReadUsage && !!AccountKey && <QueryState Pending={Query.isPending} Error={Query.error} HasData={Usage !== undefined} Label="账户额度账本" Children={Usage ? <>
            {!Usage.Available ? <div className="notice notice-warning">账本不可用：{Usage.Failure ?? '有限额度账户不能获取新传输信用'}</div> : <>
                <div className="usage-remaining"><span>可用余额</span><strong>{Usage.LimitBytes === null ? '不限额' : FormatBytes(Usage.RemainingBytes)}</strong></div>
                {Usage.LimitBytes !== null && <ProgressBar Value={100 - (Fraction(Usage.RemainingBytes, Usage.LimitBytes) ?? 0)} Tone="mint" Label="额度已占用比例" />}
                <dl className="detail-kv"><div><dt>本周期总额</dt><dd>{Usage.LimitBytes === null ? '不限额' : FormatBytes(Usage.LimitBytes)}</dd></div>
                    <div><dt>已结算</dt><dd>{FormatBytes(Usage.SettledBytes)}</dd></div><div><dt>在途预约</dt><dd>{FormatBytes(Usage.ReservedBytes)}</dd></div>
                    <div><dt>异常未结清占额</dt><dd>{FormatBytes(Usage.UncertainBytes)}</dd></div><div><dt>超额</dt><dd>{FormatBytes(Usage.OverageBytes)}</dd></div>
                    <div><dt>周期开始</dt><dd>{FormatTime(Usage.CycleStart, true)}</dd></div><div><dt>下次重置</dt><dd>{Usage.CycleEnd ? FormatTime(Usage.CycleEnd, true) : '不重置'}</dd></div></dl>
                <p className="field-hint">上、下行有效载荷合计。异常占额保持占用，明确核对后才能释放。</p>
                {CanAdjustUsage ? <details className="usage-adjustment"><summary>调整本周期额度</summary>
                    <label className="field-label">调整类型<select className="field-input" value={Kind} onChange={Event => SetKind(Event.target.value as typeof Kind)}>
                        <option value="add_allowance">增加本周期额度</option><option value="release_uncertain">释放异常占额</option></select></label>
                    <label className="field-label">字节量<input className="field-input" inputMode="numeric" value={Bytes} onChange={Event => SetBytes(Event.target.value)} placeholder="例如 1073741824" /></label>
                    <label className="field-label">调整原因<input className="field-input" value={Reason} onChange={Event => SetReason(Event.target.value)} maxLength={256} /></label>
                    <ConfirmAction Label="提交调整" Title="确认调整账户账本？" Description={`${Input.Account.Label} · ${Kind === 'add_allowance' ? '增加额度' : '释放异常占额'} ${Valid ? FormatBytes(Bytes) : ''}。使用账本修订 ${Usage.Revision}，冲突时重新读取，不覆盖并发变化。`}
                        ConfirmLabel="确认调整" Disabled={!Valid} Busy={Adjust.isPending} OnConfirm={SubmitAdjustment} />
                </details> : <p className="field-hint">当前实例未提供额度调整能力（accounts.usage.adjust）；账本保持只读。</p>}
            </>}
        </> : null} />}
        {Adjust.data && <ActionFeedback Result={Adjust.data} />}
    </section>;
}
