import { TimeLink as Link } from './TimeLink';
import { useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { useQueryClient } from '@tanstack/react-query';

import { ConfirmAction } from '../Components/ConfirmAction';
import { FormatCount, FormatBytes, FormatRate } from '../Components/Ui';
import { ChangeConfiguration } from '../Api/ConfigurationMutations';
import { ParseJsonDocument } from '../Api/JsonDocument';
import { useAdminMutation, useAdminQuery, useAdminServices, useBootstrapIdentity } from './UseOperations';
import type { EffectivePolicy } from '../Services/AdminDataSource';

/** @brief 策略只经配置事务发布，编辑前固定读取基线，避免页面维护另一套运行策略。 */
export function PolicyEditor(Input: Readonly<{ Kind: 'account-policy' | 'group-policy'; Id: string; Title: string; Effective?: EffectivePolicy | null; Sources?: Readonly<Record<string, string>> }>): ReactNode {
    const [Open, SetOpen] = useState(false), [Text, SetText] = useState(''), [Baseline, SetBaseline] = useState<{ Text: string; Generation: string } | null>(null);
    const [Message, SetMessage] = useState('');
    const QueryClient = useQueryClient();
    const Services = useAdminServices();
    const Bootstrap = useBootstrapIdentity();
    const CanEdit = Bootstrap.data?.Capabilities.includes('accounts.policy.write') ?? false;
    const Configuration = useAdminQuery('policy-configuration', Source => Source.GetConfiguration(), { Enabled: Open, Scope: [Input.Kind, Input.Id] });
    useEffect(() => { SetBaseline(null); SetText(''); SetMessage(''); }, [Input.Id]);
    useEffect(() => {
        if (!Open || !Configuration.data || Baseline) return;
        const Parsed = ParseJsonDocument({ Text: Configuration.data.Text, MaxBytes: 256 * 1024 });
        if (!Parsed.Ok || Parsed.Value.Kind !== 'object') return;
        const Items = Parsed.Value.Members.get(Input.Kind === 'account-policy' ? 'Accounts' : 'AccountGroups');
        if (Items?.Kind !== 'array') return;
        const Target = Items.Elements.find(Value => Value.Kind === 'object' && Value.Members.get('Id')?.Raw === JSON.stringify(Input.Id));
        if (!Target || Target.Kind !== 'object') { SetMessage('目标配置项不存在'); return; }
        SetBaseline(Configuration.data);
        SetText(Target.Members.get('Policy')?.Raw ?? '{}');
    }, [Configuration.data, Open, Baseline, Input.Id, Input.Kind]);
    const Mutation = useAdminMutation(async (Source, _Unused: void) => {
        if (!Baseline) throw new Error('请先读取策略配置基线');
        const Parsed = ParseJsonDocument({ Text, MaxBytes: 16 * 1024 });
        if (!Parsed.Ok || Parsed.Value.Kind !== 'object') throw new Error('策略必须是有效 JSON 对象');
        const Draft = ChangeConfiguration(Baseline.Text, { Kind: Input.Kind, Id: Input.Id, Policy: Parsed.Value.Raw });
        const Validation = await Source.ValidateConfiguration(Draft, Baseline.Generation);
        if (!Validation.Valid) throw new Error(Validation.Issues.join('；'));
        const Result = await Source.ApplyConfiguration(Draft, true, Baseline.Generation);
        SetMessage(Result.Message);
        if (Result.Status === 'completed') { SetBaseline(null); SetOpen(false); await QueryClient.invalidateQueries({ queryKey: ['operations'] }); }
        return Result;
    });
    return <section className="policy-section"><h3>{Input.Title}</h3>
        {Input.Effective ? <dl className="detail-kv">{Object.entries(Input.Effective).map(([Key, Value]) => <div key={Key}><dt>{PolicyLabel(Key)}<small>{Input.Sources?.[Key] ? ` · ${PolicySource(Input.Sources[Key])}` : ''}</small></dt>
            <dd>{PolicyValue(Key, Value)}</dd></div>)}</dl>
            : <p className="field-hint">有效策略尚未由管理快照提供；不会把默认值当成实际限制。</p>}
        {CanEdit ? <button className="button button-secondary" type="button" onClick={() => SetOpen(!Open)}>{Open ? '收起策略编辑' : '编辑配置策略'}</button>
            : <p className="field-hint">{Services.Mode === 'demo' ? '演示夹具展示策略层级；' : ''}当前实例尚未开放策略编辑合同。<Link className="text-link" to="/configuration">查看配置</Link></p>}
        {Open && <div className="policy-editor"><p className="field-hint">未设置字段继承组默认；显式不限与零额度分别表达。修改由服务端按正式策略结构校验。</p>
            {Configuration.error && <div className="notice notice-danger">{Configuration.error.message}</div>}
            <label className="field-label">Policy JSON<textarea className="field-input policy-json" spellCheck={false} value={Text} onChange={Event => SetText(Event.target.value)} /></label>
            <p className="field-hint">配置基线 Generation {Baseline?.Generation ?? '读取中'}</p>
            <ConfirmAction Label="校验并发布策略" Title="发布这份资源策略？" Description="通过配置事务校验、应用并保存。新限速影响后续传输授权；降低并发只限制新增。"
                ConfirmLabel="确认发布" Disabled={!Baseline || !Text.trim()} Busy={Mutation.isPending} OnConfirm={() => Mutation.mutateAsync()} />
        </div>}
        {Message && <div className="notice notice-info" role="status">{Message}<Link to="/operations">核对结果</Link></div>}
    </section>;
}
function PolicyLabel(Key: string): string {
    const Labels: Readonly<Record<string, string>> = { max_connections: '根连接上限', max_streams: '子流上限', limit_bytes: '周期额度 / B', upload_bytes_per_second: '上行带宽 / B/s', download_bytes_per_second: '下行带宽 / B/s', admission_limit: '准入次数', cycle: '周期', utc_offset_minutes: '时区偏移 / 分钟' };
    return Labels[Key] ?? Key;
}
function PolicySource(Value: string): string { return Value === 'account' || Value === 'Account' ? '账户覆盖' : Value.startsWith('group') || Value === 'Group' ? '组默认' : Value === 'system' || Value === 'System' ? '系统默认' : '配置策略'; }
function PolicyValue(Key: string, Value: unknown): string {
    if (Value === null) return '不限';
    if (Key === 'utc_offset_minutes' || Key === 'offset_minutes') {
        const Offset = Number(Value); if (!Number.isInteger(Offset)) return '时区未提供';
        return `UTC${Offset < 0 ? '-' : '+'}${String(Math.floor(Math.abs(Offset) / 60)).padStart(2, '0')}:${String(Math.abs(Offset) % 60).padStart(2, '0')}`;
    }
    if (Key === 'cycle') {
        const Cycles: Record<string, string> = { month: '自然月', week: '自然周', day: '自然日', none: '不重置', Month: '自然月', Week: '自然周', Day: '自然日', None: '不重置' };
        if (typeof Value === 'string') return Cycles[Value] ?? Value;
        if (Value && typeof Value === 'object' && 'kind' in Value) return `${Cycles[String(Value.kind)] ?? '周期'}${'offset_minutes' in Value ? ` · ${PolicyValue('offset_minutes', Value.offset_minutes)}` : ''}`;
    }
    if (typeof Value === 'string' && /^\d+$/.test(Value)) {
        if (Key.includes('bytes_per_second')) return FormatRate(Value);
        if (Key.includes('bytes')) return FormatBytes(Value);
        return `${FormatCount(Value)}${Key.includes('admission') ? ' 次/s' : ' 个'}`;
    }
    return typeof Value === 'object' ? '已配置' : String(Value);
}
