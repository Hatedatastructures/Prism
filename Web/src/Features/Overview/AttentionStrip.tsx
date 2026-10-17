import { TimeLink as Link } from '../TimeLink';
import type { ReactNode } from 'react';
import { ArrowRight, CircleAlert, CircleCheck } from 'lucide-react';

import type { IngressRecord, WorkerRecord } from '../../Services/AdminDataSource';

/** @brief 当前资源状态与历史告警分开展示；未知或缺失记录不被计作健康。 */
export function AttentionStrip(Input: Readonly<{
    Ingresses: readonly IngressRecord[]; Workers: readonly WorkerRecord[]; State: 'ready' | 'loading' | 'unavailable';
}>): ReactNode {
    const Entries = [
        ...Input.Ingresses.filter(Value => !Value.Ready).map(Value => ({ Id: Value.Id,
            Label: `${Value.Transport.toUpperCase()} 未就绪`, Path: `/ingresses?ingress=${encodeURIComponent(Value.Id)}` })),
        ...Input.Workers.filter(Value => !Value.Accepting).map(Value => ({ Id: Value.Id,
            Label: `${Value.Id} ${Value.State === 'draining' ? '排空中' : Value.Running ? '暂停接收' : '已停止'}`,
            Path: `/workers?worker=${encodeURIComponent(Value.Id)}` })),
    ];
    if (Input.State !== 'ready') return <div className="attention-strip attention-pending" role="status">
        {Input.State === 'loading' ? '正在获取入口与 Worker 状态…' : '资源状态暂时无法载入，请检查数据源后重试。'}</div>;
    if (Input.Ingresses.length + Input.Workers.length === 0) return <div className="attention-strip attention-pending">暂无入口与 Worker 数据</div>;
    if (Entries.length === 0) return <div className="attention-strip attention-clear"><CircleCheck size={16} aria-hidden="true" />
        <strong>已载入资源均可接收</strong><span>入口就绪，Worker 正常接收</span></div>;
    return <section className="attention-strip" aria-label="需要关注的当前资源">
        <span className="attention-title"><CircleAlert size={16} aria-hidden="true" /><strong>需要关注 {Entries.length} 项</strong></span>
        <div>{Entries.map(Entry => <Link to={Entry.Path} key={Entry.Id}>{Entry.Label}<ArrowRight size={13} aria-hidden="true" /></Link>)}</div>
    </section>;
}
