import type { IngressRecord } from '../../Services/AdminDataSource.ts';

export type IngressRuntimeRow = Readonly<{
    Value: IngressRecord;
    HasRuntimeState: boolean;
}>;

export type IngressRowPresentation = Readonly<{
    Label: string;
    Tone: 'good' | 'neutral';
    Binding: string;
}>;

/** @brief 每种传输仅首条配置行代表当前 listener 的运行态快照。 */
export function PresentIngressRows(Rows: readonly IngressRecord[]): readonly IngressRuntimeRow[] {
    const SeenTransports = new Set<string>();
    return Rows.map(Value => {
        const Transport = Value.Transport.toLowerCase();
        const HasRuntimeState = !SeenTransports.has(Transport);
        SeenTransports.add(Transport);
        return { Value, HasRuntimeState };
    });
}

/** @brief 保留 listener 行的原始 ready 值，不为后续配置占位行制造故障状态。 */
export function DecideIngressRowPresentation(
    Row: IngressRecord,
    HasRuntimeState: boolean,
): IngressRowPresentation {
    if (Row.ExpectedState === 'draining') {
        return { Label: '计划排空', Tone: 'neutral', Binding: BindingOf(Row, HasRuntimeState) };
    }
    if (Row.ExpectedState === 'disabled') {
        return { Label: '已停用', Tone: 'neutral', Binding: BindingOf(Row, HasRuntimeState) };
    }
    return {
        Label: HasRuntimeState ? Row.Ready ? '运行态报告就绪' : '运行态报告未就绪' : '未单独观测',
        Tone: HasRuntimeState && Row.Ready ? 'good' : 'neutral',
        Binding: BindingOf(Row, HasRuntimeState),
    };
}

function BindingOf(Row: IngressRecord, HasRuntimeState: boolean): string {
    return Row.BoundAddress !== null ? `当前绑定 ${Row.BoundAddress}`
        : HasRuntimeState ? '当前无绑定地址' : '绑定状态未单独采集';
}
