import type { Tone } from '../../Components/Ui';
import type { OperationRecord } from '../../Services/AdminDataSource';

type Presentation = Readonly<{ Label: string; Tone: Tone }>;

/** @brief 操作进度与结果的唯一呈现映射；只有完成状态表示成功。 */
const Presentations: Readonly<Record<OperationRecord['State'], Presentation>> = {
    accepted: { Label: '已接收', Tone: 'neutral' },
    running: { Label: '等待终态', Tone: 'neutral' },
    completed: { Label: '已完成', Tone: 'good' },
    rejected: { Label: '已拒绝', Tone: 'danger' },
    unavailable: { Label: '不可用', Tone: 'warning' },
    failed: { Label: '失败', Tone: 'danger' },
    timed_out: { Label: '超时', Tone: 'warning' },
    blocked: { Label: '受阻', Tone: 'warning' },
    restart_required: { Label: '需重启', Tone: 'warning' },
    conflict: { Label: '版本冲突', Tone: 'warning' },
    invalid: { Label: '无效请求', Tone: 'danger' },
    unknown: { Label: '结果未知', Tone: 'neutral' },
    interrupted: { Label: '中断待核对', Tone: 'warning' },
};

/** @brief 按原始状态选择文案和颜色，不根据翻译文本推断执行结果。 */
export function OperationPresentation(State: OperationRecord['State']): Presentation {
    return Presentations[State];
}
