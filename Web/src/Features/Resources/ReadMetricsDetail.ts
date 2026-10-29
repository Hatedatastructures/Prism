import type { AdminDataSource, BootstrapSnapshot, MetricsSnapshot } from '../../Services/AdminDataSource.ts';

/** @brief 指标接口独立核对采样前后实例，不把跨重启数据混入资源页面。 */
export async function ReadMetricsDetail(Source: Pick<AdminDataSource, 'GetBootstrap' | 'GetMetrics'>): Promise<Readonly<{ Metrics: MetricsSnapshot; Identity: BootstrapSnapshot }>> {
    const Before = await Source.GetBootstrap({ Fresh: true });
    if (!Before.Capabilities.includes('metrics.read')) throw new Error('当前实例没有开放 metrics.read。');
    const Metrics = await Source.GetMetrics();
    const After = await Source.GetBootstrap({ Fresh: true });
    if (Before.InstanceKey !== After.InstanceKey || Before.ProcessId !== After.ProcessId || Before.Incarnation !== After.Incarnation || Metrics.ProcessId !== After.ProcessId)
        throw new Error('读取指标时实例已变化，请重新读取。');
    return { Metrics, Identity: After };
}
