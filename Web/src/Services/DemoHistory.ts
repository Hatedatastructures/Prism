import type { HistoryRequest, HistorySnapshot } from './AdminDataSource.ts';

/** @brief 仅由显式演示模式调用的确定性窗口夹具，不参与真实请求或故障回退。 */
export function DemoHistory(Request: HistoryRequest): HistorySnapshot {
    const From = Date.parse(Request.From), To = Date.parse(Request.To);
    const Window = To - From;
    const Resolution = Window <= 900_000 ? 10_000 : Window <= 86_400_000 ? 60_000 : 900_000;
    const Count = Math.min(Request.MaxPoints ?? 1200, Math.max(2, Math.ceil(Window / Resolution)));
    const Step = Math.max(Resolution, Math.ceil(Window / Count));
    const Seed = [...`${Request.Scope}:${Request.Key}`].reduce((Sum, Character) => Sum + Character.charCodeAt(0), 0);
    const Multiplier = Request.Scope === 'process' ? 1 : .2 + Seed % 5 / 10;
    const LatencyMetric = Request.Metric === 'recognition_admission' || Request.Metric === 'dns_resolution' || Request.Metric === 'tcp_connect';
    const MetricLabel = Request.Metric === 'dns_resolution' ? 'DNS 解析' : Request.Metric === 'tcp_connect' ? 'TCP 建连' : '识别准入';
    const Coverage = LatencyMetric ? `演示夹具 · ${MetricLabel}窗口延迟样本` : '演示夹具 · 窗口有效载荷';
    return { SampledAt: Request.To, From: Request.From, To: Request.To, ResolutionMs: String(Step), Coverage, Gaps: [],
        Items: Array.from({ length: Count }, (_, Index) => {
            const Phase = Index / Count;
            const Burst = Index > 0 && Index % 47 >= 41 ? Math.sin((Index % 47 - 41) / 6 * Math.PI) * .34 : 0;
            const Noise = DeterministicNoise(Seed + Index * 17) - .5;
            const UpRate = Math.max(48_000, 365_000 + 112_000 * Math.sin(Phase * Math.PI * 3.1 + .35)
                + 46_000 * Noise + 155_000 * Burst);
            const DownRate = Math.max(72_000, 585_000 + 148_000 * Math.sin(Phase * Math.PI * 2.45 + 1.1)
                + 68_000 * (DeterministicNoise(Seed + 911 + Index * 31) - .5) + 245_000 * Burst);
            const P50 = Math.max(3_200, Math.round(5_400 + 900 * Math.sin(Phase * Math.PI * 2.2)
                + 540 * Noise + 920 * Burst));
            return { Time: new Date(Math.min(To, From + (Index + 1) * Step)).toISOString(),
                UpBytes: LatencyMetric ? null : String(Math.round(UpRate * Step / 1000 * Multiplier)),
                DownBytes: LatencyMetric ? null : String(Math.round(DownRate * Step / 1000 * Multiplier)),
                Active: null,
                P50Us: LatencyMetric ? String(P50) : null,
                P95Us: LatencyMetric ? String(P50 + 9_200 + Math.round(8_500 * Burst
                    + 2_600 * DeterministicNoise(Seed + 67 + Index * 11))) : null,
                P99Us: LatencyMetric ? String(P50 + 22_000 + Math.round(14_000 * Burst)) : null,
                SampleCount: LatencyMetric ? '24' : '0', Quality: 'demo' };
        }) };
}

/** @brief 固定种子的低成本噪声，保持演示可复现，不引入随机源或外部依赖。 */
function DeterministicNoise(Seed: number): number {
    const Value = Math.sin(Seed * 12.9898) * 43_758.5453;
    return Value - Math.floor(Value);
}
