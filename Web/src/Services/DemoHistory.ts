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
    const Coverage = Request.Metric === 'recognition_admission' ? '演示夹具 · 窗口延迟样本' : Request.Metric === 'active' ? `演示夹具 · ${Request.Scope === 'worker' ? '活动任务' : '活动量'}窗口` : '演示夹具 · 窗口有效载荷';
    return { SampledAt: Request.To, From: Request.From, To: Request.To, ResolutionMs: String(Step), Coverage, Gaps: [],
        Items: Array.from({ length: Count }, (_, Index) => {
            const Phase = Index / Count * Math.PI * 5;
            const P50 = 5000 + Math.round((Math.sin(Phase) + 1) * 2000);
            return { Time: new Date(Math.min(To, From + (Index + 1) * Step)).toISOString(),
                UpBytes: Request.Metric === 'recognition_admission' ? null : String(Math.round((400_000 + Math.sin(Phase + .8) * 180_000) * Step / 1000 * Multiplier)),
                DownBytes: Request.Metric === 'recognition_admission' ? null : String(Math.round((650_000 + Math.sin(Phase) * 240_000) * Step / 1000 * Multiplier)),
                Active: String(Math.max(0, Math.round((4 + Math.sin(Phase) * 2) * Multiplier))), P50Us: Request.Metric === 'recognition_admission' ? String(P50) : null,
                P95Us: Request.Metric === 'recognition_admission' ? String(P50 + 11000 + Math.round(Math.max(0, Math.sin(Phase + .2)) * 12000)) : null,
                P99Us: Request.Metric === 'recognition_admission' ? String(P50 + 29000) : null, SampleCount: Request.Metric === 'recognition_admission' ? '24' : '0', Quality: 'demo' };
        }) };
}
