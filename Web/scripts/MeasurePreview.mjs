/** @brief 测量本机预览的加载与布局基线；不把开发服务指标视为生产验收。 */
import { chromium } from '@playwright/test';
import { mkdir, writeFile } from 'node:fs/promises';

const Base = new URL(process.env.PRISM_WEB_URL ?? 'http://127.0.0.1:5173');
if (Base.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(Base.hostname))
    throw new Error('此测量仅接受已启动的本机 HTTP 预览。');

const Browser = await chromium.launch(process.platform === 'win32' ? { channel: 'msedge' } : {});
const Samples = [];
try {
    for (const Route of ['/', '/accounts', '/configuration']) {
        const Context = await Browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
        const Page = await Context.newPage();
        await Page.addInitScript(() => {
            const Metrics = { LcpCandidateMs: null, LayoutShiftSum: null, LongTaskCount: null };
            window.PrismPreviewMetrics = Metrics;
            if (PerformanceObserver.supportedEntryTypes.includes('largest-contentful-paint'))
                new PerformanceObserver(List => { Metrics.LcpCandidateMs = List.getEntries().at(-1)?.startTime ?? null; })
                    .observe({ type: 'largest-contentful-paint', buffered: true });
            if (PerformanceObserver.supportedEntryTypes.includes('layout-shift')) {
                Metrics.LayoutShiftSum = 0;
                new PerformanceObserver(List => {
                    for (const Entry of List.getEntries()) if (!Entry.hadRecentInput) Metrics.LayoutShiftSum += Entry.value;
                }).observe({ type: 'layout-shift', buffered: true });
            }
            if (PerformanceObserver.supportedEntryTypes.includes('longtask')) {
                Metrics.LongTaskCount = 0;
                new PerformanceObserver(List => { Metrics.LongTaskCount += List.getEntries().length; })
                    .observe({ type: 'longtask', buffered: true });
            }
        });
        await Page.goto(new URL(`${Route}?source=demo`, Base).href, { waitUntil: 'networkidle' });
        await Page.locator('main h1').waitFor({ state: 'visible' });
        await Page.evaluate(async () => {
            await document.fonts.ready;
            await new Promise(Resolve => requestAnimationFrame(() => requestAnimationFrame(Resolve)));
        });
        const Sample = await Page.evaluate(() => ({
            ...window.PrismPreviewMetrics,
            DevelopmentServer: Array.from(document.scripts).some(Script => Script.src.includes('/@vite/client')),
            Resources: performance.getEntriesByType('resource').length,
            TransferBytes: performance.getEntriesByType('resource').reduce((Total, Entry) => Total + Entry.transferSize, 0),
        }));
        Samples.push({ Route, ...Sample });
        await Context.close();
    }
} finally {
    await Browser.close();
}

const Report = { CapturedAt: new Date().toISOString(), BaseUrl: Base.href, Viewport: '1440x900 @1x',
    Cache: 'fresh browser context per route', Data: 'explicit demo', RunsPerRoute: 1,
    Boundary: '本机单次加载观察。LCP 为截止时候选；LayoutShiftSum 是无近期输入的位移总和，并非会话窗口 CLS。未测真实用户 INP 或第 75 百分位，不构成生产性能验收。', Samples };
const Directory = new URL('../../build/WebQa/', import.meta.url);
await mkdir(Directory, { recursive: true });
await writeFile(new URL('preview-performance.json', Directory), JSON.stringify(Report, null, 2));
console.log(JSON.stringify(Report, null, 2));
