import { defineConfig } from '@playwright/test';

const Viewports = [{ width: 2265, height: 1244 }, { width: 1920, height: 1080 }, { width: 1440, height: 900 },
    { width: 1280, height: 800 }, { width: 768, height: 1024 }, { width: 390, height: 844 }];
/** @brief 使用已明确启动的服务，不自动启停或替换用户现有 Vite。 */
export default defineConfig({
    testDir: './e2e', outputDir: '../build/WebQa/Playwright', workers: 1,
    use: { baseURL: process.env.PRISM_WEB_URL ?? 'http://127.0.0.1:5173', trace: 'retain-on-failure', screenshot: 'only-on-failure' },
    reporter: [['list'], ['json', { outputFile: '../build/WebQa/playwright-results.json' }]],
    projects: Viewports.flatMap(viewport => [
        { name: `chromium-${viewport.width}`, use: { browserName: 'chromium' as const, viewport, deviceScaleFactor: 1 } },
        { name: `edge-${viewport.width}`, use: { browserName: 'chromium' as const, channel: 'msedge', viewport, deviceScaleFactor: 1 } },
    ]),
});
