import { expect, test } from '@playwright/test';

test('各工作区在当前宽度下无整页横向溢出', async ({ page }) => {
    const Errors: string[] = [];
    page.on('pageerror', Error => Errors.push(Error.message));
    for (const Path of ['/', '/workers', '/accounts', '/user-groups', '/sessions', '/events', '/ingresses', '/protocols', '/resources', '/configuration', '/operations']) {
        await page.goto(`${Path}?source=demo`);
        await expect(page.locator('#main-content h1')).toBeVisible();
        const Overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
        expect(Overflow, `${Path} 整页横向溢出`).toBeLessThanOrEqual(1);
    }
    expect(Errors).toEqual([]);
});

test('工作区利用宽屏并保持表格和详情可读', async ({ page }) => {
    const Width = page.viewportSize()!.width;
    await page.goto('/sessions?source=demo');
    await expect(page.getByRole('heading', { name: 'Session 追踪' })).toBeVisible();
    const Main = page.locator('#main-content');
    const MainBounds = await Main.boundingBox();
    expect(MainBounds).not.toBeNull();
    if (Width >= 1920) expect(MainBounds!.width).toBeGreaterThan(Width - 310);
    const Overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(Overflow).toBeLessThanOrEqual(1);
    if (Width >= 1280) {
        const Table = page.getByRole('columnheader', { name: '累计流量' });
        await expect(Table).toBeInViewport();
        const Cell = await Table.boundingBox();
        const Inspector = await page.getByText('Process PRISM-DEMO-01 · Generation 42').boundingBox();
        expect(Cell).not.toBeNull();
        expect(Inspector).not.toBeNull();
        expect(Cell!.x + Cell!.width).toBeLessThan(Inspector!.x);
    }
});

test('宽屏概览的协议和 Worker 同行排列', async ({ page }) => {
    await page.goto('/?source=demo');
    const Protocol = page.getByText('协议配置与统计', { exact: true });
    const Worker = page.getByText('Worker 调度', { exact: true });
    await expect(Protocol).toBeVisible();
    await expect(Worker).toBeVisible();
    const Left = await Protocol.boundingBox(), Right = await Worker.boundingBox();
    expect(Left).not.toBeNull();
    expect(Right).not.toBeNull();
    if (page.viewportSize()!.width >= 1536) {
        expect(Math.abs(Left!.y - Right!.y)).toBeLessThan(3);
        expect(Right!.x).toBeGreaterThan(Left!.x);
    } else expect(Right!.y).toBeGreaterThan(Left!.y);
});
