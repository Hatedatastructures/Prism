import { expect, test } from '@playwright/test';

test('宽屏工作区展示完整清单和选中对象的详细数据', async ({ page }) => {
    for (const Case of [
        { Path: '/ingresses', Title: '监听清单', Column: '实际绑定' },
        { Path: '/workers', Title: 'Worker 清单', Column: '事件丢弃' },
        { Path: '/accounts', Title: '账户目录', Column: '当前速率 ↑ / ↓' },
    ]) {
        await page.goto(`${Case.Path}?source=demo`);
        const Card = page.locator('[data-slot="card"]').filter({ has: page.getByText(Case.Title, { exact: true }) });
        await expect(Card).toBeVisible();
        await expect(Card.getByRole('columnheader', { name: Case.Column, exact: true })).toBeVisible();
        const Bounds = await Card.boundingBox();
        const Main = await page.locator('#main-content').boundingBox();
        expect(Bounds).not.toBeNull();
        expect(Main).not.toBeNull();
        expect(Bounds!.width).toBeGreaterThan(Main!.width * 0.9);
    }
    await page.goto('/workers?source=demo');
    await page.getByRole('button', { name: /worker-02/ }).click();
    await expect(page.getByText('worker-02', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('Process PRISM-DEMO-01 · Generation 42', { exact: true })).toBeVisible();
});
