import { expect, test } from '@playwright/test';

test('宽屏工作区展示完整清单和选中对象的详细数据', async ({ page }) => {
    for (const Case of [
        { Path: '/ingresses', Title: '监听清单', Column: '实际绑定地址' },
        { Path: '/workers', Title: 'Worker 清单', Column: '命令失败' },
        { Path: '/accounts', Title: '账户目录', Column: '累计上行' },
    ]) {
        await page.goto(`${Case.Path}?source=demo`);
        const Card = page.locator('[data-slot="card"]').filter({ has: page.getByText(Case.Title, { exact: true }) });
        await expect(Card).toBeVisible();
        if (Case.Path === '/accounts') {
            await expect(Card.getByRole('list')).toBeVisible();
            await Card.getByRole('button', { name: /northstar/ }).click();
            await expect(page.getByRole('region', { name: '账户详情', exact: true })).toContainText('northstar');
        } else {
            await expect(Card.getByRole('columnheader', { name: Case.Column, exact: true })).toBeVisible();
        }
        if (Case.Path !== '/accounts') {
            const Bounds = await Card.boundingBox();
            const Main = await page.locator('#main-content').boundingBox();
            expect(Bounds).not.toBeNull();
            expect(Main).not.toBeNull();
            const Ratio = (page.viewportSize()?.width ?? 0) <= 767 ? 0.85 : 0.9;
            expect(Bounds!.width).toBeGreaterThan(Main!.width * Ratio);
        }
    }
    await page.goto('/workers?source=demo');
    await page.getByRole('button', { name: /worker-02/ }).click();
    await expect(page.getByText('worker-02', { exact: true }).last()).toBeVisible();
    await page.getByRole('button', { name: '查看 Worker 实例身份', exact: true }).click();
    await expect(page.getByText('Process PRISM-DEMO-01 · Generation 42 · Worker worker-02', { exact: true })).toBeVisible();
});
