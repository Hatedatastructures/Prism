import { expect, test } from '@playwright/test';

test('概览显示端口、延迟覆盖与连接趋势，入口链接保留演示来源', async ({ page }) => {
    await page.goto('/?source=demo');
    await expect(page.getByRole('heading', { name: '监听端口' })).toBeVisible();
    await expect(page.getByText('Worker 延迟：未采集 · 内存分配延迟：未采集')).toBeVisible();
    await expect(page.getByRole('heading', { name: '连接活动' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: '顶部导航' })).toHaveCount(0);
    await page.getByRole('link', { name: /TCP.*就绪/ }).click();
    await expect(page).toHaveURL(/\/ingresses\?.*source=demo/);
});

test('切换侧栏后仍可访问页面', async ({ page }) => {
    await page.goto('/?source=demo');
    await page.getByRole('button', { name: '展开或收起导航' }).click();
    const Accounts = page.locator('[data-sidebar="sidebar"] a[href^="/accounts"]');
    await expect(Accounts).toBeVisible();
    await Accounts.click();
    await expect(page).toHaveURL(/\/accounts\?.*source=demo/);
});
