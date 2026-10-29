import { expect, test } from '@playwright/test';

test('Worker 默认聚焦当前状态，累计数据按需展示', async ({ page }) => {
    await page.goto('/workers?source=demo');
    await page.getByRole('button', { name: /worker-01/ }).click();
    const Detail = page.getByRole('region', { name: 'Worker 详情', exact: true });
    await expect(Detail.getByRole('tab', { name: '趋势', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(Detail.getByText('命令邮箱', { exact: true })).toBeVisible();
    await expect(Detail.getByText('累计事件丢弃', { exact: true })).toBeHidden();
    await Detail.getByRole('tab', { name: '任务与派发', exact: true }).click();
    await expect(Detail.getByText('队列满', { exact: true })).toBeVisible();
    await Detail.getByRole('tab', { name: '关联连接', exact: false }).click();
    await expect(Detail.getByText('session-1001', { exact: true })).toBeVisible();
});

test('资源诊断默认收起，采样足够后显示真实曲线', async ({ page }) => {
    await page.goto('/resources?source=demo');
    await expect(page.getByText('等待下一次采样', { exact: false })).toBeVisible();
    await expect(page.getByRole('term').filter({ hasText: /^P95$/ })).toBeVisible();
    const Detail = page.locator('details').filter({ has: page.getByText('诊断明细', { exact: false }) });
    await expect(Detail).not.toHaveAttribute('open', '');
    await Detail.locator('summary').click();
    await expect(Detail).toHaveAttribute('open', '');
    await expect(page.getByText('近期识别准入样本', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '刷新快照' }).click();
    await expect(page.getByRole('group', { name: /资源采样/ })).toBeVisible();
});
