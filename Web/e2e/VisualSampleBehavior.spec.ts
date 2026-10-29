import { expect, test } from '@playwright/test';

test('Worker 默认聚焦当前状态，累计数据按需展示', async ({ page }) => {
    await page.goto('/workers?source=demo');
    await expect(page.getByRole('tab', { name: '概览', exact: true })).toHaveAttribute('aria-selected', 'true');
    await expect(page.getByText('命令邮箱', { exact: true }).last()).toBeVisible();
    await expect(page.getByText('拒绝合计', { exact: true })).toBeHidden();
    await page.getByRole('tab', { name: '任务与派发', exact: true }).click();
    await expect(page.getByText('拒绝合计', { exact: true })).toBeVisible();
    await page.getByRole('tab', { name: '关联 Session', exact: true }).click();
    await expect(page.getByText('session-1001', { exact: true }).last()).toBeVisible();
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
