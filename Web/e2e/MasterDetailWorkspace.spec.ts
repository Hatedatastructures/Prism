import { expect, test } from '@playwright/test';

test('账户目录保留选择、详情和撤销确认', async ({ page }, info) => {
    await page.goto('/accounts?source=demo');
    const Directory = page.getByRole('list', { name: '账户列表' });
    await expect(Directory).toBeVisible();
    await Directory.getByRole('button', { name: /blue-hour/ }).click();
    await expect(page).toHaveURL(/account=acct-blue-hour/);
    await expect(page.getByText('acct-blue-hour · Generation 42', { exact: true })).toBeVisible();
    await expect(page.getByText('累计上行', { exact: true })).toBeVisible();
    await page.getByRole('button', { name: '撤销账户' }).click();
    await expect(page.getByRole('dialog', { name: /撤销 blue-hour/ })).toBeVisible();
    await page.getByRole('button', { name: '取消', exact: true }).click();
    if (info.project.use.viewport && info.project.use.viewport.width < 768) {
        await page.getByRole('button', { name: '返回账户目录' }).click();
        await expect(Directory).toBeVisible();
    }
});

test('Worker 选择保持完整实例身份和操作确认', async ({ page }) => {
    await page.goto('/workers?source=demo');
    await page.getByRole('button', { name: /worker-02/ }).click();
    await expect(page).toHaveURL(/worker=worker-02/);
    await page.getByRole('button', { name: '查看 Worker 实例身份' }).click();
    await expect(page.getByText('Process PRISM-DEMO-01 · Generation 42 · Worker worker-02', { exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.getByRole('columnheader', { name: '事件丢弃' })).toBeVisible();
    await page.getByRole('button', { name: '排空 Worker' }).click();
    await expect(page.getByRole('dialog')).toContainText('Process PRISM-DEMO-01 · Generation 42 · Worker worker-02');
    await page.getByRole('button', { name: '取消', exact: true }).click();
});

test('入口、协议、用户组和 Session 展示选中对象的真实范围', async ({ page }) => {
    await page.goto('/ingresses?source=demo');
    await expect(page.getByRole('columnheader', { name: '配置监听' })).toBeVisible();
    await expect(page.getByRole('columnheader', { name: '实际绑定' })).toBeVisible();
    await page.getByRole('button', { name: /UDP/ }).click();
    await expect(page.getByText('udp-main', { exact: true }).last()).toBeVisible();

    await page.goto('/protocols?source=demo');
    await page.getByRole('button', { name: /VLESS/ }).click();
    await page.getByText('查看选中协议的覆盖与延迟', { exact: false }).click();
    await expect(page.getByText('TCP Session 可关联；QUIC admission 未关联').last()).toBeVisible();

    await page.goto('/user-groups?source=demo');
    await page.getByRole('button', { name: /标准用户/ }).click();
    await expect(page.getByText('Group ID · group-standard')).toBeVisible();

    await page.goto('/sessions?source=demo');
    await expect(page.getByRole('textbox', { name: '搜索 Session' })).toBeVisible();
    await page.getByRole('button', { name: 'session-1002' }).click();
    await expect(page.getByText('session-1002', { exact: true }).last()).toBeVisible();
    await expect(page.getByLabel('连接路径')).toContainText('192.0.2.41:8443');
});
