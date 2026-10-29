import { expect, test } from '@playwright/test';

test('首页保留趋势区并将连接活动放在入口之前', async ({ page }) => {
    await page.goto('/?source=demo');
    const Trends = page.getByRole('region', { name: '运行趋势' });
    const Connections = page.getByRole('heading', { name: '连接活动' });
    const Ingress = page.getByRole('heading', { name: '监听端口' });
    await expect(Trends).toBeVisible();
    await expect(Connections).toBeVisible();
    expect((await Trends.boundingBox())!.y).toBeLessThan((await Connections.boundingBox())!.y);
    expect((await Connections.boundingBox())!.y).toBeLessThan((await Ingress.boundingBox())!.y);
});

test('入口详情随选择更新，缺测连接不作为完整总数', async ({ page }) => {
    await page.goto('/ingresses?source=demo');
    await expect(page.getByText('仅 1 / 3 个监听提供连接数')).toBeVisible();
    await expect(page.locator('[data-slot=card-title]', { hasText: 'tcp-main' })).toBeVisible();
    await page.getByRole('button', { name: /UDP udp-main/ }).click();
    await expect(page.locator('[data-slot=card-title]', { hasText: 'udp-main' })).toBeVisible();
    await expect(page).toHaveURL(/ingress=udp-main/);
});

test('协议清单的选择更新详情并保留数据源上下文', async ({ page }) => {
    await page.goto('/protocols?source=demo');
    await page.getByRole('button', { name: /VLESS vless/ }).click();
    const Inspector = page.locator('[data-slot=card]').filter({ has: page.getByRole('link', { name: '查看关联 Session' }) });
    await expect(Inspector.getByText('VLESS', { exact: true })).toBeVisible();
    await expect(Inspector.getByText('TCP Session 可关联；QUIC admission 未关联')).toBeVisible();
    await Inspector.getByRole('link', { name: '查看关联 Session' }).click();
    await expect(page).toHaveURL(/sessions\?.*source=demo/);
    await expect(page).toHaveURL(/protocol=VLESS/);
});

test('账户与 Worker 详情提供关联会话入口', async ({ page }) => {
    await page.goto('/accounts?source=demo');
    await expect(page.getByText('已载入 2 条关联会话', { exact: true })).toBeVisible();
    await page.getByRole('link', { name: '查看会话', exact: true }).click();
    await expect(page).toHaveURL(/sessions\?.*account=acct-northstar/);
    await expect(page).toHaveURL(/source=demo/);
    await page.goto('/workers?source=demo');
    await expect(page.getByText(/已载入 \d+ 条关联会话/)).toBeVisible();
    await page.getByRole('link', { name: '查看会话', exact: true }).click();
    await expect(page).toHaveURL(/sessions\?.*worker=worker-01/);
    await expect(page).toHaveURL(/source=demo/);
});

test('配置长文档在编辑器内滚动并保持可编辑', async ({ page }) => {
    await page.goto('/configuration?source=demo');
    const Editor = page.getByRole('textbox', { name: '配置 JSON', exact: true });
    await expect(Editor).toBeVisible();
    await expect.poll(() => Editor.inputValue()).toContain('WorkerCount');
    const Dimensions = await Editor.evaluate(Element => ({ height: Element.clientHeight, scrollHeight: Element.scrollHeight }));
    expect(Dimensions.scrollHeight).toBeGreaterThan(Dimensions.height);
    expect(Dimensions.height).toBeLessThan(700);
    const Original = await Editor.inputValue();
    await Editor.fill(Original.replace('"WorkerCount": 4', '"WorkerCount": 5'));
    await expect(page.getByText('未保存草稿', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '应用配置', exact: true })).toBeDisabled();
});

test('Session 详情的连接路径随所选记录更新', async ({ page }) => {
    await page.goto('/sessions?source=demo');
    const Path = page.getByRole('region', { name: '连接路径' });
    await expect(Path).toContainText('VLESS');
    await expect(Path).toContainText('203.0.113.18:443');
    await page.getByRole('button', { name: 'session-1002' }).click();
    await expect(Path).toContainText('Trojan');
    await expect(Path).toContainText('192.0.2.41:8443');
});

test('组内搜索只筛选当前组成员', async ({ page }) => {
    await page.goto('/user-groups?source=demo');
    const Search = page.getByRole('textbox', { name: '搜索组内账户' });
    await Search.fill('not-a-member');
    await expect(page.getByText('当前范围没有成员')).toBeVisible();
    await Search.clear();
    await expect(page.getByRole('link', { name: 'northstar', exact: true })).toBeVisible();
});

test('资源分配范围按 Worker 展开并保留说明', async ({ page }) => {
    await page.goto('/resources?source=demo');
    const Range = page.getByText('查看范围', { exact: true }).first();
    await Range.click();
    await expect(Range.locator('..')).toContainText('WorkerResources');
});
