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
    await expect(page.getByRole('heading', { name: '连接', exact: true })).toBeVisible();
    const SessionTable = page.getByRole('table', { name: 'Session 列表', exact: true });
    await SessionTable.getByRole('button', { name: 'session-1001', exact: true }).click();
    const Main = page.locator('#main-content');
    const MainBounds = await Main.boundingBox();
    expect(MainBounds).not.toBeNull();
    if (Width >= 1920) expect(MainBounds!.width).toBeGreaterThan(Width - 310);
    const Overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(Overflow).toBeLessThanOrEqual(1);
    if (Width >= 1280) {
        const Table = SessionTable.getByRole('columnheader', { name: '累计上行', exact: true });
        await expect(Table).toBeInViewport();
        const Cell = await Table.boundingBox();
        const Inspector = await page.getByRole('region', { name: 'Session session-1001 详情', exact: true })
            .getByText('Process PRISM-DEMO-01 · Generation 42').boundingBox();
        expect(Cell).not.toBeNull();
        expect(Inspector).not.toBeNull();
        expect(Cell!.x + Cell!.width).toBeLessThan(Inspector!.x);
    }
});

test('宽屏概览按入口调度与账户协议分区排列', async ({ page }) => {
    await page.goto('/?source=demo');
    const Protocol = page.getByText('协议使用', { exact: true });
    const Worker = page.getByText('Worker 调度', { exact: true });
    const Ingress = page.getByText('监听端口', { exact: true });
    const Account = page.getByText('账户使用', { exact: true });
    await expect(Protocol).toBeVisible();
    await expect(Worker).toBeVisible();
    await expect(Ingress).toBeVisible();
    await expect(Account).toBeVisible();
    const ProtocolBounds = await Protocol.boundingBox(), WorkerBounds = await Worker.boundingBox();
    const IngressBounds = await Ingress.boundingBox(), AccountBounds = await Account.boundingBox();
    expect(ProtocolBounds).not.toBeNull();
    expect(WorkerBounds).not.toBeNull();
    expect(IngressBounds).not.toBeNull();
    expect(AccountBounds).not.toBeNull();
    if (page.viewportSize()!.width >= 1280) {
        expect(Math.abs(IngressBounds!.y - WorkerBounds!.y)).toBeLessThan(3);
        expect(Math.abs(AccountBounds!.y - ProtocolBounds!.y)).toBeLessThan(3);
        expect(WorkerBounds!.y).toBeLessThan(AccountBounds!.y);
    } else {
        expect(WorkerBounds!.y).toBeGreaterThan(IngressBounds!.y);
        expect(ProtocolBounds!.y).toBeGreaterThan(AccountBounds!.y);
    }
});
