import { expect, test } from '@playwright/test';

const Pages = [ ['/', '运行概览'], ['/workers', 'Worker'], ['/accounts', '代理账户'], ['/user-groups', '用户组'],
    ['/sessions', 'Session 追踪'], ['/events', '事件流'], ['/ingresses', '代理入口'], ['/protocols', '协议分析'],
    ['/resources', '资源与数据质量'], ['/configuration', '配置'], ['/operations', '操作中心'] ] as const;
test('所有工作区可渲染，字号与滚动范围符合合同', async ({ page }, TestInfo) => {
    const Errors: string[] = [];
    const ConsoleErrors: string[] = [];
    const FailedRequests: string[] = [];
    const TableMeasurements: Array<Readonly<{ Page: string; Cells: readonly Readonly<{ Text: string | undefined; Size: number }>[] }>> = [];
    page.on('pageerror', ErrorValue => Errors.push(ErrorValue.message));
    page.on('console', Message => { if (Message.type() === 'error') ConsoleErrors.push(Message.text()); });
    page.on('requestfailed', Request => FailedRequests.push(`${Request.method()} ${Request.url()}: ${Request.failure()?.errorText ?? 'failed'}`));
    for (const [Path, Name] of Pages) {
        await page.goto(`${Path}?source=demo`);
        await expect(page.locator('main h1')).toHaveText(Name);
        await expect(page.locator('.source-banner')).toContainText('演示预览');
        await expect(page.getByText('页面显示异常', { exact: true })).toHaveCount(0);
        await expect(page.locator('.page-loading')).toHaveCount(0);
        await page.evaluate(() => document.fonts.ready);
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)).toBe(true);
        const Body = await page.locator('body').evaluate(Element => ({ Font: getComputedStyle(Element).fontFamily, Size: parseFloat(getComputedStyle(Element).fontSize) }));
        expect(Body.Font).toContain('Noto Sans SC'); expect(Body.Size).toBeGreaterThanOrEqual(16);
        const CellSizes = await page.locator('main table tbody td').evaluateAll(Elements => Elements.map(Element => ({
            Text: Element.textContent?.trim(), Size: parseFloat(getComputedStyle(Element).fontSize),
        })));
        expect(CellSizes.every(Cell => Cell.Size >= 15), `${Path} table cell computed sizes: ${JSON.stringify(CellSizes)}`).toBe(true);
        if (Path === '/ingresses') {
            expect(CellSizes, 'Ingress fixture must expose all 18 body cells to verify the shared table size.').toHaveLength(18);
            expect(CellSizes.map(Cell => Cell.Size), 'Ingress table body cells must use the shared 15px text size.').toEqual(Array(18).fill(15));
        }
        TableMeasurements.push({ Page: Path, Cells: CellSizes });
        if (Path === '/ingresses' && TestInfo.project.name === 'chromium-2265')
            await page.screenshot({ path: TestInfo.outputPath('ingresses-2265.png'), fullPage: true });
    }
    expect(Errors).toEqual([]);
    expect(ConsoleErrors).toEqual([]);
    expect(FailedRequests).toEqual([]);
    await TestInfo.attach('rendered-table-cell-font-sizes.json', {
        body: Buffer.from(JSON.stringify({ Viewport: page.viewportSize(), TableMeasurements, ConsoleErrors, FailedRequests, PageErrors: Errors }, null, 2), 'utf8'),
        contentType: 'application/json',
    });
});
test('概览采用真实任务分区，事件不会推迟账户区域', async ({ page }) => {
    await page.goto('/?source=demo');
    await expect(page.locator('.overview-account-v2')).toBeVisible();
    await expect(page.locator('.overview-traffic-v2 .history-plot')).toBeVisible();
    await expect(page.locator('.overview-latency-v2 .history-plot')).toBeVisible();
    const Width = await page.evaluate(() => innerWidth);
    if (Width >= 1800) {
        const Worker = await page.locator('.overview-worker-v2').boundingBox(), Account = await page.locator('.overview-account-v2').boundingBox();
        expect(Worker).not.toBeNull(); expect(Account).not.toBeNull();
        expect(Account!.y - (Worker!.y + Worker!.height)).toBeLessThan(80);
    }
    if (Width < 1200) {
        const Columns = await page.locator('.overview-grid-v2').evaluate(Element => getComputedStyle(Element).gridTemplateColumns.split(' ').length);
        expect(Columns).toBe(Width < 768 ? 1 : 2);
    }
    if (Width < 768) {
        const Grid = await page.locator('.overview-grid-v2').boundingBox();
        expect(Grid).not.toBeNull();
        for (const Class of ['traffic', 'latency', 'ingress', 'worker', 'protocol', 'account', 'events', 'resource']) {
            const Panel = await page.locator(`.overview-${Class}-v2`).boundingBox();
            expect(Panel).not.toBeNull();
            expect(Math.abs(Panel!.width - Grid!.width)).toBeLessThanOrEqual(1);
        }
    }
    await page.screenshot({ path: `../build/WebQa/overview-${Width}.png`, fullPage: true });
    await page.goto('/?source=demo&range=custom&from=invalid&to=2026-10-16');
    await expect(page.locator('.overview-traffic-v2').getByRole('alert')).toContainText('时间无效');
    await expect(page.locator('.overview-traffic-v2 .query-state')).toHaveCount(0);
    await page.getByLabel('分析时间范围').selectOption('15m');
    await expect(page.locator('.overview-traffic-v2 .history-plot')).toBeVisible();
});
test('深链不命中保持目标，事件暂停固定内容', async ({ page }) => {
    await page.goto('/accounts?source=demo&account=not-existing');
    await expect(page.getByText('指定账户已不在当前快照', { exact: true })).toBeVisible();
    await expect(page.locator('.account-inspector')).toHaveCount(0);
    await page.goto('/events?source=demo');
    await page.getByRole('button', { name: '暂停追随', exact: true }).click();
    await expect(page.getByRole('button', { name: '继续追随', exact: true })).toBeVisible();
    const PauseStatus = page.getByRole('status').filter({ hasText: '已暂停：固定显示暂停时已载入' });
    await expect(PauseStatus).toContainText('服务端仍继续采集；恢复追随后读取新窗口。');
});
test('搜索可由键盘操作并带时间范围跳转', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    await page.keyboard.press('Control+k');
    const Input = page.getByRole('combobox', { name: '资源搜索关键字' });
    await expect(Input).toBeVisible(); await Input.fill('northstar');
    await expect(page.getByRole('option').filter({ hasText: 'northstar' }).first()).toBeVisible();
    await page.getByRole('option').filter({ hasText: 'northstar' }).first().click();
    await expect(page).toHaveURL(/accounts\?.*range=1h/);
    await expect(page.locator('.account-inspector')).toContainText('northstar');
});
test('默认真实模式无法连接时不会显示演示数值', async ({ page }) => {
    await page.route('**/Operations/**', Route => Route.abort('connectionrefused'));
    await page.goto('/?source=live');
    await expect(page.getByRole('link', { name: '打开演示预览' })).toBeVisible();
    await expect(page.locator('.source-banner')).not.toContainText('演示夹具');
    await expect(page.locator('.runtime-summary')).toHaveCount(0);
});
test('概览资源跳转保留时间并在刷新后保持演示与原目标', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    await page.locator('.overview-worker-v2').getByRole('link', { name: 'worker-01', exact: true }).click();
    await expect(page.locator('.worker-inspector')).toContainText('worker-01');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('worker')).toBe('worker-01');
    await page.reload();
    await expect(page.locator('.source-banner')).toContainText('演示预览');
    await expect(page.locator('.worker-inspector')).toContainText('worker-01');
    await page.goto('/?source=demo&range=1h');
    await page.locator('.overview-account-v2').getByRole('link', { name: /northstar/ }).click();
    await expect(page.locator('.account-inspector')).toContainText('northstar');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('account')).toBe('acct-northstar');
    await page.reload();
    await expect(page.locator('.source-banner')).toContainText('演示预览');
    await expect(page.locator('.account-inspector')).toContainText('northstar');
    const MobileMenu = page.getByRole('button', { name: '打开导航', exact: true });
    if (await MobileMenu.isVisible()) await MobileMenu.click();
    await page.getByRole('link', { name: 'Prism 运行概览', exact: true }).click();
    await expect(page.locator('main h1')).toHaveText('运行概览');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('source')).toBe('demo');
});
