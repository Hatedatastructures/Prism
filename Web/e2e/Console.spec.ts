import { expect, test } from '@playwright/test';

const Pages = [ ['/', '运行概览'], ['/workers', '工作线程'], ['/accounts', '代理账户'], ['/user-groups', '用户组'],
    ['/sessions', '连接'], ['/events', '事件流'], ['/ingresses', '代理入口'], ['/protocols', '协议'],
    ['/resources', '资源分析'], ['/configuration', '配置'], ['/operations', '操作中心'] ] as const;
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
        await expect(page.getByText('演示模式', { exact: true })).toBeVisible();
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
            expect(CellSizes, 'Ingress fixture must expose all 21 body cells to verify the shared table size.').toHaveLength(21);
            expect(CellSizes.map(Cell => Cell.Size), 'Ingress table body cells must use the shared 15px text size.').toEqual(Array(21).fill(15));
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
test('概览呈现运行读数、连接活动和代理资源，并按宽度排列区块', async ({ page }) => {
    await page.goto('/?source=demo');
    await expect(page.getByRole('heading', { name: '运行概览', exact: true })).toBeVisible();
    await expect(page.getByRole('region', { name: '运行指标', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '连接活动', exact: true })).toBeVisible();
    await expect(page.getByText('流量趋势', { exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '监听端口', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Worker 调度', exact: true })).toBeVisible();
    const Width = await page.evaluate(() => innerWidth);
    await page.screenshot({ path: `../build/WebQa/overview-${Width}.png`, fullPage: true });
    const IngressAndDispatch = page.getByRole('region', { name: '入口和调度', exact: true });
    const Columns = await IngressAndDispatch.evaluate(Element => getComputedStyle(Element).gridTemplateColumns.split(' ').length);
    expect(Columns).toBe(Width >= 1280 ? 2 : 1);
    await expect(page.getByRole('heading', { name: '账户使用', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: '协议使用', exact: true })).toBeVisible();
});
test('深链不命中保持目标，事件暂停固定内容', async ({ page }) => {
    await page.goto('/accounts?source=demo&account=not-existing');
    await expect(page.getByText('指定账户不在当前快照', { exact: true })).toBeVisible();
    const AccountDetails = page.getByRole('region', { name: '账户详情', exact: true });
    await expect(AccountDetails).toBeVisible();
    await expect(AccountDetails).toContainText('选择一个账户');
    await expect(AccountDetails).not.toContainText('acct-northstar');
    await page.goto('/events?source=demo');
    await page.getByRole('button', { name: '暂停追随', exact: true }).click();
    await expect(page.getByRole('button', { name: '继续追随', exact: true })).toBeVisible();
    const PauseAlert = page.getByRole('alert').filter({ hasText: '事件追随已暂停' });
    await expect(PauseAlert).toContainText('固定显示暂停时已载入的 5 条记录；恢复后才会读取新的服务端窗口。');
});
test('搜索可由键盘操作并带时间范围跳转', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    await page.keyboard.press('Control+k');
    const Input = page.getByRole('combobox', { name: '资源搜索关键字' });
    await expect(Input).toBeVisible(); await Input.fill('northstar');
    await expect(page.getByRole('option').filter({ hasText: 'northstar' }).first()).toBeVisible();
    await page.getByRole('option').filter({ hasText: 'northstar' }).first().click();
    await expect(page).toHaveURL(/accounts\?.*range=1h/);
    await expect(page.getByText(/acct-northstar · Generation 42/)).toBeVisible();
});
test('默认真实模式无法连接时不会显示演示数值', async ({ page }) => {
    await page.route('**/Operations/**', Route => Route.abort('connectionrefused'));
    await page.goto('/?source=live');
    await expect(page.getByRole('link', { name: '打开演示预览' })).toBeVisible();
    await expect(page.getByText('演示夹具')).toHaveCount(0);
    await expect(page.locator('.runtime-summary')).toHaveCount(0);
});
test('概览资源跳转保留时间并在刷新后保持演示与原目标', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    await page.getByRole('link', { name: 'worker-01', exact: true }).click();
    await expect(page.getByRole('button', { name: '查看 Worker 实例身份', exact: true })).toBeVisible();
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('worker')).toBe('worker-01');
    await page.reload();
    await expect(page.getByText('演示模式', { exact: true })).toBeVisible();
    await expect(page.getByRole('button', { name: '查看 Worker 实例身份', exact: true })).toBeVisible();
    await page.goto('/?source=demo&range=1h');
    await page.getByRole('link', { name: 'northstar', exact: true }).click();
    await expect(page.getByText(/acct-northstar · Generation 42/)).toBeVisible();
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('account')).toBe('acct-northstar');
    await page.reload();
    await expect(page.getByText('演示模式', { exact: true })).toBeVisible();
    await expect(page.getByText(/acct-northstar · Generation 42/)).toBeVisible();
    const MobileMenu = page.getByRole('button', { name: '展开或收起导航', exact: true });
    if (await MobileMenu.isVisible()) await MobileMenu.click();
    await page.getByRole('link', { name: '运行概览', exact: true }).click();
    await expect(page.locator('main h1')).toHaveText('运行概览');
    expect(new URL(page.url()).searchParams.get('range')).toBe('1h');
    expect(new URL(page.url()).searchParams.get('source')).toBe('demo');
});
