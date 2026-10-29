import { expect, test } from '@playwright/test';

test('桌面导航折叠可持久化，移动端导航仍可打开与关闭', async ({ page }) => {
    const Width = page.viewportSize()?.width ?? 0;
    await page.goto('/?source=demo&range=1h');
    if (Width > 900) {
        const Sidebar = page.locator('[data-slot="sidebar"][data-side="left"]');
        const ExpandedWidth = await page.locator('[data-slot="sidebar-container"]').evaluate(Element => Element.getBoundingClientRect().width);
        const ToggleNavigation = page.getByRole('button', { name: '展开或收起导航', exact: true });
        await ToggleNavigation.click();
        await expect(Sidebar).toHaveAttribute('data-state', 'collapsed');
        await expect(Sidebar).toHaveAttribute('data-collapsible', 'icon');
        await expect.poll(() => page.locator('[data-slot="sidebar-container"]').evaluate(Element => Element.getBoundingClientRect().width))
            .toBeLessThan(ExpandedWidth - 24);
        await expect.poll(() => page.context().cookies(page.url()).then(Cookies => Cookies.find(Cookie => Cookie.name === 'sidebar_state')?.value))
            .toBe('false');

        await page.reload();
        await expect(Sidebar).toHaveAttribute('data-state', 'collapsed');
        const EventLink = Sidebar.getByRole('link', { name: '事件', exact: true });
        await expect(EventLink).toBeVisible();
        await EventLink.click();
        await expect(page.locator('main h1')).toHaveText('事件流');
        const EventsUrl = new URL(page.url());
        expect(EventsUrl.searchParams.get('source')).toBe('demo');
        expect(EventsUrl.searchParams.get('range')).toBe('1h');
        await expect(page.getByText('演示模式', { exact: true })).toBeVisible();

        const CollapsedWidth = await page.locator('[data-slot="sidebar-container"]').evaluate(Element => Element.getBoundingClientRect().width);
        await ToggleNavigation.click();
        await expect(Sidebar).toHaveAttribute('data-state', 'expanded');
        await expect.poll(() => page.locator('[data-slot="sidebar-container"]').evaluate(Element => Element.getBoundingClientRect().width))
            .toBeGreaterThan(CollapsedWidth + 24);
        await expect.poll(() => page.context().cookies(page.url()).then(Cookies => Cookies.find(Cookie => Cookie.name === 'sidebar_state')?.value))
            .toBe('true');
        return;
    }

    const OpenNavigation = page.getByRole('button', { name: '展开或收起导航', exact: true });
    const SidebarDialog = page.getByRole('dialog', { name: '主导航', exact: true });
    await OpenNavigation.click();
    await expect(SidebarDialog).toBeVisible();
    await expect(SidebarDialog.getByRole('link', { name: '运行概览', exact: true })).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(SidebarDialog).toBeHidden();
    await expect(OpenNavigation).toBeFocused();
});

test('搜索对话框与移动导航各自处理 Escape 并恢复焦点', async ({ page }) => {
    const Width = page.viewportSize()?.width ?? 0;
    await page.goto('/?source=demo&range=1h');
    const SearchTrigger = page.getByRole('button', { name: '搜索资源', exact: true });
    const SearchDialog = page.getByRole('dialog', { name: '搜索资源', exact: true });
    const SearchInput = page.getByRole('combobox', { name: '资源搜索关键字' });

    if (Width > 900) {
        await SearchTrigger.focus();
        await page.keyboard.press('Control+k');
        await expect(SearchDialog).toBeVisible();
        await expect(SearchInput).toBeFocused();
        await page.keyboard.press('Escape');
        await expect(SearchDialog).toBeHidden();
        await expect(SearchTrigger).toBeFocused();
        return;
    }

    const OpenNavigation = page.getByRole('button', { name: '展开或收起导航', exact: true });
    const Sidebar = page.getByRole('dialog', { name: '主导航', exact: true });
    await OpenNavigation.click();
    await expect(Sidebar).toBeVisible();
    await expect(Sidebar).toHaveAttribute('aria-modal', 'true');

    const Focusable = Sidebar.locator('a[href]:visible, button:not([disabled]):visible');
    const First = Focusable.first();
    const Last = Focusable.last();
    await First.focus();
    await page.keyboard.press('Shift+Tab');
    await expect(Last).toBeFocused();
    await page.keyboard.press('Tab');
    await expect(First).toBeFocused();

    await page.keyboard.press('Escape');
    await expect(Sidebar).toBeHidden();
    await expect(OpenNavigation).toBeFocused();

    await SearchTrigger.click();
    await expect(SearchDialog).toBeVisible();
    await expect(SearchInput).toBeFocused();
    await page.keyboard.press('Escape');
    await expect(SearchDialog).toBeHidden();
    await expect(SearchTrigger).toBeFocused();
});

test('自定义时间输入清空后保留无效状态并能直接修复', async ({ page }) => {
    await page.goto('/?source=demo&range=custom&from=2026-10-22T10%3A00%3A00.000Z&to=2026-10-22T11%3A00%3A00.000Z');
    const Start = page.getByRole('textbox', { name: '开始时间', exact: true });
    const End = page.getByRole('textbox', { name: '结束时间', exact: true });
    await expect(Start).toBeVisible();
    await expect(End).toBeVisible();

    await Start.fill('');
    await expect(Start).toHaveValue('');
    await expect(page).not.toHaveURL(/(?:\?|&)from=/);
    await expect(page.locator('#time-range-error')).toHaveText('请选择完整的开始与结束时间。');
    await expect(Start).toHaveAttribute('aria-invalid', 'true');

    const ValidStart = await End.evaluate(Element => {
        const Value = new Date((Element as HTMLInputElement).value);
        Value.setMinutes(Value.getMinutes() - 30);
        const Pad = (Part: number) => String(Part).padStart(2, '0');
        return [
            `${Value.getFullYear()}-${Pad(Value.getMonth() + 1)}-${Pad(Value.getDate())}`,
            `${Pad(Value.getHours())}:${Pad(Value.getMinutes())}`,
        ].join('T');
    });
    await Start.fill(ValidStart);
    await expect(Start).not.toHaveAttribute('aria-invalid');
    await expect(page.locator('#time-range-error')).toHaveCount(0);
    expect(new URL(page.url()).searchParams.get('from')).not.toBeNull();
});

test('图表支持键盘查看和固定读数，主题可在深浅色间切换', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    const Chart = page.locator('.overview-traffic-v2 .time-series-chart[tabindex="0"]');
    await expect(Chart).toBeVisible();
    await expect(Chart).toHaveAttribute('aria-label', /使用左右方向键查看采样点/);
    const TimeLabels = await Chart.locator('.time-series-chart__axis text').filter({ hasText: /:/ })
        .evaluateAll(Labels => Labels.map(Label => {
            const Box = Label.getBoundingClientRect();
            return { Left: Box.left, Right: Box.right };
        }));
    expect(TimeLabels.length).toBeGreaterThanOrEqual(2);
    for (let Index = 1; Index < TimeLabels.length; Index += 1)
        expect(TimeLabels[Index - 1]!.Right).toBeLessThanOrEqual(TimeLabels[Index]!.Left);
    await Chart.focus();
    await page.keyboard.press('ArrowRight');
    const Tooltip = page.locator('.overview-traffic-v2 .chart-tooltip');
    await expect(Tooltip).toBeVisible();
    const Reading = Chart.getByRole('status');
    await expect(Reading).toContainText('采样时间');
    await expect(Reading).toContainText('下行：');
    await expect(Reading).toContainText('上行：');
    await expect(Chart.locator('.time-series-chart__line[stroke-dasharray="6 4"]')).not.toHaveCount(0);
    await page.keyboard.press('Enter');
    await expect(Tooltip).toContainText('已固定');
    await expect(Reading).toContainText('已固定读数');
    await page.keyboard.press('Escape');
    await expect(Tooltip).toHaveCount(0);
    await expect(Reading).toHaveText('已清除读数。');

    const Root = page.locator('html');
    await expect(Root).toHaveAttribute('data-theme', 'light');
    await page.getByRole('button', { name: '切换深色主题', exact: true }).click();
    await expect(Root).toHaveAttribute('data-theme', 'dark');
    const DarkCanvas = await Root.evaluate(Element => getComputedStyle(Element).getPropertyValue('--canvas').trim());
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute('content', DarkCanvas);
    await page.getByRole('button', { name: '切换浅色主题', exact: true }).click();
    await expect(Root).toHaveAttribute('data-theme', 'light');
    const LightCanvas = await Root.evaluate(Element => getComputedStyle(Element).getPropertyValue('--canvas').trim());
    await expect(page.locator('meta[name="theme-color"]')).toHaveAttribute('content', LightCanvas);
});

test('监测概览区分即时速率与历史区间并保留资源跳转上下文', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/?source=demo');
    expect(await page.evaluate(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)).toBe(true);
    const Motion = await page.locator('.page-header, .sidebar, .overview-traffic-v2').evaluateAll(Elements =>
        Elements.map(Element => ({ Animation: getComputedStyle(Element).animationDuration, Transition: getComputedStyle(Element).transitionDuration })));
    for (const Value of Motion) {
        expect(Value.Animation.split(',').every(Duration => parseFloat(Duration) <= 0.01)).toBe(true);
        expect(Value.Transition.split(',').every(Duration => parseFloat(Duration) <= 0.01)).toBe(true);
    }

    await expect(page.getByRole('navigation', { name: '概览分区' })).toHaveCount(0);
    const LiveRates = page.getByRole('region', { name: '运行指标', exact: true });
    await expect(LiveRates.getByText('下行速率', { exact: true }).locator('..').locator('dd').first()).toBeVisible();
    await expect(LiveRates.getByText('上行速率', { exact: true }).locator('..').locator('dd').first()).toBeVisible();
    const SnapshotTime = page.getByRole('region', { name: '运行状态与数据质量', exact: true }).locator('time[datetime]');
    await expect(SnapshotTime).toHaveCount(1);
    await expect(SnapshotTime).toHaveAttribute('datetime', /^\d{4}-\d{2}-\d{2}T/);

    await page.getByRole('combobox', { name: '分析时间范围', exact: true }).click();
    await page.getByRole('option', { name: '最近 1 小时', exact: true }).click();
    await expect(page).toHaveURL(/range=1h/);
    let CurrentUrl = new URL(page.url());
    expect(CurrentUrl.searchParams.get('source')).toBe('demo');
    expect(CurrentUrl.searchParams.get('range')).toBe('1h');
    await expect(page.locator('.overview-traffic-v2 .time-series-chart[tabindex="0"]')).toBeVisible();

    await expect(page.getByRole('heading', { name: '连接活动', exact: true })).toBeVisible();
    await page.getByRole('link', { name: '查看会话', exact: true }).click();
    await expect(page.locator('main h1')).toHaveText('连接');
    await expect(page).toHaveTitle('连接 · Prism Control Plane');
    CurrentUrl = new URL(page.url());
    expect(CurrentUrl.pathname).toBe('/sessions');
    expect(CurrentUrl.searchParams.get('source')).toBe('demo');
    expect(CurrentUrl.searchParams.get('range')).toBe('1h');
});

test('演示模式手动刷新显示完成状态并公布成功消息', async ({ page }) => {
    await page.goto('/?source=demo&range=1h');
    const RefreshButton = page.locator('.overview-refresh-button');
    await expect(RefreshButton).toBeEnabled();
    await expect(RefreshButton).toHaveText('刷新');

    await RefreshButton.click();
    await expect(RefreshButton).toHaveAttribute('data-refresh-state', 'success');
    await expect(RefreshButton).toHaveText('已更新');
    const Feedback = page.locator('.overview-refresh-feedback');
    await expect(Feedback).toHaveAttribute('role', 'status');
    await expect(Feedback).toHaveAttribute('aria-live', 'polite');
    await expect(Feedback).toHaveText('刷新成功');
});

test('账户详情保持可读宽度且连接列表各行不会相互遮挡', async ({ page }) => {
    await page.emulateMedia({ reducedMotion: 'reduce' });
    await page.goto('/accounts?source=demo');
    await page.getByRole('button', { name: 'blue-hour acct-blue-hour', exact: true }).click();
    const Inspector = page.getByRole('region', { name: '账户详情', exact: true });
    await expect(Inspector).toContainText('blue-hour');
    await Inspector.getByRole('tab', { name: '关联 Session', exact: true }).click();
    await expect(Inspector.getByRole('tabpanel')).toBeVisible();
    const DetailBounds = await Inspector.boundingBox();
    const Viewport = page.viewportSize()!;
    expect(DetailBounds).not.toBeNull();
    expect(DetailBounds!.width).toBeGreaterThanOrEqual(280);
    expect(DetailBounds!.x).toBeGreaterThanOrEqual(0);
    expect(DetailBounds!.x + DetailBounds!.width).toBeLessThanOrEqual(Viewport.width + 1);

    await page.goto('/sessions?source=demo');
    await expect(page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr')).toHaveCount(5);
    await page.evaluate(() => document.fonts.ready);
    const Rows = await page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').evaluateAll(Elements => Elements.map(Element => {
        const Bounds = Element.getBoundingClientRect();
        return { Top: Bounds.top, Bottom: Bounds.bottom };
    }));
    for (let Index = 1; Index < Rows.length; Index++)
        expect(Rows[Index]!.Top).toBeGreaterThanOrEqual(Rows[Index - 1]!.Bottom - 1);
    await page.getByRole('table', { name: 'Session 列表', exact: true }).locator('tbody tr').last().click();
    await expect(page.getByRole('region', { name: /^Session .* 详情$/ }).getByRole('heading', { level: 2 })).toHaveText('session-0998');
});
